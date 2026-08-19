#!/usr/bin/env python3
"""
gs_common.py - Shared OPSEC library for the GhostSpiral v10 toolchain
=====================================================================
Centralises integrity logging, Tor verification, atomic I/O, secure
file permissions, CSPRNG helpers, and timing decorrelation so that
every companion script uses battle-tested, consistent implementations.

OPSEC design principles
-----------------------
- All network I/O goes through Tor or aborts.
- Every sensitive file is written 0600 (owner-only).
- Integrity log uses SHA-256 hash-chain for tamper evidence.
- CSPRNG (secrets module) for all security-critical randomness.
- Timing jitter between operations to frustrate traffic analysis.
- Proxy format validated before first use.
- Signal handlers for graceful shutdown on SIGINT/SIGTERM.
"""
from __future__ import annotations
import argparse
import contextlib, errno, fcntl, hashlib, json, os, re, secrets, shutil, signal, stat as stat_module, sys, time
from decimal import Decimal, ROUND_DOWN, InvalidOperation
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse

import requests
from tenacity import retry, wait_exponential_jitter, stop_after_attempt

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

VERSION = "10.5"
CHECK_TOR_URL = "https://check.torproject.org/api/ip"
INTEGRITY_LOG = Path("integrity_chain.log")

#: One piconero, the smallest amount Monero represents. Used to put a gate
#: strictly ABOVE a computed quantity rather than merely at it.
PICONERO = Decimal("0.000000000001")
SOCKS_RE = re.compile(r"^socks5h://[^\s:]+:\d{1,5}$")
# CRITICAL: only socks5h:// is accepted. Plain socks5:// leaks DNS locally
# because the requests library resolves hostnames BEFORE sending through
# the SOCKS proxy. With socks5h://, DNS resolution happens at the proxy.

# ---------------------------------------------------------------------------
#  Secure randomness
# ---------------------------------------------------------------------------

def secure_hex(n_bytes: int) -> str:
    """Return n_bytes of cryptographically random hex (no '0x' prefix)."""
    return secrets.token_hex(n_bytes)


def secure_delay(lo: float = 2.0, hi: float = 8.0) -> None:
    """Sleep a CSPRNG-uniform duration to decorrelate timing.

    secrets.randbelow() raises ValueError("Upper bound must be positive") for
    an argument <= 0, so the old body crashed outright whenever hi == lo or
    hi < lo -- verified. Every current caller passes a valid widening range, so
    this was latent, but a crash in timing decorrelation would abort a run
    mid-pipeline for a purely cosmetic parameter. Normalise instead: swap an
    inverted range, and treat a zero-width one as a fixed sleep.
    """
    lo, hi = float(lo), float(hi)
    if hi < lo:
        lo, hi = hi, lo
    span_ms = int((hi - lo) * 1000)
    delay = lo if span_ms <= 0 else lo + secrets.randbelow(span_ms) / 1000.0
    if delay > 0:
        time.sleep(delay)

# ---------------------------------------------------------------------------
#  Integrity hash-chain logger
# ---------------------------------------------------------------------------

#: Payload patterns that describe THE RUN'S STRUCTURE rather than what happened.
#:
#: THE CHAIN IS A FORENSIC ARTIFACT. That is not an outside opinion; it is this
#: toolchain's own position, stated in three places and acted on in one:
#:
#:   * create_subs stopped labelling subaddresses because "labels are written
#:     into the WALLET FILE, and the wallet file is the one artifact
#:     paranoia_mode deliberately never deletes". What labels handed an
#:     adversary, it says, is "which outputs are decoys, which are real mix
#:     targets, which are peel carriers AND IN WHAT ORDER, which is the change
#:     sweep, and -- via 'GhostSpiral_entry' -- the name of the tool".
#:   * report_holdings prints the run's account grouping to the terminal and
#:     tells the operator, in as many words, "Not written to disk: a file
#:     naming this run's accounts would hand anyone who reads the machine the
#:     grouping". It logs a count and no numbers.
#:   * paranoia_mode's wipe calls integrity_chain.log "the exact forensic
#:     artifact this phase exists to destroy", and its mac_spoof fix already
#:     established the remedy: "The log now records only THAT a spoof happened;
#:     the MAC itself is printed to the terminal for the operator and never
#:     stored."
#:
#: Every one of those defences was then undone by the chain itself, which
#: recorded the ENTRY account and subaddress, every change-sweep account, every
#: peel carrier index in order, and one `withdrawn:<acct>/<sub>` line per
#: withdrawn output -- so the grouping report_holdings refuses to write, the
#: roles and ORDER the labels were removed to hide, and (by counting those
#: lines) the number of outputs the distribution created, were all on disk
#: anyway. The tool name and version are on every line of the file.
#:
#: So the same remedy, applied at the chokepoint instead of one call site at a
#: time: the chain records THAT a thing happened. Which account it happened to,
#: and how many there were, goes to the terminal and stays there.
#:
#: A chokepoint and not 73 careful call sites, because 73 careful call sites is
#: what this was: each one HAD been considered individually -- the fan-out logs
#: its destination COUNT under a comment explaining that the AMOUNT would be
#: linkable -- and that count is the on-chain search key build_entry_veil
#: exists to hide. Judgement per call site is precisely what failed.
#:
#: DEFAULT-DENY, for the same reason create_subs gives one account per output:
#: "makes the merge IMPOSSIBLE rather than merely discouraged". The first
#: version of this was a denylist of the structural shapes actually seen --
#: acct=N, N/M, N_outputs -- and it was whack-a-mole by construction: it missed
#: `change_swept_into_mix:12`, `accounts_count:19`, and the numerator of
#: `11_of_11` on the first pass over the real payloads. A denylist of the
#: leaks somebody already noticed is the same fragility one level up.
#:
#: So: NO PAYLOAD MAY CARRY A NUMBER. Not "no account number" -- no number.
#: That is checkable in one line by any future test, and a call site written
#: the obvious way cannot defeat it.
#:
#: Each RUN of digits collapses to a single '#', never one '#' per digit: the
#: width of the redaction would otherwise leak the magnitude, and "between 10
#: and 99 outputs" is most of the answer.
_CHAIN_DIGITS_RE = re.compile(r"\d+")

#: A scrub_address() fragment: `4AdUndZS...9kQjMdKr`.
#:
#: DIGIT REDACTION DOES NOT COVER THIS, and it is the worst thing on the chain.
#: scrub_address keeps 8 leading and 8 trailing base58 characters, and callers
#: pass it to integrity_log precisely because its docstring says that is the
#: safe form. It is safe for a TERMINAL. On the persistent chain it is a JOIN
#: KEY: ENTRY is the address the ThorChain memo carries verbatim, in plaintext,
#: in a Bitcoin OP_RETURN that anybody can read -- so 16 characters of it turn
#: a seized disk and the public Bitcoin chain into one dataset. Sixteen base58
#: characters is ~94 bits; nothing else on earth matches by accident.
#:
#: Stripping the digits out leaves 14 of them, which is still unique. The whole
#: fragment goes.
_CHAIN_ADDR_RE = re.compile(
    r"[1-9A-HJ-NP-Za-km-z]{4,}\.\.\.[1-9A-HJ-NP-Za-km-z]{4,}")

#: A bare run of base58, for the addresses that arrive WITHOUT the scrub form.
#:
#: THE FRAGMENT RULE ABOVE IS NOT ENOUGH, because it only recognises what
#: scrub_address produces. Nineteen chain payloads across the shipped tools are
#: built from EXCEPTION TEXT -- `f"rpc_err:{str(e)[:40]}"` and friends -- and
#: monero-wallet-rpc puts addresses in its error messages:
#:
#:     "Invalid destination address: 4AdUndZSHcJ..."  ->  chain gets 11 chars
#:     "could not resolve 4AdUndZSHcJ1nUAWkMHNTZ"     ->  chain gets 22 chars
#:
#: Stripping the digits leaves the letters, and twenty-two base58 characters is
#: ~129 bits. ENTRY is named in plaintext by the public ThorChain memo, so any
#: recognisable slice of it is the same join key between a seized disk and the
#: Bitcoin chain that the fragment rule exists to remove -- reached by a path
#: the fragment rule never looked at.
#:
#: Discriminating an address slice from an English word: a run of at least 12
#: base58 characters carrying at least TWO uppercase AND TWO lowercase. Monero
#: addresses alternate case densely; prose does not. "Authentication" is 14
#: base58-legal characters but has one capital, so it survives. Event names are
#: lowercase_with_underscores or UPPER_SNAKE, and the underscore is not in the
#: alphabet, so it breaks every run well below 12.
_CHAIN_B58_RUN_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{10,}")


def _b58_run_is_addressy(run: str) -> bool:
    """Dense case ALTERNATION is what separates an address from a word.

    Counting uppercase and lowercase separately is not enough: "ConnectionError"
    is fifteen base58-legal characters with two capitals and thirteen
    lowercase, and chain payloads now carry exception TYPE names for exactly
    the reason this function exists -- so a rule that ate them would delete the
    diagnostic it was introduced to protect.

    A Monero address is random base58, so its case flips roughly every other
    character. CamelCase flips once per word, so the RATE is what separates
    them -- not the count. "ConnectionRefusedError" reaches five flips purely
    by being three words long, and a flat threshold ate it; over its
    twenty-two characters that is a rate of 0.23, against ~0.5 for an address.

    Two of the commonest exception names cannot even form a run: base58
    excludes I and l, so "InvalidOperation" and "CalledProcessError" break
    apart before this is called.

    Conservative on purpose. Exception TEXT no longer reaches the chain at all
    (the call sites log type(e).__name__), so this is the second line of
    defence against a call site added later -- and a rule that occasionally
    misses a short slice is better than one that deletes the diagnostics, which
    is how a redactor gets switched off.
    """
    cased = [c for c in run if c.isalpha()]
    if len(cased) < 8:
        return False
    if sum(1 for c in cased if c.isupper()) < 2:
        return False
    if sum(1 for c in cased if c.islower()) < 2:
        return False
    flips = sum(1 for a, b in zip(cased, cased[1:]) if a.isupper() != b.isupper())
    return flips >= 4 and flips / len(cased) >= 0.35


def chain_safe(msg: str) -> str:
    """Strip every number out of a chain payload, keeping the event.

    `withdrawn:4/1` becomes `withdrawn:#/#`; `fanout_plan:1_tx:9_dests` becomes
    `fanout_plan:#_tx:#_dests`; `spend_source_ok:acct=3:idx=1` becomes
    `spend_source_ok:acct=#:idx=#`; and a scrub_address fragment such as
    `entry=4AdUndZS...9kQjMdKr` becomes `entry=<addr>`. WHAT happened survives
    in full; which output or address it happened to, and how many there were,
    does not.

    Nothing is lost that the operator needs. Every quantity worth having --
    the slippage deviation, the balances, the account grouping, the failure
    counts -- is already printed to the terminal at the moment it is computed,
    and several are in the abort message too. This is the remedy paranoia_mode
    settled on for the spoofed MAC, applied where every tool passes through:
    "the log now records only THAT a spoof happened; the [value] is printed to
    the terminal for the operator and never stored."

    Only the message is redacted, not the stage: stages come from a fixed
    vocabulary (stage0..stage5, exit, main, fee, recv, swap, paranoia) and
    carry no run data.

    Pure and total -- it never raises, so a logging call can never become the
    thing that aborts a run mid-pipeline.
    """
    try:
        # Order matters: the scrub_address form first (its halves are shorter
        # than the bare-run threshold), then bare runs, then digits. Digits
        # last, because collapsing them to '#' would break up a base58 run
        # before the run rule ever saw it.
        # A FULL address first, matched exactly rather than statistically: a
        # run of 90+ base58 characters is an address and nothing else, so this
        # branch has no false positives and no misses. The rate rule below is
        # a heuristic and gets ~99% of full addresses on its own -- 1% is not
        # a number to accept for the value that identifies the operator.
        out = re.sub(r"[1-9A-HJ-NP-Za-km-z]{90,}", "<addr>", str(msg))
        out = _CHAIN_ADDR_RE.sub("<addr>", out)
        out = _CHAIN_B58_RUN_RE.sub(
            lambda m: "<addr>" if _b58_run_is_addressy(m.group(0)) else m.group(0),
            out)
        return _CHAIN_DIGITS_RE.sub("#", out)
    except Exception:                                        # noqa: BLE001
        return "REDACTED"


def integrity_log(stage: str, msg: str, log_path: Path = INTEGRITY_LOG) -> str:
    """Append a SHA-256-chained line to the integrity log. Returns the hash.

    Timestamp is coarsened to 600-second (10-min) buckets to reduce the
    correlation window between the log and blockchain/network timestamps.
    An attacker with the log can only narrow the operation to a 10-min window
    instead of the exact second.
    """
    # LOCKED read-modify-write. This read the whole file, took the last line's
    # hash as `prev`, and appended -- with nothing serialising the three steps.
    # Two processes whose windows overlap both chain off the SAME prev, so
    # every link after that point fails recomputation and the file stops being
    # tamper-evidence, which is its only job. That is not hypothetical here:
    # gs_console runs jobs concurrently by construction (a thread per job), and
    # every tool in the chain logs at startup while receive_watch logs once per
    # failed poll for up to 24 hours.
    #
    # A separate lock file, not the log itself: the log is securely deleted by
    # paranoia_mode, and holding the lock on a file that gets unlinked
    # mid-flight would silently stop serialising anything.
    lock_path = Path(str(log_path) + ".lock")
    lock_fd = None
    try:
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
    except OSError:
        # No lock available (odd filesystem, no permission). Proceed unlocked
        # rather than lose the entry entirely -- a forked chain is bad, a
        # missing chain is worse -- but say so in the entry itself so a later
        # reader knows this link was written without serialisation.
        if lock_fd is not None:
            try: os.close(lock_fd)
            except OSError: pass
        lock_fd = None
        stage = f"{stage}!nolock"
    try:
        prev = "0" * 64
        if log_path.exists():
            text = log_path.read_text()
            lines = text.splitlines()
            if lines:
                prev = lines[-1].split(" | ")[0].strip()
        ts = int(time.time()) // 600 * 600  # coarsen to 10-min buckets
        # REDACTED HERE, at the one place every tool passes through, so a call
        # site added later cannot reintroduce the leak by being written the
        # obvious way. See chain_safe.
        line = f"{ts}|{VERSION}|{stage}|{chain_safe(msg)}"
        h = hashlib.sha256((prev + line).encode()).hexdigest()
        _append_chain_line(log_path, h, line)
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            except OSError:
                pass
    return h


#: Standard Monero address: 95 chars, base58 (no 0OIl), 4/8 mainnet prefix.
#: Integrated (106) and subaddress forms are deliberately NOT matched loosely
#: here -- see validate_xmr_address.
XMR_ADDR_RE = re.compile(r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$")


def validate_xmr_address(addr: str, what: str = "XMR address") -> None:
    """Abort unless `addr` is a well-formed Monero address WITH a valid checksum.

    Format alone is not enough and never was. Base58 addresses carry a
    four-byte checksum precisely because a transposed or mistyped character
    produces a string that still looks like an address; the regex accepts it
    and the money goes to a key nobody holds. That is unrecoverable in a way
    almost nothing else in this toolchain is -- there is no confirmation step
    and no reversal -- so the checksum is verified, not assumed.

    Shared because the withdrawal destination needs exactly the check the swap
    destination already had. thor_swap_preparer validated its --dest and
    GhostSpiral had nothing for --exit-to, which is the address the ENTIRE
    mixed balance is sent to.
    """
    if not isinstance(addr, str) or not XMR_ADDR_RE.match(addr):
        sys.exit(f"[!] Bad {what} format: {scrub_address(str(addr))}")
    # monero.address.address(), the FACTORY -- not the Address CLASS.
    #
    # Address() accepts only STANDARD addresses: it raises "Invalid address
    # netbyte 42" on a subaddress, and 42 is the mainnet subaddress netbyte.
    # Every address this toolchain hands around is a subaddress --
    # create_receive_wallet mints one for the receive, and an exchange deposit
    # address is normally one too -- so validating with the class rejected the
    # ordinary case while reporting it as "checksum invalid", which points the
    # operator at the one thing that is not wrong.
    #
    # Measured against a real subaddress from a live wallet: address() returns
    # SubAddress, Address() raises. The factory also covers integrated
    # addresses, which carry a payment ID and are equally legitimate here.
    try:
        from monero.address import address as _xmr_address
    except ImportError:
        sys.exit(f"[!] python-monero is missing, so the {what} CHECKSUM cannot "
                 f"be verified (pip install monero). Refusing to send to an "
                 f"unverified address.")
    try:
        _xmr_address(addr)
    except Exception:                                        # noqa: BLE001
        sys.exit(f"[!] {what} checksum invalid: {scrub_address(addr)}. A "
                 f"mistyped character passes the format check but not this "
                 f"one, and funds sent there are unrecoverable.")


def decimal_arg(text: str) -> Decimal:
    """argparse `type=` for a numeric amount. Use instead of type=Decimal.

    type=Decimal LOOKS right and is not. argparse converts a failing type into
    a clean "invalid value" message only for ValueError and TypeError, but
    Decimal("abc") raises decimal.InvalidOperation, which is an ArithmeticError
    -- so every numeric flag in this toolchain answered a typo with a raw
    traceback out of argparse's internals. Ten arguments across five tools did
    this, including the ones that size real spends.

    It also rejects NaN and Infinity, which Decimal ACCEPTS. Those parse, pass
    an `x > 0` test (NaN raises InvalidOperation on comparison; Infinity does
    not), and then poison every downstream calculation -- an infinite amount
    produces a plan full of garbage rather than an error. Rejecting them at the
    parse boundary means no caller has to remember to re-check.
    """
    try:
        v = Decimal(str(text))
    except Exception:                                        # noqa: BLE001
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a number") from None
    if not v.is_finite():
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a finite number ('NaN' and 'Infinity' parse as "
            f"Decimals but are not amounts)")
    return v


#: The roots paranoia_mode globs when it hunts artifacts, at depth 0 and 1.
#: Named ONCE, here, because three places now need to agree about them: the
#: wipe itself, and the two tools that write operator-chosen paths which the
#: wipe may therefore never reach.
def paranoia_search_roots() -> list:
    """The directories paranoia_mode searches for artifacts."""
    return [Path.cwd().resolve(), Path.home().resolve(),
            (Path.home() / "ghostspiral").resolve(),
            (Path.home() / "GhostSpiral").resolve()]


def wipe_covers(target) -> bool:
    """True if paranoia_mode's artifact sweep would ever look at `target`.

    paranoia_mode globs FIXED roots (cwd, $HOME, $HOME/ghostspiral,
    $HOME/GhostSpiral) at depth 0 and 1. Anything an operator redirects
    elsewhere -- `--output /mnt/usb/plans`, `--outfile /srv/exit.json` -- is
    never looked at, and nothing told them so, because both tools report
    success identically wherever they wrote.

    Shared rather than copied: exit_strategy_simulator had this logic inline
    and GhostSpiral's --output had no equivalent at all, so the two disagreed
    about the same question. A wrong answer here is silent by construction.
    """
    try:
        res = Path(target).resolve()
        if res.is_file() or res.suffix:
            res = res.parent
        return any(res == r or r in res.parents for r in paranoia_search_roots())
    except OSError:
        return False


def verify_integrity_chain(log_path: Path = INTEGRITY_LOG) -> tuple:
    """Recompute the hash chain and report the FIRST link that does not hold.

    Returns (ok, bad_lineno, reason). bad_lineno is 1-based, or None when ok.

    THIS DID NOT EXIST. Every tool in this chain advertises "integrity
    hash-chain logging" in its header and calls integrity_log on every
    meaningful step, and the chain it builds is a real one -- each line is
    sha256(previous_hash + payload), serialised under a lock. But nothing
    anywhere recomputed it. A hash chain is not tamper-EVIDENCE until something
    examines the evidence; unverified, it is an expensive append-only log, and
    an adversary who edits a line and recomputes the hashes below it is
    indistinguishable from one who does not, because nobody ever looks.

    What this can and cannot show, stated plainly so it is not oversold:
      * It detects an EDIT or a DELETION in the middle of the file: every link
        after the change fails recomputation.
      * It does NOT detect TRUNCATION of the tail, and it cannot. Nothing here
        signs the chain's length or its head, so lopping off the last N lines
        leaves a shorter chain that verifies perfectly. Detecting that needs a
        secret or an off-host anchor, neither of which this toolchain has.
        Anyone reading a "chain OK" result must understand it as "no line was
        altered", not "nothing was removed".
      * A '!nolock' stage marks a link written without serialisation, which can
        fork the chain legitimately. Those are reported, not treated as tamper.
    """
    log_path = Path(log_path)
    if not log_path.exists():
        return (False, None, f"{log_path} does not exist")
    lines = log_path.read_text().splitlines()
    if not lines:
        return (False, None, f"{log_path} is empty")
    prev = "0" * 64
    nolock = 0
    for i, raw in enumerate(lines, start=1):
        if " | " not in raw:
            return (False, i, f"line {i} is not a chain line (no ' | ' separator)")
        h, payload = raw.split(" | ", 1)
        h = h.strip()
        expect = hashlib.sha256((prev + payload).encode()).hexdigest()
        if h != expect:
            return (False, i,
                    f"line {i} does not chain: recorded {h[:16]}..., recomputed "
                    f"{expect[:16]}... — this line or one before it was altered")
        if "!nolock" in payload:
            nolock += 1
        prev = h
    reason = f"{len(lines)} links verified"
    if nolock:
        reason += (f"; {nolock} written without the lock (concurrent writers "
                   f"can fork a chain legitimately)")
    reason += "; NOTE: tail truncation is undetectable by design"
    return (True, None, reason)


def _append_chain_line(log_path: Path, h: str, line: str) -> None:
    """Append one already-computed chain line. Caller holds the lock."""
    # O_CREAT with an explicit 0600, NOT open("a") + chmod afterwards. The plain
    # append-open creates the file 0644 under the default umask, so the very
    # first log line of a run -- and this file records the wallet label, exact
    # fan-out amounts, the DAG plan and a stage timeline -- was briefly
    # world-readable, and stayed 0644 if the process died before the next call.
    # secure_write_bytes cannot be used here: it passes O_TRUNC, which would
    # destroy the hash chain this function exists to maintain.
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        with os.fdopen(fd, "a", closefd=True) as f:
            fd = -1
            f.write(f"{h} | {line}\n")
    finally:
        if fd >= 0:
            os.close(fd)
    # Narrow a log that already existed with wider perms (O_CREAT leaves an
    # existing file's mode untouched).
    secure_file_perms(log_path)

# ---------------------------------------------------------------------------
#  File security
# ---------------------------------------------------------------------------

def secure_file_perms(path: Path, mode: int = 0o600) -> None:
    """Set file to owner-read/write only.

    Prefer secure_write_bytes/secure_write_text for NEW files: chmod-after-write
    leaves a window (and, on a crash, a permanent state) where the file is
    world-readable. Use this only to fix up a file someone else created.
    """
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def secure_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Create a file with owner-only perms FROM THE START, then write it.

    The `write_bytes(...)` + `secure_file_perms(...)` sequence this replaces
    creates the file at 0644 under the default umask 022 and only narrows it
    afterwards. That is not merely a short race: if the process is killed
    between the two calls the file stays 0644 PERMANENTLY -- verified, and it
    applied to tx_*.unsigned and to tx_*.signed, i.e. a fully signed,
    relayable transaction left world-readable on disk.

    os.open() applies the mode at creation time, atomically. 0o600 has no
    group/other bits, so a umask cannot widen it (a umask can only clear bits),
    which makes this umask-safe as well -- confirmed 0o600 under umask 022.

    O_NOFOLLOW, for the same reason secure_delete_file has it. Without it,
    os.open FOLLOWS a symlink at `path` and writes THROUGH it -- demonstrated:
    a planted `broadcast_progress.json -> victim.txt` had victim.txt
    overwritten while the symlink itself survived, and the 0600 mode landed on
    the symlink's TARGET, so this function's own guarantee was applied to
    someone else's file. That is a write-where-I-want primitive for any local
    user who can create a name in a directory this toolchain writes to: a
    staging dir the operator made by hand under a shared path, or simply
    running the relayer from /tmp, where broadcast_progress.json has a
    predictable name.
    
    The delete primitive in this module already refused to follow symlinks and
    documented exactly this reasoning; the write primitive beside it did not.
    Same threat, same module, one of the pair defended.
    
    O_NOFOLLOW applies only to the FINAL path component, so a deliberately
    symlinked staging DIRECTORY (a common, legitimate setup -- stage onto
    another disk) still works. Only a symlink standing in for the output FILE
    is refused, which nothing legitimate does.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                     mode)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK):
            raise OSError(
                f"Refusing to write {path}: it is a symbolic link. Writing "
                f"through it would put this file's contents -- and its 0600 "
                f"mode -- on whatever it points at, which is how a local user "
                f"turns a predictable output name into a write primitive. "
                f"Remove the link and re-run."
            ) from e
        raise
    try:
        with os.fdopen(fd, "wb", closefd=True) as f:
            fd = -1
            f.write(data)
            f.flush()
            # fchmod on the OPEN descriptor, not chmod on the path: a
            # pre-existing file keeps its old mode through O_CREAT and must
            # still be narrowed, but doing it by path re-resolves the name and
            # could land the chmod on a file swapped in after the open.
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def secure_write_text(path: Path, data: str, mode: int = 0o600) -> None:
    """Text wrapper over secure_write_bytes -- see there for why this exists."""
    secure_write_bytes(path, data.encode(), mode)


def secure_delete_tree(path: Path) -> bool:
    """Overwrite every file in a directory tree, then remove the tree.

    The canonical "securely delete a directory" primitive. Cleanup code across
    this toolchain kept reaching for shutil.rmtree, which only unlinks: a prior
    run's tx_staging/ holds fully signed, RELAYABLE transactions, the unsigned
    tx sets, and a manifest with unscrubbed destinations and amounts. rmtree
    leaves every byte of that recoverable, which defeats the point of wiping it
    at all.

    Symlinks inside the tree are unlinked, never followed (secure_delete_file
    enforces that), so a symlink planted in a staging dir cannot redirect the
    overwrite onto an unrelated file.

    Returns True only if every file was securely erased AND the tree was
    removed, so callers can report honestly instead of assuming success.
    """
    path = Path(path)
    if not path.is_dir():
        return False
    ok = True
    # Deepest-first so directories are empty by the time we unlink them.
    for entry in sorted(path.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if entry.is_symlink() or entry.is_file():
            ok = secure_delete_file(entry) and ok
    try:
        shutil.rmtree(path)
        return ok
    except OSError:
        shutil.rmtree(path, ignore_errors=True)
        return False


def check_daemon_relay_egress(daemon_url: str,
                              proxies: Optional[Dict[str, str]] = None) -> dict:
    """Inspect where a monerod would actually BROADCAST a transaction.

    This closes the last hop nobody was checking. Every request this toolchain
    makes can be perfectly Tor-proxied and the transaction can still be handed
    to a daemon that relays it to clearnet peers -- which tells those peers
    which IP originated the transaction, defeating the whole pipeline. The code
    previously only PRINTED "verify it yourself", which is not verification.

    monerod exposes no RPC reporting its --tx-proxy setting (confirmed against
    0.18.3.1: get_info has no proxy field, and get_net_stats/get_limit are not
    even available on a restricted RPC). What IS observable is the peer list
    from get_connections: a relay peer reached over Tor/I2P has a .onion/.i2p
    address, while a clearnet peer shows a raw IP. That is a direct observation
    of where traffic leaves, not an inference from configuration.

    Returns a verdict dict -- deliberately NOT a bare bool, because "cannot
    tell" is a distinct and honest outcome from "clearnet":
      verdict: "tor" | "clearnet" | "offline" | "unknown"
      onion/clear: peer counts;  detail: human-readable reason
    Never raises: a failed probe reports "unknown" rather than blocking a
    broadcast on a diagnostic.
    """
    out = {"verdict": "unknown", "onion": 0, "clear": 0, "local": 0,
           "detail": ""}
    parsed = urlparse(daemon_url)
    host = (parsed.hostname or "127.0.0.1").lower()
    use_proxies = None
    if host not in _LOCALHOST_NAMES:
        if not proxies:
            out["detail"] = "remote daemon and no proxy available to query it"
            return out
        use_proxies = proxies

    endpoint = daemon_url.rstrip("/") + "/json_rpc"
    try:
        info = requests.post(
            endpoint, json={"jsonrpc": "2.0", "id": "0", "method": "get_info"},
            timeout=20, proxies=use_proxies).json().get("result") or {}
        if info.get("offline"):
            out["verdict"] = "offline"
            out["detail"] = "daemon is running --offline; it cannot relay at all"
            return out

        conns = requests.post(
            endpoint, json={"jsonrpc": "2.0", "id": "0", "method": "get_connections"},
            timeout=20, proxies=use_proxies).json().get("result") or {}
        peers = conns.get("connections")
        if peers is None:
            out["detail"] = ("daemon did not return a peer list (restricted RPC?) -- "
                             "cannot observe where it relays")
            return out
        # CLASSIFY BY monerod's OWN address_type, not by string-matching the
        # address. Observed on real monerod 0.18.3.1: every get_connections
        # entry carries address_type (epee's enum -- 1 ipv4, 2 ipv6, 3 i2p,
        # 4 tor), alongside address/host/ip/localhost/local_ip. Matching
        # ".onion" in a string was a guess at a format; this is the daemon
        # stating which network the connection is on. The string check stays as
        # a fallback for anything that does not report the field.
        out["local"] = 0
        for c in peers:
            addr = str(c.get("address") or c.get("host") or "").lower()
            atype = c.get("address_type")
            anon = (atype in (3, 4)) if isinstance(atype, int) else (
                ".onion" in addr or ".i2p" in addr)
            if anon:
                out["onion"] += 1
                continue
            # LOOPBACK IS NOT A CLEARNET EXPOSURE, AND IT IS NOT SAFE EITHER.
            #
            # A peer on 127.0.0.1 is another daemon on this same machine, so
            # nothing left the host by reaching it -- but that daemon has its
            # own peers, and its egress is not observable from here. Counting
            # it as "clearnet" is a false alarm; counting it as "tor" would be
            # a lie. It is genuinely unknown, and saying so is the only honest
            # option. This mattered because every false alarm pushes the
            # operator toward --allow-clearnet-relay, which switches the check
            # off for the case it exists to catch.
            if c.get("localhost") is True or addr.startswith(("127.", "[::1]", "::1")):
                out["local"] += 1
            elif addr:
                out["clear"] += 1
        if out["clear"]:
            out["verdict"] = "clearnet"
            out["detail"] = (f"{out['clear']} clearnet peer(s) vs {out['onion']} "
                             f"anonymous -- the tx would be relayed to raw IPs")
        elif out["onion"]:
            out["verdict"] = "tor"
            out["detail"] = (f"all {out['onion']} non-local relay peer(s) are "
                             f"Tor/I2P"
                             + (f" ({out['local']} loopback peer(s) ignored)"
                                if out["local"] else ""))
        elif out["local"]:
            out["detail"] = (f"only loopback peer(s) ({out['local']}): this daemon "
                             f"relays to another daemon on this machine, whose own "
                             f"egress cannot be observed from here")
        else:
            out["detail"] = "daemon has no peer connections yet; nothing to observe"
    except Exception as e:
        out["detail"] = f"probe failed: {str(e)[:60]}"
    return out


def secure_mkdir(path: Path, mode: int = 0o700) -> None:
    """Create a directory owner-only, including any parents.

    plain mkdir() produces 0755 -- world-readable and traversable. The FILES
    inside are 0600 so their contents stay private, but the directory listing
    itself is a real metadata leak for this toolchain: any local user could
    enumerate a staging dir and learn how many transactions were signed, when,
    and hence that a Monero cold-signing operation ran at all. Unlinkability is
    the entire point here, so that is not acceptable even with safe file modes.

    Two details this handles that a bare mkdir(mode=...) does not:
      * With parents=True, Python applies `mode` only to the FINAL directory;
        intermediate parents are created with the default 0777 & ~umask. Each
        level is therefore chmod'ed explicitly.
      * exist_ok=True silently keeps a pre-existing directory's mode, so an
        already-0755 staging dir would stay 0755. It is narrowed too.
    """
    path = Path(path)
    created = []
    for parent in list(path.parents)[::-1]:
        if not parent.exists():
            created.append(parent)
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    for d in created + [path]:
        try:
            if d.is_dir():
                os.chmod(d, mode)
        except OSError:
            pass


def atomic_write_json(obj, path: Path, perms: int = 0o600) -> None:
    """Write JSON atomically: tmp -> fsync -> rename. Sets secure perms.

    On ANY failure the partial .tmp is securely erased before the exception
    propagates. Without that, a Ctrl-C between the write and the rename left
    e.g. 'thor_pairs_batch.json.tmp' on disk holding the deposit address and
    memo in plaintext -- and paranoia's wipe pattern 'thor_pairs_*.json' does
    NOT match a '.json.tmp' suffix, so nothing ever cleaned it up. These
    scripts install SIGINT handlers, so an interrupted write is a realistic
    path, not a theoretical one. BaseException (not Exception) because
    KeyboardInterrupt is exactly the case that leaked.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        # Created 0600 up front, not chmod'ed afterwards: the tmp holds the
        # same plaintext as the final file, so a world-readable window (or a
        # crash leaving it 0644 forever) exposes exactly what the rename was
        # meant to protect.
        secure_write_bytes(tmp, json.dumps(obj, indent=2).encode(), perms)
        os.replace(tmp, path)
    except BaseException:
        secure_delete_file(tmp)
        raise
    with open(path) as f:
        json.load(f)


def atomic_write_text(data: str, path: Path, perms: int = 0o600) -> None:
    """Write text atomically: tmp -> fsync -> rename. Sets secure perms.

    Same partial-.tmp erasure as atomic_write_json -- see there for why.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        secure_write_text(tmp, data, perms)   # 0600 at creation, see above
        os.replace(tmp, path)
    except BaseException:
        secure_delete_file(tmp)
        raise

# ---------------------------------------------------------------------------
#  Proxy validation
# ---------------------------------------------------------------------------

def validate_proxy(proxy_url: str) -> Dict[str, str]:
    """Validate and return a proxy dict, or abort if format is wrong.

    ONLY socks5h:// is accepted. Plain socks5:// resolves DNS locally,
    leaking every destination hostname to the ISP's DNS resolver.
    """
    if proxy_url.startswith("socks5://") and not proxy_url.startswith("socks5h://"):
        sys.exit(
            f"[!] CRITICAL: socks5:// leaks DNS locally!\n"
            f"    Use socks5h:// so DNS resolves through the proxy.\n"
            f"    Change: {proxy_url} -> {proxy_url.replace('socks5://', 'socks5h://')}"
        )
    if not SOCKS_RE.match(proxy_url):
        sys.exit(
            f"[!] Invalid proxy format: {proxy_url}\n"
            f"    Expected: socks5h://host:port  (NOT socks5://)"
        )
    return {"http": proxy_url, "https": proxy_url}

# ---------------------------------------------------------------------------
#  Tor verification
# ---------------------------------------------------------------------------

@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=3, max=20), reraise=True)
def _verify_tor_once(proxy: Dict[str, str]) -> dict:
    # Same falsy-proxies guard safe_get carries. requests treats proxies={} as
    # NO proxy and connects directly, so an empty dict would send a clearnet
    # request to check.torproject.org -- announcing this host's real IP to the
    # very service being used to prove it is hidden. It would then abort
    # (IsTor false), so the outcome is fail-closed, but the packet has already
    # left. Every other network call in this toolchain has this guard; these
    # two were the ones the lesson was never applied to.
    if not proxy:
        sys.exit("[!] Tor verification called without proxies — that request "
                 "would go clearnet. Aborting.")
    r = requests.get(CHECK_TOR_URL, timeout=15, proxies=proxy)
    r.raise_for_status()
    return r.json()


def verify_tor(proxy: Dict[str, str]) -> None:
    """Verify we are exiting through Tor. Aborts on failure.

    Network errors are retried up to 4x by _verify_tor_once; reraise=True
    ensures the real requests exception (not an opaque tenacity RetryError)
    reaches this try/except once retries are exhausted, so the operator
    gets the same clear abort message as every other Tor-failure path.
    """
    try:
        data = _verify_tor_once(proxy)
    except requests.exceptions.InvalidSchema as e:
        # Not a network problem: requests cannot speak SOCKS without PySocks,
        # so EVERY socks5h:// request dies here. Reporting that as a "network
        # error" sent operators debugging their Tor daemon when the actual fix
        # is a missing dependency. Fail closed, but say what is really wrong.
        integrity_log("tor", "verify_fail:socks_support_missing")
        sys.exit(
            f"[!] SOCKS support is missing, so nothing can be routed through Tor:\n"
            f"    {str(e)[:80]}\n"
            f"    Fix: pip install PySocks   (or: pip install -r requirements.txt)\n"
            f"    Aborting rather than risk a clearnet connection."
        )
    except requests.RequestException as e:
        integrity_log("tor", f"verify_fail:{type(e).__name__}")
        sys.exit(f"[!] Cannot verify Tor (network error): {str(e)[:80]}. Aborting for safety.")
    if not data.get("IsTor"):
        integrity_log("tor", "LEAK_DETECTED")
        sys.exit("[!] Tor leak detected - traffic NOT exiting via Tor. Aborting.")
    integrity_log("tor", "verified_ok")


def tor_recheck(proxy: Dict[str, str], stage: str = "recheck") -> None:
    """Re-verify Tor mid-operation. Logs but doesn't retry as aggressively."""
    if not proxy:
        sys.exit("[!] Tor recheck called without proxies — that request would go "
                 "clearnet. Aborting.")
    try:
        r = requests.get(CHECK_TOR_URL, timeout=10, proxies=proxy)
        r.raise_for_status()
        if not r.json().get("IsTor"):
            integrity_log("tor", f"LEAK_mid_{stage}")
            sys.exit(f"[!] Tor leak detected during {stage} - aborting.")
    except requests.RequestException:
        integrity_log("tor", f"recheck_fail_{stage}")
        sys.exit(f"[!] Cannot verify Tor during {stage} - aborting for safety.")

# ---------------------------------------------------------------------------
#  NEWNYM (Tor circuit rotation)
# ---------------------------------------------------------------------------

_NEWNYM_CONSECUTIVE_FAILURES = 0
_NEWNYM_MAX_FAILURES = 3


#: In-call retries before a REQUIRED rotation is declared impossible. Control
#: -port contention is genuinely transient, and aborting a multi-hour peel chain
#: on one blip would be brittle -- so the tolerance lives HERE, inside the call
#: that must succeed, rather than in a counter that lets the caller proceed.
_NEWNYM_REQUIRED_ATTEMPTS = 3
_NEWNYM_RETRY_BACKOFF = 2.0


def newnym(ctrl: str = "/var/run/tor/control", required: bool = False) -> bool:
    """Request a new Tor circuit. With required=True: rotate, or STOP.

    WHAT THIS USED TO DO, AND WHY IT WAS A FAKE GUARANTEE. Every caller passing
    required=True says in its own comment that the rotation must happen -- "a
    silent failure leaves the subaddress creation on the same circuit as
    whatever follows it", "a silently-failed rotation puts every quote in the
    batch on ONE circuit". None of them check the return value; all twelve rely
    on this function to stop the process. It did not.

    A failure incremented a PROCESS-GLOBAL consecutive counter and returned
    False, aborting only on the third strike. So:

      * the first TWO required rotations could silently not happen, and the
        operation continued on the old circuit with nothing printed at all --
        only an integrity_log line nobody reads mid-run;
      * a script that calls this FEWER than three times could never abort.
        create_receive_wallet calls it exactly once, so required=True there was
        decorative: with no control socket the rotation simply did not occur
        and the receive address was minted on the un-rotated circuit;
      * any success reset the counter, so an alternating fail/success pattern
        never aborted -- every failed rotation in it was silent, forever.

    Reproduced before changing: one call with required=True returned False,
    printed nothing, and did not abort; three consecutive calls leaked two
    silent non-rotations before the third stopped.

    Now required=True retries in-call (transient control-port contention is
    real) and then ABORTS if the circuit could not be rotated, independent of
    any counter. required=False stays best-effort but SAYS SO on every failure
    instead of staying quiet until the third.

    WHAT IT STILL CANNOT PROMISE: Tor rate-limits NEWNYM and answers 250 OK
    even when it coalesces two signals sent close together, so a True here
    means "Tor accepted the request", not "this stream is provably on a new
    circuit". The 5s settle below narrows that window; it does not close it,
    and no control-port command exposes the guarantee.
    """
    global _NEWNYM_CONSECUTIVE_FAILURES
    attempts = _NEWNYM_REQUIRED_ATTEMPTS if required else 1
    last_err = None
    for attempt in range(1, attempts + 1):
        try:
            from stem import Signal as StemSignal
            from stem.control import Controller
            with Controller.from_socket_file(ctrl) as c:
                c.authenticate()
                c.signal(StemSignal.NEWNYM)
            time.sleep(5)
            _NEWNYM_CONSECUTIVE_FAILURES = 0
            return True
        except Exception as e:                               # noqa: BLE001
            last_err = e
            if attempt < attempts:
                integrity_log("tor", f"NEWNYM_retry:{attempt}:{type(e).__name__}")
                time.sleep(_NEWNYM_RETRY_BACKOFF * attempt)

    _NEWNYM_CONSECUTIVE_FAILURES += 1
    integrity_log("tor",
                  f"NEWNYM_fail:{_NEWNYM_CONSECUTIVE_FAILURES}:{str(last_err)[:40]}")
    if required:
        # ABORT NOW, not on some later strike. The caller asked for a rotation
        # it is about to depend on; proceeding without it is the correlation
        # the rotation exists to break.
        sys.exit(
            f"[!] Tor circuit rotation FAILED after {attempts} attempts: "
            f"{str(last_err)[:120]}\n"
            f"    This operation requires a fresh circuit and will not proceed "
            f"on the old one.\n"
            f"    Check that Tor is running with a ControlSocket at {ctrl} "
            f"(or pass the right path), that this user can read it, and that "
            f"'stem' is installed.")
    # Best-effort path: still say it, every time. A rotation that did not
    # happen is an OPSEC degradation whether or not it is the third one.
    print(f"  [!] Tor circuit rotation failed ({str(last_err)[:60]}). This "
          f"operation continues on the SAME circuit as the previous one.")
    if _NEWNYM_CONSECUTIVE_FAILURES >= _NEWNYM_MAX_FAILURES:
        print(f"  [!] NEWNYM has now failed {_NEWNYM_CONSECUTIVE_FAILURES} "
              f"consecutive times. Tor circuit rotation is NOT working.")
    return False

# ---------------------------------------------------------------------------
#  Retry-wrapped HTTP
# ---------------------------------------------------------------------------

@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=4, max=30), reraise=True)
def safe_get(url: str, proxies: Dict[str, str] = None) -> dict:
    # `not proxies`, NOT `is None`. requests treats proxies={} exactly like no
    # proxy at all and connects DIRECTLY, so an empty dict slipped past an
    # `is None` guard and produced a real clearnet request -- confirmed by
    # observing one actually reach the target. Any falsy value must abort.
    if not proxies:
        sys.exit("[!] safe_get called without proxies — clearnet leak. Aborting.")
    r = requests.get(url, timeout=20, proxies=proxies)
    r.raise_for_status()
    return r.json()


@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=4, max=30), reraise=True)
def safe_post(url: str, payload: dict, proxies: Dict[str, str] = None) -> dict:
    if not proxies:      # proxies={} means DIRECT in requests -- see safe_get
        sys.exit("[!] safe_post called without proxies — clearnet leak. Aborting.")
    r = requests.post(url, json=payload, timeout=25, proxies=proxies)
    r.raise_for_status()
    return r.json()

# ---------------------------------------------------------------------------
#  RPC connection (monero-wallet-rpc)
# ---------------------------------------------------------------------------

_LOCALHOST_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}


class MoneroRPC:
    """Wrapper around monero-python that exposes both high-level Wallet
    methods and raw JSON-RPC calls via the backend.

    OPSEC: monero-python's JSONRPCWallet uses requests internally but does
    NOT support SOCKS proxy configuration. Connections to non-localhost
    hosts go clearnet, leaking the operator's IP to the Monero node.
    We enforce localhost-only, or patch the session with proxy support.
    """

    def __init__(self, url: str, proxy_url: Optional[str] = None):
        from monero.wallet import Wallet as XMRWallet
        from monero.backends.jsonrpc import JSONRPCWallet
        parsed = urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 18083

        if host.lower() not in _LOCALHOST_NAMES:
            if not proxy_url:
                sys.exit(
                    f"[!] RPC endpoint {host}:{port} is NOT localhost.\n"
                    f"    monero-python's JSONRPCWallet has no proxy support.\n"
                    f"    Connection would be clearnet, leaking your IP to the node.\n"
                    f"    Either: (a) use 127.0.0.1 with a local RPC, or\n"
                    f"            (b) tunnel the RPC through Tor externally (socat/ssh)."
                )
        # PROXY AT CONSTRUCTION, and verify it took.
        #
        # This used to build the backend unproxied and then patch
        # `self._backend._session.proxies`. Two things were wrong with that,
        # and the second is why this is not a cosmetic fix:
        #
        #  1. monero-python 1.1.1 names the attribute `session`, not
        #     `_session`, so the hasattr was always False and the fail-closed
        #     else-branch fired unconditionally. Every non-localhost --rpc
        #     aborted, and the docstring's "or patch the session with proxy
        #     support" described code that could not run.
        #
        #  2. Patching the SESSION would not have worked either, and would
        #     have been WORSE than the abort. JSONRPCWallet.raw_request passes
        #     `proxies=self.proxies` on every single request, and a
        #     per-request proxies argument OVERRIDES the Session's. Measured:
        #     with session.proxies set to the SOCKS URL, the request still
        #     opened a plain HTTPConnection straight to the remote host --
        #     a clearnet connection to a Monero node, which is precisely the
        #     IP leak this whole guard exists to prevent.
        #
        # JSONRPCWallet accepts proxy_url= and stores it in self.proxies, so
        # pass it there. Then CHECK it landed before any request goes out --
        # the lesson of (2) is that an assignment that looks right is not
        # evidence the traffic is proxied.
        if host.lower() in _LOCALHOST_NAMES:
            # Loopback: never wrap in Tor. The daemon behind it syncs over Tor
            # already; sending 127.0.0.1 through a SOCKS proxy would fail and
            # gains nothing.
            self._backend = JSONRPCWallet(host=host, port=port)
        else:
            self._backend = JSONRPCWallet(host=host, port=port,
                                          proxy_url=proxy_url)
            applied = getattr(self._backend, "proxies", None) or {}
            if not any(str(v) == str(proxy_url) for v in applied.values()):
                integrity_log("rpc", f"non_local_rpc:{host}:{port}:proxy_VERIFY_FAILED")
                sys.exit(
                    f"[!] The proxy did not attach to the RPC client for "
                    f"{host}:{port}.\n"
                    f"    Refusing to continue: the connection would be clearnet and\n"
                    f"    would leak your IP to that node. Tunnel the RPC externally\n"
                    f"    (socat/ssh) and point at 127.0.0.1 instead."
                )
            integrity_log("rpc", f"non_local_rpc:{host}:{port}:proxy_applied")

        self._wallet = XMRWallet(self._backend)

    @property
    def accounts(self):
        return self._wallet.accounts

    def new_account(self, **kwargs):
        return self._wallet.new_account(**kwargs)

    def raw_request(self, method: str, params: dict) -> dict:
        """Send a raw JSON-RPC request to monero-wallet-rpc."""
        return self._backend.raw_request(method, params)

    def new_subaddress_indexed(self, account_index: int = 0, label: str = "") -> tuple:
        """Create a new subaddress and return (address_str, subaddress_index).

        Goes STRAIGHT to wallet-rpc's create_address, not through
        monero-python's `self._wallet.accounts[account_index]`.

        That list is a snapshot taken when the Wallet object was built. Every
        other call in this toolchain goes through raw_request(), so an account
        created after construction is invisible to it -- and creating one is
        exactly what create_receive_wallet does immediately before asking for
        the subaddress:

            acct = rpc.raw_request("create_account", ...)   # -> account_index 1
            rpc.new_subaddress_indexed(account_index=1)     # accounts == [0]
            -> IndexError: list index out of range

        Reproduced against real monero-wallet-rpc 0.18.3.1 on a fresh wallet.
        So the DEFAULT receive path -- the fresh-account-per-receive behaviour
        that keeps a run's change off the wallet's primary address -- crashed
        on every real wallet. It survived because every offline suite supplies
        a fake RPC that stubs this method, so the stale-cache dependency was
        never executed: the tests exercised the caller, never the call.

        create_address is the same operation without the cache. It returns
        {"address": ..., "address_index": N}; the index is validated rather
        than defaulted, because a wrong subaddress index is written into the
        receive bundle and later used to poll for the payment.
        """
        res = self.raw_request("create_address", {
            "account_index": int(account_index), "label": label or "",
        }) or {}
        addr = res.get("address")
        idx = res.get("address_index")
        if not isinstance(addr, str) or not addr:
            raise RuntimeError(
                f"create_address returned no address for account {account_index}")
        # AND IT MUST LOOK LIKE AN ADDRESS. "not empty" was the whole check, so
        # any non-empty string came back as a destination: found by feeding
        # malformed-but-successful RPC answers to every function that consumes
        # one. The wallet is not expected to lie, but the failure mode if it
        # does is the bad kind -- the planner builds a whole distribution
        # around the value and monerod only rejects it at transfer time, by
        # which point earlier hops have already relayed.
        #
        # Length and alphabet only. Full checksum validation lives in
        # validate_address and needs an RPC round trip per address; this is the
        # cheap invariant that a subaddress is 95 base58 characters.
        if len(addr) < 90 or len(addr) > 110 or any(c not in _B58 for c in addr):
            raise RuntimeError(
                f"create_address returned {addr[:12]!r}... for account "
                f"{account_index}, which is not a Monero address (length "
                f"{len(addr)}). Refusing to plan a distribution around it.")
        if isinstance(idx, bool) or not isinstance(idx, int) or idx < 0:
            raise RuntimeError(
                f"create_address returned no usable address_index "
                f"({idx!r}) for account {account_index}. Refusing to guess: the "
                f"index is written into the receive bundle and is what the "
                f"watcher polls for the payment.")
        return addr, idx

    def new_subaddress(self, account_index: int = 0, label: str = "") -> str:
        """Create a new subaddress and return its string address.

        Thin wrapper over new_subaddress_indexed so both share one
        implementation -- it carried its own copy of the stale-cache lookup,
        which is how one of the pair could be fixed while the other stayed
        broken."""
        addr, _idx = self.new_subaddress_indexed(account_index, label)
        return addr

    def get_subaddress_balance(self, account_index: int = 0,
                               address_index: int = 0) -> tuple:
        """Return (total, unlocked) balance for a specific subaddress in atomic units."""
        res = self.raw_request("get_balance", {
            "account_index": account_index,
            "address_indices": [address_index],
        })
        per_sub = res.get("per_subaddress", [])
        if not per_sub:
            return 0, 0
        # VERIFY the entry describes the subaddress we asked about.
        #
        # This took per_sub[0] positionally and read its balance, without ever
        # checking the entry's own account_index/address_index. The answer is
        # then reported as "the balance of the address you are watching" --
        # receive_watch prints "PAID" on it, GhostSpiral plans a spend from it.
        # A response whose first element describes a DIFFERENT subaddress would
        # be believed silently.
        #
        # Measured against real monero-wallet-rpc 0.18.3.1: asking for an index
        # the wallet does not have returns HTTP 200 with a SYNTHESISED
        # zero-balance entry carrying that index -- so the RPC is comfortable
        # answering about things that do not exist, and the shape of the reply
        # is not self-evidently trustworthy. Match the indices explicitly and
        # fail closed rather than pick an element by position.
        want_a, want_i = int(account_index), int(address_index)
        for entry in per_sub:
            if (entry.get("address_index") == want_i
                    and entry.get("account_index", want_a) == want_a):
                return entry.get("balance", 0), entry.get("unlocked_balance", 0)
        raise RuntimeError(
            f"get_balance answered about subaddress(es) "
            f"{[e.get('address_index') for e in per_sub]} when asked about "
            f"account {want_a} index {want_i}. Refusing to report another "
            f"address's balance as this one's.")


@contextlib.contextmanager
def run_lock(path: Path, what: str = "GhostSpiral"):
    """Refuse to run twice at once. Held by the KERNEL, so it cannot go stale.

    The version this replaces was

        if lock_path.exists(): sys.exit(...)
        lock_path.write_text(str(os.getpid()))

    which is check-then-act: two runs started milliseconds apart both saw no
    lock and both went on to spend the same wallet. The console starts jobs
    from threads, so that is an ordinary race. The PID it wrote was never read
    either, so a crash left a file whose only remedy was "delete the lock file
    manually" -- advice that teaches an operator to clear the guard
    reflexively, which is exactly what makes the race dangerous.

    THE FIRST REWRITE OF THIS WAS ALSO WRONG, and the way it was wrong is worth
    keeping. It used O_CREAT|O_EXCL (atomic, correct) plus a PID-liveness check
    to reclaim a stale lock, and -- to avoid locking an operator out when the
    OS recycled a PID -- treated a holder whose /proc cmdline did not mention
    the tool as dead. Under test, TWELVE concurrent acquirers all won: every
    holder's cmdline failed that match, so everyone judged everyone else stale.
    A heuristic added to soften a lockout had quietly removed the lock.

    flock has none of those problems. The kernel drops it when the holding
    process dies, however it dies, so there is no stale state to detect, no PID
    to inspect and no reuse to guess about. This module already relies on the
    same primitive for the integrity chain.

    The file is NOT unlinked on release, deliberately: unlinking it while
    another process is blocked on it leaves that process holding a lock on a
    deleted inode while a third creates a fresh file and locks that instead --
    two winners again, by a different route. An empty marker file costs
    nothing, is gitignored, and paranoia_mode wipes it.
    """
    path = Path(path)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            holder = ""
            try:
                holder = f" (pid {os.read(fd, 64).decode('utf-8', 'replace').split()[0]})"
            except Exception:                                # noqa: BLE001
                pass
            os.close(fd)
            sys.exit(
                f"[!] {what} is already running{holder}.\n"
                f"    Two runs spending the same wallet at once fight over the "
                f"same outputs and\n"
                f"    can leave a mix half-executed. Wait for it, or stop it "
                f"first.\n"
                f"    Lock: {path}\n"
                f"    (This lock is held by the kernel — if the other run has "
                f"really died it is\n"
                f"     already released, so there is never anything to delete "
                f"by hand.)")
        try:
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n{what}\n".encode())
        except OSError:
            pass                # informational only; the flock is the lock
        secure_file_perms(path)
        yield path
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass


def create_fresh_account(rpc, label: str = "") -> int:
    """Create a new wallet account and return its index. FAILS CLOSED.

    Both callers wrote this inline as

        acct = rpc.raw_request("create_account", {...})
        idx  = int((acct or {}).get("account_index", 0))

    inside a try/except that exits on an EXCEPTION -- and GhostSpiral's except
    block says, in as many words, that "silently falling back to account 0
    would put the run's change on the wallet's identity address while the
    operator believed it had been rotated away". The line above it did exactly
    that for a call that SUCCEEDS but answers with a shape nobody checked: a
    dict without account_index, a None result, an older or proxied wallet-rpc.
    `.get(..., 0)` turns every one of those into account 0, whose subaddress 0
    IS the wallet's primary address, and GhostSpiral then prints "Mix runs in a
    fresh account (0); the run's change stays off the wallet's primary
    address" -- the exact opposite of what happened.

    Three checks, because each catches a different way the answer can be wrong:

      * account_index must be PRESENT. Absent is not zero.
      * it must be a non-negative int, and not a bool (True == 1 in Python, and
        every index guard in this repo has needed that exclusion).
      * it must not be ZERO. Account 0 always pre-exists, so a newly CREATED
        account is never index 0 -- verified against real monero-wallet-rpc
        0.18.3.1, where the first create_account on a brand-new wallet returns
        1, then 2, then 3. A create that reports 0 is reporting something that
        cannot have happened, and 0 is precisely the value that would hurt.

    Raises RuntimeError; callers turn that into their own refusal message.
    """
    res = rpc.raw_request("create_account", {"label": label or ""})
    if not isinstance(res, dict) or "account_index" not in res:
        raise RuntimeError(
            f"create_account returned no account_index "
            f"({type(res).__name__}); the wallet did not say which account it "
            f"made.")
    idx = res["account_index"]
    if isinstance(idx, bool) or not isinstance(idx, int) or idx < 0:
        raise RuntimeError(
            f"create_account returned an unusable account_index {idx!r}.")
    if idx == 0:
        raise RuntimeError(
            "create_account reported the NEW account as index 0. Account 0 "
            "always pre-exists, so a freshly created account is never 0 -- and "
            "0 is the wallet's primary-address account, the one value that "
            "must never be accepted here by accident.")
    return idx


def connect_rpc(url: str, proxy_url: Optional[str] = None) -> MoneroRPC:
    """Connect to monero-wallet-rpc extracting host and port from URL.

    If the RPC host is non-localhost, proxy_url is required or the
    connection is rejected to prevent clearnet IP leaks.
    """
    return MoneroRPC(url, proxy_url=proxy_url)


def daemon_fee_estimate(daemon_url: str, proxies: Optional[Dict[str, str]] = None) -> dict:
    """Return monerod's get_fee_estimate 'result' dict, or {} on any failure.

    The result carries a base per-byte 'fee' and (on modern monerod) an explicit
    per-priority 'fees' array -- callers should prefer the array so the estimate
    matches exactly what transfer_split charges at a given priority.

    get_fee_estimate is a monerod (DAEMON) json_rpc method; monero-wallet-rpc
    does NOT expose it, so callers wanting a live fee estimate must query the
    daemon endpoint (e.g. :18081), not the wallet-rpc (:18083). A localhost
    daemon is queried directly; a non-localhost daemon is queried through the
    given Tor proxies, or refused (returns {}) if none were provided, so the
    query is never leaked to a remote node over clearnet.
    """
    parsed = urlparse(daemon_url)
    host = (parsed.hostname or "127.0.0.1").lower()
    use_proxies = None
    if host not in _LOCALHOST_NAMES:
        if not proxies:
            return {}
        use_proxies = proxies
    try:
        endpoint = daemon_url.rstrip("/") + "/json_rpc"
        r = requests.post(
            endpoint,
            json={"jsonrpc": "2.0", "id": "0", "method": "get_fee_estimate"},
            timeout=20, proxies=use_proxies,
        )
        r.raise_for_status()
        return r.json().get("result", {}) or {}
    except Exception:
        return {}

# ---------------------------------------------------------------------------
#  Resource sentinel
# ---------------------------------------------------------------------------

def resource_check(min_disk_gb: float = 2.0, max_ram_pct: float = 90.0) -> bool:
    """Return True if resources are OK. False if the system is stressed.

    Raises ResourceCheckUnavailable when psutil is not installed, rather than
    letting a bare ModuleNotFoundError traceback escape from every script's
    first line. The caller decides what an un-runnable sentinel means; this
    function will not answer "fine" for a check it never performed.
    """
    try:
        import psutil
    except ImportError as e:
        raise ResourceCheckUnavailable(str(e)) from e
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage(".")
    return mem.percent < max_ram_pct and disk.free > min_disk_gb * 1024 ** 3


class ResourceCheckUnavailable(RuntimeError):
    """psutil is missing, so the resource sentinel could not run at all."""


def require_resources(min_disk_gb: float = 2.0, max_ram_pct: float = 90.0) -> None:
    """Abort if resources are below threshold.

    A missing psutil no longer crashes with a raw traceback from the first line
    of every script. It is reported as what it is -- the sentinel DID NOT RUN --
    and the run continues, because low disk is an operational risk rather than
    a security property. Saying nothing here would be the fake-success pattern:
    the header advertises a resource sentinel, so if it cannot run, say so.
    """
    try:
        ok = resource_check(min_disk_gb, max_ram_pct)
    except ResourceCheckUnavailable:
        integrity_log("env", "resource_sentinel_unavailable:psutil_missing")
        print("  [!] Resource sentinel DISABLED — psutil is not installed, so free "
              "disk and RAM were NOT checked (pip install psutil). Continuing.")
        return
    if not ok:
        sys.exit(f"[!] Resources low (disk<{min_disk_gb}GB or RAM>{max_ram_pct}%) - aborting.")

# ---------------------------------------------------------------------------
#  Signal handling for graceful shutdown
# ---------------------------------------------------------------------------

_SHUTDOWN_REQUESTED = False


def _shutdown_handler(signum, frame):
    global _SHUTDOWN_REQUESTED
    _SHUTDOWN_REQUESTED = True
    integrity_log("signal", f"shutdown_requested_sig={signum}")
    print(f"\n[!] Shutdown signal received ({signum}). Finishing current operation...")


def disable_core_dumps() -> bool:
    """Forbid this process from writing a core file. Returns True if enforced.

    A core dump is a copy of process memory written to DISK. These processes
    hold the wallet password (and, in the wallet-rpc client path, key material)
    in memory, so a crash on a machine with the common `ulimit -c unlimited`
    default would persist that secret to a file nothing here ever wipes.
    Setting RLIMIT_CORE to 0 is the standard prevention and costs nothing.

    Note this only binds THIS process and children it spawns -- it cannot
    constrain a separately-launched monerod/monero-wallet-rpc.
    """
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    except (ImportError, ValueError, OSError):
        return False


def install_signal_handlers():
    """Install handlers for SIGINT and SIGTERM, and forbid core dumps.

    Core-dump suppression lives here because every script calls this at
    startup, so it is the one hook that reliably covers them all.
    """
    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    disable_core_dumps()


def shutdown_requested() -> bool:
    return _SHUTDOWN_REQUESTED

# ---------------------------------------------------------------------------
#  Secrets must not travel on a command line
# ---------------------------------------------------------------------------

def _argv_supplied(value) -> bool:
    """Did the operator actually put something on the command line?

    Not `value is not None`. argparse defaults --wallet-password to "", so that
    test is true on EVERY run and would warn about an exposure that did not
    happen -- and a warning that fires when nothing is wrong is a warning
    operators learn to scroll past. An empty string on a command line also
    exposes nothing, so it is not "supplied" for the purpose of this warning.
    """
    return value is not None and str(value) != ""


def env_or_argv(env_name: str, argv_value, label: str, cast=None,
                allow_empty: bool = False):
    """Take a sensitive value from the environment, falling back to argv.

    /proc/<pid>/cmdline is mode 0444 -- readable by EVERY account on the host,
    for the whole life of the process -- while /proc/<pid>/environ is 0400,
    owner only. Both measured on Linux, not assumed. A command line is
    therefore a broadcast; an environment is merely not a secret store.

    This exists because the same defect kept reappearing. The rule was written
    for the wallet password, then the off-ramp amount went on argv, then the
    BTC entry ADDRESS and the swap amounts. Every one of those is a value this
    toolchain deliberately keeps out of the integrity chain on the grounds that
    it deanonymises the operator -- and then published it to `ps`. One helper,
    so the next caller cannot half-apply the lesson.

    Environment wins over argv (matching the wallet-password precedence
    everywhere else). An argv value still works, because an operator running a
    tool by hand should not be blocked, but it warns and chains the warning.
    Returns None when neither is set; the caller decides whether that is fatal.

    allow_empty exists for ONE real case: an empty WALLET PASSWORD is
    legitimate and common, so GS_WALLET_PASSWORD="" must mean "the password is
    empty", not "unset". For an amount or an address an empty environment
    variable is how a shell unsets a value, so the default treats it as absent.
    Getting this backwards silently swaps which of two values is used for a
    spend key, which is why it is a parameter rather than a judgement call left
    to each caller -- there were three hand-rolled copies of this function
    before it existed, and all three had drifted.
    """
    raw = os.environ.get(env_name)
    if raw is not None and (allow_empty or raw != ""):
        # The environment WINS, but argv is still argv. When both are supplied
        # the value is sitting in /proc/<pid>/cmdline (mode 0444) for the
        # lifetime of the process regardless of which one this function
        # returns, and the old `if env: return / elif argv: warn` shape meant
        # the warning -- and the integrity-chain entry -- were skipped in
        # exactly that case. It also discarded the operator's typed value in
        # silence, so a mismatch between the two was never surfaced.
        if _argv_supplied(argv_value):
            print(f"  [!] {label} was ALSO passed on the command line, where any "
                  f"local user can read it via ps or /proc/<pid>/cmdline (mode "
                  f"444). {env_name} takes precedence and was used; the "
                  f"command-line copy is still exposed.")
            if str(argv_value) != str(raw):
                print(f"  [!] They DISAGREE — the environment value was used. "
                      f"Re-run with only one of them if that is not what you "
                      f"meant.")
            integrity_log("argv", f"warn:{env_name}_on_argv_and_env")
        return cast(raw) if cast else raw
    if _argv_supplied(argv_value):
        print(f"  [!] {label} was passed on the command line, where any local "
              f"user can read it via ps or /proc/<pid>/cmdline (mode 444). "
              f"Prefer {env_name}=... .")
        integrity_log("argv", f"warn:{env_name}_on_argv")
    return argv_value


# ---------------------------------------------------------------------------
#  Swap quote sanity: is this rate anywhere near reality?
# ---------------------------------------------------------------------------
CG_PRICE_URL = ("https://api.coingecko.com/api/v3/simple/price"
                "?ids=monero,bitcoin&vs_currencies=btc")


def btc_per_xmr_oracle(proxies: Optional[Dict[str, str]] = None, getter=None):
    """Current BTC/XMR rate from an independent oracle, or None if unreachable.

    Returns None rather than a hard-coded rate ON PURPOSE. An earlier build
    returned Decimal("0.003") on any failure -- CoinGecko is frequently
    unreachable over Tor -- and the caller then measured real quotes against
    that invented baseline. A quote deviating 30% from a number we made up is
    not a slippage warning; it is noise that either hides a bad quote or
    condemns a good one. None means "no cross-check available", and callers
    must say so out loud rather than pretend the check ran.

    `getter` lets a caller pass its OWN safe_get. That keeps each tool's
    network call on the seam its tests already stub -- moving the fetch in here
    unconditionally would have made this reach the real network from inside
    suites that believed they had stubbed it out.
    """
    fetch = getter or safe_get
    try:
        p = fetch(CG_PRICE_URL, proxies)
        rate = Decimal(str(p["monero"]["btc"]))
        if rate <= 0:
            raise ValueError("non-positive rate")
        integrity_log("swap", "price_oracle_ok")
        return rate
    except Exception as e:                                   # noqa: BLE001
        integrity_log("swap", f"price_oracle_fail:{type(e).__name__}")
        return None


def quote_deviation(expected_out, amount_in, rate_in_per_out):
    """How far a swap quote sits from the oracle, as a fraction (0.10 = 10%).

    Returns None when the comparison cannot be made honestly -- no oracle, a
    non-positive rate, or an unreadable quote -- so a caller can never mistake
    "could not check" for "checked and fine". Deliberately pure: no network, no
    logging of the values themselves (a quote amount is among the most
    linkable numbers in the pipeline).
    """
    if rate_in_per_out is None:
        return None
    try:
        exp = Decimal(str(expected_out))
        amt = Decimal(str(amount_in))
        rate = Decimal(str(rate_in_per_out))
    except Exception:                                        # noqa: BLE001
        return None
    if rate <= 0 or amt <= 0 or exp <= 0:
        return None
    oracle_out = amt / rate
    if oracle_out <= 0:
        return None
    return abs(exp - oracle_out) / oracle_out


#: A quote larger than this is not a swap, it is a broken or hostile feed.
#: Monero's supply is ~18.4M XMR plus tail emission of ~157k/year, so 100M is
#: unreachable for centuries -- while being far below the ~1.7e16 point where
#: quantize() runs out of the default 28-digit decimal context and accept_floor
#: raises instead of returning a floor.
XMR_ABSURD_TOTAL = Decimal("100000000")


def sum_quoted_xmr(items, key: str = "expected_xmr") -> tuple:
    """Sum the quoted XMR across swap quotes. Returns (total, unreadable, amounts).

    ONE IMPLEMENTATION, because there were two and they drifted. GhostSpiral's
    swap_expected_total and receive_watch's expected_total were the same
    function written twice; a fix to the first left the second holding every
    defect it started with. Both now call this.

    Three ways a quote is not a number, and all three arrive over the network
    or out of thor_pairs*.json, which is a file on disk that anything able to
    write it can shape:

      * NaN. `Decimal("NaN") > 0` RAISES InvalidOperation rather than returning
        False, so the comparison has to be inside the try -- it was outside in
        both copies, and a single NaN quote killed the caller with a traceback
        instead of being counted unreadable.
      * Infinity. It converts cleanly and compares greater than zero, so it was
        summed as a READABLE quote and became a target no balance can ever
        reach: the wait runs its full timeout and blames the swap.
      * An absurd finite value. Anything past ~1.7e16 makes accept_floor's
        quantize raise, hours into a run, from inside a helper the caller has
        no reason to guard.

    All three are the same thing -- a quote that is not an amount -- so all
    three are COUNTED unreadable and contribute nothing. Counted, not dropped:
    a silently deflated target is how a tool that decides "has the money
    arrived?" reports PAID on a third of it.

    The per-chunk amounts come back because the arrival gate needs the SMALLEST
    chunk, not just how many there are (see GhostSpiral.swap_arrival_floor).
    """
    total = Decimal(0)
    unreadable = 0
    amounts = []
    for item in items or ():
        try:
            v = Decimal(str((item or {}).get(key) or "0"))
            readable = v.is_finite() and Decimal(0) < v <= XMR_ABSURD_TOTAL
        except Exception:                                    # noqa: BLE001
            v, readable = Decimal(0), False
        if readable:
            total += v
            amounts.append(v)
        else:
            unreadable += 1
    return total, unreadable, amounts


def swap_arrival_floor(total: Decimal, tolerance: Decimal,
                       chunk_amounts=None, chunks: int = 1) -> tuple:
    """The unlocked balance at which every chunk has certainly arrived.

    Returns (floor, tightened) -- tightened is True when the slippage
    tolerance had to be overruled, so the caller can say so.

    THE GATE MUST NOT OPEN WHILE ANY ONE CHUNK COULD BE ENTIRELY ABSENT. That
    is the whole requirement, and stating it that way is what the previous
    attempt got wrong.

    accept_floor takes the tolerance off the summed total, so the floor sits
    `total * tolerance` below the target -- and if any chunk is worth less than
    that, the chunk can be missing and the gate still opens. The first fix
    capped the tolerance at 1/(N+1), which is correct ONLY IF every chunk is
    worth 1/N of the pot. Two shipped paths break that, and both were
    reproduced:

      * --joinmarket sets btc_chunks = jm_utxos, the tumbler's own outputs,
        which are arbitrarily unequal. Quotes of 0.50/0.30/0.15/0.05 (total
        1.00) give a floor of 0.90 under a 10% tolerance -- and the count-based
        cap does not bind at N=4 -- so the 0.05 chunk can be absent, 0.95
        arrives, and the gate opens.
      * Manual mode has no quotes, so `n_chunks = len(swap_deposits) or
        max(args.split, 1)` falls back to --split, which defaults to 1, and the
        cap returns the tolerance UNCAPPED however many swaps were really sent.
        Twelve manual swaps with --expect-total-xmr 12 gives floor 10.8 and
        returns 'funded' at 11.0: verbatim the worked example in the old
        docstring, through the one door the cap did not cover.

    So the floor is keyed on the SMALLEST chunk, not on how many there are:

        floor = max(total * (1 - tolerance),  total - smallest + 1 piconero)

    With real quotes `chunk_amounts` gives the smallest exactly. With only a
    total and a count, equal chunks are assumed (total/chunks) -- which is the
    old behaviour, now stated as the assumption it is. With neither, there is
    nothing to key on and the tolerance stands alone; the caller must say so,
    because that is the case where a missing swap is undetectable.

    Fails CLOSED. When the smallest chunk is smaller than the slippage
    tolerance the two are indistinguishable by total alone, and this prefers
    stalling -- nothing has been spent, and --accept-partial-swap is there for
    an operator who knows the rest is not coming.
    """
    if total <= 0:
        return Decimal(0), False
    floor_ = accept_floor(total, tolerance)
    smallest = None
    if chunk_amounts:
        smallest = min(chunk_amounts)
    elif chunks and int(chunks) > 1:
        smallest = total / Decimal(int(chunks))
    if smallest is None or smallest <= 0:
        return floor_, False
    # One piconero above "everything except the smallest chunk", so a whole
    # missing chunk can never satisfy it.
    guard = (total - smallest).quantize(PICONERO, rounding=ROUND_DOWN) + PICONERO
    if guard > floor_:
        return guard, True
    return floor_, False


def accept_floor(target: Decimal, tolerance: Decimal) -> Decimal:
    """The amount at which a swap's payment counts as having FULLY arrived.

    A swap essentially never delivers its quote to the digit -- the rate moves
    between quote and execution and the network takes its cut. Waiting for the
    exact quoted figure is waiting for something that will not happen, so the
    gate sits a tolerance below it and the shortfall is shown honestly.

    TWO CALLERS, ONE DEFINITION, and that is the point of it living here.
    receive_watch has always had this gate; GhostSpiral's own stage-4 arrival
    wait did not, and waited for `> DUST_XMR` instead -- so under --split N it
    returned the moment the FIRST of N chunks landed. Copying the formula into
    the second caller would have left two versions of "how much is enough" free
    to drift apart, which is the same class of defect as the one being fixed.
    """
    if target <= 0:
        return Decimal(0)
    if not (Decimal(0) <= tolerance < Decimal(1)):
        raise ValueError("tolerance must be >= 0 and < 1")
    try:
        return (target * (Decimal(1) - tolerance)).quantize(
            Decimal("0.000000000001"), rounding=ROUND_DOWN)
    except InvalidOperation:
        # quantize to 12dp needs 12 fractional digits plus the integer ones,
        # and the default decimal context carries 28 -- so a target above
        # ~1.7e16 raises rather than returning a floor. Nothing sets a wider
        # context. A number that large is not a swap quote, it is a typo or a
        # hostile bundle, and raising ValueError puts it on the same path as
        # every other bad tolerance instead of a traceback out of a logging
        # helper hours into a run.
        raise ValueError(
            "target is too large to compute an acceptance floor for "
            "(more than ~1.7e16 XMR); the total Monero supply is ~1.8e7")


# ---------------------------------------------------------------------------
#  Swap-memo binding: the ONLY thing tying a BTC deposit to your XMR address
# ---------------------------------------------------------------------------

def memo_binds_destination(memo: str, dest: str) -> bool:
    """Does this swap memo actually route the output to `dest`?

    THE BTC A SENDER PAYS GOES TO A SHARED THORCHAIN INBOUND VAULT, NOT TO YOU.
    The memo in that transaction is the only thing telling the network where to
    deliver the XMR, so a memo naming a different address pays whoever owns it,
    irreversibly, and the tool would have printed those instructions itself.

    This lived only in thor_swap_preparer. GhostSpiral's own built-in swap
    stage fetched quotes from the same API and printed "send N BTC to <addr>
    with memo <memo>" having checked the deposit address but never the memo --
    so the one path that refuses to misdirect money and the one that would
    happily instruct it sat in the same repo. It is shared now so that cannot
    diverge again.

    THORChain memos carry the destination POSITIONALLY:
        =:XMR.XMR:<dest>:<limit>/<interval>/<qty>:<affiliate>:<fee>
    (and the long form SWAP:XMR.XMR:<dest>:...). Some aggregators return the
    memo hex-encoded for the OP_RETURN, so the hex form counts too.

    THIS USED TO BE `dest in memo` -- A SUBSTRING TEST -- AND THAT IS NOT WHAT
    THE FORMAT MEANS. The docstring above has always shown an <affiliate>
    field, and an address sitting in it (or in the fee field, or in trailing
    junk) satisfied a substring test while THORChain read the DESTINATION from
    field 2 and paid whoever was named there. Measured against this function
    before the change, with OURS and ATTACKER both real addresses:

        =:XMR.XMR:<ATTACKER>:0/1/0:<OURS>:10        -> accepted
        =:XMR.XMR:<ATTACKER>:0/1/0::0 <OURS>        -> accepted
        =:BTC.BTC:<ATTACKER>:0/1/0:<OURS>:0         -> accepted
        =:XMR.XMR:<ATTACKER>:0/1/0 // refund <OURS> -> accepted
        (and the hex-encoded form of the first)     -> accepted

    Five of six hostile memos passed. This is the ONLY thing standing between
    the operator and an irreversible swap to someone else's address: the BTC
    goes to a shared THORChain vault, the memo alone says where the XMR comes
    out, and all three callers -- thor_swap_preparer before it records a pair,
    GhostSpiral before it prints deposit instructions, and receive_watch
    specifically to catch a pairs file edited between runs -- treat a True here
    as permission to tell a sender to pay.

    So it parses the fields now: the op must be a swap, the asset must be on
    the XMR chain (which is what refuses the BTC.BTC case), and field 2 must
    EQUAL dest -- not contain it.

    Strictness is the safe direction here and the asymmetry is not close: a
    memo wrongly refused costs the operator a re-quote, while a memo wrongly
    accepted costs them the entire swap with no recourse.
    """
    if not memo or not dest:
        return False
    m = str(memo).strip()
    if _memo_fields_bind(m, dest):
        return True
    # Hex-encoded for the OP_RETURN. Decode, then apply the SAME structural
    # check -- decoding and then substring-matching would reopen the hole.
    compact = m[2:] if m[:2].lower() == "0x" else m
    try:
        decoded = bytes.fromhex(compact).decode("utf-8", errors="ignore")
    except ValueError:
        return False
    return _memo_fields_bind(decoded, dest)


#: THORChain swap operations, long and short. A memo whose op is not one of
#: these is not a swap instruction at all.
_THOR_SWAP_OPS = ("swap", "s", "=")


def _memo_fields_bind(memo: str, dest: str) -> bool:
    """True only if this memo's DESTINATION FIELD is exactly `dest`.

    Split on ':' and read by position, because that is how THORChain reads it.
    The asset check accepts any asset on the XMR chain (XMR, XMR.XMR) rather
    than one exact spelling: refusing a legitimate memo over notation would
    block a real swap, while accepting a non-XMR asset is how the BTC.BTC case
    above got through.
    """
    parts = str(memo).strip().split(":")
    if len(parts) < 3:
        return False
    if parts[0].strip().lower() not in _THOR_SWAP_OPS:
        return False
    asset = parts[1].strip().upper()
    if not (asset == "XMR" or asset.startswith("XMR.")):
        return False
    return parts[2].strip() == dest


# ---------------------------------------------------------------------------
#  The receive-wallet bundle: ONE loader, used by everything
# ---------------------------------------------------------------------------
RECEIVE_SCHEMA = "gs_receive_wallet_v1"


def load_receive_bundle(path) -> dict:
    """Load and strictly validate a gs_receive_wallet_v1 bundle.

    This describes WHERE MONEY LANDS, and it used to be parsed in three
    different places with three different strictnesses -- GhostSpiral inline in
    main(), receive_watch, and thor_swap_preparer. The weakest of them decided
    the behaviour, and the weakest did this:

        receive_subaddress_index = rw_data.get("subaddress_index") or 0

    A bundle with no subaddress_index silently became index 0, which is the
    account's PRIMARY and CHANGE address -- so the entry would have been the
    change carrier rather than the intended receive output, and the tool would
    have reported no error at all. `or 0` also collapses a legitimate index 0,
    a present-but-null value, and a missing key into one indistinguishable
    case.

    One loader now serves all three callers, so no path can be laxer than
    another and a future caller cannot reintroduce a weaker parse. Every
    failure raises ValueError with a reason fit to show an operator; callers
    decide whether that is a sys.exit or an exception.
    """
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"receive wallet bundle not found: {path}")
    try:
        d = json.loads(p.read_text())
    except Exception as e:                                   # noqa: BLE001
        raise ValueError(f"receive wallet bundle is not readable JSON: {str(e)[:60]}")
    if not isinstance(d, dict):
        raise ValueError("receive wallet bundle must be a JSON object")
    if d.get("schema") != RECEIVE_SCHEMA:
        raise ValueError(
            f"expected schema {RECEIVE_SCHEMA}, got {d.get('schema')!r} — refusing "
            f"to take a payment destination from a file that is not a receive bundle")
    addr = d.get("address")
    if not addr or not isinstance(addr, str):
        raise ValueError("receive wallet bundle has no usable 'address'")
    # Absence is fatal; an explicit 0 is fine. These are kept distinct on
    # purpose -- see the docstring.
    for k in ("account_index", "subaddress_index"):
        if k not in d or d.get(k) is None:
            raise ValueError(
                f"receive wallet bundle has no '{k}'. It is not defaulted to 0, "
                f"because account 0 / subaddress 0 is the wallet's own primary and "
                f"change address — guessing it would point the pipeline at the "
                f"change carrier instead of the intended receive output.")
        v = d[k]
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ValueError(f"receive wallet bundle: '{k}' must be a "
                             f"non-negative integer, got {v!r}")
    return d


# ---------------------------------------------------------------------------
#  Sensitive data scrubbing
# ---------------------------------------------------------------------------

#: Monero's base58 alphabet -- Bitcoin's, minus the visually ambiguous
#: 0/O/I/l. A standard address is 95 chars, a subaddress 95, an integrated
#: address 106; nothing else this toolchain prints is a 90+ char base58 run,
#: so the length floor makes false positives effectively impossible while
#: still catching all three forms and any future longer one.
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ADDRESS_RE = re.compile(f"[{_B58}]{{90,}}")


def redact_addresses(text: str) -> str:
    """Mask every Monero address inside an arbitrary block of text.

    For output this toolchain did NOT write -- specifically monero-wallet-cli's
    stdout/stderr, which the signer prints when a step fails so the operator
    can see why.

    That output carries the wallet's PRIMARY ADDRESS unconditionally: every
    invocation prints "Opened wallet: <95-char address>" at the default log
    level (measured against monero-wallet-cli 0.18.3.1, no --log-level needed).
    The primary address is the single value that ties an operator to every
    subaddress in the mix, and the signer's error paths print fixed-length
    slices of that output -- result.stdout[:200], and the tail of the combined
    streams. Measured on the real binary, the address currently sits at offset
    333 and lands in NEITHER window, so nothing leaks today. But that is an
    accident of how long wallet-cli's startup banner happens to be: it is not a
    documented interface, and a banner one warning shorter, a longer wallet
    path, or a build that trims the help block slides the address straight into
    a slice we print.

    Redacting makes the property structural instead of measured -- true because
    of what this function does, not because of a byte count in someone else's
    release. scrub_address is the display form used everywhere else; this
    applies it to text rather than to a single known value.
    """
    if not text:
        return text
    return _ADDRESS_RE.sub(lambda m: scrub_address(m.group(0)), str(text))


def scrub_address(addr: str, visible: int = 8) -> str:
    """Mask an address for terminal display. NEVER returns the full value.

    The old guard was `if len(addr) <= visible*2: return addr`, which handed
    back the WHOLE string for anything 16 characters or shorter -- the exact
    opposite of scrubbing, and a fail-open in a function whose entire job is
    to withhold. Every caller passes it to print()/integrity_log() precisely
    because it is supposed to be safe there, so a short or malformed value
    (a truncated address, an error string, a label) was echoed verbatim.

    Now a short value is masked proportionally instead of exposed: nothing
    reaches the caller un-elided except a value too short to identify anything
    (<= 4 chars, e.g. "" or "n/a"), which is returned as-is because masking it
    would only produce a longer, equally uninformative string.
    """
    if addr is None:
        return "(none)"
    addr = str(addr)
    n = len(addr)
    if n <= 4:
        return addr
    if n <= visible * 2:
        # Too short for head+tail without revealing everything: show at most a
        # quarter from each end, and never more than half the string.
        keep = max(1, n // 4)
        return f"{addr[:keep]}...{addr[-keep:]}"
    return f"{addr[:visible]}...{addr[-visible:]}"


# ---------------------------------------------------------------------------
#  Real BTC bech32/bech32m checksum verification (BIP173 / BIP350)
# ---------------------------------------------------------------------------
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values) -> int:
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_checksum_ok(addr: str) -> bool:
    """Fully validate a BTC segwit address: checksum AND witness structure.

    A format regex accepts a typo'd address as long as the wrong characters stay
    in-charset; for an address we tell someone to send real BTC to, that risks
    irrecoverable funds. This runs the actual BIP173 (v0) / BIP350 (v1+ taproot)
    polymod AND enforces the witness rules, because a checksum test alone is not
    enough -- an earlier version of this function accepted three classes of
    address that Bitcoin Core rejects:
      * a v0 address carrying a bech32m checksum (and vice-versa). The checksum
        VARIANT is bound to the witness version: v0 must be bech32 (const 1),
        v1+ must be bech32m (const 0x2bc830a3). Accepting either constant for
        either version is exactly BIP350's invalid-vector list.
      * a witness program of illegal length (e.g. "bc1pw5dgrnzv"): the program
        must be 2..40 bytes, and for v0 specifically exactly 20 or 32.
      * an empty data part with no witness version byte at all.
    Sending to any of those loses the funds, so all three now return False.
    """
    if not addr or any(ord(c) < 33 or ord(c) > 126 for c in addr):
        return False
    if addr.lower() != addr and addr.upper() != addr:  # mixed case is invalid
        return False
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a) or len(a) > 90:
        return False
    hrp, data_part = a[:pos], a[pos + 1:]
    try:
        data = [_BECH32_CHARSET.index(c) for c in data_part]
    except ValueError:
        return False
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if const not in (1, 0x2bc830a3):
        return False

    payload = data[:-6]          # strip the 6 checksum symbols
    if not payload:              # no witness version byte at all
        return False
    witver = payload[0]
    if witver > 16:
        return False
    # Checksum variant is BOUND to the witness version (BIP350).
    if witver == 0 and const != 1:
        return False
    if witver >= 1 and const != 0x2bc830a3:
        return False

    # Re-pack the 5-bit groups into bytes to check the program length.
    acc = bits = 0
    program = []
    for v in payload[1:]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            program.append((acc >> bits) & 0xFF)
    if bits >= 5 or ((acc << (8 - bits)) & 0xFF):
        return False             # excess padding / non-zero pad bits
    if not (2 <= len(program) <= 40):
        return False
    if witver == 0 and len(program) not in (20, 32):
        return False
    return True


def secure_delete_file(path: Path) -> bool:
    """Overwrite a regular file's full extent in place (random then zeros), then
    unlink. Returns True on success. The single real wipe primitive -- callers
    that must not leave plaintext (a GPG bundle's source, paranoia_mode's
    artifact sweep) all use this one rather than keeping their own copy.

    NEVER follows a symlink. Opening the path directly would overwrite the
    LINK TARGET -- destroying a file the operator never asked to wipe -- and
    then unlink only the link, while reporting success. Since wipe callers
    expand shell globs, a symlink matching e.g. '*.json' would silently zero
    whatever it pointed at. O_NOFOLLOW makes the open fail atomically on a
    symlink (no TOCTOU gap), and we unlink the link itself instead: removing a
    symlink discloses nothing, as the link holds no file content.
    Non-regular files (fifo, device, socket) are likewise never overwritten.
    """
    path = Path(path)
    try:
        st = os.lstat(path)
    except OSError:
        return False

    if stat_module.S_ISLNK(st.st_mode):
        try:
            path.unlink()          # drop the link only; target untouched
            return True
        except OSError:
            return False
    if not stat_module.S_ISREG(st.st_mode):
        return False               # refuse fifo/device/socket/dir

    try:
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        size = os.fstat(fd).st_size
        if size > 0:
            # "wb" matches the O_WRONLY fd. It does NOT truncate: truncation is
            # an open(2) flag (O_TRUNC) that we deliberately never pass, so the
            # original blocks stay allocated and really are overwritten. ("r+b"
            # would also work but requests read access the fd doesn't have, so
            # any future read would raise -- match the fd instead.)
            with os.fdopen(fd, "wb", closefd=True) as f:
                fd = -1            # fdopen owns it now
                for filler in (os.urandom, lambda n: b"\x00" * n):
                    f.seek(0)
                    left = size
                    while left > 0:
                        n = min(left, 1 << 20)
                        f.write(filler(n)); left -= n
                    f.flush(); os.fsync(f.fileno())
        elif fd >= 0:
            os.close(fd); fd = -1
        path.unlink()
        return True
    except (PermissionError, OSError):
        return False
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
