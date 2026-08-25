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

# ---------------------------------------------------------------------------
#  CORE DUMPS ARE FORBIDDEN BEFORE ANYTHING ELSE HAPPENS
# ---------------------------------------------------------------------------
#
# THIS RUNS AT IMPORT, NOT FROM main(), and the difference is a real window.
#
# The secrets these processes hold arrive in the ENVIRONMENT -- GS_WALLET_PASSWORD,
# GS_WAKE_PASSPHRASE -- which means they are in the process image from execve,
# before Python executes its first line. Suppressing dumps at the top of main()
# therefore leaves the whole IMPORT PHASE uncovered, and that phase is where the
# C extensions are: requests, tenacity, nacl/libsodium, monero, psutil. A
# SIGSEGV or SIGABRT out of any of those, or a SIGQUIT from Ctrl-\, dumps the
# environment to disk.
#
# DRIVEN, not reasoned: with `ulimit -c unlimited` and GS_WALLET_PASSWORD set, a
# SIGABRT raised during the import of gs_console wrote a 5 MB core file, and
# grepping it found the password twice. The fix that only covered main() did
# nothing for it.
#
# Every tool in this chain imports gs_common immediately after its stdlib
# imports (GhostSpiral line 41, airgap_tx_signer 37, receive_watch 57), so
# doing it here covers all of them from the earliest point a shared module can
# reach. gs_console and gs_doorbell cannot import this file at all -- see
# install_signal_handlers -- and carry their own module-scope copy for the same
# reason and with the same placement.
#
# WHAT THIS CANNOT REACH is the window before the interpreter runs any of our
# code: exec, dynamic linking, site.py. No Python statement exists early enough
# for that, so it belongs to the launcher, and the systemd units set
# LimitCORE=0 to close it. Stating the boundary rather than implying the
# guarantee is complete.
def disable_core_dumps() -> bool:
    """Forbid this process from writing a core file. Returns True if enforced.

    A core dump is a copy of process memory written to DISK. These processes
    hold the wallet password (and, in the wallet-rpc client path, key material)
    in memory, so a crash on a machine with the common `ulimit -c unlimited`
    default would persist that secret to a file nothing here ever wipes.
    Setting RLIMIT_CORE to 0 is the standard prevention and costs nothing.

    Note this only binds THIS process and children it spawns -- it cannot
    constrain a separately-launched monerod/monero-wallet-rpc.

    TWO LIMITS, BOTH MEASURED, NEITHER CLOSEABLE FROM HERE.

    1. THE PRE-INTERPRETER WINDOW. The secret this protects usually arrives in
       the ENVIRONMENT (GS_WALLET_PASSWORD, GS_WAKE_PASSPHRASE), so it is in
       the process image from execve -- before CPython has run a single line of
       ours. Timed from /proc/self/stat, this call lands 120-140 ms after
       execve on an idle box, and a dump taken in that window contains the
       variable. Calling it at module scope, above every other import, makes
       the window as small as Python allows; only the launcher can remove it,
       which is what LimitCORE=0 in systemd/*.service is for and why those
       units carry it.

    2. THE HARD LIMIT IS LOWERED, AND THAT IS ONE-WAY. setrlimit here sets both
       soft and hard to 0. A process cannot RAISE its own hard limit, root
       included -- driven, root gets ValueError: not allowed to raise maximum
       limit -- and the limit is inherited, so every descendant of a tool that
       imports this module is permanently undumpable too. That is the intent
       (it is what covers the wallet-rpc client and the signer subprocesses),
       but it means a test cannot re-enable dumps after importing this module
       and must take its measurements before the import rather than after.
    """
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    except (ImportError, ValueError, OSError):
        return False


# CALLED HERE, immediately, before requests/tenacity are pulled in below.
disable_core_dumps()

import argparse
import contextlib, errno, fcntl, fnmatch, hashlib, json, os, re, secrets, shutil, signal, stat as stat_module, sys, time
from decimal import Decimal, ROUND_DOWN, InvalidOperation
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse

import logging
import requests
from tenacity import retry, wait_exponential_jitter, stop_after_attempt


# ---------------------------------------------------------------------------
#  THIRD-PARTY LOGGERS DO NOT GET STDERR
# ---------------------------------------------------------------------------
def _silence_third_party_logging() -> None:
    """Keep monero-python's own logging off every stream this toolchain uses.

    THIS WHOLE TOOLCHAIN REDACTS ADDRESSES -- scrub_address on every operator
    line, chain_safe on every integrity entry, argv kept clear of amounts -- and
    then imports a library that dumps whole JSON-RPC responses to stderr.
    monero/backends/jsonrpc/wallet.py, raw_request():

        if "error" in result:
            if not squelch_error_logging:
                _log.error("JSON RPC error:\n{result}".format(result=_ppresult))

    with _ppresult being the entire pretty-printed response, and _log.debug one
    line above it printing the entire PARAMS -- which for a transfer are the
    destination addresses and the amounts.

    A logger with no handler is not silent. Measured:

        logging.lastResort -> <_StderrHandler <stderr> (WARNING)>

    so an ERROR record with nothing configured goes to stderr anyway. In
    gs_console that stream is retained per job; in gs_wake_agent it is now the
    job log; on an operator's terminal it is scrollback. None of those are
    places an unredacted RPC response belongs, and none of them were chosen for
    it -- it arrives by default, from a dependency, past every redactor here.

    The exceptions still propagate: _err2exc raises immediately after, so the
    tool still fails and still says so in its own words. Only the dump goes.

    OPT-IN, not a permanent gag: GS_DEBUG_RPC_LOG=1 puts it back for an
    operator who is deliberately debugging, on the understanding that they have
    just turned redaction off.
    """
    if os.environ.get("GS_DEBUG_RPC_LOG"):
        return
    for name in ("monero", "monero.backends", "monero.backends.jsonrpc",
                 "monero.backends.jsonrpc.wallet",
                 "monero.backends.jsonrpc.daemon"):
        lg = logging.getLogger(name)
        lg.handlers[:] = [logging.NullHandler()]
        # propagate=False is what actually stops lastResort: a record that
        # reaches the root logger with no handlers is handed to it.
        lg.propagate = False


_silence_third_party_logging()

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

VERSION = "10.5"
CHECK_TOR_URL = "https://check.torproject.org/api/ip"
INTEGRITY_LOG = Path("integrity_chain.log")
#: Chain entries a signal handler wanted to write. See _shutdown_handler for
#: why a handler must never take the chain lock itself.
_PENDING_CHAIN: list = []

#: One piconero, the smallest amount Monero represents. Used to put a gate
#: strictly ABOVE a computed quantity rather than merely at it.
PICONERO = Decimal("0.000000000001")
#: socks5h://[user:pass@]host:port
#:
#: THE CREDENTIALS ARE THE POINT, and this regex used to forbid them.
#:
#: Tor's SocksPort has IsolateSOCKSAuth ON BY DEFAULT: two streams presenting
#: DIFFERENT SOCKS username/password are placed on DIFFERENT circuits,
#: deterministically, immediately, with no rate limit. That is the standard
#: mechanism for per-stream circuit isolation and it is what this toolchain
#: wants everywhere it calls newnym().
#:
#: It was unreachable. `^socks5h://[^\s:]+:\d{1,5}$` rejects a userinfo part,
#: so the only isolation available was SIGNAL NEWNYM -- which newnym()'s own
#: docstring admits "means 'Tor accepted the request', not 'this stream is
#: provably on a new circuit'", because Tor coalesces signals sent close
#: together and answers 250 OK either way. Verified against the running Tor:
#: three NEWNYM signals in a row were each accepted in 0.000s, while Tor's
#: internal MAX_SIGNEWNYM_RATE is 10 seconds and the code sleeps 5.
#:
#: Verified that this Tor really does offer it: a raw SOCKS5 handshake
#: presenting credentials gets method 0x02 (USERNAME/PASSWORD) and auth status
#: 0x00 (OK); presenting none gets method 0x00.
SOCKS_RE = re.compile(r"^socks5h://([^\s:@/]+:[^\s:@/]*@)?[^\s:@/]+:\d{1,5}\Z")

#: Per-process salt, so two runs on the same box do not present the same SOCKS
#: identity for the same tag. Never logged, never written to disk -- it exists
#: only to keep tags unlinkable between runs.
_SOCKS_ISOLATION_SALT = secrets.token_hex(8)


def isolated_proxy(proxy_url: str, tag: str) -> Dict[str, str]:
    """A proxy dict whose SOCKS credentials are unique to `tag`.

    Two calls with different tags give two streams that Tor places on separate
    circuits (IsolateSOCKSAuth, on by default). Two calls with the SAME tag
    reuse one circuit deliberately -- retries of one logical operation should
    not each burn a new circuit.

    STRONGER THAN newnym(), AND IT COMPOSES WITH IT. newnym asks Tor to retire
    every circuit and hope the next stream gets a fresh one; this states which
    circuit a stream belongs to. newnym is kept at the call sites that have it,
    so this is added isolation rather than replaced isolation.

    The credential is derived from a per-process salt and the tag, so it is
    stable within a run (a retry lands on the same circuit) and unlinkable
    across runs. The tag itself never reaches Tor in the clear -- only its
    hash -- because a tag like "chunk3" would otherwise tell a local observer
    of the SOCKS port how many chunks this run has.

    Falls back to the bare proxy when `proxy_url` already carries credentials,
    rather than silently replacing what the operator configured.
    """
    if not proxy_url or "@" in proxy_url:
        return {"http": proxy_url, "https": proxy_url}
    user = hashlib.sha256(
        f"{_SOCKS_ISOLATION_SALT}:{tag}".encode()).hexdigest()[:16]
    scheme, _, rest = proxy_url.partition("://")
    built = f"{scheme}://{user}:x@{rest}"
    return {"http": built, "https": built}
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
#: ALPHANUMERIC, NOT BASE58. This rule recognises what scrub_address
#: PRODUCES, and scrub_address is applied to BTC addresses too -- but base58
#: excludes 0, O, I and l, and bech32's alphabet contains 0 and l, so a
#: fragment with either in one half fell through to the digit rule:
#:
#:     scrub_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
#:       -> bc1qar0s...zzwf5mdq
#:     chain_safe("entry=bc1qar0s...zzwf5mdq")
#:       -> entry=bc#qar#s...zzwf#mdq        <- 13 of 16 characters, in order
#:
#: which is the exact output this file quotes as the BUG in the bare-bech32
#: case. Measured over 2000 random bc1q addresses, 792 (39.6%) escaped, so
#: coverage was address-dependent rather than rule-based. The '...' between two
#: runs is what makes this form recognisable; the alphabet never was.
#:
#: Widening costs nothing that was not already paid: 'waiting...done' collapsed
#: to <addr> under the base58 class too ('w','a','i','t','d','o','n','e' are
#: all base58). The literal '...' is the discriminator, and a chain payload is
#: a fixed event vocabulary, not prose.
_CHAIN_ADDR_RE = re.compile(
    r"[0-9A-Za-z]{4,}\.\.\.[0-9A-Za-z]{4,}")

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

#: An absolute (or left-truncated) filesystem path inside a chain payload.
#: Two or more '/'-separated segments, so the account/subaddress pairs this
#: chain is full of (`withdrawn:4/1`) are not mistaken for one. Defined here
#: with the other chain regexes rather than beside the address scrubbers 1800
#: lines below: chain_safe is the only caller, and a module-level name
#: resolved after its user is one import-order change away from a NameError
#: inside the logger.
_CHAIN_PATH_RE = re.compile(r"[^/\s|:]*(?:/[^/\s|]+){2,}")


#: Below this length a digitless base58 run is treated as a word, not an
#: address fragment. See _b58_run_is_addressy for the measurement.
_B58_RUN_DIGITLESS_MIN = 30


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

    AND IT WAS DELETING THEM, on the names that matter most here. The rate rule
    was measured against ConnectionError and ConnectionRefusedError and cleared
    both, so the contract above looked kept. It is not: swept over 34 realistic
    type names, THREE are eaten --

        FileNotFoundError    -> Fil<addr>      (l is not base58, so the run is
                                                "eNotFoundError": 6 flips / 14)
        ModuleNotFoundError  -> Modul<addr>
        MaxRetryError        -> <addr>

    -- and the first two are this toolchain's commonest failures by a distance:
    a missing Tor control socket, a missing plan file, an absent `stem`. Found
    by writing a real chain entry to disk and reading it back, not by a test:
    every test here captured integrity_log's ARGUMENT, which never passes
    through this function.

    Reporting "<addr>" where no address existed is worse than saying nothing.
    integrity_chain.log is the artifact an operator reads to find out what
    happened, and a reader who sees <addr> concludes an address leaked into the
    chain and that the redactor caught it. Both halves are false.

    SO A SHORT RUN MUST ALSO CARRY A DIGIT. A Monero address is uniform over
    base58, 9 of whose 58 symbols are digits, so a run of length L containing
    none has probability (49/58)^L -- 11% at 14 characters, 0.95% at 30, 0.2%
    at 40. An identifier essentially never contains one. So: a digit is
    required below 30 characters, and above it length alone still decides,
    which keeps every real address fragment the rate rule was catching (an
    address of any useful length is far past 30) while no CamelCase name
    reaches it -- the longest in the sweep, ConnectionRefusedError, is 22.

    THE COST, MEASURED rather than asserted. 4000 random base58 runs per
    length, share still redacted, before and after the digit requirement:

        length        10      14      20      25      30
        before      95.7%   98.4%   99.9%  100.0%   99.9%
        after       81.4%   89.8%   96.8%   98.8%  100.0%

    So nothing changes for a run of 30 or more, and the loss is confined to
    slices short enough to be ambiguous anyway -- a ten-character base58 run
    is as likely to be a filename as a key. A WHOLE address is not affected at
    all: the {90,} rule above matches it exactly, with no heuristic involved.
    """
    cased = [c for c in run if c.isalpha()]
    if len(cased) < 8:
        return False
    if len(run) < _B58_RUN_DIGITLESS_MIN and not any(c.isdigit() for c in run):
        return False
    if sum(1 for c in cased if c.isupper()) < 2:
        return False
    if sum(1 for c in cased if c.islower()) < 2:
        return False
    flips = sum(1 for a, b in zip(cased, cased[1:]) if a.isupper() != b.isupper())
    return flips >= 4 and flips / len(cased) >= 0.35


#: Any of the usual separators, upper or lower case. Anchored on non-hex
#: boundaries so an ordinary hex string is not mistaken for one.
#: FOUR NOTATIONS, NOT ONE. The colon/hyphen form was the only one covered,
#: and measured on the shipped function the other three walked straight
#: through -- two of them with no digits in them at all, so the digit rule
#: never fired either:
#:
#:     mac=dead.beef.cafe    ->  mac=dead.beef.cafe   (Cisco, untouched)
#:     mac=deadbeefcafe      ->  mac=deadbeefcafe     (bare, untouched)
#:     0xde:ad:be:ef:ca:fe   ->  #xde:ad:be:ef:ca:fe  (MAC intact)
#:     01:de:ad:be:ef:ca:fe  ->  <mac>:fe             (7 octets, one survives)
#:
#: paranoia_mode's own rand_mac() emits the colon form, so none of these is a
#: live leak today -- but this redactor is documented as the backstop for a
#: call site "added later", and `ip link` output, a Windows-style string or a
#: Cisco-style one is exactly how such a value would arrive. A backstop that
#: only catches the notation the current caller happens to use is not one.
#:
#: {5,} rather than {5} so a longer run is eaten whole instead of leaving its
#: tail behind; the optional 0x covers the prefixed form the lookbehind would
#: otherwise refuse to start on.
_CHAIN_MAC_RE = re.compile(
    r"(?<![0-9A-Za-z])(?:0[xX])?(?:"
    r"(?:[0-9A-Fa-f]{2}[:-]){5,}[0-9A-Fa-f]{2}"
    r"|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}"
    r"|[0-9A-Fa-f]{12}"
    r")(?![0-9A-Za-z])")
#: bech32 / bech32m, mainnet and testnet, segwit v0 and v1. The data part is
#: the bech32 charset (no 1, b, i or o), 6+ characters, and in practice 25-87.
_CHAIN_BECH32_RE = re.compile(
    r"(?<![0-9A-Za-z])(?:bc|tb|bcrt)1[02-9ac-hj-np-z]{7,87}(?![0-9A-Za-z])",
    re.I)


def chain_safe(msg: str, keep_digits: bool = False) -> str:
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
        # LINE STRUCTURE FIRST. A chain entry is ONE line, and the reader
        # splits it on " | " and then on "|". A payload carrying a newline
        # appends what looks like a second entry with no hash, so
        # verify_integrity_chain reports "line N does not chain ... this line
        # or one before it was altered" -- A TAMPER THAT NEVER HAPPENED, in the
        # file whose only job is telling the operator whether they have been
        # tampered with. It is permanent once written: every later link
        # recomputes against it. Reproduced with one "two\nlines" payload.
        # DERIVED FROM THE READER, not enumerated. This was
        # re.sub(r"[\r\n\t]+", " ", ...) -- three characters, chosen because
        # they are the three anyone thinks of. Both readers (integrity_log's
        # `prev` lookup and verify_integrity_chain) use str.splitlines(), which
        # breaks on ELEVEN: the eight not in that class -- VT, FF, FS, GS, RS,
        # NEL, U+2028, U+2029 -- passed straight through and still forked the
        # chain. Driven end to end: `paranoia_mode --iface $'wlan0\x0bEXTRA'`
        # (argv, unvalidated) reaches integrity_log through the real spoof_mac
        # and leaves verify_integrity_chain permanently reporting a tamper on a
        # file nobody edited.
        #
        # So the writer now uses the READERS' OWN definition of a line. A
        # character class cannot drift from splitlines(); this cannot, because
        # it IS splitlines(). The test that missed this swept exactly the three
        # characters the implementation already handled.
        out = " ".join(str(msg).splitlines())
        # A FILESYSTEM PATH IS AN IDENTIFIER. /home/<operator>/... names the
        # account; /run/user/<uid>/... names the login. Neither is an address
        # or a digit, so every rule below misses them, and paths reach here
        # from ordinary call sites: paranoia_mode logged the path of every
        # artifact it could not securely delete, and newnym logged the Tor
        # control socket's (that one is fixed at the call site, this is why it
        # cannot come back).
        #
        # Collapse to the BASENAME, because that is the half worth keeping --
        # WHICH file could not be wiped is the diagnostic; WHERE it lived is
        # the disclosure. Two or more segments are required, so the
        # account/subaddress pairs this chain is full of (`withdrawn:4/1`)
        # are untouched; verified against the corpus of real payloads in
        # tests/test_chain_redaction.py, which this changes none of.
        #
        # BEFORE the '|' -> '/' substitution below, deliberately: run after
        # it, a payload carrying two pipes would look like a path and lose its
        # leading fields.
        out = _CHAIN_PATH_RE.sub(
            lambda m: "<path>/" + m.group(0).rsplit("/", 1)[1], out)
        out = out.replace("\t", " ").replace("|", "/")
        # A FULL address next, matched exactly rather than statistically: a
        # run of 90+ base58 characters is an address and nothing else, so this
        # branch has no false positives and no misses. The rate rule below is
        # a heuristic and gets ~99% of full addresses on its own -- 1% is not
        # a number to accept for the value that identifies the operator.
        # A MAC ADDRESS, WHOLE, BEFORE THE DIGIT RULE EVER SEES IT.
        #
        # There was no MAC rule at all, and the digit rule is not one. Measured
        # on the shipped function:
        #
        #   mac=de:ad:be:ef:ca:fe   ->  mac=de:ad:be:ef:ca:fe   (untouched)
        #   a4:c3:f0:1b:de:ad       ->  a#:c#:f#:#b:de:ad
        #
        # The first has no digits in it, so nothing fired. The second kept two
        # octets verbatim and turned the rest into a pattern with the digit
        # POSITIONS known -- a handful of candidates, not a redaction. A MAC is
        # the one identifier that survives reinstalling the machine, and this
        # file's own comment in paranoia_mode says the remedy is to record THAT
        # a spoof happened and never the value. That remedy only holds if the
        # redactor can actually remove one when a call site slips.
        out = _CHAIN_MAC_RE.sub("<mac>", out)
        # BECH32, likewise. _CHAIN_B58_RUN_RE is base58, which excludes 0, O, I
        # and l -- and bech32 is a different alphabet entirely, so a bc1
        # address fell through to the digit rule:
        #
        #   bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
        #     ->  bc#qar#srrr#xfkvy#l#lydnw#re#gtzzwf#mdq
        #
        # which is most of the address, in order, with the gaps' widths shown.
        # That is a search key, not a redaction. The BTC entry address is what
        # the ThorChain memo publishes; it is the one value tying this operator
        # to a public Bitcoin transaction.
        out = _CHAIN_BECH32_RE.sub("<addr>", out)
        out = re.sub(r"[1-9A-HJ-NP-Za-km-z]{90,}", "<addr>", out)
        out = _CHAIN_ADDR_RE.sub("<addr>", out)
        out = _CHAIN_B58_RUN_RE.sub(
            lambda m: "<addr>" if _b58_run_is_addressy(m.group(0)) else m.group(0),
            out)
        # keep_digits is for TERMINAL lines, never for the chain. See
        # terminal_safe: on a line the operator is reading right now, the
        # numbers ARE the diagnosis, and the docstring's justification for
        # stripping them ("every quantity worth having is already printed to
        # the terminal at the moment it is computed") is false when this IS
        # that terminal line. integrity_log never passes it.
        return out if keep_digits else _CHAIN_DIGITS_RE.sub("#", out)
    except Exception:                                        # noqa: BLE001
        return "REDACTED"


def terminal_safe(msg: str) -> str:
    """Redact identifiers but KEEP the numbers, for operator-facing failures.

    chain_safe strips every digit, which is right for a durable chain payload
    and wrong for a line printed once to a terminal that the operator is
    reading to find out what went wrong. Measured on real messages:

        Method 'transfer' failed with RPC Error of code -37, message: not
        enough money
          chain_safe   -> ...RPC Error of code -#...
          terminal_safe-> ...RPC Error of code -37...

        HTTPConnectionPool(host='127.0.0.1', port=18083): Max retries exceeded
          chain_safe   -> HTTPConnectionPool(host='#.#.#.#', port=#): ...
          terminal_safe-> HTTPConnectionPool(host='127.0.0.1', port=18083): ...

    The monero-wallet-rpc error CODE is the primary diagnostic (-37 not enough
    money, -16 tx too big, -4 bad address, -9 daemon busy); collapsed to `-#`
    they are all the same message. With --rpc and --rpc-alt configured, the
    port is how the operator tells which endpoint refused.

    Addresses, MACs, bech32 and paths are still removed -- everything
    chain_safe removes EXCEPT the digit rule -- so this is not a way to print
    a destination. It is not for anything that reaches disk.
    """
    return chain_safe(msg, keep_digits=True)


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
        # ANYTHING A SIGNAL HANDLER WANTED TO SAY GOES FIRST, inside this same
        # lock. See _shutdown_handler: it may not take the lock itself, so it
        # leaves the record here and the next ordinary call writes it, chained
        # in order like everything else.
        pending = []
        while _PENDING_CHAIN:
            try:
                pending.append(_PENDING_CHAIN.pop(0))
            except IndexError:                               # pragma: no cover
                break
        h = None
        # POPPED IS NOT WRITTEN. The drain above took the deferred entries out
        # of the global; if a write below raises (ENOSPC, EROFS, the artifact
        # dir pulled out from under us) they are gone from memory AND absent
        # from disk, and one failed write drops EVERY queued signal line rather
        # than just the current one. Count what actually landed and put the
        # remainder back, so the next call retries it. The disclosed loss
        # window is "the process exits with no further call"; this keeps "a
        # later call is made and fails" from silently becoming a second one.
        _written = 0
        try:
            for _stage, _msg in pending + [(stage, msg)]:
                # REDACTED HERE, at the one place every tool passes through, so
                # a call site added later cannot reintroduce the leak by being
                # written the obvious way. See chain_safe.
                line = f"{ts}|{VERSION}|{_stage}|{chain_safe(_msg)}"
                h = hashlib.sha256((prev + line).encode()).hexdigest()
                _append_chain_line(log_path, h, line)
                prev = h
                _written += 1
        except BaseException:
            # pending[_written:] is what was drained and never written. The
            # caller's own (stage, msg) is the LAST element and is not a
            # deferred entry, so a failure on it restores nothing.
            if _written < len(pending):
                _PENDING_CHAIN[:0] = pending[_written:]
            raise
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
#: Monero's base58 alphabet -- Bitcoin's, minus the visually ambiguous 0/O/I/l.
#: Defined here rather than beside _ADDRESS_RE further down, because BOTH need
#: it and two hand-written character classes for one alphabet is how the one
#: below came to include a character the alphabet does not contain.
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

#: A mainnet Monero address: 95 chars for standard (4...) and subaddress (8...),
#: 106 for integrated (4..., carries a payment ID).
#:
#: THE OLD PATTERN WAS WRONG ABOUT MAINNET, not merely strict about testnet:
#:
#:     ^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$
#:
#: The second character was pinned to [0-9AB], a class someone derived by hand.
#: It contains '0', which base58 EXCLUDES outright, so one of its members can
#: never occur -- and it omits characters that genuinely do.
#:
#: The first base58 block of an address encodes netbyte || 7 key bytes as 11
#: characters, so the netbyte fixes the first character and BOUNDS the second.
#: Enumerating each mainnet netbyte's range gives the real alphabets:
#:
#:     standard   (netbyte 18)  4 + [123456789AB]     -- all allowed, fine
#:     subaddress (netbyte 42)  8 + [23456789ABC]     -- 'C' was REFUSED
#:     integrated (netbyte 19)  4 + [BCDEFGHJKLM]     -- all but 'B' REFUSED
#:
#: So a real mainnet SUBADDRESS beginning "8C" was rejected as a bad format.
#: That is 1.586% of the subaddress keyspace -- about one in 63 -- and
#: subaddresses are the ordinary case here: create_receive_wallet mints one,
#: and an exchange deposit address is normally one too.
#:
#: Every mainnet INTEGRATED address was rejected twice over: by that character
#: class and by the length, which allowed only 95. validate_xmr_address's own
#: comment says the factory "also covers integrated addresses, which carry a
#: payment ID and are equally legitimate here" -- while the regex three lines
#: above it refused all of them. An exchange deposit address with a payment ID
#: is exactly that shape.
#:
#: The second character is not re-derived here. It is a function of the netbyte
#: and the key, the CHECKSUM is what actually proves an address, and
#: validate_xmr_address runs monero.address.address() immediately below to
#: verify it. This is the cheap pre-filter it always was; it no longer refuses
#: real addresses in the name of being one.
#: \Z, NOT $, AND THE CHECK THAT WAS SUPPOSED TO CATCH THIS COULD NOT SEE IT.
#:
#: In Python `$` also matches just before a trailing newline, so this accepted
#: "<address>\n" -- driven: XMR_ADDR_RE.match(addr + "\n") was True.
#: tests/test_units.py has a check whose own comment says it is "STRUCTURAL,
#: not a list: this walks the shipped source and fails on ANY new `^...$`
#: validator, because enumerating the thirteen would not stop a fourteenth."
#: Its detector was a regex over single lines looking for `re.compile(r"^...$"`
#: -- which cannot match an f-string, and cannot match a call split across two
#: lines. This validator is both, and so is gs_console's copy of it. They were
#: the only two `^...$` validators left in the toolchain and the check that
#: exists to find them was blind to exactly their shape.
#:
#: Nothing was exploitable through it: validate_xmr_address below follows the
#: regex with a real Keccak checksum, which a trailing newline fails, and
#: gs_console strips before matching. That is defence in depth doing its job,
#: not a reason to leave the hole -- this is the cheap pre-filter for the value
#: the ENTIRE mixed balance is sent to.
XMR_ADDR_RE = re.compile(
    f"^[48][{_B58}]{{94}}\\Z|^4[{_B58}]{{105}}\\Z")


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


def finite_decimal(value, default=None):
    """Parse an EXTERNAL number, or return `default`. Never raises.

    For values this toolchain did not write: swap quotes, price-oracle
    responses, plan files on disk. decimal_arg guards argv and decimal_env
    guards the environment; this guards everything that arrives over a socket
    or out of a file.

    The trap is that Decimal parses "NaN" and "Infinity" happily and then
    poisons the COMPARISON rather than the conversion. `Decimal("NaN") <= 0`
    RAISES InvalidOperation, so a guard written as

        exp = Decimal(str(external))      # succeeds
        if exp <= 0:                      # raises HERE, before it can guard
            ...

    crashes at the line meant to reject the value. Measured: a SwapKit quote of
    expectedOutput="NaN" produced an uncaught InvalidOperation out of stage 2,
    and quote_deviation -- whose docstring promises it "returns None when the
    comparison cannot be made honestly" -- raised on the same input rather than
    returning None.

    Infinity is the quieter half: it compares greater than everything, so it
    survives every `<= 0` test and reaches the arithmetic, where a deviation of
    "Infinity%" gets printed at the operator.
    """
    try:
        v = Decimal(str(value))
    except Exception:                                        # noqa: BLE001
        return default
    return v if v.is_finite() else default


def decimal_env(label: str, text, positive: bool = False,
                max_value: Decimal = None) -> Decimal:
    """decimal_arg's rules, for a value that came from the ENVIRONMENT.

    THE ENV PATH BYPASSED THE ARGV PATH'S VALIDATION. Every numeric flag in
    this toolchain is declared `type=decimal_arg`, which exists because
    `type=Decimal` answers a typo with a raw traceback out of argparse's
    internals, and because Decimal ACCEPTS "NaN" and "Infinity" -- values that
    parse, survive an `x > 0` test, and then poison everything downstream.

    Then the same tools grew GS_* environment variables, preferred over argv
    because /proc/<pid>/cmdline is world-readable -- and every one of them
    re-parsed with a bare `Decimal(...)`. So the PREFERRED path was the
    unvalidated one. Four sites: GS_EXPECT_XMR, GS_SWAP_AMOUNTS,
    GS_BTC_AMOUNT and GS_EXPECT_TOTAL_XMR. Measured:
    `GS_EXPECT_XMR=Infinity receive_watch ...` produced an uncaught traceback
    out of accept_floor, hours of setup after the operator set it.

    sys.exit rather than an exception, because this runs at startup where
    argparse would have exited too -- the operator gets one line naming the
    variable, not a stack.

    LABEL FIRST, then the value: every call site reads
    decimal_env("GS_EXPECT_XMR", value), and the first version of this took
    them the other way round. Every call then tried to parse the NAME as a
    number and aborted on valid input -- caught only because a test asserted
    on the parsed VALUE rather than on the absence of an error message.
    """
    try:
        v = Decimal(str(text))
    except Exception:                                        # noqa: BLE001
        sys.exit(f"[!] {label} is not a number: {str(text)[:40]!r}")
    if not v.is_finite():
        sys.exit(f"[!] {label} is not a finite number ({v}). 'NaN' and "
                 f"'Infinity' parse as Decimals but are not amounts, and "
                 f"neither is a target any balance can reach.")
    if positive and v <= 0:
        sys.exit(f"[!] {label} must be positive (got {v}).")
    if max_value is not None and v > max_value:
        sys.exit(f"[!] {label} is implausibly large ({v}); the limit is "
                 f"{max_value}. Check the value rather than raising it.")
    return v


#: One satoshi, as a Decimal. BTC amounts quantise to this.
SATOSHI_BTC = Decimal("0.00000001")


def fmt_btc(x: Decimal) -> str:
    """A BTC amount an operator can actually type into a wallet.

    Decimal renders small values in scientific notation -- str(Decimal("3E-8"))
    is "3E-8" -- and these strings go into deposit instructions and refusal
    messages. "send at least 3E-8 BTC" is not a figure anyone can enter, and
    the number it describes is a payment. Fixed notation, eight places, with
    trailing zeros trimmed back to at least one decimal.
    """
    q = Decimal(x).quantize(SATOSHI_BTC)
    out = format(q, "f")
    if "." in out:
        out = out.rstrip("0").rstrip(".") or "0"
    return out


#: Most swap chunks a run will accept (--split N, or N JoinMarket UTXOs).
#:
#: HERE rather than in GhostSpiral because gs_console builds the argv and had
#: its own bound of 20 -- so the console offered, and the web form accepted, a
#: split the pipeline then refused, after the operator had filled the form.
#: Two numbers for one rule is the drift this module exists to stop.
#:
#: Each chunk costs a swap fee, its own entry veil transaction and its own
#: wallet account, and the offline signing wallet derives subaddresses for a
#: bounded number of accounts -- 50 by default, fixed when it was created, and
#: OPSEC_SETUP.md measures the online wallet passing that during the second
#: run. Past this point an extra run buys more than an extra chunk.
MAX_SPLIT = 8


#: The roots paranoia_mode globs when it hunts artifacts, at depth 0 and 1.
#: Named ONCE, here, because three places now need to agree about them: the
#: wipe itself, and the two tools that write operator-chosen paths which the
#: wipe may therefore never reach.
def paranoia_search_roots() -> list:
    """The directories paranoia_mode searches for artifacts."""
    return [Path.cwd().resolve(), Path.home().resolve(),
            (Path.home() / "ghostspiral").resolve(),
            (Path.home() / "GhostSpiral").resolve()]


GS_ARTIFACT_FILE_PATTERNS = [
    "unsigned_*.json", "signer_progress.json",
    "broadcast_progress.json", "wallet_*.json",
    # BOTH shapes. "thor_pairs_*.json" requires an underscore after "pairs",
    # so it never matched the plain "thor_pairs.json" -- which is the DEFAULT
    # filename gs_console writes ("--outfile", p.get("pairs_file") or
    # "thor_pairs.json"), the name in receive_watch's own usage line, and the
    # one OPSEC_SETUP.md lists among the secrets. The most common file in the
    # whole receive flow survived every wipe, holding BTC deposit addresses,
    # BTC amounts, and swap memos that carry the full 95-character XMR
    # destination in plain text.
    "thor_pairs.json", "thor_pairs.json.gpg",
    "thor_pairs_*.json", "thor_pairs_*.json.gpg", "thor_pairs_batch.json",
    "exitplan_*.json", "exitplan_v1.json",
    "integrity_chain.log", "integrity.log",
    "*.blob", "*.signed", "*.unsigned",
    "signed_manifest_v1.json", "unsigned_manifest.json",
    # The wallet OUTPUT SET the signer exports so the offline wallet can sign
    # a spend of an earlier round's output. It maps this wallet's outputs --
    # exactly the holdings picture a forensic reader wants -- so it must not
    # survive the wipe. Written 0600, but 0600 is not gone.
    "outputs_export.hex",
    # WRITTEN ONE LINE AFTER outputs_export.hex, INTO THE SAME DIRECTORY, AND
    # MATCHED BY NOTHING. airgap_tx_signer stores the online wallet's account
    # count here so the offline wallet can be checked against it. Every pattern
    # above ends in .json, .log, .hex, .key, .blob, .signed or .unsigned, and
    # this is the toolchain's only .txt artifact -- so the sweep walked past
    # it, and so did the test that scans for unswept names, whose own regex
    # enumerated those extensions and not this one.
    #
    # It is not a big secret and it is not nothing: GhostSpiral puts every
    # output in its own account, so this number is a running tally of how many
    # outputs this wallet has handled. Left on disk after a paranoia sweep it
    # says a Monero cold-signing operation ran here and roughly how much of it,
    # which is precisely the metadata the sweep exists to remove -- and it says
    # so next to an empty space where its own siblings used to be.
    "accounts_count.txt",
    # The WALLET PASSWORD, in plaintext. airgap_tx_signer cannot hand a
    # password to monero-wallet-cli on argv (/proc/<pid>/cmdline is mode 444 --
    # any local user reads it), so it writes one 0600 file and feeds it via
    # stdin redirection. It is deleted in a finally, but a SIGKILL runs no
    # finally, and 0600 is not gone. Nothing here matched it before: the name
    # starts with a dot and none of the patterns above are dotfile globs.
    ".gs_pw_*",
    # THE WAKE AGENT'S RUN STATE. gs_wake_state.json is the job ledger and the
    # 24h wake budget; gs_wake_handles.json maps a 4-hex handle to the bundle
    # and slip it names, so it is a direct index into this run's addresses.
    "gs_wake_state.json",
    # THE FOURTH FILE gs_wake_agent WRITES INTO artifact_dir, and the only one
    # of the four that was missing. gs_wake_state.json, gs_wake_handles.json
    # and gs_wake_job.log were all here; gs_wake_status.json landed with the
    # phone-only status flow and went into neither this list nor .gitignore.
    #
    # Driven against the real sweep with all four side by side in the artifact
    # directory: three "WOULD BE ERASED", this one "SURVIVES THE WIPE".
    #
    # It is receive_watch --result-json's outcome, and it carries `unlocked`
    # and `total` as exact decimal strings -- the amount that arrived from the
    # swap, to the piconero. This file strips amounts out of the integrity
    # chain on the reasoning that "the amount deanonymises the hop it is meant
    # to hide", and then left the arrival total in a JSON file in the operator's
    # working directory.
    "gs_wake_status.json",
    #: The pager's update cursor and poke timestamps. Not a secret in itself,
    #: but it is a dated record of every time you woke the vault from a phone
    #: -- which is exactly the correlation the jitters exist to break.
    "pager_state.json",
    "pager.log", "gs_wake_handles.json", ".gs_wake_inhibit",
    # WHERE A WOKEN JOB'S CHILDREN WRITE, because the alternative was the
    # systemd journal -- persistent, root-owned, rotated rather than erased,
    # and outside every root this sweep searches. It holds whatever
    # thor_swap_preparer printed: the BTC deposit address and the ThorChain
    # memo, which names the destination XMR address in plain text.
    "gs_wake_job.log",
    # integrity_log_once's run-scoped dedupe marker, written into the
    # --output directory beside the plans. It was in NEITHER this list nor
    # .gitignore, so an incomplete run -- which keeps its marker by design,
    # because report_completion exits before _wipe_spent_plans -- left it
    # behind for the wipe to walk straight past.
    ".chain_once_*",
    # THE WAKE KEYPAIR. Suffixed "*.key" on purpose: a "gs_wake_*" glob would
    # match the TRACKED scripts gs_wake_keys and gs_wake_agent, and
    # tests/test_gitignore.py's backward check (no tracked file may be
    # shadowed) would go red -- and worse, a real wipe would delete the tools.
    #
    # WIPING THIS BREAKS THE DOORBELL UNTIL BOTH BOXES ARE RE-KEYED, and the
    # summary says so by name. Without that line the next magic packet produces
    # a correct fail-closed refusal that is byte-identical to a dead switch, a
    # BIOS reset and a hostile WOL -- and the operator debugs everything except
    # the wipe they ran.
    "gs_wake_*.key",
    ".ghostspiral.lock",
    # integrity_log's serialisation lock (integrity_chain.log.lock). Holds no
    # content, but it is a per-run artifact and its mere presence dates a run.
    "*.log.lock",
    # atomic_write_json/_text stage a '<name>.tmp' before renaming. A crash or
    # Ctrl-C in that window leaves the partial file behind holding the SAME
    # plaintext (deposit addresses, memos, XMR destinations) -- and none of the
    # patterns above match a '.tmp' suffix, so it survived every wipe.
    # gs_common now erases its own partial on failure; this is defence in depth
    # for a hard kill (SIGKILL) that runs no cleanup at all.
    "*.json.tmp", "*.tmp",
    "unsigned_monero_tx", "signed_monero_tx",
    # Monero's OWN logs. This pipeline requires monerod + monero-wallet-rpc, so
    # it causes these files even though it does not write them. At the default
    # log level they were checked and carry no addresses/keys/txids -- but at
    # --log-level 2 monero-wallet-cli.log contains the FULL wallet address
    # (verified), which is a deanonymisation link for a mixing tool. monerod's
    # log is also created world-readable (0644, verified) and we cannot change
    # that from here; wiping it is what we can do.
    "monero-wallet-cli.log", "monero-wallet-rpc.log",
    "monerod.log", "bitmonero.log",
    # NOTHING TRACKED BY GIT BELONGS ON THIS LIST. "renamethis1" was here and
    # is a committed file in this repository, so a real wipe shredded a file
    # git then reported as deleted -- dirtying the working tree of the tool
    # doing the wiping, for no gain: the file is already published, and
    # deleting the local copy does not unpublish it. This list is for RUNTIME
    # artifacts, which are the ones that are private and the ones .gitignore
    # covers. tests/test_gitignore.py now checks the two lists cannot disagree
    # about that in either direction.
]
GS_ARTIFACT_DIR_PATTERNS = [
    "signed_blobs", "unsigned", "tx_staging",
    # airgap_tx_signer's per-TX scratch dir (tempfile.mkdtemp(prefix="gs_sign_")),
    # which holds unsigned_monero_tx and the signed_monero_tx wallet-cli writes.
    "gs_sign_*",
    # airgap_tx_signer's multi-round output-import scratch (prefix="gs_impout_"),
    # which holds the wallet OUTPUT-SET blob. Normally /dev/shm (RAM) and wiped
    # in a finally, but a SIGKILL before that -- or a host with no /dev/shm, so
    # it falls back to $TMPDIR -- would leave the holdings map behind. Neither
    # of those two locations is a search_root here, which is why the Temp files
    # phase now sweeps them by prefix (_wipe_targeted_temp_roots); this pattern
    # only catches a copy left in the cwd or under $HOME.
    "gs_impout_*",
]


def _wipe_sweep_reaches_item(res: Path) -> bool:
    """Would the sweep MATCH `res` ITSELF by name -- file or directory?

    NOT the same question as wipe_covers, and conflating the two is a real
    defect that was driven rather than argued.

    wipe_covers answers "would anything WRITTEN AT this location be swept",
    which is what `--output <dir>` and WorkingDirectory ask: files land inside
    that directory, and the sweep reaches inside a root (depth 0) and one
    level down (`*/pattern`). For a directory D that means D itself must BE a
    root or sit directly under one.

    wipe_will_erase asks the other question -- "would the sweep DELETE this
    target" -- and for a DIRECTORY target the sweep matches the directory by
    name via `root.glob(dirname)` and `root.glob(f"*/{dirname}")`. So the
    level that must line up is the directory's PARENT, not the directory.

    Building the delete question on the write-here answer put directories off
    by exactly one level. Driven against paranoia_mode's real dry-run sweep
    with a matching directory name at each depth:

        depth 0   wipe_will_erase True    really swept True
        depth 1   wipe_will_erase FALSE   really swept TRUE   <-- disagreed
        depth 2   wipe_will_erase False   really swept False

    Files were never wrong, because wipe_covers replaces a file with its
    parent first and that happens to produce this same test -- which is why
    the three shipped callers, all of which pass files, never saw it.

    One rule for both kinds: the matched item sits at depth 0 or 1, so its
    parent is a root or its grandparent is.
    """
    return any(res.parent == r or res.parent.parent == r
               for r in paranoia_search_roots())


def wipe_will_erase(target) -> bool:
    """True if paranoia_mode's artifact sweep would actually DELETE `target`.

    wipe_covers answers only half the question. The sweep matches on TWO
    things -- the location (roots at depth 0 and 1, which is what wipe_covers
    resolves) AND the file's NAME against GS_ARTIFACT_FILE_PATTERNS. Callers
    that print "this will be wiped with the rest of the run" were asking
    wipe_covers, so they were reporting on the location alone. Measured, with
    the file in a perfectly ordinary place:

        ~/gs/thor_pairs.json     covers=True   name matches   -> erased
        ~/gs/my_notes.json       covers=True   NO match       -> NEVER erased

    and --outfile is free-form, so the second row is one flag away. That file
    holds every BTC deposit address and every memo, and a memo carries the
    destination XMR address in full -- thor_swap_preparer's own comment calls
    it "the single artifact that ties the BTC side to the XMR side", and it
    printed no warning for it.

    A directory is judged by the directory patterns, the way the sweep does.
    """
    try:
        res = Path(target).resolve()
    except OSError:
        return False
    # _wipe_sweep_reaches_item, NOT wipe_covers. See that function: the two
    # answer different questions, and for a DIRECTORY target wipe_covers is
    # off by one level -- it says a matching directory one level down will not
    # be erased when the sweep really does erase it.
    if not _wipe_sweep_reaches_item(res):
        return False
    return _wipe_name_matches(res)


def _wipe_name_matches(res: Path) -> bool:
    """Does the sweep's NAME half match `res`? One rule, two callers.

    THE PATTERN SET DEPENDS ON WHAT THE TARGET IS, and this was written out
    twice: wipe_will_erase chose GS_ARTIFACT_DIR_PATTERNS for a directory,
    wipe_miss_reason hard-coded GS_ARTIFACT_FILE_PATTERNS for everything. So
    the function whose entire job is to EXPLAIN the other one's answer was
    answering a different question, and only for directories -- the case
    neither's tests exercised. Driven, with $HOME/gs/tx_staging (a real
    directory name from GS_ARTIFACT_DIR_PATTERNS, two levels down so the
    location is genuinely wrong):

        wipe_will_erase  False          -- correct, and for the LOCATION
        wipe_miss_reason "both"         -- wrong: the name is fine

    "both" tells an operator that no name like theirs is ever swept, so moving
    the directory cannot help -- which is the opposite of the truth and sends
    them to rename a directory whose name was never the problem. The same
    misreport hits any covered-but-misplaced staging directory.

    A path that does not exist is judged as a FILE, which is what the callers
    need: --outfile is checked before the file is written. Both callers now
    inherit that from here rather than each deciding.
    """
    pats = (GS_ARTIFACT_DIR_PATTERNS if res.is_dir()
            else GS_ARTIFACT_FILE_PATTERNS)
    return any(fnmatch.fnmatch(res.name, pat) for pat in pats)


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
        # A DOT IN A DIRECTORY NAME IS NOT A FILE EXTENSION. This was
        # `if res.is_file() or res.suffix`, so any path whose last component
        # contains a dot was treated as a file and replaced by its PARENT --
        # and directories with dots in them are ordinary:
        #
        #   $HOME/gs/run.2026    -> checked $HOME/gs   -> "covered" (depth 1)
        #   $HOME/a/b            -> checked $HOME/a/b  -> not covered (depth 2)
        #
        # So `--output ~/gs/run.2026` was reported as inside the wipe when the
        # sweep never enumerates it, and every tool that asks this question
        # says "your artifacts will be erased" on the strength of the answer.
        # The suffix shortcut only exists to turn a FILE path into its
        # directory, so ask the filesystem when it can answer and fall back to
        # the suffix heuristic only for a path that does not exist yet.
        if res.is_file():
            res = res.parent
        elif not res.exists() and res.suffix:
            res = res.parent
        # DEPTH 0 AND 1, which is what the paragraph above says and what the
        # sweep actually does. This was `r in res.parents`, which is true at
        # ANY depth -- so every path two or more levels under a root answered
        # "covered" while _wipe_gs_artifacts_inner never enumerated it. It
        # globs each root exactly twice, `root.glob(pattern)` and
        # `root.glob(f"*/{pattern}")`; there is no third level.
        #
        # Driven against the real sweep in dry mode, with cwd and $HOME pointed
        # at a scratch root holding one unsigned_fanout_*.json at each depth:
        #
        #     depth 0  covers=True   actually swept=True
        #     depth 1  covers=True   actually swept=True
        #     depth 2  covers=True   actually swept=FALSE
        #     depth 3  covers=True   actually swept=FALSE
        #
        # A WRONG ANSWER HERE IS SILENT BY CONSTRUCTION, as the docstring says,
        # and it is silent in the unsafe direction: all four callers only speak
        # when this returns False. `GhostSpiral --output plans/run7`,
        # `create_receive_wallet --output-dir ~/keys/gs`,
        # `thor_swap_preparer --outfile ~/keys/gs/thor_pairs.json` and
        # exit_strategy_simulator's --outfile each printed nothing and left
        # their plans -- hop destinations, amounts, the receive bundle, the
        # --exit-to destination -- on disk after a wipe the operator was told
        # covered them.
        #
        # res is already the containing DIRECTORY by this point, so depth 0 is
        # `res == r` (a file sitting in the root) and depth 1 is
        # `res.parent == r` (a file one directory down, which `*/pattern`
        # reaches).
        return any(res == r or res.parent == r
                   for r in paranoia_search_roots())
    except OSError:
        return False


def wipe_miss_reason(target) -> str:
    """WHY wipe_will_erase said no: "", "location", "name", or "both".

    The sweep matches on two things and the callers only ever spoke about one.
    Every tool that warns "this will not be wiped" printed a sentence of the
    form "<dir> is OUTSIDE the directories paranoia_mode sweeps" and a remedy
    of the form "write it under $HOME" or "pass --search-dir <dir>". Both are
    about LOCATION. But --outfile is free-form, and the name is half the test:

        exit_strategy_simulator --outfile myplan.json   (in the cwd)
            wipe_covers(location) True    wipe_will_erase False

    -- so the operator was told their file was outside the searched directories
    when it was sitting in one of them, and handed a remedy (add a root) that
    cannot fix a name that will never match. They re-run the wipe, believe it
    is handled, and the holding size or the deposit-address bundle is still
    there. Two of the three call sites had this; create_receive_wallet does
    not, because it picks the name itself (wallet_<hex>.json, which matches) so
    only the directory can vary -- and its comment already says exactly that.

    THE NAME HALF IS _wipe_name_matches, shared with wipe_will_erase. It was a
    second inline copy that always used the FILE patterns, so this function
    disagreed with the one it exists to explain whenever the target was a
    directory -- see _wipe_name_matches for the driven case.
    """
    if wipe_will_erase(target):
        return ""
    # THE SAME LOCATION TEST wipe_will_erase USED, or this explains a refusal
    # that function did not make: with wipe_covers here, a matching directory
    # one level down was reported as a LOCATION problem while wipe_will_erase
    # had already said it would be erased.
    try:
        loc = _wipe_sweep_reaches_item(Path(target).resolve())
    except OSError:
        loc = False
    try:
        res = Path(target).resolve()
    except OSError:
        res = Path(target)
    named = _wipe_name_matches(res)
    if loc and not named:
        return "name"
    if named and not loc:
        return "location"
    return "both"


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
      * It detects an edit or deletion in the middle of the file BY SOMETHING
        THAT DID NOT RECOMPUTE -- a partial overwrite, a truncating write, a
        filesystem corruption, an editor, a script that rewrote one line.
        Every link after the change then fails recomputation.
      * It does NOT detect an edit by an adversary WHO RECOMPUTES. The chain is
        unkeyed: each link is sha256(previous_hash + payload) and the hash
        function is public, so anyone who can write to the file can rewrite a
        payload and recompute every hash below it in a loop of four lines.
        Reproduced against this function with its own algorithm. An earlier
        version of this list said "it detects an EDIT or a DELETION in the
        middle of the file" without that qualifier, which reads as tamper
        evidence against a person and is not. Making it so would need a key
        this process cannot keep from someone holding the disk -- the same
        problem gs_wake_keys documents for the vault's keyfile -- or an
        off-machine append-only sink, which is not shipped.
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


#: Cardinality events already chained, as (stage, kind). One entry per KIND.
#:
#: Process-scoped, which is run-scoped for every tool here: one process is one
#: run, and GhostSpiral's run lock guarantees it.
_CARDINAL_EVENTS_LOGGED = set()


def integrity_log_once(stage: str, kind: str, log_path: Path = INTEGRITY_LOG) -> str:
    """Chain an event AT MOST ONCE per process. Returns "" when suppressed.

    COUNTING DEFEATS chain_safe, and chain_safe's own docstring claims
    otherwise -- "which output or address it happened to, AND HOW MANY THERE
    WERE, does not [survive]". It strips the digits, so `delay:idx=7` becomes
    `delay:idx=#` -- and a twelve-transaction round still writes TWELVE
    identical lines. Measured: 12 relays produce 12 `broadcast|delay:idx=#`
    entries, so the batch size is read straight off the file by counting.

    GhostSpiral already found this for round events and fixed it there. Its
    _ROUND_EVENTS_LOGGED comment states the rule outright: "Redacting the
    digits out of 'Exit 7/11' gives 'exit #/#', which is fine on its own and
    useless as a defence: an analyst counts the broadcast_ok:exit lines
    instead... Cardinality survives redaction whenever a loop writes a line per
    turn." That fix covered one loop. The per-transaction, per-chunk and
    per-carrier loops in the broadcaster, stage 2 and stage 5 kept writing one
    line each.

    The counts this leaks are the run's structure: how many transactions a
    round relayed, how many swap chunks --split made, how many carriers exist.
    Those are the search keys the whole pipeline is built to withhold, and
    integrity_log's own docstring assumes a reader who has the file ("An
    attacker with the log can only narrow the operation to a 10-min window").

    So the chain records THAT the kind of thing happened. How many, and which,
    are printed to the terminal at the moment they happen, where they reach the
    operator and stop -- the same trade _ROUND_EVENTS_LOGGED made, and the same
    one paranoia_mode made for the spoofed MAC.

    Failure events are deliberately NOT routed through this: counting them
    yields the number of things that went wrong, not the size of the run, and
    they are the entries an audit most needs.

    "PER PROCESS" WAS NOT ENOUGH, AND THE COMMENT ABOVE SAYS WHY WITHOUT
    NOTICING. A GhostSpiral round spawns THREE fresh child processes -- the
    signer twice and the broadcaster once -- and each one starts with an empty
    set, so a loop of N rounds writes N copies of every line these guards were
    added to collapse. Measured on a completed run's chain file: between the
    exit's own withdraw_start and withdraw_done markers, with every digit in
    the file already redacted to '#',

        9  signer     using_account_index:#
        9  signer     create_done:#_created:#_failed
        8  broadcast  relayed
        8  broadcast  done

    and that run made exactly 9 exit withdrawals. The count the parent went to
    the trouble of collapsing into a set was recoverable by counting its
    children's lines instead.

    GS_CHAIN_RUN_ONCE names a file that makes the set RUN-scoped: the parent
    creates it, passes it to every child it spawns, and deletes it at the end.
    The first round chains each kind and the rest do not. A kind that only
    appears on round seven is still new, so it is still chained -- which is
    what keeps failures visible.
    """
    key = (stage, kind)
    if key in _CARDINAL_EVENTS_LOGGED:
        return ""
    _shared = os.environ.get("GS_CHAIN_RUN_ONCE") or ""
    if _shared:
        # The chain's own lock serialises this: rounds are sequential and each
        # spawns one child at a time, so a plain read-then-append is enough,
        # and a lost race costs one duplicate line rather than a wrong chain.
        # REDACTED HERE TOO. This file is a second copy of every chain payload,
        # written to disk beside the chain and keyed on the RAW value -- so a
        # `kind` carrying an address or a MAC was stored verbatim in it while
        # the chain itself, one line below, stored chain_safe's version. The
        # redactor was bypassed by the deduplicator that feeds it.
        #
        # Redacting the key changes nothing about deduplication: chain_safe is
        # deterministic, so two payloads that redact to the same string were
        # always going to produce the same chain line, and collapsing them is
        # what this function is for.
        _line = f"{chain_safe(stage)}\t{chain_safe(kind)}\n"
        try:
            # 0600, and set at creation. This is chain material and the default
            # umask would leave it 0644.
            _fd = os.open(_shared, os.O_RDWR | os.O_CREAT, 0o600)
            with os.fdopen(_fd, "a+") as _f:
                _f.seek(0)
                if _line in _f.read():
                    return ""
                _f.write(_line)
        except OSError:
            # An unreadable marker file must not silence the chain: a missing
            # entry is worse than a duplicate one.
            pass
    _CARDINAL_EVENTS_LOGGED.add(key)
    return integrity_log(stage, kind, log_path)


def secure_delete_or_warn(path, what: str) -> bool:
    """secure_delete_file, but a FAILURE IS NEVER SILENT.

    True if nothing of `path` is left on disk -- erased, or never there.

    secure_delete_file returns True/False and eleven call sites discarded it,
    against one that checked. The files those sites erase are the most
    sensitive artifacts this toolchain creates:

      * the WALLET SPEND-KEY PASSWORD, written to a 0600 temp file because
        monero-wallet-cli cannot take a password on argv (/proc/<pid>/cmdline
        is world-readable), then fed on stdin -- four sites in
        airgap_tx_signer, all in `finally` blocks;
      * the EXIT PLAN, which carries the operator's --exit-to destination, the
        single value the whole pipeline exists to keep unlinked;
      * per-peel and change-sweep plans, which carry destinations and amounts;
      * atomic_write's partial temp file, which holds the same plaintext as the
        file it was staging.

    Every one of those deletions can fail -- a read-only filesystem, a full
    one, a permission change, or the O_NOFOLLOW open losing a race -- and every
    one failed SILENTLY. The password file's own comment says it "may live in
    /dev/shm, outside the scratch tree the rmtree below covers, so it would
    otherwise survive the whole run": its survival was understood to matter,
    and then not checked.

    The repo already knew the shape of this: `.gs_pw_*` is in paranoia_mode's
    artifact patterns precisely because "it is deleted in a finally, but a
    SIGKILL runs no finally, and 0600 is not gone". That covers the process
    dying. It does not cover the delete returning False.

    A HELPER RATHER THAN ELEVEN `if not ...` BLOCKS, for the reason
    secure_delete_file itself gives for existing: one primitive, one place to
    audit. A new caller gets the warning without remembering to write it.

    `what` names the CONTENT, not the path -- "the wallet password", "the exit
    plan" -- because that is what tells an operator whether to care. The path
    is printed too so they can go and remove it, but only to the terminal: the
    integrity chain records that a wipe failed and nothing about where.
    """
    ok = secure_delete_file(path)
    if ok:
        return True
    # NOTHING TO ERASE IS NOT A FAILED ERASE. secure_delete_file lstats first
    # and returns False when that raises, so a path that was never created
    # reports exactly like a wipe that could not run -- and the warning below
    # says "It is STILL ON DISK", which for a missing file is simply untrue.
    #
    # It is not hypothetical. atomic_write_json/atomic_write_text call this
    # from `except BaseException` to clear the partial temp file, and the
    # commonest reason those raise is secure_write_bytes failing to CREATE the
    # temp file at all (read-only or full filesystem, bad perms on the
    # directory). Every one of those would have printed a wipe failure for a
    # file that does not exist and written secure_delete_failed into the
    # integrity chain. An operator who sees that warning cry wolf is an
    # operator who ignores the one that means their spend-key password is
    # still sitting in /dev/shm.
    #
    # lexists, not exists: a broken symlink is still a directory entry to
    # report, and secure_delete_file unlinks those rather than following them.
    if not os.path.lexists(path):
        return True
    integrity_log("wipe", "secure_delete_failed")
    print(f"  [!] Could not securely erase {what}: {path}")
    print(f"      It is STILL ON DISK. Remove it yourself -- this file is "
          f"not covered by anything else that runs later.")
    return False


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
           "detail": "", "nettype": "unknown"}
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
            timeout=20, proxies=use_proxies, allow_redirects=False).json().get("result") or {}
        # WHICH CHAIN. get_info already told us; nothing was reading it.
        #
        # monerod reports nettype as "mainnet" | "testnet" | "stagenet" |
        # "fakechain" (--regtest). The WALLET cannot answer this: regtest
        # deliberately uses MAINNET address prefixes, so validate_address on a
        # regtest wallet returns nettype "mainnet" for both its own addresses
        # and real mainnet ones -- driven and confirmed. The daemon is the only
        # component that knows, and this function was already asking it and
        # throwing the answer away.
        #
        # Carried out even on the offline/early-return paths below, because
        # "which chain" is exactly the question an operator needs answered when
        # something looks wrong.
        out["nettype"] = str(info.get("nettype") or "unknown")
        if info.get("offline"):
            out["verdict"] = "offline"
            out["detail"] = "daemon is running --offline; it cannot relay at all"
            return out

        conns = requests.post(
            endpoint, json={"jsonrpc": "2.0", "id": "0", "method": "get_connections"},
            timeout=20, proxies=use_proxies, allow_redirects=False).json().get("result") or {}
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


def secure_mkdir(path: Path, mode: int = 0o700,
                 narrow_existing: bool = True) -> None:
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

    narrow_existing=False for a directory the OPERATOR chose rather than one
    this toolchain created. create_receive_wallet's --output-dir defaults to
    ".", so running it chmod'ed the operator's current working directory to
    0700 — measured, 755 -> 700. It only ever narrows, so nothing leaked; it
    silently changed a directory that has nothing to do with this tool, and
    "it was only tightened" is not a defence for modifying something you were
    merely asked to write a file into. A directory this tool CREATES is its
    own business; one that already existed is not.
    """
    path = Path(path)
    created = []
    for parent in list(path.parents)[::-1]:
        if not parent.exists():
            created.append(parent)
    _pre_existing = path.exists()
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    targets = created + ([] if (_pre_existing and not narrow_existing)
                         else [path])
    for d in targets:
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
        secure_delete_or_warn(tmp, "a partly-written file holding the same plaintext")
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
        secure_delete_or_warn(tmp, "a partly-written file holding the same plaintext")
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
    r = requests.get(CHECK_TOR_URL, timeout=15, proxies=proxy, allow_redirects=False)
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
    # ONCE per run, not once per verification. verify_tor is called at stage 0,
    # before every round, and inside every broadcast child -- so a run with N
    # withdrawals wrote N+ identical `tor|verified_ok` lines and the count came
    # straight off the file. Measured: 17 of them inside one exit bracket.
    # A FAILURE still chains every time (verify_fail / LEAK_DETECTED above are
    # not routed through this), which is the half an audit needs.
    integrity_log_once("tor", "verified_ok")


def tor_recheck(proxy: Dict[str, str], stage: str = "recheck") -> None:
    """Re-verify Tor mid-operation. Logs but doesn't retry as aggressively."""
    if not proxy:
        sys.exit("[!] Tor recheck called without proxies — that request would go "
                 "clearnet. Aborting.")
    try:
        r = requests.get(CHECK_TOR_URL, timeout=10, proxies=proxy, allow_redirects=False)
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


def tor_control_targets(proxy_url: str = "") -> list:
    """Where to look for the control port of the Tor serving `proxy_url`.

    newnym() rotated a HARDCODED /var/run/tor/control regardless of which Tor
    the traffic actually used, and returned True on success. Every call site --
    all 21 of them -- takes that default. So an operator on Tor Browser
    (`--tor-proxy socks5h://127.0.0.1:9150`) had their requests carried by
    Tor Browser's tor while newnym rotated the SYSTEM tor, a different daemon,
    and every "anonymity gate" in the run silently rotated nothing.

    That is not an exotic setup: gs_console's daemon/Tor detection offers 9150
    and tests/test_console.py pins it ("detect finds the Tor Browser port").

    Ordered most-specific first: the control port paired with this SOCKS port
    (Tor's convention, and Tor Browser's, is SOCKS+1), then the conventional
    unix socket, then the system default port. The caller verifies which Tor it
    reached -- see _control_owns_socks -- so a wrong guess here is caught
    rather than acted on.
    """
    out = []
    host, port = "127.0.0.1", None
    if proxy_url:
        try:
            _p = urlparse(proxy_url)
            host = _p.hostname or host
            port = _p.port
        except Exception:                                    # noqa: BLE001
            port = None
    if port:
        out.append(f"{host}:{port + 1}")
    out.append("/var/run/tor/control")
    if not port or port != 9050:
        out.append(f"{host}:9051")
    return out


def _control_owns_socks(controller, proxy_url: str) -> bool:
    """Is this control connection the SAME tor that serves `proxy_url`?

    Answerable, and worth answering: Tor's control port reports its own SOCKS
    listeners. Verified against a running tor --

        GETINFO net/listeners/socks -> "127.0.0.1:9050"

    -- so rotating the wrong daemon is detectable instead of silent. Returns
    True when it cannot tell (an old tor without the key), because refusing on
    a missing diagnostic would be worse than the rotation this is guarding.
    """
    if not proxy_url:
        return True
    try:
        want = urlparse(proxy_url)
        wport = want.port
        if not wport:
            return True
        listeners = controller.get_info("net/listeners/socks", "")
    except Exception:                                        # noqa: BLE001
        return True
    if not listeners:
        return True
    return any(str(wport) == l.strip().strip('"').rsplit(":", 1)[-1]
               for l in listeners.split() if ":" in l)


def newnym(ctrl: str = "/var/run/tor/control", required: bool = False,
           proxy_url: str = "") -> bool:
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
            # THE TOR THE TRAFFIC USES, not whichever one owns a fixed path.
            #
            # `ctrl` keeps its default so no call site changes, but when a
            # proxy_url is supplied the control port paired with THAT SOCKS
            # port is tried first, and whichever connection is made is then
            # asked whether it owns that SOCKS listener. Rotating a different
            # daemon and reporting success is the failure this closes.
            _targets = [ctrl] if not proxy_url else (
                tor_control_targets(proxy_url) + [ctrl])
            _seen, _c, _err = set(), None, None
            for _t in _targets:
                if _t in _seen:
                    continue
                _seen.add(_t)
                # CLOSE IT IF AUTH FAILS. The first version of this assigned
                # the Controller and then authenticated inside the same try, so
                # a control port that OPENS but refuses authentication -- an
                # unreadable cookie file is the ordinary way that happens --
                # left the socket open and simply dropped the reference. With
                # newnym called from 21 sites, several of them in per-output
                # loops, that leaks a descriptor per rotation.
                _cand = None
                try:
                    if _t.startswith("/"):
                        _cand = Controller.from_socket_file(_t)
                    else:
                        _h, _, _p = _t.rpartition(":")
                        _cand = Controller.from_port(address=_h, port=int(_p))
                    _cand.authenticate()
                    _c = _cand
                except Exception as _e:                      # noqa: BLE001
                    _err = _e
                    if _cand is not None:
                        try:
                            _cand.close()
                        except Exception:                    # noqa: BLE001
                            pass
                    _c = None
                    continue
                if _control_owns_socks(_c, proxy_url):
                    break
                # Right protocol, WRONG tor. Keep looking rather than rotate a
                # daemon that carries none of this run's traffic.
                try:
                    _c.close()
                except Exception:                            # noqa: BLE001
                    pass
                _c = None
                _err = RuntimeError("control port belongs to a different tor")
            if _c is None:
                raise _err or RuntimeError("no usable tor control port")
            with _c as c:
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
    # THE TYPE, NOT THE TEXT, and the difference is a filesystem path.
    #
    # This logged `str(last_err)[:40]` into integrity_chain.log, which is the
    # persistent on-disk artifact every other rule in this file exists to keep
    # clean -- chain_safe strips addresses and digits from it, report_holdings
    # refuses to write the account grouping to it, create_subs stopped
    # labelling subaddresses because labels outlive the run, and MoneroRPC
    # stopped logging its own host:port here for exactly this reason.
    #
    # The exception comes from Controller.from_socket_file(ctrl), so its text
    # is the CONTROL SOCKET PATH: FileNotFoundError and PermissionError both
    # quote it, and under a per-user Tor that path is /home/<operator>/... or
    # /run/user/<uid>/... -- a username, on disk, in a file whose whole design
    # premise is that it carries nothing identifying. Found in a real chain
    # log: 294 entries, every one of them written by this line.
    #
    # The TYPE is what the operator actually needs to tell the cases apart --
    # ModuleNotFoundError (stem missing), FileNotFoundError (no socket),
    # PermissionError (cannot read it), AuthenticationFailure (cookie) -- and
    # it names no path. The full text still reaches the terminal below, in
    # both the abort and the best-effort warning, where it stops.
    integrity_log("tor",
                  f"NEWNYM_fail:{_NEWNYM_CONSECUTIVE_FAILURES}:"
                  f"{type(last_err).__name__ if last_err else 'unknown'}")
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
    #
    # NAME `ctrl` RATHER THAN LETTING THE EXCEPTION CARRY IT. The chain now
    # records only the failure TYPE (above), so this print is the operator's
    # ONLY sight of which socket failed -- and str(last_err)[:60] was cutting
    # the path off mid-way for the commonest case there is: a missing socket.
    #     [Errno 2] No such file or directory: '/home/<user>/.tor/ctrl'
    # is 66 characters, so the truncation ate the end of the path and left a
    # message that says a file is missing without finishing its name.
    # PermissionError's text is shorter and survived, which is why this only
    # showed up when both were driven.
    #
    # ctrl is the exact value, is bounded, and is the thing to check -- the
    # required=True abort a few lines above already names it for the same
    # reason.
    print(f"  [!] Tor circuit rotation failed: "
          f"{type(last_err).__name__ if last_err else 'unknown'} on {ctrl} "
          f"({str(last_err)[:80]}).")
    print(f"      This operation continues on the SAME circuit as the "
          f"previous one.")
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
    r = requests.get(url, timeout=20, proxies=proxies, allow_redirects=False)
    r.raise_for_status()
    return r.json()


@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=4, max=30), reraise=True)
def safe_post(url: str, payload: dict, proxies: Dict[str, str] = None) -> dict:
    if not proxies:      # proxies={} means DIRECT in requests -- see safe_get
        sys.exit("[!] safe_post called without proxies — clearnet leak. Aborting.")
    r = requests.post(url, json=payload, timeout=25, proxies=proxies, allow_redirects=False)
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
        # THE SCHEME IS DROPPED HERE, SO SAY SO RATHER THAN SPEAK CLEARTEXT.
        # Only hostname and port are read; JSONRPCWallet is then constructed
        # with host= and port= and speaks plain HTTP. An operator who
        # configures https://wallet:18083 -- because they put the RPC behind a
        # TLS terminator, which is the ordinary reason to write https -- gets
        # an unencrypted connection and no indication of it. Refusing is the
        # only honest answer: this cannot deliver what the URL asked for, and
        # silently delivering less is the failure mode this whole file is
        # written against.
        if (parsed.scheme or "http").lower() not in ("http", ""):
            sys.exit(
                f"[!] RPC URL scheme {parsed.scheme!r} is not supported.\n"
                f"    This client speaks plain HTTP to host:port -- the scheme "
                f"is not carried through to the connection, so an https:// URL "
                f"would have been spoken in CLEARTEXT with nothing saying so.\n"
                f"    Use http:// and put the confidentiality where this "
                f"toolchain puts it: on the Tor circuit (--tor-proxy) or on "
                f"loopback.")
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
            # BOTH SCHEMES, because monero-python only sets ONE.
            #
            # JSONRPCWallet.__init__ does `self.proxies = {protocol: proxy_url}`
            # -- a single-key map keyed on the scheme of the URL it was given.
            # Inspected on the installed library: passing socks5h://... yields
            # exactly {'http': 'socks5h://127.0.0.1:9050'}. Any request the
            # backend makes over the OTHER scheme carries no proxy at all and
            # goes out clearnet to the operator's remote node.
            #
            # And the verification below could not see it: it asks whether ANY
            # value in the map matches, which a half-covered map satisfies. The
            # comment above it says "an assignment that looks right is not
            # evidence the traffic is proxied", and this was the same mistake
            # one level in -- the map was checked, its COVERAGE was not.
            #
            # Filled in rather than merely asserted, because a missing key is a
            # library detail with an obvious correct value, and refusing here
            # would strand every remote-node operator on a working setup.
            _applied = getattr(self._backend, "proxies", None)
            if isinstance(_applied, dict):
                for _scheme in ("http", "https"):
                    if _applied.get(_scheme) != proxy_url:
                        _applied[_scheme] = proxy_url
            applied = getattr(self._backend, "proxies", None) or {}
            # EVERY scheme, not any: a map covering one of them is how the
            # traffic escaped in the first place.
            if not all(str(applied.get(_s)) == str(proxy_url)
                       for _s in ("http", "https")):
                # THE HOST ITSELF STAYS OFF THE CHAIN. This wrote
                # `non_local_rpc:<host>:<port>` — the operator's remote node,
                # which is very often a v3 onion service they run. chain_safe
                # strips digits and recognises Monero addresses; a lowercase
                # base32 onion name is neither, so it survived intact onto a
                # file that persists. The host is in the abort message below,
                # on the terminal, where the operator needs it; the chain
                # records only THAT a non-local RPC was refused.
                integrity_log("rpc", "non_local_rpc:proxy_VERIFY_FAILED")
                sys.exit(
                    f"[!] The proxy did not attach to the RPC client for "
                    f"{host}:{port}.\n"
                    f"    Refusing to continue: the connection would be clearnet and\n"
                    f"    would leak your IP to that node. Tunnel the RPC externally\n"
                    f"    (socat/ssh) and point at 127.0.0.1 instead."
                )
            integrity_log("rpc", "non_local_rpc:proxy_applied")

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
            timeout=20, proxies=use_proxies, allow_redirects=False)
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
    """Set the flag, say so, and touch NOTHING that can block.

    THIS CALLED integrity_log, AND THAT IS A GUARANTEED DEADLOCK. integrity_log
    takes an exclusive flock on integrity_chain.log.lock for its whole
    read-modify-write, and it opens a FRESH descriptor every call. flock
    conflicts are per open file description, not per process, so a second
    LOCK_EX from inside a signal handler that interrupted the first one blocks
    on a lock only the interrupted code can release -- and it cannot, because
    the handler is on top of it.

    Reproduced, not reasoned about: hold the lock, deliver SIGINT, and the
    process hangs forever. `timeout` had to kill it.

    What that costs is worse than a hang. Every tool here logs at startup and
    receive_watch logs once per failed poll for up to 24 hours, so the window is
    hit in ordinary use -- and an operator whose Ctrl-C does nothing reaches for
    kill -9, which is the one thing this toolchain must not receive: SIGKILL
    runs no finally block, so .gs_pw_* (the plaintext wallet password) and the
    plan files stay on disk. A deadlock here converts an interrupt into a
    secret left behind.

    So the handler records what it wants said and returns. The next ordinary
    integrity_log call writes it, inside the lock, chained in order. If the
    process exits before there is one, the line is lost -- which is the honest
    trade and is stated rather than hidden: a missing line beats an
    uninterruptible process.
    """
    global _SHUTDOWN_REQUESTED
    _SHUTDOWN_REQUESTED = True
    # list.append is a single bytecode under the GIL, so it is safe from a
    # handler; open()/flock() are not.
    _PENDING_CHAIN.append(("signal", f"shutdown_requested_sig={signum}"))
    print(f"\n[!] Shutdown signal received ({signum}). Finishing current operation...")


def install_signal_handlers():
    """Install handlers for SIGINT and SIGTERM, and forbid core dumps.

    Core-dump suppression rides along here because every script that WANTS THE
    HANDLERS calls this at startup.

    THAT IS NOT EVERY SCRIPT, and this docstring used to say it was -- "the one
    hook that reliably covers them all". Two programs never call it, and they
    are the two long-lived servers: gs_console, which holds the wallet spend
    password in its environment for its whole lifetime, and gs_doorbell, which
    decrypts the Pi's X25519 secret and holds it for the life of the server.
    Measured under `ulimit -c unlimited`: RLIMIT_CORE was still infinite at the
    instant each had its secret in memory.

    They cannot simply be added to the list either, which is why the coverage
    gap survived. Both end in a blocking loop wrapped in
    `except KeyboardInterrupt`, and installing these handlers replaces SIGINT's
    default disposition with a flag-setter -- so KeyboardInterrupt stops being
    raised and Ctrl-C stops working. Driven, not reasoned: with the handlers
    installed a delivered SIGINT raises nothing. exit_strategy_simulator's own
    comment names this trap from the other side ("a tool that installs it and
    never checks the flag has SWALLOWED Ctrl-C outright").

    So each of those two calls disable_core_dumps' logic locally -- gs_doorbell
    is forbidden from importing this module at all, and gs_console is
    stdlib-only while this module imports requests -- and
    tests/test_listed_bugs.py pins all three against each other. The sentence
    above is now the true one: this hook covers the scripts that take the
    handlers, and the other two are named rather than assumed.
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
        # finite_decimal: a NaN rate made `rate <= 0` RAISE (caught below, so
        # it degraded to None by accident rather than by design), and an
        # Infinity rate sailed past `<= 0` and was RETURNED as a usable price.
        # Both come straight out of a third-party JSON body.
        rate = finite_decimal(p["monero"]["btc"])
        if rate is None or rate <= 0:
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
    # finite_decimal, not Decimal: this promises to return None when the
    # comparison "cannot be made honestly", and a NaN made it RAISE instead --
    # `Decimal("NaN") <= 0` throws InvalidOperation, so the guard below was the
    # line that crashed. Reachable straight off a swap quote.
    exp = finite_decimal(expected_out)
    amt = finite_decimal(amount_in)
    rate = finite_decimal(rate_in_per_out)
    if exp is None or amt is None or rate is None:
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


#: Sanity cap on a per-TX broadcast delay (7 days). The manifest is the
#: sign->relay trust boundary: an absurd delay from a corrupted or tampered
#: manifest would park signed transactions unbroadcast for effectively ever.
MAX_PLANNED_DELAY = 7 * 24 * 3600


def delay_is_sane(value, cap: bool = True) -> bool:
    """Is this a per-TX delay a relay will honour? ONE rule, THREE readers.

    The manifest path validated strictly -- "a float, a bool or a negative
    index means it was tampered with or corrupted, and coercing it would
    silently mis-key a transaction's delay" -- and the fallback that recovers
    delays from an unsigned plan did `int(tx["delay"])` inside a
    try/except (TypeError, ValueError). int() COERCES, so that except never
    fired for the values the manifest rule exists to catch. Driven, same value
    down both paths:

        True        manifest REFUSED          plan accepted as 1
        3600.9      manifest REFUSED          plan accepted as 3600
        -500        manifest REFUSED          plan accepted as -500
        "604800"    manifest REFUSED          plan accepted as 604800
        10**12      manifest REFUSED (cap)    plan accepted as 10**12

    The last one is the expensive one: 10**12 seconds is ~31,700 years, and
    MAX_PLANNED_DELAY's own refusal says why that matters -- "a manifest that
    stalls the relay indefinitely leaves signed transactions sitting
    unbroadcast". The unsigned plan is read off local disk and is not signed at
    all, so it is a WEAKER trust boundary than the manifest, and it was the one
    validated less.

    cap=False for the manifest reader, which reports the over-cap case with its
    own sentence naming MAX_PLANNED_DELAY; everything else takes the whole rule.

    IT LIVES HERE, NOT IN broadcast_signed_xmr, BECAUSE THERE IS A THIRD
    READER. GhostSpiral sizes the kill timeout it gives the broadcast child
    from the same field -- `sum(max(0, int(t.get("delay") or 0)) for t in
    _ptxs)` -- reading the UNSIGNED plan off local disk, and it coerced exactly
    as the fallback above used to. It does not mis-time a transaction; it
    defeats the timeout. Driven on that expression: a plan delay of 10**12
    yields a child timeout of ~31,700 years, so a hung broadcast is never
    killed, and "604800" quietly buys a week. The rule was written once,
    applied to two readers in one file, and the reader in the OTHER file --
    the weakest boundary of the three -- kept the defect the docstring
    describes. A shared rule in a private module is half a shared rule.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return False
    return not cap or value <= MAX_PLANNED_DELAY


#: The same ceiling for BITCOIN amounts, and it exists for the same measured
#: reason the XMR one does -- applied to the two environment variables that
#: carry a BTC amount and had no bound at all.
#:
#: GS_BTC_AMOUNT and GS_SWAP_AMOUNTS were passed to decimal_env with
#: positive=True and no max_value, so NaN and Infinity were caught and 1e30 was
#: not: it is finite and positive. Every BTC amount in this toolchain is
#: eventually rendered with fmt_btc, which is `.quantize(SATOSHI_BTC)` -- eight
#: decimal places -- and 1e30 needs 39 digits against the default 28-digit
#: context. Driven: `fmt_btc(Decimal("1e30"))` raises decimal.InvalidOperation,
#: the identical crash GS_EXIT_AMOUNT=1e400 produced before max_value was added
#: there, from the identical omission.
#:
#: 100,000,000 BTC against a 21,000,000 hard cap: no real holding is refused,
#: nothing that reaches quantize() can overflow, and this says "that is not an
#: amount" rather than "that amount looks wrong" -- the sanity-ceiling/
#: plausibility-band distinction drawn everywhere else.
BTC_ABSURD_TOTAL = Decimal("100000000")


#: The schema tag thor_swap_preparer stamps on every entry of a pairs bundle.
#: Lived in BOTH receive_watch and thor_swap_preparer -- one constant, two
#: copies, and the writer and the reader are the two sides that must agree
#: about it. Same reasoning as sum_quoted_xmr below, which is here because it
#: was written twice and the copies drifted.
PAIR_SCHEMA = "thor_pairs_v1"


def load_pairs(path) -> list:
    """Load a thor_pairs_v1 bundle (the list thor_swap_preparer writes).

    SHARED, because GhostSpiral reads these too now. It used to be reachable
    only from receive_watch, so a receiver-mode run had no way to learn what
    its own swaps were quoted to deliver and the operator had to retype the
    total by hand -- a decimal that is silent when it is wrong in the direction
    that matters (too low lowers the arrival gate, and the run spends early).
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"pairs bundle not found: {path}")
    try:
        d = json.loads(p.read_text())
    except Exception as e:                                   # noqa: BLE001
        raise ValueError(f"pairs bundle is not readable JSON: {str(e)[:60]}")
    if not isinstance(d, list) or not d:
        raise ValueError("pairs bundle must be a non-empty JSON list")
    for entry in d:
        if not isinstance(entry, dict) or entry.get("schema") != PAIR_SCHEMA:
            raise ValueError(f"every pair must carry schema {PAIR_SCHEMA}")
    return d


def pairs_for_dest(pairs: list, dest_addr: str) -> list:
    """Only the pairs actually routed to THIS receive address.

    A pairs file can hold several swaps to several destinations. Summing all of
    them would set a target this subaddress is never going to reach, and the
    watch would run until timeout on a payment that already completed.
    """
    return [p for p in pairs if p.get("dest_xmr") == dest_addr]


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
    # NEVER ABOVE THE TOTAL. A chunk smaller than one piconero -- a quote can
    # legitimately carry one, Decimal("0.0000000000001") is finite and positive
    # -- puts `total - smallest + PICONERO` ABOVE total, and a floor no arrival
    # can ever reach turns "wait for all of it" into "wait for ever, then blame
    # the swap". A chunk that small cannot be guarded against anyway: it is
    # below the unit the chain represents.
    if guard > total:
        return floor_, False
    if guard > floor_:
        return guard, True
    return floor_, False


def fmt_xmr(x: Decimal) -> str:
    """Render an XMR amount for a human.

    str(Decimal) uses scientific notation for a quantized zero -- a balance of
    nothing printed as "0E-12 XMR", which reads as a malfunction to someone
    watching a payment they are anxious about. Fixed-point always, and trailing
    zeros trimmed so 3.000000000000 shows as 3.
    """
    s = f"{x:f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s or "0"


def progress_line(unlocked: Decimal, total: Decimal, floor_: Decimal) -> str:
    """One human line: what has landed, what is still locked, how far to go.

    SHARED, because two waiters answer the same question and only one of them
    was speaking. receive_watch echoed this on EVERY poll, so an operator saw a
    live figure every 45-90 seconds. GhostSpiral's stage-4 wait
    (wait_for_swap_arrival) printed only when a MEANINGFUL amount arrived -- so
    while a cross-chain swap was still settling, which is the whole point of
    that wait and can take hours, it printed nothing at all. The operator
    watching the console saw a pane that had not moved since the run started
    and no way to tell "waiting" from "hung".

    Kept here rather than imported from receive_watch so neither copy can drift
    into describing the same balance differently.
    """
    pending = total - unlocked
    if pending < 0:
        pending = Decimal(0)
    bits = [f"unlocked {fmt_xmr(unlocked)} XMR"]
    if pending > 0:
        bits.append(f"{fmt_xmr(pending)} still confirming")
    if floor_ > 0:
        remain = floor_ - unlocked
        if remain > 0:
            pct = (unlocked / floor_ * 100) if floor_ > 0 else Decimal(0)
            bits.append(f"{fmt_xmr(remain)} to go ({pct.quantize(Decimal('0.1'))}%)")
        else:
            bits.append("target reached")
    return " · ".join(bits)


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

def instruction_field_safe(value) -> bool:
    """True if `value` can be printed into a copy-paste instruction block.

    Everything in the SENDER INSTRUCTIONS block is attacker-influenced: the
    deposit address, the memo, the amounts and the expected return all come
    back from a quote and are re-read later out of an ordinary JSON file. A
    control character in ANY of them forges a line in a block whose whole
    purpose is to be copied verbatim and paid.

    The memo hole is closed at its own gate (see _memo_fields_bind); this is
    the same rule for the fields that have no gate of their own, so a second
    field cannot be used the way the memo was.

    C1 AS WELL AS C0, because the sibling gate for this exact job already said
    so and this one did not. gs_wake_proto.plain_slip_is_wellformed guards the
    PLAINTEXT slip -- the same deposit address, memo and amount, going to the
    same human to be copied into the same wallet -- with

        ord(c) < 0x20 or 0x7f <= ord(c) <= 0x9f

    while this read `ord(ch) == 0x7f` and let the whole C1 block through. Two
    gates in one repo answering one question two ways is the drift this file
    keeps being rewritten to remove.

    It is not only tidiness. U+009B is the single-character CSI: ECMA-48 allows
    every ESC-Fe sequence to be written as one C1 byte instead, so a terminal
    that honours 8-bit controls treats U+009B exactly as ESC [ -- and ESC is
    blocked here while U+009B was not. Whether a given emulator honours them
    varies (xterm, VTE and the Linux console have each done so in some
    configuration), so this is a hazard that DEPENDS ON THE TERMINAL rather
    than a universal exploit, and it is not worth leaving open to find out: the
    values guarded here are a BTC deposit address, a swap memo and an amount,
    all base58/bech32/ASCII, so nothing legitimate is refused by widening this.
    """
    return not any(ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f
                   for ch in str(value))


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
    raw = str(memo)
    # ONE LINE OF PRINTABLE ASCII, CHECKED BEFORE ANY FIELD IS READ.
    #
    # This function splits on ':' and reads fields 0, 1 and 2. EVERYTHING after
    # the destination field is unexamined -- so a memo that binds perfectly can
    # carry its own forged continuation, and every caller prints the memo
    # verbatim into a copy-paste block it tells the operator to hand to a BTC
    # sender. Driven through the real thor_swap_preparer CLI:
    #
    #   =:XMR.XMR:<OURS>:0/1/0\n  [!] CORRECTION - the vault above rotated.
    #     Use this instead:\n    To address:   <attacker BTC>\n
    #     With memo:    =:XMR.XMR:<attacker XMR>:0/1/0\n    Ignore the
    #     previous block.
    #
    # -> binds True, and the operator is looking at two "To address:" lines
    # with an instruction to use the second. The newline sits in parts[3],
    # which nothing here ever looked at.
    #
    # Nothing legitimate is refused: this value goes into a Bitcoin OP_RETURN,
    # which cannot carry a control character in the first place. My own first
    # attempt at this attack put the newline directly after the destination,
    # which breaks the bind -- that is why an earlier pass concluded, wrongly,
    # that the memo could not be used to inject.
    # THE SHARED GATE, not a third spelling of it. This was
    # `ord(ch) < 0x20 or ord(ch) == 0x7f` inline -- the C0+DEL rule -- and when
    # instruction_field_safe was widened to include the C1 block (U+0080-U+009F,
    # where U+009B is the single-character CSI) this one was left behind. Three
    # gates in one repo screening the same class of value for the same reason,
    # and the widening reached two of them.
    #
    # instruction_field_safe's own docstring claims "The memo hole is closed at
    # its own gate (see _memo_fields_bind); this is the same rule for the
    # fields that have no gate of their own" -- which stopped being true the
    # moment they diverged. Calling it makes the sentence true by construction
    # instead of by coincidence, and there is now one place to change.
    #
    # Nothing legitimate is refused: a ThorChain memo is ASCII by construction
    # and goes into an OP_RETURN, which cannot carry a control character at all.
    if not instruction_field_safe(raw):
        return False
    parts = raw.strip().split(":")
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

#: A standard address is 95 chars, a subaddress 95, an integrated address 106;
#: nothing else this toolchain prints is a 90+ char base58 run, so the length
#: floor makes false positives effectively impossible while still catching all
#: three forms and any future longer one. _B58 is defined once, up beside
#: XMR_ADDR_RE.
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
    except PermissionError:
        # A 0400 FILE THIS TOOLCHAIN WROTE ITSELF, and it could not erase one.
        #
        # O_WRONLY on a read-only file fails with EACCES for everyone except
        # root, and the two most secret files here are minted 0400 ON PURPOSE:
        # gs_wake_keys._write_key ("a writable keyfile is a keyfile something
        # can rewrite between boots") and gs_delivery_key's
        # atomic_write_json(..., perms=0o400). Both hold an X25519 SECRET, and
        # "gs_wake_*.key" is in GS_ARTIFACT_FILE_PATTERNS -- the wipe list.
        #
        # Driven as an ordinary (non-root) owner, which is who runs this:
        #     paranoia_mode._secure_delete_file(gs_wake_thinkpad.key) -> False
        #       still on disk: True, secret still readable: True
        #     gs_delivery_key shred                                   -> printed
        #       "[+] ... destroyed.", rc 0, file still there
        # So the sweep could not erase the keypair it lists, and the one
        # command whose entire job is getting the delivery secret off the vault
        # failed every single time. Every run as root hid it.
        #
        # THE OWNER CAN ALWAYS chmod. Reopened read-only first so the mode
        # change happens through a FILE DESCRIPTOR (fchmod) rather than a path:
        # os.chmod cannot take follow_symlinks=False on Linux, so a path-based
        # chmod is a TOCTOU an attacker could aim at another file. fstat on
        # that same descriptor re-confirms regular-and-mine on the object we
        # actually hold, not on what the name pointed at a moment ago.
        #
        # ONLY the caller's own file, and only to 0600. Somebody else's 0400
        # file still returns False -- this widens nothing it did not already
        # own, and the file is destroyed microseconds later.
        fd = -1
        try:
            rfd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return False
        try:
            rst = os.fstat(rfd)
            if (not stat_module.S_ISREG(rst.st_mode)
                    or rst.st_uid != os.geteuid()):
                return False
            os.fchmod(rfd, 0o600)
        except OSError:
            return False
        finally:
            os.close(rfd)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
        except OSError:
            return False
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
