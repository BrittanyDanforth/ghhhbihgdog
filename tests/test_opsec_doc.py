#!/usr/bin/env python3
"""OPSEC_SETUP.md makes checkable promises about this code. Check them.

A setup document is a security artifact: an operator reads "the console binds
loopback only" or "the slip is 0600" and builds a threat model on it. If the
code later stops doing that, the document becomes a confident lie and the
operator's model is wrong in exactly the place they trusted it. That failure
mode is worse than having no document, because it is invisible.

So every claim OPSEC_SETUP.md makes about THIS REPO is asserted here against
the real source. Claims about hardware, BIOS, routers and Mullvad are the
operator's to verify -- those are listed at the bottom as explicitly untested,
so nobody mistakes this file for covering them.
"""
from pathlib import Path
import sys, os, re, ast, inspect

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

PASS = 0; FAIL = 0; FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1; FAILURES.append(name); print(f"  FAIL: {name}")


DOC_PATH = os.path.join(REPO, "OPSEC_SETUP.md")
check("OPSEC_SETUP.md exists", os.path.isfile(DOC_PATH))
DOC = open(DOC_PATH).read() if os.path.isfile(DOC_PATH) else ""


def src(name):
    return open(os.path.join(REPO, name)).read()


CONSOLE = src("gs_console")
RECV_W = src("receive_watch")
CRW = src("create_receive_wallet")
THOR = src("thor_swap_preparer")
GHOST = src("GhostSpiral")

# The four tools the document names as the ThinkPad's working set.
TOOLS = {"create_receive_wallet": CRW, "thor_swap_preparer": THOR,
         "receive_watch": RECV_W, "GhostSpiral": GHOST}

print("=== §4/§8: 'Console binds 127.0.0.1 only. Do not punch it out.' ===")

check("the console binds loopback and nothing else",
      'ThreadingHTTPServer(("127.0.0.1"' in CONSOLE)
check("no bind to all interfaces anywhere in the console",
      '"0.0.0.0"' not in CONSOLE and "'0.0.0.0'" not in CONSOLE)
check("the doc's claim about loopback is actually present in the doc",
      "127.0.0.1" in DOC)
# "token is per-run"
check("§8: the console token is generated per run, not stored",
      "TOKEN = secrets.token_urlsafe" in CONSOLE)

print("=== §3/§4: fail-closed networking — 'If Tor is down, it does not start' ===")

for n, s in TOOLS.items():
    check(f"{n} verifies Tor before doing anything",
          "verify_tor(" in s)
    check(f"{n} refuses to run without a Tor proxy",
          "--tor-proxy" in s and re.search(
              r'tor.proxy is REQUIRED|"--tor-proxy", required=True|'
              r"'--tor-proxy', required=True", s))
# socks5h, not socks5: the h is remote DNS. socks5:// resolves locally and
# leaks every hostname to the ISP the Mullvad pipe exists to blind.
check("the proxy scheme enforced is socks5h (remote DNS), not socks5",
      "socks5h://" in src("gs_common.py"))

print("=== §1/§4: the slip is 0600, the bundle is 0600, the dir is 0700 ===")

import gs_common as gsc
_sig = inspect.signature(gsc.atomic_write_json)
check("atomic_write_json writes 0600 by default",
      _sig.parameters["perms"].default == 0o600)
check("§1: thor writes the deposit/memo slip through that path",
      "atomic_write_json(pairs" in THOR)
check("§4: create_receive_wallet writes the bundle through that path",
      "atomic_write_json(out" in CRW)
# BEHAVIOURAL, and the guarantee is narrower than it was. This asserted the
# literal "secure_mkdir(outdir)" appears in the source — a substring search
# that broke the moment a keyword argument was added, and that was enforcing
# the F9 defect: --output-dir defaults to ".", and secure_mkdir NARROWS a
# pre-existing directory, so every run chmod'ed the operator's working
# directory to 0700. The tool no longer modifies a directory it did not create.
#
# What survives, and what §1/§4 actually depend on: the bundle FILE is 0600, so
# its contents stay private wherever it lands; a directory the tool creates is
# still 0700; and the operator is warned when the directory they chose is
# listable by others.
import stat as _st, tempfile as _tfd, shutil as _shd
_dd = _tfd.mkdtemp(prefix="opsecdir_")
_pre = os.path.join(_dd, "theirs")
os.mkdir(_pre); os.chmod(_pre, 0o755)
gsc.secure_mkdir(_pre, narrow_existing=False)
check("create_receive_wallet does NOT re-permission a directory the operator "
      "already had", _st.S_IMODE(os.stat(_pre).st_mode) == 0o755)
_new = os.path.join(_dd, "ours")
gsc.secure_mkdir(_new)
check("...while a directory it CREATES is owner-only",
      _st.S_IMODE(os.stat(_new).st_mode) == 0o700)
_bundle = os.path.join(_pre, "b.json")
gsc.atomic_write_json({"x": 1}, Path(_bundle))
check("...and the bundle FILE is 0600 wherever it lands, which is what keeps "
      "its contents private", _st.S_IMODE(os.stat(_bundle).st_mode) == 0o600)
# Whitespace-normalised, and the adjacent string literals joined: the warning
# is written across three source lines as implicitly-concatenated strings, so a
# plain substring search finds nothing and reports a missing warning that is
# right there. This repo's audit lists that exact failure ("a line-based count
# missed a call that wrapped to a second line") among the tests that were
# wrong about working code.
_crw_flat = re.sub(r"\s+", " ", CRW)
# join implicitly-concatenated literals, including the f-prefixed continuations
_crw_flat = re.sub(r'"\s*f?"', "", _crw_flat)
check("create_receive_wallet warns when the chosen directory is listable",
      "other local accounts can list it" in _crw_flat)
_shd.rmtree(_dd, ignore_errors=True)
check("secure_mkdir is 0700 by default",
      inspect.signature(gsc.secure_mkdir).parameters["mode"].default == 0o700)

print("=== §4: the ThinkPad wallet is VIEW-ONLY — the watch path must not spend ===")

# A view-only wallet cannot sign. The two tools the doc says run unattended
# (create_receive_wallet, receive_watch) must therefore never attempt a spend;
# if they did, the "pager wakes the box" flow would be trying to move money on
# a networked machine, which is the failure the whole layout exists to prevent.
SPEND_CALLS = ("transfer_split", "sign_transfer", "submit_transfer",
               "relay_tx", "sweep_all", "sweep_single")
for n in ("create_receive_wallet", "receive_watch"):
    s = TOOLS[n]
    found = [c for c in SPEND_CALLS if c in s]
    check(f"{n} makes no spend call (view-only safe): {found or 'none'}", not found)
check("§8: the doc says the mix needs the spend USB, and GhostSpiral is the mix",
      "spend USB" in DOC and "run_pipeline" in DOC)

print("=== §1: 'Telegram never gets: XMR address, memo ... ' ===")

# The doc is explicit that the pager is NOT in this repo. If a Telegram
# integration ever lands without the split being honoured, this catches it:
# nothing here may hold a bot token or post to a chat.
# The wake channel is included: gs_doorbell is the program most likely to grow
# a bot, because it is the one a trigger would talk to.
ALL_SRC = "\n".join([CONSOLE, RECV_W, CRW, THOR, GHOST, src("gs_common.py"),
                     src("airgap_tx_signer"), src("broadcast_signed_xmr"),
                     src("paranoia_mode"), src("gs_doorbell"),
                     src("gs_wake_agent"), src("gs_wake_keys"),
                     src("gs_wake_proto.py")])
for marker in ("api.telegram.org", "sendMessage", "bot_token", "TELEGRAM_TOKEN",
               "chat_id"):
    check(f"no shipped code talks to Telegram ({marker})", marker not in ALL_SRC)

# TWO INDEPENDENT CLAIMS, TWO INDEPENDENT CHECKS.
#
# This was ONE five-way OR over both of them:
#
#   check("the doc is honest that the pager is not shipped",
#         "not in this repo yet" in DOC or "not a\nshipped binary" in DOC
#         or ... or "operator procedure" in DOC)
#
# The doc makes two claims that are true at different times. "The Telegram
# pager is not in this repo yet" stays true -- no bot ships. "The Pi doorbell
# is operator procedure, not a shipped binary" became FALSE the moment
# gs_doorbell landed. Under the OR, shipping the doorbell and changing nothing
# in the doc still matched the FIRST clause: ALL GREEN, while the repo shipped
# a doorbell its own security document said it did not. That is the failure
# this file's docstring names -- "the document becomes a confident lie ...
# worse than having no document, because it is invisible" -- committed by the
# test written to prevent it.
# THE PAGER SHIPPED, SO THIS CHECK HAD TO CHANGE -- and the point of the essay
# above is that changing it is the ONLY honest move. gs_telegram_pager landed;
# a doc still saying "not in this repo yet" would be the confident lie this
# file exists to catch, and a test still asserting that sentence would be
# holding the doc to a claim the repo had already broken.
check("the doc is honest that the TELEGRAM PAGER now IS shipped",
      "**is** now in this repo" in DOC and "gs_telegram_pager" in DOC)
check("...and the pager the doc names actually exists on disk",
      os.path.isfile(os.path.join(REPO, "gs_telegram_pager")))
check("...and the doc no longer calls steps 1-2 unshipped procedure",
      "no trigger is shipped" not in DOC)

# THE SPLIT IS NOW THE GUARANTEE, not the absence. One tool may talk to
# Telegram; what none of them may do is carry the secret across.
_PAGER = src("gs_telegram_pager")
# NOT a substring hunt for the word "memo": it appears throughout the pager's
# own docstring explaining what it refuses to do, so any such check is either
# false or -- as the first draft of this line was -- rescued by an `or` that
# made it true no matter what. The real guarantee is behavioural and is driven
# in tests/test_telegram_pager.py, which runs every outcome path and asserts
# no address, memo or deposit address reaches the chat. What belongs HERE is
# the structural half: the pager never reads a field that holds one.
check("the pager's replies are built from a fixed vocabulary, not from job "
      "output: the only interpolations are the job name and the handle",
      _PAGER.count("self.send(") >= 5
      and "slip {h}" in _PAGER
      and "pending.result" in _PAGER)
for _forbidden in ("dest_xmr", "deposit", "expected_xmr", "btc_in",
                   "thor_pairs", "unsigned_"):
    check(f"the pager never reads a field named {_forbidden}",
          f'"{_forbidden}"' not in _PAGER and f"'{_forbidden}'" not in _PAGER)
check("the pager cannot name a destination: no job it sends takes one",
      "--exit-to" not in _PAGER and "--dest" not in _PAGER)
check("the pager reports only a handle, and says where the address really is",
      "slip {h}" in _PAGER and "on the vault" in _PAGER)
check("the pager's token never has a CLI flag, since argv is world-readable",
      '"--token"' not in _PAGER and "--token-file" in _PAGER)
check("the pager is fail-closed on Tor, as section 4 requires",
      "verify_tor(proxy)" in _PAGER)
check("...and does NOT still call the doorbell operator procedure, now that "
      "it ships",
      "operator procedure" not in DOC and "not a\nshipped binary" not in DOC)
check("...and the doorbell the doc describes actually exists on disk",
      all(os.path.isfile(os.path.join(REPO, f))
          for f in ("gs_doorbell", "gs_wake_agent", "gs_wake_keys",
                    "gs_wake_proto.py")))
check("...and the doc names the real invocations, not a sketch",
      "gs_doorbell wake" in DOC and "gs_wake_agent" in DOC
      and "gs_wake_keys" in DOC)

print("=== §3: 'What the Pi must never hold' — enforced, not asserted ===")
# The doorbell runs on the box the doc defines by what it must NOT hold. This
# turns that paragraph into a test. code_only, so the header that NAMES these
# as forbidden does not satisfy the check.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from srcutil import code_only                                # noqa: E402
_bell_code = code_only(os.path.join(REPO, "gs_doorbell"))
import ast as _ast
_bell_mods = set()
for _n in _ast.walk(_ast.parse(src("gs_doorbell"))):
    if isinstance(_n, _ast.Import):
        _bell_mods.update(a.name.split(".")[0] for a in _n.names)
    elif isinstance(_n, _ast.ImportFrom) and _n.module:
        _bell_mods.add(_n.module.split(".")[0])
for _m in ("gs_common", "monero", "stem", "psutil", "requests", "tenacity"):
    check(f"the Pi doorbell does not import {_m}", _m not in _bell_mods)
for _w in ("wallet_", "thor_pairs", "view_key", "spend_key", "mnemonic", "seed"):
    check(f"...and its code never mentions {_w}", _w not in _bell_code)
check("the doorbell binds an exact address, never all interfaces",
      '"0.0.0.0"' in _bell_code and "refusing to bind" in _bell_code.lower())

print("=== §4: 'Do not use the Pi as a Tor proxy' — checked, not promised ===")
# The vault's proxy comes from ITS OWN keyfile. If any argv template sourced a
# proxy from the note, a pwned Pi could put itself on the path -- which is the
# one thing §4 forbids by name, and which nothing verified until now.
_agent_code = code_only(os.path.join(REPO, "gs_wake_agent"))
check("the agent takes its Tor proxy from its keyfile",
      'key["tor_proxy"]' in _agent_code)
check("...and no schema field a note can carry is a free-form string",
      '"--tor-proxy", proxy' in _agent_code)
# The contiguous half of the sentence -- the markdown wrap splits it after
# "Do not use", and a check that matches across a line break is a check that
# breaks on a reflow rather than on a behaviour change.
check("§4: the doc still says not to proxy through the Pi",
      "the Pi as a Tor proxy" in DOC)

print("=== §1: the memo is the address — it must never reach a log ===")

# The memo carries the destination address verbatim, so logging it is logging
# the address. Every integrity_log call in the swap paths is checked for it.
for n in ("thor_swap_preparer", "GhostSpiral"):
    s = TOOLS[n]
    bad = []
    for m in re.findall(r"integrity_log\(([^)]*)\)", s, re.S):
        if re.search(r"\{\s*memo", m) or re.search(r"\bmemo\b(?![_a-z])", m.split(",")[-1]):
            bad.append(m[:60])
    check(f"{n} never interpolates the memo into the integrity chain: {bad or 'clean'}",
          not bad)

print("=== §8: the receive path the doc documents is the path the code offers ===")

# The doc tells the operator to run these three, in this order, with this flag.
check("§8: --dest-from-receive-wallet exists as documented",
      "--dest-from-receive-wallet" in THOR and "--dest-from-receive-wallet" in DOC)
check("§8: receive_watch exists as documented", os.path.isfile(
    os.path.join(REPO, "receive_watch")))
check("§8: the console exposes all three receive steps",
      all(f'"{a}"' in CONSOLE for a in ("make_receive", "swap_quote", "watch_receive")))

print("=== §7: 'find on the Pi SD: no wallet, no thor_pairs' — nothing writes off-box ===")

# Every artifact these tools write must land where the operator pointed them,
# never at a hard-coded shared or world-readable location. Checked structurally:
# find the actual write calls and confirm none targets a fixed absolute path.
WRITERS = ("atomic_write_json", "atomic_write_text", "secure_write_text",
           "secure_write_bytes")
for n, s in TOOLS.items():
    hard = []
    for node in ast.walk(ast.parse(s)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in WRITERS):
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str) \
                        and a.value.startswith("/"):
                    hard.append(f"{node.func.id}->{a.value}")
    check(f"{n} writes no artifact to a hard-coded absolute path: {hard or 'none'}",
          not hard)
check("no tool writes a secret to a hard-coded /tmp path",
      not re.search(r'["\']/tmp/[a-z_]*(wallet|pairs|memo|key|seed)', ALL_SRC, re.I))

# ===========================================================================
# EVERY FLAG THE DOC SHOWS MUST EXIST IN THE TOOL IT IS SHOWN ON.
#
# This suite has always claimed to check that the doc matches the code, and it
# did not check this. The pairing tool's flags were renamed and rewritten and
# §8 went on printing `--thinkpad-mac` and `--doorbell-host` at the operator,
# green the whole time. An operator following the doc would have got
# "unrecognized arguments" at the one moment that requires physical access to
# both boxes.
#
# So: pull every shipped-tool invocation out of the fenced blocks, resolve the
# subcommand, and ask argparse itself. A doc that names a flag that does not
# exist is a doc that has stopped describing this repository.
import subprocess as _sp                                     # noqa: E402

_TOOLS = {"GhostSpiral", "gs_console", "gs_doorbell", "gs_wake_agent",
          "gs_wake_keys", "airgap_tx_signer", "broadcast_signed_xmr",
          "create_receive_wallet", "exit_strategy_simulator", "paranoia_mode",
          "receive_watch", "thor_swap_preparer"}
_help_cache = {}


def _help_for(tool, sub):
    key = (tool, sub)
    if key not in _help_cache:
        argv = [sys.executable, os.path.join(REPO, tool)]
        if sub:
            argv.append(sub)
        argv.append("--help")
        try:
            r = _sp.run(argv, capture_output=True, text=True, timeout=120)
            _help_cache[key] = r.stdout + r.stderr
        except Exception as e:                               # noqa: BLE001
            _help_cache[key] = f"<<could not run: {e}>>"
    return _help_cache[key]


#: Join backslash continuations so a wrapped command is one command.
_blocks = re.findall(r"```(?:bash|sh)?\n(.*?)```", DOC, re.S)
_cmds = []
for _b in _blocks:
    _b = _b.replace("\\\n", " ")
    for _line in _b.splitlines():
        _line = _line.split("#", 1)[0].strip()
        if not _line:
            continue
        # One logical command may be piped into another; look at each stage.
        for _stage in _line.split("|"):
            _toks = _stage.strip().split()
            _tool = None
            for _i, _t in enumerate(_toks):
                _base = os.path.basename(_t)
                if _base in _TOOLS:
                    _tool = _base
                    _rest = _toks[_i + 1:]
                    break
            if not _tool:
                continue
            _sub = None
            if _rest and not _rest[0].startswith("-"):
                _sub = _rest[0]
            _flags = sorted({_t.split("=")[0] for _t in _rest
                             if _t.startswith("--") and len(_t) > 2})
            _cmds.append((_tool, _sub, _flags, _stage.strip()))

check("the doc actually shows some shipped-tool invocations to check "
      "(a parser that silently matches nothing would pass this section "
      "vacuously forever)", len(_cmds) >= 5)

_missing = []
for _tool, _sub, _flags, _raw in _cmds:
    _h = _help_for(_tool, _sub)
    if _h.startswith("<<could not run"):
        _missing.append(f"{_tool} {_sub or ''}: {_h}")
        continue
    for _f in _flags:
        if _f not in _h:
            _missing.append(f"{_tool} {_sub or ''} has no {_f}  (doc: {_raw[:60]})")
check(f"every --flag the doc shows on a shipped tool exists in that tool "
      f"({len(_cmds)} invocations checked)"
      + ("" if not _missing else " -- " + "; ".join(_missing[:4])),
      not _missing)

# And the subcommands themselves.
_badsub = []
for _tool, _sub, _flags, _raw in _cmds:
    if not _sub:
        continue
    _h = _help_for(_tool, None)
    if "<<could not run" in _h:
        continue
    if _sub not in _h:
        _badsub.append(f"{_tool} has no subcommand {_sub!r}")
check("every subcommand the doc shows exists"
      + ("" if not _badsub else " -- " + "; ".join(_badsub[:4])),
      not _badsub)


print()
print("NOT COVERED HERE (operator must verify by hand, per §7):")
for item in ("rfkill wifi/bt blocked on the Pi",
             "no default route when wg0 is down",
             "am.i.mullvad.net connected before Tor starts",
             "BIOS: WOL on, power-loss stay-off, WiFi/BT off",
             "router has no UDP 9 forward",
             "spend USB physically removed",
             "throwaway Telegram account"):
    print(f"  - {item}")

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    for f in FAILURES:
        print("  - " + f)
    sys.exit(1)
print("ALL GREEN")
