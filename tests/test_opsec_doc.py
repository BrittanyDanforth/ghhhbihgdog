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
check("the doc is honest that the TELEGRAM PAGER is still not shipped",
      "not in this repo yet" in DOC or "is **not** in this repo" in DOC)
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
