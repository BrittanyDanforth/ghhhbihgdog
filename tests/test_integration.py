#!/usr/bin/env python3
"""Integration tests that drive the REAL phase_create and broadcast.main()
with mocked RPC/Tor, so the actual code paths (multi-dest RPC contract, and the
resume/exit logic where the false-success bug lived) truly execute."""
import sys, os, tempfile, json, hashlib, types, importlib.util, importlib.machinery
from decimal import Decimal
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

def load(name):
    loader = importlib.machinery.SourceFileLoader(name.replace(".py", ""), os.path.join(REPO, name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec); loader.exec_module(mod); return mod

gs = load("gs_common.py"); airgap = load("airgap_tx_signer"); bcast = load("broadcast_signed_xmr")
os.chdir(tempfile.mkdtemp(prefix="gs_itest_"))

PASS = 0; FAIL = 0; FAILURES = []
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1
    else: FAIL += 1; FAILURES.append(name); print(f"  FAIL: {name}")

# ===========================================================================
# A. phase_create multi-destination contract (REAL phase_create, fake RPC)
# ===========================================================================
class FakeRPC:
    def __init__(self): self.calls = []
    def raw_request(self, method, params):
        self.calls.append((method, params))
        return {"unsigned_txset": "deadbeef"}  # non-empty hex-ish

airgap.verify_tor = lambda *a, **k: None
fake = FakeRPC()
airgap.connect_rpc = lambda *a, **k: fake

plan = [
    {"src": "ENTRY", "src_index": 7,
     "destinations": [{"address": "M1", "amount": "0.3"},
                      {"address": "M2", "amount": "0.3"},
                      {"address": "M3", "amount": "0.3"}]},              # fan-out
    {"src": "M1", "src_index": 11, "dst": "M2", "amt": "0.25"},          # dag hop
]
args = types.SimpleNamespace(tor_proxy="socks5h://127.0.0.1:9050",
                             rpc="http://127.0.0.1:18083",
                             outdir=os.path.join(os.getcwd(), "staging_A"),
                             fee_priority=2)
airgap.phase_create(args, plan, {"account_index": 5})

check("phase_create: issued 2 transfer_split calls", len(fake.calls) == 2)
fanout_params = fake.calls[0][1]
check("phase_create: fan-out is ONE call with 3 destinations",
      len(fanout_params["destinations"]) == 3)
check("phase_create: fan-out atomic amounts correct",
      [d["amount"] for d in fanout_params["destinations"]] == [300_000_000_000]*3)
check("phase_create: fan-out subaddr_indices = [src_index]",
      fanout_params["subaddr_indices"] == [7])
check("phase_create: account_index from meta",
      fanout_params["account_index"] == 5)
check("phase_create: priority passed through",
      fanout_params["priority"] == 2)
check("phase_create: do_not_relay set",
      fanout_params["do_not_relay"] is True)
hop_params = fake.calls[1][1]
check("phase_create: dag hop is single dest atomic",
      hop_params["destinations"] == [{"amount": 250_000_000_000, "address": "M2"}])
check("phase_create: dag hop subaddr_indices = [11]",
      hop_params["subaddr_indices"] == [11])
# manifest written with per-tx entries
mani = json.loads((Path(args.outdir) / "unsigned_manifest.json").read_text())
check("phase_create: manifest has 2 entries", len(mani["entries"]) == 2)
check("phase_create: multi-dest manifest summarized as _dests",
      mani["entries"][0]["dst"].endswith("_dests"))

# ===========================================================================
# B. broadcast resume/exit logic (REAL main(), fake _single_post + Tor)
# ===========================================================================
bcast.verify_tor = lambda *a, **k: None
bcast.newnym = lambda *a, **k: True
bcast.secure_delay = lambda *a, **k: None
bcast.tor_recheck = lambda *a, **k: None

def make_blobs(dirname, n):
    d = Path(os.getcwd()) / dirname; d.mkdir(parents=True, exist_ok=True)
    entries = []
    for i in range(n):
        b = d / f"tx_{i}.signed"; data = f"BLOB{i}".encode()
        b.write_bytes(data)
        entries.append({"idx": i, "file": str(b),
                        "hash": hashlib.sha256(data).hexdigest(),
                        "dst": f"D{i}", "amt": "1", "delay": 0})
    (d / "signed_manifest_v1.json").write_text(json.dumps(entries))
    return d

def run_broadcast(blob_dir, progfile, outcomes):
    """outcomes: dict hex(blobbytes)->('ok'|'double'|'raise'). Returns exit code
    (0 if main returned normally, else the SystemExit code)."""
    def fake_post(url, payload, proxies=None):
        h = payload["params"]["tx_data_hex"]
        o = outcomes.get(h, "ok")
        if o == "raise":
            raise Exception("simulated transient node error")
        if o == "double":
            return {"error": {"message": "Failed to parse tx: double spend detected"}}
        if o == "keyimage":
            return {"error": {"message": "Rejected by daemon: key image already spent"}}
        if o == "baddata":
            # REAL wallet-rpc 0.18.3.1 response for a corrupt signed blob.
            return {"error": {"code": -40, "message": "Failed to parse signed tx data."}}
        return {"result": {"tx_hash_list": ["a" * 64]}}
    bcast._single_post = fake_post
    sys.argv = ["broadcast_signed_xmr", str(blob_dir),
                "--tor-proxy", "socks5h://127.0.0.1:9050",
                "--rpc", "http://127.0.0.1:18083",
                "--resume", str(progfile), "--rebroadcast", "2"]
    try:
        bcast.main(); return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1

def hx(dirp, i):
    return (Path(dirp) / f"tx_{i}.signed").read_bytes().hex()

# --- B1: all relay -> exit 0, both in 'relayed' ---
d = make_blobs("bcast_B1", 2); prog = Path(os.getcwd()) / "progB1.json"
code = run_broadcast(d, prog, {hx(d,0): "ok", hx(d,1): "ok"})
p = json.loads(prog.read_text())
check("B1: full success returns 0", code == 0)
check("B1: both relayed", sorted(p["relayed"]) == [0, 1])
check("B1: none failed_perm", p["failed_perm"] == [])

# --- B2: one double-spend -> exit nonzero, idx1 permanent ---
d = make_blobs("bcast_B2", 2); prog = Path(os.getcwd()) / "progB2.json"
code = run_broadcast(d, prog, {hx(d,0): "ok", hx(d,1): "double"})
p = json.loads(prog.read_text())
check("B2: permanent failure exits nonzero", code != 0)
check("B2: idx0 relayed", p["relayed"] == [0])
check("B2: idx1 failed_perm", p["failed_perm"] == [1])

# --- B3: THE false-success test. Resume B2 (idx1 permanently failed) with the
#         node now healthy. idx1 is skipped (permanent), NOT retried, and the
#         run must STILL exit nonzero because not everything relayed. This is
#         exactly the bug the reviewer found and I fixed. ---
code = run_broadcast(d, prog, {hx(d,0): "ok", hx(d,1): "ok"})
p = json.loads(prog.read_text())
check("B3: resume of all-permanent-among-unrelayed still exits NONZERO", code != 0)
check("B3: idx1 stays failed_perm (not retried into relayed)",
      p["failed_perm"] == [1] and 1 not in p["relayed"])

# --- B4: transient failure is retried on resume ---
d = make_blobs("bcast_B4", 2); prog = Path(os.getcwd()) / "progB4.json"
code = run_broadcast(d, prog, {hx(d,0): "ok", hx(d,1): "raise"})
p = json.loads(prog.read_text())
check("B4: transient failure exits nonzero", code != 0)
check("B4: transient NOT marked permanent", p["failed_perm"] == [] and p["relayed"] == [0])
# resume with node healthy -> idx1 retried and relayed -> exit 0
code = run_broadcast(d, prog, {hx(d,0): "ok", hx(d,1): "ok"})
p = json.loads(prog.read_text())
check("B4: resume retries transient and succeeds (exit 0)", code == 0)
check("B4: both relayed after resume", sorted(p["relayed"]) == [0, 1])

# --- B5: a key-image rejection (no literal 'double spend' phrase) must still
#         be classified PERMANENT, not retried as transient. ---
d = make_blobs("bcast_B5", 1); prog = Path(os.getcwd()) / "progB5.json"
code = run_broadcast(d, prog, {hx(d, 0): "keyimage"})
p = json.loads(prog.read_text())
check("B5: key-image error exits nonzero", code != 0)
check("B5: key-image classified permanent (failed_perm)", p["failed_perm"] == [0])
check("B5: key-image not retried as transient", p["relayed"] == [])

# --- B6: real wallet-rpc code -40 "Failed to parse signed tx data" is
#         classified PERMANENT (corrupt blob needs re-signing, not retry). ---
d = make_blobs("bcast_B6", 1); prog = Path(os.getcwd()) / "progB6.json"
code = run_broadcast(d, prog, {hx(d, 0): "baddata"})
p = json.loads(prog.read_text())
check("B6: code -40 exits nonzero", code != 0)
check("B6: code -40 classified permanent", p["failed_perm"] == [0] and p["relayed"] == [])

# ===========================================================================
# C. phase_sign must NEVER put the wallet password on the child's argv.
#    An argv secret is readable by every local user via `ps -eo args` and the
#    world-readable /proc/<pid>/cmdline -- and this is the spend-key password.
#    Drives the REAL phase_sign with subprocess.run intercepted, so the actual
#    argv it would have executed is inspected.
# ===========================================================================
import subprocess as _subprocess

SECRET_PW = "S3cret-Spend-Pass!"

_sign_dir = Path(os.getcwd()) / "signC"
_sign_dir.mkdir(parents=True, exist_ok=True)
_unsigned = _sign_dir / "tx_0.unsigned"
_unsigned.write_text("00")          # valid hex; content irrelevant, run is faked
_plan_C = [{"src": "A", "dst": "B", "amt": "0.1", "delay": 0}]
(_sign_dir / "unsigned_manifest.json").write_text(json.dumps({
    "plan_fingerprint": airgap._compute_plan_fingerprint(_plan_C),
    "phase": "unsigned",
    "entries": [{"idx": 0, "file": str(_unsigned),
                 "hash": hashlib.sha256(_unsigned.read_text().encode()).hexdigest(),
                 "dst": "B", "amt": "0.1", "delay": 0}],
}))
_fake_wallet = Path(os.getcwd()) / "walletC.bin"
_fake_wallet.write_bytes(b"wallet")

captured = {}
_real_run = airgap.subprocess.run


def _capture_run(cmd, **kw):
    captured["cmd"] = list(cmd)
    captured["stdin"] = kw.get("input", "")
    # Read the password file back while it still exists, to prove the secret
    # actually reached wallet-cli by that route (not silently dropped).
    for i, tok in enumerate(cmd):
        if tok == "--password-file":
            pf = Path(cmd[i + 1])
            captured["pw_path"] = pf
            captured["pw_content"] = pf.read_text() if pf.exists() else None
    # Simulate wallet-cli writing the signed output so phase_sign proceeds.
    Path(kw["cwd"], "signed_monero_tx").write_bytes(b"Monero signed tx set\x00fake")
    return types.SimpleNamespace(returncode=0, stdout="", stderr="")


airgap.subprocess.run = _capture_run
try:
    _args_C = types.SimpleNamespace(outdir=str(_sign_dir), wallet_cli="monero-wallet-cli",
                                    wallet_file=str(_fake_wallet), wallet_password=SECRET_PW)
    airgap.phase_sign(_args_C, _plan_C)
finally:
    airgap.subprocess.run = _real_run

_argv = captured.get("cmd", [])
check("C: phase_sign executed a command", bool(_argv))
check("C: wallet password NOT anywhere in argv (ps-visible)",
      not any(SECRET_PW in str(tok) for tok in _argv))
check("C: no --password flag used at all", "--password" not in _argv)
check("C: uses --password-file instead", "--password-file" in _argv)
check("C: the password file actually carried the secret",
      captured.get("pw_content") == SECRET_PW)
check("C: password file securely erased after signing",
      captured.get("pw_path") is not None and not captured["pw_path"].exists())
# The verified stdin protocol must be unchanged: password first, then y's.
check("C: stdin still sends password first (protocol unchanged)",
      captured.get("stdin", "").startswith(SECRET_PW + "\n"))
check("C: stdin still sends the y confirmations",
      captured.get("stdin", "").endswith("y\ny\ny\n"))
# And the signing still succeeded end-to-end through the real code path.
check("C: signed blob still produced via password-file path",
      (_sign_dir / "signed" / "tx_0.signed").exists())
# The signed blob is a relayable transaction: it must never exist world-readable,
# not even briefly. Original check here was VACUOUS -- it asserted only the
# FINAL mode == 0o600, which the buggy write_bytes()+chmod pattern ALSO reaches
# (chmod-after still ends at 0600). Rerun phase_sign with secure_file_perms
# NEUTRALISED, so the check only passes if the mode was set AT CREATION by
# secure_write_bytes rather than chmod'ed after.
_sign_dir2 = Path(os.getcwd()) / "signC2"; _sign_dir2.mkdir(exist_ok=True)
_u2 = _sign_dir2 / "tx_0.unsigned"; _u2.write_text("00")
(_sign_dir2 / "unsigned_manifest.json").write_text(json.dumps({
    "plan_fingerprint": airgap._compute_plan_fingerprint(_plan_C),
    "phase": "unsigned",
    "entries": [{"idx": 0, "file": str(_u2),
                 "hash": hashlib.sha256(_u2.read_text().encode()).hexdigest(),
                 "dst": "B", "amt": "0.1", "delay": 0}],
}))

_prev_perms = airgap.secure_file_perms
def _capture_run2(cmd, **kw):
    Path(kw["cwd"], "signed_monero_tx").write_bytes(b"Monero signed tx set\x00fake2")
    return types.SimpleNamespace(returncode=0, stdout="", stderr="")

airgap.secure_file_perms = lambda *a, **k: None    # neutralised
_prev_run = airgap.subprocess.run
airgap.subprocess.run = _capture_run2
try:
    _args_C2 = types.SimpleNamespace(outdir=str(_sign_dir2), wallet_cli="monero-wallet-cli",
                                     wallet_file=str(_fake_wallet), wallet_password=SECRET_PW)
    airgap.phase_sign(_args_C2, _plan_C)
finally:
    airgap.secure_file_perms = _prev_perms
    airgap.subprocess.run = _prev_run

_blob2 = _sign_dir2 / "signed" / "tx_0.signed"
check("C: signed tx created 0600 even WITHOUT any chmod (proves it is set at "
      "open() time, not chmod-after)",
      _blob2.exists() and (_blob2.stat().st_mode & 0o777) == 0o600)

# ===========================================================================
# D. GhostSpiral orchestration must actually WIRE the safety features through
#    to its child processes. Building a check and not connecting it to the
#    main path is the failure mode these assertions exist to prevent.
# ===========================================================================
ghost = load("GhostSpiral")

# D1: relay-egress refusal happens at STAGE 0, before any work. Discovering a
# clearnet daemon at broadcast time would mean refusing only after the fan-out,
# the on-chain confirmation wait and the signing -- leaving signed transactions
# on disk for nothing.
_reached = {"rpc": False}


def _boom_connect(*a, **k):
    _reached["rpc"] = True
    raise RuntimeError("stage 0 should have aborted before RPC connect")


_saved = (ghost.verify_tor, ghost.require_resources,
          ghost.check_daemon_relay_egress, ghost.connect_rpc)
try:
    ghost.verify_tor = lambda *a, **k: None
    ghost.require_resources = lambda *a, **k: None
    ghost.connect_rpc = _boom_connect
    ghost.check_daemon_relay_egress = lambda *a, **k: {
        "verdict": "clearnet", "onion": 0, "clear": 4, "detail": "4 clearnet peer(s)"}
    _argv = sys.argv[:]
    sys.argv = ["GhostSpiral", "--btc-entry",
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                "--tor-proxy", "socks5h://127.0.0.1:9050"]
    _msg = ""
    try:
        ghost.main()
    except SystemExit as e:
        _msg = str(e)
    finally:
        sys.argv = _argv
    check("D1: GhostSpiral aborts on clearnet relay egress",
          "Aborting BEFORE any work" in _msg)
    check("D1: abort happens BEFORE any RPC work is done", _reached["rpc"] is False)
finally:
    (ghost.verify_tor, ghost.require_resources,
     ghost.check_daemon_relay_egress, ghost.connect_rpc) = _saved

# D2: the egress flags must actually REACH the broadcast child. The check was
# implemented in broadcast first and left unwired here, so the orchestrated
# path -- the primary one -- silently skipped it.
_stage = Path(os.getcwd()) / "stageD"
(_stage / "signed").mkdir(parents=True, exist_ok=True)
(_stage / "tx_0.unsigned").write_text("00")
(_stage / "signed" / "tx_0.signed").write_bytes(b"x")
_planD = Path(os.getcwd()) / "planD.json"
_planD.write_text("{}")


def _child_argv(allow_clearnet):
    seen = []
    real_run, real_log = ghost.subprocess.run, ghost.integrity_log
    try:
        ghost.subprocess.run = lambda cmd, **kw: (
            seen.append(list(cmd)), types.SimpleNamespace(returncode=0))[1]
        ghost.integrity_log = lambda *a, **k: None
        a = types.SimpleNamespace(
            tor_proxy="socks5h://127.0.0.1:9050",
            rpc_primary="http://127.0.0.1:18083",
            rpc_daemon="http://127.0.0.1:18081",
            wallet_file="w", wallet_password="SECRET-PW", fee_priority=1,
            allow_clearnet_relay=allow_clearnet)
        ghost._run_round(a, _planD, str(_stage), "Fan-out")
    finally:
        ghost.subprocess.run, ghost.integrity_log = real_run, real_log
    return seen


_cmds = _child_argv(False)
_bc = [c for c in _cmds if "broadcast_signed_xmr" in c]
check("D2: GhostSpiral spawns the broadcast child", len(_bc) == 1)
check("D2: --rpc-daemon forwarded (so the child VERIFIES egress, not warns)",
      "--rpc-daemon" in _bc[0])
check("D2: --allow-clearnet-relay NOT forwarded when not requested",
      "--allow-clearnet-relay" not in _bc[0])

_bc_allow = [c for c in _child_argv(True) if "broadcast_signed_xmr" in c]
check("D2: --allow-clearnet-relay IS forwarded when the operator set it "
      "(otherwise the child would refuse despite the override)",
      "--allow-clearnet-relay" in _bc_allow[0])

# D3: the signer child must never receive the wallet password on argv, where
# any local user can read it from /proc/<pid>/cmdline (mode 444).
_sign = [c for c in _cmds if "airgap_tx_signer" in c and "sign" in c]
check("D3: GhostSpiral spawns the signer child", len(_sign) == 1)
check("D3: wallet password NOT on the signer child's argv",
      not any("SECRET-PW" in str(t) for t in _sign[0]))
check("D3: --wallet-password flag not used at all",
      "--wallet-password" not in _sign[0])

# D4: the password must reach ONLY the sign child. subprocess.run() with no
# env= hands a child our whole environment, so once GS_WALLET_PASSWORD is set
# (the method this toolchain now RECOMMENDS) every child inherits the Monero
# spend-key password by default -- including JoinMarket's third-party
# tumble.py. Each child must get an env with the variable scrubbed unless it
# is the one that signs.
def _child_envs(pw_in_environ):
    seen = []
    real_run, real_log = ghost.subprocess.run, ghost.integrity_log
    prev = os.environ.get("GS_WALLET_PASSWORD")
    try:
        if pw_in_environ:
            os.environ["GS_WALLET_PASSWORD"] = "SpendKeyPass-99"
        ghost.subprocess.run = lambda cmd, **kw: (
            seen.append((list(cmd), kw.get("env"))),
            types.SimpleNamespace(returncode=0))[1]
        ghost.integrity_log = lambda *a, **k: None
        a = types.SimpleNamespace(
            tor_proxy="socks5h://127.0.0.1:9050",
            rpc_primary="http://127.0.0.1:18083",
            rpc_daemon="http://127.0.0.1:18081",
            wallet_file="w", wallet_password="SpendKeyPass-99", fee_priority=1,
            allow_clearnet_relay=False)
        ghost._run_round(a, _planD, str(_stage), "Fan-out")
    finally:
        ghost.subprocess.run, ghost.integrity_log = real_run, real_log
        os.environ.pop("GS_WALLET_PASSWORD", None)
        if prev is not None:
            os.environ["GS_WALLET_PASSWORD"] = prev
    return seen


def _sees_pw(env):
    # env=None means "inherit ours", which leaks when the var is in our environ.
    return env is None or env.get("GS_WALLET_PASSWORD") is not None


_envs = _child_envs(pw_in_environ=True)
_pw_visible = [(c, e) for c, e in _envs if _sees_pw(e)]
_sign_children = [c for c, e in _envs if "sign" in c]
_nonsign = [(c, e) for c, e in _envs if "sign" not in c]
check("D4: the sign child DOES receive the password via env",
      any(_sees_pw(e) for c, e in _envs if "sign" in c))
check("D4: NO non-sign child can see the password "
      f"(leaking: {[c[1] for c, e in _nonsign if _sees_pw(e)]})",
      not any(_sees_pw(e) for c, e in _nonsign))
check("D4: exactly one child sees it", len(_pw_visible) == 1)
# And _child_env must scrub even when the operator exported it.
os.environ["GS_WALLET_PASSWORD"] = "leaky"
try:
    check("D4: _child_env() scrubs an exported password by default",
          ghost._child_env().get("GS_WALLET_PASSWORD") is None)
    check("D4: _child_env(pw) injects it only when asked",
          ghost._child_env("x").get("GS_WALLET_PASSWORD") == "x")
finally:
    os.environ.pop("GS_WALLET_PASSWORD", None)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES); sys.exit(1)
print("ALL GREEN")
