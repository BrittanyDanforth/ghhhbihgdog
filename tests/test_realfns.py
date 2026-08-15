#!/usr/bin/env python3
"""Test the REAL exit_strategy_simulator.fetch_prices (rate-inversion fix) and
paranoia_mode.wipe_gs_artifacts (BUG 4: log must not be recreated in a real
wipe). Delete functions are no-op'd so NOTHING on disk is actually deleted."""
import sys, os, json, tempfile, importlib.util, importlib.machinery
from decimal import Decimal
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
def load(name):
    loader = importlib.machinery.SourceFileLoader(name.replace(".py", ""), os.path.join(REPO, name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec); loader.exec_module(mod); return mod

gs = load("gs_common.py")
esim = load("exit_strategy_simulator")
para = load("paranoia_mode")
os.chdir(tempfile.mkdtemp(prefix="gs_rf_"))

PASS = 0; FAIL = 0; FAILURES = []
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1
    else: FAIL += 1; FAILURES.append(name); print(f"  FAIL: {name}")

# ---------------------------------------------------------------------------
# exit_strategy_simulator.fetch_prices — Bisq fallback rate is NOT inverted
# ---------------------------------------------------------------------------
def fake_get(url, proxy):
    if url == esim.CG_URL:
        raise RuntimeError("coingecko down (force Bisq fallback)")
    if url == esim.BISQ_PRICE_URL:
        return {"data": [
            {"currencyCode": "XMR", "price": 0.005},   # 0.005 BTC per XMR
            {"currencyCode": "USD", "price": 60000},    # 60000 USD per BTC
            {"currencyCode": "EUR", "price": 55000},
        ]}
    raise AssertionError("unexpected URL " + url)
esim.safe_get = fake_get
prices = esim.fetch_prices({"http": "socks5h://127.0.0.1:9050"})
check("exit-sim: uses Bisq fallback", prices["source"] == "bisq_oracle")
# xmr_usd must be xmr_btc * btc_usd = 0.005 * 60000 = 300.00, NOT 0.005/60000
check("exit-sim: xmr_usd = 300.00 (not inverted)", prices["xmr_usd"] == Decimal("300.00"))
check("exit-sim: xmr_eur = 275.00 (not inverted)", prices["xmr_eur"] == Decimal("275.00"))
check("exit-sim: btc_usd = 60000 (not inverted)", prices["btc_usd"] == Decimal("60000.00"))
# sanity: the OLD inverted math would have produced ~8.3e-8, quantized to 0.00
check("exit-sim: not the old ~0 bug", prices["xmr_usd"] > Decimal("1"))

# ---------------------------------------------------------------------------
# paranoia_mode BUG 4 — a REAL (non-dry) wipe must NOT recreate integrity log,
# but DRY mode still logs. Delete funcs no-op'd so nothing is truly deleted.
# ---------------------------------------------------------------------------
para._secure_delete_file = lambda path: None
para._secure_delete_dir = lambda path: None
LOG = Path(os.getcwd()) / "integrity_chain.log"

# real wipe: must leave NO integrity_chain.log behind (the whole point of BUG 4)
if LOG.exists():
    LOG.unlink()
para.wipe_gs_artifacts(dry=False, extra_dirs=[])
check("paranoia: real wipe does NOT recreate integrity_chain.log", not LOG.exists())

# dry wipe: SHOULD still write the integrity log (nothing was deleted)
if LOG.exists():
    LOG.unlink()
para.wipe_gs_artifacts(dry=True, extra_dirs=[])
check("paranoia: dry wipe still logs", LOG.exists())

# ---------------------------------------------------------------------------
# paranoia _secure_delete_file must OVERWRITE the file's FULL extent IN PLACE.
# Proven with a hardlink: after deleting one link, the shared inode's bytes
# (read via the other link) must be all-zero and the ORIGINAL full size -- not
# 64 KB-capped, not left intact (the old truncate-then-64KB bug failed both).
# ---------------------------------------------------------------------------
para2 = load("paranoia_mode")        # fresh module: real _secure_delete_file,
                                     # not the no-op the BUG-4 test patched in
big = b"SECRETDATA" * 20000  # 200 KB, well over the old 64 KB cap
fa = Path(os.getcwd()) / "sd_a.bin"; fb = Path(os.getcwd()) / "sd_b.bin"
fa.write_bytes(big)
os.link(str(fa), str(fb))            # hardlink: same inode + data blocks
ok = para2._secure_delete_file(fa)
check("secure_delete: returns True", ok is True)
check("secure_delete: path unlinked", not fa.exists())
residual = fb.read_bytes()           # the inode survives via fb; read its bytes
check("secure_delete: full size overwritten (not 64KB-capped)", len(residual) == len(big))
check("secure_delete: original bytes gone (zeroed in place)", b"SECRET" not in residual and set(residual) == {0})
fb.unlink()
check("secure_delete: missing file -> False",
      para2._secure_delete_file(Path(os.getcwd()) / "nope_xyz_missing") is False)

# ---------------------------------------------------------------------------
# A symlink must NEVER be followed. Following it overwrites the LINK TARGET --
# a file the operator never asked to wipe -- then unlinks only the link while
# reporting success. wipe_gs_artifacts expands globs, so a symlink matching
# '*.json' would silently zero whatever it pointed at.
# ---------------------------------------------------------------------------
victim = Path(os.getcwd()) / "sd_victim.txt"
VICTIM_DATA = b"DO-NOT-TOUCH" * 100
victim.write_bytes(VICTIM_DATA)
link = Path(os.getcwd()) / "sd_link"
os.symlink(str(victim), str(link))
r_link = para2._secure_delete_file(link)
check("secure_delete: symlink removed", not os.path.lexists(str(link)))
check("secure_delete: symlink TARGET left intact (no collateral wipe)",
      victim.exists() and victim.read_bytes() == VICTIM_DATA)
check("secure_delete: symlink returns True (link itself is gone)", r_link is True)
victim.unlink()

# Non-regular files (fifo/device/socket) must be refused, not overwritten.
fifo = Path(os.getcwd()) / "sd_fifo"
os.mkfifo(str(fifo))
check("secure_delete: fifo refused", para2._secure_delete_file(fifo) is False)
check("secure_delete: fifo left in place", os.path.exists(str(fifo)))
fifo.unlink()

empty = Path(os.getcwd()) / "sd_empty.txt"
empty.write_bytes(b"")
check("secure_delete: zero-byte file deleted cleanly",
      para2._secure_delete_file(empty) is True and not empty.exists())

# ---------------------------------------------------------------------------
# atomic_write_* must not leave a plaintext '.tmp' behind when interrupted.
# A Ctrl-C between the write and the rename used to strand e.g.
# 'thor_pairs_batch.json.tmp' holding the deposit address and memo, and NO
# wipe pattern matched a '.json.tmp' suffix, so it was never cleaned up.
# ---------------------------------------------------------------------------
_real_replace = os.replace
_atomic_dir = Path(os.getcwd()) / "atomicdir"
_atomic_dir.mkdir(exist_ok=True)
_target = _atomic_dir / "thor_pairs_batch.json"
os.replace = lambda a, b: (_ for _ in ()).throw(KeyboardInterrupt("simulated Ctrl-C"))
_raised = None
try:
    gs.atomic_write_json({"deposit": "bc1qSENSITIVE", "memo": "SECRET"}, _target)
except BaseException as e:      # KeyboardInterrupt is the case that leaked
    _raised = type(e).__name__
finally:
    os.replace = _real_replace
check("atomic_write_json: interrupt still propagates", _raised == "KeyboardInterrupt")
check("atomic_write_json: no partial .tmp left after interrupt",
      list(_atomic_dir.glob("*.tmp")) == [])
check("atomic_write_json: no target written on interrupt", not _target.exists())

# Same guarantee for the text variant.
_target2 = _atomic_dir / "notes.txt"
os.replace = lambda a, b: (_ for _ in ()).throw(KeyboardInterrupt("simulated Ctrl-C"))
try:
    gs.atomic_write_text("SENSITIVE-MEMO", _target2)
except BaseException:
    pass
finally:
    os.replace = _real_replace
check("atomic_write_text: no partial .tmp left after interrupt",
      list(_atomic_dir.glob("*.tmp")) == [])

# Sanity: the happy path still works and content round-trips.
gs.atomic_write_json({"ok": 1}, _target)
check("atomic_write_json: happy path still writes correctly",
      _target.exists() and json.loads(_target.read_text())["ok"] == 1)
check("atomic_write_json: happy path leaves no .tmp",
      list(_atomic_dir.glob("*.tmp")) == [])

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES); sys.exit(1)
print("ALL GREEN")
