#!/usr/bin/env python3
"""Windows must be refused at import, and the CONSOLE must refuse it too.

An operator unzipped this repo on Windows 11 and followed the runbook. What
they got was:

    ModuleNotFoundError: No module named 'fcntl'

gs_common imports fcntl unconditionally (flock serialises the integrity chain
and the run lock), so every tool that imports gs_common died on a traceback
naming a module the operator has never heard of, with no hint of a remedy.

The console was worse, and is the reason this suite exists rather than a
one-line assert. gs_console is stdlib-only ON PURPOSE -- it must run on the
air-gapped machine -- so it does not import gs_common, so there was nothing to
fail. On Windows the dashboard STARTED, printed its URL, served all five wizard
steps, accepted the SPEND arm phrase and queued a run. Only the child process
died, in output the operator was not reading. A dashboard that looks like it is
mixing and is not is the worst failure this toolchain can produce: the operator
believes funds are moving, and nothing is.

So both gates are checked here, and so is the property that makes them
trustworthy -- that the gate in gs_common runs BEFORE the first Unix-only
import. A gate placed after `import fcntl` is a gate that never runs.

os.name is monkeypatched to 'nt' and the modules are executed for real. Nothing
here is stubbed at the level being tested.
"""
import ast
import importlib.machinery
import importlib.util
import os
import sys

# shutil (and anything else that branches on os.name at import time) must be
# loaded while os.name is still honest -- shutil does `import nt` on Windows,
# and that module genuinely does not exist here. Pre-importing them means the
# monkeypatch below only reaches OUR code, which is the thing under test.
import shutil, subprocess, threading, tempfile, hmac, secrets, shlex, signal  # noqa: F401

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

PASS = 0
FAIL = 0
FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  ", name)
    else:
        FAIL += 1
        FAILS.append(name)
        print("  FAIL:", name)


def exec_as_windows(path):
    """Execute a source file with os.name == 'nt'. Returns (exc, message)."""
    real = os.name
    for cached in ("gs_common", "gs_console_under_test"):
        sys.modules.pop(cached, None)
    os.name = "nt"
    try:
        loader = importlib.machinery.SourceFileLoader(
            "gs_console_under_test" if os.path.basename(path) == "gs_console"
            else "gs_common", os.path.join(REPO, path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
            return None, ""
        except BaseException as exc:            # noqa: BLE001 -- that is the point
            return exc, str(exc)
    finally:
        os.name = real
        sys.modules.pop("gs_common", None)


print("\n== the gate fires at all ==")

for path in ("gs_common.py", "gs_console"):
    exc, msg = exec_as_windows(path)
    check(f"{path}: refuses to load when os.name is 'nt'",
          isinstance(exc, SystemExit))
    # NOT ModuleNotFoundError. That is the exact regression: a Unix-only import
    # reached before the gate produces a traceback instead of an explanation.
    check(f"{path}: the refusal is not a raw ModuleNotFoundError",
          not isinstance(exc, ModuleNotFoundError))
    check(f"{path}: says Linux or POSIX is required",
          "Linux" in msg or "POSIX" in msg)
    check(f"{path}: names a remedy the operator can act on",
          "WSL" in msg)
    check(f"{path}: states that nothing has run",
          "NOTHING HAS RUN" in msg or "Refusing at startup" in msg)

# One copy of the explanation, not two that drift. gs_console gets the long
# text by importing gs_common on the failing path only, so the console's
# refusal must carry gs_common's four-reason body verbatim.
_, common_msg = exec_as_windows("gs_common.py")
_, console_msg = exec_as_windows("gs_console")
check("the console's refusal reuses gs_common's text rather than "
      "paraphrasing it (no second copy to drift)",
      "/dev/shm" in console_msg and "fcntl.flock" in console_msg)
check("...and gs_common is the file that owns that text",
      "/dev/shm" in common_msg and "fcntl.flock" in common_msg)


print("\n== the gate is placed where it can actually run ==")

# THIS is the check that keeps the fix working. Placement is the whole fix:
# `import fcntl` on line 21 followed by a gate on line 40 is not a gate. Parse
# the module and require that the sys.exit guard precedes every import of a
# module that does not exist on Windows.
UNIX_ONLY = {"fcntl", "resource", "pwd", "grp", "termios", "tty", "posix"}

tree = ast.parse(open(os.path.join(REPO, "gs_common.py")).read())

gate_line = None
for node in tree.body:
    if isinstance(node, ast.If):
        src = ast.dump(node.test)
        if "os" in src and "name" in src and "posix" in src:
            gate_line = node.lineno
            break
check("gs_common has a top-level `if os.name != 'posix'` guard",
      gate_line is not None)

first_unix_import = None
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name.split(".")[0] in UNIX_ONLY:
                if first_unix_import is None or node.lineno < first_unix_import:
                    first_unix_import = node.lineno
    elif isinstance(node, ast.ImportFrom) and node.module:
        if node.module.split(".")[0] in UNIX_ONLY:
            if first_unix_import is None or node.lineno < first_unix_import:
                first_unix_import = node.lineno

check("gs_common really does import a Unix-only module (the gate is not "
      "guarding nothing)", first_unix_import is not None)
check(f"the gate (line {gate_line}) precedes the first Unix-only import "
      f"(line {first_unix_import})",
      gate_line is not None and first_unix_import is not None
      and gate_line < first_unix_import)

# The console must gate before it binds a port or forks anything. Anything
# heavier than a stdlib import ahead of the guard is a side effect Windows
# would still get.
console_tree = ast.parse(open(os.path.join(REPO, "gs_console")).read())
console_gate = None
for node in console_tree.body:
    if isinstance(node, ast.If):
        src = ast.dump(node.test)
        if "os" in src and "name" in src and "posix" in src:
            console_gate = node.lineno
            break
check("gs_console has its own top-level `if os.name != 'posix'` guard",
      console_gate is not None)

# The console's process control is the Unix-only part that has no import to
# trip over -- os.killpg and friends resolve fine at parse time and only fail
# when called, which is why the console needed an explicit gate.
console_src = open(os.path.join(REPO, "gs_console")).read()
check("...and it is needed: gs_console calls os.killpg, which does not exist "
      "on Windows", "os.killpg(" in console_src)
check("...and passes start_new_session, which Windows rejects outright",
      "start_new_session=True" in console_src)


print("\n== POSIX is untouched ==")

# The gate must be invisible here. A guard that also changes behaviour on Linux
# would be a new defect traded for an old one.
sys.modules.pop("gs_common", None)
import gs_common  # noqa: E402
check("gs_common imports normally on this POSIX host",
      hasattr(gs_common, "VERSION"))
check("...and still exposes flock-based locking rather than a degraded "
      "fallback", "fcntl.flock" in open(os.path.join(REPO, "gs_common.py")).read())

loader = importlib.machinery.SourceFileLoader(
    "gs_console_posix", os.path.join(REPO, "gs_console"))
spec = importlib.util.spec_from_loader(loader.name, loader)
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)
check("gs_console imports normally on this POSIX host",
      hasattr(console, "ACTIONS") or hasattr(console, "ARM_PHRASE"))
check("...and did not import gs_common on the way (stdlib-only for the "
      "air-gapped machine is preserved)",
      "gs_common" not in getattr(console, "__dict__", {}))

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAIL:
    print("FAILURES: " + ", ".join(FAILS))
    sys.exit(1)
print("ALL GREEN")
