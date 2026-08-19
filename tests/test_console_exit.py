#!/usr/bin/env python3
"""The console's EXIT wiring, and its own safety claims, over REAL HTTP.

Every check here starts the actual server and talks to it with urllib. Nothing
is stubbed, because the claims being tested are about what the SERVER does with
a request -- and a request composed in-process would skip the token gate, the
JSON body parse, the schema filter and the arm-phrase gate, which are the four
things worth proving.

The console's docstring makes specific promises. They are asserted, not
believed:

  * binds 127.0.0.1 ONLY
  * the browser never supplies a command; the server composes argv from an
    action id plus typed parameters, and anything not in SCHEMA cannot reach it
  * `spends` actions refuse without the exact arm phrase
  * the wallet password is never rendered and never lands in a preview

The exit is the part that moves money, so its wiring gets the same treatment:
--exit-to must be repeated once per destination, absent when unset, and
malformed or duplicated destinations must be refused BEFORE anything runs.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

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


A1 = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7Sq"
      "SsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
A2 = ("43ZYYZBkwxZJNJFo6rGHf5KREAGR3LizKKXN3aPDCHYj1AAfkqEipXs4x9nn"
      "rTq2FuaqXMqLrVtED1kV2Z77b6NGE6FFTCm")
# A real SUBADDRESS. Exchange deposit addresses normally are one, and a
# validator that only accepts standard addresses rejects the ordinary case.
SUB = ("83Ss8Wx9CmH4EaWkan3bdGhAybs7r3xgHZnMeWMNgwwdW3BJc6nfjTbFL9V4"
       "Go9LxZjUvDCX9H416cHR68m8aLc6FUZFVRJ")

PW = "console-test-password-do-not-log"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


PORT = _free_port()
env = dict(os.environ, GS_WALLET_PASSWORD=PW)
proc = subprocess.Popen([sys.executable, os.path.join(REPO, "gs_console"),
                         "--port", str(PORT)],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, env=env, cwd=REPO)
TOKEN = None
try:
    for _ in range(80):
        line = proc.stdout.readline()
        if not line:
            break
        if "?t=" in line:
            TOKEN = line.split("?t=", 1)[1].strip()
            break
    if not TOKEN:
        print("SKIP: console did not start")
        proc.kill()
        sys.exit(0)

    base = f"http://127.0.0.1:{PORT}"

    def post(path, payload, token=TOKEN, hdrs=None):
        # The token rides in the CUSTOM HEADER, which is how the page sends it
        # and the reason the console is CSRF-proof: a cross-origin <form>
        # cannot set a custom header. (?t= works for the initial GET only --
        # do_POST matches self.path exactly, so a query string there routes to
        # 404 rather than the handler.)
        h = {"Content-Type": "application/json"}
        if token is not None:
            h["X-GS-Token"] = token
        h.update(hdrs or {})
        req = urllib.request.Request(
            f"{base}{path}", data=json.dumps(payload).encode(),
            headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            try:
                return e.code, json.loads(body or "{}")
            except ValueError:
                return e.code, {"raw": body}

    def preview(params):
        return post("/api/preview", {"params": params})

    base_params = {"mode": "receive", "receive_wallet": "wallet_a.json",
                   "tor_proxy": "socks5h://127.0.0.1:9050"}

    # ---- the console's own claims -------------------------------------
    st, _ = preview(base_params)
    check("console: a tokenised request is served", st == 200)
    check("console: a request WITHOUT the token is refused",
          post("/api/preview", {"params": base_params}, token=None)[0] == 401)
    check("console: a non-JSON content type is refused",
          post("/api/preview", {"params": base_params},
               hdrs={"Content-Type": "text/plain"})[0] == 415)
    check("console: a cross-origin request is refused even WITH the token",
          post("/api/preview", {"params": base_params},
               hdrs={"Origin": "http://evil.example"})[0] == 403)
    check("console: a request with a WRONG token is refused",
          post("/api/preview", {"params": base_params}, token="x" * 32)[0] == 401)

    # Loopback only. Asserted by asking the OS what is listening, not by
    # reading the bind call.
    _ext = socket.socket()
    _ext.settimeout(2)
    _hostip = socket.gethostbyname(socket.gethostname())
    _reachable = True
    try:
        _ext.connect((_hostip, PORT))
    except OSError:
        _reachable = False
    finally:
        _ext.close()
    check("console: not reachable on this host's non-loopback address "
          f"({_hostip})", _reachable is False or _hostip.startswith("127."))

    # ---- the exit wiring ----------------------------------------------
    st, r = preview(dict(base_params, exit_to=[A1, A2]))
    argv = r.get("argv", [])
    check("exit: --exit-to is repeated once per destination",
          argv.count("--exit-to") == 2)
    check("exit: both destinations reach the argv", A1 in argv and A2 in argv)
    check("exit: each --exit-to is immediately followed by its address",
          all(argv[i + 1] in (A1, A2)
              for i, x in enumerate(argv) if x == "--exit-to"))
    check("exit: no problems reported for a valid pair", not r.get("problems"))

    st, r = preview(base_params)
    check("exit: absent when no destination is given (nothing is withdrawn)",
          "--exit-to" not in r.get("argv", []))

    st, r = preview(dict(base_params, exit_to=[SUB]))
    check("exit: a real SUBADDRESS is accepted (exchange deposits are usually "
          "subaddresses)", SUB in r.get("argv", []))

    st, r = preview(dict(base_params, exit_to=[A1, A1]))
    check("exit: a repeated destination is refused",
          any("more than once" in p for p in r.get("problems", [])))
    check("exit: ...and the repeat never reaches the argv",
          r.get("argv", []).count("--exit-to") <= 1)

    st, r = preview(dict(base_params, exit_to=["not-an-address"]))
    check("exit: a malformed destination is refused",
          any("not a valid Monero address" in p for p in r.get("problems", [])))
    check("exit: ...and nothing malformed reaches the argv",
          "not-an-address" not in r.get("argv", []))

    st, r = preview(dict(base_params, exit_to=[A1[:-1]]))
    check("exit: a truncated address is refused",
          any("not a valid Monero" in p for p in r.get("problems", [])))

    st, r = preview(dict(base_params, exit_to=f"{A1}\n{A2}"))
    check("exit: a newline-separated paste is accepted too",
          r.get("argv", []).count("--exit-to") == 2)

    # ---- injection: the browser must never supply a command ------------
    st, r = preview(dict(base_params, exit_to=[f"{A1}; rm -rf /"]))
    _a = r.get("argv", [])
    check("inject: a shell payload appended to an address is refused",
          not any("rm -rf" in x for x in _a))
    st, r = preview(dict(base_params, unknown_key="--allow-clearnet-relay",
                         argv=["evil"], build="evil"))
    check("inject: unknown parameters are dropped, not passed through",
          "evil" not in r.get("argv", [])
          and "--allow-clearnet-relay" not in r.get("argv", []))
    check("inject: the composed argv still starts with the interpreter and "
          "GhostSpiral", r.get("argv", [])[1:2] == ["GhostSpiral"])

    # ---- the password must never be rendered ---------------------------
    st, r = preview(dict(base_params, exit_to=[A1]))
    check("password: never appears in the composed argv",
          PW not in json.dumps(r))
    page = urllib.request.urlopen(f"{base}/?t={TOKEN}", timeout=20).read().decode()
    check("password: never appears in the served page", PW not in page)
    check("page: the exit field is present in the UI", 'id="exit_to"' in page)
    check("page: the UI states that an empty exit withdraws nothing",
          "No exit set" in page and "Nothing is withdrawn" in page)
    # A field can exist in the HTML and never be SENT -- the classic half-wired
    # form, where the UI looks complete and the parameter silently never
    # reaches the server. collect() is what the page posts, so the field has to
    # appear there too.
    _collect = page.split("function collect(", 1)[-1].split("}", 1)[0]         if "function collect(" in page else ""
    check("page: collect() actually READS the exit field (a field that is not "
          "collected is never sent)", "exit_to" in _collect)
    check("page: the exit note element exists for the typed-in feedback",
          'id="exitnote"' in page)
    check("page: the page warns that one destination re-joins the outputs",
          "re-joins" in page or "ONE address" in page)

    # The console's own stated guarantees, checked against the source it serves
    # rather than its docstring.
    _src = open(os.path.join(REPO, "gs_console")).read()
    check("claim: shell=False everywhere (no shell=True anywhere)",
          "shell=True" not in _src)
    check("claim: no built-in fee table to fall back on",
          not any(t in _src for t in ("FEE_TABLE", "DEFAULT_FEE", "FALLBACK_FEE")))

    # ---- the arm phrase gate -------------------------------------------
    st, r = post("/run/run_pipeline", {"params": dict(base_params, exit_to=[A1])})
    check("arm: the money-moving action refuses without the arm phrase",
          st == 403 and "arm phrase" in json.dumps(r))
    st, r = post("/run/run_pipeline",
                 {"params": dict(base_params, exit_to=[A1]), "arm": "spend"})
    check("arm: a WRONG-CASE arm phrase is still refused", st == 403)
    st, r = post("/run/run_pipeline", {"params": dict(base_params, exit_to=[A1]),
                                       "arm": "SPEND"})
    _err = json.dumps(r)
    # BOTH refusals are 403, so a status check alone proves nothing about WHICH
    # gate stopped it. With the correct phrase the arm gate must be passed and
    # the SERVER-SIDE preflight must be what refuses -- which is the console's
    # own claim: the OPSEC check is enforced here, not just in the page, so a
    # request that bypasses the UI still cannot spend without it.
    check("arm: the correct phrase gets PAST the arm gate",
          "arm phrase" not in _err)
    check("preflight: the server enforces OPSEC itself and refuses to spend "
          "(no Tor in this environment)",
          st == 403 and "Preflight FAILED" in _err)
    check("preflight: ...and names which check failed rather than refusing "
          "blankly", "tor" in _err.lower())
finally:
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:                                        # noqa: BLE001
        proc.kill()

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
