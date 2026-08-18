#!/usr/bin/env python3
"""GhostSpiral control panel — press a button, it actually runs.

A local control surface for this toolchain: start a suite or a check, watch its
output stream in live, stop it mid-run. Not a report of a previous run.

    python3 tests/control.py            # http://127.0.0.1:8765
    python3 tests/control.py --port 9000

SAFETY, deliberately:
  * Binds 127.0.0.1 ONLY. Never 0.0.0.0 -- this thing starts processes.
  * Actions are a fixed WHITELIST defined below. The HTTP layer passes an
    action ID, never a command, so no request can inject one.
  * Every action here is read-only or dry-run. Nothing signs, relays, spends,
    or wipes. Destructive operations are run deliberately from a shell, not
    from a button that is one misclick away.

Stdlib only, so it runs on the air-gapped machine too.
"""
from __future__ import annotations
import argparse, html, json, os, signal, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
# The real-binary suites need the `monero` package; point at a venv if you have
# one (see tests/README.md for why it needs setuptools<58).
VENV_PY = os.environ.get("GS_VENV_PY", PY)


def suite(name, desc, interp=None):
    return {"cmd": [interp or PY, os.path.join("tests", f"{name}.py")], "desc": desc}


# ── the whitelist. An HTTP request selects a key; it never supplies a command ──
ACTIONS = {
    # -- fast offline suites --
    "units":       {**suite("test_units", "validation, fingerprint, money math, parsing"), "group": "Offline suites"},
    "realfns":     {**suite("test_realfns", "secure-delete, file perms, core dumps, prices"), "group": "Offline suites"},
    "cliflags":    {**suite("test_cli_flags", "every script: --help, argparse, pre-network aborts"), "group": "Offline suites"},
    "integration": {**suite("test_integration", "real phase_create/sign/broadcast + orchestration"), "group": "Offline suites"},
    "gitignore":   {**suite("test_gitignore", "enforces .gitignore covers every wiped artifact"), "group": "Offline suites"},
    "ipleak":      {**suite("test_ipleak", "proxy scheme, egress guards, localhost spoofing"), "group": "Offline suites"},
    "broadcast":   {**suite("test_broadcast", "relay loop: delays, resume, manifest boundary"), "group": "Offline suites"},
    "gapfixes":    {**suite("test_gapfixes", "MAC-spoof restore/leak, exit-sim --redact"), "group": "Offline suites"},
    "swaprecv":    {**suite("test_swap_receive", "swap memo binding, slippage stop, receive addr"), "group": "Offline suites"},
    "console":     {**suite("test_console", "password scope, no invented fees, egress, HTTP gates"), "group": "Offline suites"},
    "shmwipe":     {**suite("test_shmwipe", "/dev/shm + $TMPDIR scratch is wiped, other software's is not"), "group": "Offline suites"},
    "concurrency": {**suite("test_concurrency", "hash chain under parallel writers; console hangs, stdin, buffering"), "group": "Offline suites"},

    # -- suites that drive real monero binaries on an isolated testnet --
    "roundtrip":   {**suite("real_roundtrip_testnet", "full cold-signing round-trip", VENV_PY), "group": "Real binaries"},
    "flags":       {**suite("real_flags_testnet", "fee-priority 1-4 + multi-dest fan-out", VENV_PY), "group": "Real binaries"},
    "dagsub":      {**suite("real_dag_subaddr_testnet", "on-chain proof subaddr_indices isolates a hop", VENV_PY), "group": "Real binaries"},
    "phasesign":   {**suite("real_phase_sign_testnet", "SHIPPED phase_sign relayed + confirmed", VENV_PY), "group": "Real binaries"},
    "phasecreate": {**suite("real_phase_create_testnet", "SHIPPED phase_create -> phase_sign chain", VENV_PY), "group": "Real binaries"},
    "realbcast":   {**suite("real_broadcast_testnet", "SHIPPED broadcast main() relayed + confirmed"), "group": "Real binaries"},
    "realsend":    {**suite("real_send_testnet", "SHIPPED jittered fan-out send: exact unequal amounts land"), "group": "Real binaries"},
    "realpeel":    {**suite("real_peel_testnet", "SHIPPED peeling chain: N dests via N separate txs"), "group": "Real binaries"},
    "peelcold":    {**suite("real_peel_cold_testnet", "SHIPPED phase_create+phase_sign COLD peel chain"), "group": "Real binaries"},
    "leakaudit":   {**suite("leak_audit_testnet", "runs 3 stages, audits what hits disk", VENV_PY), "group": "Real binaries"},
    "recvcount":   {**suite("real_receive_count_testnet", "--count mints N independent receives; reuse refused"), "group": "Real binaries"},
    "watchdesync": {**suite("real_watch_desync_testnet", "kills monerod mid-watch: 'wallet stuck' != 'swap paid short'"), "group": "Real binaries"},

    # -- operational checks: inspect the live environment, change nothing --
    "paranoia_dry": {"cmd": [PY, "paranoia_mode", "--dry-run"], "group": "Operational checks",
                     "desc": "what the wipe WOULD remove — dry run, deletes nothing"},
    "compile":      {"cmd": [PY, "-m", "py_compile", "gs_common.py", "GhostSpiral", "airgap_tx_signer",
                             "broadcast_signed_xmr", "create_receive_wallet", "exit_strategy_simulator",
                             "paranoia_mode", "thor_swap_preparer"],
                     "group": "Operational checks", "desc": "every shipped script parses"},
    "git_status":   {"cmd": ["git", "status", "--short", "--branch"], "group": "Operational checks",
                     "desc": "uncommitted changes and branch position"},
    "monero_ver":   {"cmd": ["monerod", "--version"], "group": "Operational checks",
                     "desc": "which monerod the real-binary suites will use"},
}

JOBS: dict[str, dict] = {}
LOCK = threading.Lock()


def start(action_id: str) -> str:
    a = ACTIONS[action_id]
    jid = f"{action_id}-{int(time.time()*1000)}"
    job = {"id": jid, "action": action_id, "lines": [], "done": False,
           "rc": None, "started": time.time(), "proc": None}
    with LOCK:
        JOBS[jid] = job

    def run():
        try:
            p = subprocess.Popen(a["cmd"], cwd=REPO, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, bufsize=1,
                                 start_new_session=True)
            job["proc"] = p
            for line in p.stdout:
                with LOCK:
                    job["lines"].append(line.rstrip("\n"))
                    if len(job["lines"]) > 4000:
                        del job["lines"][:1000]
            p.wait()
            job["rc"] = p.returncode
        except FileNotFoundError as e:
            job["lines"].append(f"[control] not found: {e}")
            job["rc"] = 127
        except Exception as e:                      # noqa: BLE001 - surface it
            job["lines"].append(f"[control] error: {e}")
            job["rc"] = 1
        finally:
            job["done"] = True
            job["elapsed"] = round(time.time() - job["started"], 1)

    threading.Thread(target=run, daemon=True).start()
    return jid


def stop(jid: str) -> bool:
    job = JOBS.get(jid)
    if not job or job["done"] or not job["proc"]:
        return False
    try:
        # Kill the whole group: the real-binary suites spawn monerod children
        # that would otherwise survive and hold their RPC ports.
        os.killpg(os.getpgid(job["proc"].pid), signal.SIGTERM)
        job["lines"].append("[control] SIGTERM sent to process group")
        return True
    except (ProcessLookupError, PermissionError) as e:
        job["lines"].append(f"[control] stop failed: {e}")
        return False


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GhostSpiral Control</title><style>
:root{--bg:#F5F7F9;--sf:#fff;--sf2:#EDF1F4;--ink:#10151B;--ink2:#39434F;--mut:#64717F;
--line:#D6DEE4;--line2:#C2CCD5;--acc:#A85A24;--accs:#F3E4D8;--ok:#136F52;--oks:#DCEFE7;
--err:#97281F;--errs:#F7E0DD;--run:#8A5D0F;--runs:#F6EAD2;--term:#0F151B;--termink:#D5DEE6}
@media(prefers-color-scheme:dark){:root{--bg:#0C1015;--sf:#141A21;--sf2:#1B232C;--ink:#E8EDF2;
--ink2:#B4C0CC;--mut:#7E8B99;--line:#25303B;--line2:#33404E;--acc:#E0894C;--accs:#3A2718;
--ok:#4BC79B;--oks:#12332A;--err:#EE8177;--errs:#3A1D1A;--run:#DFAE55;--runs:#332711;
--term:#080B0E;--termink:#C9D4DD}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{max-width:1240px;margin:0 auto;padding:26px 20px 60px}
header{display:flex;gap:14px;align-items:baseline;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:20px}
h1{margin:0;font-size:22px;font-weight:650;letter-spacing:-.02em}
.eb{font-family:ui-monospace,Menlo,monospace;font-size:11px;letter-spacing:.13em;text-transform:uppercase;color:var(--acc)}
.hint{color:var(--mut);font-size:12.5px;margin-left:auto}
.cols{display:grid;grid-template-columns:minmax(300px,380px) 1fr;gap:20px;align-items:start}
@media(max-width:860px){.cols{grid-template-columns:1fr}}
h2{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
color:var(--mut);font-weight:600;margin:20px 0 9px;padding-bottom:7px;border-bottom:1px solid var(--line)}
h2:first-child{margin-top:0}
.act{display:flex;gap:10px;align-items:center;width:100%;text-align:left;cursor:pointer;
background:var(--sf);border:1px solid var(--line);border-radius:9px;padding:10px 12px;margin-bottom:7px;
color:var(--ink);font:inherit;transition:border-color .12s,transform .06s}
.act:hover{border-color:var(--acc)}
.act:active{transform:translateY(1px)}
.act:disabled{opacity:.55;cursor:not-allowed}
.act .nm{font-size:13.5px;font-weight:600}
.act .ds{font-size:11.5px;color:var(--mut);margin-top:2px;line-height:1.35}
.act .go{margin-left:auto;font-family:ui-monospace,Menlo,monospace;font-size:10px;letter-spacing:.09em;
text-transform:uppercase;color:var(--acc);background:var(--accs);padding:4px 9px;border-radius:5px;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--line2);flex:none}
.dot.run{background:var(--run);box-shadow:0 0 0 3px var(--runs);animation:p 1s infinite}
.dot.ok{background:var(--ok);box-shadow:0 0 0 3px var(--oks)}
.dot.err{background:var(--err);box-shadow:0 0 0 3px var(--errs)}
@keyframes p{50%{opacity:.35}}
@media(prefers-reduced-motion:reduce){.dot.run{animation:none}}
.bulk{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.bulk button{font:inherit;font-size:12.5px;padding:7px 13px;border-radius:99px;cursor:pointer;
border:1px solid var(--line2);background:var(--sf);color:var(--ink2)}
.bulk button:hover{border-color:var(--acc);color:var(--ink)}
.bulk button.stop{color:var(--err);border-color:var(--err)}
.panel{background:var(--sf);border:1px solid var(--line);border-radius:11px;overflow:hidden;position:sticky;top:18px}
.pbar{display:flex;gap:12px;align-items:center;padding:11px 14px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.ptitle{font-size:13px;font-weight:650}
.pmeta{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--mut)}
.pill{font-family:ui-monospace,Menlo,monospace;font-size:10px;letter-spacing:.08em;text-transform:uppercase;
padding:3px 8px;border-radius:5px;font-weight:600}
.pill.run{background:var(--runs);color:var(--run)}
.pill.ok{background:var(--oks);color:var(--ok)}
.pill.err{background:var(--errs);color:var(--err)}
.pacts{margin-left:auto;display:flex;gap:7px}
.pacts button{font:inherit;font-size:12px;padding:5px 11px;border-radius:7px;cursor:pointer;
background:transparent;border:1px solid var(--line2);color:var(--ink2)}
.pacts button:hover{border-color:var(--acc);color:var(--ink)}
pre{margin:0;background:var(--term);color:var(--termink);padding:14px 16px;overflow:auto;
max-height:min(62vh,620px);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:12.5px;line-height:1.55;white-space:pre-wrap;word-break:break-word}
pre .g{color:#5FD3A6}pre .r{color:#F58C82}pre .y{color:#E6BC6A}pre .d{color:#6B7A88}
.idle{padding:40px 20px;text-align:center;color:var(--mut);font-size:13.5px}
:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
.hist{margin-top:14px}
.hrow{display:flex;gap:10px;align-items:center;padding:7px 4px;border-bottom:1px solid var(--line);
font-size:12.5px;cursor:pointer}
.hrow:hover{background:var(--sf2)}
.hrow .hn{font-weight:600}
.hrow .ht{margin-left:auto;font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--mut)}
</style></head><body><div class="wrap">
<header>
  <span class="eb">Control</span>
  <h1>GhostSpiral</h1>
  <span class="hint mono">127.0.0.1 only · whitelisted actions · nothing here signs, relays or wipes</span>
</header>
<div class="cols">
  <div>
    <div class="bulk">
      <button id="run-offline">Run all offline</button>
      <button id="run-real">Run all real-binary</button>
      <button id="stop" class="stop">Stop current</button>
    </div>
    <div id="actions"></div>
    <div class="hist" id="hist"></div>
  </div>
  <div class="panel">
    <div class="pbar">
      <span class="ptitle" id="pt">No job running</span>
      <span class="pill" id="ppill" style="display:none"></span>
      <span class="pmeta" id="pm"></span>
      <span class="pacts">
        <button id="wrap-t">Wrap</button>
        <button id="copy">Copy</button>
      </span>
    </div>
    <div id="out"><div class="idle">Pick an action on the left. Output streams here live.</div></div>
  </div>
</div>
</div><script>
const A = __ACTIONS__;
const $ = s => document.querySelector(s);
let cur = null, timer = null, queue = [], history = [];

const groups = {};
for (const [id, a] of Object.entries(A)) (groups[a.group] ||= []).push([id, a]);
$('#actions').innerHTML = Object.entries(groups).map(([g, items]) => `<h2>${g}</h2>` +
  items.map(([id, a]) => `<button class="act" data-id="${id}">
    <span class="dot" id="dot-${id}"></span>
    <span><span class="nm">${a.label}</span><div class="ds">${a.desc}</div></span>
    <span class="go">Run</span></button>`).join('')).join('');

document.querySelectorAll('.act').forEach(b =>
  b.addEventListener('click', () => run(b.dataset.id)));

function setDot(id, cls){ const d = $('#dot-'+id); if (d) d.className = 'dot ' + (cls||''); }

async function run(id){
  if (cur) return;
  document.querySelectorAll('.act').forEach(b => b.disabled = true);
  setDot(id, 'run');
  $('#pt').textContent = A[id].label;
  $('#ppill').style.display = ''; $('#ppill').className = 'pill run'; $('#ppill').textContent = 'running';
  $('#pm').textContent = '';
  $('#out').innerHTML = '<pre id="pre"></pre>';
  const r = await fetch('/run/' + id, {method:'POST'}).then(r => r.json());
  cur = {jid: r.jid, id};
  timer = setInterval(poll, 400); poll();
}

function colour(l){
  const e = l.replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
  if (/FAIL|LEAK |\bERROR\b|Traceback|refused|\*\*\*/.test(l)) return `<span class="r">${e}</span>`;
  if (/RESULT:|ALL GREEN|SUCCESS|NO LEAKS|\bok\b|\[\+\]/.test(l)) return `<span class="g">${e}</span>`;
  if (/\[!\]|WARN|SKIP/.test(l)) return `<span class="y">${e}</span>`;
  if (/^\s*\[\*\]|^===/.test(l)) return `<span class="d">${e}</span>`;
  return e;
}

async function poll(){
  if (!cur) return;
  const j = await fetch('/job/' + cur.jid).then(r => r.json());
  const pre = $('#pre');
  if (pre){
    const stick = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 40;
    pre.innerHTML = j.lines.map(colour).join('\n');
    if (stick) pre.scrollTop = pre.scrollHeight;
  }
  $('#pm').textContent = j.lines.length + ' lines' + (j.elapsed ? ' · ' + j.elapsed + 's' : '');
  if (j.done){
    clearInterval(timer); timer = null;
    const ok = j.rc === 0;
    $('#ppill').className = 'pill ' + (ok ? 'ok' : 'err');
    $('#ppill').textContent = ok ? 'passed' : 'exit ' + j.rc;
    setDot(cur.id, ok ? 'ok' : 'err');
    history.unshift({id: cur.id, label: A[cur.id].label, ok, elapsed: j.elapsed, jid: cur.jid});
    renderHist();
    const done = cur; cur = null;
    document.querySelectorAll('.act').forEach(b => b.disabled = false);
    if (queue.length) run(queue.shift());
  }
}

function renderHist(){
  if (!history.length) return;
  $('#hist').innerHTML = '<h2>This session</h2>' + history.slice(0, 12).map(h =>
    `<div class="hrow" data-jid="${h.jid}"><span class="dot ${h.ok?'ok':'err'}"></span>
     <span class="hn">${h.label}</span><span class="ht">${h.ok?'passed':'failed'} · ${h.elapsed}s</span></div>`
  ).join('');
  document.querySelectorAll('.hrow').forEach(r => r.addEventListener('click', async () => {
    const j = await fetch('/job/' + r.dataset.jid).then(x => x.json());
    $('#out').innerHTML = '<pre id="pre"></pre>';
    $('#pre').innerHTML = j.lines.map(colour).join('\n');
    $('#pt').textContent = A[j.action].label + ' (finished)';
    $('#ppill').className = 'pill ' + (j.rc === 0 ? 'ok' : 'err');
    $('#ppill').textContent = j.rc === 0 ? 'passed' : 'exit ' + j.rc;
  }));
}

$('#run-offline').addEventListener('click', () => {
  queue = Object.entries(A).filter(([,a]) => a.group === 'Offline suites').map(([id]) => id);
  if (!cur && queue.length) run(queue.shift());
});
$('#run-real').addEventListener('click', () => {
  queue = Object.entries(A).filter(([,a]) => a.group === 'Real binaries').map(([id]) => id);
  if (!cur && queue.length) run(queue.shift());
});
$('#stop').addEventListener('click', async () => {
  queue = [];
  if (cur) await fetch('/stop/' + cur.jid, {method:'POST'});
});
$('#wrap-t').addEventListener('click', () => {
  const p = $('#pre'); if (!p) return;
  p.style.whiteSpace = p.style.whiteSpace === 'pre' ? 'pre-wrap' : 'pre';
});
$('#copy').addEventListener('click', () => {
  const p = $('#pre'); if (p) navigator.clipboard?.writeText(p.innerText);
});
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            meta = {k: {"label": k.replace("_", " ").title(),
                        "desc": html.escape(v["desc"]), "group": v["group"]}
                    for k, v in ACTIONS.items()}
            self._send(200, PAGE.replace("__ACTIONS__", json.dumps(meta)), "text/html; charset=utf-8")
        elif self.path.startswith("/job/"):
            job = JOBS.get(self.path[5:])
            if not job:
                return self._send(404, json.dumps({"error": "no such job"}))
            with LOCK:
                self._send(200, json.dumps({
                    "lines": job["lines"], "done": job["done"], "rc": job["rc"],
                    "action": job["action"],
                    "elapsed": job.get("elapsed", round(time.time() - job["started"], 1)),
                }))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path.startswith("/run/"):
            aid = self.path[5:]
            if aid not in ACTIONS:                      # whitelist gate
                return self._send(400, json.dumps({"error": "unknown action"}))
            self._send(200, json.dumps({"jid": start(aid)}))
        elif self.path.startswith("/stop/"):
            self._send(200, json.dumps({"stopped": stop(self.path[6:])}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def log_message(self, *a):
        pass                                            # keep the console for job output


def main():
    ap = argparse.ArgumentParser(description="GhostSpiral local control panel")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)   # localhost ONLY
    print(f"  GhostSpiral control → http://127.0.0.1:{a.port}")
    print(f"  {len(ACTIONS)} whitelisted actions · Ctrl-C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")


if __name__ == "__main__":
    main()
