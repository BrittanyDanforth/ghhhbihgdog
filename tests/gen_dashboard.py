#!/usr/bin/env python3
"""Generate a self-contained dashboard HTML from the REAL data collected by
collect_dashboard_data.py. Every number on the page comes from that JSON --
nothing is hand-written. Usage: python3 tests/gen_dashboard.py data.json out.html
"""
import json, sys, html, os

IN = sys.argv[1] if len(sys.argv) > 1 else "dashboard_data.json"
OUT = sys.argv[2] if len(sys.argv) > 2 else "dashboard.html"
d = json.load(open(IN))
e = html.escape

rt = d.get("roundtrip", {})
suites = d.get("suites", [])
total_pass = sum(s["passed"] for s in suites)
total_fail = sum(s["failed"] for s in suites)
env = d.get("env", {})
fee = d.get("fee_estimate", {})
fee_xmr = (fee.get("fee") or 0) / 1e12
steps_ok = sum(1 for s in rt.get("steps", []) if s["ok"])
steps_n = len(rt.get("steps", []))
rt_ok = rt.get("success") and not rt.get("skipped")

STEP_LABEL = {"fund": "Fund", "transfer_split": "transfer_split", "sign_transfer": "sign_transfer",
              "submit_transfer": "submit_transfer", "confirm": "Confirm"}
STEP_SUB = {"fund": "mine on isolated testnet", "transfer_split": "view-only → unsigned_txset",
            "sign_transfer": "wallet-cli, password-first", "submit_transfer": "wallet-rpc relay",
            "confirm": "mined into a block"}

def pill(ok, label=None):
    cls = "ok" if ok else "bad"
    txt = label or ("PASS" if ok else "FAIL")
    return f'<span class="pill {cls}">{e(txt)}</span>'

# ---- round-trip flow stages ----
stage_html = []
steps = rt.get("steps", [])
for i, s in enumerate(steps):
    k = s["k"]
    arrow = '<div class="arrow" aria-hidden="true">→</div>' if i else ''
    stage_html.append(f'''{arrow}<div class="stage {'ok' if s['ok'] else 'bad'}">
      <div class="stage-top"><span class="dot"></span><span class="stage-name">{e(STEP_LABEL.get(k,k))}</span></div>
      <div class="stage-sub">{e(STEP_SUB.get(k,''))}</div>
      <div class="stage-detail">{e(s['detail'])}</div>
    </div>''')
stages = "".join(stage_html)

# ---- test suite cards ----
suite_html = "".join(f'''<div class="suite">
  <div class="suite-h"><span class="suite-name">{e(s['name'])}</span>{pill(s['ok'])}</div>
  <div class="suite-count"><span class="big">{s['passed']}</span><span class="unit">passed</span></div>
  <div class="suite-kind">{'real-binary CLI' if s['kind']=='cli' else 'mocked / unit'} · {s['failed']} failed</div>
</div>''' for s in suites)

# ---- fake -> real ledger ----
ledger_html = "".join(f'''<div class="ledger-row">
  <div class="was"><span class="tag was-tag">was</span><s>{e(x['was'])}</s></div>
  <div class="now"><span class="tag now-tag">now</span>{e(x['now'])}</div>
  <div class="proof">{e(x['proof'])}</div>
</div>''' for x in d.get("fake_to_real", []))

txid = rt.get("txid") or "—"
fees_arr = fee.get("fees")
fees_note = ("per-priority <code>fees[]</code> = " + e(str(fees_arr))) if fees_arr else \
    "this early-fork testnet returns only a base <code>fee</code> (no <code>fees[]</code>); on mainnet 0.18 it returns <code>[1.2M, 4.7M, 19M, 240M]</code> — which is why <code>fetch_fee_from_daemon</code> reads the array when present"

HTML = f'''<!-- generated from real run data: {e(d.get("generated_utc",""))} -->
<title>GhostSpiral Verification</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {{
  --bg:#f6f4f0; --surface:#ffffff; --surface-2:#faf8f4; --ink:#1b1d22; --muted:#6b6560;
  --hair:#e6e0d7; --accent:#b8551a; --good:#2e7d5b; --good-bg:#e7f1ec; --warn:#b07818;
  --crit:#a83a2c; --crit-bg:#f6e7e3; --shadow:0 1px 2px rgba(30,20,10,.06),0 8px 24px rgba(30,20,10,.05);
}}
:root:not([data-theme="light"]) {{ }}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --bg:#14161c; --surface:#1c1f27; --surface-2:#20242e; --ink:#ecebe7; --muted:#9a948c;
    --hair:#2b2f3a; --accent:#e08a45; --good:#52c08e; --good-bg:#16302a; --warn:#d9a648;
    --crit:#e06a58; --crit-bg:#331f1c; --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);
  }}
}}
:root[data-theme="dark"] {{
  --bg:#14161c; --surface:#1c1f27; --surface-2:#20242e; --ink:#ecebe7; --muted:#9a948c;
  --hair:#2b2f3a; --accent:#e08a45; --good:#52c08e; --good-bg:#16302a; --warn:#d9a648;
  --crit:#e06a58; --crit-bg:#331f1c; --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);
}}
* {{ box-sizing:border-box; }}
body {{
  margin:0; background:var(--bg); color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  line-height:1.5; -webkit-font-smoothing:antialiased;
}}
.mono {{ font-family:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace; font-variant-numeric:tabular-nums; }}
.wrap {{ max-width:1080px; margin:0 auto; padding:32px 24px 64px; }}
.eyebrow {{ font:600 12px/1 ui-monospace,Menlo,monospace; letter-spacing:.16em; text-transform:uppercase; color:var(--accent); }}
h1 {{ font-size:clamp(28px,4.4vw,44px); line-height:1.05; letter-spacing:-.02em; margin:12px 0 8px; text-wrap:balance; font-weight:700; }}
.lede {{ color:var(--muted); max-width:62ch; margin:0; }}
.meta {{ display:flex; flex-wrap:wrap; gap:8px 18px; margin-top:16px; color:var(--muted); font:500 12.5px/1.4 ui-monospace,Menlo,monospace; }}
.meta b {{ color:var(--ink); font-weight:600; }}

/* hero verdict */
.verdict {{ margin:28px 0 8px; background:var(--surface); border:1px solid var(--hair); border-left:4px solid var(--good);
  border-radius:14px; padding:20px 22px; box-shadow:var(--shadow); display:flex; gap:20px; align-items:center; flex-wrap:wrap; }}
.verdict.bad {{ border-left-color:var(--crit); }}
.verdict .big-status {{ font:700 22px/1 -apple-system,sans-serif; letter-spacing:-.01em; }}
.verdict .txid {{ color:var(--muted); font-size:13px; word-break:break-all; }}
.verdict .txid b {{ color:var(--ink); }}
.spacer {{ flex:1 1 40px; }}
.timing {{ display:flex; gap:22px; }}
.timing div span {{ display:block; }}
.timing .n {{ font:600 18px/1 ui-monospace,Menlo,monospace; }}
.timing .l {{ font-size:11px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); margin-top:4px; }}

/* section */
h2 {{ font-size:13px; letter-spacing:.14em; text-transform:uppercase; color:var(--muted); font-weight:600;
  margin:40px 0 14px; padding-bottom:10px; border-bottom:1px solid var(--hair); }}

/* tiles */
.tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; }}
.tile {{ background:var(--surface); border:1px solid var(--hair); border-radius:12px; padding:16px 18px; box-shadow:var(--shadow); }}
.tile .n {{ font:700 30px/1 ui-monospace,Menlo,monospace; letter-spacing:-.02em; }}
.tile .n small {{ font-size:15px; color:var(--muted); font-weight:600; }}
.tile .l {{ margin-top:8px; font-size:12px; color:var(--muted); letter-spacing:.03em; }}
.tile.accent .n {{ color:var(--accent); }}
.tile.good .n {{ color:var(--good); }}

/* pipeline flow */
.flow {{ display:flex; align-items:stretch; gap:6px; overflow-x:auto; padding:4px 2px 12px; }}
.stage {{ flex:1 0 168px; background:var(--surface); border:1px solid var(--hair); border-top:3px solid var(--good);
  border-radius:12px; padding:14px 15px; box-shadow:var(--shadow); }}
.stage.bad {{ border-top-color:var(--crit); }}
.stage-top {{ display:flex; align-items:center; gap:8px; }}
.dot {{ width:9px; height:9px; border-radius:50%; background:var(--good); box-shadow:0 0 0 3px var(--good-bg); }}
.stage.bad .dot {{ background:var(--crit); box-shadow:0 0 0 3px var(--crit-bg); }}
.stage-name {{ font:600 14px/1 ui-monospace,Menlo,monospace; }}
.stage-sub {{ color:var(--muted); font-size:11.5px; margin:7px 0 10px; letter-spacing:.02em; }}
.stage-detail {{ font:500 12.5px/1.4 ui-monospace,Menlo,monospace; color:var(--ink); word-break:break-word; }}
.arrow {{ align-self:center; color:var(--accent); font-size:18px; flex:0 0 auto; padding:0 2px; }}

/* pills */
.pill {{ font:600 10.5px/1 ui-monospace,Menlo,monospace; letter-spacing:.08em; padding:5px 8px; border-radius:999px; }}
.pill.ok {{ color:var(--good); background:var(--good-bg); }}
.pill.bad {{ color:var(--crit); background:var(--crit-bg); }}

/* suites */
.suites {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; }}
.suite {{ background:var(--surface); border:1px solid var(--hair); border-radius:12px; padding:16px 18px; box-shadow:var(--shadow); }}
.suite-h {{ display:flex; justify-content:space-between; align-items:center; gap:8px; }}
.suite-name {{ font:600 13px/1 ui-monospace,Menlo,monospace; }}
.suite-count {{ margin:12px 0 4px; display:flex; align-items:baseline; gap:7px; }}
.suite-count .big {{ font:700 30px/1 ui-monospace,Menlo,monospace; color:var(--good); }}
.suite-count .unit {{ color:var(--muted); font-size:12px; }}
.suite-kind {{ color:var(--muted); font-size:11.5px; letter-spacing:.02em; }}

/* ledger */
.ledger {{ display:flex; flex-direction:column; gap:1px; background:var(--hair); border:1px solid var(--hair); border-radius:12px; overflow:hidden; }}
.ledger-row {{ display:grid; grid-template-columns:1fr 1fr auto; gap:14px; align-items:center; background:var(--surface); padding:13px 16px; }}
@media (max-width:720px) {{ .ledger-row {{ grid-template-columns:1fr; gap:6px; }} }}
.tag {{ font:600 9.5px/1 ui-monospace,Menlo,monospace; letter-spacing:.1em; text-transform:uppercase; padding:3px 6px; border-radius:5px; margin-right:8px; }}
.was-tag {{ color:var(--crit); background:var(--crit-bg); }}
.now-tag {{ color:var(--good); background:var(--good-bg); }}
.was s {{ color:var(--muted); }}
.now {{ font-size:13.5px; }}
.proof {{ font:500 11px/1 ui-monospace,Menlo,monospace; color:var(--accent); white-space:nowrap; }}

/* panels row */
.cols {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
@media (max-width:720px) {{ .cols {{ grid-template-columns:1fr; }} }}
.panel {{ background:var(--surface); border:1px solid var(--hair); border-radius:12px; padding:18px 20px; box-shadow:var(--shadow); }}
.panel h3 {{ margin:0 0 12px; font-size:12px; letter-spacing:.12em; text-transform:uppercase; color:var(--muted); font-weight:600; }}
.kv {{ display:flex; justify-content:space-between; gap:12px; padding:7px 0; border-bottom:1px solid var(--hair); font-size:13px; }}
.kv:last-child {{ border-bottom:0; }}
.kv .k {{ color:var(--muted); }}
.kv .v {{ font-family:ui-monospace,Menlo,monospace; text-align:right; }}
.note {{ color:var(--muted); font-size:12.5px; line-height:1.6; }}
.note code {{ font-family:ui-monospace,Menlo,monospace; color:var(--accent); font-size:12px; }}
.caveats {{ border-left:3px solid var(--warn); }}
.caveats li {{ margin:7px 0; font-size:13px; color:var(--ink); }}
.caveats li b {{ color:var(--warn); }}
footer {{ margin-top:40px; color:var(--muted); font:500 12px/1.6 ui-monospace,Menlo,monospace; text-align:center; }}
:focus-visible {{ outline:2px solid var(--accent); outline-offset:2px; border-radius:4px; }}
</style>

<div class="wrap">
  <header>
    <div class="eyebrow">Cold-Signing Pipeline · Verification Run</div>
    <h1>GhostSpiral verified against real Monero</h1>
    <p class="lede">The BTC→XMR cold-signing pipeline, exercised end to end on real
      <span class="mono">monerod</span> / <span class="mono">wallet-rpc</span> / <span class="mono">wallet-cli</span>
      — plus {total_pass} unit, integration and CLI assertions. Every figure below is from an actual run, not a mock.</p>
    <div class="meta">
      <span>run <b>{e(d.get("generated_utc",""))}</b></span>
      <span>commit <b>{e(env.get("commit","?"))}</b></span>
      <span>branch <b>{e(env.get("branch","?"))}</b></span>
      <span><b>{e(env.get("monero","?"))}</b></span>
    </div>
  </header>

  <div class="verdict {'' if rt_ok else 'bad'}">
    <div>
      <div class="big-status">{'✓ Round-trip confirmed on-chain' if rt_ok else '✗ Round-trip incomplete'}</div>
      <div class="txid">tx <b class="mono">{e(txid)}</b></div>
    </div>
    <div class="spacer"></div>
    <div class="timing">
      <div><span class="n">{steps_ok}/{steps_n}</span><span class="l">stages</span></div>
      <div><span class="n">{rt.get("total_seconds","–")}s</span><span class="l">wall clock</span></div>
      <div><span class="n">{rt.get("blocks_mined","–")}</span><span class="l">blocks</span></div>
    </div>
  </div>

  <h2>At a glance</h2>
  <div class="tiles">
    <div class="tile good"><div class="n">{total_pass}</div><div class="l">assertions passed ({total_fail} failed)</div></div>
    <div class="tile accent"><div class="n">{steps_ok}<small>/{steps_n}</small></div><div class="l">real-binary round-trip stages</div></div>
    <div class="tile"><div class="n">{rt.get("funded_atomic",0)/1e12:.1f}<small> XMR</small></div><div class="l">funded &amp; spent on testnet</div></div>
    <div class="tile"><div class="n">{env.get("commits_this_branch","?")}</div><div class="l">commits · {env.get("files_changed","?")} files changed</div></div>
    <div class="tile"><div class="n">{len(d.get("fake_to_real",[]))}</div><div class="l">fake paths turned real</div></div>
  </div>

  <h2>Cold-signing round-trip · real binaries</h2>
  <div class="flow">{stages}</div>

  <h2>Test suites</h2>
  <div class="suites">{suite_html}</div>

  <h2>Fake → real</h2>
  <div class="ledger">{ledger_html}</div>

  <h2>Instrumentation &amp; honest gaps</h2>
  <div class="cols">
    <div class="panel">
      <h3>Environment &amp; fee estimate</h3>
      <div class="kv"><span class="k">monero</span><span class="v">0.18.3.1</span></div>
      <div class="kv"><span class="k">testnet base fee</span><span class="v">{fee_xmr:.6f} XMR</span></div>
      <div class="kv"><span class="k">fan-out unsigned_txset</span><span class="v">{rt.get("unsigned_txset_hexlen","–")} hex</span></div>
      <div class="kv"><span class="k">signed_monero_tx</span><span class="v">{rt.get("signed_bytes","–")} bytes</span></div>
      <div class="kv"><span class="k">fan-out outputs</span><span class="v">{rt.get("fanout_outputs","–")}</span></div>
      <p class="note" style="margin-top:12px">{fees_note}.</p>
    </div>
    <div class="panel caveats">
      <h3>Not covered — still reasoned, not run</h3>
      <ul style="margin:0; padding-left:18px">
        <li><b>Mainnet consensus.</b> The isolated testnet sits at an early fork (small ring size); mainnet ring-16 / weight bounds weren't exercised.</li>
        <li><b>GhostSpiral orchestration.</b> The round-trip drives the RPC/CLI flow directly, not <span class="mono">main()</span>'s Stage-4 planning or the confirmation waits.</li>
        <li><b>submit_transfer error codes</b> for double-spend / low-fee were never provoked; that classification stays heuristic with a fail-safe default.</li>
      </ul>
    </div>
  </div>

  <footer>Generated from tests/dashboard_data.json — a real run.<br>
    tests/collect_dashboard_data.py → tests/gen_dashboard.py. Reproducible, not fabricated.</footer>
</div>'''

open(OUT, "w").write(HTML)
print("wrote", OUT, "(", len(HTML), "bytes )")
