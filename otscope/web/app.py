"""Web dashboard.

Self-contained by design: no CDN, no external font, no JS framework.  A plant
network is usually offline, and this page has to work from a laptop plugged into
it.  Everything (CSS, JS, charts) is served from this process.

Run with `otscope dashboard --host 0.0.0.0 --port 8055`.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, List, Optional

from flask import Flask, Response, jsonify, request

from .. import __version__, report as report_mod, scenarios
from ..active import probes
from ..active.safety import ProbePolicy
from ..analysis.engine import Engine
from ..config import ScanConfig
from ..vuln.db import AdvisoryDB

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8055


class AppState:
    """Holds the latest report and serialises scans (one at a time)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.report: Dict[str, Any] = {}
        self.generation = 0
        self.busy = False
        self.last_error = ""
        self.log: List[Dict[str, Any]] = []
        self.pcap: Optional[str] = None
        self.iface: Optional[str] = None
        self.seconds: float = 20.0
        self.config = ScanConfig(name="dashboard")

    # ------------------------------------------------------------------
    def publish(self, report: Any, note: str = "") -> None:
        data = report.to_dict()
        with self.condition:
            self.report = data
            self.generation += 1
            self.busy = False
            self._log(note or f"analysed {data.get('source', '')}")
            self.condition.notify_all()

    def fail(self, message: str) -> None:
        with self.condition:
            self.last_error = message
            self.busy = False
            self._log(f"error: {message}")
            self.condition.notify_all()

    def start(self, note: str) -> bool:
        with self.condition:
            if self.busy:
                return False
            self.busy = True
            self._log(note)
            return True

    def _log(self, message: str) -> None:
        self.log.append({"ts": time.time(), "message": message})
        del self.log[:-200]

    def wait(self, generation: int, timeout: float) -> bool:
        with self.condition:
            return self.condition.wait_for(lambda: self.generation != generation or not self.busy, timeout=timeout)

    def status(self) -> Dict[str, Any]:
        with self.lock:
            summary = self.report.get("summary", {})
            return {
                "version": __version__,
                "busy": self.busy,
                "generation": self.generation,
                "source": self.report.get("source", ""),
                "generated": self.report.get("generated", 0),
                "findings": summary.get("findings", 0),
                "severity": summary.get("severity", {}),
                "assets": summary.get("assets", 0),
                "frames": summary.get("frames", 0),
                "last_error": self.last_error,
                "log": self.log[-25:],
            }


STATE = AppState()


# --------------------------------------------------------------------- scans
def run_scan(pcap: Optional[str] = None, iface: Optional[str] = None, seconds: float = 20.0, active: bool = False) -> None:
    source = pcap or STATE.pcap
    generated = False
    try:
        if iface:
            STATE.start(f"capturing on {iface} for {seconds:.0f}s")
            eng = Engine(STATE.config)
            eng.run_live(iface, seconds=seconds)
            src = f"live:{iface}"
        else:
            if not source:
                source = os.path.join("/tmp", "otscope-dashboard-demo.pcap")
                count = scenarios.write_pcap(source)
                STATE._log(f"generated demo capture: {count:,} frames")
                generated = True
            if not os.path.exists(source):
                STATE.fail(f"capture file not found: {source}")
                return
            eng = Engine(STATE.config)
            eng.run_file(source)
            src = os.path.basename(source)
        probe: Dict[str, Any] = {}
        if active:
            probe = probes.run(eng.stats, STATE.config)
        report = eng.analyse(probe=probe, source=src)
        STATE.publish(report, f"analysed {src}: {len(report.findings)} findings")
        if generated:
            STATE.pcap = source
    except Exception as exc:  # a scan failure must not kill the server
        STATE.fail(f"{exc!r}")


def _worker(**kwargs: Any) -> None:
    threading.Thread(target=run_scan, kwargs=kwargs, daemon=True).start()


# ---------------------------------------------------------------------- app
def create_app(pcap: Optional[str] = None, iface: Optional[str] = None, seconds: float = 20.0) -> Flask:
    app = Flask(__name__)
    STATE.pcap = pcap
    STATE.iface = iface
    STATE.seconds = seconds

    @app.route("/")
    def index() -> Response:
        return Response(PAGE, mimetype="text/html")

    @app.route("/healthz")
    def healthz() -> Response:
        return jsonify({"ok": True, "version": __version__})

    @app.route("/api/status")
    def api_status() -> Response:
        return jsonify(STATE.status())

    @app.route("/api/report")
    def api_report() -> Response:
        with STATE.lock:
            data = dict(STATE.report)
        only = request.args.get("only")
        if only:
            data["findings"] = [f for f in data.get("findings", []) if f["severity"] in only.split(",")]
        limit = request.args.get("limit", type=int)
        if limit:
            data["findings"] = data.get("findings", [])[:limit]
        return jsonify(data)

    @app.route("/api/findings")
    def api_findings() -> Response:
        with STATE.lock:
            findings = list(STATE.report.get("findings", []))
        cat = request.args.get("category")
        if cat:
            findings = [f for f in findings if f["category"] == cat]
        return jsonify(findings)

    @app.route("/api/scan", methods=["POST"])
    def api_scan() -> Response:
        body = request.get_json(silent=True) or {}
        pcap = body.get("pcap") or STATE.pcap
        iface = body.get("iface")
        seconds = float(body.get("seconds") or STATE.seconds)
        active = bool(body.get("active", False))
        if not STATE.start("scan requested"):
            return jsonify({"ok": False, "error": "a scan is already running"}), 409
        _worker(pcap=pcap, iface=iface, seconds=seconds, active=active)
        return jsonify({"ok": True, "started": True})

    @app.route("/api/probe", methods=["POST"])
    def api_probe() -> Response:
        """Read-only identification probe of explicitly named hosts."""
        body = request.get_json(silent=True) or {}
        targets = [t for t in (body.get("targets") or []) if isinstance(t, str)]
        if not targets:
            return jsonify({"ok": False, "error": "no targets given"}), 400
        policy = ProbePolicy(targets=targets, rate_per_second=float(body.get("rate", 10.0)))
        for key, value in (body.get("service_ports") or {}).items():
            if isinstance(value, int):
                policy.service_ports[key] = value
        out = probes.run(Engine(STATE.config).stats, STATE.config, policy=policy)
        return jsonify(out)

    @app.route("/api/advisories")
    def api_advisories() -> Response:
        db = AdvisoryDB.load()
        return jsonify(
            {
                "summary": db.summary(),
                "advisories": [a.to_dict() for a in db.advisories],
                "lifecycle": [lc.to_dict() for lc in db.lifecycle],
            }
        )

    @app.route("/api/stream")
    def api_stream() -> Response:
        def gen():
            seen = STATE.generation
            yield f"data: {json.dumps(STATE.status())}\n\n"
            while True:
                changed = STATE.wait(seen, timeout=15.0)
                with STATE.lock:
                    if STATE.generation == seen and not changed:
                        yield ": keepalive\n\n"
                        continue
                    seen = STATE.generation
                    payload = STATE.status()
                yield f"data: {json.dumps(payload)}\n\n"

        return Response(gen(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route("/report.html")
    def report_html() -> Response:
        """The static, printable report for the current scan."""

        class _Saved:
            def to_dict(self) -> Dict[str, Any]:
                with STATE.lock:
                    return dict(STATE.report)

            def __getattr__(self, name: str) -> Any:
                with STATE.lock:
                    return STATE.report[name]

        return Response(report_mod.to_html(_Saved()), mimetype="text/html")

    return app


def serve(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    pcap: Optional[str] = None,
    iface: Optional[str] = None,
    seconds: float = 20.0,
    debug: bool = False,
) -> None:
    app = create_app(pcap=pcap, iface=iface, seconds=seconds)
    _worker(pcap=pcap, iface=iface, seconds=seconds)
    print(f"otscope dashboard on http://{host}:{port}  (source: {pcap or iface or 'demo scenario'})")
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>otscope dashboard</title>
<style>
:root { --ink:#111827; --mut:#6b7280; --line:#e5e7eb; --bg:#f8fafc; }
* { box-sizing:border-box; }
body { margin:0; font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif; color:var(--ink); background:var(--bg); }
header { background:#0b1220; color:#fff; padding:14px 24px; display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
header h1 { margin:0; font-size:18px; }
header .sub { color:#94a3b8; font-size:12.5px; }
button { font:inherit; background:#2563eb; color:#fff; border:0; border-radius:7px; padding:7px 14px; cursor:pointer; }
button.ghost { background:#1f2937; }
button:disabled { background:#4b5563; cursor:progress; }
main { padding:20px 24px 60px; max-width:1320px; margin:0 auto; }
h2 { font-size:14px; text-transform:uppercase; letter-spacing:.8px; color:#374151; margin:30px 0 10px; }
.cards { display:flex; gap:12px; flex-wrap:wrap; }
.card { background:#fff; border:1px solid var(--line); border-radius:10px; padding:10px 18px; min-width:104px; }
.card .num { font-size:26px; font-weight:650; }
.card .lbl { color:var(--mut); font-size:11.5px; text-transform:uppercase; letter-spacing:.6px; }
.panel { background:#fff; border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
th { color:var(--mut); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
td.ctr, th.ctr { text-align:center; }
.mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12.5px; }
.pill { font-size:11px; font-weight:700; padding:2px 7px; border-radius:20px; letter-spacing:.4px; }
.row { display:flex; gap:10px; align-items:center; padding:8px 10px; border-bottom:1px solid var(--line); cursor:pointer; }
.row:hover { background:#f8fafc; }
.row .t { font-weight:600; }
.row code { background:#f1f5f9; padding:1px 5px; border-radius:4px; font-size:12px; }
.row .meta { color:var(--mut); font-size:12px; margin-left:auto; }
.detail { padding:8px 14px 14px; background:#fbfdff; border-bottom:1px solid var(--line); }
.detail ul { margin:6px 0; padding-left:20px; color:#374151; }
.rec { background:#f0f9ff; border-left:3px solid #38bdf8; padding:8px 11px; border-radius:4px; }
.spark { width:100%; height:80px; display:block; }
.log { font-family:ui-monospace,Menlo,monospace; font-size:12px; color:#374151; max-height:160px; overflow:auto; }
.filters { display:flex; gap:6px; flex-wrap:wrap; margin:8px 0 14px; }
.chip { border:1px solid var(--line); background:#fff; border-radius:20px; padding:3px 11px; font-size:12px; cursor:pointer; }
.chip.on { background:#111827; color:#fff; border-color:#111827; }
.live { background:#16a34a; color:#fff; font-size:11px; padding:2px 8px; border-radius:20px; letter-spacing:.8px; }
.busy { background:#dc2626; }
</style></head><body>
<header>
  <h1>otscope</h1><span class="sub">OT / ERP network analyser</span>
  <span class="sub" id="source"></span>
  <span id="state" class="live">IDLE</span>
  <span style="margin-left:auto" class="sub">v<span id="ver"></span></span>
  <button id="rescan">Re-run analysis</button>
  <a href="/report.html" target="_blank"><button class="ghost">Printable report</button></a>
</header>
<main>
  <div class="cards" id="cards"></div>

  <h2>Traffic over the capture window</h2>
  <div class="panel"><svg class="spark" id="spark" viewBox="0 0 900 80" preserveAspectRatio="none"></svg></div>

  <h2>Findings</h2>
  <div class="filters" id="filters"></div>
  <div class="panel" id="findings" style="padding:4px 6px"></div>

  <h2>Inventory</h2>
  <div class="panel"><table><thead><tr><th>IP / MAC</th><th>role</th><th class="ctr">P</th><th>vendor</th>
    <th>family</th><th>model</th><th>firmware</th><th>services</th><th class="ctr">frames</th></tr></thead>
    <tbody id="assets"></tbody></table></div>

  <h2>Advisory database</h2>
  <div class="panel"><table><thead><tr><th>advisory</th><th>CVE</th><th class="ctr">CVSS</th><th>families</th>
    <th>KEV</th></tr></thead><tbody id="advisories"></tbody></table></div>

  <h2>Activity log</h2>
  <div class="panel log" id="log"></div>
</main>
<script>
const SEV = {critical:'#b3261e', high:'#e8710a', medium:'#b58900', low:'#3d7ea6', info:'#6b7280'};
const BG = {critical:'#fdecea', high:'#fff1e0', medium:'#fff8e1', low:'#eaf3f8', info:'#f1f3f5'};
let REPORT = {}, FILTER = new Set(['critical','high','medium','low','info']);

const el = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

async function loadReport() {
  const r = await fetch('/api/report'); REPORT = await r.json(); render();
}

function render() {
  const s = REPORT.summary || {};
  const sev = s.severity || {};
  el('source').textContent = 'source: ' + (REPORT.source || '-');
  el('ver').textContent = REPORT.version || '';
  const cards = [['critical',sev.critical],['high',sev.high],['medium',sev.medium],['low',sev.low],['info',sev.info],
                 ['hosts',s.assets],['frames',(s.frames||0).toLocaleString()],['flows',s.flows]];
  el('cards').innerHTML = cards.map(([l,v]) =>
    `<div class="card" style="border-top:4px solid ${SEV[l]||'#cbd5e1'}"><div class="num" style="color:${SEV[l]||'#111827'}">${v||0}</div><div class="lbl">${l}</div></div>`).join('');

  // sparkline from the timeline buckets
  const tl = REPORT.timeline || [];
  const peak = Math.max(1, ...tl.map(b => b.bytes||0));
  const step = tl.length > 1 ? 900/(tl.length-1) : 900;
  const pts = tl.map((b,i) => `${(i*step).toFixed(1)},${(80 - (b.bytes/peak)*74 - 3).toFixed(1)}`).join(' ');
  el('spark').innerHTML = tl.length ? `<polygon points="0,80 ${pts} 900,80" fill="#dbeafe"/>
    <polyline points="${pts}" fill="none" stroke="#2563eb" stroke-width="1.5"/>` : '';

  el('filters').innerHTML = ['critical','high','medium','low','info'].map(k =>
    `<span class="chip ${FILTER.has(k)?'on':''}" data-k="${k}">${k} (${sev[k]||0})</span>`).join('');
  document.querySelectorAll('.chip').forEach(c => c.onclick = () => {
    const k = c.dataset.k; FILTER.has(k) ? FILTER.delete(k) : FILTER.add(k); render();
  });

  const list = (REPORT.findings || []).filter(f => FILTER.has(f.severity));
  el('findings').innerHTML = list.map((f,i) => `
    <div class="row" data-i="${i}">
      <span class="pill" style="background:${BG[f.severity]};color:${SEV[f.severity]}">${f.severity.toUpperCase()}</span>
      <code>${esc(f.id)}</code><span class="t">${esc(f.title)}</span>
      <span class="meta">${esc(f.window)} &middot; ${esc(f.category_label)}</span>
    </div>
    <div class="detail" id="d${i}" style="display:none">
      <p>${esc(f.summary)}</p>
      ${(f.evidence||[]).length ? '<ul>' + f.evidence.slice(0,8).map(e => `<li>${esc(e)}</li>`).join('') + '</ul>' : ''}
      ${f.recommendation ? `<p class="rec"><b>Recommendation.</b> ${esc(f.recommendation)}</p>` : ''}
      ${(f.references||[]).length ? `<p class="meta">${f.references.map(esc).join(' &middot; ')}</p>` : ''}
      <p class="meta">affected: ${esc((f.affected||[]).join(', ') || '-')}</p>
    </div>`).join('') || '<p style="padding:12px">no findings</p>';
  el('findings').querySelectorAll('.row').forEach(r => r.onclick = () => {
    const d = el('d' + r.dataset.i); d.style.display = d.style.display === 'none' ? '' : 'none';
  });

  el('assets').innerHTML = (REPORT.assets||[]).map(a => `<tr>
    <td class="mono">${esc(a.ip || a.mac || a.key)}</td><td>${esc(a.role)}</td>
    <td class="ctr">${esc(a.purdue)}</td><td>${esc(a.vendor)}</td><td>${esc(a.family)}</td>
    <td class="mono">${esc(a.model)}</td><td class="mono">${esc(a.firmware)}</td>
    <td class="mono">${esc((a.server_ports||[]).join(', ') || '-')}</td>
    <td class="ctr">${(a.frames||0).toLocaleString()}</td></tr>`).join('');
}

async function loadAdvisories() {
  const r = await fetch('/api/advisories'); const d = await r.json();
  el('advisories').innerHTML = (d.advisories||[]).map(a => `<tr>
    <td class="mono">${esc(a.id)}</td><td class="mono">${esc((a.cve||[]).join(', '))}</td>
    <td class="ctr">${esc(a.cvss)}</td><td>${esc((a.families||[]).join(', '))}</td>
    <td class="ctr">${a.kev ? 'yes' : ''}</td></tr>`).join('');
}

function paintStatus(st) {
  const badge = el('state');
  badge.textContent = st.busy ? 'WORKING' : 'IDLE';
  badge.className = st.busy ? 'live busy' : 'live';
  el('log').innerHTML = (st.log||[]).slice().reverse()
    .map(l => `${new Date(l.ts*1000).toLocaleTimeString()}  ${esc(l.message)}`).join('<br>');
  el('rescan').disabled = st.busy;
}

el('rescan').onclick = async () => {
  el('rescan').disabled = true;
  await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
};

const es = new EventSource('/api/stream');
es.onmessage = (e) => { const st = JSON.parse(e.data); paintStatus(st); if (st.generation !== window._gen) { window._gen = st.generation; loadReport(); } };
es.onerror = () => { el('state').textContent = 'RECONNECTING'; };
paintStatus({log: []});
loadReport(); loadAdvisories();
</script></body></html>"""
