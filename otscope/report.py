"""Report rendering: console, markdown, JSON and a self-contained HTML page.

The HTML page has no external dependencies at all - no CDN, no web font, no
JavaScript library.  A plant network is usually an offline network, and the
dashboard is meant to be served from a laptop inside it.
"""

from __future__ import annotations

import html
import json
import time
from typing import Any, Dict, List, Optional

from .models import CATEGORY_LABELS

SEV_COLOR = {
    "critical": "#b3261e",
    "high": "#e8710a",
    "medium": "#b58900",
    "low": "#3d7ea6",
    "info": "#6b7280",
}
SEV_BG = {
    "critical": "#fdecea",
    "high": "#fff1e0",
    "medium": "#fff8e1",
    "low": "#eaf3f8",
    "info": "#f1f3f5",
}


def _ts(ts: Optional[float]) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


# ------------------------------------------------------------------ console
def to_console(report: Any, width: int = 100) -> str:
    sev = report.by_severity()
    out: List[str] = []
    line = "=" * width
    out.append(line)
    out.append(f"otscope {report.version}   source: {report.source or '-'}   generated {_ts(report.generated)}")
    s = report.stats.summary()
    out.append(
        f"frames {s.get('frames', 0):,}   bytes {s.get('bytes', 0):,}   hosts {s.get('assets', 0)}   "
        f"segments {s.get('segments', 0)}   flows {s.get('flows', 0)}   window {s.get('duration', 0):.1f}s"
    )
    out.append(
        "findings "
        + "  ".join(f"{k}:{v}" for k, v in sev.items() if v)
        + f"   total {len(report.findings)}"
    )
    out.append(line)
    if report.warnings:
        out.append("WARNINGS")
        for w in report.warnings:
            out.append(f"  ! {w}")
        out.append(line)

    for category, findings in report.by_category().items():
        out.append(f"[{CATEGORY_LABELS.get(category, category).upper()}]")
        for f in findings:
            out.append(f"  {f.severity.upper():<8} {f.fid:<28} {f.title}")
            out.append(f"           {f.summary}")
            for ev in f.evidence[:3]:
                out.append(f"           - {ev}")
            if f.recommendation:
                out.append(f"           -> {f.recommendation}")
        out.append("")

    out.append("[INVENTORY]")
    hdr = f"  {'IP':<16} {'role':<20} {'P':<2} {'vendor':<18} {'family':<18} {'model':<22} ports"
    out.append(hdr)
    for a in report.to_dict()["assets"]:
        ip = a.get("ip") or a.get("mac") or a["key"]
        ports = ",".join(str(p) for p in sorted(a.get("server_ports", []))) or "-"
        out.append(
            f"  {ip:<16} {a.get('role', '')[:20]:<20} {str(a.get('purdue', ''))[:2]:<2} "
            f"{a.get('vendor', '')[:18]:<18} {a.get('family', '')[:18]:<18} "
            f"{a.get('model', '')[:22]:<22} {ports}"
        )
    out.append("")

    probe = report.probe or {}
    hosts = probe.get("hosts") or {}
    if hosts:
        out.append("[ACTIVE PROBE - read only]")
        for ip, res in hosts.items():
            ident = f"{res.get('vendor', '')} {res.get('model', '')} {res.get('firmware', '')}".strip()
            out.append(f"  {ip:<16} open={','.join(str(p) for p in res.get('open_ports', [])) or '-'}  {ident}")
            for err in res.get("errors", []):
                out.append(f"      ! {err}")
            for note in res.get("notes", []):
                out.append(f"      i {note}")
        out.append("")
    return "\n".join(out)


# ----------------------------------------------------------------- markdown
def to_markdown(report: Any) -> str:
    sev = report.by_severity()
    s = report.stats.summary()
    out: List[str] = []
    out.append(f"# otscope report - {report.source or 'live capture'}")
    out.append("")
    out.append(f"* generated: {_ts(report.generated)}")
    out.append(f"* version: {report.version}")
    out.append(
        f"* frames: **{s.get('frames', 0):,}**, bytes: {s.get('bytes', 0):,}, hosts: {s.get('assets', 0)}, "
        f"segments: {s.get('segments', 0)}, flows: {s.get('flows', 0)}, window: {s.get('duration', 0):.1f} s"
    )
    out.append("")
    out.append("| severity | count |")
    out.append("| --- | --- |")
    for k in ("critical", "high", "medium", "low", "info"):
        out.append(f"| {k} | {sev.get(k, 0)} |")
    out.append("")

    if report.warnings:
        out.append("## Capture warnings")
        for w in report.warnings:
            out.append(f"- {w}")
        out.append("")

    for category, findings in report.by_category().items():
        out.append(f"## {CATEGORY_LABELS.get(category, category)}")
        out.append("")
        for f in findings:
            out.append(f"### {f.severity.upper()} - {f.title} `{f.fid}`")
            out.append("")
            out.append(f.summary)
            out.append("")
            if f.affected:
                out.append(f"*affected:* {', '.join(f.affected[:12])}")
            for ev in f.evidence:
                out.append(f"- {ev}")
            if f.recommendation:
                out.append("")
                out.append(f"**Recommendation:** {f.recommendation}")
            if f.references:
                out.append("")
                out.append("References: " + " ; ".join(f.references))
            out.append("")

    out.append("## Inventory")
    out.append("")
    out.append("| IP / MAC | role | Purdue | vendor | family | model | firmware | services |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for a in report.to_dict()["assets"]:
        ip = a.get("ip") or a.get("mac") or a["key"]
        ports = ", ".join(str(p) for p in sorted(a.get("server_ports", []))) or "-"
        out.append(
            f"| {ip} | {a.get('role', '')} | {a.get('purdue', '')} | {a.get('vendor', '')} | "
            f"{a.get('family', '')} | {a.get('model', '')} | {a.get('firmware', '')} | {ports} |"
        )
    out.append("")

    hosts = (report.probe or {}).get("hosts") or {}
    if hosts:
        out.append("## Active probe (read only)")
        out.append("")
        out.append("| target | open ports | identified as | notes |")
        out.append("| --- | --- | --- | --- |")
        for ip, res in hosts.items():
            ident = f"{res.get('vendor', '')} {res.get('model', '')} {res.get('firmware', '')}".strip() or "-"
            notes = "; ".join(list(res.get("errors", [])) + list(res.get("notes", []))) or "-"
            out.append(f"| {ip} | {', '.join(str(p) for p in res.get('open_ports', [])) or '-'} | {ident} | {notes} |")
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------- json
def to_json(report: Any, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False, default=str)


# --------------------------------------------------------------------- html
def _svg_sparkline(buckets: List[Dict[str, Any]], width: int = 900, height: int = 90) -> str:
    if not buckets:
        return ""
    vals = [b.get("bytes", 0) or 0 for b in buckets]
    peak = max(vals) or 1
    n = len(vals)
    step = width / max(n - 1, 1)
    pts = " ".join(f"{i * step:.1f},{height - (v / peak) * (height - 6) - 3:.1f}" for i, v in enumerate(vals))
    area = f"0,{height} {pts} {width},{height}"
    return (
        f'<svg viewBox="0 0 {width} {height}" preserveAspectRatio="none" class="spark">'
        f'<polygon points="{area}" fill="#dbeafe"/>'
        f'<polyline points="{pts}" fill="none" stroke="#2563eb" stroke-width="1.5"/></svg>'
    )


def _bar_rows(counts: Dict[str, int]) -> str:
    if not counts:
        return ""
    peak = max(counts.values()) or 1
    rows = []
    for name, value in list(counts.items())[:16]:
        pct = int(value / peak * 100)
        rows.append(
            f'<div class="bar"><span class="blabel">{html.escape(name)}</span>'
            f'<span class="btrack"><span class="bfill" style="width:{pct}%"></span></span>'
            f'<span class="bval">{value:,}</span></div>'
        )
    return "".join(rows)


def to_html(report: Any, live: bool = False) -> str:
    """Render the full self-contained dashboard page."""
    data = report.to_dict()
    sev = data["summary"]["severity"]
    assets = data["assets"]
    esc = html.escape

    sev_cards = "".join(
        f'<div class="card" style="border-top:4px solid {SEV_COLOR[k]}">'
        f'<div class="num" style="color:{SEV_COLOR[k]}">{sev.get(k, 0)}</div><div class="lbl">{k}</div></div>'
        for k in ("critical", "high", "medium", "low", "info")
    )

    finding_rows = []
    for f in data["findings"]:
        sev_name = f["severity"]
        color = SEV_COLOR.get(sev_name, "#666")
        bg = SEV_BG.get(sev_name, "#f6f6f6")
        evidence = "".join(f"<li>{esc(str(e))}</li>" for e in f["evidence"][:8])
        refs = " ".join(f'<span class="ref">{esc(r)}</span>' for r in f["references"])
        finding_rows.append(
            f'<details class="finding" data-cat="{esc(f["category"])}" data-sev="{esc(sev_name)}">'
            f'<summary><span class="pill" style="background:{bg};color:{color}">{esc(sev_name.upper())}</span>'
            f'<code>{esc(f["id"])}</code> <span class="ftitle">{esc(f["title"])}</span>'
            f'<span class="meta">{esc(f["window"])} &middot; {esc(f["category_label"])}</span></summary>'
            f'<div class="body"><p>{esc(f["summary"])}</p>'
            + (f"<ul>{evidence}</ul>" if evidence else "")
            + (f'<p class="rec"><b>Recommendation.</b> {esc(f["recommendation"])}</p>' if f["recommendation"] else "")
            + (f'<p class="refs">{refs}</p>' if refs else "")
            + f'<p class="meta">affected: {esc(", ".join(f["affected"][:16]) or "-")}</p></div></details>'
        )

    asset_rows = "".join(
        "<tr>"
        + f'<td class="mono">{esc(str(a.get("ip") or a.get("mac") or a["key"]))}</td>'
        + f'<td>{esc(a.get("role", ""))}</td>'
        + f'<td class="ctr">{esc(str(a.get("purdue", "")))}</td>'
        + f'<td>{esc(a.get("vendor", ""))}</td>'
        + f'<td>{esc(a.get("family", ""))}</td>'
        + f'<td class="mono">{esc(a.get("model", ""))}</td>'
        + f'<td class="mono">{esc(a.get("firmware", ""))}</td>'
        + f'<td class="mono">{esc(", ".join(str(p) for p in sorted(a.get("server_ports", []))) or "-")}</td>'
        + f'<td class="ctr">{a.get("frames", 0):,}</td>'
        + "</tr>"
        for a in assets
    )

    def _flow_row(f: Dict[str, Any]) -> str:
        packets = f.get("packets", 0) or 0
        retrans = f.get("retrans", 0) or 0
        rtt = f.get("rtt_p95_ms") or f.get("rtt_syn_ms")
        proto = ", ".join(sorted(f.get("protocols", {}) or {})) or "-"
        return (
            "<tr>"
            + f'<td class="mono">{esc(str(f.get("client", "")))} &rarr; {esc(str(f.get("server", "")))}</td>'
            + f'<td class="ctr">{esc(str(f.get("cport", "")))} &rarr; {esc(str(f.get("sport", "")))}</td>'
            + f'<td>{esc(proto)}</td>'
            + f'<td class="ctr">{packets:,}</td>'
            + f'<td class="ctr">{f.get("bytes", 0):,}</td>'
            + f'<td class="ctr">{(retrans / packets * 100 if packets else 0):.1f}%</td>'
            + f'<td class="ctr">{f"{rtt:.2f}" if rtt else "-"}</td>'
            + "</tr>"
        )

    flow_rows = "".join(_flow_row(f) for f in data.get("flows", [])[:25])

    probe_blocks = []
    for ip, res in (data.get("probe") or {}).get("hosts", {}).items():
        ports = "".join(
            f'<span class="port {"open" if v.get("state") == "open" else "closed"}" title="{esc(v.get("service", ""))}">{esc(str(k))}</span>'
            for k, v in sorted(res.get("ports", {}).items(), key=lambda kv: int(kv[0]))
        )
        ident = esc(f"{res.get('vendor', '')} {res.get('model', '')} {res.get('firmware', '')}".strip() or "not identified")
        notes = "".join(f'<li class="warn">{esc(n)}</li>' for n in list(res.get("errors", [])) + list(res.get("notes", [])))
        probe_blocks.append(
            f'<div class="probe"><div class="probehead"><span class="mono">{esc(ip)}</span>'
            f'<span class="ident">{ident}</span></div>'
            f'<div class="ports">{ports}</div>'
            + (f"<ul>{notes}</ul>" if notes else "")
            + "</div>"
        )

    warnings = "".join(f'<li>{esc(w)}</li>' for w in data.get("warnings", []))
    timeline = _svg_sparkline(data.get("timeline", []))
    live_badge = '<span class="live">LIVE</span>' if live else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>otscope - OT network assessment</title>
<style>
:root {{ --ink:#111827; --mut:#6b7280; --line:#e5e7eb; --bg:#f8fafc; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       color:var(--ink); background:var(--bg); }}
header {{ background:#0b1220; color:#fff; padding:18px 28px; display:flex; align-items:baseline; gap:14px; flex-wrap:wrap; }}
header h1 {{ margin:0; font-size:19px; letter-spacing:.4px; }}
header .sub {{ color:#94a3b8; font-size:12.5px; }}
main {{ padding:22px 28px 60px; max-width:1280px; margin:0 auto; }}
h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.8px; color:#374151; margin:34px 0 10px; }}
.cards {{ display:flex; gap:12px; flex-wrap:wrap; }}
.card {{ background:#fff; border:1px solid var(--line); border-radius:10px; padding:12px 20px; min-width:110px; }}
.card .num {{ font-size:28px; font-weight:650; }}
.card .lbl {{ color:var(--mut); font-size:12px; text-transform:uppercase; letter-spacing:.6px; }}
.panel {{ background:#fff; border:1px solid var(--line); border-radius:10px; padding:16px 18px; }}
.spark {{ width:100%; height:90px; display:block; }}
.bar {{ display:flex; align-items:center; gap:10px; margin:3px 0; font-size:12.5px; }}
.blabel {{ width:110px; color:#374151; }}
.btrack {{ flex:1; background:#eef2f7; height:10px; border-radius:5px; overflow:hidden; }}
.bfill {{ display:block; height:10px; background:#3b82f6; }}
.bval {{ width:70px; text-align:right; color:var(--mut); }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th,td {{ text-align:left; padding:7px 9px; border-bottom:1px solid var(--line); }}
th {{ color:var(--mut); font-weight:600; font-size:11.5px; text-transform:uppercase; letter-spacing:.5px; }}
td.ctr, th.ctr {{ text-align:center; }}
.mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12.5px; }}
details.finding {{ background:#fff; border:1px solid var(--line); border-left:3px solid #cbd5e1;
                  border-radius:8px; margin:6px 0; }}
details.finding summary {{ cursor:pointer; padding:9px 13px; display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
details.finding .body {{ padding:2px 16px 14px; border-top:1px solid var(--line); }}
details.finding ul {{ margin:6px 0; padding-left:20px; color:#374151; }}
details.finding .rec {{ background:#f0f9ff; border-left:3px solid #38bdf8; padding:8px 11px; border-radius:4px; }}
details.finding code {{ background:#f1f5f9; padding:1px 5px; border-radius:4px; font-size:12px; }}
.pill {{ font-size:11px; font-weight:700; padding:2px 7px; border-radius:20px; letter-spacing:.4px; }}
.ftitle {{ font-weight:600; }}
.meta {{ color:var(--mut); font-size:12px; margin-left:auto; }}
.refs {{ color:var(--mut); font-size:12px; }}
.ref {{ background:#f1f5f9; border-radius:4px; padding:1px 6px; margin-right:5px; }}
.probe {{ border:1px solid var(--line); border-radius:8px; padding:10px 13px; margin:8px 0; background:#fff; }}
.probehead {{ display:flex; gap:12px; align-items:baseline; }}
.ident {{ color:#374151; }}
.ports {{ margin:7px 0; }}
.port {{ display:inline-block; font-family:ui-monospace,Menlo,monospace; font-size:11.5px; padding:1px 6px;
        border-radius:4px; margin:0 4px 4px 0; background:#eef2f7; color:#64748b; }}
.port.open {{ background:#dcfce7; color:#166534; }}
.probe ul {{ margin:6px 0 0; padding-left:18px; color:#7c2d12; font-size:12.5px; }}
.warnbar {{ background:#fffbeb; border:1px solid #fde68a; border-radius:8px; padding:10px 16px; margin:14px 0; }}
.live {{ background:#dc2626; color:#fff; font-size:11px; padding:2px 8px; border-radius:20px; letter-spacing:1px; }}
footer {{ color:var(--mut); font-size:12px; margin-top:40px; }}
.grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
@media (max-width:900px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
</style></head><body>
<header>
  <h1>otscope</h1><span class="sub">OT / ERP network assessment</span>
  <span class="sub">source: {esc(data.get("source") or "-")}</span>
  <span class="sub">{esc(_ts(report.generated))}</span>
  {live_badge}
  <span class="sub" style="margin-left:auto">v{esc(report.version)}</span>
</header>
<main>
  <div class="cards">{sev_cards}
    <div class="card"><div class="num">{data["summary"].get("assets", 0)}</div><div class="lbl">hosts</div></div>
    <div class="card"><div class="num">{data["summary"].get("frames", 0):,}</div><div class="lbl">frames</div></div>
    <div class="card"><div class="num">{len(data.get("segments", []))}</div><div class="lbl">segments</div></div>
  </div>

  {"<div class='warnbar'><b>Capture warnings</b><ul>" + warnings + "</ul></div>" if warnings else ""}

  <h2>Traffic over the capture window</h2>
  <div class="panel">{timeline}</div>

  <h2>Protocol frames seen</h2>
  <div class="panel">{_bar_rows(data.get("protocol_frames", {}))}</div>

  <h2>Findings ({len(data["findings"])})</h2>
  <div class="panel" style="padding:10px 12px">{''.join(finding_rows) or '<p>nothing found</p>'}</div>

  <h2>Inventory</h2>
  <div class="panel"><table>
    <thead><tr><th>IP / MAC</th><th>role</th><th class="ctr">P</th><th>vendor</th><th>family</th>
    <th>model</th><th>firmware</th><th>services</th><th class="ctr">frames</th></tr></thead>
    <tbody>{asset_rows}</tbody></table></div>

  {("<h2>Top flows</h2><div class='panel'><table><thead><tr><th>flow</th><th class='ctr'>ports</th>"
     "<th>protocols</th><th class='ctr'>packets</th><th class='ctr'>bytes</th><th class='ctr'>retrans</th>"
     "<th class='ctr'>rtt p95 ms</th></tr></thead><tbody>" + flow_rows + "</tbody></table></div>")
   if flow_rows else ""}

  {("<h2>Active probe results (read only)</h2><div class='panel'>" + ''.join(probe_blocks) + "</div>")
   if probe_blocks else ""}

  <footer>otscope is a diagnostic tool. Findings are heuristics derived from observed traffic and a
  curated advisory list; always confirm against the vendor advisory before acting on a control system.</footer>
</main></body></html>"""
