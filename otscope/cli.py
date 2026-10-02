"""Command line interface for otscope."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Sequence

from . import __version__, report as report_mod, scenarios
from .active import probes
from .active.safety import ProbePolicy
from .analysis.engine import Engine, analyse_file
from .config import EXAMPLE_CONFIG, ScanConfig
from .store import State
from .vuln.db import AdvisoryDB

DEFAULT_FORMAT = "console"


# ------------------------------------------------------------------ helpers
def _load_cfg(path: Optional[str]) -> ScanConfig:
    if not path:
        return ScanConfig(name="default")
    if not os.path.exists(path):
        raise SystemExit(f"config file not found: {path}")
    return ScanConfig.load(path)


def _emit(report: Any, fmt: str, out: Optional[str]) -> None:
    if fmt == "json":
        text = report_mod.to_json(report)
    elif fmt == "markdown" or fmt == "md":
        text = report_mod.to_markdown(report)
    elif fmt == "html":
        text = report_mod.to_html(report)
    else:
        text = report_mod.to_console(report)
    if out:
        parent = os.path.dirname(os.path.abspath(out))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"written: {out}", file=sys.stderr)
    else:
        print(text)


def _policy(args: argparse.Namespace, cfg: ScanConfig, targets: Optional[List[str]] = None) -> ProbePolicy:
    ports: Dict[str, int] = {}
    for item in getattr(args, "service_port", None) or []:
        if "=" not in item:
            raise SystemExit(f"--service-port expects NAME=PORT, got '{item}'")
        name, value = item.split("=", 1)
        ports[name.strip()] = int(value)
    overrides: Dict[str, Any] = {
        "rate_per_second": args.rate,
        "timeout_s": args.timeout,
        "do_snmp": bool(args.snmp),
    }
    if ports:
        overrides["service_ports"] = ports
    if getattr(args, "extra_port", None):
        overrides["extra_ports"] = list(args.extra_port)
    return probes.policy_from_config(cfg, targets=targets, **overrides)


# ------------------------------------------------------------------ commands
def cmd_scan(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args.config)
    state = State(args.state) if args.state else None
    eng = Engine(cfg, state=state)

    if args.iface:
        seconds = args.seconds or 60.0
        print(f"capturing on {args.iface} for {seconds:.0f}s ...", file=sys.stderr)
        n = eng.run_live(args.iface, seconds=seconds, limit=args.limit)
        source = f"live:{args.iface}"
    else:
        path = args.source
        if not path or not os.path.exists(path):
            raise SystemExit(f"capture file not found: {path}")
        n = eng.run_file(path, limit=args.limit)
        source = os.path.basename(path)
    print(f"read {n:,} frames", file=sys.stderr)

    probe: Dict[str, Any] = {}
    if args.active:
        policy = _policy(args, cfg)
        print(policy.banner(), file=sys.stderr)
        probe = probes.run(eng.stats, cfg, policy=policy, on_result=_on_probe)

    rep = eng.analyse(probe=probe, source=source)
    _emit(rep, args.format, args.out)
    return 1 if any(f.severity == "critical" for f in rep.findings) and args.strict else 0


def _on_probe(res: Dict[str, Any]) -> None:
    ident = f"{res.get('vendor', '')} {res.get('model', '')} {res.get('firmware', '')}".strip()
    if not ident and res.get("http_server"):
        ident = f"HTTP server: {res['http_server']}"
    ports = ",".join(str(p) for p in res.get("open_ports", [])) or "none"
    print(f"  {res.get('ip'):<16} open: {ports:<28} {ident}", file=sys.stderr)


def cmd_probe(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args.config)
    policy = _policy(args, cfg, targets=list(args.targets))
    print(policy.banner(), file=sys.stderr)
    out = probes.run(Engine(cfg).stats, cfg, policy=policy, on_result=_on_probe)
    lines: List[str] = []
    if args.format == "json":
        lines.append(json.dumps(out, indent=2, default=str))
    else:
        for ip, res in out.get("hosts", {}).items():
            ident = f"{res.get('vendor', '')} {res.get('model', '')} {res.get('firmware', '')}".strip()
            lines.append(f"\n{ip}  ({res.get('duration_s', 0):.2f}s)" + (f"  ->  {ident}" if ident else ""))
            if res.get("family_hint"):
                lines.append(f"  family: {res['family_hint']}")
            for port, info in sorted(res.get("ports", {}).items(), key=lambda kv: int(kv[0])):
                if info.get("state") == "open":
                    lines.append(
                        f"  {port:>6}  open   {info.get('service', '')}  rtt {info.get('rtt_ms', 0)}ms"
                    )
                    if info.get("banner"):
                        lines.append(f"          banner: {info['banner']}")
            for key, info in (res.get("identity") or {}).items():
                if info.get("error"):
                    lines.append(f"  {key}: {info['error']}")
                elif key == "s7" and info.get("steps"):
                    lines.append(f"  s7: {', '.join(info['steps'])}")
                elif key == "snmp" and info.get("sysdescr"):
                    lines.append(f"  snmp: {info['sysdescr']}")
                elif key in ("http", "https") and (info.get("status") or info.get("server")):
                    lines.append(
                        f"  {key}: {info.get('status', '')}"
                        + (f"  [Server: {info['server']}]" if info.get("server") else "")
                        + f"  {info.get('latency_s', 0)}s"
                    )
            for note in list(res.get("errors", [])) + list(res.get("notes", [])):
                lines.append(f"  ! {note}")
    text = "\n".join(lines)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"written: {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args.config)
    state = State(args.state)
    print(
        f"watch mode: {args.iface}, {args.seconds:.0f}s captures every {args.interval:.0f}s "
        f"(state: {args.state})",
        file=sys.stderr,
    )
    iteration = 0
    try:
        while True:
            iteration += 1
            known_before = set(state.data.get("findings", {}).keys())
            eng = Engine(cfg, state=state)
            eng.run_live(args.iface, seconds=args.seconds)
            probe: Dict[str, Any] = {}
            if args.active:
                probe = probes.run(eng.stats, cfg, policy=_policy(args, cfg))
            rep = eng.analyse(probe=probe, source=f"live:{args.iface} #{iteration}")
            new_ids = {f.fid for f in rep.findings if f.fid not in known_before}
            sev = rep.by_severity()
            print(
                f"[{time.strftime('%H:%M:%S')}] #{iteration} frames={eng.stats.total_frames:,} "
                f"critical={sev['critical']} high={sev['high']} new_findings={len(new_ids)}"
            )
            for f in rep.sorted_findings():
                if f.fid in new_ids or args.verbose:
                    print(f"    {f.severity.upper():<8} {f.fid:<30} {f.title}")
            if args.once:
                break
            time.sleep(max(args.interval - args.seconds, 0.0))
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    names = list(args.scenario) if args.scenario else None
    path = args.pcap or "/tmp/otscope-demo.pcap"
    count = scenarios.write_pcap(path, names)
    print(f"generated {count:,} frames -> {path}", file=sys.stderr)
    cfg = _load_cfg(args.config)
    eng = Engine(cfg, state=State(args.state) if args.state else None)
    eng.run_file(path)
    probe: Dict[str, Any] = {}
    if args.active:
        # the demo plant is synthetic, so probing needs the emulator's ports
        from .devnet import DevNet

        policy = _policy(args, cfg)
        if not policy.service_ports.get("s7"):
            policy.service_ports = dict(DevNet.DEMO_PORTS)
        probe = probes.run(eng.stats, cfg, policy=policy, on_result=_on_probe)
    rep = eng.analyse(probe=probe, source=f"demo:{os.path.basename(path)}")
    _emit(rep, args.format, args.out)
    return 0


def cmd_devnet(args: argparse.Namespace) -> int:
    from .devnet import DevNet

    net = DevNet(fixed_ports=args.fixed_ports).start()
    print(json.dumps(net.describe(), indent=2))
    print("\nemulated plant is listening. Targets:", " ".join(net.targets))
    print("probe them with:\n  " + net.probe_command())
    if not args.forever:
        time.sleep(args.seconds)
        net.stop()
        print("stopped", file=sys.stderr)
        return 0
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        net.stop()
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    try:
        from .web.app import serve
    except ImportError as exc:  # pragma: no cover - optional extra
        raise SystemExit(f"the dashboard needs Flask: pip install 'otscope[web]' ({exc})")
    serve(
        host=args.host,
        port=args.port,
        pcap=args.pcap,
        iface=args.iface,
        seconds=args.seconds,
        debug=args.debug,
    )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    with open(args.input, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if args.format == "json":
        print(json.dumps(data, indent=2))
        return 0
    text = _render_saved(data, args.format)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"written: {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


def _render_saved(data: Dict[str, Any], fmt: str) -> str:
    """Re-render a stored JSON report without re-running the analysis."""

    class _Saved:
        def __init__(self, d: Dict[str, Any]) -> None:
            self._d = d

        def to_dict(self) -> Dict[str, Any]:
            return self._d

        def __getattr__(self, name: str) -> Any:
            return self._d[name]

    saved = _Saved(data)
    if fmt == "html":
        return report_mod.to_html(saved)
    raise SystemExit(f"re-rendering to {fmt} is not supported; use html or json")


def cmd_advisories(args: argparse.Namespace) -> int:
    db = AdvisoryDB.load()
    if args.action == "update":
        from .vuln import feeds

        ok, message, count = feeds.update_kev(path=args.kev_cache)
        print(f"KEV catalog: {message} ({count} entries)")
        if args.nvd:
            for adv in db.advisories:
                for cve in adv.cve:
                    hits, note = feeds.lookup_nvd(cve)
                    print(f"{cve}: {len(hits)} NVD records - {note}")
        return 0 if ok else 2
    if args.action == "show":
        adv = next((a for a in db.advisories if a.id == args.id or args.id in a.cve), None)
        if not adv:
            raise SystemExit(f"no advisory with id/cve {args.id}")
        print(json.dumps(adv.to_dict(), indent=2))
        return 0
    print(f"{len(db.advisories)} advisories, generated {db.generated}")
    for adv in sorted(db.advisories, key=lambda a: -(a.cvss or 0)):
        kev = " KEV" if adv.kev else ""
        print(
            f"  {adv.id:<16} CVSS {adv.cvss:<5} {', '.join(adv.cve) or '-':<28} "
            f"{', '.join(adv.families)}{kev}"
        )
    print()
    print("product lifecycle (discontinuation / spare-part horizon):")
    for life in sorted(db.lifecycle, key=lambda lc: lc.family):
        print(
            f"  {life.family:<26} phase-out announced {life.phase_out_announced or '?':<12} "
            f"type cancellation {life.type_cancellation or '?':<12} "
            f"spare parts until {life.spare_parts_until or '?':<12} {life.source}"
        )
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    text = json.dumps(EXAMPLE_CONFIG, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"written: {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_scenarios(_args: argparse.Namespace) -> int:
    print(f"{len(scenarios.SCENARIOS)} built-in scenarios (each injects one known problem):")
    for name in sorted(scenarios.SCENARIOS):
        fn = scenarios.SCENARIOS[name]
        doc = (fn.__doc__ or "").strip().splitlines()
        print(f"  {name:<24} {doc[0] if doc else ''}")
    return 0


def cmd_selftest(_args: argparse.Namespace) -> int:
    """Run the analyser over a freshly generated capture and check the outcome."""
    import tempfile

    path = os.path.join(tempfile.gettempdir(), "otscope-selftest.pcap")
    count = scenarios.write_pcap(path)
    rep = analyse_file(path)
    sev = rep.by_severity()
    ids = set()
    for f in rep.findings:
        ids.add(f.fid)
        tail = f.fid.rsplit("-", 1)[-1]
        if len(tail) == 12 and all(c in "0123456789abcdef" for c in tail):
            ids.add(f.fid.rsplit("-", 1)[0])  # instance suffix removed
    expected = {
        # inventory / anomalies
        "INV-SUMMARY",
        "ANOM-SCAN",
        "ANOM-IP-CONFLICT",
        "ANOM-WRITE-PLC",
        "ANOM-NEW-ASSET",
        # protocol faults
        "CRASH-CONTROL-COMMAND",
        "CRASH-CORRELATED-L2",
        "CRASH-S7-FAULT",
        "CRASH-MODBUS-EXCEPTION",
        "CRASH-CIP-FAULT",
        "CRASH-MALFORMED-PROTOCOL-FRAMES",
        "CRASH-SNMP-FLOOD",
        "CRASH-SILENCE",
        # loops / storms
        "LOOP-ARP-STORM",
        "LOOP-FRAME-REPEAT",
        "LOOP-MRP-DOUBLE-MANAGER",
        "LOOP-STP-TCN-STORM",
        "LOOP-BCAST-STORM",
        # performance
        "PERF-RETRANS",
        "PERF-ZEROWINDOW",
        "PERF-POLL-GAP",
        "PERF-SLOW-HTTP",
        "PERF-TOP-TALKER",
        # forward risk + vulnerability matching
        "FWD-EOL",
        "FWD-NOAUTH-S7COMM",
        "FWD-NOAUTH-MODBUS",
        "FWD-NOAUTH-ENIP",
        "FWD-RISK-RUNWAY",
        "VULN-COVERAGE",
        "VULN-ICSA-15-064-04",
        "VULN-ICSA-21-056-03",
        "VULN-ICSA-25-114-01",
    }
    missing = sorted(expected - ids)
    print(f"otscope {__version__} selftest")
    print(f"  frames generated : {count:,}")
    print(f"  frames analysed  : {rep.stats.total_frames:,}")
    print(f"  dissector errors : {rep.stats.protocols.get('dissector-error', 0)}")
    print(f"  warnings         : {len(rep.warnings)} {rep.warnings[:3]}")
    print(f"  findings         : {len(rep.findings)} {sev}")
    print(f"  advisory matches : {sum(1 for f in rep.findings if f.fid.startswith('VULN-ICSA'))}")
    print(f"  assets identified: "
          f"{sum(1 for a in rep.to_dict()['assets'] if a.get('model'))}/{len(rep.to_dict()['assets'])}")
    ok = not missing and rep.stats.protocols.get("dissector-error", 0) == 0 and not rep.warnings
    print(f"  expected finding ids missing: {missing or 'none'}")
    print("  RESULT: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


# ------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="otscope",
        description=(
            "Passive-first network analyser for plant (OT) and ERP networks: finds loops, "
            "protocol faults, performance problems, known vulnerabilities and forward risk."
        ),
    )
    p.add_argument("--version", action="version", version=f"otscope {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--config", help="JSON config file (see `otscope config`)")
        sp.add_argument("--state", help="state file for change tracking (default .state/otscope-state.json)")
        sp.add_argument("--format", default=DEFAULT_FORMAT, choices=["console", "json", "markdown", "md", "html"])
        sp.add_argument("--out", help="write the report to this file instead of stdout")
        sp.add_argument("--limit", type=int, help="stop after N frames")
        add_active(sp)

    def add_active(sp: argparse.ArgumentParser) -> None:
        g = sp.add_argument_group("active probing (read only, opt-in)")
        g.add_argument("--active", action="store_true", help="run read-only identification probes")
        g.add_argument("--rate", type=float, default=10.0, help="requests per second (default 10)")
        g.add_argument("--timeout", type=float, default=1.5, help="probe timeout in seconds")
        g.add_argument("--snmp", action="store_true", help="also try SNMP GET sysDescr.0 with the public community")
        g.add_argument(
            "--service-port",
            action="append",
            metavar="NAME=PORT",
            help="override a protocol port, e.g. --service-port s7=10102",
        )
        g.add_argument("--extra-port", action="append", type=int, help="extra TCP port to test for reachability")

    sp = sub.add_parser("scan", help="analyse a capture file or a live interface")
    sp.add_argument("source", nargs="?", help="pcap/pcapng file")
    sp.add_argument("--iface", help="capture live on this interface instead")
    sp.add_argument("--seconds", type=float, help="how long to capture (live mode)")
    sp.add_argument("--strict", action="store_true", help="exit non-zero if a critical finding exists")
    add_common(sp)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("probe", help="read-only identification of specific hosts")
    sp.add_argument("targets", nargs="+", help="IP addresses to probe")
    add_common(sp)
    sp.set_defaults(func=cmd_probe)

    sp = sub.add_parser("watch", help="continuous monitoring with change tracking")
    sp.add_argument("--iface", required=True)
    sp.add_argument("--seconds", type=float, default=30.0, help="capture length per iteration")
    sp.add_argument("--interval", type=float, default=60.0, help="seconds between iterations")
    sp.add_argument("--once", action="store_true", help="run a single iteration and exit")
    sp.add_argument("-v", "--verbose", action="store_true", help="print every finding, not only new ones")
    add_common(sp)
    sp.set_defaults(func=cmd_watch)

    sp = sub.add_parser("dashboard", help="serve the web dashboard")
    sp.add_argument("--host", default="0.0.0.0")
    sp.add_argument("--port", type=int, default=8055)
    sp.add_argument("--pcap", help="analyse this capture file (default: demo scenario)")
    sp.add_argument("--iface", help="capture live on this interface when the page is opened")
    sp.add_argument("--seconds", type=float, default=20.0)
    sp.add_argument("--debug", action="store_true")
    sp.set_defaults(func=cmd_dashboard)

    sp = sub.add_parser("report", help="re-render a saved JSON report")
    sp.add_argument("input")
    sp.add_argument("--format", default="html", choices=["html", "json"])
    sp.add_argument("--out")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("demo", help="generate a synthetic plant capture and analyse it")
    sp.add_argument("--scenario", action="append", help="scenario name (repeatable; default: all)")
    sp.add_argument("--pcap", help="where to write the generated capture")
    add_common(sp)
    sp.set_defaults(func=cmd_demo)

    sp = sub.add_parser("devnet", help="run the emulated OT/ERP network on loopback")
    sp.add_argument("--fixed-ports", action="store_true", help="use the real OT ports (needs root)")
    sp.add_argument("--seconds", type=float, default=120.0, help="how long to run (unless --forever)")
    sp.add_argument("--forever", action="store_true")
    sp.set_defaults(func=cmd_devnet)

    sp = sub.add_parser("advisories", help="inspect or refresh the advisory database")
    sp.add_argument("action", nargs="?", default="list", choices=["list", "show", "update"])
    sp.add_argument("id", nargs="?", help="advisory id or CVE for `show`")
    sp.add_argument("--kev-cache", default=None)
    sp.add_argument("--nvd", action="store_true", help="also query the NVD API for every CVE")
    sp.set_defaults(func=cmd_advisories)

    sp = sub.add_parser("config", help="print an example configuration file")
    sp.add_argument("--out")
    sp.set_defaults(func=cmd_config)

    sp = sub.add_parser("scenarios", help="list the built-in demo scenarios")
    sp.set_defaults(func=cmd_scenarios)

    sp = sub.add_parser("selftest", help="analyse a generated capture and verify the results")
    sp.set_defaults(func=cmd_selftest)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
    except SystemExit:
        raise
    except Exception as exc:  # keep a traceback for anything unexpected
        if os.environ.get("OTSCOPE_DEBUG"):
            raise
        print(f"error: {exc!r}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
