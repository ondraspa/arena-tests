"""Orchestration: ingest a capture, run every analyser, produce a report."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from .. import __version__
from ..capture import FrameTuple, iter_file, iter_frames, iter_live
from ..config import ScanConfig
from ..dissect.registry import dissect
from ..models import Finding, Packet, sev_rank
from ..pcap import CaptureError
from ..store import State
from ..vuln.db import AdvisoryDB
from ..vuln import forward as forward_vuln
from ..vuln import matcher as vuln_matcher
from . import anomalies, crashes, loops, perf, topology
from .stats import TrafficStats

ANALYSERS = [
    ("topology", topology.analyse),
    ("loops", loops.analyse),
    ("perf", perf.analyse),
    ("crashes", crashes.analyse),
    ("anomalies", anomalies.analyse),
]


@dataclass
class Report:
    config: ScanConfig
    stats: TrafficStats
    findings: List[Finding] = field(default_factory=list)
    probe: Dict[str, Any] = field(default_factory=dict)
    generated: float = field(default_factory=time.time)
    version: str = __version__
    source: str = ""
    warnings: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (-sev_rank(f.severity), f.category, f.fid))

    def by_severity(self) -> Dict[str, int]:
        out: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def by_category(self) -> Dict[str, List[Finding]]:
        out: Dict[str, List[Finding]] = {}
        for f in self.sorted_findings():
            out.setdefault(f.category, []).append(f)
        return out

    def to_dict(self) -> Dict[str, Any]:
        sev = self.by_severity()
        return {
            "version": self.version,
            "generated": self.generated,
            "source": self.source,
            "config": self.config.to_dict(),
            "summary": {
                **self.stats.summary(),
                "findings": len(self.findings),
                "severity": sev,
                "worst": self.sorted_findings()[0].title if self.findings else "",
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "assets": topology.asset_table(self.stats),
            "segments": [s.to_dict() for s in sorted(self.stats.segments.values(), key=lambda s: s.cidr)],
            "flows": perf.flow_table(self.stats),
            "timeline": [b.to_dict() for b in self.stats.bucket_list()],
            "protocol_frames": dict(sorted(self.stats.protocols.items(), key=lambda kv: -kv[1])),
            "probe": self.probe,
            "warnings": list(self.warnings),
        }

    def to_json(self, indent: int = 2) -> str:
        import json

        return json.dumps(self.to_dict(), indent=indent, default=str)


class Engine:
    def __init__(
        self,
        cfg: Optional[ScanConfig] = None,
        db: Optional[AdvisoryDB] = None,
        state: Optional[State] = None,
        on_packet: Optional[Callable[[Packet], None]] = None,
    ) -> None:
        self.cfg = cfg or ScanConfig()
        self.db = db
        self.state = state
        self.stats = TrafficStats(self.cfg)
        self.on_packet = on_packet
        self.warnings: List[str] = []
        self.packets = 0

    # ------------------------------------------------------------------
    def feed(self, pkt: Packet) -> None:
        facts = dissect(pkt)
        self.stats.add(pkt, facts)
        self.packets += 1
        if self.on_packet is not None:
            self.on_packet(pkt)

    def feed_frames(self, frames: Iterable[FrameTuple], iface: str = "", limit: Optional[int] = None) -> int:
        n = 0
        for pkt in iter_frames(iter(frames), iface=iface, limit=limit):
            self.feed(pkt)
            n += 1
        return n

    def run_file(self, path: str, limit: Optional[int] = None, progress: Optional[Callable[[int], None]] = None) -> int:
        n = 0
        try:
            for pkt in iter_frames(iter_file(path), iface=os.path.basename(path), limit=limit):
                self.feed(pkt)
                n += 1
                if progress and n % 5000 == 0:
                    progress(n)
        except CaptureError as exc:
            self.warnings.append(str(exc))
        return n

    def run_live(self, iface: str, seconds: Optional[float] = None, limit: Optional[int] = None) -> int:
        n = 0
        for pkt in iter_frames(iter_live(iface, seconds=seconds), iface=iface, limit=limit):
            self.feed(pkt)
            n += 1
        return n

    # ------------------------------------------------------------------
    def analyse(self, probe: Optional[Dict[str, Any]] = None, source: str = "") -> Report:
        report = Report(config=self.cfg, stats=self.stats, probe=probe or {}, source=source)
        report.warnings.extend(self.warnings)
        findings: List[Finding] = []
        db = self.db or AdvisoryDB.load()
        for name, fn in ANALYSERS:
            try:
                findings.extend(fn(self.stats, self.cfg))
            except Exception as exc:  # an analyser failure must not lose the report
                report.warnings.append(f"analyser '{name}' failed: {exc!r}")
        try:
            findings.extend(vuln_matcher.analyse(self.stats, self.cfg, db=db, probe=probe))
        except Exception as exc:
            report.warnings.append(f"analyser 'vuln' failed: {exc!r}")
        try:
            findings.extend(forward_vuln.analyse(self.stats, self.cfg, db=db, state=self.state, findings=findings))
        except Exception as exc:
            report.warnings.append(f"analyser 'forward' failed: {exc!r}")
        report.findings = _dedupe(findings)
        if self.state is not None:
            self.state.record_assets({a.key: a.to_dict() for a in self.stats.assets.values()})
            self.state.record_findings([f.to_dict() for f in report.findings])
            self.state.record_run(
                {
                    "source": source,
                    "frames": self.stats.total_frames,
                    "findings": len(report.findings),
                    "severity": report.by_severity(),
                }
            )
            try:
                self.state.save()
            except OSError as exc:  # a read-only disk must not lose the report
                report.warnings.append(f"could not write the state file {self.state.path}: {exc}")
        return report


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen: Dict[str, Finding] = {}
    for f in findings:
        prev = seen.get(f.fid)
        if prev is None:
            seen[f.fid] = f
            continue
        # merge duplicates: keep the highest severity, union the evidence
        if sev_rank(f.severity) > sev_rank(prev.severity):
            prev.severity = f.severity
        prev.count += f.count
        for e in f.evidence:
            if e not in prev.evidence:
                prev.evidence.append(e)
        for a in f.affected:
            if a not in prev.affected:
                prev.affected.append(a)
    return list(seen.values())


def analyse_file(path: str, cfg: Optional[ScanConfig] = None, limit: Optional[int] = None) -> Report:
    eng = Engine(cfg)
    eng.run_file(path, limit=limit)
    return eng.analyse(source=os.path.basename(path))


def analyse_live(iface: str, seconds: float, cfg: Optional[ScanConfig] = None) -> Report:
    eng = Engine(cfg)
    eng.run_live(iface, seconds=seconds)
    return eng.analyse(source=f"live:{iface}")
