"""Shared data model: parsed packets, protocol facts and findings."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_RANK = {v: k for k, v in SEVERITY_ORDER.items()}

CATEGORY_LABELS = {
    "inventory": "Asset inventory / topology",
    "loop": "Layer-2 loops & broadcast storms",
    "crash": "Industrial protocol faults / device crashes",
    "perf": "Network performance degradation",
    "anomaly": "Suspicious activity & anomalies",
    "vuln": "Known vulnerabilities",
    "forward": "Latent & future risk",
    "config": "Hardening & configuration gaps",
}


def sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(str(sev).lower(), 0)


@dataclass
class Packet:
    """A fully decoded frame (layers are `None` when not present)."""

    idx: int
    ts: float
    iface: str
    caplen: int
    origlen: int
    src_mac: str = ""
    dst_mac: str = ""
    ethertype: int = 0
    vlans: Tuple[int, ...] = ()
    ip_ver: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_id: Optional[int] = None
    ip_ttl: Optional[int] = None
    ip_tos: int = 0
    ip_df: bool = False
    ip_mf: bool = False
    ip_frag_off: int = 0
    proto: Optional[int] = None
    sport: Optional[int] = None
    dport: Optional[int] = None
    tcp_flags: int = 0
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_win: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    payload: bytes = b""
    malformed: List[str] = field(default_factory=list)

    # ---- convenience -------------------------------------------------
    @property
    def is_broadcast(self) -> bool:
        return self.dst_mac == "ff:ff:ff:ff:ff:ff" or self.dst_ip in (
            "255.255.255.255",
        ) or (
            self.dst_ip is not None
            and self.dst_ip.startswith(("224.", "225.", "226.", "227.", "228.", "229.", "230.", "231.", "232.", "233.", "234.", "235.", "236.", "237.", "238.", "239."))
        )

    @property
    def is_multicast(self) -> bool:
        if self.dst_mac and self.dst_mac.startswith(("01:00:5e", "33:33", "01:80:c2", "01:00:0c")):
            return True
        return self.is_broadcast

    @property
    def is_tcp(self) -> bool:
        return self.proto == 6

    @property
    def is_udp(self) -> bool:
        return self.proto == 17

    def flag(self, name: str) -> bool:
        return bool(self.tcp_flags & TCP_FLAGS.get(name, 0))

    @property
    def flow5(self) -> Tuple[str, Optional[int], str, Optional[int], str]:
        """Normalised (unordered) 5-tuple."""
        a = (self.src_ip or self.src_mac, self.sport)
        b = (self.dst_ip or self.dst_mac, self.dport)
        proto = "tcp" if self.is_tcp else ("udp" if self.is_udp else str(self.proto))
        if a <= b:
            return (a[0], a[1], b[0], b[1], proto)
        return (b[0], b[1], a[0], a[1], proto)

    @property
    def directed_flow(self) -> Tuple[str, Optional[int], str, Optional[int], str]:
        proto = "tcp" if self.is_tcp else ("udp" if self.is_udp else str(self.proto))
        return (self.src_ip or self.src_mac, self.sport, self.dst_ip or self.dst_mac, self.dport, proto)

    def describe(self) -> str:
        if self.ip_ver:
            return f"{self.src_ip}:{self.sport} -> {self.dst_ip}:{self.dport} proto={self.proto}"
        return f"{self.src_mac} -> {self.dst_mac} etype=0x{self.ethertype:04x}"


TCP_FLAGS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
}


def flags_str(f: int) -> str:
    return "".join(n[0] for n, b in TCP_FLAGS.items() if f & b) or "-"


@dataclass
class ProtoFact:
    """Something a dissector understood (or failed to understand)."""

    proto: str
    summary: str
    attrs: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)

    def event(self, kind: str, detail: str = "", severity: str = "info", **kw: Any) -> None:
        ev = {"kind": kind, "detail": detail, "severity": severity}
        ev.update(kw)
        self.events.append(ev)


@dataclass
class Finding:
    fid: str
    category: str
    severity: str
    title: str
    summary: str
    evidence: List[str] = field(default_factory=list)
    affected: List[str] = field(default_factory=list)
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    metric: Dict[str, Any] = field(default_factory=dict)
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    count: int = 1
    tags: List[str] = field(default_factory=list)

    @property
    def window(self) -> str:
        if self.first_ts is None:
            return "-"
        a = time.strftime("%H:%M:%S", time.localtime(self.first_ts))
        if self.last_ts is None or abs(self.last_ts - self.first_ts) < 0.5:
            return a
        return f"{a}-{time.strftime('%H:%M:%S', time.localtime(self.last_ts))}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.fid,
            "category": self.category,
            "category_label": CATEGORY_LABELS.get(self.category, self.category),
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "affected": list(self.affected),
            "recommendation": self.recommendation,
            "references": list(self.references),
            "metric": dict(self.metric),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "window": self.window,
            "count": self.count,
            "tags": list(self.tags),
        }

    def sort_key(self) -> Tuple[int, str]:
        return (-sev_rank(self.severity), self.fid)


@dataclass
class Asset:
    """A discovered endpoint."""

    key: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    firmware: str = ""
    serial: str = ""
    family: str = ""
    role: str = "unknown"
    purdue: str = "?"
    protocols: Dict[str, int] = field(default_factory=dict)
    server_ports: Dict[int, str] = field(default_factory=dict)
    client_ports: Dict[int, int] = field(default_factory=dict)
    probed_ports: Dict[int, int] = field(default_factory=dict)
    peers: Dict[str, int] = field(default_factory=dict)
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    frames: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    confidence: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    segment: str = ""

    def note(self, text: str, source: str) -> None:
        self.confidence[source] = text
        if text not in self.notes:
            self.notes.append(text)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "model": self.model,
            "firmware": self.firmware,
            "serial": self.serial,
            "family": self.family,
            "role": self.role,
            "purdue": self.purdue,
            "protocols": dict(self.protocols),
            "server_ports": {str(k): v for k, v in self.server_ports.items()},
            "probed_ports": {str(k): v for k, v in self.probed_ports.items()},
            "peers": dict(self.peers),
            "first_seen": self.first_ts,
            "last_seen": self.last_ts,
            "frames": self.frames,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "segment": self.segment,
            "notes": list(self.notes),
            "evidence": dict(self.confidence),
        }


@dataclass
class Segment:
    cidr: str
    label: str = ""
    purdue: str = "?"
    assets: List[str] = field(default_factory=list)
    frames: int = 0
    broadcast_frames: int = 0
    protocols: Dict[str, int] = field(default_factory=dict)

    @property
    def broadcast_ratio(self) -> float:
        if not self.frames:
            return 0.0
        return self.broadcast_frames / self.frames

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cidr": self.cidr,
            "label": self.label,
            "purdue": self.purdue,
            "assets": list(self.assets),
            "frames": self.frames,
            "broadcast_frames": self.broadcast_frames,
            "broadcast_ratio": round(self.broadcast_ratio, 5),
            "protocols": dict(self.protocols),
        }
