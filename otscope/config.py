"""Scan profile + tunable thresholds.

Everything the analyser decides is driven from here so the same capture can be
re-scored for a different plant without touching code.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

DEFAULT_SUBNETS: List[Dict[str, Any]] = []

# Purdue model defaults: which service ports imply which level.
PORT_PURDUE: Dict[int, str] = {
    102: "0-2",      # S7comm to the CPU
    502: "0-2",      # Modbus TCP
    20000: "1-2",    # DNP3
    44818: "1-2",    # EtherNet/IP
    2222: "1-2",
    34962: "1",
    34963: "1",
    34964: "1",
    47808: "2-3",    # BACnet/IP
    4840: "2-3",     # OPC UA
    135: "3-4",
    445: "3-4",
    1433: "4",
    3306: "4",
    1521: "4",
    5000: "4",
    3200: "4",
    80: "4-5",
    443: "4-5",
    3389: "3-4",
    22: "3-4",
}

PURDUE_LABELS = {
    "0": "L0 process",
    "1": "L1 sensing/basic control",
    "2": "L2 supervisory control",
    "3": "L3 operations (SCADA/historian)",
    "4": "L4 business (ERP)",
    "5": "L5 enterprise",
    "0-2": "L0-L2 device/control",
    "1-2": "L1-L2 control",
    "2-3": "L2-L3 supervisory",
    "3-4": "L3-L4 boundary",
    "4-5": "L4-L5 business",
}


@dataclass
class SubnetProfile:
    cidr: str
    label: str = ""
    purdue: str = "?"
    role: str = ""            # ot | dmz | erp | office
    allow_protocols: List[str] = field(default_factory=list)
    trusted_engineers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Thresholds:
    # ---- loops / storms
    broadcast_ratio_warn: float = 0.20
    broadcast_ratio_crit: float = 0.45
    broadcast_pps_warn: float = 120.0
    broadcast_pps_crit: float = 400.0
    arp_rate_warn: float = 12.0          # identical ARP requests / second
    mac_flap_window: float = 5.0
    broadcast_min_frames: int = 50       # below this a "storm" is just a short capture
    new_asset_after_ratio: float = 0.2   # a device first seen after this share of the window is new
    loop_min_repeat: int = 6             # identical frames to call it a loop
    loop_poll_rate_max: float = 25.0     # answered identical frames below this rate are polling
    loop_rate_min: float = 5.0           # single-interface unicast repeats below this are not a loop
    loop_rate_wire: float = 50.0         # at or above this rate it is a loop, whatever else it looks like
    correlation_window: float = 5.0      # +/- seconds linking protocol faults to layer-2 events
    correlation_min_events: int = 3      # correlated faults needed to name a root cause
    loop_window: float = 1.0
    stp_tcn_rate_warn: float = 1.0       # TCN BPDUs per second
    # ---- performance
    rtt_warn_ms: float = 20.0
    rtt_crit_ms: float = 100.0
    jitter_warn_ms: float = 10.0
    retrans_warn: float = 0.02           # 2 % of segments
    retrans_crit: float = 0.10
    zero_window_warn: int = 5
    poll_gap_factor: float = 3.0         # gap > factor * median => polling gap
    poll_gap_min_ms: float = 200.0
    slow_http_warn_ms: float = 1500.0
    slow_http_crit_ms: float = 5000.0
    loss_warn: float = 0.01
    util_warn: float = 0.55
    util_crit: float = 0.85
    # ---- anomalies
    scan_port_threshold: int = 15        # distinct ports from one source
    scan_host_threshold: int = 10        # distinct hosts from one source
    beacon_cv_max: float = 0.15          # coefficient of variation
    beacon_min_count: int = 6
    error_storm_min: int = 5
    error_storm_window: float = 60.0
    session_churn_min: int = 8
    session_churn_window: float = 60.0
    silence_warn_s: float = 30.0
    # ---- scoring
    z_warn: float = 3.0
    z_crit: float = 5.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanConfig:
    name: str = "default"
    link_speed_mbps: float = 100.0
    subnets: List[SubnetProfile] = field(default_factory=list)
    engineering_stations: List[str] = field(default_factory=list)
    known_plcs: List[str] = field(default_factory=list)
    erp_hosts: List[str] = field(default_factory=list)
    fragile_devices: List[str] = field(default_factory=list)
    thresholds: Thresholds = field(default_factory=Thresholds)
    window_seconds: float = 60.0
    segment_prefix: int = 24
    allow_active: bool = False
    notes: str = ""

    # ------------------------------------------------------------------
    def subnet_for(self, ip: Optional[str]) -> Optional[SubnetProfile]:
        if not ip:
            return None
        for s in self.subnets:
            if _in_cidr(ip, s.cidr):
                return s
        return None

    def purdue_for_ip(self, ip: Optional[str]) -> str:
        s = self.subnet_for(ip)
        if s and s.purdue != "?":
            return s.purdue
        return "?"

    def is_engineer(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        if ip in self.engineering_stations:
            return True
        s = self.subnet_for(ip)
        return bool(s and ip in s.trusted_engineers)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "link_speed_mbps": self.link_speed_mbps,
            "subnets": [s.to_dict() for s in self.subnets],
            "engineering_stations": list(self.engineering_stations),
            "known_plcs": list(self.known_plcs),
            "erp_hosts": list(self.erp_hosts),
            "fragile_devices": list(self.fragile_devices),
            "thresholds": self.thresholds.to_dict(),
            "window_seconds": self.window_seconds,
            "segment_prefix": self.segment_prefix,
            "notes": self.notes,
        }

    @classmethod
    def load(cls, path: str) -> "ScanConfig":
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "ScanConfig":
        cfg = cls(
            name=raw.get("name", "default"),
            link_speed_mbps=float(raw.get("link_speed_mbps", 100.0)),
            engineering_stations=list(raw.get("engineering_stations", [])),
            known_plcs=list(raw.get("known_plcs", [])),
            erp_hosts=list(raw.get("erp_hosts", [])),
            fragile_devices=list(raw.get("fragile_devices", [])),
            window_seconds=float(raw.get("window_seconds", 60.0)),
            segment_prefix=int(raw.get("segment_prefix", 24)),
            notes=raw.get("notes", ""),
        )
        th = raw.get("thresholds", {})
        for k, v in th.items():
            if hasattr(cfg.thresholds, k):
                setattr(cfg.thresholds, k, v)
        for s in raw.get("subnets", []):
            cfg.subnets.append(
                SubnetProfile(
                    cidr=s["cidr"],
                    label=s.get("label", ""),
                    purdue=str(s.get("purdue", "?")),
                    role=s.get("role", ""),
                    allow_protocols=list(s.get("allow_protocols", [])),
                    trusted_engineers=list(s.get("trusted_engineers", [])),
                )
            )
        return cfg

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)


EXAMPLE_CONFIG = {
    "name": "example-plant",
    "link_speed_mbps": 100.0,
    "segment_prefix": 24,
    "window_seconds": 60,
    "engineering_stations": ["10.20.1.10", "10.20.1.11"],
    "erp_hosts": ["10.10.0.21", "10.10.0.22"],
    "known_plcs": ["10.20.2.10", "10.20.2.11", "10.20.3.20"],
    "fragile_devices": ["10.20.2.10"],
    "subnets": [
        {"cidr": "10.10.0.0/24", "label": "ERP servers", "purdue": "4", "role": "erp", "allow_protocols": ["http", "https", "service"]},
        {"cidr": "10.20.1.0/24", "label": "Engineering / HMI", "purdue": "3", "role": "ot",
         "allow_protocols": ["s7comm", "modbus", "enip", "lldp", "stp", "http"],
         "trusted_engineers": ["10.20.1.10", "10.20.1.11"]},
        {"cidr": "10.20.2.0/24", "label": "Siemens line 1 (S7-300/1500)", "purdue": "2", "role": "ot",
         "allow_protocols": ["s7comm", "cotp", "lldp", "mrp", "profinet-dcp"]},
        {"cidr": "10.20.3.0/24", "label": "Rockwell line 2 (CompactLogix)", "purdue": "2", "role": "ot",
         "allow_protocols": ["enip", "cotp", "lldp"]},
        {"cidr": "10.20.4.0/24", "label": "Schneider line 3 (Modicon)", "purdue": "2", "role": "ot",
         "allow_protocols": ["modbus", "lldp"]},
    ],
    "thresholds": {"retrans_warn": 0.02, "retrans_crit": 0.10, "broadcast_pps_warn": 120},
    "notes": "Edit this to match your own address plan; unknown segments are still analysed with defaults.",
}


def _in_cidr(ip: str, cidr: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
