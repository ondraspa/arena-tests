"""Asset inventory, role classification and Purdue-level mapping."""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from ..config import PORT_PURDUE, ScanConfig
from ..models import Asset, Finding
from ..util import stable_id
from .stats import TrafficStats

CONTROLLER_PORTS = {102, 502, 44818}
SWITCH_HINTS = ("switch", "scalance", "stratix", "conel", "moxa", "edrs", "hirschmann", "rsg", "managed")

S7_FAMILY = [
    (r"6ES7\s*51", "S7-1500"),
    (r"6ES7\s*5", "S7-1500"),
    (r"6ES7\s*4", "S7-400"),
    (r"6ES7\s*3", "S7-300"),
    (r"6ES7\s*21", "S7-1200"),
    (r"6ES7\s*2", "S7-1200"),
    (r"6GK7", "S7 communication processor"),
    (r"6SN\d", "SINAMICS"),
]

MODICON_FAMILY = [
    (r"BMX\s*P34", "Modicon M340"),
    (r"BMX\s*P58", "Modicon M580"),
    (r"BME\s*P58", "Modicon M580"),
    (r"140\s*CPU", "Modicon Quantum"),
    (r"TSX\s*P57", "Modicon Premium"),
    (r"TM\d", "Modicon M2xx"),
    (r"BMX\s*NOC", "Modbus/TCP X80 module"),
    (r"BMX\s*NOE", "Modbus/TCP NOE module"),
]

LOGIX_FAMILY = [
    (r"1769-L3", "CompactLogix 5370"),
    (r"1769-L1", "CompactLogix 5370"),
    (r"1769-L2", "CompactLogix 5370"),
    (r"1769-L", "CompactLogix 1769"),
    (r"5069-L3", "CompactLogix 5380"),
    (r"1756-L", "ControlLogix"),
    (r"1756-EN", "ControlLogix EtherNet/IP adapter"),
    (r"1768-L", "CompactLogix 1768"),
    (r"1734-AEN", "POINT I/O adapter"),
]


def family_from_name(text: str) -> Tuple[str, str]:
    """Return (family, vendor) inferred from a device name string."""
    if not text:
        return "", ""
    for pattern, fam in S7_FAMILY:
        if re.search(pattern, text, re.I):
            return fam, "Siemens"
    for pattern, fam in MODICON_FAMILY:
        if re.search(pattern, text, re.I):
            return fam, "Schneider Electric"
    for pattern, fam in LOGIX_FAMILY:
        if re.search(pattern, text, re.I):
            return fam, "Rockwell Automation"
    if re.search(r"SIMATIC|SINUMERIK|SINAMICS|SIPLUS|SCALANCE", text, re.I):
        return "SIMATIC/SINUMERIK", "Siemens"
    if re.search(r"Modicon|Schneider|BMX|BME", text, re.I):
        return "Modicon", "Schneider Electric"
    if re.search(r"Logix|Allen-Bradley|Rockwell|Stratix", text, re.I):
        return "Logix", "Rockwell Automation"
    return "", ""


def classify(stats: TrafficStats, cfg: ScanConfig) -> None:
    """Fill in role / purdue / identity for every asset."""
    for key, a in stats.assets.items():
        ports = set(a.server_ports)
        protos = set(a.protocols)
        # --- identity from protocol evidence
        if not a.family:
            for ts, text, src in stats.s7_szl:
                if src == a.ip or key == src:
                    fam, vendor = family_from_name(text)
                    if fam:
                        a.family = fam
                        a.model = text[:40]
                        a.vendor = a.vendor or vendor
                        a.note(f"S7 module identification: {text}", "s7-szl")
                        break
            for ts, src, ident in stats.enip_identities:
                if src == a.ip or (ident.get("ip") and ident.get("ip") == a.ip):
                    a.vendor = ident.get("vendor") or a.vendor
                    a.model = ident.get("product_name") or a.model
                    a.serial = ident.get("serial") or a.serial
                    a.firmware = ident.get("revision") or a.firmware
                    fam, _v = family_from_name(ident.get("product_name", ""))
                    a.family = fam or (ident.get("device_type_name", "") if ident.get("device_type") else "")
                    a.note(
                        f"EtherNet/IP ListIdentity: {ident.get('vendor')} {ident.get('product_name')} "
                        f"rev {ident.get('revision')} serial {ident.get('serial')}",
                        "enip-identity",
                    )
                    break
            for ts, src, dev in stats.modbus_device_id:
                if src == a.ip:
                    a.vendor = dev.get("VendorName", a.vendor)
                    a.model = dev.get("ProductName") or dev.get("ModelName") or a.model
                    a.firmware = dev.get("MajorMinorRevision", a.firmware)
                    fam, _v = family_from_name(f"{a.model} {dev.get('ProductCode', '')}")
                    a.family = fam or a.family
                    a.note(f"Modbus device identification: {dev}", "modbus-fc43")
                    break
            for ts, name, src in stats.dcp_station_names:
                if src == a.ip or src == a.mac:
                    a.hostname = a.hostname or name
                    a.note(f"PROFINET DCP station name: {name}", "dcp")
            for (mac, sysname), info in stats.lldp_neighbors.items():
                if mac == a.mac:
                    a.hostname = a.hostname or str(info.get("system_name", ""))
                    desc = str(info.get("system_desc", ""))
                    if desc:
                        a.note(f"LLDP: {sysname} - {desc[:80]}", "lldp")
                    fam, vendor = family_from_name(f"{sysname} {desc}")
                    if fam:
                        a.family = a.family or fam
                        a.vendor = a.vendor or vendor
            for (mac, devid), info in stats.cdp_neighbors.items():
                if mac == a.mac:
                    a.hostname = a.hostname or str(info.get("device_id", ""))
                    plat = str(info.get("platform", ""))
                    if plat:
                        a.note(f"CDP platform: {plat}", "cdp")

        # --- role
        role = "unknown"
        if ports & CONTROLLER_PORTS:
            role = "controller"
            if a.family and ("adapter" in a.family.lower() or "EN2" in (a.model or "")):
                role = "io-adapter"
        elif any(p in (102, 502, 44818) for p in a.client_ports):
            role = "hmi-scada"
        elif a.vendor and any(h in (a.hostname or "").lower() for h in SWITCH_HINTS):
            role = "switch"
        elif protos & {"stp", "mrp"} and not (ports & CONTROLLER_PORTS):
            role = "switch"
        elif ports & {80, 443, 3306, 1433, 1521, 5000, 3200}:
            role = "server"
        elif ports & {3389, 22} or protos & {"http"}:
            role = "workstation"
        if a.ip and a.ip in cfg.known_plcs:
            role = "controller"
        if a.ip and a.ip in cfg.erp_hosts:
            role = "erp-server"
        if cfg.is_engineer(a.ip):
            role = "engineering-station"
        if role == "unknown" and a.frames and not a.bytes_out:
            # only ever seen as a destination: powered off, firewalled or a scan target
            role = "no-response"
            a.note("never sent a frame in this capture (powered off, filtered, or a scan target)", "silence")
        a.role = role

        # --- purdue
        if cfg.purdue_for_ip(a.ip) != "?":
            a.purdue = cfg.purdue_for_ip(a.ip)
        else:
            a.purdue = _infer_purdue(a, ports, role)

        seg = stats.segment(a.ip)
        if seg:
            a.segment = seg.cidr
            if a.role == "controller" and a.key not in seg.assets:
                seg.assets.append(a.key)
        # peers
        for fkey, flow in stats.flows.items():
            if flow.server == a.ip:
                a.peers[flow.client or "?"] = a.peers.get(flow.client or "?", 0) + flow.packets
            elif flow.client == a.ip:
                a.peers[flow.server or "?"] = a.peers.get(flow.server or "?", 0) + flow.packets


def _infer_purdue(a: Asset, ports: set, role: str) -> str:
    best = "?"
    for p in ports:
        lvl = PORT_PURDUE.get(p)
        if lvl is None:
            continue
        if best == "?" or _purdue_rank(lvl) < _purdue_rank(best):
            best = lvl
    if best == "?":
        if role == "erp-server":
            return "4"
        if role == "switch":
            return "2-3"
        if role == "workstation":
            return "3-4"
    return best


def _purdue_rank(level: str) -> int:
    try:
        return int(level.split("-")[0])
    except (ValueError, IndexError):
        return 9


def analyse(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    classify(stats, cfg)
    out: List[Finding] = []
    controllers = [a for a in stats.assets.values() if a.role == "controller"]
    out.append(
        Finding(
            fid="INV-SUMMARY",
            category="inventory",
            severity="info",
            title=f"{len(stats.assets)} hosts discovered on {len(stats.segments)} segments",
            summary=(
                f"{len(controllers)} controllers, "
                f"{sum(1 for a in stats.assets.values() if a.role == 'hmi-scada')} HMI/SCADA clients, "
                f"{sum(1 for a in stats.assets.values() if a.role == 'switch')} switches, "
                f"{sum(1 for a in stats.assets.values() if a.role in ('server', 'erp-server'))} servers."
            ),
            evidence=[
                f"segments: {', '.join(sorted(stats.segments))}",
                f"controllers: {', '.join(sorted(a.ip or a.key for a in controllers)[:10])}",
            ],
            first_ts=stats.first_ts,
            last_ts=stats.last_ts,
            metric={
                "assets": len(stats.assets),
                "segments": len(stats.segments),
                "controllers": len(controllers),
            },
            tags=["inventory"],
        )
    )
    # controllers without identification
    unknown = [a for a in controllers if not a.family and not a.model]
    for a in unknown:
        out.append(
            Finding(
                fid=f"INV-UNIDENTIFIED-{stable_id(a.key)}",
                category="inventory",
                severity="medium",
                title=f"Controller {a.ip or a.key} could not be identified",
                summary=(
                    f"{a.ip or a.key} speaks {', '.join(sorted(a.protocols)[:4])} but no device "
                    "identification was captured. Without model and firmware version it is impossible "
                    "to say whether it is affected by a published advisory."
                ),
                evidence=[
                    f"protocols: {', '.join(sorted(a.protocols))}",
                    f"MAC {a.mac or 'n/a'} ({a.vendor or 'unknown vendor'})",
                    "run 'otscope probe' for a read-only identification request",
                ],
                affected=[a.ip or a.key],
                recommendation=(
                    "Run the read-only active probe (otscope probe --targets <ip>) which asks for the "
                    "Modbus device identification / S7 module ID / EtherNet/IP identity."
                ),
                first_ts=a.first_ts,
                last_ts=a.last_ts,
                tags=["inventory", "identification"],
            )
        )
    # single-homed controllers (no redundancy)
    for a in controllers:
        peers = [p for p in a.peers]
        if len(peers) <= 1 and a.ip:
            out.append(
                Finding(
                    fid=f"INV-NO-REDUNDANCY-{stable_id(a.key)}",
                    category="inventory",
                    severity="low",
                    title=f"Controller {a.ip} has a single communication peer",
                    summary=(
                        f"{a.ip} ({a.family or a.model or 'unidentified'}) talks to only "
                        f"{len(peers)} other host(s). If that is its only network path, one cable or "
                        "one switch port failure stops the line."
                    ),
                    evidence=[f"peers: {', '.join(peers) or 'none'}"],
                    affected=[a.ip],
                    recommendation="Consider MRP/RST redundancy or a second CP interface for line-critical controllers.",
                    first_ts=a.first_ts,
                    last_ts=a.last_ts,
                    tags=["resilience", "inventory"],
                )
            )
    return out


def asset_table(stats: TrafficStats) -> List[Dict[str, object]]:
    rows = []
    for a in sorted(stats.assets.values(), key=lambda a: (a.purdue, a.ip or a.key)):
        rows.append(a.to_dict())
    return rows
