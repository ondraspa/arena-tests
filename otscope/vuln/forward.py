"""Latent and future risk.

A vulnerability scan tells you what is wrong today.  This module covers the two
things the user of an ERP + OT network actually asks about the future:

1. *Which assets will become unfixable?*  Products at end of commercialisation
   will never receive a fix for the next advisory that lands on them.
2. *Which exposures will be exploited by the next advisory?*  Unauthenticated
   protocols, clear-text services and a flat segment mean that when the next
   CVE for that family is published, there is nothing in the way.

It also compares the advisory database against the previous run, so a newly
published advisory that matches an already-inventoried asset is reported as new.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ..analysis.stats import TrafficStats
from ..config import ScanConfig
from ..models import Finding
from ..store import State
from ..util import stable_id
from .db import AdvisoryDB

UNAUTHENTICATED = {
    "modbus": (
        "Modbus TCP has no authentication: any host that can open TCP 502 can read and write "
        "process values, and function code 0x10 (write multiple registers) changes the process. "
        "A future vulnerability in a Modbus device does not even need credentials to be usable."
    ),
    "s7comm": (
        "S7comm on 102/tcp is unauthenticated by default (CPU protection level 1). Any host that "
        "can reach the port can read the whole data block layout, write values, and - with a "
        "STOP command - halt the CPU."
    ),
    "enip": (
        "EtherNet/IP explicit messaging is unauthenticated: RegisterSession is open to anyone and "
        "gives access to tag read/write services."
    ),
}

INSECURE_SERVICES = {
    "Telnet": "clear-text remote shell on the control network",
    "FTP": "clear-text file transfer - and a documented Modicon attack surface (ICSA-18-086-01)",
    "SNMP": "SNMP v1/v2c community strings travel in clear text",
    "HTTP": "clear-text web server, frequently the CPU's embedded web server",
    "VNC": "remote desktop without encryption on a control segment",
    "RDP": "remote desktop exposed on a control segment",
    "SMB": "file sharing exposed to the control segment (WannaCry/NotPetya propagation path)",
    "MSRPC/DCOM (OPC Classic)": "DCOM-based OPC Classic is unencrypted and needs broad port access",
    "rexec": "clear-text remote execution service",
    "rlogin": "clear-text remote login",
    "rsh/syslog": "clear-text remote shell / syslog",
    "TFTP": "trivial file transfer without authentication",
    "NetBIOS session": "NetBIOS session service on a control segment",
}


def analyse(
    stats: TrafficStats,
    cfg: ScanConfig,
    db: Optional[AdvisoryDB] = None,
    state: Optional[State] = None,
    findings: Optional[List[Finding]] = None,
) -> List[Finding]:
    db = db or AdvisoryDB.load()
    findings = findings or []
    out: List[Finding] = []

    out.extend(_eol(stats, db))
    out.extend(_unauthenticated(stats, cfg))
    out.extend(_insecure_services(stats, cfg))
    out.extend(_flat_network(stats, cfg))
    out.extend(_new_advisories(stats, db, state))
    out.extend(_risk_runway(stats, cfg, db, findings))
    return out


# ------------------------------------------------------------------ EOL
def _eol(stats: TrafficStats, db: AdvisoryDB) -> List[Finding]:
    out: List[Finding] = []
    families = sorted({a.family for a in stats.assets.values() if a.family})
    for fam in families:
        lc = db.lifecycle_for(fam)
        if not lc:
            continue
        assets = [a for a in stats.assets.values() if a.family == fam]
        advs = db.for_family(fam)
        today = time.strftime("%Y-%m-%d")
        cancelled = bool(lc.type_cancellation and lc.type_cancellation <= today)
        announced = bool(lc.phase_out_announced and lc.phase_out_announced <= today)
        sev = "high" if cancelled else ("medium" if announced else "low")
        evidence = [
            f"{len(assets)} device(s) of family {fam}: " + ", ".join(sorted((a.ip or a.key) for a in assets)[:8]),
            f"phase-out announcement (PM400): {lc.phase_out_announced or 'n/a'}",
            f"type cancellation (PM410): {lc.type_cancellation or 'n/a'}",
        ]
        if lc.spare_parts_until:
            evidence.append(f"spare parts planned until: {lc.spare_parts_until}")
        evidence.append(f"successor: {lc.successor or 'n/a'}")
        evidence.append(f"source: {lc.source} (checked {lc.checked})")
        if advs:
            evidence.append(f"{len(advs)} published advisories already affect this family: {', '.join(a.id for a in advs)}")
        out.append(
            Finding(
                fid=f"FWD-EOL-{stable_id(fam)}",
                category="forward",
                severity=sev,
                title=f"{fam} is {'discontinued' if cancelled else 'in phase-out'} - future vulnerabilities will not be fixed",
                summary=(
                    f"{lc.vendor} {fam} reached type cancellation on {lc.type_cancellation}."
                    if cancelled
                    else f"{lc.vendor} {fam} is in product phase-out (announced {lc.phase_out_announced})."
                )
                + (
                    " No security fixes are being produced for this family, so every future advisory "
                    "that lands on it becomes a permanent exposure. Migration planning is the only fix."
                ),
                evidence=evidence,
                affected=sorted((a.ip or a.key) for a in assets),
                recommendation=(
                    f"Plan the migration to {lc.successor or 'the current product family'}; in the "
                    "meantime compensate with segmentation: allow 102/502/44818 only from the "
                    "engineering stations and block everything else to these devices."
                ),
                references=[lc.source] if lc.source.startswith("http") else [],
                first_ts=min((a.first_ts for a in assets if a.first_ts), default=stats.first_ts),
                last_ts=max((a.last_ts for a in assets if a.last_ts), default=stats.last_ts),
                metric={"family": fam, "cancelled": cancelled, "devices": len(assets)},
                tags=["lifecycle", "eol"],
            )
        )
    return out


# ------------------------------------------------- unauthenticated protocols
def _unauthenticated(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    for proto, text in UNAUTHENTICATED.items():
        if not stats.protocols.get(proto):
            continue
        servers = sorted(
            {
                f.server
                for f in stats.flows.values()
                if proto in f.protocols and f.server
            }
        )
        clients = sorted({f.client for f in stats.flows.values() if proto in f.protocols and f.client})
        writes = {
            "modbus": len(stats.modbus_writes),
            "s7comm": len(stats.s7_writes),
            "enip": len(stats.enip_writes),
        }[proto]
        out.append(
            Finding(
                fid=f"FWD-NOAUTH-{proto.upper()}",
                category="forward",
                severity="high",
                title=f"{proto.upper()} is unauthenticated by design on {len(servers)} device(s)",
                summary=text,
                evidence=[
                    f"{stats.protocols[proto]} frames decoded",
                    f"devices: {', '.join(servers[:8])}",
                    f"clients: {', '.join(clients[:8])}",
                    f"{writes} write operations observed in this capture",
                ],
                affected=servers,
                recommendation=(
                    "Restrict the port at the segment firewall to the named HMI/engineering stations "
                    "(ACL or industrial firewall with deep packet inspection). Where the device supports "
                    "it, enable the vendor's protection level (S7 protection level 3, CIP Security, "
                    "Modbus/TCP Security) and require a VPN for engineering access."
                ),
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                metric={"protocol": proto, "devices": servers, "writes": writes},
                tags=["hardening", "authentication", proto],
            )
        )
    return out


# ------------------------------------------------------- insecure services
def _insecure_services(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    hits: Dict[str, List[str]] = {}
    ot_ports = {102, 502, 44818, 2222, 4840, 20000}
    confirmed: Dict[str, List[str]] = {}
    for asset in stats.assets.values():
        seg = cfg.subnet_for(asset.ip)
        if seg is not None and seg.role not in ("ot", ""):
            continue
        # recognisably an OT device: speaks an OT protocol, has a PLC family or is
        # the controller of a segment
        is_ot = bool(ot_ports & set(asset.server_ports)) or bool(asset.family) or asset.role == "controller"
        if seg is None and cfg.subnets and not is_ot:
            # profiles exist and this host is not in an OT subnet: an office
            # workstation with SMB is not a plant finding
            continue
        for port, service in asset.server_ports.items():
            if service in INSECURE_SERVICES:
                hits.setdefault(service, []).append(f"{asset.ip}:{port}")
                if is_ot or seg is not None:
                    confirmed.setdefault(service, []).append(f"{asset.ip}:{port}")
    for service, where in sorted(hits.items(), key=lambda kv: -len(kv[1])):
        ot_confirmed = bool(confirmed.get(service))
        out.append(
            Finding(
                fid=f"FWD-INSECURE-{stable_id(service)}",
                category="forward",
                severity=("high" if ot_confirmed else "medium")
                if service in ("Telnet", "FTP", "VNC", "RDP", "SMB")
                else "medium",
                title=(
                    f"{service} exposed on the control segment ({len(where)} endpoint(s))"
                    if ot_confirmed
                    else f"{service} in clear text on the plant network ({len(where)} endpoint(s))"
                ),
                summary=(
                    f"{service} is running"
                    + (" on an OT device" if ot_confirmed else " on a host that could not be attributed to a segment")
                    + f": {INSECURE_SERVICES[service]}."
                ),
                evidence=[", ".join(where[:10])],
                affected=sorted({w.split(":")[0] for w in where}),
                recommendation=(
                    "Disable the service if it is not required; otherwise restrict it to the "
                    "engineering VLAN and tunnel it (SSH instead of Telnet, SFTP instead of FTP)."
                ),
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                metric={"service": service, "endpoints": where[:20], "ot_device": ot_confirmed},
                tags=["hardening", "clear-text"],
            )
        )
    return out


# ------------------------------------------------------------ flat network
def _flat_network(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    ot_segments = [s for s in cfg.subnets if s.role == "ot"]
    if len(cfg.subnets) <= 1 and len(stats.segments) > 1:
        out.append(
            Finding(
                fid="FWD-NO-PROFILE",
                category="forward",
                severity="medium",
                title="No network profile supplied",
                summary=(
                    f"{len(stats.segments)} segments were observed but the profile describes "
                    f"{len(cfg.subnets)}. Without a profile the analyser cannot tell a segmentation "
                    "violation from normal traffic, and cannot map hosts to Purdue levels."
                ),
                evidence=[f"observed segments: {', '.join(sorted(stats.segments))}"],
                recommendation="Write a profile with 'otscope profile init' and fill in the CIDR blocks, roles and Purdue levels.",
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                tags=["configuration"],
            )
        )
    controllers = [a for a in stats.assets.values() if a.role == "controller"]
    if controllers and not ot_segments and len({a.segment for a in controllers}) == 1:
        out.append(
            Finding(
                fid="FWD-FLAT",
                category="forward",
                severity="medium",
                title="All controllers share one segment",
                summary=(
                    f"{len(controllers)} controllers sit in the same broadcast domain "
                    f"({sorted({a.segment for a in controllers})}). One broadcast storm or one "
                    "compromised host affects every line at once."
                ),
                evidence=[f"controllers: {', '.join(sorted((a.ip or a.key) for a in controllers)[:10])}"],
                recommendation="Put each production line on its own VLAN with a firewall (or at least an ACL) between them.",
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                tags=["segmentation"],
            )
        )
    return out


# ------------------------------------------------------ new advisory watch
def _new_advisories(stats: TrafficStats, db: AdvisoryDB, state: Optional[State]) -> List[Finding]:
    if state is None:
        return []
    records = [a.to_dict() for a in db.advisories]
    fresh = state.new_advisories(records)
    state.record_advisories(records)
    if not fresh:
        return []
    families = {a.family for a in stats.assets.values() if a.family}
    relevant = [a for a in fresh if set(a.get("families", [])) & families]
    if not relevant:
        return [
            Finding(
                fid="FWD-WATCH",
                category="forward",
                severity="info",
                title=f"{len(fresh)} advisory record(s) new or updated since the last run",
                summary=(
                    f"None of them affect an inventoried product family ({', '.join(sorted(families)) or 'none identified'})."
                ),
                evidence=[f"new/updated: {', '.join(a['id'] for a in fresh[:10])}"],
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                tags=["watch"],
            )
        ]
    out = []
    for a in relevant:
        affected_assets = sorted(
            {
                (x.ip or x.key)
                for x in stats.assets.values()
                if x.family and x.family in a.get("families", [])
            }
        )
        out.append(
            Finding(
                fid=f"FWD-NEW-ADV-{stable_id(a['id'])}",
                category="forward",
                severity="critical" if (a.get("cvss") or 0) >= 9 else ("high" if (a.get("cvss") or 0) >= 7 else "medium"),
                title=f"New advisory {a['id']} affects {len(affected_assets)} device(s) you already run",
                summary=(
                    f"{a.get('vendor')} {a.get('product')}: {a.get('title')}. This record is new or was "
                    "updated since the previous run, and it matches hardware that is already in the "
                    "asset inventory - i.e. this is a vulnerability that arrived after the devices were "
                    "installed."
                ),
                evidence=[
                    f"CVSS v{a.get('cvss_version')} {a.get('cvss')}",
                    f"affected families: {', '.join(a.get('families', []))}",
                    f"matching assets: {', '.join(affected_assets[:8])}",
                    f"source: {a.get('source')}",
                ],
                affected=affected_assets,
                recommendation=a.get("remediation", ""),
                references=[a.get("source")] if a.get("source") else [],
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                metric={"advisory": a["id"]},
                tags=["watch", "new-advisory"],
            )
        )
    return out


# ------------------------------------------------------------- risk runway
def _risk_runway(stats: TrafficStats, cfg: ScanConfig, db: AdvisoryDB, findings: List[Finding]) -> List[Finding]:
    per_asset: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        for a in f.affected:
            d = per_asset.setdefault(a, {"score": 0, "drivers": []})
            if f.category == "vuln":
                weight = {"critical": 30, "high": 20, "medium": 10, "low": 5}.get(f.severity, 0)
                if f.metric.get("confidence") in ("confirmed", "likely"):
                    d["score"] += weight
                    d["drivers"].append(f"{f.metric.get('advisory')} ({f.severity})")
    out: List[Finding] = []
    for asset in stats.assets.values():
        key = asset.ip or asset.key
        d = per_asset.setdefault(key, {"score": 0, "drivers": []})
        base = {"controller": 25, "io-adapter": 20, "hmi-scada": 15, "switch": 10, "server": 10, "erp-server": 10}.get(asset.role, 5)
        d["score"] += base
        d["drivers"].append(f"role={asset.role}")
        if db.lifecycle_for(asset.family):
            d["score"] += 20
            d["drivers"].append("product discontinued/phase-out")
        if asset.role == "controller" and any(p in asset.server_ports for p in (102, 502, 44818)):
            d["score"] += 15
            d["drivers"].append("unauthenticated control protocol reachable")
        insecure = [s for s in asset.server_ports.values() if s in INSECURE_SERVICES]
        if insecure:
            d["score"] += 10
            d["drivers"].append(f"insecure services: {', '.join(sorted(set(insecure)))}")
        if len(asset.server_ports) > 5:
            d["score"] += 5
            d["drivers"].append(f"{len(asset.server_ports)} listening services")
        d["score"] = min(100, d["score"])
        d["asset"] = key
        d["role"] = asset.role
        d["family"] = asset.family
    ranked = sorted(per_asset.values(), key=lambda d: -d["score"])[:15]
    if not ranked:
        return out
    rows = "; ".join(f"{d['asset']} {d['score']} ({d['role']})" for d in ranked[:8])
    out.append(
        Finding(
            fid="FWD-RISK-RUNWAY",
            category="forward",
            severity="high" if ranked[0]["score"] >= 70 else "medium",
            title=f"Risk runway: {ranked[0]['asset']} scores {ranked[0]['score']}/100",
            summary=(
                "Composite forward-looking risk: role criticality + published advisories + product "
                "lifecycle + unauthenticated/insecure exposure. The score is a triage order, not a "
                "prediction - it says where the next published advisory would hurt most."
            ),
            evidence=[f"top assets: {rows}"]
            + [f"{d['asset']}: {', '.join(d['drivers'])}" for d in ranked[:6]],
            affected=[d["asset"] for d in ranked[:5]],
            recommendation="Work down this list: segment first, then patch/replace, then harden.",
            first_ts=stats.first_ts,
            last_ts=stats.last_ts,
            metric={"ranked": ranked},
            tags=["risk", "triage"],
        )
    )
    return out
