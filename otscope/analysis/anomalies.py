"""Anomaly / suspicious activity detection.

Focused on the things that actually endanger an OT segment: somebody writing to
a PLC who should not be, host discovery against the controllers, ARP spoofing,
traffic that crosses the ERP/OT boundary directly, and protocol confusion.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from ..config import ScanConfig
from ..models import Finding
from ..util import stable_id
from .stats import TrafficStats

OT_PORTS = {102, 502, 44818, 2222, 4840, 20000, 47808}
CONTROL_PORTS = {102, 502, 44818}


def analyse(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    out.extend(_unauthorised_writes(stats, cfg))
    out.extend(_scans(stats, cfg))
    out.extend(_beaconing(stats, cfg))
    out.extend(_arp_issues(stats, cfg))
    out.extend(_segmentation(stats, cfg))
    out.extend(_protocol_confusion(stats, cfg))
    out.extend(_new_assets(stats, cfg))
    out.extend(_icmp_anomalies(stats, cfg))
    return out


# ------------------------------------------------------------------ writes
def _unauthorised_writes(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    writes: List[Tuple[float, str, str, str, str]] = []
    for ts, src, dst, items in stats.s7_writes:
        desc = ", ".join(
            f"{it.get('area_name', '?')} DB{it.get('db', 0)}.{it.get('address', 0)}" for it in items[:4]
        )
        writes.append((ts, src, dst, "S7 Write Var", desc))
    for ts, src, dst, fn in stats.modbus_writes:
        writes.append((ts, src, dst, f"Modbus {fn}", ""))
    for ts, src, dst, fn in stats.enip_writes:
        writes.append((ts, src, dst, f"CIP {fn}", ""))
    # NB: no early return here - the DCP/S7-password checks below must run even
    # when nothing was written to a PLC.
    by_pair: Dict[Tuple[str, str], List[Tuple[float, str, str]]] = defaultdict(list)
    for ts, src, dst, kind, desc in writes:
        by_pair[(src, dst)].append((ts, kind, desc))
    for (src, dst), evs in sorted(by_pair.items(), key=lambda kv: -len(kv[1])):
        allowed = cfg.is_engineer(src) or src in cfg.known_plcs
        kinds = sorted({k for _t, k, _d in evs})
        sev = "info" if allowed else "critical"
        out.append(
            Finding(
                fid=f"ANOM-WRITE-PLC-{stable_id(src, dst)}",
                category="anomaly",
                severity=sev,
                title=("Authorised" if allowed else "UNAUTHORISED") + f" write to controller {dst} from {src}",
                summary=(
                    f"{src} performed {len(evs)} write operations against {dst} ({', '.join(kinds)}). "
                    + (
                        "This host is in the configured engineering-station list."
                        if allowed
                        else "This host is NOT in the configured list of engineering stations, so either "
                        "the configuration is incomplete or something is changing process values."
                    )
                ),
                evidence=[
                    f"{len(evs)} writes between {time.strftime('%H:%M:%S', time.localtime(evs[0][0]))} and {time.strftime('%H:%M:%S', time.localtime(evs[-1][0]))}",
                    f"operations: {', '.join(kinds)}",
                    f"example: {evs[0][2]}" if evs[0][2] else f"first write at {time.strftime('%H:%M:%S', time.localtime(evs[0][0]))}",
                ],
                affected=[dst, src],
                recommendation=(
                    "Add the host to the profile if it is legitimate. Otherwise block it at the "
                    "segment firewall and review the PLC audit log."
                    if not allowed
                    else "Consider requiring the write to be logged by the SCADA so plant changes are traceable."
                ),
                first_ts=evs[0][0],
                last_ts=evs[-1][0],
                count=len(evs),
                tags=["write", "ot", "authorised" if allowed else "unauthorised"],
            )
        )
    # DCP set / factory reset
    for ev in stats.events_prefix("dcp-set"):
        out.append(
            Finding(
                fid=f"ANOM-DCP-SET-{stable_id(ev.src, ev.ts)}",
                category="anomaly",
                severity="high",
                title="PROFINET DCP Set on the wire",
                summary=(
                    f"{ev.src} sent a PROFINET DCP Set ({ev.detail}). DCP Set renames or re-addresses "
                    "devices; a factory-reset DCP takes a whole machine off the ring."
                ),
                evidence=[f"{time.strftime('%H:%M:%S', time.localtime(ev.ts))} {ev.src}: {ev.detail}"],
                affected=[ev.src],
                recommendation="Only engineering stations should send DCP Set. Filter 0x8892 at the segment boundary.",
                first_ts=ev.ts,
                last_ts=ev.ts,
                tags=["profinet", "configuration-change"],
            )
        )
    for ev in stats.events_prefix("s7-password"):
        out.append(
            Finding(
                fid=f"ANOM-S7-PASSWORD-{stable_id(ev.src, ev.ts)}",
                category="anomaly",
                severity="high",
                title="S7 password function requested",
                summary=f"{ev.src} attempted an S7 password operation against {ev.dst}.",
                evidence=[f"{time.strftime('%H:%M:%S', time.localtime(ev.ts))} {ev.src} -> {ev.dst}"],
                affected=[ev.dst],
                recommendation="Set protection level 3 on the CPU and restrict 102/tcp to known engineering stations.",
                first_ts=ev.ts,
                last_ts=ev.ts,
                tags=["s7comm", "access-control"],
            )
        )
    return out


# ------------------------------------------------------------------- scans
def _scans(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    th = cfg.thresholds
    out: List[Finding] = []
    for src, targets in stats.conn_attempts.items():
        if len(targets) < th.scan_port_threshold:
            continue
        ports = {p for _h, p in targets}
        hosts = {h for h, _p in targets}
        ot_targets = sorted({h for h, p in targets if p in OT_PORTS})
        times = list(targets.values())
        window = (max(times) - min(times)) if len(times) > 1 else 1.0
        seq_ports = len(ports) >= th.scan_port_threshold and max(ports) - min(ports) <= len(ports) * 3
        sev = "high"
        if ot_targets:
            sev = "critical"
        out.append(
            Finding(
                fid=f"ANOM-SCAN-{stable_id(src)}",
                category="anomaly",
                severity=sev,
                title=f"Port/host discovery from {src}: {len(ports)} ports across {len(hosts)} hosts",
                summary=(
                    f"{src} opened connections to {len(ports)} distinct ports on {len(hosts)} hosts "
                    f"in {window:.0f}s"
                    + (f", including controller ports on {', '.join(ot_targets)}" if ot_targets else "")
                    + ("." if not seq_ports else " - a sequential sweep.")
                    + " On a plant network nothing discovers like this except a scanner or a compromised host."
                ),
                evidence=[
                    f"ports: {', '.join(str(p) for p in sorted(ports)[:20])}{'...' if len(ports) > 20 else ''}",
                    f"hosts: {', '.join(sorted(hosts)[:10])}{'...' if len(hosts) > 10 else ''}",
                    f"controller ports touched: {', '.join(ot_targets) if ot_targets else 'none'}",
                ],
                affected=sorted(hosts),
                recommendation=(
                    "Identify the host. If it is a vulnerability scanner, schedule it and restrict it "
                    "to safe read-only checks - active scanning of PLCs is a known way to stop a CPU."
                ),
                first_ts=min(times),
                last_ts=max(times),
                count=len(targets),
                metric={"ports": len(ports), "hosts": len(hosts), "ot_targets": ot_targets},
                tags=["scan", "reconnaissance"],
            )
        )
    # ARP sweeps
    arp_sweep = defaultdict(set)
    for (mac, target, op), times in stats.arp_requests.items():
        if len(times) > 5:
            arp_sweep[mac].add(target)
    for mac, targets in arp_sweep.items():
        if len(targets) < 20:
            continue
        out.append(
            Finding(
                fid=f"ANOM-ARP-SWEEP-{stable_id(mac)}",
                category="anomaly",
                severity="medium",
                title=f"ARP sweep from {mac} covering {len(targets)} addresses",
                summary=(
                    f"{mac} asked for {len(targets)} different IP addresses. Host discovery on the "
                    "plant VLAN, or an IP conflict storm."
                ),
                evidence=[f"{len(targets)} distinct targets", f"example targets: {', '.join(sorted(targets)[:8])}"],
                recommendation="Enable DHCP snooping and dynamic ARP inspection on the access switches.",
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                count=len(targets),
                tags=["scan", "arp"],
            )
        )
    return out


# --------------------------------------------------------------- beaconing
def _beaconing(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    th = cfg.thresholds
    out: List[Finding] = []
    for key, times in stats.beacon_ts.items():
        if len(times) < th.beacon_min_count:
            continue
        gaps = [times[i] - times[i - 1] for i in range(1, len(times))]
        if not gaps:
            continue
        mean = sum(gaps) / len(gaps)
        if mean <= 0:
            continue
        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        sd = var ** 0.5
        cv = sd / mean
        if cv > th.beacon_cv_max or mean < 0.5 or mean > 3600:
            continue
        src, dst, port = key
        if port in OT_PORTS:
            continue  # cyclic control traffic is expected to be periodic
        out.append(
            Finding(
                fid=f"ANOM-BEACON-{stable_id(*key)}",
                category="anomaly",
                severity="medium",
                title=f"Beaconing pattern {src} -> {dst}:{port} every {mean:.1f}s",
                summary=(
                    f"{len(times)} connections at a fixed {mean:.1f}s interval (jitter {cv * 100:.1f}%). "
                    "Machine-precise periodicity to a non-control port is how implants, telemetry "
                    "agents and data exfiltration look on a plant network."
                ),
                evidence=[f"{len(times)} events, interval {mean:.2f}s +/- {sd:.2f}s"],
                affected=[src, dst],
                recommendation="Identify the process on the source host; if it is not a sanctioned monitoring agent, investigate.",
                first_ts=times[0],
                last_ts=times[-1],
                count=len(times),
                metric={"interval_s": round(mean, 2), "cv": round(cv, 3)},
                tags=["beaconing"],
            )
        )
    return out


# --------------------------------------------------------------------- ARP
def _arp_issues(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    for ip_, macs in stats.ip_macs.items():
        if len(macs) < 2:
            continue
        if not ip_ or ip_.endswith((".0", ".255")) or ip_ == "255.255.255.255":
            continue
        detail = ", ".join(f"{m} ({len(ts)} frames, last {time.strftime('%H:%M:%S', time.localtime(ts[-1]))})" for m, ts in sorted(macs.items(), key=lambda kv: -len(kv[1])))
        asset = stats.assets.get(ip_)
        critical = bool(asset and asset.purdue in ("0-2", "1-2", "2", "1", "0", "2-3"))
        out.append(
            Finding(
                fid=f"ANOM-IP-CONFLICT-{stable_id(ip_)}",
                category="anomaly",
                severity="critical" if critical else "high",
                title=f"IP {ip_} seen with {len(macs)} MAC addresses",
                summary=(
                    f"{ip_} is claimed by more than one hardware address: {detail}. "
                    "This is either a duplicate IP - which by itself makes a PLC unreachable - or ARP "
                    "spoofing."
                ),
                evidence=[f"{detail}"],
                affected=[ip_],
                recommendation=(
                    "Check the switch MAC table for the port of each address. If both are live, it is a "
                    "conflict; if the MAC keeps changing rapidly, it is spoofing - enable DAI."
                ),
                first_ts=min(ts[0] for ts in macs.values()),
                last_ts=max(ts[-1] for ts in macs.values()),
                metric={"macs": len(macs)},
                tags=["arp", "conflict"],
            )
        )
    for mac, ips in stats.mac_ips.items():
        if len(ips) < 10:
            continue
        out.append(
            Finding(
                fid=f"ANOM-MAC-MANY-IP-{stable_id(mac)}",
                category="anomaly",
                severity="medium",
                title=f"{mac} appears with {len(ips)} source IP addresses",
                summary=(
                    f"One hardware address is the source of {len(ips)} different IP addresses. Normal "
                    "for a router or a virtualisation host, suspicious for a workstation on a plant VLAN."
                ),
                evidence=[f"IPs: {', '.join(sorted(ips)[:10])}"],
                recommendation="Confirm the host's role; a virtualisation host on a control VLAN should be segmented.",
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                metric={"ips": len(ips)},
                tags=["arp", "virtualisation"],
            )
        )
    return out


# ------------------------------------------------------------ segmentation
def _segmentation(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    crossings: Dict[Tuple[str, str, Optional[int]], int] = defaultdict(int)
    for key, flow in stats.flows.items():
        client, cport, server, sport, proto = key
        if not client or not server:
            continue
        if sport not in CONTROL_PORTS:
            continue
        seg_c = cfg.subnet_for(client)
        seg_s = cfg.subnet_for(server)
        if seg_c is None or seg_s is None:
            continue
        if seg_c.cidr == seg_s.cidr:
            continue
        purdue_c = seg_c.purdue
        purdue_s = seg_s.purdue
        erp_like = purdue_c in ("4", "5", "4-5", "3-4") or (cfg.subnet_for(client) and cfg.subnet_for(client).role == "erp")
        ot_like = purdue_s in ("0", "1", "2", "0-2", "1-2", "2-3") or (seg_s.role == "ot")
        if erp_like and ot_like:
            crossings[(client, server, sport)] += flow.packets
    for (client, server, sport), n in sorted(crossings.items(), key=lambda kv: -kv[1]):
        port_name = {102: "S7comm", 502: "Modbus TCP", 44818: "EtherNet/IP"}.get(sport or 0, str(sport))
        out.append(
            Finding(
                fid=f"ANOM-SEGMENTATION-{stable_id(client, server, sport)}",
                category="anomaly",
                severity="critical",
                title=f"Business host {client} talks {port_name} directly to controller {server}",
                summary=(
                    f"{client} ({cfg.purdue_for_ip(client)}) exchanged {n} packets with {server} "
                    f"({cfg.purdue_for_ip(server)}) on {sport}/tcp. A business/ERP host should never "
                    "reach a controller port directly - that is exactly the path an attacker moves "
                    "along after compromising the ERP."
                ),
                evidence=[f"{n} packets {client} -> {server}:{sport}", f"source level {cfg.purdue_for_ip(client)}, target level {cfg.purdue_for_ip(server)}"],
                affected=[client, server],
                recommendation=(
                    "Move the data exchange to a historian/OPC UA server in the DMZ and add a firewall "
                    "rule that blocks 102/502/44818 from the business VLAN to the control VLAN."
                ),
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                count=n,
                tags=["segmentation", "purdue", "firewall"],
            )
        )
    if not crossings and cfg.subnets:
        erp = [s for s in cfg.subnets if s.role == "erp"]
        ot = [s for s in cfg.subnets if s.role == "ot"]
        if erp and ot:
            out.append(
                Finding(
                    fid="ANOM-SEGMENTATION-OK",
                    category="anomaly",
                    severity="info",
                    title="No direct ERP-to-controller sessions observed",
                    summary=(
                        f"No controller-port traffic (102/502/44818) crossed from the business segments "
                        f"({', '.join(s.cidr for s in erp)}) to the control segments "
                        f"({', '.join(s.cidr for s in ot)})."
                    ),
                    first_ts=stats.first_ts,
                    last_ts=stats.last_ts,
                    tags=["segmentation"],
                )
            )
    return out


# -------------------------------------------------------- protocol confusion
def _protocol_confusion(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    for ip_, asset in stats.assets.items():
        if not ip_:
            continue
        prof = cfg.subnet_for(ip_)
        if not prof or not prof.allow_protocols:
            continue
        allowed = set(prof.allow_protocols)
        seen = {p for p in asset.protocols if p not in ("service", "other", "arp", "icmp")}
        extra = sorted(seen - allowed - {"cotp", "lldp", "stp", "mrp", "profinet-dcp"})
        if not extra:
            continue
        out.append(
            Finding(
                fid=f"ANOM-PROTO-{stable_id(ip_)}",
                category="anomaly",
                severity="medium",
                title=f"{ip_} speaks protocols not allowed on {prof.label or prof.cidr}",
                summary=(
                    f"{ip_} used {', '.join(extra)} but the profile for {prof.cidr} only allows "
                    f"{', '.join(allowed)}. Either the profile is out of date or a new service has "
                    "appeared on the segment."
                ),
                evidence=[f"observed: {', '.join(sorted(seen))}", f"allowed: {', '.join(sorted(allowed))}"],
                affected=[ip_],
                recommendation="Confirm the service; if it is new, add it to the profile or block it at the segment firewall.",
                first_ts=asset.first_ts,
                last_ts=asset.last_ts,
                tags=["profile", "protocol"],
            )
        )
    # control protocol on a non-standard port.  The assigned ports are per
    # protocol: EtherNet/IP uses 44818/tcp for explicit messaging and 2222/udp
    # for implicit (class 0/1) messaging, so 2222 is standard, not suspicious.
    standard_ports = {"s7comm": {102}, "cotp": {102}, "modbus": {502}, "enip": {44818, 2222}}
    for key, flow in stats.flows.items():
        _c, _cp, server, sport, _proto = key
        for p in flow.protocols:
            if p not in standard_ports or sport in standard_ports[p]:
                continue
            out.append(
                Finding(
                    fid=f"ANOM-PORT-{stable_id(*key)}",
                    category="anomaly",
                    severity="medium",
                    title=f"{p.upper()} traffic on non-standard port {sport}",
                    summary=(
                        f"{p.upper()} protocol frames were seen on port {sport} instead of its "
                        f"assigned port ({', '.join(str(x) for x in sorted(standard_ports[p]))}). "
                        "Port confusion usually means a protocol converter, a deliberately hidden "
                        "service, or a misconfigured gateway."
                    ),
                    evidence=[f"flow {flow.client}:{flow.cport} -> {server}:{sport}"],
                    affected=[server],
                    recommendation="Identify the device and confirm the port mapping; document it or shut it down.",
                    first_ts=flow.first_ts,
                    last_ts=flow.last_ts,
                    tags=["protocol", "port"],
                )
            )
    return out


# ------------------------------------------------------------- new devices
def _new_assets(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    for key, a in stats.assets.items():
        if not a.ip or not a.mac:
            continue
        if a.vendor and ("VirtualBox" in a.vendor or "VMware" in a.vendor or "QEMU" in a.vendor or "Hyper-V" in a.vendor):
            seg = cfg.subnet_for(a.ip)
            if seg and seg.role == "ot":
                out.append(
                    Finding(
                        fid=f"ANOM-VM-OT-{stable_id(a.ip)}",
                        category="anomaly",
                        severity="high",
                        title=f"Virtual machine on the control segment: {a.ip}",
                        summary=(
                            f"{a.ip} ({a.mac}) has the OUI of {a.vendor} and sits in "
                            f"{seg.label or seg.cidr} ({seg.purdue}). VMs are frequently migrated and "
                            "cloned, which breaks MAC/port bindings and loop protection assumptions."
                        ),
                        evidence=[f"MAC {a.mac} -> {a.vendor}", f"segment {seg.cidr} level {seg.purdue}"],
                        affected=[a.ip],
                        recommendation="Document the VM's purpose and pin it, or move it off the control VLAN.",
                        first_ts=a.first_ts,
                        last_ts=a.last_ts,
                        tags=["virtualisation", "segmentation"],
                    )
                )
        # "new" = absent for the first part of the observation window. 20% with
        # a 30 s floor: on a long capture a host that is silent for a fifth of
        # the window was not part of the baseline, and on a short one 30 s of
        # silence is still enough to call it a late arrival.
        first_seen_after = max(stats.duration() * cfg.thresholds.new_asset_after_ratio, 30.0)
        if a.first_ts and stats.first_ts and a.first_ts - stats.first_ts > first_seen_after:
            out.append(
                Finding(
                    fid=f"ANOM-NEW-ASSET-{stable_id(a.ip)}",
                    category="anomaly",
                    severity="medium",
                    title=f"Device appeared mid-capture: {a.ip}",
                    summary=(
                        f"{a.ip} ({a.mac or 'no MAC'}) first appeared "
                        f"{a.first_ts - stats.first_ts:.0f}s after the capture started, using "
                        f"{', '.join(sorted(a.protocols)[:5])}."
                    ),
                    evidence=[f"first seen {time.strftime('%H:%M:%S', time.localtime(a.first_ts))}", f"MAC {a.mac or 'n/a'}"],
                    affected=[a.ip],
                    recommendation="Confirm what was plugged in; unplanned devices on a plant segment should be quarantined until identified.",
                    first_ts=a.first_ts,
                    last_ts=a.last_ts,
                    tags=["inventory", "new-device"],
                )
            )
    return out


# -------------------------------------------------------------------- ICMP
def _icmp_anomalies(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    for (itype, icode), n in sorted(stats.icmp_types.items(), key=lambda kv: -kv[1]):
        if itype == 5 and n >= 5:
            out.append(
                Finding(
                    fid=f"ANOM-ICMP-REDIRECT-{stable_id(itype, icode)}",
                    category="anomaly",
                    severity="high",
                    title=f"{n} ICMP redirect messages",
                    summary=(
                        f"{n} ICMP redirects captured. Routers send these when a host uses the wrong "
                        "next hop - and attackers send them to hijack routing on a flat network."
                    ),
                    evidence=[f"ICMP type {itype} code {icode}: {n} messages"],
                    recommendation="Disable ICMP redirects on the plant routers unless you know why they are there.",
                    first_ts=stats.first_ts,
                    last_ts=stats.last_ts,
                    count=n,
                    tags=["routing"],
                )
            )
        if itype == 3 and icode in (1, 3) and n >= 10:
            out.append(
                Finding(
                    fid=f"ANOM-ICMP-UNREACH-{stable_id(itype, icode)}",
                    category="anomaly",
                    severity="medium",
                    title=f"{n} ICMP unreachable messages (code {icode})",
                    summary=(
                        f"{n} 'host/port unreachable' responses. Something is being addressed that is "
                        "not there - a decommissioned device still in a driver configuration, or a scan."
                    ),
                    evidence=[f"ICMP type {itype} code {icode}: {n} messages"],
                    recommendation="Find the sender and correct its configuration.",
                    first_ts=stats.first_ts,
                    last_ts=stats.last_ts,
                    count=n,
                    tags=["routing", "configuration"],
                )
            )
    return out
