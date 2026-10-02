"""Industrial protocol fault / device-crash analysis.

This is the module that answers "why did the PLC drop out?".  It looks for the
signatures a controller leaves when it is being faulted rather than merely busy:
S7 error PDUs, Modbus exception storms, CIP status errors, malformed frames that
are known to crash specific stacks, connection churn and sudden silence - and
then correlates those timestamps with the layer-2 events from the loop analyser.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Sequence, Tuple

from ..config import ScanConfig
from ..models import Finding
from ..util import human_ms, stable_id
from .stats import Event, TrafficStats

OT_PORTS = {102, 502, 44818, 2222, 4840, 20000}

MALFORMED_KINDS = (
    "cotp-malformed",
    "cotp-li-mismatch",
    "cotp-bad-tpdu-size",
    "cotp-param-overflow",
    "cotp-truncated",
    "cotp-unknown-pdu",
    "s7-malformed",
    "s7-short",
    "s7-param-truncated",
    "s7-data-truncated",
    "s7-item-mismatch",
    "s7-bad-rosctr",
    "s7-pdu-too-big",
    "s7-amq-excess",
    "modbus-malformed",
    "modbus-length-mismatch",
    "modbus-bad-protocol-id",
    "modbus-unknown-function",
    "enip-length-mismatch",
    "enip-cpf-truncated",
    "enip-bad-version",
)


def analyse(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    th = cfg.thresholds
    out: List[Finding] = []

    # ------------------------------------------------------------ S7 errors
    out.extend(_grouped_faults(
        stats,
        cfg,
        kinds=("s7-error",),
        fid="CRASH-S7-FAULT",
        title_tpl="S7 communication faults from {device}",
        summary_tpl=(
            "The controller answered {count} S7 requests with an error PDU ({codes}). "
            "S7 errors of this shape are how an S7 CPU reports that it cannot service the "
            "request - protected area, missing object, no free resources - and a burst of them "
            "is what an operator sees as 'the PLC is dropping out'."
        ),
        attr_key="err_class",
        attr_label="error class",
        device_is="src",
        protocol="s7comm",
    ))

    # ------------------------------------------------------- Modbus exceptions
    out.extend(_grouped_faults(
        stats,
        cfg,
        kinds=("modbus-exception",),
        fid="CRASH-MODBUS-EXCEPTION",
        title_tpl="Modbus exception storm from {device}",
        summary_tpl=(
            "The Modbus server returned {count} exception responses ({codes}). Codes 02/03 mean "
            "the client is asking for something the server rejects; 04/08/0B mean the device "
            "itself failed, and a stream of those is the fingerprint of a controller that is "
            "crashing or of a serial gateway that has lost its downstream link."
        ),
        attr_key="exception_code",
        attr_label="exception",
        device_is="src",
        protocol="modbus",
    ))

    # ------------------------------------------------------------- CIP errors
    out.extend(_grouped_faults(
        stats,
        cfg,
        kinds=("cip-error",),
        fid="CRASH-CIP-FAULT",
        title_tpl="EtherNet/IP CIP errors from {device}",
        summary_tpl=(
            "{count} CIP responses carried a non-zero general status ({codes}). "
            "0x07 'connection lost' means the RPI/timeout budget was missed, 0x02 'resource "
            "unavailable' means the controller ran out of connections - both are capacity faults, "
            "not cabling faults."
        ),
        attr_key="cip_status",
        attr_label="CIP status",
        device_is="src",
        protocol="enip",
    ))

    out.extend(_grouped_faults(
        stats,
        cfg,
        kinds=("enip-error",),
        fid="CRASH-ENIP-ENCAP",
        title_tpl="EtherNet/IP encapsulation errors from {device}",
        summary_tpl=(
            "{count} EtherNet/IP encapsulation errors ({codes}). The adapter is rejecting the "
            "session or the command itself, which stops the SCADA tag subscription before any "
            "CIP data is exchanged."
        ),
        attr_key="status",
        attr_label="encap status",
        device_is="src",
        protocol="enip",
    ))

    # ------------------------------------------------- malformed / crash vectors
    malformed = [e for e in stats.events if e.kind in MALFORMED_KINDS]
    if malformed:
        by_kind: Dict[str, List[Event]] = defaultdict(list)
        for e in malformed:
            by_kind[e.kind].append(e)
        worst = sorted(by_kind.items(), key=lambda kv: -len(kv[1]))
        lines = [f"{k}: {len(v)} frames" for k, v in worst[:8]]
        targets = sorted({e.dst for e in malformed if e.dst})
        sources = sorted({e.src for e in malformed if e.src})
        out.append(
            Finding(
                fid="CRASH-MALFORMED-PROTOCOL-FRAMES",
                category="crash",
                severity="critical" if len(malformed) >= 20 else "high",
                title=f"{len(malformed)} malformed industrial protocol frames",
                summary=(
                    "Frames on 102/502/44818 that violate the protocol's own length or parameter "
                    "rules. Malformed frames are the mechanism behind most documented PLC denial-of-"
                    "service advisories - a stack that trusts the length field overruns its buffer. "
                    "They also indicate a buggy driver, a protocol converter or a scanning tool."
                ),
                evidence=lines + [f"affected devices: {', '.join(targets[:8])}", f"senders: {', '.join(sources[:8])}"]
                + [f"example: frame {malformed[0].idx}: {malformed[0].detail}"],
                affected=targets,
                recommendation=(
                    "Identify the sender and the tool it is running. If it is an HMI/driver, update "
                    "it; if it is unknown, treat it as hostile traffic towards the controllers."
                ),
                first_ts=malformed[0].ts,
                last_ts=malformed[-1].ts,
                count=len(malformed),
                metric={"by_kind": {k: len(v) for k, v in worst}},
                tags=["protocol-fault", "dos-vector"],
            )
        )

    # ------------------------------------------------------- control commands
    if stats.control_commands:
        for ts, src, dst, detail in stats.control_commands:
            out.append(
                Finding(
                    fid=f"CRASH-CONTROL-COMMAND-{stable_id(src, dst, ts)}",
                    category="crash",
                    severity="critical",
                    title=f"PLC control command: {detail}",
                    summary=(
                        f"{src} sent {dst} a controller control command ({detail}). On an S7 CPU this "
                        "changes the operating mode or the program - production stops."
                    ),
                    evidence=[f"{time.strftime('%H:%M:%S', time.localtime(ts))} {src} -> {dst}: {detail}"],
                    affected=[dst, src],
                    recommendation="Verify this was a planned maintenance action; otherwise treat it as an incident and revoke access.",
                    first_ts=ts,
                    last_ts=ts,
                    tags=["safety", "control-command"],
                )
            )

    # ------------------------------------------------- connection churn / restarts
    out.extend(_s7_session_churn(stats, cfg))

    # -------------------------------------------------------------- TCP RSTs
    rst_flows = [(f, f.rst_count) for f in stats.flows.values() if f.rst_count >= 10 and f.sport in OT_PORTS]
    for f, n in sorted(rst_flows, key=lambda kv: -kv[1])[:4]:
        out.append(
            Finding(
                fid=f"CRASH-RST-STORM-{stable_id(f.server)}",
                category="crash",
                severity="high",
                title=f"{f.server}:{f.sport} reset {n} connections",
                summary=(
                    f"{n} TCP RSTs on the controller port. A device that resets sessions it just "
                    "accepted has usually run out of connection resources or has restarted its "
                    "communication stack."
                ),
                evidence=[f"{n} RSTs in {human_ms(f.duration())} between {f.client} and {f.server}:{f.sport}"],
                affected=[f.server],
                recommendation="Reduce the number of concurrent connections from HMI/SCADA to the controller, or check the CPU's connection resource table.",
                first_ts=f.first_ts,
                last_ts=f.last_ts,
                count=n,
                tags=["tcp", "resource-exhaustion"],
            )
        )

    # ---------------------------------------------------------------- silence
    for (client, server, port, proto), times in stats.polls.items():
        if len(times) < 5 or not times:
            continue
        if port not in OT_PORTS:
            continue  # silence on an HTTP endpoint is a performance issue, not a crash
        gaps = [(times[i] - times[i - 1], times[i - 1]) for i in range(1, len(times))]
        big = [(g, t) for g, t in gaps if g >= th.silence_warn_s]
        if not big:
            continue
        worst_gap, at = max(big)
        out.append(
            Finding(
                fid=f"CRASH-SILENCE-{stable_id(client, server, port)}",
                category="crash",
                severity="critical" if worst_gap >= th.silence_warn_s * 4 else "high",
                title=f"Communication with {server}:{port} went silent for {human_ms(worst_gap)}",
                summary=(
                    f"{client} polls {server}:{port} continuously but there is a {human_ms(worst_gap)} "
                    "gap with no traffic at all. Either the device stopped responding, lost power, "
                    "rebooted, or the switch path went down."
                ),
                evidence=[
                    f"gap of {human_ms(worst_gap)} starting {time.strftime('%H:%M:%S', time.localtime(at))}",
                    f"{len(big)} such gaps in the capture",
                ],
                affected=[server, client],
                recommendation="Check the device's run LED and the switch port state at that timestamp; correlate with the loop and fault findings below.",
                first_ts=at,
                last_ts=at + worst_gap,
                count=len(big),
                metric={"worst_gap_s": round(worst_gap, 2)},
                tags=["availability", "ot"],
            )
        )

    # ------------------------------------------------- SNMP flood (CVE pattern)
    snmp_to_plcs = [e for e in stats.events if e.kind.startswith("snmp")]
    udp161 = defaultdict(int)
    for key, flow in stats.flows.items():
        _c, _cp, server, sport, proto = key
        if sport == 161 and proto == "udp":
            udp161[server] += flow.packets
    for dev, n in sorted(udp161.items(), key=lambda kv: -kv[1]):
        if n < 20:
            continue
        asset = stats.assets.get(dev)
        siemens = bool(asset and "Siemens" in (asset.vendor or ""))
        out.append(
            Finding(
                fid=f"CRASH-SNMP-FLOOD-{stable_id(dev)}",
                category="crash",
                severity="high" if not siemens else "critical",
                title=f"{n} SNMP packets directed at {dev}",
                summary=(
                    f"{dev} received {n} SNMP packets."
                    + (
                        " It is a Siemens device: specially crafted packets to 161/udp are a documented "
                        "denial-of-service vector that requires a manual restart (CISA ICSA-17-339-01 / "
                        "CVE-2017-12741). Siemens' own mitigation is to disable SNMP or block 161/udp."
                        if siemens
                        else " SNMP on control devices is usually enabled by accident and adds an attack surface."
                    )
                ),
                evidence=[f"{n} packets to {dev}:161/udp", f"device: {asset.vendor or 'unknown vendor'} {asset.model or ''}" if asset else f"device {dev}"],
                affected=[dev],
                recommendation="Disable SNMP on the controller if it is not used for monitoring, or restrict 161/udp to the NMS address with an ACL.",
                references=["https://www.cisa.gov/news-events/ics-advisories/icsa-17-339-01"],
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                count=n,
                tags=["dos-vector", "snmp", "siemens" if siemens else "hardening"],
            )
        )
    del snmp_to_plcs

    # -------------------------------------------------------- correlation
    out.extend(_correlate(stats, cfg, out))
    return out


def _grouped_faults(
    stats: TrafficStats,
    cfg: ScanConfig,
    kinds: Sequence[str],
    fid: str,
    title_tpl: str,
    summary_tpl: str,
    attr_key: str,
    attr_label: str,
    device_is: str,
    protocol: str,
) -> List[Finding]:
    th = cfg.thresholds
    events = [e for e in stats.events if e.kind in kinds]
    if not events:
        return []
    groups: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
    for e in events:
        device = e.src if device_is == "src" else e.dst
        code = e.attrs.get(attr_key)
        code_str = f"0x{code:02x}" if isinstance(code, int) else str(code)
        groups[(device or "?", code_str)].append(e)
    out: List[Finding] = []
    for (device, code), evs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        if len(evs) < th.error_storm_min:
            continue
        window = evs[-1].ts - evs[0].ts
        rate = len(evs) / window if window > 0 else float(len(evs))
        peers = sorted({e.dst for e in evs} if device_is == "src" else {e.src for e in evs})
        codes = ", ".join(sorted({e.attrs.get(attr_label, code) or code for e in evs if e.attrs.get(attr_label)}))
        out.append(
            Finding(
                fid=f"{fid}-{stable_id(device, code)}",
                category="crash",
                severity="critical" if rate >= 5 else "high",
                title=title_tpl.format(device=device),
                summary=summary_tpl.format(count=len(evs), codes=codes or code),
                evidence=[
                    f"{len(evs)} events between {time.strftime('%H:%M:%S', time.localtime(evs[0].ts))} and {time.strftime('%H:%M:%S', time.localtime(evs[-1].ts))}",
                    f"{rate:.1f} faults/second",
                    f"peers: {', '.join(peers[:6])}",
                    f"example: {evs[0].detail}",
                ],
                affected=[device] + peers,
                recommendation=_recommendation(protocol, code),
                first_ts=evs[0].ts,
                last_ts=evs[-1].ts,
                count=len(evs),
                metric={"rate": round(rate, 2), "code": code},
                tags=["protocol-fault", protocol],
            )
        )
    return out


def _recommendation(protocol: str, code) -> str:
    if protocol == "s7comm":
        return (
            "Read the CPU's diagnostic buffer (TIA Portal > Online & diagnostics) for the same "
            "timestamp. Error class 0x83 means the CPU has no free connection or PDU resources; "
            "0x87 means the HMI is addressing a DB that does not exist in the loaded program - "
            "usually after a program change that the HMI project was not updated for."
        )
    if protocol == "modbus":
        return (
            "Check the register map the client is polling against the current controller program. "
            "Exception 0x04/0x0B means the device or its serial gateway failed - power-cycle only "
            "during a planned window, and capture the controller log first."
        )
    if protocol == "enip":
        return (
            "In Studio 5000 check the controller's connection table and the RPI values of the "
            "EtherNet/IP connections; reduce the number of consumed connections or increase the RPI."
        )
    return "Investigate the device log around the reported timestamps."


def _s7_session_churn(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    th = cfg.thresholds
    out: List[Finding] = []
    # COTP connect requests vs confirms
    by_server: Dict[str, List[Tuple[float, bool]]] = defaultdict(list)
    for ts, _client, server, is_confirm in stats.cotp_connects:
        by_server[server].append((ts, is_confirm))
    for server, events in by_server.items():
        if len(events) < th.session_churn_min:
            continue
        requests = [t for t, c in events if not c]
        confirms = [t for t, c in events if c]
        window = events[-1][0] - events[0][0]
        if window <= 0:
            continue
        rate = len(requests) / window
        if rate < th.session_churn_min / th.session_churn_window:
            continue
        ratio = len(confirms) / max(len(requests), 1)
        out.append(
            Finding(
                fid=f"CRASH-S7-CHURN-{stable_id(server)}",
                category="crash",
                severity="high",
                title=f"{len(requests)} S7 connection attempts to {server} in {window:.0f}s",
                summary=(
                    f"{len(requests)} COTP connect requests, {len(confirms)} accepted "
                    f"({ratio * 100:.0f}%). A controller that is healthy answers immediately; this "
                    "pattern means clients are retrying because the CPU is not accepting sessions - "
                    "it is in STOP, has no free connection resources, or is restarting."
                ),
                evidence=[
                    f"{len(requests)} requests / {len(confirms)} confirms over {window:.1f}s",
                    f"{rate:.1f} attempts per second",
                ],
                affected=[server],
                recommendation="Check the CPU operating mode (RUN/STOP) and the number of configured PG/OP/S7 connections in the hardware configuration.",
                first_ts=events[0][0],
                last_ts=events[-1][0],
                count=len(requests),
                metric={"requests": len(requests), "confirms": len(confirms)},
                tags=["s7comm", "availability"],
            )
        )

    # renegotiation bursts = probable restart
    setups: Dict[str, List[float]] = defaultdict(list)
    for ts, _client, server, _pdu in stats.s7_setup:
        setups[server].append(ts)
    for server, times in setups.items():
        if len(times) < 3:
            continue
        gaps = [(times[i] - times[i - 1], times[i]) for i in range(1, len(times))]
        idle = [(g, t) for g, t in gaps if g > 30]
        if not idle:
            continue
        worst, at = max(idle)
        out.append(
            Finding(
                fid=f"CRASH-S7-RENEGOTIATE-{stable_id(server, at)}",
                category="crash",
                severity="high",
                title=f"S7 session renegotiated with {server} after {human_ms(worst)} idle",
                summary=(
                    f"A 'Setup communication' handshake happened again after {human_ms(worst)} of "
                    "silence. Clients only re-handshake when the session died - which is what a CPU "
                    "restart, a STOP->RUN transition or a communication fault looks like on the wire."
                ),
                evidence=[
                    f"{len(times)} setup-communication exchanges in the capture",
                    f"longest idle before renegotiation: {human_ms(worst)} at {time.strftime('%H:%M:%S', time.localtime(at))}",
                ],
                affected=[server],
                recommendation="Cross-check with the CPU diagnostic buffer and the plant event log for a restart at that time.",
                first_ts=at - worst,
                last_ts=at,
                count=len(times),
                tags=["s7comm", "restart"],
            )
        )
    return out


def _correlate(stats: TrafficStats, cfg: ScanConfig, findings: List[Finding]) -> List[Finding]:
    """Link protocol faults to layer-2 events inside the correlation window."""
    th = cfg.thresholds
    out: List[Finding] = []
    fault_events = [
        e for e in stats.events
        if e.kind.startswith(("s7-error", "modbus-exception", "cip-error")) or e.kind in MALFORMED_KINDS
    ]
    if not fault_events:
        return out
    storm_seconds = {b.ts for b in stats.bucket_list() if b.bcast >= th.broadcast_pps_warn}
    l2_events = (
        [(t, "STP topology change") for t in stats.stp_tcn]
        + [(t, f"MRP topology change (SA {sa})") for t, sa in stats.mrp_topology_changes]
        + [(t, f"MRP link down (SA {sa})") for t, sa in stats.mrp_link_down]
        + [(t, "broadcast storm second") for t in storm_seconds]
    )
    linked: List[Tuple[float, str, Event]] = []
    window = th.correlation_window
    for fe in fault_events:
        for t, label in l2_events:
            if abs(t - fe.ts) <= window:
                linked.append((fe.ts, label, fe))
                break
    if len(linked) < th.correlation_min_events:
        return out
    first, last = linked[0][0], linked[-1][0]
    labels = sorted({l for _t, l, _e in linked})
    devices = sorted({e.src for _t, _l, e in linked})
    out.append(
        Finding(
            fid="CRASH-CORRELATED-L2",
            category="crash",
            severity="critical",
            title=f"{len(linked)} protocol faults coincide with layer-2 events - likely root cause",
            summary=(
                f"{len(linked)} industrial protocol faults happened within {window:g} seconds of a layer-2 "
                f"event ({', '.join(labels)}). When controller faults line up with switching events, "
                "the controller is a victim: the frames are being dropped or delayed by the fabric, "
                "not rejected by the CPU. Fix the loop/storm first, then re-measure."
            ),
            evidence=[
                f"{len(linked)} correlated events between {time.strftime('%H:%M:%S', time.localtime(first))} and {time.strftime('%H:%M:%S', time.localtime(last))}",
                "layer-2 events in window: " + ", ".join(labels),
                "devices reporting faults: " + ", ".join(devices[:8]),
            ]
            + [
                f"{time.strftime('%H:%M:%S', time.localtime(t))} - {label} / {e.kind}: {e.detail[:90]}"
                for t, label, e in linked[:6]
            ],
            affected=devices,
            recommendation=(
                "1) Clear the layer-2 problem (loop, TCN storm, broadcast source). "
                "2) Re-run the capture. 3) Only if faults persist, investigate the controller itself."
            ),
            first_ts=first,
            last_ts=last,
            count=len(linked),
            metric={"correlated": len(linked), "window_s": window},
            tags=["correlation", "root-cause"],
        )
    )
    return out
