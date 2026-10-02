"""Layer-2 loop, broadcast-storm and redundancy-protocol analysis.

The distinguishing question on a plant network is *"is this a loop, or is one
host simply chatty?"*  A loop repeats the *same* frame and collapses unicast
capacity; a chatty host sends *different* frames.  This module separates the two
using the identical-frame index, the MRP/STP state and the per-second counters.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import List

from ..config import ScanConfig
from ..models import Finding
from ..util import stable_id
from .stats import TrafficStats

ETHER_NAMES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x88CC: "LLDP",
    0x8892: "PROFINET",
    0x88E3: "PROFINET MRP",
    0x88F7: "PTP",
    0x8100: "802.1Q",
}


def analyse(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    th = cfg.thresholds
    out: List[Finding] = []
    duration = max(stats.duration(), 1e-6)

    # ---------------------------------------------------------- broadcast rate
    buckets = stats.bucket_list()
    if buckets:
        peak = max(buckets, key=lambda b: b.bcast)
        bcast_total = sum(b.bcast for b in buckets)
        ratio = bcast_total / max(stats.total_frames, 1)
        bps_peak = peak.bcast / stats.bucket_seconds
        avg_bps = bcast_total / duration
        top = sorted(stats.bcast_sources.items(), key=lambda kv: -kv[1])[:5]
        top_str = ", ".join(f"{ip} ({n} frames)" for ip, n in top)
        sev = "info"
        if ratio >= th.broadcast_ratio_crit or bps_peak >= th.broadcast_pps_crit:
            sev = "critical"
        elif ratio >= th.broadcast_ratio_warn or bps_peak >= th.broadcast_pps_warn:
            sev = "high" if bps_peak >= th.broadcast_pps_warn else "medium"
        # a handful of multicast frames in a short capture is not a storm
        if sev != "info" and bcast_total < th.broadcast_min_frames:
            sev = "info"
        if sev != "info":
            out.append(
                Finding(
                    fid="LOOP-BCAST-STORM",
                    category="loop",
                    severity=sev,
                    title="Broadcast/multicast storm consuming switch capacity",
                    summary=(
                        f"{bcast_total} broadcast frames ({ratio * 100:.1f}% of all traffic), "
                        f"peak {bps_peak:.0f} broadcast frames/s. Every broadcast is copied to every "
                        f"port of the segment, including PLC CPUs that must interrupt their scan "
                        f"cycle to drop it."
                    ),
                    evidence=[
                        f"average {avg_bps:.1f} broadcast frames/s, peak {bps_peak:.0f}/s at {time.strftime('%H:%M:%S', time.localtime(peak.ts))}",
                        f"thresholds: warn {th.broadcast_pps_warn:.0f}/s or {th.broadcast_ratio_warn * 100:.0f}%, critical {th.broadcast_pps_crit:.0f}/s or {th.broadcast_ratio_crit * 100:.0f}%",
                        f"top sources: {top_str}",
                    ],
                    affected=[ip for ip, _ in top],
                    recommendation=(
                        "Segment the affected hosts behind a managed switch, disable the unnecessary "
                        "broadcast service (NetBIOS/LLMNR/mDNS/BACnet BBMD) and verify no unmanaged "
                        "hub or bridged wireless AP is on the plant VLAN."
                    ),
                    first_ts=stats.first_ts,
                    last_ts=stats.last_ts,
                    count=bcast_total,
                    metric={"broadcast_ratio": round(ratio, 4), "peak_bps": round(bps_peak, 1), "total": bcast_total},
                    tags=["broadcast", "performance"],
                )
            )

    # per-segment broadcast concentration
    for seg in stats.segments.values():
        if seg.frames < 50 or seg.broadcast_ratio < th.broadcast_ratio_warn:
            continue
        out.append(
            Finding(
                fid=f"LOOP-SEGMENT-BCAST-{stable_id(seg.cidr)}",
                category="loop",
                severity="high" if seg.broadcast_ratio >= th.broadcast_ratio_crit else "medium",
                title=f"Segment {seg.cidr} is broadcast dominated",
                summary=(
                    f"{seg.broadcast_frames}/{seg.frames} frames ({seg.broadcast_ratio * 100:.1f}%) on "
                    f"{seg.label or seg.cidr} are broadcast. On a control segment this directly "
                    f"reduces the time budget available for cyclic PLC communication."
                ),
                evidence=[f"segment {seg.cidr} ({seg.label})", f"purdue level {seg.purdue}"],
                affected=[seg.cidr],
                recommendation="Move broadcast-generating hosts (workstations, printers, DHCP/DNS clients) off the control VLAN.",
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                metric={"ratio": round(seg.broadcast_ratio, 4)},
                tags=["broadcast", "segmentation"],
            )
        )

    # ----------------------------------------------------------- identical frames
    loop_hits = []
    for h, seen in stats.frame_index.items():
        if len(seen) < th.loop_min_repeat:
            continue
        times = [t for t, _i, _ttl, _k in seen]
        window = times[-1] - times[0] if len(times) > 1 else 0.0
        rate = (len(times) / window) if window > 0 else float(len(times))
        ttls = {t for _ts, _i, t, _k in seen if t is not None}
        ifaces = {i for _ts, i, _t, _k in seen if i}
        keys = {k for _ts, _i, _t, k in seen if k}
        loop_hits.append((rate, len(times), h, window, ttls, ifaces, keys))
    loop_hits.sort(reverse=True)
    for rate, count, h, window, ttls, ifaces, keys in loop_hits[:8]:
        if rate < 2.0:
            continue
        multi_iface = len(ifaces) > 1
        layer2 = not any(">" in h for _ in (0,)) and "|" in h and h.count("|") < 4
        # A cyclic poll request is byte-identical every cycle, so "same frame
        # repeated" alone would flag every healthy plant.  What separates a loop
        # from polling is whether the frame is answered and how fast it repeats:
        # a real loop runs at wire speed and gets no application reply.
        answered = 0
        for key in keys:
            fl = stats.flows.get(key)
            if fl is not None and fl.bytes_a2b and fl.bytes_b2a:
                answered += 1
        if keys and answered == len(keys) and not multi_iface and rate <= th.loop_poll_rate_max:
            continue
        # Repeated *retransmissions* are also byte-identical, but that is TCP
        # recovering from loss, not a loop: PERF-RETRANS owns that case.
        retrans = sum((stats.flows[k].retrans for k in keys if stats.flows.get(k)), 0)
        if keys and retrans >= count * 0.5 and rate < th.loop_rate_wire:
            continue
        # A single unicast flow repeating a few times per second is protocol
        # behaviour (a stuck zero window, a slow retransmit); a loop is fast.
        if not multi_iface and not layer2 and rate < th.loop_rate_min:
            continue
        out.append(
            Finding(
                fid=f"LOOP-FRAME-REPEAT-{stable_id(h)}",
                category="loop",
                severity="critical" if (rate >= 20 and multi_iface) else "high",
                title="Identical frame repeated rapidly - switching loop, duplicate source or flood",
                summary=(
                    f"The same frame content was seen {count} times in {window:.1f}s ({rate:.0f}/s)"
                    + (f" on {len(ifaces)} different interfaces." if multi_iface else ".")
                    + " A frame that repeats identically and fast is what a loop, a duplicated source "
                    "or an unsolicited flood does; a normal application changes its payload or "
                    "sequence numbers every time."
                ),
                evidence=[
                    f"frame index {h}",
                    f"{count} occurrences, {rate:.0f} frames/s over {window:.1f}s",
                    f"interfaces: {', '.join(sorted(ifaces)) if ifaces else 'single capture point'}",
                    f"IP TTL values observed: {sorted(ttls) if ttls else 'n/a (layer 2 frame)'}",
                ],
                recommendation=(
                    "Trace the source MAC on the managed switches. If the frame appears on two ports, "
                    "unplug the second one; if spanning-tree is disabled, enable RSTP on all plant ports. "
                    "Check for a media converter or a bridged access point creating a second path."
                ),
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                count=count,
                metric={
                    "rate": round(rate, 1),
                    "count": count,
                    "multi_interface": multi_iface,
                    "answered_flows": answered,
                    "flows": len(keys),
                    "retransmissions": retrans,
                },
                tags=["loop"],
            )
        )

    # --------------------------------------------------------------- ARP storm
    for (mac, target, op), times in stats.arp_requests.items():
        if len(times) < 10:
            continue
        window = times[-1] - times[0]
        rate = len(times) / window if window > 0 else float(len(times))
        if rate < th.arp_rate_warn:
            continue
        out.append(
            Finding(
                fid=f"LOOP-ARP-STORM-{stable_id(mac, target)}",
                category="loop",
                severity="high" if rate < th.arp_rate_warn * 5 else "critical",
                title=f"ARP request flood for {target}",
                summary=(
                    f"{mac} sent {len(times)} identical 'who-has {target}' requests "
                    f"({rate:.0f}/s). Unanswered ARP at this rate means a missing host, a duplicate "
                    f"IP or an ARP reflection loop - and it saturates the control VLAN."
                ),
                evidence=[
                    f"source MAC {mac}",
                    f"target {target}, {len(times)} requests over {window:.1f}s",
                ],
                affected=[target],
                recommendation=(
                    "Check whether the target is powered off or has a duplicate IP, and add a static "
                    "ARP entry / DHCP reservation. Enable DHCP snooping + DAI on the switch."
                ),
                first_ts=times[0],
                last_ts=times[-1],
                count=len(times),
                metric={"rate": round(rate, 1)},
                tags=["arp", "broadcast"],
            )
        )

    # ------------------------------------------------------------ MAC flapping
    for mac, ifaces in stats.mac_ifaces.items():
        if len(ifaces) < 2:
            continue
        counts = ", ".join(f"{i}:{n}" for i, n in sorted(ifaces.items(), key=lambda kv: -kv[1]))
        out.append(
            Finding(
                fid=f"LOOP-MAC-FLAP-{stable_id(mac)}",
                category="loop",
                severity="high",
                title=f"MAC {mac} observed on {len(ifaces)} interfaces",
                summary=(
                    f"The same source address appears on {len(ifaces)} capture points ({counts}). "
                    "This is the classic signature of a loop or of a device that is dual-homed "
                    "across two VLANs without a router."
                ),
                evidence=[f"interfaces: {counts}"],
                affected=[mac],
                recommendation="Enable STP BPDU guard on access ports and verify no device is bridging two plant segments.",
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                metric={"interfaces": len(ifaces)},
                tags=["loop", "mac"],
            )
        )

    # --------------------------------------------------- STP / MRP state
    bpdu_count = len(stats.bpdu_ts)
    bcast_rate = sum(b.bcast for b in buckets) / duration if buckets else 0.0
    if bpdu_count == 0 and bcast_rate >= th.broadcast_pps_warn:
        out.append(
            Finding(
                fid="LOOP-NO-STP",
                category="loop",
                severity="high",
                title="No spanning-tree BPDUs while broadcast load is high",
                summary=(
                    f"{len(buckets)} seconds of traffic contain no STP/RSTP BPDU at all while broadcast "
                    f"runs at {bcast_rate:.0f} frames/s. Without STP a single accidental cable between "
                    "two ports takes the whole plant segment down, and nothing will stop it."
                ),
                evidence=["0 BPDU frames captured", f"broadcast rate {bcast_rate:.0f}/s"],
                recommendation=(
                    "Confirm whether the plant switches are managed. If they are, enable RSTP; if they "
                    "are not, replace them with managed switches (loop protection is the minimum "
                    "requirement for an OT VLAN) or use MRP rings consistently."
                ),
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                tags=["stp", "resilience"],
            )
        )
    elif bpdu_count:
        tcn = stats.stp_tcn
        if len(tcn) >= 2:
            window = tcn[-1] - tcn[0]
            rate = len(tcn) / window if window > 0 else float(len(tcn))
            if rate >= th.stp_tcn_rate_warn or len(tcn) >= 5:
                out.append(
                    Finding(
                        fid="LOOP-STP-TCN-STORM",
                        category="loop",
                        severity="high",
                        title="STP topology-change storm",
                        summary=(
                            f"{len(tcn)} topology-change BPDUs in {window:.1f}s. Every TCN flushes the "
                            "MAC table of all switches, which floods unicast traffic as broadcast - the "
                            "second most common cause of a 'network suddenly got slow' ticket."
                        ),
                        evidence=[f"{len(tcn)} TCNs over {window:.1f}s ({rate:.2f}/s)"],
                        recommendation="Find the flapping port (a failing NIC, a loose cable or a device power-cycling) and enable BPDU guard/loop guard.",
                        first_ts=tcn[0],
                        last_ts=tcn[-1],
                        count=len(tcn),
                        metric={"rate": round(rate, 2)},
                        tags=["stp", "loop"],
                    )
                )
        roots = {mac: len(ts) for mac, ts in stats.stp_root.items()}
        if len(roots) > 1:
            detail = ", ".join(f"{m} ({n} BPDUs)" for m, n in sorted(roots.items(), key=lambda kv: -kv[1]))
            out.append(
                Finding(
                    fid="LOOP-STP-ROOT-FLAP",
                    category="loop",
                    severity="high",
                    title=f"{len(roots)} different STP root bridges advertising",
                    summary=(
                        f"Root bridge candidates: {detail}. Root election is unstable, so the tree is "
                        "being recomputed - traffic is briefly black-holed each time."
                    ),
                    evidence=[f"root bridge IDs seen: {detail}"],
                    recommendation="Set an explicit root bridge priority on the core switch pair and root-guard on all downstream ports.",
                    first_ts=stats.first_ts,
                    last_ts=stats.last_ts,
                    count=len(roots),
                    tags=["stp", "resilience"],
                )
            )

    if len(stats.mrp_managers) > 1:
        detail = ", ".join(f"{m} ({len(ts)} test frames)" for m, ts in sorted(stats.mrp_managers.items(), key=lambda kv: -len(kv[1])))
        out.append(
            Finding(
                fid="LOOP-MRP-DOUBLE-MANAGER",
                category="loop",
                severity="critical",
                title="More than one MRP redundancy manager in the ring",
                summary=(
                    f"MRP managers seen: {detail}. A PROFINET ring must have exactly one MRM; with two, "
                    "the ring is opened and closed unpredictably and - if both close it - you get a real "
                    "layer-2 loop inside the machine network."
                ),
                evidence=[f"managers: {detail}"],
                recommendation="Configure exactly one device as MRM (Redundancy Manager) and all others as MRC (client).",
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                count=len(stats.mrp_managers),
                tags=["mrp", "loop", "profinet"],
            )
        )

    tcs = stats.mrp_topology_changes
    if len(tcs) >= 3:
        window = tcs[-1][0] - tcs[0][0]
        out.append(
            Finding(
                fid="LOOP-MRP-TOPOLOGY-FLAP",
                category="loop",
                severity="high",
                title="PROFINET MRP ring is flapping",
                summary=(
                    f"{len(tcs)} MRP topology-change events in {window:.1f}s. The ring keeps breaking and "
                    "re-closing; during each transition IO devices lose their cyclic data."
                ),
                evidence=[
                    f"{len(tcs)} topology changes over {window:.1f}s",
                    "reporting devices: " + ", ".join(sorted({sa for _t, sa in tcs if sa})),
                ],
                recommendation="Inspect ring cabling and MRM/MRC roles; check for a failing port or an unshielded cable near a drive.",
                first_ts=tcs[0][0],
                last_ts=tcs[-1][0],
                count=len(tcs),
                tags=["mrp", "profinet", "availability"],
            )
        )

    for ev in stats.events_prefix("stp-aged"):
        out.append(
            Finding(
                fid=f"LOOP-STP-AGED-{stable_id(ev.detail)}",
                category="loop",
                severity="medium",
                title="BPDU aged out near max age",
                summary=ev.detail,
                evidence=[f"frame {ev.idx} from {ev.src}", ev.detail],
                recommendation="A BPDU that arrives almost expired means the path is congested or a switch is dropping BPDUs - both point at a loop or a saturated uplink.",
                first_ts=ev.ts,
                last_ts=ev.ts,
                tags=["stp"],
            )
        )

    # --------------------------------------------------- layer-3 loop / TTL
    ttl1 = sum(1 for e in stats.events if e.kind == "icmp-time-exceeded")
    icmp11 = sum(n for (t, c), n in stats.icmp_types.items() if t == 11)
    if icmp11 >= 10:
        out.append(
            Finding(
                fid="LOOP-L3-TTL",
                category="loop",
                severity="high",
                title="TTL expiry flood - possible routing loop",
                summary=(
                    f"{icmp11} ICMP 'time exceeded' messages captured. Packets are circling between "
                    "routers until their TTL reaches zero."
                ),
                evidence=[f"{icmp11} ICMP type 11 messages"],
                recommendation="Check for asymmetric routes / overlapping static routes between the ERP and plant routers.",
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                count=icmp11,
                tags=["routing", "loop"],
            )
        )
    del ttl1

    # ------------------------------------------------- broadcast amplifiers
    proto_counts = Counter()
    for (src, etype), n in stats.bcast_source_proto.items():
        proto_counts[ETHER_NAMES.get(etype, f"0x{etype:04x}")] += n
    if proto_counts:
        top = proto_counts.most_common(4)
        names = ", ".join(f"{k} {v}" for k, v in top)
        if any(k in ("ARP", "IPv4", "IPv6") and v > 200 for k, v in top):
            out.append(
                Finding(
                    fid="LOOP-BCAST-MIX",
                    category="loop",
                    severity="medium",
                    title="Broadcast traffic composition",
                    summary=f"Broadcast frames by ethertype: {names}.",
                    evidence=[f"total broadcast frames: {sum(proto_counts.values())}"],
                    recommendation=(
                        "ARP-dominated broadcast usually means missing static mappings or DHCP churn; "
                        "IPv4/IPv6-dominated broadcast usually means Windows name resolution (NetBIOS, "
                        "LLMNR, mDNS) leaking into the plant VLAN."
                    ),
                    first_ts=stats.first_ts,
                    last_ts=stats.last_ts,
                    tags=["broadcast"],
                )
            )
    return out
