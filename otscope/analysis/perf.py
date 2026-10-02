"""Network performance / degradation analysis.

Answers the operational question "what is slowing the network down?" with
numbers: retransmissions, latency to the controllers, polling gaps, receiver
stalls, link utilisation and statistical deviation from the capture's own
baseline.
"""

from __future__ import annotations

import time
from typing import Dict, List, Tuple

from ..config import ScanConfig
from ..models import Finding
from ..util import Ewma, human_bytes, human_ms, human_rate, percentile, stable_id
from .stats import TrafficStats

OT_PORTS = {102, 502, 44818, 2222, 4840, 20000, 47808}


def analyse(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    th = cfg.thresholds
    out: List[Finding] = []

    # ------------------------------------------------------------ utilisation
    if cfg.link_speed_mbps:
        util = (stats.bps() / (cfg.link_speed_mbps * 1e6)) if cfg.link_speed_mbps else 0.0
        buckets = stats.bucket_list()
        peak_util = max((b.bytes * 8 / (cfg.link_speed_mbps * 1e6)) for b in buckets) if buckets else 0.0
        if util >= th.util_warn or peak_util >= th.util_crit:
            out.append(
                Finding(
                    fid="PERF-UTILISATION",
                    category="perf",
                    severity="critical" if peak_util >= th.util_crit else "high",
                    title=f"Link utilisation {util * 100:.0f}% (peak {peak_util * 100:.0f}%)",
                    summary=(
                        f"Average {human_rate(stats.bps() / 8)} on a {cfg.link_speed_mbps:.0f} Mbit/s link, "
                        f"peak {peak_util * 100:.0f}% in a single second. Above ~50% utilisation, "
                        "switch queues start to add latency to *every* frame, including cyclic PLC data."
                    ),
                    evidence=[
                        f"average {human_rate(stats.bps() / 8)}, peak {human_rate((peak_util * cfg.link_speed_mbps * 1e6) / 8)}",
                        f"configured link speed {cfg.link_speed_mbps:.0f} Mbit/s",
                    ],
                    recommendation="Move the bulk transfer (historian sync, camera stream, backup) to a separate VLAN/link or upgrade the uplink.",
                    first_ts=stats.first_ts,
                    last_ts=stats.last_ts,
                    metric={"avg_util": round(util, 4), "peak_util": round(peak_util, 4)},
                    tags=["throughput"],
                )
            )

    # ------------------------------------------------------- retransmissions
    total_segs = sum(f.data_segments for f in stats.flows.values())
    total_retrans = sum(f.retrans for f in stats.flows.values())
    if total_segs:
        rate = total_retrans / total_segs
        if rate >= th.retrans_warn:
            worst = sorted(stats.flows.values(), key=lambda f: -f.retrans)[:5]
            worst_str = "; ".join(
                f"{f.client}:{f.cport}->{f.server}:{f.sport} {f.retrans}/{f.data_segments} "
                f"({f.retrans / max(f.data_segments, 1) * 100:.1f}%)"
                for f in worst
                if f.retrans
            )
            out.append(
                Finding(
                    fid="PERF-RETRANS",
                    category="perf",
                    severity="critical" if rate >= th.retrans_crit else "high",
                    title=f"TCP retransmission rate {rate * 100:.1f}%",
                    summary=(
                        f"{total_retrans} of {total_segs} data segments were retransmitted. Retransmission "
                        "is the network telling you frames are being dropped - congestion, a duplex "
                        "mismatch, CRC errors on a cable, or a loop. TCP then backs off, which is what "
                        "users experience as 'the ERP is slow'."
                    ),
                    evidence=[f"overall {rate * 100:.2f}% (warn {th.retrans_warn * 100:.1f}%, critical {th.retrans_crit * 100:.0f}%)", f"worst flows: {worst_str}"],
                    affected=sorted({f.server for f in worst if f.retrans}),
                    recommendation=(
                        "Check switch port counters for CRC/input errors and duplex mismatches on the "
                        "affected uplinks, then re-run a capture on the switch span port closest to the "
                        "worst flow."
                    ),
                    first_ts=stats.first_ts,
                    last_ts=stats.last_ts,
                    count=total_retrans,
                    metric={"rate": round(rate, 5), "segments": total_segs, "retrans": total_retrans},
                    tags=["tcp", "packet-loss"],
                )
            )

    # ----------------------------------------------------- inferred loss/gaps
    gap_flows = [
        (f, f.seq_gaps)
        for f in stats.flows.values()
        if f.seq_gaps >= 3 and f.seq_gaps >= 0.02 * max(f.data_segments, 1)
    ]
    if gap_flows:
        gap_flows.sort(key=lambda kv: -kv[1])
        total_gaps = sum(g for _f, g in gap_flows)
        sample = "; ".join(f"{f.client}->{f.server}:{f.sport} {g} gaps" for f, g in gap_flows[:5])
        out.append(
            Finding(
                fid="PERF-SEQ-GAPS",
                category="perf",
                severity="high" if total_gaps >= 20 else "medium",
                title=f"{total_gaps} TCP sequence gaps (frames lost in transit or at the tap)",
                summary=(
                    f"Sequence numbers jump forward in {len(gap_flows)} flows without the missing segment "
                    "ever arriving. Either frames are dropped between the endpoints, or the capture point "
                    "is itself losing frames (overloaded SPAN port / undersized tap)."
                ),
                evidence=[f"total gaps {total_gaps}", f"examples: {sample}"],
                recommendation="Compare with the switch's own drop counters; if the switch is clean, the tap/SPAN session is dropping and the capture under-reports.",
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                count=total_gaps,
                tags=["packet-loss", "capture-quality"],
            )
        )

    # ----------------------------------------------------- zero window stalls
    zw = [(f, f.zero_window) for f in stats.flows.values() if f.zero_window >= th.zero_window_warn]
    for f, n in sorted(zw, key=lambda kv: -kv[1])[:5]:
        out.append(
            Finding(
                fid=f"PERF-ZEROWINDOW-{stable_id(*f.key)}",
                category="perf",
                severity="high" if n >= th.zero_window_warn * 4 else "medium",
                title=f"{f.server}:{f.sport} advertised a zero window {n} times",
                summary=(
                    f"{f.server}:{f.sport} told its peers to stop sending because its receive buffer was "
                    "full. This is an application/CPU stall, not a cable problem - typical of an "
                    "overloaded ERP database server or a PLC that has run out of connection resources."
                ),
                evidence=[f"{n} zero-window advertisements in {human_ms(f.duration())}", f"peer {f.client}:{f.cport}"],
                affected=[f.server],
                recommendation="Look at CPU, memory and connection limits on the receiving host; on a PLC check the number of configured S7/CIP connections.",
                first_ts=f.first_ts,
                last_ts=f.last_ts,
                count=n,
                tags=["tcp", "congestion"],
            )
        )

    # ------------------------------------------------------- latency to devices
    lat_rows: List[Tuple[str, str, List[float]]] = []
    for f in stats.flows.values():
        samples = f.app_rtt_samples
        if f.rtt_syn is not None:
            samples = samples + [f.rtt_syn]
        if len(samples) < 3:
            continue
        lat_rows.append((f.server or "?", f"{f.server}:{f.sport}", samples))
    if lat_rows:
        # aggregate per server
        per_server: Dict[str, List[float]] = {}
        for server, _label, samples in lat_rows:
            per_server.setdefault(server, []).extend(samples)
        worst = sorted(per_server.items(), key=lambda kv: -percentile(kv[1], 95))
        rows = "; ".join(
            f"{srv} p50={human_ms(percentile(s, 50))} p95={human_ms(percentile(s, 95))} max={human_ms(max(s))} n={len(s)}"
            for srv, s in worst[:6]
        )
        ot_slow = [
            (srv, s)
            for srv, s in worst
            if any(f.sport in OT_PORTS and f.server == srv for f in stats.flows.values())
        ]
        for srv, s in ot_slow[:4]:
            p95 = percentile(s, 95)
            if p95 >= th.rtt_crit_ms / 1000:
                out.append(
                    Finding(
                        fid=f"PERF-OT-LATENCY-{stable_id(srv)}",
                        category="perf",
                        severity="critical" if p95 >= th.rtt_crit_ms / 1000 * 3 else "high",
                        title=f"Response time to industrial device {srv} is {human_ms(p95)} at p95",
                        summary=(
                            f"Request/response latency to {srv} reaches {human_ms(p95)} (p95) with a "
                            f"maximum of {human_ms(max(s))}. Cyclic control traffic is usually expected "
                            "to stay in the low single-digit milliseconds; at this level the HMI/SCADA "
                            "starts missing values and watchdogs may trip."
                        ),
                        evidence=[
                            f"n={len(s)} samples, p50={human_ms(percentile(s, 50))}, p95={human_ms(p95)}, max={human_ms(max(s))}",
                        ],
                        affected=[srv],
                        recommendation=(
                            "Check switch queueing and CPU load of the controller; a PLC that is also "
                            "serving web/OPC traffic will answer cyclic requests late."
                        ),
                        first_ts=stats.first_ts,
                        last_ts=stats.last_ts,
                        metric={"p50_ms": round(percentile(s, 50) * 1000, 2), "p95_ms": round(p95 * 1000, 2)},
                        tags=["latency", "ot"],
                    )
                )
        out.append(
            Finding(
                fid="PERF-LATENCY-TABLE",
                category="perf",
                severity="info",
                title="Response time per server",
                summary=f"Measured request/response latency: {rows}",
                evidence=[rows],
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                metric={"servers": {srv: {"p50_ms": round(percentile(s, 50) * 1000, 2), "p95_ms": round(percentile(s, 95) * 1000, 2), "n": len(s)} for srv, s in worst[:10]}},
                tags=["latency"],
            )
        )

    # -------------------------------------------------------------- jitter
    for f in stats.flows.values():
        if f.sport not in OT_PORTS:
            continue
        s = f.app_rtt_samples
        if len(s) < 8:
            continue
        p50 = percentile(s, 50)
        p95 = percentile(s, 95)
        jitter = p95 - p50
        if jitter >= th.jitter_warn_ms / 1000:
            out.append(
                Finding(
                    fid=f"PERF-JITTER-{stable_id(*f.key)}",
                    category="perf",
                    severity="high",
                    title=f"High jitter talking to {f.server}:{f.sport}",
                    summary=(
                        f"Latency to {f.server} swings between {human_ms(p50)} (p50) and {human_ms(p95)} "
                        f"(p95). Jitter, more than absolute latency, is what breaks isochronous PROFINET "
                        "and causes EtherNet/IP RPI timeouts."
                    ),
                    evidence=[f"p50={human_ms(p50)} p95={human_ms(p95)} spread={human_ms(jitter)} over {len(s)} samples"],
                    affected=[f.server],
                    recommendation="Prioritise control traffic (DSCP 26/EF for PROFINET RT, DSCP 46 for CIP IO) and remove competing bulk traffic from the segment.",
                    first_ts=f.first_ts,
                    last_ts=f.last_ts,
                    metric={"jitter_ms": round(jitter * 1000, 2)},
                    tags=["jitter", "ot"],
                )
            )

    # --------------------------------------------------------- polling gaps
    for (client, server, port, proto), times in stats.polls.items():
        if len(times) < 6:
            continue
        gaps = [(times[i] - times[i - 1], times[i]) for i in range(1, len(times))]
        if not gaps:
            continue
        med = percentile([g for g, _ in gaps], 50)
        if med <= 0:
            continue
        bad = [(g, t) for g, t in gaps if g > med * th.poll_gap_factor and g * 1000 >= th.poll_gap_min_ms]
        if not bad:
            continue
        worst_gap, worst_t = max(bad)
        total_lost = sum(g for g, _ in bad)
        out.append(
            Finding(
                fid=f"PERF-POLL-GAP-{stable_id(client, server, port)}",
                category="perf",
                severity="high" if worst_gap > med * 10 else "medium",
                title=f"Polling to {server}:{port} stopped for {human_ms(worst_gap)}",
                summary=(
                    f"{client} normally polls {server}:{port} every {human_ms(med)} but {len(bad)} times "
                    f"the interval stretched out - the worst gap was {human_ms(worst_gap)}. During that "
                    "window the SCADA/HMI has no fresh data and any watchdog in the application fires."
                ),
                evidence=[
                    f"median interval {human_ms(med)} over {len(times)} requests",
                    f"{len(bad)} gaps above {th.poll_gap_factor:g}x median, total lost time {human_ms(total_lost)}",
                    f"worst gap at {time.strftime('%H:%M:%S', time.localtime(worst_t))}",
                ],
                affected=[server, client],
                recommendation=(
                    "Correlate the gap timestamps with broadcast storms, PLC error PDUs and switch "
                    "topology changes in this report; a gap that coincides with a storm is congestion, "
                    "a gap with an S7 error PDU is the controller."
                ),
                first_ts=times[0],
                last_ts=times[-1],
                count=len(bad),
                metric={"median_ms": round(med * 1000, 2), "worst_gap_ms": round(worst_gap * 1000, 2), "gaps": len(bad)},
                tags=["polling", "availability", "ot"],
            )
        )

    # ----------------------------------------------------------- slow HTTP
    slow_rows = []
    for (client, host, path), lat in stats.http_latencies.items():
        p95 = percentile(lat, 95)
        if p95 >= th.slow_http_warn_ms / 1000:
            slow_rows.append((p95, client, host, path, len(lat), max(lat)))
    if slow_rows:
        slow_rows.sort(reverse=True)
        rows = "; ".join(f"{host}{path} p95={human_ms(p95)} (n={n})" for p95, _c, host, path, n, _m in slow_rows[:6])
        worst = slow_rows[0]
        out.append(
            Finding(
                fid="PERF-SLOW-HTTP",
                category="perf",
                severity="critical" if worst[0] >= th.slow_http_crit_ms / 1000 else "high",
                title=f"ERP web endpoints are slow (worst p95 {human_ms(worst[0])})",
                summary=(
                    f"Measured server response times on the HTTP(S) endpoints: {rows}. "
                    "These are measured end to end on the wire, so they exclude the client - the time is "
                    "spent inside the server or its database."
                ),
                evidence=[f"{len(slow_rows)} slow endpoints", f"worst: {worst[2]}{worst[3]} max {human_ms(worst[5])}"],
                affected=sorted({h for _p, _c, h, _path, _n, _m in slow_rows}),
                recommendation="Profile the slowest path server-side (database query, RFC round trip); the network delivered the request in time.",
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                metric={"worst_p95_ms": round(worst[0] * 1000, 1)},
                tags=["erp", "application"],
            )
        )

    # --------------------------------------------------- baseline deviation
    out.extend(_baseline_deviations(stats, cfg))

    # -------------------------------------------------------- top talkers
    talkers: Dict[str, int] = {}
    for f in stats.flows.values():
        talkers[f.server or "?"] = talkers.get(f.server or "?", 0) + f.bytes
        talkers[f.client or "?"] = talkers.get(f.client or "?", 0) + f.bytes
    total = max(stats.total_bytes, 1)
    top = sorted(talkers.items(), key=lambda kv: -kv[1])[:5]
    if top and top[0][1] / total >= 0.5:
        host, nbytes = top[0]
        out.append(
            Finding(
                fid=f"PERF-TOP-TALKER-{stable_id(host)}",
                category="perf",
                severity="medium",
                title=f"{host} accounts for {nbytes / total * 100:.0f}% of the traffic",
                summary=(
                    f"{host} moved {human_bytes(nbytes)} of {human_bytes(total)} captured bytes. A single "
                    "host dominating a shared plant segment is the usual cause of intermittent slowness "
                    "for everyone else on it."
                ),
                evidence=[", ".join(f"{h}: {human_bytes(n)} ({n / total * 100:.0f}%)" for h, n in top)],
                affected=[host],
                recommendation="Confirm the host belongs on that segment; move bulk traffic (historian, camera, backup) to its own VLAN.",
                first_ts=stats.first_ts,
                last_ts=stats.last_ts,
                metric={"share": round(nbytes / total, 3)},
                tags=["throughput"],
            )
        )

    # ------------------------------------------------------- duplicate ACKs
    dup = [(f, f.dup_ack) for f in stats.flows.values() if f.dup_ack >= 5]
    for f, n in sorted(dup, key=lambda kv: -kv[1])[:3]:
        out.append(
            Finding(
                fid=f"PERF-DUPACK-{stable_id(*f.key)}",
                category="perf",
                severity="medium",
                title=f"Duplicate ACK storm towards {f.server}:{f.sport}",
                summary=(
                    f"{n} triple-duplicate-ACK groups in this flow: the receiver keeps asking for the "
                    "same segment, which means it is not arriving intact."
                ),
                evidence=[f"{n} duplicate-ACK events between {f.client} and {f.server}:{f.sport}"],
                affected=[f.server],
                recommendation="Check the cable/NIC of the peer and the switch port error counters.",
                first_ts=f.first_ts,
                last_ts=f.last_ts,
                count=n,
                tags=["tcp", "packet-loss"],
            )
        )
    return out


def _baseline_deviations(stats: TrafficStats, cfg: ScanConfig) -> List[Finding]:
    """EWMA baseline per second, then report the windows that break out of it."""
    th = cfg.thresholds
    buckets = stats.bucket_list()
    if len(buckets) < 15:
        return []
    series = {
        "pps": [float(b.frames) for b in buckets],
        "broadcast": [float(b.bcast) for b in buckets],
        "retrans": [float(b.retrans) for b in buckets],
        "bytes": [float(b.bytes) for b in buckets],
    }
    out: List[Finding] = []
    for name, values in series.items():
        ewma = Ewma(alpha=0.15)
        worst_z = 0.0
        worst_i = -1
        spikes: List[int] = []
        for i, v in enumerate(values):
            if i >= 10:
                z = min(ewma.z(v), 99.0)
                if z > th.z_warn:
                    spikes.append(i)
                    if z > worst_z:
                        worst_z, worst_i = z, i
            ewma.update(v)
        if worst_i < 0:
            continue
        b = buckets[worst_i]
        baseline = ewma.mean
        sev = "high" if worst_z >= th.z_crit else "medium"
        out.append(
            Finding(
                fid=f"PERF-BASELINE-{name.upper()}",
                category="perf",
                severity=sev,
                title=f"{name.replace('pps', 'Packet rate').replace('broadcast', 'Broadcast rate').replace('retrans', 'Retransmission rate').title()} spiked to {worst_z:.1f} sigma",
                summary=(
                    f"{name} reached {values[worst_i]:.0f} against a baseline of {baseline:.1f} "
                    f"(z={worst_z:.1f}) at {time.strftime('%H:%M:%S', time.localtime(b.ts))}. "
                    f"{len(spikes)} seconds in the capture exceeded {th.z_warn:g} sigma."
                ),
                evidence=[
                    f"peak {values[worst_i]:.0f} vs baseline {baseline:.1f} (sd {ewma.sd:.1f})",
                    f"{len(spikes)} anomalous seconds",
                    f"peak at {time.strftime('%H:%M:%S', time.localtime(b.ts))}",
                ],
                first_ts=buckets[spikes[0]].ts if spikes else b.ts,
                last_ts=b.ts,
                count=len(spikes),
                metric={"z": round(worst_z, 2), "peak": values[worst_i], "baseline": round(baseline, 2)},
                tags=["baseline", name],
            )
        )
    return out


def flow_table(stats: TrafficStats, limit: int = 40) -> List[Dict[str, object]]:
    """Conversation table for the report / dashboard."""
    rows = []
    for f in sorted(stats.flows.values(), key=lambda f: -f.bytes)[:limit]:
        rows.append(
            {
                "client": f.client,
                "cport": f.cport,
                "server": f.server,
                "sport": f.sport,
                "proto": f.proto,
                "packets": f.packets,
                "bytes": f.bytes,
                "a2b_bytes": f.bytes_a2b,
                "b2a_bytes": f.bytes_b2a,
                "duration": round(f.duration(), 3),
                "rtt_syn_ms": round(f.rtt_syn * 1000, 3) if f.rtt_syn else None,
                "rtt_p95_ms": round(percentile(f.app_rtt_samples, 95) * 1000, 3) if f.app_rtt_samples else None,
                "retrans": f.retrans,
                "seq_gaps": f.seq_gaps,
                "zero_window": f.zero_window,
                "rst": f.rst_count,
                "protocols": dict(f.protocols),
            }
        )
    return rows
