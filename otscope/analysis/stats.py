"""Traffic collection: everything the analysers need is computed in one pass.

`TrafficStats.add()` is called for every decoded packet.  It maintains the flow
table, the TCP health counters, the frame-hash index used for loop detection,
the per-second counters used for storm detection and the asset inventory.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..config import ScanConfig
from ..models import Asset, Packet, ProtoFact, Segment
from ..util import lookup_oui, net_of

MAX_HASH_INDEX = 300_000
MAX_PER_HASH = 128

FlowKey = Tuple[str, Optional[int], str, Optional[int], str]


@dataclass
class FlowStat:
    key: FlowKey
    client: str = ""
    cport: Optional[int] = None
    server: str = ""
    sport: Optional[int] = None
    proto: str = "tcp"
    packets: int = 0
    bytes: int = 0
    bytes_a2b: int = 0
    bytes_b2a: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    syn_ts: Optional[float] = None
    synack_ts: Optional[float] = None
    rtt_syn: Optional[float] = None
    fin_ts: Optional[float] = None
    rst_count: int = 0
    retrans: int = 0
    dup_ack: int = 0
    zero_window: int = 0
    seq_gaps: int = 0
    data_segments: int = 0
    protocols: Dict[str, int] = field(default_factory=dict)
    syn_sources: Dict[str, int] = field(default_factory=dict)
    # internals
    _segments: Dict[Tuple[str, int, int, str], float] = field(default_factory=dict, repr=False)
    _acks: Dict[Tuple[str, int], int] = field(default_factory=dict, repr=False)
    _next_seq: Dict[str, int] = field(default_factory=dict, repr=False)
    _app_rtts: List[float] = field(default_factory=list, repr=False)
    _pending_req: Dict[str, float] = field(default_factory=dict, repr=False)

    @property
    def app_rtt_samples(self) -> List[float]:
        return list(self._app_rtts)

    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)


@dataclass
class Event:
    ts: float
    kind: str
    proto: str
    severity: str
    detail: str
    src: str = ""
    dst: str = ""
    sport: Optional[int] = None
    dport: Optional[int] = None
    iface: str = ""
    idx: int = 0
    attrs: Dict[str, Any] = field(default_factory=dict)


class Bucket:
    __slots__ = ("ts", "frames", "bytes", "bcast", "bcast_bytes", "retrans", "errors", "uniframes")

    def __init__(self, ts: float) -> None:
        self.ts = ts
        self.frames = 0
        self.bytes = 0
        self.bcast = 0
        self.bcast_bytes = 0
        self.retrans = 0
        self.errors = 0
        self.uniframes = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.ts,
            "frames": self.frames,
            "bytes": self.bytes,
            "bcast": self.bcast,
            "bcast_bytes": self.bcast_bytes,
            "retrans": self.retrans,
            "errors": self.errors,
            "unicast": self.uniframes,
            "pps": self.frames,
            "bps": self.bytes * 8,
            "bcast_ratio": round(self.bcast / self.frames, 5) if self.frames else 0.0,
        }


class TrafficStats:
    def __init__(self, cfg: Optional[ScanConfig] = None, bucket_seconds: float = 1.0) -> None:
        self.cfg = cfg or ScanConfig()
        self.bucket_seconds = bucket_seconds

        self.assets: Dict[str, Asset] = {}
        self.segments: Dict[str, Segment] = {}
        self.flows: Dict[FlowKey, FlowStat] = {}
        self.events: List[Event] = []
        self.protocols: Dict[str, int] = {}
        self.protocol_bytes: Dict[str, int] = {}
        self.total_frames = 0
        self.total_bytes = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.iface_frames: Dict[str, int] = {}
        self.iface_bytes: Dict[str, int] = {}
        self.malformed: Dict[str, int] = {}
        self.dropped_short = 0

        # per-second counters
        self.buckets: Dict[int, Bucket] = {}
        # broadcast attribution
        self.bcast_sources: Dict[str, int] = {}
        self.bcast_ether: Dict[int, int] = {}
        self.bcast_source_proto: Dict[Tuple[str, int], int] = {}
        # identical-frame index (loop detection)
        self.frame_index: Dict[str, List[Tuple[float, str, Optional[int], Optional[FlowKey]]]] = {}
        # ARP storm detection: (src_mac, target_ip, op) -> [ts]
        self.arp_requests: Dict[Tuple[str, str, int], List[float]] = {}
        # MAC flapping: mac -> {iface: count}
        self.mac_ifaces: Dict[str, Dict[str, int]] = {}
        # IP/MAC binding changes
        self.ip_macs: Dict[str, Dict[str, List[float]]] = {}
        self.mac_ips: Dict[str, Dict[str, int]] = {}
        # scan detection: src -> set((dst, dport))
        self.conn_attempts: Dict[str, Dict[Tuple[str, Optional[int]], float]] = {}
        # beaconing: (src, dst, dport) -> [ts]
        self.beacon_ts: Dict[Tuple[str, str, Optional[int]], List[float]] = {}
        # control protocol state
        self.stp_root: Dict[str, List[float]] = {}          # root bridge mac -> ts
        self.stp_tcn: List[float] = []
        self.bpdu_ts: List[float] = []
        self.mrp_managers: Dict[str, List[float]] = {}
        self.mrp_topology_changes: List[Tuple[float, str]] = []
        self.mrp_link_down: List[Tuple[float, str]] = []
        self.lldp_neighbors: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.cdp_neighbors: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.dcp_events: List[Tuple[float, str, str]] = []
        # HTTP timing: (client, host, path) -> [latency]
        self.http_latencies: Dict[Tuple[str, str, str], List[float]] = {}
        self._http_pending: Dict[Tuple[str, str], Tuple[float, str, str]] = {}
        # protocol-level poll cadence: (client, server, port, proto) -> [request ts]
        self.polls: Dict[Tuple[str, str, Optional[int], str], List[float]] = {}
        self.poll_errors: Dict[Tuple[str, str, Optional[int], str], List[float]] = {}
        # ICMP
        self.icmp_types: Dict[Tuple[int, int], int] = {}
        # silence tracking per critical flow
        self.flow_gaps: Dict[FlowKey, List[Tuple[float, float]]] = {}
        # ---- industrial protocol facts used by the crash + fingerprint engines
        self.s7_setup: List[Tuple[float, str, str, int]] = []          # ts, client, server, pdu_len
        self.cotp_connects: List[Tuple[float, str, str, bool]] = []    # ts, client, server, is_confirm
        self.s7_writes: List[Tuple[float, str, str, List[Any]]] = []
        self.control_commands: List[Tuple[float, str, str, str]] = []
        self.s7_szl: List[Tuple[float, str, str]] = []                 # ts, text, server
        self.enip_identities: List[Tuple[float, str, Dict[str, Any]]] = []
        self.modbus_device_id: List[Tuple[float, str, Dict[str, Any]]] = []
        self.dcp_station_names: List[Tuple[float, str, str]] = []
        self.enip_writes: List[Tuple[float, str, str, str]] = []
        self.modbus_writes: List[Tuple[float, str, str, str]] = []
        self.device_restarts: List[Tuple[float, str, str]] = []

    # ------------------------------------------------------------------
    def _bucket(self, ts: float) -> Bucket:
        key = int(ts // self.bucket_seconds)
        b = self.buckets.get(key)
        if b is None:
            b = Bucket(key * self.bucket_seconds)
            self.buckets[key] = b
        return b

    def asset(self, ip: Optional[str] = None, mac: Optional[str] = None) -> Optional[Asset]:
        key = ip or mac
        if not key:
            return None
        a = self.assets.get(key)
        if a is None:
            a = Asset(key=key, ip=ip, mac=mac)
            self.assets[key] = a
        if ip and not a.ip:
            a.ip = ip
        if ip and mac:
            # A device that only ever spoke layer-2 protocols (STP/LLDP/MRP) was
            # inventoried under its MAC; fold it into the IP-addressed record.
            other = self.assets.get(mac)
            if other is not None and other.key != a.key:
                self._merge_asset(a, other)
                del self.assets[mac]
            a.mac = mac
        elif mac and not a.mac:
            a.mac = mac
        if mac and not a.vendor:
            v = lookup_oui(mac)
            if v:
                a.vendor = v
                a.note(f"MAC OUI {mac[:8].upper()} -> {v}", "oui")
        return a

    @staticmethod
    def _merge_asset(target: Asset, src: Asset) -> None:
        """Fold a MAC-keyed record into an IP-keyed one (IP record wins on identity)."""
        for attr in ("hostname", "vendor", "model", "firmware", "serial", "family"):
            if not getattr(target, attr) and getattr(src, attr):
                setattr(target, attr, getattr(src, attr))
        if target.first_ts is None or (src.first_ts and src.first_ts < target.first_ts):
            target.first_ts = src.first_ts
        if src.last_ts and (target.last_ts is None or src.last_ts > target.last_ts):
            target.last_ts = src.last_ts
        target.frames += src.frames
        target.bytes_in += src.bytes_in
        target.bytes_out += src.bytes_out
        for k, v in src.protocols.items():
            target.protocols[k] = target.protocols.get(k, 0) + v
        for k, v in src.peers.items():
            target.peers[k] = target.peers.get(k, 0) + v
        for k, v in src.confidence.items():
            if k not in target.confidence:
                target.note(v, k)

    def segment(self, ip: Optional[str]) -> Optional[Segment]:
        if not ip:
            return None
        cidr = net_of(ip, self.cfg.segment_prefix)
        s = self.segments.get(cidr)
        if s is None:
            prof = self.cfg.subnet_for(ip)
            s = Segment(cidr=cidr, label=prof.label if prof else "", purdue=prof.purdue if prof else "?")
            self.segments[cidr] = s
        elif prof := self.cfg.subnet_for(ip):
            if not s.label:
                s.label = prof.label
            if s.purdue == "?":
                s.purdue = prof.purdue
        return s

    # ------------------------------------------------------------------
    def add(self, pkt: Packet, facts: Sequence[ProtoFact]) -> None:
        ts = pkt.ts
        self.total_frames += 1
        self.total_bytes += pkt.origlen
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts
        if pkt.iface:
            self.iface_frames[pkt.iface] = self.iface_frames.get(pkt.iface, 0) + 1
            self.iface_bytes[pkt.iface] = self.iface_bytes.get(pkt.iface, 0) + pkt.origlen
        for m in pkt.malformed:
            self.malformed[m] = self.malformed.get(m, 0) + 1

        b = self._bucket(ts)
        b.frames += 1
        b.bytes += pkt.origlen
        bcast = pkt.is_broadcast

        # ---- layer 2 bookkeeping -------------------------------------
        if pkt.src_mac:
            ifaces = self.mac_ifaces.setdefault(pkt.src_mac, {})
            ifaces[pkt.iface or "-"] = ifaces.get(pkt.iface or "-", 0) + 1
        if pkt.src_ip and pkt.src_mac and pkt.ethertype == 0x0806:
            self._arp(pkt, ts)
        if pkt.src_ip and pkt.src_mac:
            self.ip_macs.setdefault(pkt.src_ip, {}).setdefault(pkt.src_mac, []).append(ts)
            self.mac_ips.setdefault(pkt.src_mac, {})[pkt.src_ip] = self.mac_ips.get(pkt.src_mac, {}).get(pkt.src_ip, 0) + 1

        # ---- loop index: identical frames seen repeatedly ------------
        h = self._frame_hash(pkt)
        if h is not None:
            lst = self.frame_index.setdefault(h, [])
            if len(lst) < MAX_PER_HASH:
                lst.append((ts, pkt.iface, pkt.ip_ttl, pkt.flow5))
            if len(self.frame_index) > MAX_HASH_INDEX:  # hard cap on memory
                self.frame_index.pop(h, None)

        # ---- assets & segments ---------------------------------------
        for ip, mac, direction in ((pkt.src_ip, pkt.src_mac, "out"), (pkt.dst_ip, pkt.dst_mac, "in")):
            a = self.asset(ip, mac if direction == "out" else None)
            if a is None or not ip:
                continue
            if a.first_ts is None:
                a.first_ts = ts
            a.last_ts = ts
            a.frames += 1
            if direction == "out":
                a.bytes_out += pkt.origlen
            else:
                a.bytes_in += pkt.origlen
            seg = self.segment(ip)
            if seg and a.key not in seg.assets:
                seg.assets.append(a.key)

        for ip in (pkt.src_ip, pkt.dst_ip):
            seg = self.segment(ip)
            if seg:
                if ip == pkt.src_ip:
                    seg.frames += 1
                    if bcast:
                        seg.broadcast_frames += 1
        if bcast:
            b.bcast += 1
            b.bcast_bytes += pkt.origlen
            src = pkt.src_ip or pkt.src_mac or "?"
            self.bcast_sources[src] = self.bcast_sources.get(src, 0) + 1
            self.bcast_ether[pkt.ethertype] = self.bcast_ether.get(pkt.ethertype, 0) + 1
            pk = (src, pkt.ethertype)
            self.bcast_source_proto[pk] = self.bcast_source_proto.get(pk, 0) + 1
        else:
            b.uniframes += 1

        # ---- flows & TCP health --------------------------------------
        if pkt.src_ip and pkt.dst_ip and (pkt.is_tcp or pkt.is_udp):
            self._flow(pkt, ts, b)
            if pkt.is_tcp:
                self._conn_attempt(pkt, ts)
            self._register_services(pkt)

        # ---- protocols -----------------------------------------------
        named = False
        for f in facts:
            self.protocols[f.proto] = self.protocols.get(f.proto, 0) + 1
            self.protocol_bytes[f.proto] = self.protocol_bytes.get(f.proto, 0) + pkt.origlen
            named = True
            fl = self.flows.get(pkt.flow5)
            if fl is not None:
                fl.protocols[f.proto] = fl.protocols.get(f.proto, 0) + 1
            if pkt.src_ip or pkt.dst_ip:
                endpoints = [self.assets.get(ip_) for ip_ in (pkt.src_ip, pkt.dst_ip)]
            else:
                # layer-2-only device (a switch sending STP/LLDP/MRP has no IP):
                # inventory it under its MAC so its protocols are not lost
                endpoints = [self.assets.get(m) for m in (pkt.src_mac, pkt.dst_mac)]
            for aa in endpoints:
                if aa is not None:
                    aa.protocols[f.proto] = aa.protocols.get(f.proto, 0) + 1
            seg = self.segment(pkt.src_ip)
            if seg:
                seg.protocols[f.proto] = seg.protocols.get(f.proto, 0) + 1
            for ev in f.events:
                self.record_event(pkt, f.proto, ev)
            self._protocol_side_effects(pkt, f, ts)
        if not named:
            key = "arp" if pkt.ethertype == 0x0806 else ("icmp" if pkt.proto == 1 else "other")
            self.protocols[key] = self.protocols.get(key, 0) + 1
            self.protocol_bytes[key] = self.protocol_bytes.get(key, 0) + pkt.origlen

        if pkt.proto == 1 and pkt.icmp_type is not None:
            self.icmp_types[(pkt.icmp_type, pkt.icmp_code or 0)] = self.icmp_types.get((pkt.icmp_type, pkt.icmp_code or 0), 0) + 1

    # ------------------------------------------------------------------
    def _arp(self, pkt: Packet, ts: float) -> None:
        op = getattr(pkt, "arp_op", None) or (pkt.sport or 0)
        if op != 1 or not pkt.dst_ip:
            return
        key = (pkt.src_mac, pkt.dst_ip, op)
        lst = self.arp_requests.setdefault(key, [])
        lst.append(ts)
        if len(lst) > 5000:
            del lst[: len(lst) // 2]

    def _frame_hash(self, pkt: Packet) -> Optional[str]:
        """Hash that identifies 'the same frame again' for loop detection.

        Broadcast/multicast frames and small unicast frames are indexed on
        (src mac, dst mac, first 48 payload bytes); ARP/STP/LLDP are naturally
        repetitive so they only count as a loop when the rate is extreme.
        """
        if pkt.origlen > 1500:
            return None
        material = f"{pkt.src_mac}|{pkt.dst_mac}|{pkt.ethertype:04x}|"
        if pkt.src_ip:
            material += f"{pkt.src_ip}>{pkt.dst_ip}:{pkt.dport}/{pkt.proto}|"
        material += hashlib.blake2b(bytes(pkt.payload[:48]), digest_size=8).hexdigest()
        return material

    def _conn_attempt(self, pkt: Packet, ts: float) -> None:
        if not (pkt.flag("SYN") and not pkt.flag("ACK")):
            return
        d = self.conn_attempts.setdefault(pkt.src_ip or "", {})
        d[(pkt.dst_ip or "", pkt.dport)] = ts

    def _register_services(self, pkt: Packet) -> None:
        """Record which ports each host really listens on.

        A SYN only proves that somebody *asked*, so unanswered SYNs are recorded
        as probed ports, not as open services.  A port counts as a service once
        the host answers from it (SYN-ACK) or sends payload from it.
        """
        if not (pkt.sport and pkt.dport and pkt.src_ip and pkt.dst_ip):
            return
        from ..dissect.misc import WELL_KNOWN_PORTS

        if pkt.is_tcp and pkt.flag("SYN") and not pkt.flag("ACK"):
            ca = self.asset(pkt.src_ip)
            if ca is not None:
                ca.client_ports[pkt.dport] = ca.client_ports.get(pkt.dport, 0) + 1
            sa = self.asset(pkt.dst_ip)
            if sa is not None:
                sa.probed_ports[pkt.dport] = sa.probed_ports.get(pkt.dport, 0) + 1
            return
        if pkt.is_tcp and pkt.flag("SYN") and pkt.flag("ACK"):
            sa = self.asset(pkt.src_ip)
            if sa is not None:
                sa.server_ports.setdefault(pkt.sport, WELL_KNOWN_PORTS.get(pkt.sport, f"tcp/{pkt.sport}"))
            return
        if not pkt.payload:
            return
        server, port = (pkt.src_ip, pkt.sport) if pkt.sport <= pkt.dport else (pkt.dst_ip, pkt.dport)
        name = WELL_KNOWN_PORTS.get(port, f"tcp/{port}" if pkt.is_tcp else f"udp/{port}")
        sa = self.asset(server)
        if sa is not None:
            sa.server_ports.setdefault(port, name)

    def _flow(self, pkt: Packet, ts: float, bucket: Bucket) -> None:
        key = pkt.flow5
        fl = self.flows.get(key)
        if fl is None:
            fl = FlowStat(key=key, first_ts=ts)
            self.flows[key] = fl
            # heuristic direction: the SYN sender is the client
            if pkt.flag("SYN") and not pkt.flag("ACK"):
                fl.client, fl.cport = pkt.src_ip, pkt.sport
                fl.server, fl.sport = pkt.dst_ip, pkt.dport
            else:
                lo = min(pkt.sport or 0, pkt.dport or 0)
                if (pkt.sport or 0) == lo:
                    fl.server, fl.sport = pkt.src_ip, pkt.sport
                    fl.client, fl.cport = pkt.dst_ip, pkt.dport
                else:
                    fl.server, fl.sport = pkt.dst_ip, pkt.dport
                    fl.client, fl.cport = pkt.src_ip, pkt.sport
            fl.proto = "tcp" if pkt.is_tcp else "udp"
            self.flow_gaps[key] = []
        fl.packets += 1
        fl.bytes += pkt.origlen
        if fl.last_ts and ts - fl.last_ts > 0:
            gap = ts - fl.last_ts
            if gap > 5.0:
                self.flow_gaps.setdefault(key, []).append((fl.last_ts, gap))
        fl.last_ts = ts

        a2b = pkt.src_ip == fl.client
        if a2b:
            fl.bytes_a2b += pkt.origlen
        else:
            fl.bytes_b2a += pkt.origlen

        if pkt.is_tcp:
            self._tcp(fl, pkt, ts, a2b, bucket)
        else:
            if pkt.payload:
                self._app_rtt(fl, pkt, ts, a2b)

        if pkt.payload:
            self._poll_tick(fl, pkt, ts, a2b)

    def _tcp(self, fl: FlowStat, pkt: Packet, ts: float, a2b: bool, bucket: Bucket) -> None:
        flags = pkt.tcp_flags
        if flags & 0x02 and not flags & 0x10:  # SYN
            if fl.syn_ts is None:
                fl.syn_ts = ts
            fl.syn_sources[pkt.src_ip or ""] = fl.syn_sources.get(pkt.src_ip or "", 0) + 1
        if flags & 0x02 and flags & 0x10:  # SYN-ACK
            fl.synack_ts = ts
            if fl.syn_ts is not None and fl.rtt_syn is None:
                fl.rtt_syn = ts - fl.syn_ts
        if flags & 0x04:
            fl.rst_count += 1
        if flags & 0x01:
            fl.fin_ts = ts
        if pkt.tcp_win == 0 and flags & 0x10:
            fl.zero_window += 1

        plen = len(pkt.payload)
        if plen:
            fl.data_segments += 1
            direction = "a2b" if a2b else "b2a"
            seg_key = (direction, pkt.tcp_seq or 0, plen, hashlib.blake2b(pkt.payload[:32], digest_size=6).hexdigest())
            prev = fl._segments.get(seg_key)
            if prev is not None and ts - prev > 1e-4:
                fl.retrans += 1
                bucket.retrans += 1
            else:
                fl._segments[seg_key] = ts
                # sequence-gap (loss) detection
                nxt = fl._next_seq.get(direction)
                seq = pkt.tcp_seq or 0
                if nxt is not None and seq > nxt:
                    fl.seq_gaps += 1
                if nxt is None or seq + plen > nxt:
                    fl._next_seq[direction] = seq + plen
            self._app_rtt(fl, pkt, ts, a2b)
        else:
            if flags & 0x10 and not flags & 0x02:
                ack_key = ("a2b" if a2b else "b2a", pkt.tcp_ack or 0)
                fl._acks[ack_key] = fl._acks.get(ack_key, 0) + 1
                if fl._acks[ack_key] == 3:
                    fl.dup_ack += 1

    def _app_rtt(self, fl: FlowStat, pkt: Packet, ts: float, a2b: bool) -> None:
        """Request -> response latency measured from payload frames."""
        if a2b:
            if fl._pending_req.get("a2b") is None:
                fl._pending_req["a2b"] = ts
            fl._pending_req.pop("b2a", None)
        else:
            start = fl._pending_req.get("a2b")
            if start is not None:
                rtt = ts - start
                if 0 <= rtt < 30:
                    fl._app_rtts.append(rtt)
                fl._pending_req.pop("a2b", None)
            else:
                fl._pending_req["b2a"] = ts

    def _poll_tick(self, fl: FlowStat, pkt: Packet, ts: float, a2b: bool) -> None:
        """Record polling requests/responses for cadence analysis."""
        if not a2b:
            return
        proto = "tcp"
        port = fl.sport
        for name, p in (("s7comm", 102), ("modbus", 502), ("enip", 44818)):
            if port == p:
                proto = name
                break
        key = (fl.client or "", fl.server or "", port, proto)
        lst = self.polls.setdefault(key, [])
        lst.append(ts)
        if len(lst) > 20000:
            del lst[: len(lst) // 2]

    def _protocol_side_effects(self, pkt: Packet, fact: ProtoFact, ts: float) -> None:
        a = fact.attrs
        if fact.proto == "stp":
            self.bpdu_ts.append(ts)
            root = a.get("root_bridge")
            if root:
                self.stp_root.setdefault(root, []).append(ts)
            if a.get("tc") or a.get("type_name") == "TCN BPDU":
                self.stp_tcn.append(ts)
        elif fact.proto == "mrp":
            for tlv in a.get("tlvs", []):
                if tlv.get("role") == 0x00 and tlv.get("sa"):
                    self.mrp_managers.setdefault(tlv["sa"], []).append(ts)
                if tlv["type"] == 0x03:
                    self.mrp_topology_changes.append((ts, tlv.get("sa", "")))
                if tlv["type"] == 0x04:
                    self.mrp_link_down.append((ts, tlv.get("sa", "")))
        elif fact.proto == "lldp":
            if pkt.src_mac:
                self.lldp_neighbors[(pkt.src_mac, a.get("system_name", "?"))] = a
        elif fact.proto == "cdp":
            if pkt.src_mac:
                self.cdp_neighbors[(pkt.src_mac, a.get("device_id", "?"))] = a
        elif fact.proto == "profinet-dcp":
            self.dcp_events.append((ts, a.get("service_id", 0), pkt.src_ip or pkt.src_mac))
            if a.get("is_response"):
                # only an Identify response is an authoritative "this device is
                # called X"; a Set request names the *target*, not the sender
                for blk in a.get("blocks", []):
                    if blk.get("station_name"):
                        self.dcp_station_names.append((ts, blk["station_name"], pkt.src_ip or pkt.src_mac))
        elif fact.proto == "http":
            self._http_timing(pkt, a, ts)
        elif fact.proto == "cotp":
            for pdu in a.get("pdus", []):
                if pdu.get("type") == 0xE0:
                    self.cotp_connects.append((ts, pkt.src_ip or "", pkt.dst_ip or "", False))
                elif pdu.get("type") == 0xD0:
                    self.cotp_connects.append((ts, pkt.src_ip or "", pkt.dst_ip or "", True))
        elif fact.proto == "s7comm":
            self._s7_facts(pkt, a, ts)
        elif fact.proto == "enip":
            ident = a.get("identity")
            if ident:
                self.enip_identities.append((ts, pkt.src_ip or "", ident))
            if a.get("service") in (0x4D, 0x4F, 0x10, 0x02, 0x04, 0x4B):
                self.enip_writes.append(
                    (ts, pkt.src_ip or "", pkt.dst_ip or "", str(a.get("service_name") or a.get("service")))
                )
        elif fact.proto == "modbus":
            dev = a.get("device_id")
            if dev:
                self.modbus_device_id.append((ts, pkt.src_ip or "", dev))
            if a.get("write"):
                self.modbus_writes.append(
                    (ts, pkt.src_ip or "", pkt.dst_ip or "", str(a.get("function_name") or a.get("function")))
                )
        # protocol error counters feed the crash analyser
        for ev in fact.events:
            kind = ev.get("kind", "")
            if kind.startswith("s7-control-command") or kind.startswith("s7-mode-transition"):
                self.control_commands.append((ts, pkt.src_ip or "", pkt.dst_ip or "", str(ev.get("detail", kind))))
            if kind.endswith(("error", "exception")) or "error" in kind:
                ot_ports = (102, 502, 44818, 2222, 4840)
                port = pkt.sport if pkt.sport in ot_ports else pkt.dport
                key = (pkt.src_ip or "", pkt.dst_ip or "", port, fact.proto)
                self.poll_errors.setdefault(key, []).append(ts)

    def _http_timing(self, pkt: Packet, a: Dict[str, Any], ts: float) -> None:
        """Pair HTTP requests with their responses, keyed by the client.

        The Host header names a virtual host, not the IP, so matching is done on
        the TCP endpoints: the pending request belongs to the client that is the
        destination of the response frame.
        """
        if a.get("method"):
            key = (pkt.src_ip or "", pkt.dst_ip or "")
            if key not in self._http_pending:
                self._http_pending[key] = (ts, a.get("host", ""), a.get("path", ""))
        elif a.get("status_code"):
            key = (pkt.dst_ip or "", pkt.src_ip or "")
            pending = self._http_pending.pop(key, None)
            if pending is not None:
                t0, host, path = pending
                lat = ts - t0
                if lat >= 0:
                    self.http_latencies.setdefault((key[0], host or key[1], path), []).append(lat)

    def _s7_facts(self, pkt: Packet, a: Dict[str, Any], ts: float) -> None:
        src, dst = pkt.src_ip or "", pkt.dst_ip or ""
        for pdu in a.get("pdus", []):
            func = pdu.get("function")
            if func == 0xF0:
                setup = pdu.get("setup") or {}
                self.s7_setup.append((ts, src, dst, int(setup.get("pdu_length") or 0)))
            elif func == 0x05:
                self.s7_writes.append((ts, src, dst, pdu.get("items", [])))
            if pdu.get("szl_text"):
                self.s7_szl.append((ts, str(pdu["szl_text"]), src))

    # ------------------------------------------------------------------
    def record_event(self, pkt: Packet, proto: str, ev: Dict[str, Any]) -> None:
        kind = str(ev.get("kind", "event"))
        detail = str(ev.get("detail", ""))
        severity = str(ev.get("severity", "info"))
        attrs = {k: v for k, v in ev.items() if k not in ("kind", "detail", "severity")}
        self.events.append(
            Event(
                ts=pkt.ts,
                kind=kind,
                proto=proto,
                severity=severity,
                detail=detail,
                src=pkt.src_ip or pkt.src_mac,
                dst=pkt.dst_ip or pkt.dst_mac,
                sport=pkt.sport,
                dport=pkt.dport,
                iface=pkt.iface,
                idx=pkt.idx,
                attrs=attrs,
            )
        )

    # ------------------------------------------------------------------
    def bucket_list(self) -> List[Bucket]:
        return [self.buckets[k] for k in sorted(self.buckets)]

    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    def pps(self) -> float:
        d = self.duration()
        return self.total_frames / d if d > 0 else 0.0

    def bps(self) -> float:
        d = self.duration()
        return self.total_bytes * 8 / d if d > 0 else 0.0

    def events_of(self, *kinds: str) -> List[Event]:
        ks = set(kinds)
        return [e for e in self.events if e.kind in ks]

    def events_prefix(self, prefix: str) -> List[Event]:
        return [e for e in self.events if e.kind.startswith(prefix)]

    def summary(self) -> Dict[str, Any]:
        return {
            "frames": self.total_frames,
            "bytes": self.total_bytes,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "duration": round(self.duration(), 3),
            "pps": round(self.pps(), 2),
            "bps": round(self.bps(), 1),
            "assets": len(self.assets),
            "segments": len(self.segments),
            "flows": len(self.flows),
            "events": len(self.events),
            "protocols": dict(sorted(self.protocols.items(), key=lambda kv: -kv[1])),
            "interfaces": dict(self.iface_frames),
            "malformed": dict(self.malformed),
        }
