"""Layer 2/3/4 frame parser -> otscope.models.Packet."""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple

from .models import Packet
from .util import ip6_str, ip_str, mac_str

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100
ETH_P_QINQ = 0x88A8
ETH_P_LLDP = 0x88CC
ETH_P_PTP = 0x88F7
ETH_P_PROFINET = 0x8892
ETH_P_MRP = 0x88E3
ETH_P_CDP = 0x2000  # carried in LLC, not ethertype
ETH_P_MACSEC = 0x88E5

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58


def parse_frame(raw: bytes, ts: float = 0.0, iface: str = "", idx: int = 0, caplen: Optional[int] = None) -> Packet:
    p = Packet(
        idx=idx,
        ts=ts,
        iface=iface,
        caplen=caplen if caplen is not None else len(raw),
        origlen=len(raw),
    )
    if len(raw) < 14:
        p.malformed.append("short-ethernet-frame")
        return p

    p.dst_mac = mac_str(raw[0:6])
    p.src_mac = mac_str(raw[6:12])
    etype = struct.unpack(">H", raw[12:14])[0]
    off = 14
    vlans: List[int] = []
    depth = 0
    while etype in (ETH_P_VLAN, ETH_P_QINQ) and off + 4 <= len(raw) and depth < 4:
        tci, etype = struct.unpack(">HH", raw[off : off + 4])
        vlans.append(tci & 0x0FFF)
        off += 4
        depth += 1
    p.vlans = tuple(vlans)
    p.ethertype = etype

    body = raw[off:]
    if etype == ETH_P_ARP:
        _parse_arp(p, body)
        return p
    if etype == ETH_P_IP:
        _parse_ipv4(p, body)
    elif etype == ETH_P_IPV6:
        _parse_ipv6(p, body)
    elif etype in (ETH_P_LLDP, ETH_P_PROFINET, ETH_P_MRP, ETH_P_PTP):
        p.payload = body
    elif etype < 1500:
        # LLC frame (STP BPDU, CDP, ...): keep the LLC header as payload
        p.payload = body
    else:
        p.payload = body
    return p


def _parse_arp(p: Packet, body: bytes) -> None:
    if len(body) < 28:
        p.malformed.append("short-arp")
        return
    htype, ptype, hlen, plen, op = struct.unpack(">HHBBH", body[0:8])
    if hlen != 6 or plen != 4:
        p.malformed.append("arp-unexpected-address-length")
        return
    # keep the Ethernet addresses in src_mac/dst_mac (an ARP *request* has a
    # zeroed target hardware address, which would otherwise hide the broadcast)
    p.src_ip = ip_str(body[14:18])
    p.dst_ip = ip_str(body[24:28])
    p.proto = 0x0806
    p.payload = body
    p.sport = op  # reuse sport/dport so flows group per operation
    p.dport = op
    p.ip_ver = 4
    p.arp_op = op  # type: ignore[attr-defined]
    p.arp_sha = mac_str(body[8:14])  # type: ignore[attr-defined]
    p.arp_tha = mac_str(body[18:24])  # type: ignore[attr-defined]


def _parse_ipv4(p: Packet, body: bytes) -> None:
    if len(body) < 20:
        p.malformed.append("short-ipv4")
        return
    vihl, tos, total, ident, flags_frag, ttl, proto, _csum = struct.unpack(">BBHHHBBH", body[0:12])
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(body) < ihl:
        p.malformed.append("bad-ipv4-ihl")
        return
    p.ip_ver = 4
    p.src_ip = ip_str(body[12:16])
    p.dst_ip = ip_str(body[16:20])
    p.ip_id = ident
    p.ip_ttl = ttl
    p.ip_tos = tos
    p.ip_df = bool(flags_frag & 0x4000)
    p.ip_mf = bool(flags_frag & 0x2000)
    p.ip_frag_off = (flags_frag & 0x1FFF) * 8
    p.proto = proto
    l4 = body[ihl:total] if total <= len(body) else body[ihl:]
    if p.ip_frag_off:  # non-first fragment: no L4 header
        p.payload = l4
        return
    _parse_l4(p, l4)


def _parse_ipv6(p: Packet, body: bytes) -> None:
    if len(body) < 40:
        p.malformed.append("short-ipv6")
        return
    p.ip_ver = 6
    plen, nxt = struct.unpack(">HB", body[4:7])
    p.ip_ttl = body[7]  # hop limit
    p.src_ip = ip6_str(body[8:24])
    p.dst_ip = ip6_str(body[24:40])
    off = 40
    hops = 0
    while nxt in (0, 43, 44, 50, 51, 60, 135) and off + 2 <= len(body) and hops < 8:
        nxt = body[off]
        ext_len = 8 + body[off + 1] * 8
        off += ext_len
        hops += 1
    p.proto = nxt
    _parse_l4(p, body[off : 40 + plen])


def _parse_l4(p: Packet, l4: bytes) -> None:
    if p.proto == IPPROTO_TCP:
        if len(l4) < 20:
            p.malformed.append("short-tcp")
            return
        sport, dport, seq, ack, off_flags, win, _csum, urg = struct.unpack(">HHIIHHHH", l4[0:20])
        p.sport, p.dport = sport, dport
        p.tcp_seq, p.tcp_ack, p.tcp_win = seq, ack, win
        # off_flags: bits 12-15 data offset, bits 9-11 reserved, bits 0-8 flags
        p.tcp_flags = off_flags & 0x01FF
        doff = (off_flags >> 12) * 4
        p.payload = l4[doff:] if doff >= 20 else l4[20:]
        if urg & 0x20:  # ECE bit rides in the urg field's upper part
            p.tcp_flags |= 0x40
    elif p.proto == IPPROTO_UDP:
        if len(l4) < 8:
            p.malformed.append("short-udp")
            return
        sport, dport, ulen, _csum = struct.unpack(">HHHH", l4[0:8])
        p.sport, p.dport = sport, dport
        if ulen and ulen < 8:
            p.malformed.append("bad-udp-length")
        p.payload = l4[8:]
    elif p.proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
        if len(l4) < 4:
            p.malformed.append("short-icmp")
            return
        p.icmp_type, p.icmp_code = l4[0], l4[1]
        p.payload = l4
    else:
        p.payload = l4


# ---------------------------------------------------------------------------
# helpers used by dissectors / analysis
# ---------------------------------------------------------------------------
def llc_info(raw: bytes) -> Tuple[int, int, bytes]:
    """Return (dsap, ssap, info) for an LLC frame (STP/CDP)."""
    if len(raw) < 3:
        return (0, 0, b"")
    return raw[0], raw[1], raw[3:]


def oui_of_mac(mac: str) -> str:
    return mac[:8].lower()


def is_bpdu(p: Packet) -> bool:
    return p.dst_mac.startswith("01:80:c2:00:00:0")


def is_cdp(p: Packet) -> bool:
    return p.dst_mac == "01:00:0c:cc:cc:cc"


def is_lldp(p: Packet) -> bool:
    return p.ethertype == ETH_P_LLDP
