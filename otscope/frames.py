"""Frame and PDU builders.

Used by the bundled network emulator (`otscope devnet`), by the test suite and
by `otscope replay`, which can inject a scenario into the analyser.  Every
builder produces the bytes a real device would put on the wire, so the
dissectors are always exercised against real protocol structures.
"""

from __future__ import annotations

import struct
from typing import Optional, Sequence, Tuple


# ----------------------------------------------------------------- checksums
def _ones_complement(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(">{}H".format(len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _ip_to_bytes(ip: str) -> bytes:
    return bytes(int(p) for p in ip.split("."))


def _mac_to_bytes(mac: str) -> bytes:
    return bytes(int(p, 16) for p in mac.split(":"))


# --------------------------------------------------------------------- L2/L3
def eth(dst_mac: str, src_mac: str, payload: bytes, etype: int = 0x0800, vlan: Optional[int] = None) -> bytes:
    body = b""
    if vlan is not None:
        body = struct.pack(">HH", 0x8100, vlan & 0x0FFF) + struct.pack(">H", etype)
    else:
        body = struct.pack(">H", etype)
    return _mac_to_bytes(dst_mac) + _mac_to_bytes(src_mac) + body + payload


def ip(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 0, df: bool = True, tos: int = 0) -> bytes:
    total = 20 + len(payload)
    flags_frag = (0x4000 if df else 0)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, tos, total, ident & 0xFFFF, flags_frag, ttl, proto, 0, _ip_to_bytes(src), _ip_to_bytes(dst))
    csum = _ones_complement(hdr)
    return struct.pack(">BBHHHBBH4s4s", 0x45, tos, total, ident & 0xFFFF, flags_frag, ttl, proto, csum, _ip_to_bytes(src), _ip_to_bytes(dst)) + payload


def tcp(sport: int, dport: int, payload: bytes = b"", seq: int = 0, ack: int = 0, flags: int = 0x18, win: int = 8192, src: Optional[str] = None, dst: Optional[str] = None, urgent: int = 0) -> bytes:
    off_flags = (5 << 12) | (flags & 0x1FF)
    hdr = struct.pack(">HHIIHHH", sport, dport, seq, ack, off_flags, win, 0)
    if src and dst:
        pseudo = _ip_to_bytes(src) + _ip_to_bytes(dst) + struct.pack(">BBH", 0, 6, 20 + len(payload))
        csum = _ones_complement(pseudo + struct.pack(">HHIIHHH", sport, dport, seq, ack, off_flags, win, 0) + struct.pack(">H", urgent) + payload)
        hdr = struct.pack(">HHIIHHH", sport, dport, seq, ack, off_flags, win, csum)
    return hdr + struct.pack(">H", urgent) + payload


def udp(sport: int, dport: int, payload: bytes = b"", src: Optional[str] = None, dst: Optional[str] = None) -> bytes:
    length = 8 + len(payload)
    if src and dst:
        pseudo = _ip_to_bytes(src) + _ip_to_bytes(dst) + struct.pack(">BBH", 0, 17, length)
        csum = _ones_complement(pseudo + struct.pack(">HHHH", sport, dport, length, 0) + payload)
    else:
        csum = 0
    return struct.pack(">HHHH", sport, dport, length, csum) + payload


def arp(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + _mac_to_bytes(sha) + _ip_to_bytes(spa) + _mac_to_bytes(tha) + _ip_to_bytes(tpa)


def icmp(itype: int, icode: int = 0, payload: bytes = b"", ident: int = 0, seq: int = 0) -> bytes:
    body = struct.pack(">BBHHH", itype, icode, 0, ident, seq) + payload
    csum = _ones_complement(body)
    return struct.pack(">BBHHH", itype, icode, csum, ident, seq) + payload


# ---------------------------------------------------------------- TPKT / COTP
def tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 3, 0, 4 + len(payload)) + payload


def cotp_cr(calling: bytes = b"\x01\x00", called: bytes = b"\x03\x01", tpdu_size: int = 0x0A, src_ref: int = 1) -> bytes:
    params = b"\xc0\x01" + bytes([tpdu_size]) + b"\xc1" + bytes([len(calling)]) + calling + b"\xc2" + bytes([len(called)]) + called
    body = struct.pack(">HHB", 0, src_ref, 0x00) + params
    return bytes([len(body) + 1, 0xE0]) + body


def cotp_cc(src_ref: int = 1, dst_ref: int = 1, tpdu_size: int = 0x0A) -> bytes:
    body = struct.pack(">HHB", dst_ref, src_ref, 0x00) + b"\xc0\x01" + bytes([tpdu_size])
    return bytes([len(body) + 1, 0xD0]) + body


def cotp_dt(payload: bytes, eot: bool = True, nr: int = 0) -> bytes:
    return bytes([0x02, 0xF0, (0x80 if eot else 0x00) | (nr & 0x7F)]) + payload


# -------------------------------------------------------------------- S7comm
def s7_header(rosctr: int, pdu_ref: int, param: bytes, data: bytes = b"", err: Optional[Tuple[int, int]] = None) -> bytes:
    hdr = struct.pack(">BBHHHH", 0x32, rosctr, 0, pdu_ref, len(param), len(data))
    if rosctr in (0x02, 0x03):
        ec, eo = err or (0, 0)
        hdr += bytes([ec, eo])
    return hdr + param + data


def s7_setup_request(pdu_ref: int = 1, amq_calling: int = 1, amq_called: int = 1, pdu_len: int = 480) -> bytes:
    param = bytes([0xF0, 0x00]) + struct.pack(">HHH", amq_calling, amq_called, pdu_len)
    return s7_header(0x01, pdu_ref, param)


def s7_setup_response(pdu_ref: int = 1, amq_calling: int = 1, amq_called: int = 1, pdu_len: int = 480) -> bytes:
    param = bytes([0xF0, 0x00]) + struct.pack(">HHH", amq_calling, amq_called, pdu_len)
    return s7_header(0x03, pdu_ref, param, err=(0, 0))


def s7_read_var(pdu_ref: int = 1, db: int = 1, start_byte: int = 0, count: int = 4, area: int = 0x84, transport: int = 0x02) -> bytes:
    item = bytes([0x12, 0x0A, 0x10, transport]) + struct.pack(">HHB", count, db, area) + (start_byte * 8).to_bytes(3, "big")
    param = bytes([0x04, 0x01]) + item
    return s7_header(0x01, pdu_ref, param)


def s7_read_var_response(pdu_ref: int = 1, values: bytes = b"\x00\x00\x00\x00") -> bytes:
    data = bytes([0xFF, 0x04]) + struct.pack(">H", len(values) * 8) + values
    param = bytes([0x04, 0x01])
    return s7_header(0x03, pdu_ref, param, data, err=(0, 0))


def s7_write_var(pdu_ref: int = 1, db: int = 1, start_byte: int = 0, values: bytes = b"\x00\x01", area: int = 0x84) -> bytes:
    count = len(values)
    item = bytes([0x12, 0x0A, 0x10, 0x02]) + struct.pack(">HHB", count, db, area) + (start_byte * 8).to_bytes(3, "big")
    param = bytes([0x05, 0x01]) + item
    data = bytes([0x00, 0x04]) + struct.pack(">H", count * 8) + values
    return s7_header(0x01, pdu_ref, param, data)


def s7_error_response(pdu_ref: int = 1, err_class: int = 0x87, err_code: int = 0x03, func: int = 0x04) -> bytes:
    return s7_header(0x03, pdu_ref, bytes([func, 0x01]), err=(err_class, err_code))


def s7_stop_request(pdu_ref: int = 1) -> bytes:
    param = bytes([0x29, 0x00, 0x00, 0x00, 0x00, 0x09]) + b"P_PROGRAM"
    return s7_header(0x01, pdu_ref, param)


def s7_start_request(pdu_ref: int = 1) -> bytes:
    param = bytes([0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0x09]) + b"P_PROGRAM"
    return s7_header(0x01, pdu_ref, param)


def s7_userdata_header(pdu_ref: int = 1, group: int = 0x07, sub: int = 0x01, ptype: int = 0x11, seq: int = 0) -> bytes:
    param = bytes([0x00, 0x01, 0x12, 0x04, ptype, group, sub, seq])
    return param


def s7_szl_request(pdu_ref: int = 1, szl_id: int = 0x0011, index: int = 0x0001) -> bytes:
    param = s7_userdata_header(pdu_ref, 0x07, 0x01)
    data = b"\xff\x09" + struct.pack(">HHH", 4, szl_id, index)
    return s7_header(0x07, pdu_ref, param, data)


def s7_szl_response(pdu_ref: int = 1, text: str = "6ES7 515-2AM01-0AB0", szl_id: int = 0x0011, index: int = 1) -> bytes:
    param = s7_userdata_header(pdu_ref, 0x07, 0x01, ptype=0x12, seq=1)
    payload = text.encode("ascii")
    # SZL header (length, id, index) followed by the module identification record
    records = struct.pack(">HHH", 0x0008, szl_id, index) + payload
    data = b"\xff\x09" + struct.pack(">H", len(records) * 8) + records
    return s7_header(0x07, pdu_ref, param, data, err=(0, 0))


# ------------------------------------------------------------------ Modbus
def modbus_request(txid: int, unit: int, fc: int, body: bytes = b"") -> bytes:
    pdu = bytes([fc]) + body
    return struct.pack(">HHHB", txid, 0, len(pdu) + 1, unit) + pdu


def modbus_response(txid: int, unit: int, fc: int, body: bytes = b"") -> bytes:
    pdu = bytes([fc]) + body
    return struct.pack(">HHHB", txid, 0, len(pdu) + 1, unit) + pdu


def modbus_read_holding(txid: int, unit: int, addr: int, count: int) -> bytes:
    return modbus_request(txid, unit, 0x03, struct.pack(">HH", addr, count))


def modbus_holding_response(txid: int, unit: int, values: Sequence[int]) -> bytes:
    body = bytes([len(values) * 2]) + b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
    return modbus_response(txid, unit, 0x03, body)


def modbus_write_single(txid: int, unit: int, addr: int, value: int) -> bytes:
    return modbus_request(txid, unit, 0x06, struct.pack(">HH", addr, value))


def modbus_write_multiple(txid: int, unit: int, addr: int, values: Sequence[int]) -> bytes:
    body = struct.pack(">HHB", addr, len(values), len(values) * 2) + b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
    return modbus_request(txid, unit, 0x10, body)


def modbus_exception(txid: int, unit: int, fc: int, code: int) -> bytes:
    return modbus_response(txid, unit, fc | 0x80, bytes([code]))


def modbus_device_id_request(txid: int, unit: int) -> bytes:
    return modbus_request(txid, unit, 0x2B, bytes([0x0E, 0x01, 0x00]))


def modbus_device_id_response(txid: int, unit: int, objects: Sequence[Tuple[int, str]]) -> bytes:
    body = bytes([0x0E, 0x01, 0x01, 0x00, 0x00, len(objects)])
    for oid, text in objects:
        raw = text.encode("ascii")
        body += bytes([oid, len(raw)]) + raw
    return modbus_response(txid, unit, 0x2B, body)


# --------------------------------------------------------------- EtherNet/IP
def enip_header(command: int, body: bytes = b"", session: int = 0, status: int = 0, context: bytes = b"\x00" * 8) -> bytes:
    return struct.pack("<HHII", command, len(body), session, status) + context + struct.pack("<I", 0) + body


def enip_register_session() -> bytes:
    return enip_header(0x0066, struct.pack("<HH", 1, 0))


def enip_register_session_reply(session: int) -> bytes:
    return enip_header(0x0066, struct.pack("<HH", 1, 0), session=session)


def enip_identity_item(
    vendor_id: int = 1,
    device_type: int = 0x0E,
    product_code: int = 0x1234,
    major: int = 32,
    minor: int = 11,
    serial: int = 0x00ABCDEF,
    product_name: str = "1769-L33ER",
    ip: str = "10.20.3.20",
    port: int = 44818,
    state: int = 3,
) -> bytes:
    name = product_name.encode("ascii")
    sin = struct.pack(">HH", 2, port) + _ip_to_bytes(ip) + b"\x00" * 8
    body = struct.pack("<H", 1) + sin + struct.pack("<HHH", vendor_id, device_type, product_code)
    body += bytes([major, minor]) + struct.pack("<HI", 0x0030, serial) + bytes([len(name)]) + name + bytes([state])
    return body


def enip_list_identity_reply(items: Sequence[bytes]) -> bytes:
    # ListIdentity reply: item count, then the identity items (no CPF preamble)
    cpf = struct.pack("<H", len(items))
    for it in items:
        cpf += struct.pack("<HH", 0x000C, len(it)) + it
    return enip_header(0x0064, cpf)


def enip_cip_unconnected(cip: bytes, session: int = 1) -> bytes:
    body = struct.pack("<IHH", 0, 0, 2)
    body += struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip)) + cip
    return enip_header(0x006F, body, session=session)


def cip_read_tag(tag: str) -> bytes:
    raw = tag.encode("ascii")
    path = bytes([0x91, len(raw)]) + raw + (b"\x00" if len(raw) % 2 else b"")
    return bytes([0x4C, len(path) // 2]) + path


def cip_write_tag(tag: str, value: bytes = b"\x01\x00", type_code: int = 0x00C3) -> bytes:
    raw = tag.encode("ascii")
    path = bytes([0x91, len(raw)]) + raw + (b"\x00" if len(raw) % 2 else b"")
    return bytes([0x4D, len(path) // 2]) + path + struct.pack("<HH", type_code, len(value) // 2) + value


def cip_reply(service: int, status: int = 0x00, data: bytes = b"", additional: Sequence[int] = ()) -> bytes:
    body = bytes([service | 0x80, 0x00, status, len(additional)])
    for a in additional:
        body += struct.pack("<H", a)
    return body + data


# --------------------------------------------------------------- L2 protocols
def lldp_frame(chassis_id: str, port_id: str, system_name: str, system_desc: str = "", mgmt_ip: str = "", ttl: int = 120) -> bytes:
    def tlv(t: int, v: bytes) -> bytes:
        return struct.pack(">H", (t << 9) | len(v)) + v

    out = tlv(1, bytes([4]) + _mac_to_bytes(chassis_id))
    out += tlv(2, bytes([5]) + port_id.encode("ascii"))
    out += tlv(3, struct.pack(">H", ttl))
    if system_name:
        out += tlv(5, system_name.encode("ascii"))
    if system_desc:
        out += tlv(6, system_desc.encode("ascii"))
    if mgmt_ip:
        out += tlv(8, bytes([1, 1]) + _ip_to_bytes(mgmt_ip) + bytes([2]) + struct.pack(">I", 2))
    out += tlv(0, b"")
    return out


def stp_bpdu(root_mac: str, bridge_mac: str, bpdu_type: int = 0x02, flags: int = 0, root_cost: int = 0, msg_age: int = 0, max_age: int = 20, hello: int = 2, port_id: int = 0x8001) -> bytes:
    body = struct.pack(">HBB", 0, 0, bpdu_type)
    body += bytes([flags])
    body += struct.pack(">H", 0x8000) + _mac_to_bytes(root_mac)
    body += struct.pack(">I", root_cost)
    body += struct.pack(">H", 0x8000) + _mac_to_bytes(bridge_mac)
    body += struct.pack(">H", port_id)
    body += struct.pack(">HHHH", msg_age * 256, max_age * 256, hello * 256, 15 * 256)
    # IEEE 802.3 frame with LLC header DSAP=SSAP=0x42 (STP), no SNAP
    return bytes([0x42, 0x42, 0x03]) + body


def mrp_frame(sa: str, role: int = 0x00, sequence: int = 1, tlvs: Sequence[Tuple[int, int]] = ((0x02, 16),)) -> bytes:
    body = struct.pack(">H", 0)
    for ttype, tlen in tlvs:
        body += bytes([ttype, tlen])
        payload = struct.pack(">HH", sequence, role) + _mac_to_bytes(sa) + b"\x00" * max(0, tlen - 10)
        body += payload[:tlen]
    body += bytes([0x00, 0x00])
    return body


def dcp_identify(dst_mac: str = "01:0e:cf:00:00:00", xid: int = 1) -> bytes:
    body = bytes([0x06, 0x00]) + struct.pack(">I", xid) + bytes([0xFF, 0xFF]) + struct.pack(">H", 2) + bytes([0xFF, 0xFF, 0x00, 0x00])
    return body


def dcp_set_name(name: str, xid: int = 2) -> bytes:
    """DCP Set (Set.Name).  Block length counts the 2-byte block qualifier."""
    raw = name.encode("ascii") + (b"\x00" if len(name) % 2 else b"")
    block = bytes([0x01, 0x02]) + struct.pack(">HH", len(raw) + 2, 0) + raw
    body = bytes([0x05, 0x00]) + struct.pack(">I", xid) + bytes([0xFF, 0xFF]) + struct.pack(">H", len(block)) + block
    return body


def dcp_identify_reply(src_mac: str, name: str, ip: str, netmask: str = "255.255.255.0", gw: str = "0.0.0.0") -> bytes:
    padded = name.encode("ascii") + (b"\x00" if len(name) % 2 else b"")
    name_block = bytes([0x01, 0x02]) + struct.pack(">HH", len(padded) + 2, 0) + padded
    ip_block = bytes([0x00, 0x02]) + struct.pack(">HH", 16, 0) + struct.pack(">H", 1) + _ip_to_bytes(ip) + _ip_to_bytes(netmask) + _ip_to_bytes(gw)
    body = bytes([0x06, 0x01]) + struct.pack(">I", 1) + bytes([0xFF, 0xFF]) + struct.pack(">H", len(name_block) + len(ip_block)) + name_block + ip_block
    return body
