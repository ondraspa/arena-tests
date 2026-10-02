"""Remaining protocols seen on an ERP + OT network: HTTP, SNMP, DNP3, BACnet/IP,
plus plain service identification for the ports that should not be there.

Nothing here needs to be exhaustive -- the goal is to name the protocol, flag
insecure variants (clear-text credentials, SNMP v1/v2c community strings) and
spot broadcast amplifiers (BACnet BBMD, NetBIOS) that slow an OT segment down.
"""

from __future__ import annotations

import base64
import binascii
import struct
from typing import Dict, Optional, Tuple

from ..models import Packet, ProtoFact

WELL_KNOWN_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    23: "Telnet",
    53: "DNS",
    69: "TFTP",
    80: "HTTP",
    102: "S7comm (ISO-on-TCP)",
    111: "RPC portmapper",
    123: "NTP",
    135: "MSRPC/DCOM (OPC Classic)",
    137: "NetBIOS name service",
    138: "NetBIOS datagram",
    139: "NetBIOS session",
    161: "SNMP",
    162: "SNMP trap",
    443: "HTTPS",
    445: "SMB",
    502: "Modbus TCP",
    512: "rexec",
    513: "rlogin",
    514: "rsh/syslog",
    1433: "MSSQL",
    1521: "Oracle DB",
    1812: "RADIUS",
    1962: "PCSOFT / PC Worx",
    2004: "Siemens CP243 / S7 (alt)",
    2222: "EtherNet/IP UDP / AB PCCC",
    3306: "MySQL",
    3389: "RDP",
    4000: "Siemens S7 (alt) / ICSS",
    4480: "Schneider Electric",
    4840: "OPC UA",
    4880: "OPC UA (alt)",
    5000: "SAP Router / Commix",
    5450: "Siemens S7 (alt)",
    5900: "VNC",
    5985: "WinRM",
    8000: "SAP (alt)",
    8100: "SAP dispatcher (alt)",
    10102: "S7comm (alt)",
    10307: "Siemens S7-Plus",
    11001: "Siemens S7 (alt)",
    20000: "DNP3",
    20547: "PROFINET CBA",
    34962: "PROFINET (UDP)",
    34963: "PROFINET (UDP)",
    34964: "PROFINET (UDP)",
    44818: "EtherNet/IP",
    47808: "BACnet/IP",
    49152: "Siemens / dynamic",
}

OT_PORTS = {102, 502, 44818, 2222, 4840, 20000, 47808, 10307, 34962, 34963, 34964, 1962, 4480, 20547}
INSECURE_PORTS = {20, 21, 23, 69, 80, 135, 139, 161, 445, 512, 513, 514, 3389, 5900}

SNMP_DEFAULT_COMMUNITIES = {"public", "private", "community", "admin", "user", "guest", "monitor", "Switch", "ILMI"}

BACNET_FUNCS = {
    0x00: "Result",
    0x01: "Read Broadcast Distribution Table",
    0x02: "Read BD Table Ack",
    0x03: "Forwarded NPDU",
    0x04: "Register Foreign Device",
    0x05: "Read FDT",
    0x06: "Read FDT Ack",
    0x07: "Delete FDT Entry",
    0x08: "Distribute Broadcast to Network",
    0x09: "Original-Unicast NPDU",
    0x0A: "Original-Broadcast NPDU",
    0x0B: "Secure BVLL",
}


def _ber_len(data: bytes, off: int) -> Tuple[int, int]:
    if off >= len(data):
        return 0, off
    b = data[off]
    if b < 0x80:
        return b, off + 1
    n = b & 0x7F
    if n == 0 or off + 1 + n > len(data):
        return 0, off + 1
    return int.from_bytes(data[off + 1 : off + 1 + n], "big"), off + 1 + n


def decode_http(pkt: Packet) -> Optional[ProtoFact]:
    if not pkt.payload or 80 not in (pkt.dport, pkt.sport):
        return None
    head = pkt.payload[:4096]
    methods = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE ")
    is_req = head.startswith(methods)
    is_resp = head.startswith(b"HTTP/")
    if not (is_req or is_resp):
        return None
    text = head.decode("latin-1", "replace")
    lines = text.split("\r\n")
    fact = ProtoFact(proto="http", summary="", attrs={})
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    if is_req:
        method, path, _ver = (lines[0].split(" ") + ["", ""])[:3]
        fact.attrs.update({"method": method, "path": path, "host": headers.get("host", "")})
        fact.attrs["server"] = ""
        fact.summary = f"HTTP {method} {path}"
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("latin-1", "replace")
            except (binascii.Error, ValueError):
                decoded = ""
            user = decoded.split(":", 1)[0] if decoded else "?"
            fact.attrs["basic_auth_user"] = user
            fact.event(
                "http-basic-auth",
                f"HTTP Basic authentication in clear text for user '{user}' - credential leak on the wire",
                severity="high",
            )
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            fact.event("http-write", f"HTTP {method} {path}", severity="info")
    else:
        parts = lines[0].split(" ", 2)
        code = parts[1] if len(parts) > 1 else "?"
        fact.attrs.update({"status_code": code, "server": headers.get("server", ""), "content_type": headers.get("content-type", "")})
        fact.summary = f"HTTP {code}"
        server = headers.get("server", "")
        if server:
            fact.event("http-server-banner", f"HTTP server banner: {server}", severity="info")
    return fact


def decode_snmp(pkt: Packet) -> Optional[ProtoFact]:
    if 161 not in (pkt.dport, pkt.sport) and 162 not in (pkt.dport, pkt.sport):
        return None
    d = pkt.payload
    if len(d) < 6 or d[0] != 0x30:
        return None
    _total, off = _ber_len(d, 1)
    if off >= len(d) or d[off] != 0x02:
        return None
    vlen, off2 = _ber_len(d, off + 1)
    version = int.from_bytes(d[off2 : off2 + vlen], "big") if vlen else 0
    off3 = off2 + vlen
    community = ""
    if off3 < len(d) and d[off3] == 0x04:
        clen, off4 = _ber_len(d, off3 + 1)
        community = d[off4 : off4 + clen].decode("latin-1", "replace")
    else:
        off4 = off3
    pdutype = d[off4] if off4 < len(d) else None
    pdu_names = {
        0xA0: "GetRequest",
        0xA1: "GetNextRequest",
        0xA2: "GetResponse",
        0xA3: "SetRequest",
        0xA4: "Trap",
        0xA5: "GetBulkRequest",
        0xA7: "Report",
        0xA8: "InformRequest",
    }
    vname = {0: "v1", 1: "v2c", 3: "v3"}.get(version, f"version {version}")
    fact = ProtoFact(
        proto="snmp",
        summary=f"SNMP {vname} {pdu_names.get(pdutype or -1, hex(pdutype or 0))}",
        attrs={"version": version, "version_name": vname, "community": community, "pdu": pdu_names.get(pdutype or -1, "")},
    )
    if version in (0, 1):
        fact.event(
            "snmp-clear-community",
            f"SNMP {vname} with community string sent in clear text" + (" (default community)" if community.lower() in SNMP_DEFAULT_COMMUNITIES else ""),
            severity="high" if community.lower() in SNMP_DEFAULT_COMMUNITIES else "medium",
        )
        if community.lower() in SNMP_DEFAULT_COMMUNITIES:
            fact.event(
                "snmp-default-community",
                f"well-known SNMP community '{community}' in use",
                severity="high",
            )
    if pdutype == 0xA3:
        fact.event("snmp-set", "SNMP SetRequest: configuration change over the network", severity="high")
    return fact


def decode_bacnet(pkt: Packet) -> Optional[ProtoFact]:
    if 47808 not in (pkt.dport, pkt.sport) and not pkt.payload.startswith(b"\x81"):
        return None
    d = pkt.payload
    if len(d) < 4 or d[0] != 0x81:
        return None
    func, blen = d[1], struct.unpack(">H", d[2:4])[0]
    name = BACNET_FUNCS.get(func, f"BVLL 0x{func:02x}")
    fact = ProtoFact(proto="bacnet", summary=f"BACnet/IP {name}", attrs={"function": func, "function_name": name, "length": blen})
    if func in (0x08, 0x0A):
        fact.event("bacnet-broadcast", f"BACnet/IP {name} (broadcast)", severity="info")
    return fact


def decode_dnp3(pkt: Packet) -> Optional[ProtoFact]:
    if 20000 not in (pkt.dport, pkt.sport):
        return None
    d = pkt.payload
    if len(d) < 5 or d[0:2] != b"\x05\x64":
        return None
    length = d[2]
    control = d[3]
    dest, src = struct.unpack("<HH", d[5:9]) if len(d) >= 9 else (None, None)
    fact = ProtoFact(
        proto="dnp3",
        summary=f"DNP3 {length}B control=0x{control:02x} dst={dest} src={src}",
        attrs={"length": length, "control": control, "dest": dest, "src": src},
    )
    if control & 0x40:
        fact.event("dnp3-unsolicited", "DNP3 unsolicited response bit set", severity="info")
    return fact


def decode_service(pkt: Packet) -> Optional[ProtoFact]:
    """Last resort: name the service by port so unknown traffic is still visible."""
    if not pkt.is_tcp and not pkt.is_udp:
        return None
    ports = {p for p in (pkt.dport, pkt.sport) if p}
    known = ports & set(WELL_KNOWN_PORTS)
    if not known:
        return None
    port = min(known)
    name = WELL_KNOWN_PORTS[port]
    fact = ProtoFact(proto="service", summary=f"{name} ({port}/{'tcp' if pkt.is_tcp else 'udp'})", attrs={"service": name, "port": port})
    if port in INSECURE_PORTS and not pkt.flag("RST") and not (pkt.flag("ACK") and not pkt.payload):
        fact.event(
            "insecure-service",
            f"{name} traffic observed on {port}/{'tcp' if pkt.is_tcp else 'udp'} - clear-text or unauthenticated protocol",
            severity="medium",
            service=name,
            port=port,
        )
    if pkt.payload:
        banner = pkt.payload[:64]
        if banner[:4] in (b"SSH-", b"220 ", b"421 "):
            fact.attrs["banner"] = banner.split(b"\r\n")[0].decode("latin-1", "replace")[:80]
            fact.event("service-banner", f"banner: {fact.attrs['banner']}", severity="info")
        if port == 23 and pkt.payload:
            fact.event("telnet-data", "Telnet session data (clear text)", severity="medium")
    return fact


DISSECTORS = [decode_http, decode_snmp, decode_bacnet, decode_dnp3, decode_service]


def decode_any(pkt: Packet) -> Optional[ProtoFact]:
    for fn in DISSECTORS:
        out = fn(pkt)
        if out is not None:
            return out
    return None
