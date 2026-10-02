"""EtherNet/IP encapsulation + CIP explicit messaging (Rockwell / Allen-Bradley).

Identity is parsed structurally (item type 0x000C) so a fingerprint is produced
even if the encapsulation command code table of a vendor implementation differs.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional

from ..models import Packet, ProtoFact

ENCAP_COMMANDS = {
    0x0000: "NOP",
    0x0063: "ListServices",
    0x0064: "ListIdentity",
    0x0065: "ListInterfaces",
    0x0066: "RegisterSession",
    0x0067: "UnRegisterSession",
    0x006F: "SendRRData",
    0x0070: "SendUnitData",
    0x0072: "IndicateStatus",
    0x0073: "Cancel",
}

ENCAP_STATUS = {
    0x0000: "success",
    0x0001: "invalid or unsupported command",
    0x0002: "insufficient memory resources",
    0x0003: "malformed or incorrect data",
    0x0064: "invalid session handle",
    0x0065: "invalid length",
    0x0066: "unsupported protocol revision",
    0x0069: "encapsulation error",
}

ITEM_TYPES = {
    0x0000: "Null Address",
    0x00A1: "Connected Address",
    0x00B1: "Connected Data",
    0x00B2: "Unconnected Data",
    0x000C: "List Identity",
    0x008A: "Sequenced Address",
    0x0100: "Safety",
}

# Partial ODVA vendor list -- extend as needed, the raw id is always reported.
VENDOR_IDS = {
    1: "Rockwell Automation / Allen-Bradley",
    3: "Honeywell",
    10: "Omron",
    100: "Schneider Electric",
    190: "Festo",
    283: "Beckhoff",
    311: "Endress+Hauser",
    453: "B&R",
    666: "Siemens (CIP gateway)",
}

DEVICE_TYPES = {
    0x00: "Generic",
    0x02: "AC Drive",
    0x03: "Motor Overload",
    0x04: "Limit Switch",
    0x05: "Inductive Proximity Switch",
    0x06: "Photoelectric Sensor",
    0x07: "General Purpose Discrete I/O",
    0x09: "Resolver",
    0x0C: "Communications Adapter",
    0x0E: "Programmable Controller",
    0x10: "Position Controller",
    0x13: "DC Drive",
    0x15: "Contactor",
    0x18: "Mass Flow Controller",
    0x1B: "Programmable Logic Controller",
    0x20: "Human Interface",
    0x21: "Mass Flow Controller",
    0x25: "Network Security Device",
    0x29: "Discrete Input Group",
    0x2B: "Managed Switch",
    0x3F: "Safety Supervisor",
}

CIP_SERVICES = {
    0x01: "Get Attributes All",
    0x02: "Set Attributes All",
    0x03: "Get Attribute List",
    0x04: "Set Attribute List",
    0x05: "Reset",
    0x0E: "Get Attribute Single",
    0x10: "Set Attribute Single",
    0x4B: "Execute PCCC Service",
    0x4C: "Read Tag Service",
    0x4D: "Write Tag Service",
    0x4E: "Read Tag Fragmented",
    0x4F: "Write Tag Fragmented",
    0x52: "Unconnected Send",
    0x54: "Forward Open",
    0x4E2: "Forward Close",
}

WRITE_SERVICES = {0x02, 0x04, 0x05, 0x10, 0x4D, 0x4F, 0x4B}

CIP_STATUS = {
    0x00: "success",
    0x01: "connection failure",
    0x02: "resource unavailable",
    0x03: "invalid parameter value",
    0x04: "path segment error",
    0x05: "path destination unknown",
    0x06: "partial transfer",
    0x07: "connection lost",
    0x08: "service not supported",
    0x09: "invalid attribute value",
    0x0A: "attribute list error",
    0x0B: "already in requested state",
    0x0C: "object state conflict",
    0x0D: "object already exists",
    0x0E: "attribute not settable",
    0x0F: "privilege violation",
    0x10: "device state conflict",
    0x11: "reply data too large",
    0x13: "insufficient command data",
    0x14: "attribute not supported",
    0x16: "object does not exist",
    0x1C: "vendor specific",
    0x1E: "invalid parameter",
    0x22: "embedded service error",
    0x25: "key failure in path",
    0x26: "path size invalid",
    0xFF: "general error",
}


def decode_path(path: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"classes": [], "instances": [], "attributes": [], "symbols": []}
    i = 0
    while i < len(path):
        seg = path[i]
        if seg == 0x20 and i + 1 < len(path):
            out["classes"].append(path[i + 1])
            i += 2
        elif seg == 0x21 and i + 3 < len(path):
            out["classes"].append(struct.unpack("<H", path[i + 2 : i + 4])[0])
            i += 4
        elif seg == 0x24 and i + 1 < len(path):
            out["instances"].append(path[i + 1])
            i += 2
        elif seg == 0x25 and i + 3 < len(path):
            out["instances"].append(struct.unpack("<H", path[i + 2 : i + 4])[0])
            i += 4
        elif seg == 0x30 and i + 1 < len(path):
            out["attributes"].append(path[i + 1])
            i += 2
        elif seg == 0x91 and i + 1 < len(path):
            ln = path[i + 1]
            name = path[i + 2 : i + 2 + ln].decode("ascii", "replace")
            out["symbols"].append(name)
            i += 2 + ln + (ln % 2)
        elif seg in (0x28, 0x29) and i + 1 < len(path):
            i += 2 + path[i + 1]
        else:
            break
    return out


def decode_identity(data: bytes) -> Optional[Dict[str, Any]]:
    """Decode a List Identity item body (item type 0x000C).

    Layout: encap version(2), socket addr info(16), vendor(2), device type(2),
    product code(2), revision(1+1), status(2), serial(4), name(len+ascii), state(1)
    """
    if len(data) < 33:
        return None
    (proto_ver,) = struct.unpack("<H", data[0:2])
    sin_port = struct.unpack(">H", data[4:6])[0]
    vendor, dev_type, prod_code = struct.unpack("<HHH", data[18:24])
    rev_major, rev_minor = data[24], data[25]
    (status,) = struct.unpack("<H", data[26:28])
    (serial,) = struct.unpack("<I", data[28:32])
    nlen = data[32]
    name = data[33 : 33 + nlen].decode("ascii", "replace")
    state = data[33 + nlen] if len(data) >= 34 + nlen else None
    return {
        "encap_version": proto_ver,
        "port": sin_port,
        "ip": ".".join(str(b) for b in data[6:10]),
        "vendor_id": vendor,
        "vendor": VENDOR_IDS.get(vendor, f"vendor {vendor}"),
        "device_type": dev_type,
        "device_type_name": DEVICE_TYPES.get(dev_type, f"type 0x{dev_type:02x}"),
        "product_code": prod_code,
        "revision": f"{rev_major}.{rev_minor}",
        "status": status,
        "serial": f"{serial:08x}",
        "product_name": name,
        "state": state,
    }


def decode(pkt: Packet) -> Optional[ProtoFact]:
    if len(pkt.payload) < 24:
        return None
    if 44818 not in (pkt.dport, pkt.sport) and 2222 not in (pkt.dport, pkt.sport):
        return None
    command, length, session, status = struct.unpack("<HHII", pkt.payload[:12])
    options = struct.unpack("<I", pkt.payload[20:24])[0]
    if command not in ENCAP_COMMANDS and command > 0x00FF:
        return None
    fact = ProtoFact(proto="enip", summary="")
    cmd_name = ENCAP_COMMANDS.get(command, f"command 0x{command:04x}")
    fact.attrs.update({"command": command, "command_name": cmd_name, "session": session, "status": status})
    if command not in ENCAP_COMMANDS:
        fact.event("enip-unknown-command", f"unknown encapsulation command 0x{command:04x}", severity="medium")
    if status != 0:
        fact.event(
            "enip-error",
            f"{cmd_name} answered with encapsulation status 0x{status:04x} ({ENCAP_STATUS.get(status, 'unknown')})",
            severity="high" if status not in (0x0064,) else "medium",
            status=status,
        )
    if options != 0:
        fact.event("enip-options", f"non-zero encapsulation options 0x{options:08x}", severity="low")
    body = pkt.payload[24 : 24 + length] if length else pkt.payload[24:]
    if length and len(pkt.payload) - 24 < length:
        fact.event(
            "enip-length-mismatch",
            f"encapsulation length {length} exceeds captured body ({len(pkt.payload) - 24})",
            severity="high",
        )

    if command in (0x0063, 0x0064, 0x0065):
        ident = _scan_identities(body, fact)
        if ident:
            fact.attrs["identity"] = ident
            fact.summary = f"EtherNet/IP {cmd_name}: {ident.get('vendor')} {ident.get('product_name')} rev {ident.get('revision')}"
            return fact
        fact.summary = f"EtherNet/IP {cmd_name}"
        return fact

    if command in (0x0066,):
        if len(body) >= 4:
            pv, of = struct.unpack("<HH", body[0:4])
            fact.attrs["register"] = {"protocol_version": pv, "option_flags": of}
            if pv != 1:
                fact.event("enip-bad-version", f"RegisterSession protocol version {pv} (expected 1)", severity="medium")
        fact.summary = f"EtherNet/IP {cmd_name} (session 0x{session:08x})"
        return fact

    if command in (0x006F, 0x0070):
        cip = _decode_cpf(body, fact)
        fact.attrs.update(cip)
        label = cmd_name
        if cip.get("service_name"):
            label += f": {cip['service_name']}"
            if cip.get("symbol"):
                label += f" [{cip['symbol']}]"
            if cip.get("is_response"):
                label += f" status={cip.get('status_name')}"
        fact.summary = f"EtherNet/IP {label}"
        return fact

    fact.summary = f"EtherNet/IP {cmd_name}"
    return fact


def _scan_identities(body: bytes, fact: ProtoFact) -> Optional[Dict[str, Any]]:
    """Find identity items either inside a CPF list or as a bare identity body."""
    found: Optional[Dict[str, Any]] = None
    # ListIdentity/ListServices replies carry the item count first; SendRRData
    # prefixes an interface handle (4) + timeout (2).  Try both layouts and keep
    # the one whose first item really is an identity item.
    for count_at in (0, 6):
        if len(body) < count_at + 6:
            continue
        count = struct.unpack("<H", body[count_at : count_at + 2])[0]
        if not 0 < count < 32:
            continue
        off = count_at + 2
        if off + 4 > len(body):
            continue
        itype, ilen = struct.unpack("<HH", body[off : off + 4])
        if itype != 0x000C:
            continue
        for _ in range(count):
            if off + 4 > len(body):
                break
            itype, ilen = struct.unpack("<HH", body[off : off + 4])
            data = body[off + 4 : off + 4 + ilen]
            if itype == 0x000C:
                ident = decode_identity(data)
                if ident:
                    found = ident
                    fact.event(
                        "enip-identity",
                        f"identity: {ident['vendor']} {ident['product_name']} "
                        f"({ident['device_type_name']}, rev {ident['revision']}, serial {ident['serial']})",
                        severity="info",
                        identity=ident,
                    )
            off += 4 + ilen
        if found:
            break
    if found:
        return found
    ident = decode_identity(body)
    if ident:
        fact.event(
            "enip-identity",
            f"identity: {ident['vendor']} {ident['product_name']} ({ident['device_type_name']}, rev {ident['revision']})",
            severity="info",
            identity=ident,
        )
    return ident


def _decode_cpf(body: bytes, fact: ProtoFact) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if len(body) < 10:
        return out
    iface, timeout, count = struct.unpack("<IHH", body[0:8])
    out["cpf_count"] = count
    off = 8
    cip_data = b""
    for _ in range(count):
        if off + 4 > len(body):
            fact.event("enip-cpf-truncated", "CPF item header truncated", severity="medium")
            break
        itype, ilen = struct.unpack("<HH", body[off : off + 4])
        data = body[off + 4 : off + 4 + ilen]
        out.setdefault("item_types", []).append(ITEM_TYPES.get(itype, f"0x{itype:04x}"))
        if itype in (0x00B2, 0x00B1):
            cip_data = data
        elif itype == 0x000C:
            ident = decode_identity(data)
            if ident:
                out["identity"] = ident
        off += 4 + ilen
    if not cip_data:
        return out
    if cip_data[0] & 0x80:
        # reply
        service = cip_data[0] & 0x7F
        gstatus = cip_data[2] if len(cip_data) > 2 else 0
        add_size = cip_data[3] if len(cip_data) > 3 else 0
        add = []
        for i in range(add_size):
            if len(cip_data) >= 6 + 2 * i:
                add.append(struct.unpack("<H", cip_data[4 + 2 * i : 6 + 2 * i])[0])
        out.update(
            {
                "is_response": True,
                "service": service,
                "service_name": CIP_SERVICES.get(service, f"service 0x{service:02x}"),
                "status": gstatus,
                "status_name": CIP_STATUS.get(gstatus, f"status 0x{gstatus:02x}"),
                "additional_status": add,
            }
        )
        if gstatus != 0:
            sev = "high" if gstatus in (0x01, 0x02, 0x07, 0x10) else "medium"
            fact.event(
                "cip-error",
                f"CIP {out['service_name']} reply status 0x{gstatus:02x} ({out['status_name']})"
                + (f" additional={['0x%04x' % a for a in add]}" if add else ""),
                severity=sev,
                cip_status=gstatus,
            )
    else:
        service = cip_data[0]
        psize = cip_data[1] if len(cip_data) > 1 else 0
        path = cip_data[2 : 2 + 2 * psize]
        parsed = decode_path(path)
        out.update(
            {
                "is_response": False,
                "service": service,
                "service_name": CIP_SERVICES.get(service, f"service 0x{service:02x}"),
                "path": parsed,
                "symbol": parsed["symbols"][0] if parsed["symbols"] else None,
            }
        )
        if service in WRITE_SERVICES:
            fact.event(
                "cip-write",
                f"CIP {out['service_name']}" + (f" tag '{out['symbol']}'" if out["symbol"] else "")
                + f" class={parsed['classes']} instance={parsed['instances']}",
                severity="info",
                cip_service=service,
            )
        if service == 0x05:
            fact.event("cip-reset", "CIP Reset service requested against a controller", severity="critical")
    return out
