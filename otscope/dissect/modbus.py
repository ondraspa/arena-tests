"""Modbus TCP (MBAP + PDU).

Exception responses are decoded in full: on a Modicon/Quantum an "uncaught
exception reading memory blocks with an invalid data size or offset" is a
documented denial of service (CISA ICSA-25-114-01 / CVE-2018-7843), so a stream
of exception codes 0x02/0x03/0x04 is treated as a fault signature, not noise.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional

from ..models import Packet, ProtoFact

FUNCTIONS = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0B: "Get Comm Event Counter",
    0x0C: "Get Comm Event Log",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Server ID",
    0x14: "Read File Record",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x18: "Read FIFO Queue",
    0x2B: "Encapsulated Interface Transport",
}

WRITE_FUNCTIONS = {0x05, 0x06, 0x0F, 0x10, 0x15, 0x16, 0x17}

EXCEPTIONS = {
    0x01: "Illegal Function",
    0x02: "Illegal Data Address",
    0x03: "Illegal Data Value",
    0x04: "Server Device Failure",
    0x05: "Acknowledge (long running operation)",
    0x06: "Server Device Busy",
    0x07: "Negative Acknowledge",
    0x08: "Memory Parity Error",
    0x09: "Gateway Path Unavailable (legacy)",
    0x0A: "Gateway Path Unavailable",
    0x0B: "Gateway Target Device Failed to Respond",
}

DIAG_SUBFUNCTIONS = {
    0x0000: "Return Query Data",
    0x0001: "Restart Communications",
    0x000A: "Clear Counters",
    0x0014: "Clear Overrun Counter",
}

MEI_TYPES = {0x0D: "CANopen general reference", 0x0E: "Read Device Identification", 0x0F: "reserved"}

DEVICE_ID_OBJECTS = {
    0x00: "VendorName",
    0x01: "ProductCode",
    0x02: "MajorMinorRevision",
    0x03: "VendorURL",
    0x04: "ProductName",
    0x05: "ModelName",
    0x06: "UserApplicationName",
}


def decode(pkt: Packet) -> Optional[ProtoFact]:
    if len(pkt.payload) < 8:
        return None
    if 502 not in (pkt.dport, pkt.sport):
        return None
    txid, proto_id, length, unit = struct.unpack(">HHHB", pkt.payload[:7])
    fact = ProtoFact(proto="modbus", summary="")
    if proto_id != 0:
        fact.event(
            "modbus-bad-protocol-id",
            f"MBAP protocol identifier {proto_id} (expected 0): not Modbus TCP or forged",
            severity="high",
        )
        fact.summary = f"Modbus TCP (bad protocol id {proto_id})"
        fact.attrs.update({"txid": txid, "unit": unit, "proto_id": proto_id})
        return fact
    avail = len(pkt.payload) - 7
    if length - 1 != avail:
        fact.event(
            "modbus-length-mismatch",
            f"MBAP length field {length} vs {avail + 1} bytes present (fragmented, forged or non-Modbus on 502)",
            severity="high",
        )
    fact.attrs.update({"txid": txid, "unit": unit, "mbap_length": length})
    pdu = pkt.payload[7:]
    if not pdu:
        fact.summary = "Modbus TCP (empty PDU)"
        return fact
    fc = pdu[0]
    fact.attrs["function"] = fc

    if fc & 0x80:
        base = fc & 0x7F
        code = pdu[1] if len(pdu) > 1 else None
        name = EXCEPTIONS.get(code or -1, f"exception 0x{code:02x}" if code is not None else "?")
        fact.attrs.update({"exception": code, "exception_name": name, "base_function": base})
        sev = "high" if code in (0x04, 0x08, 0x0B) else "medium" if code in (0x02, 0x03) else "info"
        fact.event(
            "modbus-exception",
            f"{FUNCTIONS.get(base, f'FC 0x{base:02x}')} answered with {name} (unit {unit})",
            severity=sev,
            exception_code=code,
            exception_name=name,
            base_function=base,
        )
        if base == 0x08:
            fact.event(
                "modbus-diagnostic",
                "diagnostics request answered with an exception",
                severity="medium",
            )
        fact.summary = f"Modbus exception: {name}"
        return fact

    name = FUNCTIONS.get(fc, f"FC 0x{fc:02x}")
    fact.attrs["function_name"] = name
    if fc not in FUNCTIONS:
        fact.event(
            "modbus-unknown-function",
            f"unknown function code 0x{fc:02x}",
            severity="medium",
        )
    if fc in WRITE_FUNCTIONS:
        fact.attrs["write"] = True
        detail = name
        if fc == 0x06 and len(pdu) >= 5:
            addr, val = struct.unpack(">HH", pdu[1:5])
            detail = f"{name} addr={addr} value={val}"
            fact.attrs.update({"address": addr, "value": val})
        elif fc == 0x05 and len(pdu) >= 5:
            addr, val = struct.unpack(">HH", pdu[1:5])
            state = "ON" if val == 0xFF00 else ("OFF" if val == 0 else f"invalid 0x{val:04x}")
            detail = f"{name} addr={addr} -> {state}"
            fact.attrs.update({"address": addr, "value": val, "coil_state": state})
            if val not in (0x0000, 0xFF00):
                fact.event(
                    "modbus-malformed",
                    f"Write Single Coil with value 0x{val:04x} (must be 0x0000 or 0xFF00)",
                    severity="high",
                )
        elif fc == 0x10 and len(pdu) >= 6:
            addr, count, nbytes = struct.unpack(">HHB", pdu[1:6])
            detail = f"{name} addr={addr} count={count}"
            fact.attrs.update({"address": addr, "count": count})
            if len(pdu) >= 6 + nbytes and nbytes != count * 2:
                fact.event(
                    "modbus-malformed",
                    f"Write Multiple Registers byte count {nbytes} != count {count} * 2",
                    severity="high",
                )
        elif fc == 0x0F and len(pdu) >= 6:
            addr, count, nbytes = struct.unpack(">HHB", pdu[1:6])
            detail = f"{name} addr={addr} count={count}"
            fact.attrs.update({"address": addr, "count": count})
        elif fc == 0x16 and len(pdu) >= 7:
            addr, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
            detail = f"{name} addr={addr} and=0x{and_mask:04x} or=0x{or_mask:04x}"
            fact.attrs.update({"address": addr})
        fact.event("modbus-write", detail, severity="info", function=fc)
        if unit == 0:
            fact.event(
                "modbus-broadcast-write",
                f"broadcast write ({detail}) to unit 0 - no response will be returned, failures are silent",
                severity="high",
            )
    elif fc == 0x08:
        sub = struct.unpack(">H", pdu[1:3])[0] if len(pdu) >= 3 else None
        fact.attrs["diag_subfunction"] = sub
        sub_name = DIAG_SUBFUNCTIONS.get(sub or -1, f"subfunction 0x{sub or 0:04x}")
        fact.attrs["diag_name"] = sub_name
        if sub in (0x0001, 0x000A, 0x0014):
            fact.event(
                "modbus-diagnostic-command",
                f"Modbus diagnostics: {sub_name} - this resets the device communication stack",
                severity="critical",
                subfunction=sub,
            )
        fact.summary = f"Modbus {name} ({sub_name})"
        return fact
    elif fc == 0x2B:
        info = _decode_mei(pdu, fact)
        fact.attrs.update(info)
        fact.summary = f"Modbus {name}: {info.get('mei_name', '')}"
        return fact
    else:
        if fc in (0x01, 0x02, 0x03, 0x04) and len(pdu) >= 5:
            addr, count = struct.unpack(">HH", pdu[1:5])
            fact.attrs.update({"address": addr, "count": count})
            if count == 0:
                fact.event(
                    "modbus-malformed",
                    f"{name} with quantity 0",
                    severity="medium",
                )
        if fc in (0x03, 0x04) and fact.attrs.get("count") is None and len(pdu) > 1:
            # response frame: byte count + data
            nbytes = pdu[1]
            fact.attrs["byte_count"] = nbytes
            if nbytes and len(pdu) < 2 + nbytes:
                fact.event(
                    "modbus-malformed",
                    f"{name} response byte count {nbytes} exceeds PDU ({len(pdu) - 2} bytes)",
                    severity="high",
                )
    fact.summary = f"Modbus {name} (unit {unit})"
    return fact


def _decode_mei(pdu: bytes, fact: ProtoFact) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if len(pdu) < 3:
        fact.event("modbus-malformed", "truncated MEI request", severity="high")
        return out
    mei = pdu[1]
    out["mei"] = mei
    out["mei_name"] = MEI_TYPES.get(mei, f"MEI 0x{mei:02x}")
    if mei != 0x0E:
        return out
    dev_id = pdu[2]
    out["device_id_level"] = dev_id
    # response form: MEI(1), ReadDevID code(1), conformity(1), MoreFollows(1),
    #                NextObjectID(1), NumberOfObjects(1), objects...
    if len(pdu) >= 7:
        out["conformity"] = pdu[3]
        num_obj = pdu[6]
        out["object_count"] = num_obj
        off = 7
        objs: Dict[str, str] = {}
        for _ in range(num_obj):
            if off + 2 > len(pdu):
                break
            oid, olen = pdu[off], pdu[off + 1]
            if off + 2 + olen > len(pdu):
                fact.event("modbus-malformed", "device identification object overruns PDU", severity="medium")
                break
            text = pdu[off + 2 : off + 2 + olen].decode("ascii", "replace")
            objs[DEVICE_ID_OBJECTS.get(oid, f"0x{oid:02x}")] = text
            off += 2 + olen
        out["device_id"] = objs
        if objs:
            fact.event(
                "modbus-device-identification",
                "Modbus device identification: " + ", ".join(f"{k}={v}" for k, v in objs.items()),
                severity="info",
                device_id=objs,
            )
    return out
