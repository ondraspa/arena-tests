"""S7comm (Siemens S7 / S7-Plus) PDU dissection.

Sits on top of COTP DT PDUs on 102/tcp.  Besides the happy path this decodes
the error class/code of every Ack_Data PDU, because a burst of S7 errors is the
fingerprint of a controller that is being faulted (bad item, protected area,
resource exhaustion) rather than merely slow.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

from ..models import Packet, ProtoFact
from .cotp import decode_cotp, iter_tpkt

ROSCTR = {
    0x01: "Job",
    0x02: "Ack",
    0x03: "Ack_Data",
    0x07: "Userdata",
    0x0F: "S7-Data",
}

FUNC = {
    0x00: "CPU functions (userdata)",
    0x04: "Read Var",
    0x05: "Write Var",
    0x1A: "Download request",
    0x1B: "Download block",
    0x1C: "Download ended",
    0x1D: "Start upload",
    0x1E: "Upload",
    0x1F: "End upload",
    0x28: "PLC Control (insert/start)",
    0x29: "PLC Stop",
    0xF0: "Setup communication",
}

WRITE_FUNCS = {0x05, 0x1A, 0x1B, 0x1C, 0x15, 0x16}
DANGEROUS_FUNCS = {
    0x29: "PLC STOP command",
    0x28: "PLC Control / START command",
    0x1A: "program DOWNLOAD request",
    0x1B: "block DOWNLOAD",
    0x1C: "DOWNLOAD end",
}

ERR_CLASS = {
    0x00: "no error",
    0x81: "application / relationship error",
    0x82: "object definition error",
    0x83: "no resources available",
    0x84: "service processing error",
    0x85: "error on supplies",
    0x86: "version error",
    0x87: "object access error (area protected or not present)",
}

AREA = {
    0x81: "Inputs (I)",
    0x82: "Outputs (Q)",
    0x83: "Flags/Merker (M)",
    0x84: "Data blocks (DB)",
    0x1C: "Counters (C)",
    0x1D: "Timers (T)",
    0x1B: "S7 counters",
    0x1E: "S7 timers",
    0x23: "S7 counters (sys)",
    0x24: "S7 timers (sys)",
}

TRANSPORT_SIZE = {
    0x01: "BIT",
    0x02: "BYTE",
    0x03: "CHAR",
    0x04: "WORD",
    0x05: "INT",
    0x06: "DWORD",
    0x07: "DINT",
    0x08: "REAL",
    0x09: "Date",
    0x12: "STRING",
    0x1D: "STRING",
}

SZL_IDS = {
    0x0011: "module identification",
    0x001C: "component identification",
    0x0111: "module identification (extended)",
    0x0131: "communication capability",
    0x0A10: "station status",
    0x0D91: "operating status of CPU",
    0x0F1E: "firmware version",
}

USERDATA_GROUPS = {
    0x0: "CPU functions",
    0x1: "PBC",
    0x2: "security / protection",
    0x3: "mode transition (START/STOP)",
    0x4: "program invocation",
    0x5: "cyclic data",
    0x6: "block functions",
    0x7: "SZL functions",
    0x8: "password functions",
    0x9: "block functions (extended)",
    0xF: "data exchange",
}


def _ascii(data: bytes) -> str:
    return "".join(chr(b) for b in data if 32 <= b < 127).strip()


def _decode_data_items(data: bytes, count: int, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Decode the data items of a Read/Write Var *response*."""
    items: List[Dict[str, Any]] = []
    i = 0
    for _ in range(count):
        if i + 4 > len(data):
            break
        ret, tsize, bitlen = data[i], data[i + 1], struct.unpack(">H", data[i + 2 : i + 4])[0]
        nbytes = (bitlen + 7) // 8 if tsize in (0x03, 0x04, 0x05, 0x07, 0x09) else bitlen // 8
        if nbytes == 0:
            nbytes = bitlen
        items.append({"return_code": ret, "transport_size": tsize, "bits": bitlen, "bytes": nbytes})
        if ret == 0x0A:
            events.append(
                {"kind": "s7-item-error", "detail": "item returned 'object does not exist'", "severity": "medium"}
            )
        elif ret not in (0x00, 0xFF, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09):
            events.append(
                {
                    "kind": "s7-item-error",
                    "detail": f"item returned error code 0x{ret:02x}",
                    "severity": "medium",
                }
            )
        i += 4 + nbytes + (1 if nbytes % 2 else 0)
    return items


def decode_s7(pdu: bytes) -> Dict[str, Any]:
    """Decode one S7 PDU (the payload of a COTP DT unit)."""
    events: List[Dict[str, Any]] = []
    out: Dict[str, Any] = {"events": events}
    if len(pdu) < 10:
        if pdu:
            events.append({"kind": "s7-short", "detail": f"S7 PDU only {len(pdu)} bytes (min 10)", "severity": "high"})
        return out
    if pdu[0] != 0x32:
        return out
    rosctr = pdu[1]
    out["rosctr"] = rosctr
    out["rosctr_name"] = ROSCTR.get(rosctr, f"unknown 0x{rosctr:02x}")
    if rosctr not in ROSCTR:
        events.append({"kind": "s7-bad-rosctr", "detail": f"unknown ROSCTR 0x{rosctr:02x}", "severity": "medium"})
    out["redundancy"], out["pdu_ref"] = struct.unpack(">HH", pdu[2:6])
    plen, dlen = struct.unpack(">HH", pdu[6:10])
    out["param_len"], out["data_len"] = plen, dlen
    off = 10
    err_class = err_code = 0
    if rosctr in (0x02, 0x03):
        if len(pdu) < 12:
            events.append({"kind": "s7-short", "detail": "Ack_Data missing error class/code", "severity": "high"})
            return out
        err_class, err_code = pdu[10], pdu[11]
        off = 12
        out["err_class"], out["err_code"] = err_class, err_code
        out["err_class_name"] = ERR_CLASS.get(err_class, f"vendor-specific class 0x{err_class:02x}")
    param = pdu[off : off + plen]
    data = pdu[off + plen : off + plen + dlen]
    if plen and len(param) < plen:
        events.append(
            {
                "kind": "s7-param-truncated",
                "detail": f"parameter length {plen} but only {len(param)} bytes present",
                "severity": "high",
            }
        )
    if dlen and len(data) < dlen:
        events.append(
            {
                "kind": "s7-data-truncated",
                "detail": f"data length {dlen} but only {len(data)} bytes present",
                "severity": "high",
            }
        )
    out["param"], out["data"] = param, data

    if not param:
        return out
    func = param[0]
    out["function"] = func
    out["function_name"] = FUNC.get(func, f"function 0x{func:02x}")

    if func in (0x04, 0x05):
        if len(param) < 2:
            events.append({"kind": "s7-malformed", "detail": "Read/Write Var without item count", "severity": "high"})
            return out
        count = param[1]
        out["item_count"] = count
        if rosctr == 0x01:
            # request: the item list is in the parameter
            items = _decode_items(param[2:], count, events)
            out["items"] = items
            if count and not items:
                events.append(
                    {
                        "kind": "s7-item-mismatch",
                        "detail": f"{count} items declared but none decodable - malformed request (known crash vector)",
                        "severity": "high",
                    }
                )
            if func == 0x05:
                out["write"] = True
                for it in items:
                    it["area_name"] = AREA.get(it.get("area", 0), f"area 0x{it.get('area', 0):02x}")
        else:
            # response: the parameter only echoes function + count, the payload
            # carries one data item per requested item
            out["items"] = _decode_data_items(data, count, events)
            if func == 0x05:
                out["write"] = True
    elif func == 0xF0:
        # setup communication: function, reserved, Max AmQ calling, Max AmQ called, PDU length
        if len(param) >= 8:
            amq_c, amq_s, pdu_len = struct.unpack(">HHH", param[2:8])
            out["setup"] = {"amq_calling": amq_c, "amq_called": amq_s, "pdu_length": pdu_len}
            if pdu_len > 480:
                events.append(
                    {
                        "kind": "s7-pdu-too-big",
                        "detail": f"setup communication requests PDU length {pdu_len} (S7-300/400 max 480)",
                        "severity": "medium",
                    }
                )
            if amq_c > 32 or amq_s > 32:
                events.append(
                    {
                        "kind": "s7-amq-excess",
                        "detail": f"setup communication requests {amq_c}/{amq_s} acknowledged queues (resource exhaustion risk)",
                        "severity": "medium",
                    }
                )
        else:
            events.append({"kind": "s7-malformed", "detail": "truncated Setup communication parameter", "severity": "high"})
    elif func in DANGEROUS_FUNCS:
        events.append(
            {
                "kind": "s7-control-command",
                "detail": f"{DANGEROUS_FUNCS[func]} in request",
                "severity": "critical",
                "action": FUNC.get(func, f"0x{func:02x}"),
            }
        )
    elif func == 0x00:
        # userdata
        # userdata parameter: 00 01 12 <len> <ptype> <group> <subfunction> <seq>
        if len(param) >= 8 and param[1] == 0x01 and param[2] == 0x12:
            ptype = param[4]
            group = param[5]
            sub = param[6]
            out["userdata"] = {"ptype": ptype, "group": group, "subfunction": sub}
            out["userdata_group_name"] = USERDATA_GROUPS.get(group, f"group 0x{group:02x}")
            if group == 0x08:
                events.append(
                    {"kind": "s7-password", "detail": "S7 password function requested", "severity": "high"}
                )
            if group == 0x03:
                events.append(
                    {
                        "kind": "s7-mode-transition",
                        "detail": f"S7 mode transition request (subfunction 0x{sub or 0:02x})",
                        "severity": "high",
                    }
                )
            if group == 0x07 and len(data) >= 4:
                # data may carry the S7 data header (return code, transport size,
                # length) and, in responses, an SZL header-length field
                off = 0
                if data[0] in (0xFF, 0x00, 0x0A) and len(data) >= 4:
                    off = 4
                szl_id = szl_idx = 0
                body = data[off:]
                if len(body) >= 6 and struct.unpack(">H", body[0:2])[0] == 0x0008:
                    szl_id, szl_idx = struct.unpack(">HH", body[2:6])
                    body = body[6:]
                elif len(body) >= 4:
                    szl_id, szl_idx = struct.unpack(">HH", body[0:4])
                    body = body[4:]
                out["szl_id"], out["szl_index"] = szl_id, szl_idx
                out["szl_name"] = SZL_IDS.get(szl_id, f"SZL 0x{szl_id:04x}")
                if szl_id in (0x0011, 0x001C, 0x0111):
                    text = _ascii(data)
                    if text:
                        out["szl_text"] = text
    if err_class:
        events.append(
            {
                "kind": "s7-error",
                "detail": (
                    f"S7 error class 0x{err_class:02x} ({ERR_CLASS.get(err_class, 'vendor-specific')}) "
                    f"code 0x{err_code:02x} on {out.get('function_name', 'response')}"
                ),
                "severity": "high",
                "err_class": err_class,
                "err_code": err_code,
            }
        )
    return out


def _decode_items(param: bytes, count: int, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    i = 0
    for _ in range(count):
        if i + 2 > len(param):
            break
        if param[i] != 0x12:
            events.append(
                {
                    "kind": "s7-malformed",
                    "detail": f"var item does not start with 0x12 (got 0x{param[i]:02x})",
                    "severity": "high",
                }
            )
            break
        ilen = param[i + 1]
        if i + 2 + ilen > len(param) or ilen < 2:
            events.append(
                {"kind": "s7-malformed", "detail": f"var item length {ilen} overruns parameter", "severity": "high"}
            )
            break
        body = param[i + 2 : i + 2 + ilen]
        item: Dict[str, Any] = {"syntax_id": body[0], "transport_size": body[1] if len(body) > 1 else None}
        if len(body) >= 10:
            # S7ANY item: syntax_id(1), transport_size(1), length(2), db(2), area(1), address(3)
            tsize, length, db, area = struct.unpack(">BHHB", body[1:7])
            addr = int.from_bytes(body[7:10], "big")
            item.update(
                {
                    "transport_size": tsize,
                    "length": length,
                    "db": db,
                    "area": area,
                    "address": addr,
                    "area_name": AREA.get(area, f"area 0x{area:02x}"),
                }
            )
            if length == 0:
                events.append(
                    {"kind": "s7-malformed", "detail": f"var item with length 0 in {item['area_name']}", "severity": "medium"}
                )
            if area not in AREA:
                events.append(
                    {"kind": "s7-malformed", "detail": f"unknown area 0x{area:02x}", "severity": "high"}
                )
        else:
            events.append({"kind": "s7-malformed", "detail": "short S7ANY item", "severity": "high"})
        items.append(item)
        i += 2 + ilen
    return items


def decode(pkt: Packet) -> Optional[ProtoFact]:
    """Dissector entry point: find S7 PDUs inside TPKT/COTP on 102/tcp."""
    if len(pkt.payload) < 4 or pkt.payload[0] != 3:
        return None
    if 102 not in (pkt.dport, pkt.sport):
        return None
    fact = ProtoFact(proto="s7comm", summary="")
    pdus: List[Dict[str, Any]] = []
    for unit in iter_tpkt(pkt.payload):
        if unit["kind"] != "pdu":
            continue
        cotp = decode_cotp(bytes(unit.get("data", b"")))
        if cotp.get("type") != 0xF0:
            continue
        body = cotp.get("data", b"")
        if not body or body[0] != 0x32:
            continue
        info = decode_s7(bytes(body))
        evs = info.pop("events", [])
        pdus.append(info)
        for ev in evs:
            kind = str(ev.get("kind", ""))
            if not kind.startswith("s7-"):
                kind = f"s7-{kind}"
            fact.event(
                kind,
                str(ev.get("detail", "")),
                severity=str(ev.get("severity", "info")),
                **{k: v for k, v in ev.items() if k not in ("kind", "detail", "severity")},
            )
    if not pdus and not fact.events:
        return None
    labels = []
    for d in pdus:
        name = d.get("function_name") or d.get("rosctr_name") or "?"
        if d.get("rosctr") == 0x03 and d.get("err_class"):
            name += f" ERR 0x{d['err_class']:02x}/0x{d.get('err_code', 0):02x}"
        if d.get("userdata_group_name"):
            name += f" [{d['userdata_group_name']}]"
        labels.append(f"{d.get('rosctr_name', '?')}:{name}")
    fact.summary = "S7 " + ", ".join(labels)
    fact.attrs["pdus"] = [
        {k: v for k, v in d.items() if k not in ("param", "data")} for d in pdus
    ]
    return fact
