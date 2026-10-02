"""TPKT (RFC 1006) + ISO-on-TCP COTP (RFC 905) -- the transport under S7comm.

Malformed COTP/TPKT is the single most common way an S7 CPU is knocked into
defect mode (see advisory records ICSA-15-064-04 / ICSA-18-079-02), so every
length and parameter inconsistency is reported as an event.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from ..models import Packet, ProtoFact

COTP_PDUS = {
    0xE0: "CR (connect request)",
    0xD0: "CC (connect confirm)",
    0x80: "DR (disconnect request)",
    0xF0: "DT (data)",
    0x70: "ER (error)",
    0x10: "AK (ack)",
    0xC0: "RJ (reject)",
}

TSAP_CLASSES = {
    0x01: "PG (programmer)",
    0x02: "OP (operator panel)",
    0x03: "S7 basic / CPU-to-CPU",
    0x00: "reserved/unknown",
}

TPDU_SIZE_CODES = {
    0x07: 128,
    0x08: 256,
    0x09: 512,
    0x0A: 1024,
    0x0B: 2048,
    0x0C: 4096,
    0x0D: 8192,
}


def tsap_class(tsap: bytes) -> str:
    if not tsap:
        return "empty"
    return TSAP_CLASSES.get(tsap[0], f"unknown 0x{tsap[0]:02x}")


def rack_slot(called_tsap: bytes) -> Optional[Tuple[int, int]]:
    """Decode the Siemens rack/slot encoding of the called TSAP."""
    if len(called_tsap) < 2:
        return None
    v = called_tsap[1]
    return (v >> 5) & 0x07, v & 0x1F


def iter_tpkt(payload: bytes) -> List[Dict[str, object]]:
    """Split a TCP payload into TPKT units, flagging inconsistencies."""
    units: List[Dict[str, object]] = []
    off = 0
    n = len(payload)
    while off < n:
        if n - off < 4:
            units.append({"kind": "malformed", "detail": f"TPKT header truncated ({n - off} bytes left)", "offset": off})
            break
        ver, res, length = struct.unpack(">BBH", payload[off : off + 4])
        if ver != 3:
            units.append(
                {
                    "kind": "malformed",
                    "detail": f"TPKT version {ver} (expected 3) at offset {off}",
                    "offset": off,
                }
            )
            break
        if length < 7:
            units.append(
                {
                    "kind": "malformed",
                    "detail": f"TPKT length {length} below minimum (7)",
                    "offset": off,
                    "length": length,
                }
            )
            # A bogus length field is a classic S7 crash vector: keep going with
            # the remaining bytes so the analyser still sees the PDU.
            units.append({"kind": "pdu", "data": payload[off + 4 :], "offset": off, "length": length, "bad_length": True})
            break
        if off + length > n:
            units.append(
                {
                    "kind": "malformed",
                    "detail": f"TPKT length {length} exceeds captured bytes ({n - off}) - fragmented or forged",
                    "offset": off,
                    "length": length,
                }
            )
            units.append({"kind": "pdu", "data": payload[off + 4 : n], "offset": off, "length": length, "short": True})
            break
        units.append({"kind": "pdu", "data": payload[off + 4 : off + length], "offset": off, "length": length})
        off += length
    return units


def decode_cotp(data: bytes) -> Dict[str, object]:
    """Decode one COTP PDU.  Returns a dict with parsed fields + events."""
    events: List[Dict[str, object]] = []
    out: Dict[str, object] = {"events": events, "type": None}
    if not data:
        events.append({"kind": "cotp-empty", "detail": "empty COTP PDU inside TPKT", "severity": "medium"})
        return out
    li = data[0]
    if li + 1 > len(data):
        events.append(
            {
                "kind": "cotp-li-mismatch",
                "detail": f"COTP length indicator {li} exceeds PDU bytes ({len(data)})",
                "severity": "high",
            }
        )
        li = len(data) - 1
    if len(data) < 2:
        events.append({"kind": "cotp-truncated", "detail": "COTP PDU truncated before PDU type", "severity": "high"})
        return out
    ptype = data[1]
    # For DT PDUs everything after the header is user data, so "trailing data"
    # is only an inconsistency for the header-only PDU types.
    if li + 1 < len(data) and ptype != 0xF0:
        events.append(
            {
                "kind": "cotp-li-mismatch",
                "detail": f"COTP length indicator {li} shorter than PDU ({len(data)} bytes): trailing data",
                "severity": "medium",
            }
        )
    out["type"] = ptype
    out["type_name"] = COTP_PDUS.get(ptype, f"unknown 0x{ptype:02x}")
    if ptype not in COTP_PDUS:
        events.append(
            {"kind": "cotp-unknown-pdu", "detail": f"unknown COTP PDU type 0x{ptype:02x}", "severity": "medium"}
        )
    body = data[2 : li + 1]

    if ptype in (0xE0, 0xD0):
        if len(body) < 5:
            events.append({"kind": "cotp-truncated", "detail": "CR/CC PDU too short for header", "severity": "high"})
            return out
        dst_ref, src_ref, cls = struct.unpack(">HHB", body[:5])
        out["dst_ref"], out["src_ref"], out["class"] = dst_ref, src_ref, cls
        params = body[5:]
        i = 0
        tpdu_size = None
        calling = called = b""
        while i + 2 <= len(params):
            code = params[i]
            plen = params[i + 1]
            if i + 2 + plen > len(params):
                events.append(
                    {
                        "kind": "cotp-param-overflow",
                        "detail": f"parameter 0x{code:02x} length {plen} overruns PDU",
                        "severity": "high",
                    }
                )
                break
            val = params[i + 2 : i + 2 + plen]
            if code == 0xC0:
                if plen >= 1:
                    tpdu_size = TPDU_SIZE_CODES.get(val[0], 2 ** (7 + val[0]) if val[0] >= 7 else None)
                    out["tpdu_size_code"] = val[0]
                    out["tpdu_size"] = tpdu_size
                    if val[0] > 0x0D:
                        events.append(
                            {
                                "kind": "cotp-bad-tpdu-size",
                                "detail": f"TPDU size code 0x{val[0]:02x} outside 0x07-0x0D",
                                "severity": "high",
                            }
                        )
                else:
                    events.append({"kind": "cotp-empty-param", "detail": "empty TPDU-size parameter", "severity": "medium"})
            elif code == 0xC1:
                calling = val
            elif code == 0xC2:
                called = val
            i += 2 + plen
        out["calling_tsap"] = calling
        out["called_tsap"] = called
        out["calling_class"] = tsap_class(calling)
        out["rack_slot"] = rack_slot(called) if called else None
        if ptype == 0xE0 and not called:
            events.append({"kind": "cotp-no-called-tsap", "detail": "connect request without called TSAP", "severity": "low"})
        return out

    if ptype == 0xF0:
        # DT header is (length indicator, PDU type, TPDU nr/EOT) = li + 1 bytes,
        # so the user data starts at li + 1 and runs to the end of the PDU.
        if len(data) < 3:
            events.append({"kind": "cotp-truncated", "detail": "DT PDU too short", "severity": "high"})
            return out
        nr_eot = data[2]
        out["eot"] = bool(nr_eot & 0x80)
        out["tpdu_nr"] = nr_eot & 0x7F
        out["data"] = data[li + 1 :]
        if not out["eot"]:
            events.append(
                {
                    "kind": "cotp-no-eot",
                    "detail": "DT PDU without EOT bit: incomplete COTP SDU (fragmented S7 message)",
                    "severity": "low",
                }
            )
        return out

    if ptype == 0x80:
        out["reason"] = body.hex()
        events.append({"kind": "cotp-disconnect", "detail": "COTP disconnect request", "severity": "info"})
        return out

    if ptype == 0x70:
        events.append({"kind": "cotp-error", "detail": f"COTP error PDU: {body.hex()}", "severity": "high"})
    return out


def decode(pkt: Packet) -> Optional[ProtoFact]:
    """Dissector entry point for TPKT/COTP (default port 102/tcp)."""
    if pkt.payload is None or len(pkt.payload) < 2:
        return None
    if pkt.payload[0] != 3 and pkt.dport != 102 and pkt.sport != 102:
        return None
    fact = ProtoFact(proto="cotp", summary="")
    units = iter_tpkt(pkt.payload)
    pdus = []
    for u in units:
        if u["kind"] == "malformed":
            fact.event(
                "cotp-malformed",
                str(u["detail"]),
                severity="high",
                direction="rx" if pkt.dport == 102 else "tx",
            )
            continue
        data = u.get("data", b"")
        info = decode_cotp(bytes(data))
        evs = info.pop("events", [])
        pdus.append(info)
        for ev in evs:
            kind = str(ev.get("kind", ""))
            if not kind.startswith("cotp-"):
                kind = f"cotp-{kind}"
            fact.event(
                kind,
                str(ev.get("detail", "")),
                severity=str(ev.get("severity", "info")),
            )
    if not pdus:
        return None if not fact.events else fact
    kinds = []
    for d in pdus:
        t = d.get("type")
        kinds.append(COTP_PDUS.get(t, f"0x{t:02x}" if isinstance(t, int) else "?"))
    extra = ""
    for d in pdus:
        if d.get("rack_slot"):
            r, s = d["rack_slot"]  # type: ignore[misc]
            extra = f" rack{r}/slot{s}"
        if d.get("tpdu_size"):
            extra += f" tpdu={d['tpdu_size']}B"
        if d.get("calling_class") and d.get("calling_class") != "empty":
            extra += f" tsap={d['calling_class']}"
    fact.summary = f"COTP {' + '.join(kinds)}{extra}"
    fact.attrs["pdus"] = pdus
    return fact
