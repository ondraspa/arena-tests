"""Dissector registry: run every relevant dissector over a packet.

Two-tier dispatch, the way a packet analyser does it:

1. the well-known port for the protocol (102 for S7, 502 for Modbus, ...); or
2. no port match, but the payload satisfies a *strict* structural test.

Tier 2 matters because plant devices are frequently configured on non-standard
ports, but it has to be strict: a Modbus TCP transaction id of 0x0003 starts
with the same byte as a TPKT header, and decoding that as COTP produces fake
"malformed protocol frame" findings on perfectly healthy Modbus polling.
"""

from __future__ import annotations

from typing import List, Optional

from ..models import Packet, ProtoFact
from . import cotp, enip, l2, misc, modbus, s7comm

# Order matters: the most specific industrial dissectors run first, and the
# generic service namer only runs when nothing else claimed the frame.
L4_DISSECTORS = [
    ("s7comm", s7comm.decode),
    ("cotp", cotp.decode),
    ("modbus", modbus.decode),
    ("enip", enip.decode),
]

L2_DISSECTORS = [("l2", l2.decode_any)]

FALLBACK_DISSECTORS = [("misc", misc.decode_any)]

#: well-known ports per dissector; a dissector also runs on any port when the
#: strict structural test in _looks_like() passes
PORT_TABLE = {
    "s7comm": {102},
    "cotp": {102},
    "modbus": {502},
    "enip": {44818, 2222},
}


def _looks_like(name: str, payload: bytes) -> bool:
    """Strict structural test used when the port does not match."""
    if name in ("s7comm", "cotp"):
        # TPKT: version 3, reserved 0, length exactly the packet, known COTP PDU
        if len(payload) < 7 or payload[0] != 3 or payload[1] != 0:
            return False
        if int.from_bytes(payload[2:4], "big") != len(payload):
            return False
        li = payload[4]
        return li >= 1 and li + 1 <= len(payload) and payload[5] in (0xE0, 0xD0, 0xF0, 0x80)
    if name == "modbus":
        # MBAP: protocol id 0 and a length that covers exactly the PDU
        if len(payload) < 8:
            return False
        if int.from_bytes(payload[2:4], "big") != 0:
            return False
        return int.from_bytes(payload[4:6], "big") == len(payload) - 6
    if name == "enip":
        # encapsulation header: known command and a length matching the payload
        if len(payload) < 24:
            return False
        command = int.from_bytes(payload[0:2], "little")
        if command not in enip.ENCAP_COMMANDS:
            return False
        return int.from_bytes(payload[2:4], "little") == len(payload) - 24
    return True


def applies(name: str, pkt: Packet) -> bool:
    known = PORT_TABLE.get(name)
    if not known or not pkt.payload:
        return bool(pkt.payload)
    if known & {pkt.sport, pkt.dport}:
        return True
    return _looks_like(name, pkt.payload)


def dissect(pkt: Packet) -> List[ProtoFact]:
    """Return every protocol fact for a packet (usually zero or one)."""
    facts: List[ProtoFact] = []
    claimed = False
    for _name, fn in L4_DISSECTORS:
        if pkt.payload and applies(_name, pkt):
            try:
                out = fn(pkt)
            except Exception as exc:  # a dissector must never kill the capture
                out = ProtoFact(proto="dissector-error", summary=str(exc))
                out.event("dissector-exception", f"{_name}: {exc}", severity="low")
            if out is not None:
                facts.append(out)
                claimed = True
    if claimed:
        return facts
    for _name, fn in L2_DISSECTORS + FALLBACK_DISSECTORS:
        try:
            out = fn(pkt)
        except Exception as exc:  # a dissector must never kill the capture
            out = ProtoFact(proto="dissector-error", summary=str(exc))
            out.event("dissector-exception", f"{_name}: {exc}", severity="low")
        if out is not None:
            facts.append(out)
            if _name == "l2":
                claimed = True
    return facts


def primary(facts: List[ProtoFact]) -> Optional[ProtoFact]:
    return facts[0] if facts else None
