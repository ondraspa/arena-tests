"""Safety policy for active probing.

Active probing of a live PLC can stop a production line, so the rules here are
deliberately conservative and cannot be relaxed from the command line:

* only read-only operations are ever sent (device identification, SZL reads,
  ListIdentity, SNMP GET);
* the write-blocking guard is a hard check on the bytes about to be sent, not a
  flag that a caller can flip;
* families known to be fragile are limited to a TCP connect test;
* every probe is rate limited.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

# Function codes / services that mutate state.  The guard rejects any frame
# containing one of these in the protocol position.
MODBUS_WRITE_FCS = {0x05, 0x06, 0x0F, 0x10, 0x15, 0x16, 0x17, 0x2B}
MODBUS_WRITE_FCS.discard(0x2B)  # 0x2B with MEI 0x0E is a read
MODBUS_DIAG_RESET = 0x0001

S7_WRITE_FUNCS = {0x05, 0x15, 0x16, 0x1A, 0x1B, 0x1C, 0x28, 0x29}
CIP_WRITE_SERVICES = {0x02, 0x04, 0x05, 0x10, 0x4B, 0x4D, 0x4F}

# Controllers documented to be crashable by hostile traffic or to have very few
# communication resources.  For these we allow exactly one read-only
# identification session (COTP connect + Setup + a single SZL read - what an
# engineering tool does on every online connection) and no enumeration, no
# repeated connects and no variable reads.
FRAGILE_FAMILIES = ("S7-300", "S7-400", "Modicon Premium", "Modicon Quantum", "S7-200")

FRAGILE_NOTE = (
    "{family} is on the fragile list: probing was limited to a single read-only "
    "identification session (no enumeration, no repeated connects, no variable reads)"
)

BANNER = """\
otscope active probe - READ ONLY
  * no writes, no start/stop, no program download, no configuration change
  * rate limited to {rate:.0f} requests/second, {ports} ports per host
  * fragile families are limited to ONE read-only identification session: {fragile}
"""


DEFAULT_SERVICE_PORTS: Dict[str, int] = {
    "s7": 102,
    "modbus": 502,
    "enip": 44818,
    "enip_udp": 2222,
    "opcua": 4840,
    "http": 80,
    "https": 443,
    "snmp": 161,
    "dnp3": 20000,
}


@dataclass
class ProbePolicy:
    targets: List[str] = field(default_factory=list)
    #: which port each protocol probe speaks to.  Override per site, e.g. when a
    #: controller runs S7 on a non-standard port or sits behind a port mapping.
    service_ports: Dict[str, int] = field(default_factory=lambda: dict(DEFAULT_SERVICE_PORTS))
    #: additional ports to test for reachability only (no protocol traffic)
    extra_ports: List[int] = field(default_factory=list)
    rate_per_second: float = 10.0
    timeout_s: float = 1.5
    max_ports_per_host: int = 32
    connect_only_families: Sequence[str] = FRAGILE_FAMILIES
    do_s7_identity: bool = True
    #: also read SZL 0x001C (component identification) for the firmware version,
    #: unless the device is on the fragile list
    do_s7_components: bool = True
    do_modbus_identity: bool = True
    do_enip_identity: bool = True
    do_http: bool = True
    do_snmp: bool = False
    snmp_community: str = "public"
    s7_rack: int = 0
    s7_slot: int = 1
    modbus_unit: int = 1
    allow_write: bool = False  # never honoured; kept so callers cannot pass True silently
    notes: List[str] = field(default_factory=list)

    def banner(self) -> str:
        return BANNER.format(
            rate=self.rate_per_second,
            ports=self.max_ports_per_host,
            fragile=", ".join(self.connect_only_families),
        )

    @property
    def ports(self) -> List[int]:
        """Every port this policy may touch, in a stable order."""
        out = sorted({int(p) for p in list(self.service_ports.values()) + list(self.extra_ports)})
        return out[: self.max_ports_per_host]

    def port_of(self, service: str) -> Optional[int]:
        return self.service_ports.get(service)

    def __post_init__(self) -> None:
        if self.allow_write:
            self.allow_write = False
            self.notes.append("allow_write=True was ignored: otscope never writes to a device")


class WriteAttempt(Exception):
    """Raised if anything tries to send a mutating request."""


def guard_modbus(payload: bytes) -> None:
    """Refuse to send a Modbus frame that is not a read."""
    if len(payload) < 8:
        raise WriteAttempt("truncated Modbus request")
    unit = payload[6]
    fc = payload[7]
    if fc in MODBUS_WRITE_FCS:
        raise WriteAttempt(f"Modbus function code 0x{fc:02x} is a write operation")
    if fc == 0x08 and len(payload) >= 10:
        sub = int.from_bytes(payload[8:10], "big")
        if sub == MODBUS_DIAG_RESET:
            raise WriteAttempt("Modbus diagnostics 'restart communications' is not read-only")
    if fc == 0x2B and len(payload) >= 9 and payload[8] != 0x0E:
        raise WriteAttempt(f"Modbus MEI type 0x{payload[8]:02x} is not device identification")
    if fc not in (0x01, 0x02, 0x03, 0x04, 0x07, 0x0B, 0x0C, 0x11, 0x14, 0x18, 0x2B):
        raise WriteAttempt(f"Modbus function code 0x{fc:02x} is not on the read-only allow list")
    del unit


def guard_s7(pdu: bytes) -> None:
    """Refuse to send an S7 PDU that is not a read / setup / SZL request."""
    if len(pdu) < 11 or pdu[0] != 0x32:
        raise WriteAttempt("not an S7 PDU")
    rosctr = pdu[1]
    if rosctr != 0x01 and rosctr != 0x07:
        raise WriteAttempt(f"S7 ROSCTR 0x{rosctr:02x} is not a request")
    param_off = 10
    param_len = int.from_bytes(pdu[6:8], "big")
    if param_len and len(pdu) > param_off:
        func = pdu[param_off]
        if func in S7_WRITE_FUNCS:
            raise WriteAttempt(f"S7 function 0x{func:02x} is a write / control operation")
        if func == 0x00 and len(pdu) > param_off + 5:
            group = pdu[param_off + 5]
            if group == 0x03:
                raise WriteAttempt("S7 mode-transition (START/STOP) request blocked")
            if group == 0x08:
                raise WriteAttempt("S7 password function blocked")
            if group in (0x06, 0x09):
                raise WriteAttempt("S7 block function (download/upload) blocked")


def guard_cip(cip: bytes) -> None:
    if not cip:
        raise WriteAttempt("empty CIP request")
    service = cip[0]
    if service in CIP_WRITE_SERVICES:
        raise WriteAttempt(f"CIP service 0x{service:02x} is a write/reset operation")


def guard_snmp(payload: bytes) -> None:
    """Accept only GetRequest / GetNextRequest / GetBulkRequest."""
    i = 0
    if not payload or payload[0] != 0x30:
        raise WriteAttempt("not an SNMP message")
    # skip the SEQUENCE and the version INTEGER to find the PDU type byte
    i = 1
    b = payload[i]
    i += 1 + (b & 0x7F) if b & 0x80 else 1
    if i >= len(payload) or payload[i] != 0x02:
        raise WriteAttempt("SNMP version field missing")
    vlen = payload[i + 1]
    i += 2 + vlen
    if i >= len(payload) or payload[i] != 0x04:
        raise WriteAttempt("SNMP community field missing")
    clen = payload[i + 1]
    i += 2 + clen
    if i >= len(payload):
        raise WriteAttempt("SNMP PDU missing")
    if payload[i] not in (0xA0, 0xA1, 0xA5):
        raise WriteAttempt(f"SNMP PDU type 0x{payload[i]:02x} is not a read operation")


class Limiter:
    def __init__(self, rate_per_second: float) -> None:
        self.interval = 1.0 / max(rate_per_second, 0.001)
        self.last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        delta = now - self.last
        if delta < self.interval:
            time.sleep(self.interval - delta)
        self.last = time.monotonic()
