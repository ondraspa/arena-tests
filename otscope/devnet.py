"""A tiny emulated OT + ERP network, for demos and for testing the probes.

It speaks real protocols on real sockets (loopback only):

* an S7 CPU answering COTP / Setup communication / SZL module identification
* a Modbus TCP slave answering Read Device Identification and register reads
* an EtherNet/IP adapter answering ListIdentity on UDP and TCP
* an HTTP server with a deliberately slow endpoint (the "slow ERP" case)
* an SNMP agent answering GET sysDescr.0

The point is that `otscope probe` and the dissectors are exercised against bytes
produced by a server implementation, not against hand-written fixtures.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from . import frames as F
from .dissect.cotp import decode_cotp, iter_tpkt
from .dissect.s7comm import decode_s7

HOST = "127.0.0.1"


@dataclass
class DeviceProfile:
    name: str
    host: str = HOST
    #: which emulated services this device answers
    services: Tuple[str, ...] = ("s7", "modbus", "enip", "http", "snmp")
    module: str = "6ES7 315-2EH14-0AB0"
    firmware: str = "3.2.14"
    modbus_vendor: str = "Schneider Electric"
    modbus_product: str = "Modicon M340"
    modbus_code: str = "BMX P34 2020"
    modbus_version: str = "V3.30"
    cip_vendor_id: int = 1
    cip_product: str = "1769-L33ER"
    cip_major: int = 32
    cip_minor: int = 11
    sysdescr: str = "Siemens, SIMATIC S7-300, CPU 315-2 PN/DP, V3.2.14"
    http_server: str = "SAP NetWeaver 7.50"
    slow_seconds: float = 1.6
    fail_every: int = 0  # return an error PDU every Nth request (0 = never)


class _Server(threading.Thread):
    daemon = True

    def __init__(self, name: str) -> None:
        super().__init__(name=name, daemon=True)
        self._stopped = threading.Event()
        self.port = 0
        self.hits = 0
        self.port_was_taken = False

    def stop(self) -> None:
        self._stopped.set()


def _bind(sock: socket.socket, host: str, port: int) -> Tuple[int, bool]:
    """Bind to `port`, or to an ephemeral port if something else already has it."""
    try:
        sock.bind((host, port))
        return port, False
    except OSError:
        if port == 0:
            raise
        sock.bind((host, 0))
        return sock.getsockname()[1], True


class S7Server(_Server):
    """Minimal S7 CPU: COTP CR/CC, Setup communication, SZL 0x0011 read."""

    def __init__(self, profile: DeviceProfile, port: int = 0) -> None:
        super().__init__("devnet-s7")
        self.profile = profile
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.port, self.port_was_taken = _bind(self.sock, profile.host, port)
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.requests = 0

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                conn, _addr = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        try:
            self.sock.close()
        except OSError:
            pass

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(5.0)
        try:
            while not self._stopped.is_set():
                try:
                    data = conn.recv(4096)
                except (socket.timeout, OSError):
                    return
                if not data:
                    return
                for unit in iter_tpkt(data):
                    if unit["kind"] != "pdu":
                        continue
                    cotp = decode_cotp(bytes(unit.get("data", b"")))
                    ptype = cotp.get("type")
                    if ptype == 0xE0:
                        self.hits += 1
                        conn.sendall(F.tpkt(F.cotp_cc()))
                    elif ptype == 0xF0:
                        body = cotp.get("data", b"") or b""
                        if not body or body[0] != 0x32:
                            continue
                        pdu = decode_s7(bytes(body))
                        pdu.pop("events", None)
                        self.requests += 1
                        conn.sendall(F.tpkt(F.cotp_dt(self._answer(pdu))))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _answer(self, pdu: Dict[str, Any]) -> bytes:
        ref = int(pdu.get("pdu_ref") or 0)
        func = pdu.get("function")
        if self.profile.fail_every and self.requests % self.profile.fail_every == 0:
            return F.s7_error_response(pdu_ref=ref, err_class=0x87, err_code=0x03, func=func or 0x04)
        if func == 0xF0:
            return F.s7_setup_response(pdu_ref=ref, pdu_len=240)
        if func == 0x00:
            szl_id = int(pdu.get("szl_id") or 0x0011)
            if szl_id == 0x001C:
                # component identification: what an engineering tool reads to
                # learn the firmware version
                return F.s7_szl_response(
                    pdu_ref=ref, text=f"{self.profile.module} V{self.profile.firmware}", szl_id=szl_id
                )
            if szl_id in (0x0011, 0x0111):
                return F.s7_szl_response(pdu_ref=ref, text=self.profile.module, szl_id=szl_id)
            return F.s7_error_response(pdu_ref=ref, err_class=0x84, err_code=0x01, func=0x00)
        if func == 0x04:
            return F.s7_read_var_response(pdu_ref=ref, values=b"\x00\x2a\x00\x00")
        return F.s7_error_response(pdu_ref=ref, err_class=0x81, err_code=0x04, func=func or 0)


class ModbusServer(_Server):
    def __init__(self, profile: DeviceProfile, port: int = 0) -> None:
        super().__init__("devnet-modbus")
        self.profile = profile
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.port, self.port_was_taken = _bind(self.sock, profile.host, port)
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self.requests = 0

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                conn, _addr = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        try:
            self.sock.close()
        except OSError:
            pass

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(5.0)
        try:
            while not self._stopped.is_set():
                try:
                    data = conn.recv(4096)
                except (socket.timeout, OSError):
                    return
                if not data:
                    return
                if len(data) < 8:
                    continue
                txid, _proto, _len, unit = struct.unpack(">HHHB", data[:7])
                fc = data[7]
                self.requests += 1
                if self.profile.fail_every and self.requests % self.profile.fail_every == 0:
                    conn.sendall(F.modbus_exception(txid, unit, fc, 0x04))
                    continue
                if fc == 0x2B:
                    objs = [(0, self.profile.modbus_vendor), (1, self.profile.modbus_code), (2, self.profile.modbus_version), (4, self.profile.modbus_product)]
                    conn.sendall(F.modbus_device_id_response(txid, unit, objs))
                elif fc in (0x03, 0x04):
                    count = struct.unpack(">H", data[10:12])[0] if len(data) >= 12 else 1
                    conn.sendall(F.modbus_holding_response(txid, unit, [100 + i for i in range(min(count, 20))]))
                elif fc in (0x05, 0x06, 0x0F, 0x10, 0x15, 0x16):
                    # the emulator refuses writes: a controller under otscope is never written to
                    conn.sendall(F.modbus_exception(txid, unit, fc, 0x01))
                else:
                    conn.sendall(F.modbus_exception(txid, unit, fc, 0x01))
        finally:
            try:
                conn.close()
            except OSError:
                pass


class EnipServer(_Server):
    """EtherNet/IP identity responder on UDP 2222-style and TCP 44818-style ports."""

    def __init__(self, profile: DeviceProfile, udp_port: int = 0, tcp_port: int = 0) -> None:
        super().__init__("devnet-enip")
        self.profile = profile
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_port, udp_taken = _bind(self.udp, profile.host, udp_port)
        self.udp.settimeout(0.5)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_port, tcp_taken = _bind(self.tcp, profile.host, tcp_port)
        self.tcp.listen(8)
        self.tcp.settimeout(0.5)
        self.port = self.tcp_port
        self.port_was_taken = udp_taken or tcp_taken

    def run(self) -> None:
        threading.Thread(target=self._udp_loop, daemon=True).start()
        while not self._stopped.is_set():
            try:
                conn, _addr = self.tcp.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._tcp_handle, args=(conn,), daemon=True).start()
        for s in (self.udp, self.tcp):
            try:
                s.close()
            except OSError:
                pass

    def _reply(self, command: int) -> bytes:
        del command  # the reply is identical for either ListIdentity command code
        ident = F.enip_identity_item(
            vendor_id=self.profile.cip_vendor_id,
            product_code=0x1234,
            major=self.profile.cip_major,
            minor=self.profile.cip_minor,
            product_name=self.profile.cip_product,
            ip=self.profile.host,
            port=self.tcp_port,
        )
        return F.enip_list_identity_reply([ident])

    def _udp_loop(self) -> None:
        while not self._stopped.is_set():
            try:
                data, addr = self.udp.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            if len(data) < 24:
                continue
            self.hits += 1
            command = struct.unpack("<H", data[0:2])[0]
            try:
                self.udp.sendto(self._reply(command), addr)
            except OSError:
                pass

    def _tcp_handle(self, conn: socket.socket) -> None:
        conn.settimeout(5.0)
        try:
            data = conn.recv(4096)
            if len(data) >= 24:
                self.hits += 1
                command = struct.unpack("<H", data[0:2])[0]
                conn.sendall(self._reply(command))
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class HttpServer(_Server):
    def __init__(self, profile: DeviceProfile, port: int = 0) -> None:
        super().__init__("devnet-http")
        self.profile = profile
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.port, self.port_was_taken = _bind(self.sock, profile.host, port)
        self.sock.listen(8)
        self.sock.settimeout(0.5)

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                conn, _addr = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        try:
            self.sock.close()
        except OSError:
            pass

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(10.0)
        try:
            data = conn.recv(4096)
            self.hits += 1
            path = data.split(b" ")[1].decode("latin-1", "replace") if b" " in data else "/"
            if "slow" in path:
                time.sleep(self.profile.slow_seconds)
            body = b"<html><body>ERP</body></html>"
            head = (
                f"HTTP/1.1 200 OK\r\nServer: {self.profile.http_server}\r\n"
                f"Content-Type: text/html\r\nContent-Length: {len(body)}\r\n\r\n"
            ).encode()
            conn.sendall(head + body)
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class SnmpServer(_Server):
    def __init__(self, profile: DeviceProfile, port: int = 0) -> None:
        super().__init__("devnet-snmp")
        self.profile = profile
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.port, self.port_was_taken = _bind(self.sock, profile.host, port)
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            self.hits += 1
            reply = self._response(data)
            if reply is None:
                continue
            try:
                self.sock.sendto(reply, addr)
            except OSError:
                pass
        try:
            self.sock.close()
        except OSError:
            pass

    def _response(self, request: bytes) -> Optional[bytes]:
        # a real agent silently drops a request with an unknown community
        if b"\x04\x06public" not in request:
            return None
        text = self.profile.sysdescr.encode("ascii")
        oid = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        varbind = b"\x30" + bytes([len(oid) + len(text) + 4]) + b"\x06" + bytes([len(oid)]) + oid + b"\x04" + bytes([len(text)]) + text
        vbl = b"\x30" + bytes([len(varbind)]) + varbind
        pdu = b"\xA2" + bytes([len(vbl) + 9]) + b"\x02\x01\x01\x02\x01\x00\x02\x01\x00" + vbl
        com = b"public"
        msg = b"\x02\x01\x00\x04" + bytes([len(com)]) + com + pdu
        return b"\x30" + bytes([len(msg)]) + msg


class DevNet:
    """A whole emulated plant: one entry per device, each on its own loopback IP."""

    #: non-privileged stand-ins for the real OT ports, so one probe policy
    #: addresses every emulated device (each device is its own loopback IP, so
    #: they can all bind the same port numbers).
    DEMO_PORTS = {"s7": 10102, "modbus": 10502, "enip": 14481, "enip_udp": 12222, "http": 10080, "snmp": 10161}

    def __init__(self, profiles: Optional[List[DeviceProfile]] = None, fixed_ports: bool = False) -> None:
        self.profiles = profiles if profiles is not None else default_profiles()
        self.fixed_ports = fixed_ports
        self.servers: List[_Server] = []
        self.by_host: Dict[str, Dict[str, Any]] = {}

    def start(self) -> "DevNet":
        if self.fixed_ports:
            fixed = {"s7": 102, "modbus": 502, "enip": 44818, "enip_udp": 2222, "http": 80, "snmp": 161}
        else:
            fixed = dict(self.DEMO_PORTS)
        for profile in self.profiles:
            entry: Dict[str, Any] = {"name": profile.name, "services": list(profile.services)}
            for service in profile.services:
                if service == "s7":
                    srv: _Server = S7Server(profile, fixed["s7"])
                    entry["s7_port"] = srv.port
                elif service == "modbus":
                    srv = ModbusServer(profile, fixed["modbus"])
                    entry["modbus_port"] = srv.port
                elif service == "enip":
                    enip = EnipServer(profile, fixed["enip_udp"], fixed["enip"])
                    srv = enip
                    entry["enip_port"] = enip.tcp_port
                    entry["enip_udp_port"] = enip.udp_port
                elif service == "http":
                    srv = HttpServer(profile, fixed["http"])
                    entry["http_port"] = srv.port
                elif service == "snmp":
                    srv = SnmpServer(profile, fixed["snmp"])
                    entry["snmp_port"] = srv.port
                else:
                    continue
                if getattr(srv, "port_was_taken", False):
                    entry.setdefault("notes", []).append(
                        f"a demo port for {service} was busy, using {getattr(srv, 'port', '?')}"
                    )
                self.servers.append(srv)
                srv.start()
            self.by_host[profile.host] = entry
        time.sleep(0.15)
        return self

    def stop(self) -> None:
        for s in self.servers:
            s.stop()
        for s in self.servers:
            s.join(timeout=2.0)
        self.servers.clear()

    def __enter__(self) -> "DevNet":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def targets(self) -> List[str]:
        return [p.host for p in self.profiles]

    def service_ports(self) -> Dict[str, int]:
        """Union of the ports in use - what a probe policy should aim at."""
        ports: Dict[str, int] = {}
        for entry in self.by_host.values():
            for key in ("s7_port", "modbus_port", "enip_port", "enip_udp_port", "http_port", "snmp_port"):
                if key in entry and key not in ports:
                    ports[key] = entry[key]
        return ports

    def policy_ports(self) -> Dict[str, int]:
        """{service: port} ready to be handed to a ProbePolicy."""
        mapping = {
            "s7": "s7_port",
            "modbus": "modbus_port",
            "enip": "enip_port",
            "enip_udp": "enip_udp_port",
            "http": "http_port",
            "snmp": "snmp_port",
        }
        ports = self.service_ports()
        return {service: ports[key] for service, key in mapping.items() if key in ports}

    def probe_command(self, binary: str = "otscope") -> str:
        flags = " ".join(f"--service-port {k}={v}" for k, v in sorted(self.policy_ports().items()))
        return f"{binary} probe {' '.join(self.targets)} {flags} --rate 20 --snmp"

    def describe(self) -> Dict[str, Any]:
        return {"hosts": self.by_host, "profiles": {p.host: p.name for p in self.profiles}}


def default_profiles() -> List[DeviceProfile]:
    """The demo plant: three PLCs of three vendors plus the ERP tier."""
    return [
        DeviceProfile(
            name="S7-300 CPU (line 1)",
            host="127.0.0.2",
            services=("s7", "snmp"),
            module="6ES7 315-2EH14-0AB0",
            sysdescr="Siemens, SIMATIC S7-300, CPU 315-2 PN/DP, V3.2.14",
        ),
        DeviceProfile(
            name="CompactLogix 5370 (line 2)",
            host="127.0.0.3",
            services=("enip",),
            cip_product="1769-L33ER",
            cip_major=32,
            cip_minor=11,
        ),
        DeviceProfile(
            name="Modicon M340 (line 3)",
            host="127.0.0.4",
            services=("modbus",),
            modbus_vendor="Schneider Electric",
            modbus_product="Modicon M340",
            modbus_code="BMX P34 2020",
            modbus_version="V3.30",
        ),
        DeviceProfile(
            name="ERP application server",
            host="127.0.0.5",
            services=("http",),
            http_server="SAP NetWeaver 7.50",
            slow_seconds=1.4,
        ),
    ]


def main() -> None:  # pragma: no cover - CLI entry point
    import json

    net = DevNet().start()
    print(json.dumps(net.describe(), indent=2))
    print("targets:", " ".join(net.targets))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        net.stop()


if __name__ == "__main__":  # pragma: no cover
    main()
