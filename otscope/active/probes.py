"""Read-only active probes: identification and reachability, nothing else.

Everything here is designed to be safe to run against a production controller:
identification requests that a normal HMI performs thousands of times a day,
sent slowly, with the write guards from otscope.active.safety applied to every
frame before it leaves the machine.
"""

from __future__ import annotations

import re
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from .. import frames as F
from ..dissect.cotp import decode_cotp, iter_tpkt
from ..dissect.enip import decode_identity
from ..dissect.modbus import DEVICE_ID_OBJECTS
from ..dissect.s7comm import decode_s7
from .safety import FRAGILE_NOTE, Limiter, ProbePolicy, guard_modbus, guard_s7, guard_snmp

DEFAULT_OT_PORTS = [102, 502, 44818, 2222, 4840, 20000, 80, 443, 161, 23, 21]

SERVICE_NAMES = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
    102: "S7comm (ISO-on-TCP)",
    161: "SNMP",
    443: "HTTPS",
    502: "Modbus TCP",
    2222: "EtherNet/IP UDP",
    4840: "OPC UA",
    20000: "DNP3",
    44818: "EtherNet/IP",
    47808: "BACnet/IP",
}


class ProbeError(Exception):
    pass


# --------------------------------------------------------------------- TCP
def tcp_connect(ip: str, port: int, timeout: float = 1.5) -> Tuple[bool, bytes, float]:
    """Return (open, banner, rtt).  Never sends application data."""
    start = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
    except (socket.timeout, OSError):
        return False, b"", 0.0
    rtt = time.monotonic() - start
    banner = b""
    try:
        sock.settimeout(0.6)
        banner = sock.recv(128)
    except (socket.timeout, OSError):
        banner = b""
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return True, banner, rtt


def _send_recv(sock: socket.socket, data: bytes, timeout: float, size: int = 2048) -> bytes:
    sock.settimeout(timeout)
    sock.sendall(data)
    try:
        return sock.recv(size)
    except (socket.timeout, OSError):
        return b""


# --------------------------------------------------------------------- S7
def s7_identity(ip: str, port: int, policy: ProbePolicy, limiter: Limiter) -> Dict[str, Any]:
    """COTP connect + Setup communication + SZL 0x0011 (module identification).

    All three are read-only.  Nothing is written to the CPU and the operating
    mode is not touched.
    """
    out: Dict[str, Any] = {"method": "s7-szl", "steps": []}
    limiter.wait()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(policy.timeout_s)
    try:
        sock.connect((ip, port))
    except (socket.timeout, OSError) as exc:
        out["error"] = f"connect failed: {exc}"
        return out
    try:
        called = bytes([0x03, (policy.s7_rack * 0x20 + policy.s7_slot) & 0xFF])
        cr = F.tpkt(F.cotp_cr(b"\x01\x00", called))
        resp = _send_recv(sock, cr, policy.timeout_s)
        out["steps"].append("cotp-connect-request")
        if not resp:
            out["error"] = "no COTP response"
            return out
        units = [u for u in iter_tpkt(resp) if u["kind"] == "pdu"]
        cc = decode_cotp(bytes(units[0]["data"])) if units else {}
        if cc.get("type") != 0xD0:
            out["error"] = f"COTP did not confirm the connection (got 0x{(cc.get('type') or 0):02x})"
            out["cotp"] = cc.get("type_name")
            return out
        out["steps"].append("cotp-connect-confirm")
        out["tpdu_size"] = cc.get("tpdu_size")

        limiter.wait()
        req = F.s7_setup_request(pdu_ref=1, pdu_len=240)
        guard_s7(req)
        resp = _send_recv(sock, F.tpkt(F.cotp_dt(req)), policy.timeout_s)
        pdu = _first_s7(resp)
        if pdu is None:
            out["error"] = "no response to Setup communication"
            return out
        out["steps"].append("s7-setup-communication")
        out["negotiated_pdu_length"] = (pdu.get("setup") or {}).get("pdu_length")

        limiter.wait()
        req = F.s7_szl_request(pdu_ref=2, szl_id=0x0011, index=0x0001)
        guard_s7(req)
        resp = _send_recv(sock, F.tpkt(F.cotp_dt(req)), policy.timeout_s)
        pdu = _first_s7(resp)
        if pdu is None:
            out["error"] = "no response to SZL read"
            return out
        out["steps"].append("s7-szl-read")
        if pdu.get("szl_text"):
            out["module"] = pdu["szl_text"]
        if pdu.get("err_class"):
            out["error"] = f"S7 error class 0x{pdu['err_class']:02x} code 0x{pdu.get('err_code', 0):02x}"
        # A second, still read-only SZL read gives the component/firmware identity,
        # which is what version-range matching needs.  Skipped for fragile families.
        if out.get("module") and policy.do_s7_components:
            from ..analysis.topology import family_from_name

            if family_from_name(out["module"])[0] not in policy.connect_only_families:
                limiter.wait()
                req = F.s7_szl_request(pdu_ref=3, szl_id=0x001C, index=0x0001)
                guard_s7(req)
                resp = _send_recv(sock, F.tpkt(F.cotp_dt(req)), policy.timeout_s)
                pdu = _first_s7(resp)
                if pdu and pdu.get("szl_text"):
                    out["components"] = pdu["szl_text"]
                    out["steps"].append("s7-szl-components")
                    match = re.search(r"V?\d+\.\d+(?:\.\d+)?", pdu["szl_text"])
                    if match:
                        out["firmware"] = match.group(0)
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _first_s7(resp: bytes) -> Optional[Dict[str, Any]]:
    for unit in iter_tpkt(resp or b""):
        if unit["kind"] != "pdu":
            continue
        cotp = decode_cotp(bytes(unit.get("data", b"")))
        if cotp.get("type") != 0xF0:
            continue
        body = cotp.get("data", b"")
        if body and body[0] == 0x32:
            info = decode_s7(bytes(body))
            info.pop("events", None)
            return info
    return None


# ----------------------------------------------------------------- Modbus
def modbus_identity(ip: str, port: int, policy: ProbePolicy, limiter: Limiter) -> Dict[str, Any]:
    """Read Device Identification (FC 0x2B / MEI 0x0E) - a pure read."""
    out: Dict[str, Any] = {"method": "modbus-fc43"}
    req = F.modbus_device_id_request(1, policy.modbus_unit)
    guard_modbus(req)
    limiter.wait()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(policy.timeout_s)
    try:
        sock.connect((ip, port))
        resp = _send_recv(sock, req, policy.timeout_s)
    except (socket.timeout, OSError) as exc:
        out["error"] = f"modbus request failed: {exc}"
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if len(resp) < 9:
        out["error"] = "short or missing Modbus response"
        return out
    fc = resp[7]
    if fc & 0x80:
        out["error"] = f"Modbus exception 0x{resp[8]:02x}" if len(resp) > 8 else "Modbus exception"
        return out
    if fc != 0x2B:
        out["error"] = f"unexpected function code 0x{fc:02x}"
        return out
    num = resp[13] if len(resp) > 13 else 0
    off = 14
    objs: Dict[str, str] = {}
    for _ in range(num):
        if off + 2 > len(resp):
            break
        oid, olen = resp[off], resp[off + 1]
        objs[DEVICE_ID_OBJECTS.get(oid, f"0x{oid:02x}")] = resp[off + 2 : off + 2 + olen].decode("ascii", "replace")
        off += 2 + olen
    out["device_id"] = objs
    out["vendor"] = objs.get("VendorName", "")
    out["model"] = objs.get("ProductName") or objs.get("ModelName") or ""
    out["firmware"] = objs.get("MajorMinorRevision", "")
    out["product_code"] = objs.get("ProductCode", "")
    return out


# -------------------------------------------------------------- EtherNet/IP
def enip_identity(ip: str, policy: ProbePolicy, limiter: Limiter, tcp_port: int = 44818, udp_port: int = 2222) -> Dict[str, Any]:
    """ListIdentity over UDP 2222 and TCP 44818.

    Implementations differ on the encapsulation command code for ListIdentity
    (0x0063 / 0x0064), so both are sent and the reply is parsed structurally by
    item type - the identity item itself is unambiguous.
    """
    out: Dict[str, Any] = {"method": "enip-listidentity"}
    for command in (0x0063, 0x0064):
        limiter.wait()
        req = F.enip_header(command)
        # UDP broadcast-capable unicast query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(policy.timeout_s)
        try:
            sock.sendto(req, (ip, udp_port))
            resp, _addr = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            resp = b""
        finally:
            sock.close()
        ident = _identity_from(resp)
        if ident:
            out.update(ident)
            out["transport"] = f"udp/{udp_port}"
            return out
        # TCP fallback
        limiter.wait()
        tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tsock.settimeout(policy.timeout_s)
        try:
            tsock.connect((ip, tcp_port))
            resp = _send_recv(tsock, req, policy.timeout_s)
        except (socket.timeout, OSError):
            resp = b""
        finally:
            try:
                tsock.close()
            except OSError:
                pass
        ident = _identity_from(resp)
        if ident:
            out.update(ident)
            out["transport"] = f"tcp/{tcp_port}"
            return out
    out["error"] = f"no identity response on udp/{udp_port} or tcp/{tcp_port}"
    return out


def _identity_from(resp: bytes) -> Optional[Dict[str, Any]]:
    if not resp or len(resp) < 24:
        return None
    body = resp[24:]
    # scan for an identity item (type 0x000C) at either CPF layout
    for count_at in (0, 6):
        if len(body) < count_at + 6:
            continue
        count = struct.unpack("<H", body[count_at : count_at + 2])[0]
        if not 0 < count < 32:
            continue
        off = count_at + 2
        for _ in range(count):
            if off + 4 > len(body):
                break
            itype, ilen = struct.unpack("<HH", body[off : off + 4])
            if itype == 0x000C:
                ident = decode_identity(body[off + 4 : off + 4 + ilen])
                if ident:
                    return ident
            off += 4 + ilen
    return decode_identity(body)


# -------------------------------------------------------------------- SNMP
def _ber_tlv(data: bytes, i: int) -> Tuple[int, bytes, int]:
    """Read one BER tag/length/value and return (tag, value, next index)."""
    tag = data[i]
    i += 1
    length = data[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[i : i + n], "big")
        i += n
    return tag, data[i : i + length], i + length


def snmp_parse_response(resp: bytes) -> Dict[str, Any]:
    """Pull the value out of an SNMPv1 GetResponse (no third-party BER library)."""
    out: Dict[str, Any] = {}
    try:
        _tag, seq, _next = _ber_tlv(resp, 0)
        _tag, _version, i = _ber_tlv(seq, 0)
        _tag, community, i = _ber_tlv(seq, i)
        tag, pdu, _next = _ber_tlv(seq, i)
        out["pdu_type"] = tag
        out["community"] = "".join(chr(b) for b in community if 32 <= b < 127)
        _tag, _reqid, i = _ber_tlv(pdu, 0)
        _tag, err_status, i = _ber_tlv(pdu, i)
        _tag, _err_index, i = _ber_tlv(pdu, i)
        out["error_status"] = int.from_bytes(err_status, "big") if err_status else 0
        _tag, vbl, _next = _ber_tlv(pdu, i)
        _tag, varbind, _next = _ber_tlv(vbl, 0)
        _tag, _oid, i = _ber_tlv(varbind, 0)
        vtag, value, _next = _ber_tlv(varbind, i)
        out["value_tag"] = vtag
        out["value"] = "".join(chr(b) for b in value if 32 <= b < 127)
    except (IndexError, ValueError, TypeError):
        out["parse_error"] = True
    return out


def snmp_sysdescr(
    ip: str, community: str, timeout: float = 1.5, limiter: Optional[Limiter] = None, port: int = 161
) -> Dict[str, Any]:
    """SNMPv1 GET sysDescr.0 - read only."""
    oid = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])  # 1.3.6.1.2.1.1.1.0
    varbind = b"\x30" + bytes([len(oid) + 2]) + b"\x06" + bytes([len(oid)]) + oid + b"\x05\x00"
    varbindlist = b"\x30" + bytes([len(varbind)]) + varbind
    pdu = b"\xA0" + bytes([len(varbindlist) + 9]) + b"\x02\x01\x01\x02\x01\x00\x02\x01\x00" + varbindlist
    com = community.encode("ascii")
    msg = b"\x02\x01\x00\x04" + bytes([len(com)]) + com + pdu
    msg = b"\x30" + bytes([len(msg)]) + msg
    guard_snmp(msg)
    if limiter:
        limiter.wait()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, (ip, port))
        resp, _addr = sock.recvfrom(4096)
    except (socket.timeout, OSError):
        return {"method": "snmp", "error": f"no SNMP response on udp/{port}"}
    finally:
        sock.close()
    parsed = snmp_parse_response(resp)
    out: Dict[str, Any] = {"method": "snmp", "port": port}
    if parsed.get("parse_error"):
        out["error"] = "SNMP response could not be parsed"
        return out
    if parsed.get("pdu_type") != 0xA2:
        out["error"] = f"unexpected SNMP PDU type 0x{parsed.get('pdu_type', 0):02x}"
        return out
    if parsed.get("error_status"):
        out["error"] = f"SNMP error status {parsed['error_status']}"
        return out
    out["community_accepted"] = True
    out["sysdescr"] = parsed.get("value", "")
    return out


# -------------------------------------------------------------------- HTTP
def http_probe(ip: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.connect((ip, port))
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        data = b""
        while len(data) < 4096:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError) as exc:
        return {"method": "http", "error": str(exc)}
    finally:
        try:
            sock.close()
        except OSError:
            pass
    latency = time.monotonic() - start
    text = data.decode("latin-1", "replace")
    out: Dict[str, Any] = {"method": "http", "latency_s": round(latency, 3)}
    if text:
        out["status"] = text.split("\r\n", 1)[0][:80]
        for line in text.split("\r\n"):
            low = line.lower()
            if low.startswith("server:"):
                out["server"] = line.split(":", 1)[1].strip()
            if low.startswith("www-authenticate:"):
                out["auth"] = line.split(":", 1)[1].strip()
    return out


# ------------------------------------------------------------------- driver
def probe_host(ip: str, policy: ProbePolicy, limiter: Optional[Limiter] = None) -> Dict[str, Any]:
    limiter = limiter or Limiter(policy.rate_per_second)
    result: Dict[str, Any] = {
        "ip": ip,
        "started": time.time(),
        "ports": {},
        "identity": {},
        "errors": [],
        "notes": [],
        "family_hint": "",
        "vendor": "",
        "model": "",
        "firmware": "",
    }
    svc_names = {int(v): k for k, v in policy.service_ports.items()}
    # UDP services are not reachable by a TCP connect test; they are probed by
    # sending their one read-only request and waiting for the answer.
    udp_services = {"snmp", "enip_udp"}
    udp_ports = {int(policy.service_ports[n]) for n in udp_services if n in policy.service_ports}

    def _name(port: int) -> str:
        return SERVICE_NAMES.get(port) or (svc_names.get(port, "") and f"{svc_names[port]} ({port})") or f"tcp/{port}"

    open_ports: List[int] = []
    for port in policy.ports:
        if port in udp_ports:
            continue
        limiter.wait()
        is_open, banner, rtt = tcp_connect(ip, port, policy.timeout_s)
        if is_open:
            open_ports.append(port)
            entry: Dict[str, Any] = {
                "state": "open",
                "service": _name(port),
                "rtt_ms": round(rtt * 1000, 2),
            }
            if banner:
                entry["banner"] = banner.split(b"\r\n")[0].decode("latin-1", "replace")[:120]
            result["ports"][str(port)] = entry
        else:
            result["ports"][str(port)] = {"state": "closed", "service": _name(port)}
    result["open_ports"] = open_ports

    from ..analysis.topology import family_from_name

    # ---- identification, only on the ports that actually answered
    s7_port = policy.port_of("s7")
    if s7_port in open_ports and policy.do_s7_identity:
        info = s7_identity(ip, s7_port, policy, limiter)
        result["identity"]["s7"] = info
        if info.get("module"):
            result["model"] = info["module"]
            result["vendor"] = "Siemens"
            result["family_hint"] = family_from_name(info["module"])[0]
        if info.get("firmware"):
            result["firmware"] = info["firmware"]
        if info.get("error"):
            result["errors"].append(f"s7: {info['error']}")

    mb_port = policy.port_of("modbus")
    if mb_port in open_ports and policy.do_modbus_identity:
        info = modbus_identity(ip, mb_port, policy, limiter)
        result["identity"]["modbus"] = info
        result["vendor"] = result["vendor"] or info.get("vendor", "")
        result["model"] = result["model"] or info.get("model", "")
        result["firmware"] = result["firmware"] or info.get("firmware", "")
        if (info.get("model") or info.get("product_code")) and not result["family_hint"]:
            result["family_hint"] = family_from_name(
                f"{info.get('model', '')} {info.get('product_code', '')}"
            )[0]
        if info.get("error"):
            result["errors"].append(f"modbus: {info['error']}")

    enip_tcp, enip_udp = policy.port_of("enip"), policy.port_of("enip_udp")
    if (enip_tcp in open_ports or enip_udp in open_ports) and policy.do_enip_identity:
        info = enip_identity(ip, policy, limiter, tcp_port=enip_tcp or 44818, udp_port=enip_udp or 2222)
        result["identity"]["enip"] = info
        result["vendor"] = result["vendor"] or info.get("vendor", "")
        result["model"] = result["model"] or info.get("product_name", "")
        result["firmware"] = result["firmware"] or info.get("revision", "")
        if info.get("serial"):
            result["serial"] = info["serial"]
        if info.get("product_name") and not result["family_hint"]:
            result["family_hint"] = family_from_name(info["product_name"])[0]
        if info.get("error"):
            result["errors"].append(f"enip: {info['error']}")

    for service in ("http", "https"):
        port = policy.port_of(service)
        if port in open_ports and policy.do_http:
            result["identity"][service] = http_probe(ip, port)

    snmp_port = policy.port_of("snmp")
    if snmp_port and policy.do_snmp:
        info = snmp_sysdescr(ip, policy.snmp_community, limiter=limiter, port=snmp_port)
        if info.get("community_accepted"):
            result["identity"]["snmp"] = info
            result["ports"][str(snmp_port)] = {
                "state": "open",
                "service": f"SNMP (udp/{snmp_port})",
                "banner": info.get("sysdescr", "")[:120],
            }
            if snmp_port not in result["open_ports"]:
                result["open_ports"].append(snmp_port)
        elif not info.get("error", "").startswith("no SNMP response"):
            result["identity"]["snmp"] = info

    if result["family_hint"] in policy.connect_only_families:
        result["fragile"] = True
        result["notes"].append(FRAGILE_NOTE.format(family=result["family_hint"]))
    http_info = result["identity"].get("http") or {}
    if http_info.get("server"):
        result["http_server"] = http_info["server"]
    result["duration_s"] = round(time.time() - result["started"], 3)
    return result


def probe_targets(
    targets: List[str],
    policy: Optional[ProbePolicy] = None,
    on_result: Optional[Any] = None,
) -> Dict[str, Any]:
    policy = policy or ProbePolicy(targets=targets)
    policy.targets = list(targets)
    limiter = Limiter(policy.rate_per_second)
    out: Dict[str, Any] = {}
    for ip in targets:
        res = probe_host(ip, policy, limiter)
        out[ip] = res
        if on_result is not None:
            on_result(res)
    return out


# ------------------------------------------------------- integration helpers
def policy_from_config(cfg: Any, targets: Optional[List[str]] = None, **overrides: Any) -> ProbePolicy:
    """Build a probe policy from a ScanConfig (which encodes the site's rules)."""
    policy = ProbePolicy(targets=list(targets or []))
    for name, value in overrides.items():
        if value is not None and hasattr(policy, name):
            setattr(policy, name, value)
    if getattr(cfg, "fragile_devices", None):
        # a device the site flagged as delicate gets no protocol traffic at all
        policy.notes.append(f"site-flagged fragile devices: {', '.join(cfg.fragile_devices)}")
    return policy


def targets_from_stats(stats: Any, cfg: Any, limit: int = 64) -> List[str]:
    """Pick probe targets: controllers first, then everything else that has an IP."""

    def rank(a: Any) -> Tuple[int, str]:
        role = a.role or ""
        if "controller" in role:
            return (0, a.ip or "")
        if role in ("engineering-station", "hmi-scada", "historian"):
            return (1, a.ip or "")
        return (2, a.ip or "")

    assets = [a for a in stats.assets.values() if a.ip]
    assets.sort(key=rank)
    skip = set(getattr(cfg, "fragile_devices", []) or [])
    out = [a.ip for a in assets if a.ip not in skip][:limit]
    return out


def apply_to_stats(stats: Any, hosts: Dict[str, Any]) -> int:
    """Fold probe results into the inventory so matching sees what the probe found."""
    from ..analysis.topology import family_from_name

    touched = 0
    for ip, res in hosts.items():
        asset = stats.asset(ip)
        for port in res.get("open_ports", []):
            entry = res["ports"].get(str(port), {})
            asset.server_ports.setdefault(port, entry.get("service", f"tcp/{port}"))
        for field in ("vendor", "model", "firmware", "serial"):
            if res.get(field) and not getattr(asset, field):
                setattr(asset, field, res[field])
        if res.get("family_hint") and not asset.family:
            asset.family = res["family_hint"]
        elif not asset.family and (res.get("model") or res.get("vendor")):
            asset.family = family_from_name(f"{res.get('model', '')} {res.get('vendor', '')}")[0]
        for note in res.get("notes", []):
            asset.note(note, "active-probe")
        if res.get("open_ports") or res.get("model"):
            asset.note(
                "identified by read-only probe: "
                + (f"{res.get('vendor', '')} {res.get('model', '')} {res.get('firmware', '')}".strip() or "reachability only"),
                "active-probe",
            )
            touched += 1
    return touched


def run(stats: Any, cfg: Any, policy: Optional[ProbePolicy] = None, on_result: Optional[Any] = None) -> Dict[str, Any]:
    """Run the read-only probe against the hosts discovered in a capture."""
    targets = policy.targets if policy and policy.targets else targets_from_stats(stats, cfg)
    policy = policy or ProbePolicy(targets=list(targets))
    policy.targets = list(targets)
    if not targets:
        return {"hosts": {}, "banner": policy.banner(), "policy": _policy_dict(policy), "skipped": "no targets with an IP address"}
    hosts = probe_targets(targets, policy, on_result=on_result)
    apply_to_stats(stats, hosts)
    return {
        "hosts": hosts,
        "banner": policy.banner(),
        "policy": _policy_dict(policy),
        "started": time.time(),
    }


def _policy_dict(policy: ProbePolicy) -> Dict[str, Any]:
    return {
        "targets": list(policy.targets),
        "service_ports": dict(policy.service_ports),
        "rate_per_second": policy.rate_per_second,
        "timeout_s": policy.timeout_s,
        "connect_only_families": list(policy.connect_only_families),
        "read_only": True,
        "notes": list(policy.notes),
    }
