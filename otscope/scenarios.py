"""Synthetic traffic scenarios.

Two uses:
* the test-suite feeds these through the real dissectors and asserts that the
  analyser finds the injected problem (a scenario is a known-answer test);
* `otscope replay --scenario <name>` demos the analyser without a plant network.

Every frame is built with otscope.frames, i.e. the same bytes a device would
send, so the dissectors are exercised for real.
"""

from __future__ import annotations

import struct
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import frames as F

Timeline = List[Tuple[float, bytes]]

# ---- fixed addressing for the demo plant ---------------------------------
SW_CORE = "00:1b:1b:00:00:01"
HMI_MAC = "00:0e:8c:11:22:33"
HMI = "10.20.1.10"
PLC_S7_MAC = "00:0e:8c:aa:00:10"
PLC_S7 = "10.20.2.10"        # Siemens S7-300
PLC_AB_MAC = "00:1d:9c:bb:00:20"
PLC_AB = "10.20.3.20"        # Allen-Bradley CompactLogix
PLC_SE_MAC = "00:00:54:cc:00:30"
PLC_SE = "10.20.4.30"        # Schneider Modicon M340
ERP_MAC = "00:50:56:dd:00:40"
ERP = "10.10.0.21"
ATTACKER_MAC = "b8:27:eb:ee:00:50"
ATTACKER = "10.20.1.99"
DCP_MULTICAST = "01:0e:cf:00:00:00"   # PROFINET DCP multicast group


def _tcp_frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload=b"", seq=0, ack=0, flags=0x18, ttl=64, win=8192):
    return F.eth(dst_mac, src_mac, F.ip(src_ip, dst_ip, 6, F.tcp(sport, dport, payload, seq=seq, ack=ack, flags=flags, win=win, src=src_ip, dst=dst_ip), ttl=ttl))


def _udp_frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload=b"", ttl=64):
    return F.eth(dst_mac, src_mac, F.ip(src_ip, dst_ip, 17, F.udp(sport, dport, payload, src=src_ip, dst=dst_ip), ttl=ttl))


def _arp_frame(src_mac, dst_mac, op, spa, tpa, tha="00:00:00:00:00:00"):
    return F.eth(dst_mac, src_mac, F.arp(op, src_mac, spa, tha, tpa), etype=0x0806)


class Seq:
    """Per-direction TCP sequence tracker so flows look like real traffic.

    Without this every injected flow has arbitrary sequence numbers, which the
    analyser would (correctly) report as packet loss.
    """

    def __init__(self, start: int = 1000) -> None:
        self.n: Dict[Tuple[str, str, int], int] = {}
        self.start = start

    def take(self, src: str, dst: str, port: int, nbytes: int = 0) -> int:
        key = (src, dst, port)
        v = self.n.get(key, self.start)
        self.n[key] = v + max(nbytes, 1)
        return v

    def peek(self, src: str, dst: str, port: int) -> int:
        return self.n.get((src, dst, port), self.start)


# ---------------------------------------------------------------- baseline
def baseline(duration: float = 30.0, poll_period: float = 0.2) -> Timeline:
    """Healthy plant traffic: S7 + Modbus + EtherNet/IP polling, ERP HTTP, STP/LLDP."""
    t: Timeline = []
    # STP from the core switch every 2 s
    ts = 0.0
    while ts < duration:
        t.append((ts, F.eth("01:80:c2:00:00:00", SW_CORE, F.stp_bpdu(SW_CORE, SW_CORE), etype=0x0026)))
        ts += 2.0
    # LLDP from the switch
    t.append((1.0, F.eth("01:80:c2:00:00:0e", SW_CORE, F.lldp_frame(SW_CORE, "Gi1/0/1", "PLANT-CORE-SW", "SCALANCE X308-2M", "10.20.1.1"), etype=0x88CC)))
    t.append((1.5, F.eth("01:80:c2:00:00:0e", PLC_S7_MAC, F.lldp_frame(PLC_S7_MAC, "X1 P1", "S7-300-LINE1", "SIMATIC S7-300 CPU 315-2 PN/DP", PLC_S7), etype=0x88CC)))

    # ARP resolution
    t.append((0.1, _arp_frame(HMI_MAC, "ff:ff:ff:ff:ff:ff", 1, HMI, PLC_S7)))
    t.append((0.11, _arp_frame(PLC_S7_MAC, HMI_MAC, 2, PLC_S7, HMI, tha=HMI_MAC)))

    # ---- S7 session setup + cyclic reads -------------------------------
    sq = Seq()
    s7 = (HMI, PLC_S7, 49152)
    s7r = (PLC_S7, HMI, 102)
    syn = sq.take(*s7)
    synack = sq.take(*s7r)
    t.append((0.2, _tcp_frame(HMI_MAC, PLC_S7_MAC, HMI, PLC_S7, 49152, 102, b"", flags=0x02, seq=syn)))
    t.append((0.205, _tcp_frame(PLC_S7_MAC, HMI_MAC, PLC_S7, HMI, 102, 49152, b"", flags=0x12, seq=synack, ack=syn + 1)))
    sq.take(*s7)  # SYN consumed one sequence number
    sq.take(*s7r)
    cr = F.tpkt(F.cotp_cr(b"\x01\x00", b"\x03\x01"))
    t.append((0.3, _tcp_frame(HMI_MAC, PLC_S7_MAC, HMI, PLC_S7, 49152, 102, cr, seq=sq.peek(*s7), ack=sq.peek(*s7r))))
    sq.take(*s7, len(cr))
    cc = F.tpkt(F.cotp_cc())
    t.append((0.32, _tcp_frame(PLC_S7_MAC, HMI_MAC, PLC_S7, HMI, 102, 49152, cc, seq=sq.peek(*s7r), ack=sq.peek(*s7))))
    sq.take(*s7r, len(cc))
    setup = F.tpkt(F.cotp_dt(F.s7_setup_request(pdu_len=240)))
    t.append((0.4, _tcp_frame(HMI_MAC, PLC_S7_MAC, HMI, PLC_S7, 49152, 102, setup, seq=sq.peek(*s7), ack=sq.peek(*s7r))))
    sq.take(*s7, len(setup))
    setup_r = F.tpkt(F.cotp_dt(F.s7_setup_response(pdu_len=240)))
    t.append((0.42, _tcp_frame(PLC_S7_MAC, HMI_MAC, PLC_S7, HMI, 102, 49152, setup_r, seq=sq.peek(*s7r), ack=sq.peek(*s7))))
    sq.take(*s7r, len(setup_r))
    szl = F.tpkt(F.cotp_dt(F.s7_szl_request(szl_id=0x0011)))
    t.append((0.5, _tcp_frame(HMI_MAC, PLC_S7_MAC, HMI, PLC_S7, 49152, 102, szl, seq=sq.peek(*s7), ack=sq.peek(*s7r))))
    sq.take(*s7, len(szl))
    szl_r = F.tpkt(F.cotp_dt(F.s7_szl_response(text="6ES7 315-2EH14-0AB0")))
    t.append((0.53, _tcp_frame(PLC_S7_MAC, HMI_MAC, PLC_S7, HMI, 102, 49152, szl_r, seq=sq.peek(*s7r), ack=sq.peek(*s7))))
    sq.take(*s7r, len(szl_r))
    ts = 1.0
    n = 0
    while ts < duration:
        req = F.tpkt(F.cotp_dt(F.s7_read_var(pdu_ref=n & 0xFFFF, db=1, start_byte=0, count=4)))
        resp = F.tpkt(F.cotp_dt(F.s7_read_var_response(pdu_ref=n & 0xFFFF)))
        t.append((ts, _tcp_frame(HMI_MAC, PLC_S7_MAC, HMI, PLC_S7, 49152, 102, req, seq=sq.peek(*s7), ack=sq.peek(*s7r))))
        sq.take(*s7, len(req))
        t.append((ts + 0.004, _tcp_frame(PLC_S7_MAC, HMI_MAC, PLC_S7, HMI, 102, 49152, resp, seq=sq.peek(*s7r), ack=sq.peek(*s7))))
        sq.take(*s7r, len(resp))
        ts += poll_period
        n += 1

    # ---- Modbus polling of the Modicon ---------------------------------
    mb = (HMI, PLC_SE, 50001)
    mbr = (PLC_SE, HMI, 502)
    ts = 1.0
    txid = 1
    while ts < duration:
        req = F.modbus_read_holding(txid, 1, 0, 10)
        resp = F.modbus_holding_response(txid, 1, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        t.append((ts, _tcp_frame(HMI_MAC, PLC_SE_MAC, HMI, PLC_SE, 50001, 502, req, seq=sq.peek(*mb), ack=sq.peek(*mbr))))
        sq.take(*mb, len(req))
        t.append((ts + 0.006, _tcp_frame(PLC_SE_MAC, HMI_MAC, PLC_SE, HMI, 502, 50001, resp, seq=sq.peek(*mbr), ack=sq.peek(*mb))))
        sq.take(*mbr, len(resp))
        ts += poll_period * 2
        txid += 1
    id_req = F.modbus_device_id_request(900, 1)
    id_resp = F.modbus_device_id_response(900, 1, [(0, "Schneider Electric"), (1, "BMX P34 2020"), (2, "V3.30"), (4, "Modicon M340")])
    t.append((2.0, _tcp_frame(HMI_MAC, PLC_SE_MAC, HMI, PLC_SE, 50001, 502, id_req, seq=sq.peek(*mb), ack=sq.peek(*mbr))))
    sq.take(*mb, len(id_req))
    t.append((2.01, _tcp_frame(PLC_SE_MAC, HMI_MAC, PLC_SE, HMI, 502, 50001, id_resp, seq=sq.peek(*mbr), ack=sq.peek(*mb))))
    sq.take(*mbr, len(id_resp))

    # ---- EtherNet/IP identity + tag read -------------------------------
    t.append((3.0, _udp_frame(HMI_MAC, PLC_AB_MAC, HMI, PLC_AB, 50003, 2222, F.enip_header(0x0064))))
    t.append((3.01, _udp_frame(PLC_AB_MAC, HMI_MAC, PLC_AB, HMI, 2222, 50003, F.enip_list_identity_reply([F.enip_identity_item(product_name="1769-L33ER", ip=PLC_AB, major=32, minor=11)]))))
    ab = (HMI, PLC_AB, 50004)
    abr = (PLC_AB, HMI, 44818)
    syn2 = sq.take(*ab)
    synack2 = sq.take(*abr)
    t.append((3.1, _tcp_frame(HMI_MAC, PLC_AB_MAC, HMI, PLC_AB, 50004, 44818, b"", flags=0x02, seq=syn2)))
    t.append((3.11, _tcp_frame(PLC_AB_MAC, HMI_MAC, PLC_AB, HMI, 44818, 50004, b"", flags=0x12, seq=synack2, ack=syn2 + 1)))
    reg = F.enip_register_session()
    reg_r = F.enip_register_session_reply(0x12345678)
    t.append((3.2, _tcp_frame(HMI_MAC, PLC_AB_MAC, HMI, PLC_AB, 50004, 44818, reg, seq=sq.peek(*ab), ack=sq.peek(*abr))))
    sq.take(*ab, len(reg))
    t.append((3.21, _tcp_frame(PLC_AB_MAC, HMI_MAC, PLC_AB, HMI, 44818, 50004, reg_r, seq=sq.peek(*abr), ack=sq.peek(*ab))))
    sq.take(*abr, len(reg_r))
    ts = 3.3
    while ts < duration:
        req = F.enip_cip_unconnected(F.cip_read_tag("Machine1_Speed"), session=0x12345678)
        reply = F.enip_cip_unconnected(F.cip_reply(0x4C, 0x00, b"\x01\x00"), session=0x12345678)
        t.append((ts, _tcp_frame(HMI_MAC, PLC_AB_MAC, HMI, PLC_AB, 50004, 44818, req, seq=sq.peek(*ab), ack=sq.peek(*abr))))
        sq.take(*ab, len(req))
        t.append((ts + 0.005, _tcp_frame(PLC_AB_MAC, HMI_MAC, PLC_AB, HMI, 44818, 50004, reply, seq=sq.peek(*abr), ack=sq.peek(*ab))))
        sq.take(*abr, len(reply))
        ts += poll_period

    # ---- ERP HTTP traffic ----------------------------------------------
    http_c = (HMI, ERP, 51000)
    http_s = (ERP, HMI, 80)
    ts = 2.0
    while ts < duration:
        req = b"GET /sap/bc/HTTP/health HTTP/1.1\r\nHost: erp01\r\n\r\n"
        resp = b"HTTP/1.1 200 OK\r\nServer: SAP NetWeaver\r\nContent-Length: 2\r\n\r\nOK"
        t.append((ts, _tcp_frame(HMI_MAC, ERP_MAC, HMI, ERP, 51000, 80, req, seq=sq.peek(*http_c), ack=sq.peek(*http_s))))
        sq.take(*http_c, len(req))
        t.append((ts + 0.04, _tcp_frame(ERP_MAC, HMI_MAC, ERP, HMI, 80, 51000, resp, seq=sq.peek(*http_s), ack=sq.peek(*http_c))))
        sq.take(*http_s, len(resp))
        ts += 5.0
    return sorted(t, key=lambda x: x[0])


# ----------------------------------------------------------------- problems
def broadcast_storm(seconds: float = 3.0, rate: float = 300.0) -> Timeline:
    """A host flooding identical ARP requests - broadcast storm."""
    t: Timeline = []
    ts = 0.0
    step = 1.0 / rate
    while ts < seconds:
        t.append((ts, _arp_frame(ATTACKER_MAC, "ff:ff:ff:ff:ff:ff", 1, ATTACKER, "10.20.2.99")))
        ts += step
    return t


def switch_loop(seconds: float = 2.0, rate: float = 200.0, tcns: int = 6) -> Timeline:
    """Identical frame reflected between two capture points + STP TCN storm."""
    t: Timeline = []
    step = 1.0 / rate
    ts = 0.0
    payload = F.tpkt(F.cotp_dt(F.s7_read_var(db=7, start_byte=8)))
    while ts < seconds:
        t.append((ts, _tcp_frame(HMI_MAC, PLC_S7_MAC, HMI, PLC_S7, 49152, 102, payload, seq=500, ack=600)))
        t.append((ts + step / 2, _tcp_frame(PLC_S7_MAC, HMI_MAC, PLC_S7, HMI, 102, 49152, payload, seq=600, ack=700)))
        ts += step
    for i in range(tcns):
        t.append((i * (seconds / tcns), F.eth("01:80:c2:00:00:00", SW_CORE, F.stp_bpdu(SW_CORE, SW_CORE, bpdu_type=0x80), etype=0x0026)))
    return sorted(t, key=lambda x: x[0])


def s7_faults(count: int = 12, err_class: int = 0x87, err_code: int = 0x03) -> Timeline:
    """S7 error responses: protected area, no resources, bad item."""
    t: Timeline = []
    sq = Seq()
    c = (HMI, PLC_S7, 49153)
    r = (PLC_S7, HMI, 102)
    ts = 1.0
    for i in range(count):
        req = F.tpkt(F.cotp_dt(F.s7_read_var(pdu_ref=i, db=99, start_byte=0)))
        resp = F.tpkt(F.cotp_dt(F.s7_error_response(pdu_ref=i, err_class=err_class, err_code=err_code)))
        t.append((ts, _tcp_frame(HMI_MAC, PLC_S7_MAC, HMI, PLC_S7, 49153, 102, req, seq=sq.peek(*c), ack=sq.peek(*r))))
        sq.take(*c, len(req))
        t.append((ts + 0.01, _tcp_frame(PLC_S7_MAC, HMI_MAC, PLC_S7, HMI, 102, 49153, resp, seq=sq.peek(*r), ack=sq.peek(*c))))
        sq.take(*r, len(resp))
        ts += 0.5
    return t


def s7_stop_command() -> Timeline:
    """An engineering-looking host sending a PLC STOP."""
    return [
        (0.0, _tcp_frame(ATTACKER_MAC, PLC_S7_MAC, ATTACKER, PLC_S7, 55555, 102, b"", flags=0x02, seq=1)),
        (0.01, _tcp_frame(PLC_S7_MAC, ATTACKER_MAC, PLC_S7, ATTACKER, 102, 55555, b"", flags=0x12, seq=1, ack=2)),
        (0.1, _tcp_frame(ATTACKER_MAC, PLC_S7_MAC, ATTACKER, PLC_S7, 55555, 102, F.tpkt(F.cotp_cr(b"\x01\x00", b"\x03\x01")), seq=2, ack=2)),
        (0.2, _tcp_frame(ATTACKER_MAC, PLC_S7_MAC, ATTACKER, PLC_S7, 55555, 102, F.tpkt(F.cotp_dt(F.s7_stop_request())), seq=100, ack=100)),
    ]


def s7_write_from_erp() -> Timeline:
    """The ERP host reaching into the control segment and writing a value."""
    return [
        (0.0, _tcp_frame(ERP_MAC, PLC_S7_MAC, ERP, PLC_S7, 60000, 102, b"", flags=0x02, seq=1)),
        (0.01, _tcp_frame(PLC_S7_MAC, ERP_MAC, PLC_S7, ERP, 102, 60000, b"", flags=0x12, seq=1, ack=2)),
        (0.1, _tcp_frame(ERP_MAC, PLC_S7_MAC, ERP, PLC_S7, 60000, 102, F.tpkt(F.cotp_cr()), seq=2, ack=2)),
        (0.2, _tcp_frame(ERP_MAC, PLC_S7_MAC, ERP, PLC_S7, 60000, 102, F.tpkt(F.cotp_dt(F.s7_write_var(db=10, start_byte=4, values=b"\x01\x00"))), seq=200, ack=200)),
    ]


def modbus_faults(count: int = 10, code: int = 0x04) -> Timeline:
    """Modbus exception responses (illegal function, device failure) during polling."""
    t: Timeline = []
    sq = Seq()
    c = (HMI, PLC_SE, 50010)
    r = (PLC_SE, HMI, 502)
    ts = 1.0
    for i in range(count):
        req = F.modbus_read_holding(i + 1, 1, 4000 + i, 2)
        resp = F.modbus_exception(i + 1, 1, 0x03, code)
        t.append((ts, _tcp_frame(HMI_MAC, PLC_SE_MAC, HMI, PLC_SE, 50010, 502, req, seq=sq.peek(*c), ack=sq.peek(*r))))
        sq.take(*c, len(req))
        t.append((ts + 0.01, _tcp_frame(PLC_SE_MAC, HMI_MAC, PLC_SE, HMI, 502, 50010, resp, seq=sq.peek(*r), ack=sq.peek(*c))))
        sq.take(*r, len(resp))
        ts += 0.4
    return t


def cip_errors(count: int = 8, status: int = 0x07) -> Timeline:
    """EtherNet/IP / CIP error replies from the CompactLogix controller."""
    t: Timeline = []
    sq = Seq()
    c = (HMI, PLC_AB, 50020)
    r = (PLC_AB, HMI, 44818)
    ts = 1.0
    for i in range(count):
        req = F.enip_cip_unconnected(F.cip_read_tag("Line2_Counter"), session=0x12345678)
        reply = F.enip_cip_unconnected(F.cip_reply(0x4C, status, additional=[0x0100]), session=0x12345678)
        t.append((ts, _tcp_frame(HMI_MAC, PLC_AB_MAC, HMI, PLC_AB, 50020, 44818, req, seq=sq.peek(*c), ack=sq.peek(*r))))
        sq.take(*c, len(req))
        t.append((ts + 0.008, _tcp_frame(PLC_AB_MAC, HMI_MAC, PLC_AB, HMI, 44818, 50020, reply, seq=sq.peek(*r), ack=sq.peek(*c))))
        sq.take(*r, len(reply))
        ts += 0.6
    return t


def malformed_s7(count: int = 8) -> Timeline:
    """Frames with a bogus TPKT length - the classic S7 crash vector."""
    t: Timeline = []
    ts = 1.0
    for i in range(count):
        bad = struct.pack(">BBH", 3, 0, 4000) + F.cotp_dt(F.s7_read_var(pdu_ref=i))
        t.append((ts, _tcp_frame(ATTACKER_MAC, PLC_S7_MAC, ATTACKER, PLC_S7, 55000 + i, 102, bad)))
        ts += 0.3
    return t


def port_scan(targets: Sequence[str] = (PLC_S7, PLC_AB, PLC_SE, HMI), ports: Sequence[int] = tuple(range(20, 60))) -> Timeline:
    """A sequential TCP sweep from the HMI segment across the plant."""
    t: Timeline = []
    ts = 1.0
    for host in targets:
        mac = {PLC_S7: PLC_S7_MAC, PLC_AB: PLC_AB_MAC, PLC_SE: PLC_SE_MAC}.get(host, HMI_MAC)
        for p in ports:
            t.append((ts, _tcp_frame(ATTACKER_MAC, mac, ATTACKER, host, 40000 + p, p, b"", flags=0x02, seq=p)))
            ts += 0.002
    return t


def retransmission_storm(count: int = 40) -> Timeline:
    """Heavy TCP retransmission on the HMI-to-controller flows."""
    t: Timeline = []
    ts = 1.0
    payload = F.modbus_read_holding(1, 1, 0, 10)
    for i in range(count):
        t.append((ts, _tcp_frame(HMI_MAC, PLC_SE_MAC, HMI, PLC_SE, 50030, 502, payload, seq=1000 + i, ack=2000)))
        t.append((ts + 0.05, _tcp_frame(HMI_MAC, PLC_SE_MAC, HMI, PLC_SE, 50030, 502, payload, seq=1000 + i, ack=2000)))
        ts += 0.1
    return t


def zero_window(count: int = 8) -> Timeline:
    """A server advertising a zero window (receiver overwhelmed)."""
    t: Timeline = []
    ts = 1.0
    for i in range(count):
        t.append((ts, _tcp_frame(ERP_MAC, HMI_MAC, ERP, HMI, 80, 51100, b"", flags=0x10, seq=5000 + i, ack=6000, win=0)))
        ts += 0.5
    return t


def slow_erp(count: int = 6, delay: float = 2.5) -> Timeline:
    """The ERP web tier answering slowly - user-visible slowness."""
    t: Timeline = []
    ts = 1.0
    req = b"POST /sap/bc/srt/rfc/sap/zmm_report HTTP/1.1\r\nHost: erp01\r\nContent-Length: 0\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nServer: SAP NetWeaver\r\nContent-Length: 2\r\n\r\nOK"
    for i in range(count):
        t.append((ts, _tcp_frame(HMI_MAC, ERP_MAC, HMI, ERP, 51200 + i, 80, req)))
        t.append((ts + delay, _tcp_frame(ERP_MAC, HMI_MAC, ERP, HMI, 80, 51200 + i, resp)))
        ts += delay + 1.0
    return t


def polling_gap(duration: float = 20.0, gap_at: float = 8.0, gap_len: float = 4.0) -> Timeline:
    """Cyclic polling of a PLC stops for tens of seconds."""
    t: Timeline = []
    sq = Seq()
    c = (HMI, PLC_S7, 49200)
    r = (PLC_S7, HMI, 102)
    ts = 0.0
    n = 0
    while ts < duration:
        if gap_at <= ts < gap_at + gap_len:
            ts += 0.2
            continue
        req = F.tpkt(F.cotp_dt(F.s7_read_var(pdu_ref=n, db=1)))
        resp = F.tpkt(F.cotp_dt(F.s7_read_var_response(pdu_ref=n)))
        t.append((ts, _tcp_frame(HMI_MAC, PLC_S7_MAC, HMI, PLC_S7, 49200, 102, req, seq=sq.peek(*c), ack=sq.peek(*r))))
        sq.take(*c, len(req))
        t.append((ts + 0.005, _tcp_frame(PLC_S7_MAC, HMI_MAC, PLC_S7, HMI, 102, 49200, resp, seq=sq.peek(*r), ack=sq.peek(*c))))
        sq.take(*r, len(resp))
        ts += 0.2
        n += 1
    return t


def mrp_double_manager() -> Timeline:
    """Two MRP managers in the same ring - a ring protocol fault."""
    t: Timeline = []
    for i in range(5):
        t.append((i * 0.5, F.eth("01:15:1d:00:00:01", PLC_S7_MAC, F.mrp_frame(PLC_S7_MAC, role=0x00, sequence=i), etype=0x88E3)))
        t.append((i * 0.5 + 0.1, F.eth("01:15:1d:00:00:01", PLC_SE_MAC, F.mrp_frame(PLC_SE_MAC, role=0x00, sequence=i + 100), etype=0x88E3)))
    for i in range(4):
        t.append((10.0 + i, F.eth("01:15:1d:00:00:01", PLC_S7_MAC, F.mrp_frame(PLC_S7_MAC, role=0x00, sequence=200 + i, tlvs=((0x03, 16),)), etype=0x88E3)))
    return sorted(t, key=lambda x: x[0])


def snmp_flood(count: int = 60) -> Timeline:
    """Crafted SNMP traffic at a Siemens CPU (CVE-2017-12741 pattern)."""
    t: Timeline = []
    ts = 1.0
    getreq = bytes.fromhex("302602010004067075626c6963a019020401020304020100020100300b300906052b060102010500")
    for i in range(count):
        t.append((ts, _udp_frame(ATTACKER_MAC, PLC_S7_MAC, ATTACKER, PLC_S7, 40000 + i, 161, getreq)))
        ts += 0.05
    return t


def insecure_services() -> Timeline:
    """Telnet and FTP listening on the control segment."""
    t: Timeline = []
    # Telnet + FTP + SNMP v1 'public' on the control segment
    t.append((1.0, _tcp_frame(PLC_SE_MAC, HMI_MAC, PLC_SE, HMI, 23, 52000, b"\xff\xfd\x01Welcome to Modicon\r\n")))
    t.append((1.1, _tcp_frame(PLC_SE_MAC, HMI_MAC, PLC_SE, HMI, 21, 52001, b"220 Modicon FTP ready\r\n")))
    snmp = bytes.fromhex("302602010004067075626c6963a019020401020304020100020100300b300906052b060102010500")
    t.append((1.2, _udp_frame(HMI_MAC, PLC_S7_MAC, HMI, PLC_S7, 52002, 161, snmp)))
    return t


def arp_conflict() -> Timeline:
    """Two MACs claiming the PLC address."""
    t: Timeline = []
    for i in range(6):
        t.append((1.0 + i, _arp_frame(PLC_S7_MAC, "ff:ff:ff:ff:ff:ff", 1, PLC_S7, PLC_S7)))
        t.append((1.5 + i, _arp_frame(ATTACKER_MAC, "ff:ff:ff:ff:ff:ff", 1, PLC_S7, PLC_S7)))
    return sorted(t, key=lambda x: x[0])


def dcp_rename(t0: float = 0.0, seconds: float = 6.0) -> Timeline:
    """PROFINET DCP discovery followed by a DCP Set that renames a PLC."""
    t: Timeline = []
    eng_mac = "00:50:56:dd:00:10"
    # 1. an engineering station discovers the device
    t.append((t0 + 0.2, F.eth(DCP_MULTICAST, eng_mac, F.dcp_identify(xid=7), etype=0x8892)))
    t.append(
        (
            t0 + 0.4,
            F.eth(
                "ff:ff:ff:ff:ff:ff",
                PLC_S7_MAC,
                F.dcp_identify_reply(PLC_S7_MAC, "s7-line1-cpu", PLC_S7),
                etype=0x8892,
            ),
        )
    )
    # 2. someone renames it - this takes the device out of the project
    t.append((t0 + seconds * 0.6, F.eth(DCP_MULTICAST, eng_mac, F.dcp_set_name("s7-line1-cpu-new", xid=8), etype=0x8892)))
    return t


SCENARIOS: Dict[str, object] = {
    "baseline": baseline,
    "broadcast-storm": broadcast_storm,
    "switch-loop": switch_loop,
    "s7-faults": s7_faults,
    "s7-stop": s7_stop_command,
    "erp-writes-plc": s7_write_from_erp,
    "modbus-faults": modbus_faults,
    "cip-errors": cip_errors,
    "malformed-s7": malformed_s7,
    "port-scan": port_scan,
    "retransmission": retransmission_storm,
    "zero-window": zero_window,
    "slow-erp": slow_erp,
    "polling-gap": polling_gap,
    "mrp-double-manager": mrp_double_manager,
    "snmp-flood": snmp_flood,
    "insecure-services": insecure_services,
    "arp-conflict": arp_conflict,
    "dcp-rename": dcp_rename,
}


def build(names: Iterable[str], t0: float = 1_700_000_000.0) -> Timeline:
    """Concatenate scenarios, each starting 1 second after the previous ends."""
    out: Timeline = []
    cursor = 0.0
    for name in names:
        if name not in SCENARIOS:
            raise KeyError(f"unknown scenario '{name}' (available: {', '.join(sorted(SCENARIOS))})")
        fn = SCENARIOS[name]
        part = fn()  # type: ignore[operator]
        end = max((ts for ts, _ in part), default=0.0)
        out.extend((t0 + cursor + ts, frame) for ts, frame in part)
        cursor += end + 1.0
    return sorted(out, key=lambda x: x[0])


def frames_of(names: Iterable[str]) -> List[bytes]:
    return [frame for _ts, frame in build(names)]


def write_pcap(
    path: str, names: Optional[Iterable[str]] = None, step: float = 0.0, t0: float = 1_700_000_000.0
) -> int:
    """Write a scenario timeline to a pcap file, preserving the timing.

    `names` defaults to every scenario, i.e. a full "bad day" on the plant.
    """
    from .pcap import PcapWriter

    timeline = build(list(names) if names is not None else sorted(SCENARIOS), t0=t0)
    with PcapWriter(path) as w:
        for ts, frame in timeline:
            w.write(frame, ts)
    return len(timeline)
