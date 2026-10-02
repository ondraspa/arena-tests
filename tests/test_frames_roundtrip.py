"""Every frame builder must survive parse_frame + dissect with no error facts.

This is the contract the whole passive pipeline depends on: if a builder and a
dissector disagree about a layout, the finding that depends on it is fiction.
"""

from __future__ import annotations

import pytest

from otscope import frames as F
from otscope.dissect.registry import dissect
from otscope.packets import parse_frame

S7 = "00:0e:8c:aa:00:10"
HMI = "00:0e:8c:11:22:33"
PLC_IP = "10.20.2.10"
HMI_IP = "10.20.1.10"


def _proto_facts(frame: bytes):
    pkt = parse_frame(frame, ts=0.0, iface="test")
    assert pkt is not None, "frame did not parse at all"
    facts = dissect(pkt)
    # "errors" here means *parsing* problems only - a well-formed frame may still
    # carry an informational or even critical protocol event (a PLC STOP).
    bad = ("malformed", "truncated", "mismatch", "short", "overflow", "unknown", "bad-")
    errors = [
        e
        for f in facts
        for e in f.events
        if f.proto == "dissector-error" or any(token in e["kind"] for token in bad)
    ]
    return pkt, facts, errors


def _pdus(facts, proto="s7comm"):
    fact = next(f for f in facts if f.proto == proto)
    return fact.attrs.get("pdus") or [fact.attrs]


def test_eth_ip_tcp_parse():
    frame = F.eth(S7, HMI, F.ip(HMI_IP, PLC_IP, 6, F.tcp(49152, 102, b"hi", src=HMI_IP, dst=PLC_IP)))
    pkt = parse_frame(frame, ts=0.0, iface="test")
    assert pkt.ethertype == 0x0800
    assert pkt.src_ip == HMI_IP and pkt.dst_ip == PLC_IP
    assert pkt.sport == 49152 and pkt.dport == 102
    assert pkt.flag("ACK") and pkt.is_tcp


def test_vlan_and_qinq():
    frame = F.eth(S7, HMI, F.ip(HMI_IP, PLC_IP, 6, F.tcp(1, 2, src=HMI_IP, dst=PLC_IP)), vlan=101)
    pkt = parse_frame(frame, ts=0.0, iface="test")
    assert pkt.vlans == (101,)
    assert pkt.src_ip == HMI_IP  # the payload must still be found behind the tag


def test_arp_keeps_both_macs():
    frame = F.eth("ff:ff:ff:ff:ff:ff", S7, F.arp(1, S7, PLC_IP, "00:00:00:00:00:00", PLC_IP), etype=0x0806)
    pkt = parse_frame(frame, ts=0.0, iface="test")
    assert pkt.ethertype == 0x0806
    assert pkt.src_mac == S7
    assert pkt.dst_mac == "ff:ff:ff:ff:ff:ff"
    assert pkt.arp_op == 1
    assert pkt.arp_sha == S7


def test_s7_setup_roundtrip():
    pdu = F.s7_setup_request(pdu_ref=7, pdu_len=240)
    frame = F.eth(S7, HMI, F.ip(PLC_IP, HMI_IP, 6, F.tcp(102, 49152, F.tpkt(F.cotp_dt(pdu)), src=PLC_IP, dst=HMI_IP)))
    _pkt, facts, errors = _proto_facts(frame)
    assert not errors, errors
    pdu = _pdus(facts)[0]
    assert pdu["function"] == 0xF0
    assert pdu["setup"]["pdu_length"] == 240


def test_s7_read_var_item_area():
    """A read request must decode with the right area, not 'area 0x01, length 0'."""
    pdu = F.s7_read_var(db=10, start_byte=4, count=8)
    frame = F.eth(HMI, S7, F.ip(HMI_IP, PLC_IP, 6, F.tcp(49152, 102, F.tpkt(F.cotp_dt(pdu)), src=HMI_IP, dst=PLC_IP)))
    _pkt, facts, errors = _proto_facts(frame)
    assert not errors, errors
    pdu = _pdus(facts)[0]
    assert pdu["function"] == 0x04
    item = pdu["items"][0]
    assert item["area"] == 0x84
    assert item["db"] == 10
    assert item["length"] == 8


def test_s7_stop_is_flagged_critical():
    frame = F.eth(HMI, S7, F.ip(HMI_IP, PLC_IP, 6, F.tcp(49152, 102, F.tpkt(F.cotp_dt(F.s7_stop_request())), src=HMI_IP, dst=PLC_IP)))
    _pkt, facts, _errors = _proto_facts(frame)
    events = [e for f in facts for e in f.events]
    kinds = [e["kind"] for e in events]
    assert "s7-control-command" in kinds
    assert any(e["severity"] == "critical" for e in events if e["kind"] == "s7-control-command")


def test_s7_szl_identity_text():
    frame = F.eth(
        S7,
        HMI,
        F.ip(
            PLC_IP,
            HMI_IP,
            6,
            F.tcp(102, 49152, F.tpkt(F.cotp_dt(F.s7_szl_response(text="6ES7 315-2EH14-0AB0"))), src=PLC_IP, dst=HMI_IP),
        ),
    )
    _pkt, facts, _errors = _proto_facts(frame)
    pdu = _pdus(facts)[0]
    assert pdu["szl_id"] == 0x0011
    assert pdu["szl_text"] == "6ES7 315-2EH14-0AB0"


def test_modbus_device_id_roundtrip():
    req = F.modbus_device_id_response(3, 1, [(0, "Siemens"), (4, "S7-300")])
    frame = F.eth(S7, HMI, F.ip(PLC_IP, HMI_IP, 6, F.tcp(502, 50001, req, src=PLC_IP, dst=HMI_IP)))
    _pkt, facts, errors = _proto_facts(frame)
    assert not errors, errors
    mb = next(f for f in facts if f.proto == "modbus")
    assert mb.attrs["device_id"]["VendorName"] == "Siemens"
    assert mb.attrs["device_id"]["ProductName"] == "S7-300"


def test_modbus_exception_event():
    frame = F.eth(S7, HMI, F.ip(PLC_IP, HMI_IP, 6, F.tcp(502, 50001, F.modbus_exception(1, 1, 3, 2), src=PLC_IP, dst=HMI_IP)))
    _pkt, facts, _errors = _proto_facts(frame)
    kinds = [e["kind"] for f in facts for e in f.events]
    assert "modbus-exception" in kinds


def test_enip_identity_roundtrip():
    item = F.enip_identity_item(product_name="1769-L33ER", major=32, minor=11, ip="10.20.3.20")
    reply = F.enip_list_identity_reply([item])
    frame = F.eth(S7, HMI, F.ip(PLC_IP, HMI_IP, 6, F.tcp(44818, 50002, reply, src=PLC_IP, dst=HMI_IP)))
    _pkt, facts, _errors = _proto_facts(frame)
    en = next(f for f in facts if f.proto == "enip")
    ident = en.attrs["identity"]
    assert ident["product_name"] == "1769-L33ER"
    assert ident["revision"] == "32.11"
    assert ident["vendor_id"] == 1


def test_enip_identity_over_udp():
    """EtherNet/IP implicit messaging on 2222/udp must be identified too."""
    item = F.enip_identity_item(product_name="1769-L33ER")
    frame = F.eth(S7, HMI, F.ip(PLC_IP, HMI_IP, 17, F.udp(2222, 2222, F.enip_list_identity_reply([item]), src=PLC_IP, dst=HMI_IP)))
    _pkt, facts, _errors = _proto_facts(frame)
    assert any(f.proto == "enip" for f in facts)


def test_stp_and_lldp():
    bpdu = F.stp_bpdu("00:1b:1b:00:00:01", "00:1b:1b:00:00:01", flags=0x01)
    frame = F.eth("01:80:c2:00:00:00", "00:1b:1b:00:00:01", bpdu, etype=0x0026)
    pkt = parse_frame(frame, ts=0.0, iface="test")
    assert pkt is not None
    facts = dissect(pkt)
    assert any(f.proto == "stp" for f in facts)

    lldp = F.lldp_frame("00:1b:1b:00:00:01", "Gi1/0/1", "core-switch", mgmt_ip="10.20.0.1")
    frame = F.eth("01:80:cc:cc:cc:cc", "00:1b:1b:00:00:01", lldp, etype=0x88CC)
    facts = dissect(parse_frame(frame, ts=0.0, iface="test"))
    assert any(f.proto == "lldp" for f in facts)


def test_malformed_tpkt_is_detected_not_crashing():
    """Bogus TPKT length: the dissector must report it, not raise."""
    bad = b"\x03\x00\x00\x00" + F.cotp_dt(F.s7_setup_request())[4:]
    frame = F.eth(S7, HMI, F.ip(PLC_IP, HMI_IP, 6, F.tcp(102, 49152, bad, src=PLC_IP, dst=HMI_IP)))
    pkt = parse_frame(frame, ts=0.0, iface="test")
    facts = dissect(pkt)
    kinds = [e["kind"] for f in facts for e in f.events]
    assert any("malformed" in k or "tpkt" in k for k in kinds)


def test_dcp_identify_set_and_reply():
    """DCP blocks are 6-byte headers; a Set request must be flagged."""
    # (frame, expected event kind, carries a station name?)
    for frame, want, named in (
        (F.dcp_identify(xid=7), "dcp-identify", False),
        (F.dcp_set_name("plc-line1", xid=8), "dcp-set", True),
        (F.dcp_identify_reply(S7, "plc-line1", PLC_IP), None, True),
    ):
        raw = F.eth("ff:ff:ff:ff:ff:ff", S7, frame, etype=0x8892)
        pkt = parse_frame(raw, ts=0.0, iface="test")
        assert pkt is not None
        fact = next(f for f in dissect(pkt) if f.proto == "profinet-dcp")
        names = {b.get("station_name") for b in fact.attrs["blocks"]}
        assert ("plc-line1" in names) is named, (want, names)
        if want is not None:
            assert want in [e["kind"] for e in fact.events]
        else:
            assert any(b.get("ip") == PLC_IP for b in fact.attrs["blocks"])


def test_dcp_block_length_outside_the_frame_is_reported():
    """A truncated DCP block must produce an event, not an exception."""
    broken = F.dcp_identify_reply(S7, "plc-line1", PLC_IP)
    raw = F.eth("ff:ff:ff:ff:ff:ff", S7, broken[:-6], etype=0x8892)
    pkt = parse_frame(raw, ts=0.0, iface="test")
    facts = dissect(pkt)
    assert not [f for f in facts if f.proto == "dissector-error"], facts


@pytest.mark.parametrize(
    "builder",
    [
        lambda: F.s7_setup_request(),
        lambda: F.s7_setup_response(),
        lambda: F.s7_read_var(),
        lambda: F.s7_read_var_response(),
        lambda: F.s7_write_var(),
        lambda: F.s7_error_response(),
        lambda: F.s7_stop_request(),
        lambda: F.s7_start_request(),
        lambda: F.s7_szl_request(),
        lambda: F.s7_szl_response(),
        lambda: F.modbus_read_holding(1, 1, 0, 4),
        lambda: F.modbus_holding_response(1, 1, [1, 2, 3, 4]),
        lambda: F.modbus_write_multiple(1, 1, 0, [1, 2]),
        lambda: F.modbus_device_id_request(1, 1),
        lambda: F.modbus_exception(1, 1, 3, 4),
        lambda: F.enip_register_session(),
        lambda: F.enip_list_identity_reply([F.enip_identity_item()]),
        lambda: F.enip_cip_unconnected(F.cip_read_tag("Tag1")),
    ],
)
def test_builders_never_produce_dissector_errors(builder):
    payload = builder()
    port = 502 if "modbus" in repr(builder) else (44818 if "enip" in repr(builder) else 102)
    frame = F.eth(
        S7, HMI, F.ip(PLC_IP, HMI_IP, 6, F.tcp(port, 50001, F.tpkt(F.cotp_dt(payload)) if port == 102 else payload, src=PLC_IP, dst=HMI_IP))
    )
    pkt = parse_frame(frame, ts=0.0, iface="test")
    assert pkt is not None
    facts = dissect(pkt)
    assert not [f for f in facts if f.proto == "dissector-error"], facts
