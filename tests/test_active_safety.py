"""The active probe must be read-only, and it must actually identify devices."""

from __future__ import annotations

import pytest

from otscope import frames as F
from otscope.active import probes
from otscope.active.safety import (
    Limiter,
    ProbePolicy,
    WriteAttempt,
    guard_cip,
    guard_modbus,
    guard_s7,
    guard_snmp,
)
from otscope.analysis.engine import Engine
from otscope.config import ScanConfig
from otscope.devnet import DevNet, DeviceProfile




# --------------------------------------------------------------- write guards
def test_modbus_writes_are_refused():
    for frame in (
        F.modbus_write_single(1, 1, 0, 1),
        F.modbus_write_multiple(1, 1, 0, [1, 2]),
        F.modbus_request(1, 1, 0x0F, b"\x00" * 5),
        F.modbus_request(1, 1, 0x10, b"\x00" * 5),
        F.modbus_request(1, 1, 0x15, b"\x00" * 5),
        F.modbus_request(1, 1, 0x16, b"\x00" * 5),
    ):
        with pytest.raises(WriteAttempt):
            guard_modbus(frame)


def test_modbus_reads_are_allowed():
    guard_modbus(F.modbus_read_holding(1, 1, 0, 4))
    guard_modbus(F.modbus_device_id_request(1, 1))
    guard_modbus(F.modbus_request(1, 1, 0x04, b"\x00\x00\x00\x04"))


def test_modbus_restart_diagnostics_is_refused():
    with pytest.raises(WriteAttempt):
        guard_modbus(F.modbus_request(1, 1, 0x08, b"\x00\x01"))


def test_s7_stop_start_and_download_are_refused():
    with pytest.raises(WriteAttempt):
        guard_s7(F.s7_stop_request())
    with pytest.raises(WriteAttempt):
        guard_s7(F.s7_start_request())
    with pytest.raises(WriteAttempt):
        guard_s7(F.s7_write_var())
    with pytest.raises(WriteAttempt):
        guard_s7(F.s7_header(0x01, 1, bytes([0x1A, 0x00])))


def test_s7_reads_setup_and_szl_are_allowed():
    guard_s7(F.s7_setup_request())
    guard_s7(F.s7_read_var())
    guard_s7(F.s7_szl_request())


def test_s7_userdata_groups_are_blocked():
    """Mode transition, password and block (download) userdata groups."""
    for group in (0x03, 0x08, 0x06, 0x09):
        param = F.s7_userdata_header(group=group)
        with pytest.raises(WriteAttempt):
            guard_s7(F.s7_header(0x07, 1, param, b"\xff\x09\x00\x04\x00\x00\x00\x00"))
    # the SZL group is fine
    guard_s7(F.s7_szl_request())


def test_cip_writes_are_refused():
    with pytest.raises(WriteAttempt):
        guard_cip(F.cip_write_tag("Tag1"))
    guard_cip(F.cip_read_tag("Tag1"))


def test_snmp_only_reads():
    set_request = b"\x30\x1c\x02\x01\x00\x04\x06public\xa3\x0f\x02\x01\x01\x02\x01\x00\x02\x01\x00"
    with pytest.raises(WriteAttempt):
        guard_snmp(set_request)
    get = probes_snmp_get_bytes()
    guard_snmp(get)


def probes_snmp_get_bytes() -> bytes:
    """Rebuild the exact GetRequest the SNMP probe sends."""
    oid = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    varbind = b"\x30" + bytes([len(oid) + 2]) + b"\x06" + bytes([len(oid)]) + oid + b"\x05\x00"
    vbl = b"\x30" + bytes([len(varbind)]) + varbind
    pdu = b"\xA0" + bytes([len(vbl) + 8]) + b"\x02\x01\x01\x02\x01\x00\x02\x01\x00" + vbl
    com = b"public"
    msg = b"\x02\x01\x00\x04" + bytes([len(com)]) + com + pdu
    return b"\x30" + bytes([len(msg)]) + msg


def test_policy_cannot_be_told_to_write():
    policy = ProbePolicy(allow_write=True)
    assert policy.allow_write is False
    assert any("ignored" in n for n in policy.notes)


def test_limiter_spaces_requests():
    import time

    limiter = Limiter(50)  # 20 ms
    start = time.monotonic()
    for _ in range(4):
        limiter.wait()
    assert time.monotonic() - start >= 0.05


# ------------------------------------------------------------ probe against devnet
def test_probe_identifies_siemens_rockwell_and_schneider():
    with DevNet() as net:
        policy = ProbePolicy(
            targets=net.targets,
            service_ports=net.policy_ports(),
            rate_per_second=60,
            timeout_s=2.0,
            do_snmp=True,
        )
        hosts = probes.probe_targets(net.targets, policy)

    s7 = hosts["127.0.0.2"]
    assert s7["vendor"] == "Siemens"
    assert s7["model"] == "6ES7 315-2EH14-0AB0"
    assert s7["family_hint"] == "S7-300"
    assert s7["identity"]["s7"]["steps"][-1] == "s7-szl-read"
    # the fragile-family note must be present for an S7-300
    assert s7["fragile"] is True
    # exact match: a truncated BER parse here once dropped the last character
    assert s7["identity"]["snmp"]["sysdescr"] == "Siemens, SIMATIC S7-300, CPU 315-2 PN/DP, V3.2.14"

    ab = hosts["127.0.0.3"]
    assert "Allen-Bradley" in ab["vendor"]
    assert ab["model"] == "1769-L33ER"
    assert ab["firmware"] == "32.11"
    assert ab["family_hint"] == "CompactLogix 5370"

    se = hosts["127.0.0.4"]
    assert "Schneider" in se["vendor"]
    assert se["model"] == "Modicon M340"
    assert se["firmware"] == "V3.30"

    erp = hosts["127.0.0.5"]
    assert erp["http_server"] == "SAP NetWeaver 7.50"


def test_fragile_family_gets_no_second_szl_read():
    """S7-300/400 get one identification session and nothing more."""
    profile = DeviceProfile(name="s300", host="127.0.0.21", services=("s7",), module="6ES7 315-2EH14-0AB0")
    with DevNet([profile]) as net:
        policy = ProbePolicy(service_ports=net.policy_ports(), rate_per_second=60, timeout_s=2.0)
        res = probes.probe_host("127.0.0.21", policy)
    steps = res["identity"]["s7"]["steps"]
    assert steps[-1] == "s7-szl-read"
    assert "s7-szl-components" not in steps
    assert res["firmware"] == ""


def test_non_fragile_s7_gets_firmware_version():
    """An S7-1500 gets the component SZL read, which yields the firmware."""
    profile = DeviceProfile(
        name="s1500", host="127.0.0.22", services=("s7",), module="6ES7 515-2AM01-0AB0", firmware="2.9.4"
    )
    with DevNet([profile]) as net:
        policy = ProbePolicy(service_ports=net.policy_ports(), rate_per_second=60, timeout_s=2.0)
        res = probes.probe_host("127.0.0.22", policy)
    assert res["family_hint"] == "S7-1500"
    assert res["firmware"] == "V2.9.4"
    assert "s7-szl-components" in res["identity"]["s7"]["steps"]


def test_probe_results_feed_vulnerability_matching():
    """The probe is what lets an asset with no traffic still be matched."""
    with DevNet() as net:
        eng = Engine(ScanConfig(name="devnet"))
        policy = ProbePolicy(targets=net.targets, service_ports=net.policy_ports(), rate_per_second=60, timeout_s=2.0)
        probe = probes.run(eng.stats, ScanConfig(name="devnet"), policy=policy)
        report = eng.analyse(probe=probe, source="devnet")

    advisories = {f.metric.get("advisory") for f in report.findings if f.fid.startswith("VULN-ICSA")}
    assert "ICSA-15-064-04" in advisories  # Siemens S7-300
    assert "ICSA-21-056-03" in advisories  # Rockwell, KEV
    assert "ICSA-25-114-01" in advisories  # Schneider M340
    # the probe must have filled the inventory in
    models = {a["ip"]: a["model"] for a in report.to_dict()["assets"] if a.get("model")}
    assert models["127.0.0.2"] == "6ES7 315-2EH14-0AB0"


def test_closed_ports_are_reported_not_guessed():
    """A port that did not answer must be reported closed, never inferred."""
    with DevNet() as net:
        ports = net.policy_ports()
        policy = ProbePolicy(targets=["127.0.0.5"], service_ports=ports, rate_per_second=60, timeout_s=1.0)
        res = probes.probe_host("127.0.0.5", policy)
    assert res["ports"][str(ports["http"])]["state"] == "open"
    assert res["ports"][str(ports["s7"])]["state"] == "closed"
    assert "s7" not in res["identity"]
    assert ports["s7"] not in res["open_ports"]


def test_unreachable_target_does_not_raise():
    policy = ProbePolicy(
        targets=["127.0.0.250"], service_ports=dict(DevNet.DEMO_PORTS), rate_per_second=60, timeout_s=0.3
    )
    res = probes.probe_host("127.0.0.250", policy)
    assert res["open_ports"] == []
    assert res["vendor"] == "" and res["model"] == ""


def test_wrong_snmp_community_gets_no_answer():
    with DevNet() as net:
        info = probes.snmp_sysdescr("127.0.0.2", "notpublic", timeout=0.5, port=net.policy_ports()["snmp"])
    assert "community_accepted" not in info
    assert "no SNMP response" in info["error"]


def test_snmp_get_request_is_well_formed_ber():
    """The probe's own GetRequest must have consistent BER lengths."""
    from otscope.active.probes import _ber_tlv, guard_snmp

    oid = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    varbind = b"\x30" + bytes([len(oid) + 2]) + b"\x06" + bytes([len(oid)]) + oid + b"\x05\x00"
    vbl = b"\x30" + bytes([len(varbind)]) + varbind
    pdu = b"\xA0" + bytes([len(vbl) + 9]) + b"\x02\x01\x01\x02\x01\x00\x02\x01\x00" + vbl
    com = b"public"
    msg = b"\x02\x01\x00\x04" + bytes([len(com)]) + com + pdu
    msg = b"\x30" + bytes([len(msg)]) + msg
    guard_snmp(msg)
    tag, seq, nxt = _ber_tlv(msg, 0)
    assert tag == 0x30 and nxt == len(msg), "outer SEQUENCE length must cover the whole message"
    _t, _v, i = _ber_tlv(seq, 0)
    _t, community, i = _ber_tlv(seq, i)
    assert community == b"public"
    tag, pdu_body, nxt = _ber_tlv(seq, i)
    assert tag == 0xA0, "GetRequest PDU"
    assert nxt == len(seq), "PDU length must cover the remainder of the message"
