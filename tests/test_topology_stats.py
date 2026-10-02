"""Inventory, flow statistics and the layer-2 / protocol-fault correlation."""

from __future__ import annotations

from otscope import frames as F, scenarios
from otscope.analysis.engine import analyse_file
from otscope.analysis.stats import TrafficStats
from otscope.config import ScanConfig
from otscope.packets import parse_frame

from .conftest import capture_of

SW = "00:1b:1b:00:00:01"
HMI_MAC = "00:0e:8c:11:22:33"


def _stats_of(names, cfg=None) -> TrafficStats:
    from otscope.analysis.engine import Engine
    from otscope.capture import iter_file, iter_frames

    path = "/tmp/otscope-topology.pcap"
    scenarios.write_pcap(path, names)
    eng = Engine(cfg)
    for pkt in iter_frames(iter_file(path), iface="eth0"):
        eng.feed(pkt)
    return eng.stats


def test_controller_roles_and_purdue_levels(tmp_path):
    report = analyse_file(capture_of(tmp_path, ["baseline"]))
    assets = {a["ip"]: a for a in report.to_dict()["assets"] if a.get("ip")}
    assert assets["10.20.2.10"]["role"] == "controller"
    assert assets["10.20.3.20"]["role"] == "controller"
    assert assets["10.20.4.30"]["role"] == "controller"
    # with no profile every HMI-tier host is "hmi-scada"; ...
    assert assets["10.20.1.10"]["role"] == "hmi-scada"
    # JSON turns the port keys into strings
    assert "102" in assets["10.20.2.10"]["server_ports"]
    assert "502" in assets["10.20.4.30"]["server_ports"]
    assert "44818" in assets["10.20.3.20"]["server_ports"]


def test_configured_engineering_station_gets_its_role(tmp_path):
    cfg = ScanConfig(name="site")
    cfg.engineering_stations = ["10.20.1.10"]
    cfg.erp_hosts = ["10.10.0.21"]
    report = analyse_file(capture_of(tmp_path, ["baseline"]), cfg=cfg)
    assets = {a["ip"]: a for a in report.to_dict()["assets"] if a.get("ip")}
    assert assets["10.20.1.10"]["role"] == "engineering-station"
    assert assets["10.10.0.21"]["role"] == "erp-server"


def test_a_syn_does_not_make_a_service(tmp_path):
    """A scan target must not be inventoried as running the scanned services."""
    report = analyse_file(capture_of(tmp_path, ["port-scan"]))
    scanned = {a["ip"]: a for a in report.to_dict()["assets"] if a.get("ip")}
    victim = scanned.get("10.20.2.10")
    assert victim is not None
    assert victim["probed_ports"], "the scan itself must be recorded"
    assert not victim["server_ports"], victim["server_ports"]


def test_protocols_are_counted_per_asset():
    stats = _stats_of(["baseline"])
    plc = stats.assets["10.20.2.10"]
    assert plc.protocols.get("s7comm")
    assert plc.protocols.get("cotp")
    ab = stats.assets["10.20.3.20"]
    assert ab.protocols.get("enip")
    modicon = stats.assets["10.20.4.30"]
    assert modicon.protocols.get("modbus")


def test_l2_only_device_is_inventoried_by_mac():
    """A switch that only sends STP/LLDP has no IP - it must still appear."""
    stats = _stats_of(["baseline"])
    switch = stats.assets.get(SW)
    assert switch is not None
    assert switch.ip is None
    assert switch.protocols.get("stp") or switch.protocols.get("lldp")


def test_mac_keyed_record_merges_into_the_ip_record():
    """When the same device is later seen with an IP, the two records merge."""
    stats = TrafficStats(ScanConfig())
    frame = F.eth("01:80:c2:00:00:00", SW, F.stp_bpdu(SW, SW), etype=0x0026)
    pkt = parse_frame(frame, ts=100.0, iface="eth0")
    from otscope.dissect.registry import dissect

    stats.add(pkt, dissect(pkt))
    assert SW in stats.assets
    assert stats.assets[SW].ip is None

    # now the switch answers ARP with an IP
    arp = F.eth(HMI_MAC, SW, F.arp(2, SW, "10.20.0.1", HMI_MAC, "10.20.1.10"), etype=0x0806)
    pkt2 = parse_frame(arp, ts=101.0, iface="eth0")
    stats.add(pkt2, dissect(pkt2))
    merged = stats.asset("10.20.0.1")
    assert merged is not None
    assert merged.mac == SW
    assert merged.protocols.get("stp"), "the layer-2 history must survive the merge"


def test_retransmissions_are_counted_per_flow():
    stats = _stats_of(["retransmission"])
    retrans = sum(f.retrans for f in stats.flows.values())
    assert retrans >= 20
    # the same frames must NOT be blamed on a switching loop
    report_ids = {f.fid for f in __import__("otscope.analysis.engine", fromlist=["analyse_file"]).analyse_file("/tmp/otscope-topology.pcap").findings}
    assert any(i.startswith("PERF-RETRANS") for i in report_ids)
    assert not any(i.startswith("LOOP-FRAME-REPEAT") for i in report_ids)


def test_broadcast_ratio_is_measured():
    stats = _stats_of(["broadcast-storm"])
    total = stats.total_frames
    bcast = sum(b.bcast for b in stats.bucket_list())
    assert bcast / total > 0.5


# --------------------------------------------------------- correlation (the signature feature)
def test_protocol_faults_alone_are_not_blamed_on_the_network(tmp_path):
    report = analyse_file(capture_of(tmp_path, ["s7-faults"]))
    assert any(f.fid.startswith("CRASH-S7-FAULT") for f in report.findings)
    assert not any(f.fid == "CRASH-CORRELATED-L2" for f in report.findings)


def test_protocol_faults_during_a_loop_are_correlated(tmp_path):
    """Faults inside +/-5 s of a layer-2 event point at the loop, not the PLC."""
    report = analyse_file(capture_of(tmp_path, ["s7-faults", "switch-loop"]))
    corr = [f for f in report.findings if f.fid == "CRASH-CORRELATED-L2"]
    assert corr, [f.fid for f in report.findings]
    assert corr[0].severity == "critical"
    assert "root cause" in corr[0].title.lower() or "root cause" in corr[0].summary.lower()
    assert corr[0].metric["correlated"] >= 3
    assert corr[0].recommendation


def test_correlation_window_is_bounded(tmp_path):
    """A storm long after the faults must not be correlated with them."""
    cfg = ScanConfig(name="tight")
    cfg.thresholds.correlation_window = 0.0  # nothing can correlate
    stats = _stats_of(["s7-faults", "switch-loop"], cfg=cfg)
    from otscope.analysis import crashes

    findings = crashes.analyse(stats, cfg)
    assert not [f for f in findings if f.fid == "CRASH-CORRELATED-L2"]
