"""Known-answer tests: each scenario injects one problem, one finding must catch it."""

from __future__ import annotations

import pytest

from otscope import scenarios
from otscope.analysis.engine import analyse_file

from .conftest import capture_of

# scenario -> finding id prefixes that must appear
EXPECTED = {
    "arp-conflict": ["ANOM-IP-CONFLICT"],
    "broadcast-storm": ["LOOP-ARP-STORM", "LOOP-BCAST-STORM"],
    "cip-errors": ["CRASH-CIP-FAULT"],
    "dcp-rename": ["ANOM-DCP-SET"],
    "erp-writes-plc": ["ANOM-WRITE-PLC"],
    "insecure-services": ["FWD-INSECURE"],
    "malformed-s7": ["CRASH-MALFORMED-PROTOCOL-FRAMES"],
    "modbus-faults": ["CRASH-MODBUS-EXCEPTION"],
    "mrp-double-manager": ["LOOP-MRP-DOUBLE-MANAGER"],
    "polling-gap": ["PERF-POLL-GAP"],
    "port-scan": ["ANOM-SCAN"],
    "retransmission": ["PERF-RETRANS"],
    "s7-faults": ["CRASH-S7-FAULT"],
    "s7-stop": ["CRASH-CONTROL-COMMAND"],
    "slow-erp": ["PERF-SLOW-HTTP"],
    "snmp-flood": ["CRASH-SNMP-FLOOD"],
    "switch-loop": ["LOOP-STP-TCN-STORM", "LOOP-FRAME-REPEAT"],
    "zero-window": ["PERF-ZEROWINDOW"],
}


def _report(tmp_path, names):
    return analyse_file(capture_of(tmp_path, names))


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_scenario_is_detected(tmp_path, name):
    report = _report(tmp_path, [name])
    assert report.stats.total_frames > 0
    ids = {f.fid for f in report.findings}
    missing = [prefix for prefix in EXPECTED[name] if not any(i.startswith(prefix) for i in ids)]
    assert not missing, f"{name}: missing {missing}; got {sorted(ids)}"


def test_every_scenario_is_covered():
    assert set(EXPECTED) | {"baseline"} == set(scenarios.SCENARIOS)


def test_healthy_traffic_produces_no_fault_or_loop_findings(tmp_path):
    """The baseline must be clean, or the tool cries wolf on a working plant."""
    report = _report(tmp_path, ["baseline"])
    noisy = [
        f.fid
        for f in report.findings
        if f.fid.startswith(("CRASH-", "LOOP-")) or f.fid.startswith("PERF-RETRANS")
    ]
    assert not noisy, noisy
    assert not [w for w in report.warnings], report.warnings


def test_healthy_traffic_still_identifies_all_three_vendors(tmp_path):
    report = _report(tmp_path, ["baseline"])
    assets = {a["ip"]: a for a in report.to_dict()["assets"] if a.get("ip")}
    assert assets["10.20.2.10"]["family"] == "S7-300"
    assert assets["10.20.2.10"]["model"] == "6ES7 315-2EH14-0AB0"
    assert assets["10.20.3.20"]["family"] == "CompactLogix 5370"
    assert assets["10.20.3.20"]["firmware"] == "32.11"
    assert assets["10.20.4.30"]["family"].startswith("Modicon")
    assert assets["10.20.4.30"]["firmware"] == "V3.30"


def test_all_three_vendors_get_advisory_matches(tmp_path):
    report = _report(tmp_path, ["baseline"])
    by_ip = {}
    for f in report.findings:
        if f.fid.startswith("VULN-ICSA"):
            ip = f.metric.get("ip") or (f.affected[0] if f.affected else "")
            by_ip.setdefault(ip, []).append(f.metric.get("advisory"))
    assert "ICSA-15-064-04" in by_ip.get("10.20.2.10", []), by_ip
    assert "ICSA-21-056-03" in by_ip.get("10.20.3.20", []), by_ip
    assert "ICSA-25-114-01" in by_ip.get("10.20.4.30", []), by_ip


def test_kev_membership_raises_severity(tmp_path):
    """CVE-2021-22681 is in the CISA KEV, so it cannot be reported below high."""
    report = _report(tmp_path, ["baseline"])
    kev = [f for f in report.findings if f.metric.get("kev")]
    assert kev, "expected at least one KEV-flagged advisory match"
    from otscope.models import sev_rank

    assert all(sev_rank(f.severity) >= 3 for f in kev), [(f.fid, f.severity) for f in kev]


def test_combined_capture_has_no_dissector_errors(full_report):
    assert full_report.stats.protocols.get("dissector-error", 0) == 0
    assert full_report.warnings == []
