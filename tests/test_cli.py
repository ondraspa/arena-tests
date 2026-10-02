"""End-to-end CLI tests: the commands a user actually types."""

from __future__ import annotations

import json
import os

import pytest

from otscope.cli import main
from otscope.devnet import DevNet


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "otscope" in capsys.readouterr().out


def test_selftest_passes():
    """The built-in selftest is the project's own check; it must pass."""
    assert main(["selftest"]) == 0


def test_scenarios_lists_every_builder(capsys):
    from otscope import scenarios

    assert main(["scenarios"]) == 0
    out = capsys.readouterr().out
    for name in scenarios.SCENARIOS:
        assert name in out, name


def test_demo_console(tmp_path, capsys):
    assert main(["demo", "--pcap", str(tmp_path / "d.pcap"), "--scenario", "s7-stop", "--format", "console"]) == 0
    out = capsys.readouterr().out
    assert "CRASH-CONTROL-COMMAND" in out
    assert os.path.exists(tmp_path / "d.pcap")


def test_demo_json_roundtrip(tmp_path):
    out = tmp_path / "r.json"
    assert main(["demo", "--pcap", str(tmp_path / "d.pcap"), "--format", "json", "--out", str(out)]) == 0
    data = json.loads(out.read_text())
    assert data["summary"]["findings"] == len(data["findings"])
    assert any(f["id"].startswith("VULN-ICSA") for f in data["findings"])


def test_demo_html(tmp_path):
    out = tmp_path / "r.html"
    assert main(["demo", "--pcap", str(tmp_path / "d.pcap"), "--scenario", "switch-loop", "--format", "html", "--out", str(out)]) == 0
    assert "<!doctype html>" in out.read_text()


def test_scan_a_pcap(tmp_path, capsys):
    from otscope import scenarios

    pcap = str(tmp_path / "s.pcap")
    scenarios.write_pcap(pcap, ["port-scan", "broadcast-storm"])
    assert main(["scan", pcap, "--format", "json", "--out", str(tmp_path / "s.json")]) == 0
    data = json.loads((tmp_path / "s.json").read_text())
    ids = {f["id"] for f in data["findings"]}
    assert any(i.startswith("ANOM-SCAN") for i in ids)
    assert any(i.startswith("LOOP-ARP-STORM") for i in ids)


def test_scan_strict_exit_code(tmp_path):
    from otscope import scenarios

    pcap = str(tmp_path / "s.pcap")
    scenarios.write_pcap(pcap, ["s7-stop"])
    assert main(["scan", pcap, "--format", "json", "--out", str(tmp_path / "a.json")]) == 0
    assert main(["scan", pcap, "--strict", "--format", "json", "--out", str(tmp_path / "b.json")]) == 1


def test_scan_missing_file():
    with pytest.raises(SystemExit):
        main(["scan", "/nonexistent/nope.pcap"])


def test_probe_against_the_emulated_plant(capsys):
    with DevNet() as net:
        ports = " ".join(f"--service-port {k}={v}" for k, v in net.policy_ports().items())
        argv = f"probe {' '.join(net.targets)} {ports} --rate 60 --snmp".split()
        assert main(argv) == 0
    out = capsys.readouterr().out
    assert "6ES7 315-2EH14-0AB0" in out
    assert "1769-L33ER" in out
    assert "Modicon M340" in out


def test_probe_json(tmp_path):
    with DevNet() as net:
        argv = ["probe", "127.0.0.4", "--format", "json", "--out", str(tmp_path / "p.json"), "--rate", "60"]
        for name, port in net.policy_ports().items():
            argv += ["--service-port", f"{name}={port}"]
        assert main(argv) == 0
    data = json.loads((tmp_path / "p.json").read_text())
    assert data["hosts"]["127.0.0.4"]["model"] == "Modicon M340"
    assert data["policy"]["read_only"] is True


def test_advisories_list_and_show(capsys):
    assert main(["advisories", "list"]) == 0
    out = capsys.readouterr().out
    assert "ICSA-15-064-04" in out
    assert "product lifecycle" in out

    assert main(["advisories", "show", "ICSA-21-056-03"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["id"] == "ICSA-21-056-03"
    assert "CVE-2021-22681" in shown["cve"]
    assert shown["kev"] is True

    assert main(["advisories", "show", "CVE-2018-7843"]) == 0
    assert json.loads(capsys.readouterr().out)["id"] == "ICSA-25-114-01"


def test_config_example_is_loadable(tmp_path):
    out = tmp_path / "cfg.json"
    assert main(["config", "--out", str(out)]) == 0
    from otscope.config import ScanConfig

    cfg = ScanConfig.load(str(out))
    assert cfg.subnets
    assert cfg.engineering_stations


def test_state_is_persisted_across_runs(tmp_path):
    """The state file is what makes `watch` able to say what is new."""
    from otscope import scenarios
    from otscope.store import State

    pcap = str(tmp_path / "s.pcap")
    scenarios.write_pcap(pcap, ["s7-stop"])
    state = str(tmp_path / "state.json")
    common = ["scan", pcap, "--state", state, "--format", "json", "--out", str(tmp_path / "a.json")]
    assert main(common) == 0
    assert os.path.exists(state)
    saved = json.loads(open(state).read())
    assert saved["findings"], saved
    assert saved["runs"], saved
    assert any(k.startswith("CRASH-CONTROL-COMMAND") for k in saved["findings"])

    # a second run sees the same findings, so nothing is new any more
    before = State(state)
    known = set(before.data["findings"])
    assert main(common) == 0
    after = json.loads(open(state).read())
    assert set(after["findings"]) == known
    assert len(after["runs"]) == len(saved["runs"]) + 1
    stop = [k for k in after["findings"] if k.startswith("CRASH-CONTROL-COMMAND")]
    assert stop, after["findings"]
    assert after["findings"][stop[0]]["count"] >= 1
