"""Capture I/O round-trips and the four report renderers."""

from __future__ import annotations

import json

import pytest

from otscope import frames as F, report as report_mod, scenarios
from otscope.pcap import CaptureError, PcapWriter, iter_capture, iter_pcap
from otscope.packets import parse_frame


def test_pcap_write_read_roundtrip(tmp_path):
    path = str(tmp_path / "rt.pcap")
    frame = F.eth(
        "00:0e:8c:aa:00:10",
        "00:0e:8c:11:22:33",
        F.ip("10.20.2.10", "10.20.1.10", 6, F.tcp(102, 49152, b"payload", src="10.20.2.10", dst="10.20.1.10")),
    )
    with PcapWriter(path) as w:
        w.write(frame, ts=1700000000.5)
        w.write(frame, ts=1700000001.25)
    got = list(iter_pcap(path))
    assert len(got) == 2
    assert got[0][0] == pytest.approx(1700000000.5, abs=1e-6)
    assert got[1][0] > got[0][0]
    assert got[0][3] == frame


def test_capture_rejects_a_non_pcap_file(tmp_path):
    path = tmp_path / "not-a-capture.pcap"
    path.write_bytes(b"this is definitely not a pcap file, not even close")
    with pytest.raises(CaptureError):
        list(iter_capture(str(path)))


def test_iter_capture_accepts_our_own_writer(tmp_path):
    path = str(tmp_path / "x.pcap")
    scenarios.write_pcap(path, ["s7-stop"])
    frames = list(iter_capture(path))
    assert len(frames) == 4
    assert all(parse_frame(f[3], ts=f[0], iface="x") is not None for f in frames)


def test_scenario_frame_count_is_stable():
    """The scenario timeline is the regression baseline; it must not drift."""
    assert scenarios.write_pcap("/tmp/otscope-stable.pcap") == scenarios.write_pcap("/tmp/otscope-stable2.pcap")
    assert len(scenarios.build(sorted(scenarios.SCENARIOS))) > 3000


# ----------------------------------------------------------------- renderers
def test_console_report(full_report):
    text = report_mod.to_console(full_report)
    assert "otscope" in text
    assert "CRASH-CORRELATED-L2" in text
    assert "INVENTORY" in text
    assert "6ES7 315-2EH14-0AB0" in text


def test_markdown_report(full_report):
    text = report_mod.to_markdown(full_report)
    assert text.startswith("# otscope report")
    assert "| severity | count |" in text
    assert "## Inventory" in text
    assert "ICSA-21-056-03" in text


def test_json_report_is_complete(full_report):
    data = json.loads(report_mod.to_json(full_report))
    for key in (
        "version",
        "summary",
        "findings",
        "assets",
        "segments",
        "flows",
        "timeline",
        "protocol_frames",
        "warnings",
    ):
        assert key in data, key
    assert data["summary"]["findings"] == len(data["findings"])
    assert data["warnings"] == []
    # every finding is fully serialised
    for f in data["findings"]:
        assert f["id"] and f["severity"] and f["title"] and f["summary"]
        assert f["severity"] in ("critical", "high", "medium", "low", "info")


def test_html_report_is_self_contained(full_report):
    text = report_mod.to_html(full_report)
    assert text.startswith("<!doctype html>")
    # no CDN, no external asset: the plant network is offline
    for banned in ("http://", "https://cdn", "//cdn.", "googleapis", "unpkg", "jsdelivr", "<link rel=\"stylesheet\""):
        assert banned not in text.replace("http://www.w3.org", ""), banned
    assert "<style>" in text and "<svg" in text
    assert "CRASH-CORRELATED-L2" in text
    assert "6ES7 315-2EH14-0AB0" in text


def test_report_severity_counts_match(full_report):
    sev = full_report.by_severity()
    assert sum(sev.values()) == len(full_report.findings)
    data = json.loads(report_mod.to_json(full_report))
    assert data["summary"]["severity"] == sev
