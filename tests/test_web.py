"""Dashboard: every endpoint, no external dependency, no blocking on a scan."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("flask")

from otscope.web import app as webapp  # noqa: E402
from otscope.devnet import DevNet  # noqa: E402


@pytest.fixture()
def client(tmp_path, full_capture):
    webapp.STATE.__init__()
    application = webapp.create_app(pcap=full_capture)
    webapp.run_scan(pcap=full_capture)  # synchronous, so the assertions are deterministic
    return application.test_client()


def test_index_has_no_external_dependencies(client):
    body = client.get("/").get_data(as_text=True)
    assert "<title>otscope dashboard</title>" in body
    for banned in ("cdn.", "unpkg", "jsdelivr", "googleapis", "bootstrap.min"):
        assert banned not in body, banned
    assert "EventSource('/api/stream')" in body


def test_healthz(client):
    data = client.get("/healthz").get_json()
    assert data["ok"] is True
    assert data["version"]


def test_status_and_report(client):
    status = client.get("/api/status").get_json()
    assert status["busy"] is False
    assert status["findings"] > 0
    assert status["severity"]["critical"] > 0

    report = client.get("/api/report").get_json()
    assert report["summary"]["findings"] == len(report["findings"])
    assert any(f["id"] == "CRASH-CORRELATED-L2" for f in report["findings"])

    only = client.get("/api/report?only=critical").get_json()
    assert only["findings"]
    assert all(f["severity"] == "critical" for f in only["findings"])

    limited = client.get("/api/report?limit=3").get_json()
    assert len(limited["findings"]) == 3


def test_findings_filter(client):
    findings = client.get("/api/findings?category=loop").get_json()
    assert findings
    assert all(f["category"] == "loop" for f in findings)


def test_printable_report(client):
    body = client.get("/report.html").get_data(as_text=True)
    assert "<!doctype html>" in body
    assert "Findings" in body


def test_advisories_endpoint(client):
    data = client.get("/api/advisories").get_json()
    assert data["summary"]["advisories"] >= 14
    assert any(a["id"] == "ICSA-15-064-04" for a in data["advisories"])
    assert any(lc["family"] == "S7-300" for lc in data["lifecycle"])


def test_scan_endpoint_runs(client):
    first = client.get("/api/status").get_json()["generation"]
    resp = client.post("/api/scan", json={})
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True
    for _ in range(100):
        if client.get("/api/status").get_json()["generation"] != first:
            break
        time.sleep(0.05)
    assert client.get("/api/status").get_json()["generation"] != first


def test_probe_endpoint_is_read_only(client):
    with DevNet() as net:
        resp = client.post(
            "/api/probe",
            json={"targets": ["127.0.0.4"], "rate": 60, "service_ports": net.policy_ports()},
        )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["hosts"]["127.0.0.4"]["model"] == "Modicon M340"
    assert data["policy"]["read_only"] is True


def test_probe_endpoint_rejects_no_targets(client):
    resp = client.post("/api/probe", json={"targets": []})
    assert resp.status_code == 400
