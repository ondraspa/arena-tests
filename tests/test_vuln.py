"""Advisory matching: confidence tiers, exposure, KEV escalation, EOL."""

from __future__ import annotations

import json
import re

import pytest

from otscope.analysis.stats import TrafficStats
from otscope.config import ScanConfig
from otscope.models import Asset, sev_rank
from otscope.vuln import feeds, forward, matcher
from otscope.vuln.db import AdvisoryDB


def make_asset(**kw) -> Asset:
    a = Asset(key=kw.get("ip", "10.0.0.1"))
    for k, v in kw.items():
        setattr(a, k, v)
    return a


@pytest.fixture(scope="module")
def db() -> AdvisoryDB:
    return AdvisoryDB.load()


def test_bundled_database_shape(db):
    assert len(db.advisories) >= 14
    assert len(db.lifecycle) >= 4
    for adv in db.advisories:
        assert adv.families, adv.id
        assert adv.source, f"{adv.id} has no source"
        assert adv.checked, f"{adv.id} has no verification date"
        assert 0 <= adv.cvss <= 10
        for cve in adv.cve:
            assert re.fullmatch(r"CVE-\d{4}-\d{4,}", cve), (adv.id, cve)


def test_known_advisories_are_present(db):
    ids = {a.id for a in db.advisories}
    for expected in (
        "ICSA-15-064-04",  # S7-300 ISO-TSAP DoS
        "ICSA-17-339-01",  # Siemens SNMP DoS
        "ICSA-21-056-03",  # Rockwell, CISA KEV
        "ICSA-25-114-01",  # Schneider Modicon DoS
        "ICSA-20-329-01",  # FactoryTalk Linx
    ):
        assert expected in ids


def test_lifecycle_records(db):
    s7_300 = db.lifecycle_for("S7-300")
    assert s7_300 is not None
    assert s7_300.phase_out_announced == "2023-10-01"
    assert s7_300.type_cancellation == "2025-10-01"
    assert s7_300.spare_parts_until == "2033-10-01"
    assert db.lifecycle_for("Modicon Premium").phase_out_announced == "2018-12-01"
    assert db.lifecycle_for("S7-1500") is None  # still in production


def test_for_family(db):
    s7 = {a.id for a in db.for_family("S7-300")}
    assert {"ICSA-15-064-04", "ICSA-17-339-01", "ICSA-20-070-02"} <= s7
    assert db.for_family("No such product") == []


def test_affected_all_versions_is_confirmed(db):
    asset = make_asset(ip="10.20.2.10", family="S7-300", vendor="Siemens", model="6ES7 315-2EH14-0AB0")
    asset.server_ports[102] = "S7comm"
    findings = matcher.match_asset(asset, db, ScanConfig())
    adv = {f.metric["advisory"]: f for f in findings}
    assert "ICSA-15-064-04" in adv
    # all versions are affected and the version could not be read from the
    # capture, so the honest confidence is "likely"; exposure makes it critical
    assert adv["ICSA-15-064-04"].metric["confidence"] == "likely"
    assert adv["ICSA-15-064-04"].severity == "critical"


def test_version_inside_range_is_confirmed(db):
    asset = make_asset(ip="10.20.4.30", family="Modicon M340", firmware="V3.30")
    asset.server_ports[502] = "Modbus"
    findings = {f.metric["advisory"]: f for f in matcher.match_asset(asset, db, ScanConfig())}
    assert findings["ICSA-25-114-01"].metric["confidence"] == "confirmed"  # fixed in SV3.60


def test_version_at_or_above_fix_is_not_reported(db):
    asset = make_asset(ip="10.20.4.31", family="Modicon M340", firmware="V3.60")
    asset.server_ports[502] = "Modbus"
    findings = {f.metric["advisory"]: f for f in matcher.match_asset(asset, db, ScanConfig())}
    assert "ICSA-25-114-01" not in findings


def test_unknown_version_downgrades_confidence(db):
    asset = make_asset(ip="10.20.4.32", family="Modicon M340")  # no firmware
    asset.server_ports[502] = "Modbus"
    findings = {f.metric["advisory"]: f for f in matcher.match_asset(asset, db, ScanConfig())}
    assert findings["ICSA-25-114-01"].metric["confidence"] == "possible"


def test_unexposed_port_becomes_latent(db):
    """CVSS says 7.8, but 102/tcp is not reachable - so it must not read as critical."""
    exposed = make_asset(ip="10.0.0.1", family="S7-300")
    exposed.server_ports[102] = "S7comm"
    hidden = make_asset(ip="10.0.0.2", family="S7-300")
    hidden.server_ports[161] = "SNMP"
    e = {f.metric["advisory"]: f for f in matcher.match_asset(exposed, db, ScanConfig())}
    h = {f.metric["advisory"]: f for f in matcher.match_asset(hidden, db, ScanConfig())}
    assert e["ICSA-15-064-04"].metric["confidence"] == "likely"
    assert h["ICSA-15-064-04"].metric["confidence"] == "latent"
    assert sev_rank(h["ICSA-15-064-04"].severity) < sev_rank(e["ICSA-15-064-04"].severity)


def test_kev_membership_forces_at_least_high(db):
    asset = make_asset(ip="10.20.3.20", family="CompactLogix 5370", model="1769-L33ER")
    findings = {f.metric["advisory"]: f for f in matcher.match_asset(asset, db, ScanConfig())}
    kev = findings["ICSA-21-056-03"]
    assert kev.metric["kev"] is True
    assert sev_rank(kev.severity) >= 3, kev.severity


def test_probe_results_are_used_for_matching(db):
    """The probe dict form used by the report ({'hosts': {...}}) must be understood."""
    asset = make_asset(ip="10.20.2.10", family="S7-300")
    probe = {"hosts": {"10.20.2.10": {"ports": {"102": {"state": "open"}}, "firmware": "V3.2.14"}}}
    without = {f.metric["advisory"]: f for f in matcher.match_asset(asset, db, ScanConfig())}
    with_probe = {f.metric["advisory"]: f for f in matcher.match_asset(asset, db, ScanConfig(), probe=probe)}
    # without the probe the port is unknown, so exposure cannot be confirmed
    assert without["ICSA-15-064-04"].metric["confidence"] == "latent"
    assert with_probe["ICSA-15-064-04"].metric["confidence"] == "confirmed"
    # a bare {ip: result} mapping is accepted too
    bare = {f.metric["advisory"]: f for f in matcher.match_asset(asset, db, ScanConfig(), probe=probe["hosts"])}
    assert bare["ICSA-15-064-04"].metric["confidence"] == "confirmed"


def test_coverage_finding_lists_unmatched_families(db):
    stats = TrafficStats(ScanConfig())
    stats.assets["10.20.2.10"] = make_asset(ip="10.20.2.10", family="S7-300")
    findings = matcher.analyse(stats, ScanConfig(), db=db)
    cov = [f for f in findings if f.fid == "VULN-COVERAGE"]
    assert len(cov) == 1
    assert "FactoryTalk Linx" in cov[0].summary or "Not matched" in cov[0].summary


def test_unknown_assets_are_reported_not_ignored(db):
    stats = TrafficStats(ScanConfig())
    stats.assets["10.0.0.9"] = make_asset(ip="10.0.0.9")
    findings = matcher.analyse(stats, ScanConfig(), db=db)
    assert any("could not be identified" in f.recommendation for f in findings)


def test_forward_eol_finding():
    stats = TrafficStats(ScanConfig())
    stats.assets["10.20.2.10"] = make_asset(ip="10.20.2.10", family="S7-300", vendor="Siemens")
    findings = forward.analyse(stats, ScanConfig(), db=AdvisoryDB.load())
    eol = [f for f in findings if f.fid.startswith("FWD-EOL")]
    assert eol, "S7-300 must be flagged as discontinued"
    assert eol[0].severity == "high"  # type cancellation 2025-10-01 has passed
    assert "2033-10-01" in " ".join(eol[0].evidence)


def test_forward_unauthenticated_protocols():
    stats = TrafficStats(ScanConfig())
    a = make_asset(ip="10.20.2.10", family="S7-300")
    a.protocols["s7comm"] = 100
    stats.protocols["s7comm"] = 100
    stats.assets["10.20.2.10"] = a
    findings = forward.analyse(stats, ScanConfig(), db=AdvisoryDB.load())
    assert any(f.fid == "FWD-NOAUTH-S7COMM" for f in findings)


def test_kev_feed_parsing_with_a_local_catalog(tmp_path):
    """The live CISA endpoint is unreachable in CI, so parse a local catalog."""
    catalog = {
        "catalogVersion": "2026.10.02",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-22681",
                "product": "CompactLogix",
                "vulnerabilityName": "Insufficiently protected credentials",
                "shortDescription": "x",
                "dateAdded": "2022-02-10",
                "requiredAction": "Apply updates",
            }
        ],
    }
    path = str(tmp_path / "kev.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(catalog, fh)
    db = AdvisoryDB.load(use_kev_cache=False)
    assert db.kev == {}
    n = db.load_kev_cache(path)
    db.dedupe()
    assert n == 1
    assert db.kev_catalog_version == "2026.10.02"
    assert next(a for a in db.advisories if a.id == "ICSA-21-056-03").kev is True
    count, notes = feeds.enrich(db, kev_path=path)
    assert count >= 1
    assert not any("no KEV cache" in n for n in notes)


def test_version_comparison_helpers():
    from otscope.util import version_cmp, version_lt

    assert version_lt("3.2.14", "3.3.12")
    assert not version_lt("3.3.12", "3.2.14")
    assert version_cmp("V3.60", "V3.60") == 0
    assert version_cmp("V3.60", "SV3.60") == 0  # vendor prefixes carry no order
    assert version_cmp("V3.60", "3.60") == 0
    assert version_lt("V3.30", "SV3.60")
    assert version_lt("6.11", "6.20")
    assert not version_lt("V3.60", "SV3.60")
