"""Match inventoried assets against the advisory database."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from ..analysis.stats import TrafficStats
from ..config import ScanConfig
from ..models import SEVERITY_RANK, Asset, Finding, sev_rank
from ..util import stable_id, version_lt
from .db import AdvisoryDB

RANGE_RE = re.compile(r"(<=?)\s*(?:[A-Za-z]{0,3})\s*(\d[\w.]*)")

SEV_BY_CVSS = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")]


def sev_from_cvss(cvss: float) -> str:
    for limit, sev in SEV_BY_CVSS:
        if cvss >= limit:
            return sev
    return "info"


def parse_range(text: str) -> Tuple[bool, Optional[str]]:
    """Return (affects_all_versions, upper_bound_version)."""
    if not text:
        return True, None
    lowered = text.lower()
    if "all" in lowered and "<" not in text:
        return True, None
    m = RANGE_RE.search(text)
    if m:
        return False, m.group(2)
    return True, None


def asset_versions(asset: Asset) -> List[str]:
    out = []
    if asset.firmware:
        out.append(asset.firmware)
    m = re.findall(r"[Vv]?\d+(?:\.\d+)+", asset.model or "")
    out.extend(m)
    return out


def probe_hosts(probe: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Accept both the wrapped report form {"hosts": {...}} and a bare {ip: res}."""
    if not probe:
        return {}
    hosts = probe.get("hosts")
    return hosts if isinstance(hosts, dict) else probe


def match_asset(asset: Asset, db: AdvisoryDB, cfg: ScanConfig, probe: Optional[Dict[str, Any]] = None) -> List[Finding]:
    """Produce vulnerability findings for one asset."""
    out: List[Finding] = []
    pres: Dict[str, Any] = probe_hosts(probe).get(asset.ip or "") or {}
    families = {asset.family} if asset.family else set()
    if pres.get("family_hint"):
        families.add(pres["family_hint"])
    model = asset.model or pres.get("model") or ""
    if model:
        for fam in {f for a in db.advisories for f in a.families}:
            if fam.lower() in model.lower():
                families.add(fam)
    families.discard("")
    if not families:
        return out

    probe_ports = {int(p) for p, v in (pres.get("ports") or {}).items() if v.get("state") == "open"}
    observed_ports = set(asset.server_ports)
    reachable = observed_ports | probe_ports

    for adv in db.advisories:
        hit_families = families & set(adv.families)
        if not hit_families:
            continue
        entry = next((a for a in adv.affected if a.get("family") in hit_families), None)
        affects_all, bound = parse_range((entry or {}).get("range", ""))
        versions = asset_versions(asset)
        if not versions and pres.get("firmware"):
            versions = [pres["firmware"]]
        version = versions[0] if versions else ""
        confidence = "likely"
        reason = ""
        if affects_all:
            confidence = "likely" if not version else "confirmed"
            reason = (
                f"all versions of {', '.join(sorted(hit_families))} are affected"
                if not version
                else f"version {version} is inside the affected range ({(entry or {}).get('range', 'all')})"
            )
        elif bound:
            if not version:
                confidence = "possible"
                reason = f"affected below {bound}, but the running version could not be determined from the capture"
            elif version_lt(version, bound):
                confidence = "confirmed"
                reason = f"version {version} is older than the fixed version {bound}"
            else:
                continue
        ports = set(adv.ports)
        exposed = sorted(ports & reachable)
        if ports and not exposed:
            confidence = "latent" if confidence != "possible" else "possible"
            reason += f"; the vulnerable port(s) {sorted(ports)} were not observed in use by this asset"

        base = sev_from_cvss(adv.cvss)
        rank = sev_rank(base)
        if exposed and confidence in ("confirmed", "likely"):
            rank = min(4, rank + 1)
        if confidence == "possible":
            rank = max(0, rank - 1)
        if confidence == "latent":
            rank = max(0, rank - 1)
        if adv.kev:
            rank = min(4, max(rank, 3))

        sev = SEVERITY_RANK.get(rank, "info")

        evidence = [
            f"asset: {asset.ip or asset.key} - {asset.vendor or pres.get('vendor', '')} {model} "
            f"(family {asset.family or '?'}, firmware {asset.firmware or 'unknown'})",
            f"advisory {adv.id}" + (f" / {', '.join(adv.cve)}" if adv.cve else ""),
            f"CVSS v{adv.cvss_version} {adv.cvss}" + (f" ({adv.cvss_vector})" if adv.cvss_vector else ""),
            f"affected: {(entry or {}).get('range', 'see advisory')}" + (f", fixed in {(entry or {}).get('fixed')}" if (entry or {}).get("fixed") else ""),
            f"confidence: {confidence} - {reason}",
            f"vulnerable service: {sorted(ports) if ports else 'not port specific'}"
            + (f" - OBSERVED OPEN on this asset: {exposed}" if exposed else ""),
        ]
        if adv.kev:
            evidence.append("listed in the CISA Known Exploited Vulnerabilities catalog (active exploitation)")
        if adv.attack:
            evidence.append(f"attack: {adv.attack}")
        out.append(
            Finding(
                fid=f"VULN-{adv.id}-{stable_id(asset.key, adv.id)}",
                category="vuln",
                severity=sev,
                title=f"{asset.ip or asset.key}: {adv.vendor} {adv.title}",
                summary=(
                    f"{adv.vendor} {adv.product} - {adv.impact or adv.title}. "
                    f"Matching confidence: {confidence}."
                ),
                evidence=evidence,
                affected=[asset.ip or asset.key],
                recommendation=adv.remediation,
                references=[adv.source] if adv.source else [],
                first_ts=asset.first_ts,
                last_ts=asset.last_ts,
                metric={
                    "advisory": adv.id,
                    "cve": adv.cve,
                    "cvss": adv.cvss,
                    "confidence": confidence,
                    "exposed_ports": exposed,
                    "kev": adv.kev,
                    "family": sorted(hit_families),
                },
                tags=["vulnerability", adv.vendor.lower().replace(" ", "-")] + (["kev"] if adv.kev else []),
            )
        )
    return out


def analyse(stats: TrafficStats, cfg: ScanConfig, db: Optional[AdvisoryDB] = None, probe: Optional[Dict[str, Any]] = None) -> List[Finding]:
    db = db or AdvisoryDB.load()
    out: List[Finding] = []
    for asset in stats.assets.values():
        out.extend(match_asset(asset, db, cfg, probe))
    matched = {f.metric.get("advisory") for f in out}
    families = {a.family for a in stats.assets.values() if a.family}
    unmatched = sorted({adv.id for adv in db.advisories if not (set(adv.families) & families)})
    out.append(
        Finding(
            fid="VULN-COVERAGE",
            category="vuln",
            severity="info",
            title=f"Vulnerability matching: {len(out)} findings, {len(matched)} advisories matched",
            summary=(
                f"The bundled database holds {len(db.advisories)} advisories covering "
                f"{len({f for a in db.advisories for f in a.families})} product families. "
                f"{len(matched)} matched an inventoried asset."
                + (f" Not matched (no such product found on the network): {', '.join(unmatched[:8])}." if unmatched else "")
            ),
            evidence=[
                f"inventoried families: {', '.join(sorted(families)) or 'none identified'}",
                f"database: {len(db.advisories)} advisories, generated {db.generated}",
            ],
            recommendation=(
                "Assets that could not be identified cannot be matched - run the read-only probe so "
                "model and firmware version become known."
            ),
            first_ts=stats.first_ts,
            last_ts=stats.last_ts,
            metric={"matched": sorted(matched), "unmatched": unmatched, "db": db.summary()},
            tags=["coverage"],
        )
    )
    return out
