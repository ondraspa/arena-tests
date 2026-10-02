"""Advisory database loader (bundled + user-supplied + KEV enrichment)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
BUNDLED = os.path.join(DATA_DIR, "advisories.json")
LOCAL = os.path.join(DATA_DIR, "local.json")
KEV_CACHE = os.path.join(DATA_DIR, "cache", "kev.json")


@dataclass
class Advisory:
    id: str
    vendor: str
    product: str
    title: str
    families: List[str]
    affected: List[Dict[str, str]]
    cvss: float = 0.0
    cvss_version: int = 3
    cvss_vector: str = ""
    cwe: str = ""
    ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    attack: str = ""
    impact: str = ""
    remediation: str = ""
    published: str = ""
    source: str = ""
    cve: List[str] = field(default_factory=list)
    kev: bool = False
    checked: str = ""
    lifecycle_note: str = ""

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Advisory":
        return cls(
            id=raw.get("id", ""),
            vendor=raw.get("vendor", ""),
            product=raw.get("product", ""),
            title=raw.get("title", ""),
            families=list(raw.get("families", [])),
            affected=list(raw.get("affected", [])),
            cvss=float(raw.get("cvss", 0) or 0),
            cvss_version=int(raw.get("cvss_version", 3) or 3),
            cvss_vector=raw.get("cvss_vector", ""),
            cwe=raw.get("cwe", ""),
            ports=[int(p) for p in raw.get("ports", [])],
            protocols=list(raw.get("protocols", [])),
            attack=raw.get("attack", ""),
            impact=raw.get("impact", ""),
            remediation=raw.get("remediation", ""),
            published=raw.get("published", ""),
            source=raw.get("source", ""),
            cve=list(raw.get("cve", [])),
            kev=bool(raw.get("kev", False)),
            checked=raw.get("checked", ""),
            lifecycle_note=raw.get("lifecycle_note", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vendor": self.vendor,
            "product": self.product,
            "title": self.title,
            "families": self.families,
            "affected": self.affected,
            "cvss": self.cvss,
            "cvss_version": self.cvss_version,
            "cvss_vector": self.cvss_vector,
            "cwe": self.cwe,
            "ports": self.ports,
            "protocols": self.protocols,
            "attack": self.attack,
            "impact": self.impact,
            "remediation": self.remediation,
            "published": self.published,
            "source": self.source,
            "cve": self.cve,
            "kev": self.kev,
            "checked": self.checked,
        }


@dataclass
class Lifecycle:
    vendor: str
    family: str
    products: List[str]
    phase_out_announced: str
    type_cancellation: str
    spare_parts_until: str
    successor: str
    source: str
    note: str
    checked: str

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Lifecycle":
        return cls(
            vendor=raw.get("vendor", ""),
            family=raw.get("family", ""),
            products=list(raw.get("products", [])),
            phase_out_announced=raw.get("phase_out_announced", ""),
            type_cancellation=raw.get("type_cancellation", ""),
            spare_parts_until=raw.get("spare_parts_until", ""),
            successor=raw.get("successor", ""),
            source=raw.get("source", ""),
            note=raw.get("note", ""),
            checked=raw.get("checked", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class AdvisoryDB:
    def __init__(self) -> None:
        self.advisories: List[Advisory] = []
        self.lifecycle: List[Lifecycle] = []
        self.generated = ""
        self.kev: Dict[str, Dict[str, Any]] = {}
        self.kev_catalog_version = ""
        self.sources: List[str] = []

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, extra_paths: Optional[List[str]] = None, use_kev_cache: bool = True) -> "AdvisoryDB":
        db = cls()
        paths = [BUNDLED, LOCAL]
        if extra_paths:
            paths.extend(extra_paths)
        for path in paths:
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            db.sources.append(path)
            db.generated = raw.get("generated", db.generated)
            for a in raw.get("advisories", []):
                adv = Advisory.from_dict(a)
                if adv.id:
                    db.advisories.append(adv)
            for lc in raw.get("lifecycle", []):
                db.lifecycle.append(Lifecycle.from_dict(lc))
        if use_kev_cache and os.path.exists(KEV_CACHE):
            db.load_kev_cache(KEV_CACHE)
        db.dedupe()
        return db

    def dedupe(self) -> None:
        seen: Dict[str, Advisory] = {}
        for a in self.advisories:
            prev = seen.get(a.id)
            if prev is None:
                seen[a.id] = a
            else:
                # later record wins for the fields it fills in
                for f in ("cvss", "cvss_vector", "cwe", "remediation", "checked", "kev", "published"):
                    v = getattr(a, f)
                    if v:
                        setattr(prev, f, v)
                prev.cve = sorted(set(prev.cve) | set(a.cve))
                prev.families = sorted(set(prev.families) | set(a.families))
        self.advisories = sorted(seen.values(), key=lambda a: a.id)
        for a in self.advisories:
            kev = self.kev.get(",".join(a.cve)) or next((self.kev[c] for c in a.cve if c in self.kev), None)
            if kev:
                a.kev = True

    # ------------------------------------------------------------------
    def load_kev_cache(self, path: str = KEV_CACHE) -> int:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        self.kev_catalog_version = raw.get("catalogVersion", "")
        n = 0
        for v in raw.get("vulnerabilities", []):
            cve = v.get("cveID")
            if cve:
                self.kev[cve] = v
                n += 1
        return n

    def for_family(self, family: str) -> List[Advisory]:
        return [a for a in self.advisories if family and family in a.families]

    def lifecycle_for(self, family: str) -> Optional[Lifecycle]:
        for lc in self.lifecycle:
            if lc.family == family:
                return lc
        return None

    def summary(self) -> Dict[str, Any]:
        return {
            "advisories": len(self.advisories),
            "cves": len({c for a in self.advisories for c in a.cve}),
            "families": len({f for a in self.advisories for f in a.families}),
            "lifecycle_records": len(self.lifecycle),
            "kev_records": len(self.kev),
            "kev_catalog_version": self.kev_catalog_version,
            "generated": self.generated,
            "sources": self.sources,
        }
