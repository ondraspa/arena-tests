"""Persistent state between runs: baseline assets, seen advisories, finding history."""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

DEFAULT_PATH = os.path.join(".state", "otscope-state.json")


class State:
    def __init__(self, path: str = DEFAULT_PATH) -> None:
        self.path = path
        self.data: Dict[str, Any] = {"version": 1, "runs": [], "assets": {}, "advisories": {}, "findings": {}}
        self.loaded = False
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    self.data.update(json.load(fh))
                self.loaded = True
            except (OSError, ValueError):
                self.loaded = False

    # ------------------------------------------------------------------
    def save(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, default=str)
        os.replace(tmp, self.path)

    # ------------------------------------------------------------------
    def known_assets(self) -> Dict[str, Any]:
        return self.data.setdefault("assets", {})

    def new_assets(self, assets: Dict[str, Any]) -> List[str]:
        """Return keys that were not present in the previous run."""
        known = set(self.known_assets())
        return sorted(k for k in assets if k not in known)

    def record_assets(self, assets: Dict[str, Any]) -> None:
        now = time.time()
        store = self.data.setdefault("assets", {})
        for key, a in assets.items():
            prev = store.get(key, {})
            store[key] = {
                "ip": a.get("ip"),
                "mac": a.get("mac"),
                "vendor": a.get("vendor"),
                "model": a.get("model"),
                "family": a.get("family"),
                "firmware": a.get("firmware"),
                "role": a.get("role"),
                "protocols": sorted(a.get("protocols", {})),
                "first_seen": prev.get("first_seen", a.get("first_seen")),
                "last_seen": a.get("last_seen") or now,
                "runs": int(prev.get("runs", 0)) + 1,
            }

    # ------------------------------------------------------------------
    def known_advisories(self) -> Dict[str, Any]:
        return self.data.setdefault("advisories", {})

    def new_advisories(self, advisories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        known = self.known_advisories()
        out = []
        for a in advisories:
            prev = known.get(a["id"])
            if prev is None or prev.get("checked") != a.get("checked"):
                out.append(a)
        return out

    def record_advisories(self, advisories: List[Dict[str, Any]]) -> None:
        store = self.data.setdefault("advisories", {})
        for a in advisories:
            store[a["id"]] = {"checked": a.get("checked"), "cvss": a.get("cvss"), "cve": a.get("cve")}

    # ------------------------------------------------------------------
    def record_run(self, summary: Dict[str, Any]) -> None:
        runs = self.data.setdefault("runs", [])
        runs.append({"ts": time.time(), **summary})
        del runs[:-50]

    def last_run(self) -> Optional[Dict[str, Any]]:
        runs = self.data.get("runs") or []
        return runs[-1] if runs else None

    def record_findings(self, findings: List[Dict[str, Any]]) -> None:
        store = self.data.setdefault("findings", {})
        now = time.time()
        for f in findings:
            key = f["id"]
            prev = store.get(key)
            store[key] = {
                "first_seen": (prev or {}).get("first_seen", now),
                "last_seen": now,
                "severity": f.get("severity"),
                "count": int((prev or {}).get("count", 0)) + 1,
            }
        for key in list(store):
            if store[key]["last_seen"] < now - 86400 * 90:
                del store[key]

    def new_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        known = self.data.get("findings", {})
        return [f for f in findings if f["id"] not in known]
