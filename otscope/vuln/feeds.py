"""Feed updates: CISA Known Exploited Vulnerabilities catalog (+ optional NVD).

The bundled advisory set is static on purpose, so that the analyser works on an
air-gapped jump host.  This module adds exploit intelligence when a connection
is available, and degrades to a clear message when it is not.
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .db import KEV_CACHE, AdvisoryDB

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kw}&resultsPerPage=50"

USER_AGENT = "otscope/0.1 (industrial network analyser)"


def fetch_url(url: str, timeout: float = 20.0, verify: bool = True) -> Tuple[Optional[bytes], str]:
    ctx: Optional[ssl.SSLContext] = None
    if not verify:
        ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read(), ""
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code} from {url}"
    except urllib.error.URLError as exc:
        return None, f"network error contacting {url}: {exc.reason}"
    except (TimeoutError, ssl.SSLError, OSError) as exc:
        return None, f"could not reach {url}: {exc}"


def update_kev(path: str = KEV_CACHE, url: str = KEV_URL, verify: bool = True) -> Tuple[bool, str, int]:
    """Download the CISA KEV catalog.  Returns (ok, message, record_count)."""
    data, err = fetch_url(url, verify=verify)
    if data is None:
        if os.path.exists(path):
            age = time.time() - os.path.getmtime(path)
            return False, f"{err} - using cached catalog from {age / 86400:.1f} days ago", 0
        return False, f"{err} - no cache available, continuing with the bundled advisory set", 0
    try:
        raw = json.loads(data.decode("utf-8"))
    except ValueError as exc:
        return False, f"KEV response was not valid JSON: {exc}", 0
    if "vulnerabilities" not in raw:
        return False, "KEV response did not contain a 'vulnerabilities' list", 0
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)
    return True, f"KEV catalog {raw.get('catalogVersion', '?')} written to {path}", len(raw["vulnerabilities"])


def lookup_nvd(keyword: str, verify: bool = True) -> Tuple[List[Dict[str, Any]], str]:
    """Best-effort NVD keyword search (used by `otscope advisories search`)."""
    url = NVD_URL.format(kw=urllib.parse.quote(keyword))
    data, err = fetch_url(url, verify=verify)
    if data is None:
        return [], err
    try:
        raw = json.loads(data.decode("utf-8"))
    except ValueError as exc:
        return [], f"NVD response was not valid JSON: {exc}"
    out = []
    for item in raw.get("vulnerabilities", []):
        cve = item.get("cve", {})
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        out.append({"id": cve.get("id", ""), "published": cve.get("published", ""), "description": desc[:400]})
    return out, ""


def enrich(db: AdvisoryDB, kev_path: str = KEV_CACHE) -> Tuple[int, List[str]]:
    """Flag bundled advisories that are in the KEV catalog."""
    if not os.path.exists(kev_path):
        return 0, ["no KEV cache - run 'otscope advisories update' while connected to the internet"]
    n = db.load_kev_cache(kev_path)
    db.dedupe()
    kev_ids = sorted({c for a in db.advisories if a.kev for c in a.cve})
    return n, kev_ids
