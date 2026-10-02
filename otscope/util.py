"""Small helpers: formatting, OUI lookup, EWMA/percentiles, version compare."""

from __future__ import annotations

import ipaddress
import math
import os
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# OUI vendor table
# --------------------------------------------------------------------------
# Deliberately small seed covering the vendors that matter for an ERP + OT
# network.  Extend it by dropping the IEEE registry (oui.csv / oui.txt) next to
# this file as `oui_override.csv` or by editing the dict -- see `lookup_oui`.
OUI_SEED: Dict[str, str] = {
    # Siemens / industrial
    "00:0e:8c": "Siemens AG",
    "00:1b:1b": "Siemens AG",
    "00:1c:06": "Siemens Numerical Control",
    "00:08:9b": "Siemens AG",
    "00:00:bc": "Rockwell Automation",
    "00:1d:9c": "Rockwell Automation",
    "00:00:54": "Schneider Electric",
    "00:1e:33": "Schneider Electric",
    "00:90:e8": "Moxa Technologies",
    "00:0d:b8": "Hirschmann (Belden)",
    "00:1a:6b": "Belden",
    # infrastructure / virtualisation (useful to spot a VM posing as OT)
    "08:00:27": "Oracle VirtualBox",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:15:5d": "Microsoft Hyper-V",
    "52:54:00": "QEMU/KVM",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Foundation",
}

_oui_cache: Optional[Dict[str, str]] = None


def _load_oui() -> Dict[str, str]:
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache
    table = dict(OUI_SEED)
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("oui_override.csv", "data/oui_override.csv"):
        path = os.path.join(here, name)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        parts = [p.strip() for p in line.split(",", 2)]
                        if len(parts) >= 2 and re.match(r"^[0-9A-Fa-f]{2}[:-]", parts[0]):
                            oui = parts[0].replace("-", ":").lower()[:8]
                            table[oui] = parts[1]
            except OSError:
                pass
    _oui_cache = table
    return table


def lookup_oui(mac: str) -> str:
    if not mac:
        return ""
    return _load_oui().get(mac[:8].lower(), "")


# --------------------------------------------------------------------------
# formatting
# --------------------------------------------------------------------------
def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ip_str(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def ip6_str(raw: bytes) -> str:
    try:
        return str(ipaddress.IPv6Address(raw))
    except Exception:  # pragma: no cover - malformed input
        return ":".join(raw[i : i + 2].hex() for i in range(0, len(raw), 2))


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def human_rate(n: float) -> str:
    return human_bytes(n) + "/s"


def human_ms(seconds: float) -> str:
    if seconds is None:
        return "-"
    if seconds < 1e-3:
        return f"{seconds * 1e6:.0f} us"
    if seconds < 1:
        return f"{seconds * 1e3:.1f} ms"
    return f"{seconds:.2f} s"


def hexdump(data: bytes, limit: int = 32) -> str:
    data = bytes(data[:limit])
    hexed = " ".join(f"{b:02x}" for b in data)
    ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{hexed}  |{ascii_}|"


# --------------------------------------------------------------------------
# statistics
# --------------------------------------------------------------------------
def percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    xs = sorted(values)
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * (pct / 100.0)
    lo = int(math.floor(k))
    hi = int(math.ceil(k))
    if lo == hi:
        return float(xs[lo])
    return float(xs[lo] + (xs[hi] - xs[lo]) * (k - lo))


def mean(values: Iterable[float]) -> float:
    xs = list(values)
    return sum(xs) / len(xs) if xs else 0.0


def stdev(values: Iterable[float]) -> float:
    xs = list(values)
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


class Ewma:
    """Exponentially weighted mean + variance, for streaming baselines."""

    __slots__ = ("alpha", "n", "mean", "var")

    def __init__(self, alpha: float = 0.2, mean: float = 0.0, var: float = 0.0) -> None:
        self.alpha = alpha
        self.n = 0
        self.mean = mean
        self.var = var

    def update(self, x: float) -> None:
        self.n += 1
        if self.n == 1:
            self.mean = float(x)
            self.var = 0.0
            return
        d = x - self.mean
        self.mean += self.alpha * d
        self.var = (1 - self.alpha) * (self.var + self.alpha * d * d)

    @property
    def sd(self) -> float:
        return math.sqrt(max(self.var, 0.0))

    def z(self, x: float) -> float:
        if self.sd < 1e-9:
            return 0.0 if abs(x - self.mean) < 1e-9 else float("inf") * (1 if x > self.mean else -1)
        return (x - self.mean) / self.sd


# --------------------------------------------------------------------------
# version handling (vendor version strings are messy: V3.2.12, 3.X.17, v4.1)
# --------------------------------------------------------------------------
_VER_RE = re.compile(r"(\d+|[A-Za-z]+)")


def version_tuple(v: str) -> Tuple[Any, ...]:
    """Split a vendor version string into a comparable tuple.

    Unknown / placeholder components ("3.X.17", "all versions") collapse to the
    numeric parts that are known, which is enough for range checks and keeps the
    analyser from inventing precision it does not have.
    """
    if not v:
        return ()
    # Vendor prefixes ("V3.60", "SV3.60", "FW 2.9.4") carry no ordering
    # information, so only the numeric groups are compared - otherwise "V3.60"
    # sorts below the bare "3.60" it is supposed to equal.
    out: List[Any] = []
    for tok in _VER_RE.findall(v.strip()):
        if tok.isdigit():
            out.append(int(tok))
    return tuple(out)


def version_cmp(a: str, b: str) -> int:
    ta, tb = version_tuple(a), version_tuple(b)
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def version_lt(a: str, b: str) -> bool:
    """Is version `a` older than `b`?  Empty `a` means 'unknown' -> False."""
    if not a or not b:
        return False
    return version_cmp(a, b) < 0


class RateLimiter:
    """Token-bucket rate limiter for active probes."""

    def __init__(self, per_second: float, burst: int = 1) -> None:
        self.rate = max(0.0001, per_second)
        self.burst = max(1, burst)
        self.tokens = float(burst)
        self.last = time.monotonic()

    def wait(self) -> float:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return 0.0
        need = (1 - self.tokens) / self.rate
        time.sleep(need)
        self.tokens = 0.0
        self.last = time.monotonic()
        return need


def net_of(ip: str, prefix: int = 24) -> str:
    """Best-effort /prefix label for an IPv4 address (no external deps)."""
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(net)
    except ValueError:
        parts = ip.split(".")
        if len(parts) != 4:
            return "unknown"
        if prefix <= 8:
            return f"{parts[0]}.0.0.0/8"
        if prefix <= 16:
            return f"{'.'.join(parts[:2])}.0.0/16"
        return f"{'.'.join(parts[:3])}.0/24"


def in_same_net(a: str, b: str, prefix: int = 24) -> bool:
    return net_of(a, prefix) == net_of(b, prefix)


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def stable_id(*parts: Any) -> str:
    import hashlib

    h = hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return h[:12]
