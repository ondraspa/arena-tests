"""Capture I/O: classic pcap + pcapng readers and a pcap writer.

Written from scratch so the analyser has no third-party dependency and can run
on a locked-down OT jump host with nothing but Python 3.
"""

from __future__ import annotations

import os
import struct
import time
from typing import Iterator, List, Optional, Tuple

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D

DLT_NULL = 0
DLT_EN10MB = 1
DLT_IEEE802 = 6
DLT_RAW = 12
DLT_RAW2 = 14
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
DLT_LOOP = 108

PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
PCAPNG_SPB = 0x00000003
PCAPNG_ISB = 0x00000005


class CaptureError(Exception):
    pass


def iter_pcap(path: str) -> Iterator[Tuple[float, int, int, bytes]]:
    """Yield (ts, linktype, caplen, raw) from a classic pcap file."""
    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            raise CaptureError(f"{path}: truncated global header")
        magic = struct.unpack("<I", head[:4])[0]
        if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            nano = magic == PCAP_MAGIC_NS
            endian = "<"
        else:
            magic_be = struct.unpack(">I", head[:4])[0]
            if magic_be not in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
                raise CaptureError(f"{path}: not a pcap file (magic 0x{magic:08x})")
            nano = magic_be == PCAP_MAGIC_NS
            endian = ">"
        linktype = struct.unpack(endian + "I", head[20:24])[0] & 0x0FFFFFFF
        rec = struct.Struct(endian + "IIII")
        while True:
            hdr = fh.read(16)
            if len(hdr) < 16:
                return
            ts_sec, ts_frac, caplen, _origlen = rec.unpack(hdr)
            data = fh.read(caplen)
            if len(data) < caplen:
                return
            ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
            yield float(ts), int(linktype), int(caplen), data


def iter_pcapng(path: str) -> Iterator[Tuple[float, int, int, bytes]]:
    """Yield (ts, linktype, caplen, raw) from a pcapng file."""
    with open(path, "rb") as fh:
        blob = fh.read()
    off = 0
    endian = "<"
    linktypes: List[int] = []
    if_timestamp_resol = 1e-6
    ts_high = 0
    ts_low = 0
    have_ts = False
    while off + 8 <= len(blob):
        btype, blen = struct.unpack(endian + "II", blob[off : off + 8])
        if btype == PCAPNG_SHB and blen < 0x01000000:
            endian = "<" if struct.unpack("<I", blob[off + 8 : off + 12])[0] == 0x1A2B3C4D else ">"
            btype, blen = struct.unpack(endian + "II", blob[off : off + 8])
        if blen < 12 or off + blen > len(blob):
            return
        body = blob[off + 8 : off + blen - 4]
        if btype == PCAPNG_IDB and len(body) >= 8:
            linktypes.append(struct.unpack(endian + "H", body[0:2])[0])
            # option: if_tsresol
            opts = body[8:]
            i = 0
            while i + 4 <= len(opts):
                code, olen = struct.unpack(endian + "HH", opts[i : i + 4])
                if code == 0:
                    break
                if i + 4 + olen > len(opts):
                    break
                if code == 9 and olen >= 1:
                    v = opts[i + 4]
                    if_timestamp_resol = (1.0 / (2 ** (v & 0x7F))) if v & 0x80 else (1.0 / (10 ** v))
                i += 4 + olen + ((4 - (olen % 4)) % 4)
        elif btype == PCAPNG_EPB and len(body) >= 20:
            iface_id, th, tl, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
            ts = ((th << 32) | tl) * if_timestamp_resol
            data = body[20 : 20 + caplen]
            lt = linktypes[iface_id] if iface_id < len(linktypes) else (linktypes[0] if linktypes else DLT_EN10MB)
            yield ts, int(lt), int(caplen), data
        elif btype == PCAPNG_SPB and len(body) >= 4:
            (orig,) = struct.unpack(endian + "I", body[:4])
            data = body[4 : 4 + min(orig, len(body) - 4)]
            yield 0.0, linktypes[0] if linktypes else DLT_EN10MB, len(data), data
        off += blen
    # keep static analysers happy about unused locals in the ts path
    del ts_high, ts_low, have_ts


def iter_capture(path: str) -> Iterator[Tuple[float, int, int, bytes]]:
    """Dispatch on magic bytes."""
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if len(magic) < 4:
        raise CaptureError(f"{path}: empty capture file")
    if magic == struct.pack("<I", PCAPNG_SHB):
        yield from iter_pcapng(path)
        return
    yield from iter_pcap(path)


def strip_link_layer(linktype: int, raw: bytes) -> bytes:
    """Return the L2 Ethernet frame (or a synthetic one for non-Ethernet DLTs).

    For raw-IP / loopback / Linux-cooked captures we synthesise a minimal
    Ethernet header so the rest of the pipeline can stay link-type agnostic.
    """
    if linktype == DLT_EN10MB or linktype == DLT_IEEE802:
        return raw
    if linktype in (DLT_NULL, DLT_LOOP):
        if len(raw) < 4:
            return b""
        fam = struct.unpack("<I", raw[:4])[0]
        body = raw[4:]
        etype = 0x0800 if fam == 2 else (0x86DD if fam in (24, 28, 30) else 0)
        return b"\x00" * 6 + b"\x00" * 6 + struct.pack(">H", etype) + body
    if linktype == DLT_LINUX_SLL:
        if len(raw) < 16:
            return b""
        etype = struct.unpack(">H", raw[14:16])[0]
        src = raw[6:12]
        return src + b"\x00" * 6 + struct.pack(">H", etype) + raw[16:]
    if linktype == DLT_LINUX_SLL2:
        if len(raw) < 20:
            return b""
        etype = struct.unpack(">H", raw[0:2])[0]
        return b"\x00" * 6 + b"\x00" * 6 + struct.pack(">H", etype) + raw[20:]
    if linktype in (DLT_RAW, DLT_RAW2, 228, 229):
        if not raw:
            return b""
        etype = 0x0800 if (raw[0] >> 4) == 4 else 0x86DD
        return b"\x00" * 6 + b"\x00" * 6 + struct.pack(">H", etype) + raw
    return raw


class PcapWriter:
    """Minimal classic-pcap writer (used by capture-to-disk and test fixtures)."""

    def __init__(self, path: str, linktype: int = DLT_EN10MB, snaplen: int = 65535) -> None:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, snaplen, linktype))

    def write(self, frame: bytes, ts: Optional[float] = None) -> None:
        ts = time.time() if ts is None else ts
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        self.fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.fh.write(frame)

    def close(self) -> None:
        self.fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
