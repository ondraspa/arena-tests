"""Capture sources: pcap/pcapng files, live AF_PACKET sockets, and iterators."""

from __future__ import annotations

import os
import socket
import struct
import time
from typing import Callable, Iterator, Optional, Tuple

from .models import Packet
from .packets import parse_frame
from .pcap import iter_capture, strip_link_layer

FrameTuple = Tuple[float, int, int, bytes]  # ts, linktype, caplen, raw


def iter_file(path: str) -> Iterator[FrameTuple]:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    yield from iter_capture(path)


def iter_live(
    iface: str,
    seconds: Optional[float] = None,
    snaplen: int = 65535,
    bpf: Optional[bytes] = None,
    packet_limit: Optional[int] = None,
) -> Iterator[FrameTuple]:
    """Capture from a network interface using a raw AF_PACKET socket (Linux).

    Needs CAP_NET_RAW (i.e. root).  Promiscuous mode is enabled so that traffic
    on a span port is visible.
    """
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except (PermissionError, OSError) as exc:
        raise PermissionError(
            f"live capture on {iface} needs root/CAP_NET_RAW: {exc}. "
            "Run with sudo, or analyse a capture file instead (otscope analyse file.pcap)."
        ) from exc
    sock.bind((iface, 0))
    try:
        import fcntl

        SIOCGIFINDEX = 0x8933
        ifr = struct.pack("256s", iface[:15].encode("utf-8"))
        idx = struct.unpack("I", fcntl.ioctl(sock.fileno(), SIOCGIFINDEX, ifr)[16:20])[0]
        PACKET_ADD_MEMBERSHIP = 1
        PACKET_MR_PROMISC = 1
        mr = struct.pack("IHH8s", idx, 1, PACKET_MR_PROMISC, b"\x00" * 8)
        try:
            sock.setsockopt(socket.SOL_PACKET, PACKET_ADD_MEMBERSHIP, mr)
        except OSError:
            pass  # promiscuous mode is best-effort
    except Exception:
        pass
    sock.settimeout(1.0)
    start = time.time()
    count = 0
    try:
        while True:
            if seconds is not None and time.time() - start >= seconds:
                return
            try:
                raw, addr = sock.recvfrom(snaplen)
            except socket.timeout:
                continue
            except OSError:
                return
            count += 1
            if packet_limit is not None and count > packet_limit:
                return
            ts = time.time()
            yield ts, 1, len(raw), raw
    finally:
        sock.close()


def iter_frames(
    frames: Iterator[FrameTuple],
    iface: str = "",
    limit: Optional[int] = None,
    on_packet: Optional[Callable[[Packet], None]] = None,
) -> Iterator[Packet]:
    n = 0
    for ts, linktype, caplen, raw in frames:
        frame = strip_link_layer(linktype, raw)
        pkt = parse_frame(frame, ts=ts, iface=iface, idx=n, caplen=caplen)
        n += 1
        if on_packet is not None:
            on_packet(pkt)
        yield pkt
        if limit is not None and n >= limit:
            return


def write_pcap(path: str, frames: Iterator[bytes], start_ts: Optional[float] = None, step: float = 0.01) -> int:
    from .pcap import PcapWriter

    ts = start_ts or time.time()
    n = 0
    with PcapWriter(path) as w:
        for f in frames:
            w.write(f, ts)
            ts += step
            n += 1
    return n
