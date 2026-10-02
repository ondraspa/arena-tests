# otscope

**Passive-first network analyser for a small plant: ERP + Siemens / Allen-Bradley /
Schneider controllers on the same LAN.**

otscope answers four questions about a network that carries both business and
control traffic:

1. **What is on it?** — inventory of hosts, vendors, PLC families, firmware, roles
   and Purdue levels, from the traffic itself.
2. **What is broken right now?** — industrial-protocol faults (S7 errors, Modbus
   exceptions, CIP errors, malformed PDUs), loops and broadcast storms, and the
   things that make the network *slow* (retransmission, latency, polling gaps,
   zero windows, utilisation).
3. **What is vulnerable?** — observed devices matched against a curated advisory
   database (CISA ICS advisories + CVEs, CISA KEV membership), with a confidence
   level instead of a bare score.
4. **What will break next?** — discontinued hardware, protocols that are
   unauthenticated *by design*, clear-text services on the control segment, flat
   segmentation, and a watch mode that re-matches the inventory whenever the
   advisory set is refreshed.

It is **passive by default**: a pcap file or a live capture is enough. Active
identification probing exists, is opt-in, and is strictly read-only.

```
otscope demo                       # no plant needed: synthetic capture, full analysis
otscope scan capture.pcap          # analyse a capture file
sudo otscope scan --iface eth0 --seconds 60
otscope scan capture.pcap --active # + read-only identification probes
otscope dashboard --port 8055      # web dashboard (no CDN, works offline)
```

---

## Why it exists

A plant network fails in a specific way: a switch loop, a duplicate IP or a
broadcast storm delays the cyclic polling of a PLC, the PLC answers with protocol
errors or not at all, the HMI shows "communication fault", and everybody starts
rebooting controllers. The controller was the *victim*.

The signature feature of otscope is the correlation of those two layers: protocol
faults that fall inside a ±5 s window of a layer-2 event (STP topology change,
MRP topology change/link-down, broadcast-storm second) are reported as
`CRASH-CORRELATED-L2` — *fix the fabric first, then re-measure*.

## Install

Python 3.9+, no runtime dependencies for the analyser (own pcap reader and own
dissectors). Flask is only needed for the dashboard.

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/otscope selftest
```

`make demo`, `make test`, `make dashboard` wrap the same commands.

## Commands

| command | what it does |
| --- | --- |
| `otscope scan SOURCE` | analyse a pcap/pcapng file (`--iface IFACE --seconds N` for live) |
| `otscope probe IP...` | read-only identification of specific hosts |
| `otscope watch --iface IFACE` | continuous monitoring; reports only *new* findings |
| `otscope dashboard` | web dashboard on `0.0.0.0:8055` |
| `otscope report r.json --format html` | re-render a saved report |
| `otscope demo` | generate a synthetic plant capture and analyse it |
| `otscope devnet` | run an emulated plant on loopback (real sockets) |
| `otscope advisories list|show ID|update` | inspect/refresh the advisory database |
| `otscope config` | print an example site configuration |
| `otscope scenarios` | list the built-in demo scenarios |
| `otscope selftest` | analyse a generated capture and verify the outcome |

Report formats: `--format console|json|markdown|html`, written with `--out FILE`.
`--strict` exits non-zero when a critical finding exists (CI gate).

### Live capture

`scan --iface`, `watch` and `dashboard --iface` open an `AF_PACKET` socket and
need root or `CAP_NET_RAW`. Everything else works without privileges.

## What it detects

| category | examples |
| --- | --- |
| `loop` | switching loop (identical frame at wire speed), ARP storm, broadcast storm/dominance, STP TCN storm, two MRP managers, MAC flapping, no STP on a segment |
| `crash` | S7 error storms (protected area, no resources), PLC STOP/START command seen on the wire, program download, Modbus exception storms, CIP error storms, malformed TPKT/COTP/S7 frames, SNMP flood, controller going silent, **fault↔L2 correlation** |
| `perf` | retransmission rate, RTT/jitter per server, zero windows, duplicate ACKs, sequence gaps, utilisation against link speed, polling gaps, slow HTTP endpoints, baseline spikes (σ), top talkers |
| `anomaly` | port/host scanning, duplicate IP / ARP spoofing, unauthorised write to a PLC, new device, protocol on a non-standard port, beaconing, protocol not allowed by the segment profile |
| `vuln` | advisory matches per device with confidence `confirmed / likely / possible / latent` and port exposure |
| `forward` | EOL hardware, unauthenticated-by-design protocols, clear-text services, flat network, new advisories since the last run, risk runway score |

## Active probing — read-only by construction

`--active` (or `otscope probe`) sends only what an engineering tool sends on
every online connection, and it is rate limited (default 10 req/s):

* TCP connect test on the configured ports
* S7: COTP connect → Setup communication → **SZL 0x0011** (module identification),
  plus **SZL 0x001C** (firmware) only when the device is *not* on the fragile list
* Modbus: **FC 0x2B / MEI 0x0E** Read Device Identification
* EtherNet/IP: **ListIdentity** (both encapsulation command codes are tried, the
  reply is parsed structurally by item type)
* HTTP: one `GET /`; SNMP: one `GET sysDescr.0`

Every frame passes a byte-level guard before it is sent (`otscope/active/safety.py`):
Modbus write function codes, S7 write/download/START/STOP/password functions, CIP
write/reset services and SNMP Set requests raise `WriteAttempt`. `allow_write=True`
is silently forced back to `False`. S7-300/400, S7-200 and Modicon
Premium/Quantum are on a fragile list: they get one identification session and no
enumeration, because ICSA-15-064-04 documents that crafted 102/tcp traffic puts an
S7-300 into defect mode.

`otscope devnet` starts an emulated plant on loopback (127.0.0.2–.5: an S7-300,
a CompactLogix 5370, a Modicon M340 and an ERP web server) that speaks these
protocols on real sockets, so the probes and the dissectors can be tested end to
end:

```bash
.venv/bin/otscope devnet --forever &   # prints a ready-to-paste probe command
.venv/bin/otscope probe 127.0.0.2 127.0.0.3 127.0.0.4 \
    --service-port s7=10102 --service-port modbus=10502 \
    --service-port enip=14481 --service-port enip_udp=12222 \
    --service-port http=10080 --service-port snmp=10161 --snmp
```

If a demo port is already taken the emulator falls back to a free port and says
so, so always copy the command it prints.

## Advisory database

`otscope/vuln/data/advisories.json` is a curated snapshot (**checked 2026-10-02**)
of CISA ICS advisories for the families this tool sees: Siemens S7, Rockwell
Logix / FactoryTalk Linx, Schneider Modicon. 14 advisories, 8 CVEs, 22 product
families, plus 4 product-lifecycle records (S7-300 / S7-400 phase-out and
spare-part horizon, Modicon Premium / Quantum end of commercialisation).

Each record carries its `source` and `checked` date, so a match can be verified.
Only facts that were read from the advisories are stored — no invented CVE ids,
scores or version ranges.

`otscope advisories update` downloads the CISA KEV catalog and flags bundled
advisories that appear in it. **Note:** `cisa.gov` was not reachable from the
sandbox where this project was built, so the live download path is exercised by
the test suite against a local catalog file, not against the real endpoint.
CVE-2021-22681 (ICSA-21-056-03) is already marked KEV in the bundled data.

Add your own records in `otscope/vuln/data/advisories.local.json`; they are
merged automatically.

Matching is **confidence-based, not score-based**:

| confidence | meaning |
| --- | --- |
| `confirmed` | family matches and the running version is inside the affected range |
| `likely` | all versions of the family are affected, version unknown |
| `possible` | version could not be determined |
| `latent` | affected product present but the vulnerable port was never observed in use |

Exposure upgrades severity, KEV membership forces at least *high*.

## Site configuration

`otscope config > site.json` prints a commented example: subnets with Purdue
level and role, allowed protocols, trusted engineering stations, known PLCs,
ERP hosts, fragile devices, link speed and thresholds. Pass it with `--config`.
Without a config the analyser infers segments and roles from the traffic — it
just cannot know which hosts are *allowed* to write to a PLC.

## Dashboard

`otscope dashboard` serves a self-contained page: inline CSS/JS, an SVG sparkline
of the capture window, severity cards, filterable findings, inventory, advisory
list, activity log, plus a printable `/report.html`. No CDN, no web font, no
framework — a plant network is usually an offline network. It binds `0.0.0.0` and
pushes updates over Server-Sent Events.

## Tests

```bash
.venv/bin/python -m pytest          # 135 tests
.venv/bin/otscope selftest          # analyser known-answer check
```

The suite is built around **known-answer tests**: each of the 19 scenarios in
`otscope/scenarios.py` injects exactly one problem, and a test asserts the finding
that must catch it. The same scenarios feed `otscope demo`. Every frame builder
in `otscope/frames.py` is round-tripped through the real parser and dissectors.
The active-probe tests run against the emulated plant over real sockets.

## Limitations

* The dissectors cover what a small plant actually runs: S7comm/COTP, Modbus TCP,
  EtherNet/IP-CIP, plus STP/MRP/LLDP/CDP/DCP, SNMP, HTTP, DNP3 and BACnet
  identification. OPC UA and PROFINET RT are seen and named, not decoded.
* MRP/STP/DCP layouts were written from the specifications and are exercised
  against synthetic frames, not vendor captures.
* EtherNet/IP encapsulation command numbering differs between implementations;
  ListIdentity is therefore parsed structurally and raw codes are always reported.
* Findings are heuristics. Confirm against the vendor advisory before touching a
  control system, and never scan a production PLC without a change window.
