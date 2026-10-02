"""otscope - passive-first health, protocol-fault and vulnerability analyser.

Target environment: a small local network that carries ERP traffic plus one or
more OT/ICS segments with Siemens (S7comm / PROFINET), Rockwell / Allen-Bradley
(EtherNet-IP / CIP) and Schneider Electric (Modbus TCP) controllers.

Design rules
------------
1. Passive first.  Everything valuable is extracted from captured frames; the
   analyser never needs to touch the PLCs to produce a report.
2. Active probing is opt-in, read-only and rate limited (see otscope.active).
   It is hard-blocked from issuing writes, start/stop or downloads.
3. Every claim in a report is backed by evidence lines that point at frames,
   counters or an external advisory record.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
