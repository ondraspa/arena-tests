"""Industrial protocol dissectors.

Each module exposes ``decode(pkt) -> ProtoFact | None`` and is registered in
``otscope.dissect.registry``.  Decoding is intentionally strict about lengths:
the malformed-frame paths are exactly the traffic that crashes PLC comms, so a
length mismatch is reported rather than silently skipped.
"""
