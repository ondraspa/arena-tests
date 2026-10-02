"""Layer-2 control protocols: STP BPDUs, LLDP, CDP, PROFINET DCP and MRP.

These are the primary *loop* evidence sources: MRP ring state, STP topology
changes and DCP re-configuration all tell you what the switching fabric is
doing, which is what you need to tell a loop from a broadcast-heavy host.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

from ..models import Packet, ProtoFact
from ..util import ip_str, mac_str

# ---------------------------------------------------------------- STP / RSTP
def decode_stp(pkt: Packet) -> Optional[ProtoFact]:
    if not pkt.dst_mac.startswith("01:80:c2:00:00:0"):
        return None
    body = pkt.payload
    if len(body) < 4 or body[0] != 0x42 or body[1] != 0x42:
        return None
    body = body[3:]  # strip LLC + control
    if len(body) < 35:
        return ProtoFact(proto="stp", summary="BPDU (truncated)")
    proto_id, proto_ver, bpdu_type = struct.unpack(">HBB", body[0:4])
    flags = body[4]
    root_id = body[5:13]
    root_cost = struct.unpack(">I", body[13:17])[0]
    bridge_id = body[17:25]
    port_id = struct.unpack(">H", body[25:27])[0]
    msg_age, max_age, hello, fwd_delay = struct.unpack(">HHHH", body[27:35])
    kind = {0x00: "Config BPDU", 0x02: "RST BPDU", 0x80: "TCN BPDU"}.get(bpdu_type, f"BPDU 0x{bpdu_type:02x}")
    root_mac = mac_str(root_id[2:8])
    bridge_mac = mac_str(bridge_id[2:8])
    fact = ProtoFact(
        proto="stp",
        summary=f"{kind} root={root_mac} bridge={bridge_mac} age={msg_age / 256:.0f}",
        attrs={
            "bpdu_type": bpdu_type,
            "type_name": kind,
            "flags": flags,
            "tc": bool(flags & 0x01),
            "tca": bool(flags & 0x80),
            "root_bridge": root_mac,
            "root_priority": struct.unpack(">H", root_id[0:2])[0],
            "root_cost": root_cost,
            "bridge_mac": bridge_mac,
            "bridge_priority": struct.unpack(">H", bridge_id[0:2])[0],
            "port_id": port_id,
            "msg_age": msg_age / 256.0,
            "max_age": max_age / 256.0,
            "hello": hello / 256.0,
        },
    )
    if bpdu_type == 0x80:
        fact.event("stp-tcn", "Topology Change Notification BPDU", severity="medium")
    if flags & 0x01:
        fact.event("stp-tc-flag", "BPDU with Topology Change flag set", severity="medium")
    if msg_age / 256.0 > max_age / 256.0 * 0.8 and bpdu_type == 0x00:
        fact.event(
            "stp-aged-bpdu",
            f"BPDU age {msg_age / 256:.1f}s close to max age {max_age / 256:.1f}s: "
            "root path is unstable or a BPDU is being black-holed",
            severity="high",
        )
    return fact


# ---------------------------------------------------------------------- LLDP
LLDP_TLVS = {
    0: "End",
    1: "Chassis ID",
    2: "Port ID",
    3: "TTL",
    4: "Port Description",
    5: "System Name",
    6: "System Description",
    7: "System Capabilities",
    8: "Management Address",
    127: "Organisation specific",
}


def decode_lldp(pkt: Packet) -> Optional[ProtoFact]:
    if pkt.ethertype != 0x88CC:
        return None
    data = pkt.payload
    info: Dict[str, Any] = {}
    i = 0
    while i + 2 <= len(data):
        hdr = struct.unpack(">H", data[i : i + 2])[0]
        ttype, tlen = hdr >> 9, hdr & 0x1FF
        val = data[i + 2 : i + 2 + tlen]
        if ttype == 1 and len(val) >= 2:
            sub = val[0]
            ident = val[1:]
            info["chassis_id"] = mac_str(ident) if sub == 4 and len(ident) == 6 else ident.decode("ascii", "replace")
            info["chassis_subtype"] = sub
        elif ttype == 2 and len(val) >= 2:
            sub = val[0]
            ident = val[1:]
            info["port_id"] = mac_str(ident) if sub == 3 and len(ident) == 6 else ident.decode("ascii", "replace")
        elif ttype == 3:
            info["ttl"] = struct.unpack(">H", val)[0] if len(val) >= 2 else None
        elif ttype in (4, 5, 6):
            key = {4: "port_desc", 5: "system_name", 6: "system_desc"}[ttype]
            info[key] = val.decode("utf-8", "replace").strip("\x00")
        elif ttype == 8 and len(val) >= 2:
            sub = val[0]
            addr = val[1:]
            if sub == 1 and len(addr) == 4:
                info["mgmt_ip"] = ip_str(addr)
            elif sub == 2:
                info["mgmt_ip"] = ":".join(addr[i : i + 2].hex() for i in range(0, len(addr), 2))
            info["mgmt_iface"] = int.from_bytes(val[-4:], "big") if len(val) >= 5 else None
        elif ttype == 127 and len(val) >= 4:
            oui = val[0:3].hex()
            info.setdefault("org_tlvs", []).append(oui)
            if oui == "0080c3" and len(val) >= 10:
                info["pn_subtype"] = val[3]  # PROFINET specific subtype
        i += 2 + tlen
        if ttype == 0:
            break
    fact = ProtoFact(
        proto="lldp",
        summary=f"LLDP {info.get('system_name', '?')} port {info.get('port_id', '?')}",
        attrs=info,
    )
    if info.get("system_name"):
        fact.event("lldp-neighbor", f"LLDP neighbour: {info['system_name']} on port {info.get('port_id')}", severity="info")
    return fact


# ----------------------------------------------------------------------- CDP
def decode_cdp(pkt: Packet) -> Optional[ProtoFact]:
    if pkt.dst_mac != "01:00:0c:cc:cc:cc":
        return None
    data = pkt.payload
    if len(data) < 4:
        return None
    if data[0] not in (0x01, 0x02):
        return None
    info: Dict[str, Any] = {"version": data[0], "ttl": data[1]}
    i = 4
    names = {1: "device_id", 2: "addresses", 3: "port_id", 4: "capabilities", 5: "version_text", 6: "platform", 9: "vtp_domain", 10: "native_vlan", 16: "duplex", 23: "mgmt_addresses"}
    while i + 4 <= len(data):
        ttype, tlen = struct.unpack(">HH", data[i : i + 4])
        if tlen < 4:
            break
        val = data[i + 4 : i + tlen]
        key = names.get(ttype)
        if key and ttype not in (2, 23):
            info[key] = val.decode("utf-8", "replace").strip("\x00")
        elif ttype == 23 and len(val) >= 5:
            n = val[0]
            off = 1
            addrs = []
            for _ in range(n):
                if off + 5 > len(val):
                    break
                af, alen = struct.unpack(">HH", val[off : off + 4])
                addr = val[off + 4 : off + 4 + alen]
                addrs.append(ip_str(addr) if af == 1 and alen == 4 else addr.hex())
                off += 4 + alen
            info["mgmt_addresses"] = addrs
        i += tlen
    fact = ProtoFact(proto="cdp", summary=f"CDP {info.get('device_id', '?')} port {info.get('port_id', '?')}", attrs=info)
    fact.event("cdp-neighbor", f"CDP neighbour: {info.get('device_id')} on {info.get('port_id')}", severity="info")
    return fact


# -------------------------------------------------------- PROFINET DCP (8892)
DCP_SERVICES = {
    0x00: "Manufacturer-Specific",
    0x01: "Manufacturer-Specific (Get)",
    0x02: "Client",
    0x03: "Response",
    0x04: "Get",
    0x05: "Set",
    0x06: "Identify",
    0x07: "Hello",
}

DCP_OPTIONS = {
    0x00: "IP",
    0x01: "Device properties",
    0x02: "DHCP",
    0x03: "Reserved",
    0x04: "Control",
    0x05: "Device Initiative",
    0x06: "All selector",
    0xFF: "All selector",
}

DCP_IP_SUBOPTIONS = {0x01: "MAC address", 0x02: "IP parameter"}
DCP_CONTROL_SUBOPTIONS = {0x01: "Start transaction", 0x02: "End transaction", 0x03: "Signal", 0x04: "Response", 0x05: "Set Factory Reset", 0x06: "Reset to Factory"}
DCP_PROP_SUBOPTIONS = {
    0x01: "Type of Station",
    0x02: "Name of Station",
    0x03: "IP of Station",
    0x04: "Device Role",
    0x05: "Device Options",
    0x06: "Alias Name",
    0x07: "Device ID",
    0x08: "OEM Device ID",
}


def decode_dcp(pkt: Packet) -> Optional[ProtoFact]:
    if pkt.ethertype != 0x8892:
        return None
    d = pkt.payload
    if len(d) < 10:
        return ProtoFact(proto="profinet-dcp", summary="PROFINET DCP (truncated)")
    service_id, service_type, xid = d[0], d[1], struct.unpack(">I", d[2:6])[0]
    dcp_len = struct.unpack(">H", d[8:10])[0]
    fact = ProtoFact(
        proto="profinet-dcp",
        summary="",
        attrs={"service_id": service_id, "service_type": service_type, "xid": xid, "dcp_length": dcp_len},
    )
    sname = DCP_SERVICES.get(service_id, f"service 0x{service_id:02x}")
    resp = bool(service_type & 0x01)
    fact.attrs["is_response"] = resp
    off = 10
    blocks: List[Dict[str, Any]] = []
    end = min(len(d), 10 + dcp_len)
    # block header: option(1) suboption(1) block length(2) block qualifier(2).
    # The block length counts the qualifier, so the data runs from off+6 to
    # off+4+length.
    while off + 6 <= end:
        option, suboption = d[off], d[off + 1]
        blen = struct.unpack(">H", d[off + 2 : off + 4])[0]
        qual = struct.unpack(">H", d[off + 4 : off + 6])[0]
        if blen < 2 or off + 4 + blen > len(d):
            fact.event(
                "dcp-block-length",
                f"DCP block length {blen} does not fit the frame ({len(d) - off - 4} bytes left)",
                severity="medium",
            )
            break
        body = d[off + 6 : off + 4 + blen]
        blk: Dict[str, Any] = {
            "option": option,
            "option_name": DCP_OPTIONS.get(option, f"option 0x{option:02x}"),
            "suboption": suboption,
            "length": blen,
            "qualifier": qual,
        }
        if option == 0x00 and suboption == 0x02 and len(body) >= 14:
            blk["ip"] = ip_str(body[2:6])
            blk["netmask"] = ip_str(body[6:10])
            blk["gateway"] = ip_str(body[10:14])
        elif option == 0x01 and suboption == 0x02:
            blk["station_name"] = body.rstrip(b"\x00").decode("ascii", "replace")
        elif option == 0x01 and suboption == 0x01:
            blk["station_type"] = body.rstrip(b"\x00").decode("ascii", "replace")
        elif option == 0x01 and suboption == 0x07 and len(body) >= 2:
            blk["device_id"] = struct.unpack(">H", body[0:2])[0]
        elif option == 0x04:
            blk["control_name"] = DCP_CONTROL_SUBOPTIONS.get(suboption, f"control 0x{suboption:02x}")
        blocks.append(blk)
        off += 4 + blen + (blen % 2)  # blocks are padded to an even length
    fact.attrs["blocks"] = blocks
    parts = [sname]
    for b in blocks:
        if b.get("station_name"):
            parts.append(f"name={b['station_name']}")
        if b.get("ip"):
            parts.append(f"ip={b['ip']}")
        if b.get("control_name"):
            parts.append(b["control_name"])
    fact.summary = "PROFINET DCP " + " ".join(parts)

    if service_id == 0x05 and not resp:
        names = [b.get("control_name") or b.get("option_name") for b in blocks]
        dangerous = any("Factory" in (n or "") for n in names)
        fact.event(
            "dcp-set",
            f"PROFINET DCP Set request ({', '.join(n for n in names if n)}): "
            "a DCP Set reconfigures or renames devices on the wire",
            severity="critical" if dangerous else "high",
        )
    if service_id == 0x06 and not resp:
        fact.event("dcp-identify", "PROFINET DCP Identify (device discovery) request", severity="info")
    if service_id == 0x07:
        fact.event("dcp-hello", "PROFINET DCP Hello: a device is being brought online", severity="info")
    return fact


# ------------------------------------------------------------------ MRP (88E3)
MRP_TLV = {
    0x00: "End",
    0x01: "Common",
    0x02: "Test",
    0x03: "Topology Change",
    0x04: "Link Down",
    0x05: "Link Up",
    0x06: "Media Check",
    0x1C: "Other",
}
MRP_ROLE = {0x00: "MRM (redundancy manager)", 0x01: "MRC (client)", 0x02: "MRM+MRC (interconnection)"}


def decode_mrp(pkt: Packet) -> Optional[ProtoFact]:
    if pkt.ethertype != 0x88E3:
        return None
    d = pkt.payload
    fact = ProtoFact(proto="mrp", summary="PROFINET MRP", attrs={"tlvs": []})
    if len(d) < 2:
        return fact
    version = struct.unpack(">H", d[0:2])[0]
    fact.attrs["version"] = version
    i = 2
    roles = []
    while i + 2 <= len(d):
        ttype, tlen = d[i], d[i + 1]
        body = d[i + 2 : i + 2 + tlen]
        tlv: Dict[str, Any] = {"type": ttype, "name": MRP_TLV.get(ttype, f"TLV 0x{ttype:02x}"), "length": tlen}
        if ttype in (0x02, 0x03, 0x04, 0x05, 0x06) and len(body) >= 10:
            seq, role = struct.unpack(">HH", body[0:4])
            sa = mac_str(body[4:10])
            tlv.update({"sequence": seq, "role": role, "role_name": MRP_ROLE.get(role, f"role 0x{role:02x}"), "sa": sa})
            roles.append(role)
        fact.attrs["tlvs"].append(tlv)
        i += 2 + tlen
        if ttype == 0x00:
            break
    names = [t["name"] for t in fact.attrs["tlvs"]]
    fact.summary = "PROFINET MRP " + ", ".join(names)
    managers = [t for t in fact.attrs["tlvs"] if t.get("role") == 0x00]
    if managers:
        fact.event(
            "mrp-manager",
            f"MRP redundancy manager activity (SA {managers[0]['sa']}, sequence {managers[0]['sequence']})",
            severity="info",
            manager_mac=managers[0]["sa"],
        )
    for t in fact.attrs["tlvs"]:
        if t["type"] == 0x03:
            fact.event(
                "mrp-topology-change",
                f"MRP Topology Change (SA {t.get('sa')}, port info {t.get('length')}B): the ring was broken or re-closed",
                severity="high",
                sa=t.get("sa"),
            )
        elif t["type"] == 0x04:
            fact.event("mrp-link-down", f"MRP Link Down (SA {t.get('sa')})", severity="high")
        elif t["type"] == 0x06:
            fact.event("mrp-media-check", f"MRP Media Check (SA {t.get('sa')})", severity="medium")
    return fact


ALL = [decode_stp, decode_lldp, decode_cdp, decode_dcp, decode_mrp]


def decode_any(pkt: Packet) -> Optional[ProtoFact]:
    for fn in ALL:
        out = fn(pkt)
        if out is not None:
            return out
    return None
