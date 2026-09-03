"""STP (IEEE 802.1D Spanning Tree Protocol) decoder for PacketSnitch backend.

Decodes STP BPDUs (Bridge Protocol Data Units) carried over IEEE 802.2 LLC
with DSAP=0x42 SSAP=0x42.  STP operates at Layer 2 on the reserved multicast
address 01:80:C2:00:00:00 (for the common spanning tree) and uses no IP
layer.

BPDU wire format (after the 3-byte LLC header DSAP/SSAP/Control):

  Common BPDU header (4 bytes):
    - Protocol Identifier   (2 bytes, always 0x0000)
    - Protocol Version      (1 byte, 0 = STP, 2 = RSTP/MSTP)
    - BPDU Type             (1 byte)

  Configuration BPDU body (31 bytes after header):
    - Flags                 (1 byte)
    - Root Bridge ID        (8 bytes: priority(2) + MAC(6))
    - Root Path Cost        (4 bytes)
    - Bridge ID             (8 bytes: priority(2) + MAC(6))
    - Port ID               (2 bytes)
    - Message Age           (2 bytes, 1/256 s)
    - Max Age               (2 bytes, 1/256 s)
    - Hello Time            (2 bytes, 1/256 s)
    - Forward Delay         (2 bytes, 1/256 s)

  Topology Change Notification BPDU (1 byte after header, no body)

This decoder accepts either a scapy packet ``p`` (with ``STP`` layer) or
raw BPDU bytes (the payload after the LLC header).  It follows the same
dual-key dict pattern as the other decoders, returning a dict on success
or ``None`` on mismatch.
"""

import struct

# BPDU type codes (IEEE 802.1D Table 17-2)
STP_BPDU_TYPES = {
    0x00: "Configuration BPDU",
    0x02: "Rapid Spanning Tree (RSTP) BPDU",
    0x80: "Topology Change Notification (TCN)",
}

# Flags for Configuration / RSTP BPDUs (IEEE 802.1D 17.5.2 / 802.1w)
STP_FLAG_BITS = {
    0x01: "Topology Change (TC)",
    0x02: "Proposal",
    0x04: "Learning",
    0x08: "Forwarding",
    0x10: "Agreement",
    0x20: "Synchronization",
    0x40: "Root Port / Alternate/Backup",
    0x80: "Topology Change Acknowledgment (TCA)",
}

# Only these three flags are defined in classic 802.1D STP (not RSTP).
STP_CLASSIC_FLAG_BITS = {
    0x01: "Topology Change (TC)",
    0x80: "Topology Change Acknowledgment (TCA)",
}


def _decodeStateFlags(flags, isRstp):
    bits = STP_FLAG_BITS if isRstp else STP_CLASSIC_FLAG_BITS
    names = []
    for bit, name in bits.items():
        if flags & bit:
            names.append(name)
    return " | ".join(names) if names else "None"


def _decodeBridgeId(raw):
    """Decode an 8-byte Bridge ID (priority(2) + MAC(6)).

    Returns ``(priority, mac_str, bridge_id_str)`` or ``(0, "00:00:00:00:00:00", "0/00:00:00:00:00:00")``.
    """
    if raw is None or len(raw) < 8:
        return (0, "00:00:00:00:00:00", "0/00:00:00:00:00:00")
    priority = struct.unpack_from(">H", raw, 0)[0]
    mac = raw[2:8]
    macStr = ":".join(f"{b:02x}" for b in mac)
    # Extended System ID: lower 12 bits of priority are the VLAN ID (IEEE 802.1t)
    basePriority = (priority >> 12) & 0x0F
    vlanId = priority & 0x0FFF
    if vlanId != 0:
        bridgeIdStr = f"{basePriority}.{vlanId}/{macStr}"
    else:
        bridgeIdStr = f"{priority}/{macStr}"
    return (priority, macStr, bridgeIdStr)


def _formatTime(timesixteenths):
    """Convert STP time field (1/256 s units) to a human-readable seconds string."""
    seconds = timesixteenths / 256.0
    if seconds == int(seconds):
        return f"{int(seconds)}s"
    return f"{seconds:.2f}s"


def _extractStpBytes(p, linkRaw):
    """Try to get raw BPDU bytes (after LLC header) from a scapy packet or raw payload.

    ``p`` may be a scapy packet with an ``STP`` layer, or ``None`` when called
    with raw bytes only.  ``linkRaw`` is the Ethernet payload (including LLC
    header) when available.
    """
    # Prefer the scapy STP layer if present.
    if p is not None:
        try:
            if p.haslayer("STP"):
                stpLayer = p["STP"]
                # bytes(stpLayer) gives the raw STP/BPDU fields (no LLC header)
                return bytes(stpLayer)
        except Exception:
            pass

    # Fall back to manual LLC stripping from linkRaw.
    if linkRaw is None or len(linkRaw) < 4:
        return None

    # LLC header: DSAP(1) + SSAP(1) + Control(1 or 2).
    # STP BPDUs use DSAP=0x42 SSAP=0x42.
    dsap = int(linkRaw[0])
    ssap = int(linkRaw[1])
    if dsap != 0x42 or (ssap & 0xFE) != 0x42:
        return None

    ctrl = int(linkRaw[2])
    if (ctrl & 0x03) == 0x03:
        # U-frame — 1-byte control field, payload starts at offset 3
        return linkRaw[3:]
    else:
        # I/S-frame — 2-byte control field, payload starts at offset 4
        return linkRaw[4:]


def decodeSTP(p=None, linkRaw=None):
    """Decode an STP BPDU from a scapy packet or raw link-layer payload.

    Returns a dict on success or ``None`` when the bytes do not match
    the STP BPDU wire format.
    """
    try:
        bpdu = _extractStpBytes(p, linkRaw)
        if bpdu is None or len(bpdu) < 4:
            return None

        protoId = struct.unpack_from(">H", bpdu, 0)[0]
        if protoId != 0x0000:
            return None

        version = int(bpdu[2])
        bpduType = int(bpdu[3])
        bpduTypeName = STP_BPDU_TYPES.get(bpduType, f"Unknown (0x{bpduType:02x})")
        isRstp = (version == 2 and bpduType == 0x02)

        result = {
            "Protocol Identifier": protoId,
            "stp.proto_id": protoId,
            "link.stp.proto_id": protoId,
            "Protocol Version": version,
            "stp.version": version,
            "link.stp.version": version,
            "BPDU Type": bpduTypeName,
            "stp.bpdu_type": bpduTypeName,
            "link.stp.bpdu_type": bpduTypeName,
            "BPDU Type Code": f"0x{bpduType:02x}",
            "stp.bpdu_type_code": f"0x{bpduType:02x}",
            "link.stp.bpdu_type_code": f"0x{bpduType:02x}",
            "Wire Length": len(bpdu),
            "wire.len": len(bpdu),
            "link.stp.wire.len": len(bpdu),
        }

        # TCN BPDU — header only, no body
        if bpduType == 0x80:
            result["Type"] = "TCN"
            result["stp.type"] = "TCN"
            result["link.stp.type"] = "TCN"
            return result

        # Configuration / RSTP BPDU — needs at least 4 (header) + 27 (body) = 31 bytes
        if len(bpdu) < 35:
            return None

        flags = int(bpdu[4])
        flagsStr = _decodeStateFlags(flags, isRstp)
        result["Flags"] = flagsStr
        result["stp.flags"] = flagsStr
        result["link.stp.flags"] = flagsStr
        result["Flags Code"] = f"0x{flags:02x}"
        result["stp.flags_code"] = f"0x{flags:02x}"
        result["link.stp.flags_code"] = f"0x{flags:02x}"

        rootPriority, rootMac, rootBridgeId = _decodeBridgeId(bpdu[5:13])
        result["Root Bridge ID"] = rootBridgeId
        result["stp.root_bridge_id"] = rootBridgeId
        result["link.stp.root_bridge_id"] = rootBridgeId
        result["Root Priority"] = rootPriority
        result["stp.root_priority"] = rootPriority
        result["link.stp.root_priority"] = rootPriority
        result["Root MAC"] = rootMac
        result["stp.root_mac"] = rootMac
        result["link.stp.root_mac"] = rootMac

        rootPathCost = struct.unpack_from(">I", bpdu, 13)[0]
        result["Root Path Cost"] = rootPathCost
        result["stp.root_path_cost"] = rootPathCost
        result["link.stp.root_path_cost"] = rootPathCost

        bridgePriority, bridgeMac, bridgeId = _decodeBridgeId(bpdu[17:25])
        result["Bridge ID"] = bridgeId
        result["stp.bridge_id"] = bridgeId
        result["link.stp.bridge_id"] = bridgeId
        result["Bridge Priority"] = bridgePriority
        result["stp.bridge_priority"] = bridgePriority
        result["link.stp.bridge_priority"] = bridgePriority
        result["Bridge MAC"] = bridgeMac
        result["stp.bridge_mac"] = bridgeMac
        result["link.stp.bridge_mac"] = bridgeMac

        portId = struct.unpack_from(">H", bpdu, 25)[0]
        result["Port ID"] = f"0x{portId:04x}"
        result["stp.port_id"] = f"0x{portId:04x}"
        result["link.stp.port_id"] = f"0x{portId:04x}"

        messageAge = struct.unpack_from(">H", bpdu, 27)[0]
        maxAge = struct.unpack_from(">H", bpdu, 29)[0]
        helloTime = struct.unpack_from(">H", bpdu, 31)[0]
        fwdDelay = struct.unpack_from(">H", bpdu, 33)[0]

        result["Message Age"] = _formatTime(messageAge)
        result["stp.message_age"] = _formatTime(messageAge)
        result["link.stp.message_age"] = _formatTime(messageAge)
        result["Max Age"] = _formatTime(maxAge)
        result["stp.max_age"] = _formatTime(maxAge)
        result["link.stp.max_age"] = _formatTime(maxAge)
        result["Hello Time"] = _formatTime(helloTime)
        result["stp.hello_time"] = _formatTime(helloTime)
        result["link.stp.hello_time"] = _formatTime(helloTime)
        result["Forward Delay"] = _formatTime(fwdDelay)
        result["stp.forward_delay"] = _formatTime(fwdDelay)
        result["link.stp.forward_delay"] = _formatTime(fwdDelay)

        # Label for stats categorization
        if isRstp:
            result["Type"] = "RSTP"
        else:
            result["Type"] = "Config"
        result["stp.type"] = result["Type"]
        result["link.stp.type"] = result["Type"]

        # Frame hex preview (first 64 bytes)
        result["Frame Hex"] = bpdu[:64].hex()
        result["stp.frame_hex"] = bpdu[:64].hex()
        result["link.stp.frame_hex"] = bpdu[:64].hex()

        return result
    except Exception:
        return None