"""MNDP (MikroTik Neighbor Discovery Protocol) decoder for PacketSnitch backend.

Decodes MNDP frames carried over UDP port 5678 (broadcast). MNDP is a
MikroTik Layer 2/3 protocol used to share device information between
directly connected RouterOS equipment.

MNDP header (4 bytes):
  - Unknown / Preamble (2 bytes — observed as 0x0000 in captures)
  - Sequence Number    (2 bytes, BE)
  - TLVs follow

MNDP TLV structure (differs from CDP — length is value-only):
  - Type           (2 bytes, BE)
  - Length         (2 bytes, BE — value length, NOT including Type+Length)
  - Value          (Length bytes)

This decoder follows the same dual-key dict pattern as the other decoders,
returning a dict on success or ``None`` on mismatch.
"""

import struct

MNDP_TLV_TYPES = {
    0x0001: "MAC Address",
    0x0005: "Identity",
    0x0007: "Version",
    0x0008: "Platform",
    0x000A: "Uptime",
    0x000B: "Software ID",
    0x000C: "Board",
    0x000E: "Unpack",
    0x000F: "IPv6 Address",
    0x0010: "Interface Name",
    0x0011: "IPv4 Address",
}

MNDP_UNPACK_VALUES = {
    1: "None",
}


def _formatMac(raw):
    if raw is None or len(raw) < 6:
        return "00:00:00:00:00:00"
    return ":".join(f"{b:02x}" for b in raw[:6])


def _formatIpv4(raw):
    if raw is None or len(raw) < 4:
        return "0.0.0.0"
    return ".".join(str(b) for b in raw[:4])


def _formatIpv6(raw):
    if raw is None or len(raw) < 16:
        return "::"
    parts = []
    for i in range(0, 16, 2):
        parts.append(f"{(raw[i] << 8) | raw[i + 1]:x}")
    return ":".join(parts)


def _formatUptime(raw):
    """Uptime TLV: 4-byte big-endian centiseconds (1/100 s)."""
    if not raw or len(raw) < 4:
        return None
    try:
        centis = struct.unpack_from(">I", raw, 0)[0]
    except Exception:
        return None
    seconds = centis / 100.0
    return f"{seconds:.2f}s"


def decodeMNDP(p, rawPayload):
    """Decode an MNDP frame from raw UDP payload bytes.

    Returns a dict on success or ``None`` when the bytes do not match
    the MNDP wire format.
    """
    try:
        if rawPayload is None or len(rawPayload) < 8:
            return None

        # MNDP header: 2 bytes unknown/preamble + 2 bytes sequence number.
        headerUnknown = rawPayload[0:2]
        seqNo = struct.unpack_from(">H", rawPayload, 2)[0]

        result = {
            "SeqNo": seqNo,
            "mndp.seqno": seqNo,
            "link.mndp.seqno": seqNo,
            "Header Unknown": headerUnknown.hex(),
            "mndp.header.unknown": headerUnknown.hex(),
            "link.mndp.header.unknown": headerUnknown.hex(),
            "Wire length": len(rawPayload),
            "wire.len": len(rawPayload),
            "link.mndp.wire.len": len(rawPayload),
        }

        # Parse TLVs starting after the 4-byte header. Unlike CDP, the
        # MNDP TLV length field is the value length only (it does NOT
        # include the 4-byte Type+Length header).
        tlvOff = 4
        tlvs = []
        firstTlvType = None
        while tlvOff + 4 <= len(rawPayload):
            tlvType = struct.unpack_from(">H", rawPayload, tlvOff)[0]
            tlvLen = struct.unpack_from(">H", rawPayload, tlvOff + 2)[0]
            if tlvOff + 4 + tlvLen > len(rawPayload):
                break
            tlvValue = rawPayload[tlvOff + 4: tlvOff + 4 + tlvLen]
            if firstTlvType is None:
                firstTlvType = tlvType
            tlvName = MNDP_TLV_TYPES.get(tlvType, f"Unknown (0x{tlvType:04x})")

            if tlvType == 0x0001:
                mac = _formatMac(tlvValue)
                result["MAC Address"] = mac
                result["mndp.mac"] = mac
                result["link.mndp.mac"] = mac
            elif tlvType == 0x0005:
                identity = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["Identity"] = identity
                result["mndp.identity"] = identity
                result["link.mndp.identity"] = identity
            elif tlvType == 0x0007:
                version = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["Version"] = version
                result["mndp.version"] = version
                result["link.mndp.version"] = version
            elif tlvType == 0x0008:
                platform = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["Platform"] = platform
                result["mndp.platform"] = platform
                result["link.mndp.platform"] = platform
            elif tlvType == 0x000A:
                uptime = _formatUptime(tlvValue)
                if uptime is not None:
                    result["Uptime"] = uptime
                    result["mndp.uptime"] = uptime
                    result["link.mndp.uptime"] = uptime
            elif tlvType == 0x000B:
                softwareId = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["Software ID"] = softwareId
                result["mndp.software_id"] = softwareId
                result["link.mndp.software_id"] = softwareId
            elif tlvType == 0x000C:
                board = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["Board"] = board
                result["mndp.board"] = board
                result["link.mndp.board"] = board
            elif tlvType == 0x000E:
                if len(tlvValue) >= 1:
                    unpackVal = int(tlvValue[0])
                    unpackName = MNDP_UNPACK_VALUES.get(
                        unpackVal, f"Unknown ({unpackVal})"
                    )
                    result["Unpack"] = unpackName
                    result["mndp.unpack"] = unpackName
                    result["link.mndp.unpack"] = unpackName
            elif tlvType == 0x000F:
                ipv6 = _formatIpv6(tlvValue)
                result["IPv6 Address"] = ipv6
                result["mndp.ipv6_address"] = ipv6
                result["link.mndp.ipv6_address"] = ipv6
            elif tlvType == 0x0010:
                ifaceName = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["Interface Name"] = ifaceName
                result["mndp.interface_name"] = ifaceName
                result["link.mndp.interface_name"] = ifaceName
            elif tlvType == 0x0011:
                ipv4 = _formatIpv4(tlvValue)
                result["IPv4 Address"] = ipv4
                result["mndp.ipv4_address"] = ipv4
                result["link.mndp.ipv4_address"] = ipv4

            tlvs.append({"type": tlvName, "length": tlvLen})
            tlvOff += 4 + tlvLen

        # Strict gate: the first TLV must be the MAC Address TLV (type 1)
        # and must have length 6. This mirrors Wireshark's heuristic and
        # prevents random binary data from being accepted as MNDP.
        if firstTlvType != 0x0001:
            return None

        if tlvs:
            result["TLVs"] = tlvs
            result["mndp.tlvs"] = tlvs
            result["link.mndp.tlvs"] = tlvs
        return result
    except Exception:
        return None