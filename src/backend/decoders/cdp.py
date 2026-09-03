"""CDP (Cisco Discovery Protocol) decoder for PacketSnitch backend.

Decodes CDP frames carried directly over Ethernet with EtherType 0x88cc
(or over 802.2 LLC DSAP=0xAA SSAP=0xAA with SNAP OUI 0x00000C). CDP is a
Cisco-proprietary Layer 2 protocol used to share device information
between directly connected Cisco equipment.

CDP header (4 bytes):
  - Version        (1 byte, typically 1 or 2)
  - TTL            (1 byte, seconds before discarding)
  - Checksum       (2 bytes, BE)
  - TLVs follow

CDP TLV structure:
  - Type           (2 bytes, BE)
  - Length         (2 bytes, BE — includes Type + Length)
  - Value          (Length - 4 bytes)

This decoder follows the same dual-key dict pattern as the other decoders,
returning a dict on success or ``None`` on mismatch.
"""

import struct

CDP_TLV_TYPES = {
    0x0001: "Device ID",
    0x0002: "Addresses",
    0x0003: "Port ID",
    0x0004: "Capabilities",
    0x0005: "Software Version",
    0x0006: "Platform",
    0x0007: "IP Network Prefix",
    0x0008: "VTP Management Domain",
    0x0009: "Native VLAN",
    0x000A: "Duplex",
    0x000B: "VLAN Trunk (TLV Appliance)",
    0x000C: "VoIP VLAN Reply",
    0x000D: "VoIP VLAN Query",
    0x000E: "Power Available",
    0x000F: "MTU",
    0x0010: "Trust Bitmap",
    0x0011: "Untrusted Port CoS",
    0x0012: "System Name",
    0x0013: "System Object ID",
    0x0014: "Management Address",
    0x0015: "Location",
    0x0016: "External Port ID",
    0x0017: "Power Requested",
    0x0018: "Power Available (v2)",
    0x0019: "Port Unidirectional",
    0x001A: "MTU (v2)",
}

CDP_CAPABILITY_BITS = {
    0x01: "Router",
    0x02: "Transparent Bridge",
    0x04: "Source-Route Bridge",
    0x08: "Network Switch",
    0x10: "Host",
    0x20: "IGMP Capable",
    0x40: "Repeater",
    0x80: "VoIP Phone",
}

ADDRESS_PROTOCOL_IDS = {
    1: "NLPID (IPv4 = 0xCC)",
    2: "802.2 (MAC)",
    6: "IPv6",
    0x11: "IPv4",
    0x0c: "Novell IPX",
}


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


def _decodeAddressesTlv(value):
    """Decode the CDP Addresses TLV value into a list of protocol addresses.

    Layout: count(4 bytes), then per entry:
      protocol_type(1) + protocol_length(1) + protocol_value(proto_len) +
      address_length(2) + address(addr_len)
    For NLPID IPv4 (proto_type=1, proto_value=0xCC) the address is 4 bytes.
    """
    if not value or len(value) < 4:
        return []
    try:
        count = struct.unpack_from(">I", value, 0)[0]
    except Exception:
        return []
    addresses = []
    off = 4
    for _ in range(count):
        if off + 2 > len(value):
            break
        protoType = int(value[off])
        protoLen = int(value[off + 1])
        if off + 2 + protoLen + 2 > len(value):
            break
        protoValue = value[off + 2: off + 2 + protoLen]
        addrLen = struct.unpack_from(">H", value, off + 2 + protoLen)[0]
        addrStart = off + 2 + protoLen + 2
        addrValue = value[addrStart: addrStart + addrLen]
        protoName = ADDRESS_PROTOCOL_IDS.get(protoType, f"Proto {protoType}")
        if protoType in (1, 0x11) and len(addrValue) >= 4:
            addrStr = _formatIpv4(addrValue)
        elif protoType == 6 and len(addrValue) >= 16:
            addrStr = _formatIpv6(addrValue)
        elif protoType == 2:
            addrStr = ":".join(f"{b:02x}" for b in addrValue[:6])
        else:
            addrStr = addrValue.hex()
        addresses.append(f"{protoName}: {addrStr}")
        off = addrStart + addrLen
    return addresses


def _decodeCapabilitiesTlv(value):
    if not value or len(value) < 4:
        return "None"
    capValue = struct.unpack_from(">I", value, 0)[0]
    caps = []
    for bit, name in CDP_CAPABILITY_BITS.items():
        if capValue & bit:
            caps.append(name)
    return " | ".join(caps) if caps else "None"


def decodeCDP(p, rawPayload):
    """Decode a CDP frame from raw Ethernet payload bytes.

    Returns a dict on success or ``None`` when the bytes do not match
    the CDP wire format.
    """
    try:
        if rawPayload is None or len(rawPayload) < 4:
            return None

        # CDP starts with Version (1) + TTL (1) + Checksum (2) + TLVs.
        # Some captures prepend a SNAP header (DSAP=0xAA SSAP=0xAA
        # Control=0x03 OUI=00:00:0C + 0x0000); detect and skip it.
        offset = 0
        if (
            len(rawPayload) >= 8
            and rawPayload[0] == 0xAA
            and rawPayload[1] == 0xAA
            and rawPayload[2] == 0x03
        ):
            offset = 8

        if len(rawPayload) < offset + 4:
            return None

        version = int(rawPayload[offset])
        ttl = int(rawPayload[offset + 1])
        checksum = struct.unpack_from(">H", rawPayload, offset + 2)[0]

        result = {
            "Version": version,
            "cdp.version": version,
            "link.cdp.version": version,
            "TTL (s)": ttl,
            "cdp.ttl": ttl,
            "link.cdp.ttl": ttl,
            "Checksum": hex(checksum),
            "cdp.chksum": hex(checksum),
            "link.cdp.chksum": hex(checksum),
            "Wire length": len(rawPayload),
            "wire.len": len(rawPayload),
            "link.cdp.wire.len": len(rawPayload),
        }

        # Parse TLVs starting after the 4-byte header
        tlvOff = offset + 4
        tlvs = []
        while tlvOff + 4 <= len(rawPayload):
            tlvType = struct.unpack_from(">H", rawPayload, tlvOff)[0]
            tlvLen = struct.unpack_from(">H", rawPayload, tlvOff + 2)[0]
            if tlvLen < 4 or tlvOff + tlvLen > len(rawPayload):
                break
            tlvValue = rawPayload[tlvOff + 4: tlvOff + tlvLen]
            tlvName = CDP_TLV_TYPES.get(tlvType, f"Unknown (0x{tlvType:04x})")

            if tlvType == 0x0001:
                deviceId = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["Device ID"] = deviceId
                result["cdp.device_id"] = deviceId
                result["link.cdp.device_id"] = deviceId
            elif tlvType == 0x0002:
                addresses = _decodeAddressesTlv(tlvValue)
                result["Addresses"] = addresses
                result["cdp.addresses"] = addresses
                result["link.cdp.addresses"] = addresses
            elif tlvType == 0x0003:
                portId = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["Port ID"] = portId
                result["cdp.port_id"] = portId
                result["link.cdp.port_id"] = portId
            elif tlvType == 0x0004:
                caps = _decodeCapabilitiesTlv(tlvValue)
                result["Capabilities"] = caps
                result["cdp.capabilities"] = caps
                result["link.cdp.capabilities"] = caps
            elif tlvType == 0x0005:
                swVersion = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["Software Version"] = swVersion
                result["cdp.software_version"] = swVersion
                result["link.cdp.software_version"] = swVersion
            elif tlvType == 0x0006:
                platform = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["Platform"] = platform
                result["cdp.platform"] = platform
                result["link.cdp.platform"] = platform
            elif tlvType == 0x0009:
                vtpDomain = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["VTP Management Domain"] = vtpDomain
                result["cdp.vtp_domain"] = vtpDomain
                result["link.cdp.vtp_domain"] = vtpDomain
            elif tlvType == 0x000A:
                if len(tlvValue) >= 2:
                    nativeVlan = struct.unpack_from(">H", tlvValue, 0)[0]
                    result["Native VLAN"] = nativeVlan
                    result["cdp.native_vlan"] = nativeVlan
                    result["link.cdp.native_vlan"] = nativeVlan
            elif tlvType == 0x000B:
                if len(tlvValue) >= 1:
                    duplex = int(tlvValue[0])
                    duplexName = {0: "Half", 1: "Full"}.get(duplex, f"Unknown ({duplex})")
                    result["Duplex"] = duplexName
                    result["cdp.duplex"] = duplexName
                    result["link.cdp.duplex"] = duplexName
            elif tlvType == 0x000F:
                if len(tlvValue) >= 4:
                    mtu = struct.unpack_from(">I", tlvValue, 0)[0]
                    result["MTU"] = mtu
                    result["cdp.mtu"] = mtu
                    result["link.cdp.mtu"] = mtu
            elif tlvType == 0x0012:
                systemName = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["System Name"] = systemName
                result["cdp.system_name"] = systemName
                result["link.cdp.system_name"] = systemName
            elif tlvType == 0x0014:
                mgmtAddresses = _decodeAddressesTlv(tlvValue)
                result["Management Address"] = mgmtAddresses
                result["cdp.mgmt_address"] = mgmtAddresses
                result["link.cdp.mgmt_address"] = mgmtAddresses
            elif tlvType == 0x0015:
                location = tlvValue.decode(errors="ignore").rstrip("\x00")
                result["Location"] = location
                result["cdp.location"] = location
                result["link.cdp.location"] = location

            tlvs.append({"type": tlvName, "length": tlvLen})
            tlvOff += tlvLen

        if tlvs:
            result["TLVs"] = tlvs
            result["cdp.tlvs"] = tlvs
            result["link.cdp.tlvs"] = tlvs
        return result
    except Exception:
        return None