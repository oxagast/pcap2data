"""OSPF (Open Shortest Path First) protocol decoder for PacketSnitch backend.

Decodes OSPFv2 (RFC 2328) and OSPFv3 (RFC 5340) messages carried directly
over IP (protocol number 89). OSPF runs directly on IP — there is no TCP/UDP
transport layer.

OSPFv2 header (24 bytes):
  - Version        (1 byte, 2)
  - Type           (1 byte: 1=Hello, 2=DD, 3=LS Request, 4=LS Update, 5=LS ACK)
  - Packet length  (2 bytes, BE)
  - Router ID      (4 bytes, dotted)
  - Area ID        (4 bytes, dotted)
  - Checksum       (2 bytes)
  - Auth Type      (2 bytes: 0=None, 1=Simple, 2=Crypto)
  - Auth Data      (8 bytes)

OSPFv3 header (16 bytes, no authentication fields):
  - Version        (1 byte, 3)
  - Type           (1 byte)
  - Packet length  (2 bytes, BE)
  - Router ID      (4 bytes, dotted)
  - Area ID        (4 bytes, dotted)
  - Checksum       (2 bytes)
  - Instance ID    (1 byte)
  - Reserved       (1 byte, 0)

This decoder follows the same dual-key dict pattern as the other decoders,
returning a dict on success or ``None`` on mismatch.
"""

import struct

OSPF_VERSIONS = {2: "OSPFv2", 3: "OSPFv3"}

OSPF_TYPES = {
    1: "Hello",
    2: "Database Description",
    3: "Link State Request",
    4: "Link State Update",
    5: "Link State ACK",
}

OSPF_AUTH_TYPES = {
    0: "None",
    1: "Simple Password",
    2: "Cryptographic (MD5)",
}

OSPF_LSA_TYPES_V2 = {
    1: "Router-LSA",
    2: "Network-LSA",
    3: "Summary-LSA (IP network)",
    4: "Summary-LSA (ASBR)",
    5: "AS-External-LSA",
    6: "Group-Membership-LSA",
    7: "Type-7-LSA (NSSA)",
    8: "External-Attributes-LSA",
    9: "Opaque-LSA (link-local)",
    10: "Opaque-LSA (area)",
    11: "Opaque-LSA (AS)",
}

OSPF_LSA_TYPES_V3 = {
    1: "Router-LSA",
    2: "Network-LSA",
    3: "Inter-Area-Prefix-LSA",
    4: "Inter-Area-Router-LSA",
    5: "AS-External-LSA",
    7: "Type-7-LSA (NSSA)",
    8: "Link-LSA",
    9: "Intra-Area-Prefix-LSA",
    10: "Opaque-LSA (area)",
    11: "Opaque-LSA (AS)",
}


def _formatIpv4(raw):
    if raw is None or len(raw) < 4:
        return "0.0.0.0"
    return ".".join(str(b) for b in raw[:4])


def decodeOSPF(p, rawPayload):
    """Decode an OSPFv2/v3 packet from a scapy packet or raw IP payload.

    Prefers the scapy OSPF layer when present; otherwise parses the raw
    bytes. Returns a dict on success or ``None`` when the bytes do not
    match the OSPF wire format.
    """
    try:
        if rawPayload is None or len(rawPayload) < 16:
            return None

        version = int(rawPayload[0])
        if version not in (2, 3):
            return None

        msgType = int(rawPayload[1])
        typeName = OSPF_TYPES.get(msgType, f"Unknown ({msgType})")
        versionName = OSPF_VERSIONS.get(version, f"OSPFv{version}")

        if version == 2:
            if len(rawPayload) < 24:
                return None
            pktLen = struct.unpack_from(">H", rawPayload, 2)[0]
            routerId = _formatIpv4(rawPayload[4:8])
            areaId = _formatIpv4(rawPayload[8:12])
            checksum = struct.unpack_from(">H", rawPayload, 12)[0]
            authType = struct.unpack_from(">H", rawPayload, 14)[0]
            authTypeName = OSPF_AUTH_TYPES.get(authType, f"Unknown ({authType})")
            result = {
                "Version": versionName,
                "ospf.version": versionName,
                "network.ospf.version": versionName,
                "Type": typeName,
                "ospf.type": typeName,
                "network.ospf.type": typeName,
                "Packet Length": pktLen,
                "ospf.length": pktLen,
                "network.ospf.length": pktLen,
                "Router ID": routerId,
                "ospf.router_id": routerId,
                "network.ospf.router_id": routerId,
                "Area ID": areaId,
                "ospf.area_id": areaId,
                "network.ospf.area_id": areaId,
                "Checksum": hex(checksum),
                "ospf.chksum": hex(checksum),
                "network.ospf.chksum": hex(checksum),
                "Auth Type": authTypeName,
                "ospf.auth_type": authTypeName,
                "network.ospf.auth_type": authTypeName,
                "Auth Type Code": authType,
                "ospf.auth_type_code": authType,
                "network.ospf.auth_type_code": authType,
            }
            # Hello-specific fields (OSPFv2)
            if msgType == 1 and len(rawPayload) >= 44:
                networkMask = _formatIpv4(rawPayload[24:28])
                helloInterval = struct.unpack_from(">H", rawPayload, 28)[0]
                options = int(rawPayload[30])
                priority = int(rawPayload[31])
                deadInterval = struct.unpack_from(">I", rawPayload, 32)[0]
                dr = _formatIpv4(rawPayload[36:40])
                bdr = _formatIpv4(rawPayload[40:44])
                result.update(
                    {
                        "Network Mask": networkMask,
                        "ospf.network_mask": networkMask,
                        "network.ospf.network_mask": networkMask,
                        "Hello Interval (s)": helloInterval,
                        "ospf.hello_interval": helloInterval,
                        "network.ospf.hello_interval": helloInterval,
                        "Options": hex(options),
                        "ospf.options": hex(options),
                        "network.ospf.options": hex(options),
                        "Router Priority": priority,
                        "ospf.router_priority": priority,
                        "network.ospf.router_priority": priority,
                        "Dead Interval (s)": deadInterval,
                        "ospf.dead_interval": deadInterval,
                        "network.ospf.dead_interval": deadInterval,
                        "Designated Router": dr,
                        "ospf.dr": dr,
                        "network.ospf.dr": dr,
                        "Backup Designated Router": bdr,
                        "ospf.bdr": bdr,
                        "network.ospf.bdr": bdr,
                    }
                )
                # Active neighbors (each 4 bytes after offset 44)
                neighbors = []
                off = 44
                while off + 4 <= len(rawPayload):
                    neighbors.append(_formatIpv4(rawPayload[off:off + 4]))
                    off += 4
                if neighbors:
                    result["Active Neighbors"] = neighbors
                    result["ospf.neighbors"] = neighbors
                    result["network.ospf.neighbors"] = neighbors
                    result["Neighbor Count"] = len(neighbors)
                    result["ospf.neighbor_count"] = len(neighbors)
                    result["network.ospf.neighbor_count"] = len(neighbors)
            # Database Description fields (OSPFv2)
            elif msgType == 2 and len(rawPayload) >= 32:
                mtu = struct.unpack_from(">H", rawPayload, 24)[0]
                options = int(rawPayload[26])
                flags = int(rawPayload[27])
                seqNum = struct.unpack_from(">I", rawPayload, 28)[0]
                flagNames = []
                if flags & 0x01:
                    flagNames.append("MS (Master/Slave)")
                if flags & 0x02:
                    flagNames.append("M (More)")
                if flags & 0x04:
                    flagNames.append("I (Init)")
                result.update(
                    {
                        "Interface MTU": mtu,
                        "ospf.if_mtu": mtu,
                        "network.ospf.if_mtu": mtu,
                        "Options": hex(options),
                        "ospf.options": hex(options),
                        "network.ospf.options": hex(options),
                        "DD Flags": " | ".join(flagNames) if flagNames else "None",
                        "ospf.dd_flags": hex(flags),
                        "network.ospf.dd_flags": hex(flags),
                        "DD Sequence": seqNum,
                        "ospf.dd_seq": seqNum,
                        "network.ospf.dd_seq": seqNum,
                    }
                )
            # Link State Update: number of LSAs
            elif msgType == 4 and len(rawPayload) >= 28:
                lsaCount = struct.unpack_from(">I", rawPayload, 24)[0]
                result["LSA Count"] = lsaCount
                result["ospf.lsa_count"] = lsaCount
                result["network.ospf.lsa_count"] = lsaCount
        else:
            # OSPFv3 (16-byte header)
            if len(rawPayload) < 16:
                return None
            pktLen = struct.unpack_from(">H", rawPayload, 2)[0]
            routerId = _formatIpv4(rawPayload[4:8])
            areaId = _formatIpv4(rawPayload[8:12])
            checksum = struct.unpack_from(">H", rawPayload, 12)[0]
            instanceId = int(rawPayload[14])
            result = {
                "Version": versionName,
                "ospf.version": versionName,
                "network.ospf.version": versionName,
                "Type": typeName,
                "ospf.type": typeName,
                "network.ospf.type": typeName,
                "Packet Length": pktLen,
                "ospf.length": pktLen,
                "network.ospf.length": pktLen,
                "Router ID": routerId,
                "ospf.router_id": routerId,
                "network.ospf.router_id": routerId,
                "Area ID": areaId,
                "ospf.area_id": areaId,
                "network.ospf.area_id": areaId,
                "Checksum": hex(checksum),
                "ospf.chksum": hex(checksum),
                "network.ospf.chksum": hex(checksum),
                "Instance ID": instanceId,
                "ospf.instance_id": instanceId,
                "network.ospf.instance_id": instanceId,
            }
            # OSPFv3 Hello fields
            if msgType == 1 and len(rawPayload) >= 36:
                interfaceId = struct.unpack_from(">I", rawPayload, 16)[0]
                priority = int(rawPayload[20])
                options = struct.unpack_from(">I", rawPayload, 21)[0] & 0x00FFFFFF
                helloInterval = struct.unpack_from(">H", rawPayload, 24)[0]
                deadInterval = struct.unpack_from(">H", rawPayload, 26)[0]
                dr = _formatIpv4(rawPayload[28:32])
                bdr = _formatIpv4(rawPayload[32:36])
                result.update(
                    {
                        "Interface ID": interfaceId,
                        "ospf.interface_id": interfaceId,
                        "network.ospf.interface_id": interfaceId,
                        "Router Priority": priority,
                        "ospf.router_priority": priority,
                        "network.ospf.router_priority": priority,
                        "Options": hex(options),
                        "ospf.options": hex(options),
                        "network.ospf.options": hex(options),
                        "Hello Interval (s)": helloInterval,
                        "ospf.hello_interval": helloInterval,
                        "network.ospf.hello_interval": helloInterval,
                        "Dead Interval (s)": deadInterval,
                        "ospf.dead_interval": deadInterval,
                        "network.ospf.dead_interval": deadInterval,
                        "Designated Router": dr,
                        "ospf.dr": dr,
                        "network.ospf.dr": dr,
                        "Backup Designated Router": bdr,
                        "ospf.bdr": bdr,
                        "network.ospf.bdr": bdr,
                    }
                )
                neighbors = []
                off = 36
                while off + 4 <= len(rawPayload):
                    neighbors.append(_formatIpv4(rawPayload[off:off + 4]))
                    off += 4
                if neighbors:
                    result["Active Neighbors"] = neighbors
                    result["ospf.neighbors"] = neighbors
                    result["network.ospf.neighbors"] = neighbors
                    result["Neighbor Count"] = len(neighbors)
                    result["ospf.neighbor_count"] = len(neighbors)
                    result["network.ospf.neighbor_count"] = len(neighbors)
            elif msgType == 4 and len(rawPayload) >= 20:
                lsaCount = struct.unpack_from(">I", rawPayload, 16)[0]
                result["LSA Count"] = lsaCount
                result["ospf.lsa_count"] = lsaCount
                result["network.ospf.lsa_count"] = lsaCount

        result["Wire length"] = len(rawPayload)
        result["wire.len"] = len(rawPayload)
        result["network.ospf.wire.len"] = len(rawPayload)
        return result
    except Exception:
        return None