"""LACP (Link Aggregation Control Protocol) decoder for PacketSnitch backend.

Decodes LACP frames (IEEE 802.3ad / 802.1AX) carried directly over Ethernet
with EtherType 0x8809 and Slow Protocols subtype 0x01.

LACPDU frame (110 bytes payload):
  - Subtype LACP    (1 byte, 0x01)
  - Version         (1 byte, 0x01)
  - TLV Actor       (20 bytes)
  - TLV Partner     (20 bytes)
  - TLV Collector   (20 bytes)
  - Reserved        (60 bytes)
  - Terminator      (1 byte subtype 0x00) + Version (1 byte) + padding

Actor/Partner TLV (20 bytes each):
  - TLV Type        (1 byte: 0x01=Actor, 0x02=Partner)
  - TLV Length      (1 byte, 0x14=20)
  - System Priority (2 bytes, BE)
  - System          (2 bytes, BE — MAC-derived)
  - Key             (2 bytes, BE)
  - Port Priority   (2 bytes, BE)
  - Port            (2 bytes, BE)
  - State           (1 byte, bitmask)
  - Reserved        (3 bytes)

This decoder follows the same dual-key dict pattern as the other decoders,
returning a dict on success or ``None`` on mismatch.
"""

import struct

LACP_SUBTYPES = {
    0x01: "LACP",
    0x02: "Marker Protocol",
}

LACP_STATE_BITS = {
    0x01: "Activity",
    0x02: "Timeout",
    0x04: "Aggregation",
    0x08: "Synchronization",
    0x10: "Collecting",
    0x20: "Distributing",
    0x40: "Defaulted",
    0x80: "Expired",
}

MARKER_TLV_TYPES = {
    0x01: "Marker Information",
    0x02: "Marker Response Information",
}


def _decodeStateFlags(state):
    flags = []
    for bit, name in LACP_STATE_BITS.items():
        if state & bit:
            flags.append(name)
    return " | ".join(flags) if flags else "None"


def _decodeActorPartnerTlv(raw, role):
    """Decode an Actor (0x01) or Partner (0x02) TLV (20 bytes).

    Layout: Type(1) + Len(1) + SystemPriority(2) + System(6, MAC) +
    Key(2) + PortPriority(2) + Port(2) + State(1) + Reserved(3).
    """
    if raw is None or len(raw) < 20:
        return None
    tlvType = int(raw[0])
    tlvLen = int(raw[1])
    sysPriority = struct.unpack_from(">H", raw, 2)[0]
    system = raw[4:10]
    systemStr = ":".join(f"{b:02x}" for b in system)
    key = struct.unpack_from(">H", raw, 10)[0]
    portPriority = struct.unpack_from(">H", raw, 12)[0]
    port = struct.unpack_from(">H", raw, 14)[0]
    state = int(raw[16])
    stateFlags = _decodeStateFlags(state)
    return {
        f"{role} TLV Type": tlvType,
        f"{role}.tlv_type": tlvType,
        f"link.lacp.{role.lower()}.tlv_type": tlvType,
        f"{role} TLV Length": tlvLen,
        f"{role}.tlv_len": tlvLen,
        f"link.lacp.{role.lower()}.tlv_len": tlvLen,
        f"{role} System Priority": sysPriority,
        f"{role}.sys_priority": sysPriority,
        f"link.lacp.{role.lower()}.sys_priority": sysPriority,
        f"{role} System": systemStr,
        f"{role}.system": systemStr,
        f"link.lacp.{role.lower()}.system": systemStr,
        f"{role} Key": key,
        f"{role}.key": key,
        f"link.lacp.{role.lower()}.key": key,
        f"{role} Port Priority": portPriority,
        f"{role}.port_priority": portPriority,
        f"link.lacp.{role.lower()}.port_priority": portPriority,
        f"{role} Port": port,
        f"{role}.port": port,
        f"link.lacp.{role.lower()}.port": port,
        f"{role} State": stateFlags,
        f"{role}.state": stateFlags,
        f"link.lacp.{role.lower()}.state": stateFlags,
        f"{role} State Code": f"0x{state:02x}",
        f"{role}.state_code": f"0x{state:02x}",
        f"link.lacp.{role.lower()}.state_code": f"0x{state:02x}",
    }


def decodeLACP(p, rawPayload):
    """Decode an LACPDU from raw Ethernet payload bytes.

    Returns a dict on success or ``None`` when the bytes do not match
    the LACP / Marker wire format.
    """
    try:
        if rawPayload is None or len(rawPayload) < 2:
            return None

        subtype = int(rawPayload[0])
        if subtype not in (0x01, 0x02):
            return None

        version = int(rawPayload[1])
        subtypeName = LACP_SUBTYPES.get(subtype, f"Unknown (0x{subtype:02x})")

        result = {
            "Subtype": subtypeName,
            "lacp.subtype": subtypeName,
            "link.lacp.subtype": subtypeName,
            "Version": version,
            "lacp.version": version,
            "link.lacp.version": version,
            "Wire length": len(rawPayload),
            "wire.len": len(rawPayload),
            "link.lacp.wire.len": len(rawPayload),
        }

        # LACPDU: Actor + Partner + Collector TLVs
        if subtype == 0x01 and len(rawPayload) >= 4:
            actor = _decodeActorPartnerTlv(rawPayload[2:22], "Actor")
            if actor:
                result.update(actor)
            partner = _decodeActorPartnerTlv(rawPayload[22:42], "Partner")
            if partner:
                result.update(partner)
            # Collector TLV (starts at offset 42)
            if len(rawPayload) >= 62:
                colType = int(rawPayload[42])
                colLen = int(rawPayload[43])
                maxDelay = struct.unpack_from(">H", rawPayload, 44)[0]
                result["Collector TLV Type"] = colType
                result["lacp.collector_tlv_type"] = colType
                result["link.lacp.collector_tlv_type"] = colType
                result["Collector TLV Length"] = colLen
                result["lacp.collector_tlv_len"] = colLen
                result["link.lacp.collector_tlv_len"] = colLen
                result["Collector Max Delay"] = maxDelay
                result["lacp.collector_max_delay"] = maxDelay
                result["link.lacp.collector_max_delay"] = maxDelay

        # Marker: Actor TLV + Partner TLV
        elif subtype == 0x02 and len(rawPayload) >= 4:
            actor = _decodeActorPartnerTlv(rawPayload[2:22], "Actor")
            if actor:
                result.update(actor)
            partner = _decodeActorPartnerTlv(rawPayload[22:42], "Partner")
            if partner:
                result.update(partner)

        return result
    except Exception:
        return None