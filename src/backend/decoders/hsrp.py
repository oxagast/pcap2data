"""HSRP (Hot Standby Router Protocol) decoder for PacketSnitch backend.

Decodes HSRPv1 (RFC 2281) and HSRPv2 messages carried over UDP port 1985.
HSRPv1 uses the multicast address 224.0.0.2; HSRPv2 uses 224.0.0.102.

HSRPv1 header (20 bytes):
  - Version        (1 byte, 0)
  - Op Code        (1 byte: 0=Hello, 1=Coup, 2=Resign)
  - State          (1 byte: 0=Initial, 1=Learn, 2=Listen, 4=Speak, 8=Standby, 16=Active)
  - Hello Time     (1 byte, seconds)
  - Hold Time      (1 byte, seconds)
  - Priority       (1 byte)
  - Group          (1 byte)
  - Reserved       (1 byte, 0)
  - Auth Data      (8 bytes, default "cisco" + NULs)
  - Virtual IP     (4 bytes, dotted)

HSRPv2 header (variable):
  - Version        (1 byte, 1 for IPv4, 2 for IPv6)
  - Op Code        (1 byte: 0=Hello, 1=Coup, 2=Resign, 3=Advertise)
  - State          (1 byte)
  - Hellotime      (1 byte)
  - Holdtime       (1 byte)
  - Priority       (1 byte)
  - Group          (1 byte)
  - Reserved       (1 byte, 0)
  - TLVs follow

This decoder follows the same dual-key dict pattern as the other decoders,
returning a dict on success or ``None`` on mismatch.
"""

import struct

HSRP_VERSIONS = {0: "HSRPv1", 1: "HSRPv2 (IPv4)", 2: "HSRPv2 (IPv6)"}

HSRP_OPCODES = {
    0: "Hello",
    1: "Coup",
    2: "Resign",
    3: "Advertise",
}

HSRP_STATES = {
    0: "Initial",
    1: "Learn",
    2: "Listen",
    4: "Speak",
    8: "Standby",
    16: "Active",
}

HSRPV2_TLV_TYPES = {
    1: "Unknown",
    2: "Group State TLV",
    3: "Interface Tracking TLV",
    4: "MD5 Authentication TLV",
    5: "Text Authentication TLV",
    6: "IPv4 Virtual IP TLV",
}


def _formatIpv4(raw):
    if raw is None or len(raw) < 4:
        return "0.0.0.0"
    return ".".join(str(b) for b in raw[:4])


def decodeHSRP(p, rawPayload):
    """Decode an HSRP packet from raw UDP payload bytes.

    Returns a dict on success or ``None`` when the bytes do not match
    the HSRP wire format.
    """
    try:
        if rawPayload is None or len(rawPayload) < 1:
            return None

        version = int(rawPayload[0])
        if version not in (0, 1, 2):
            return None

        versionName = HSRP_VERSIONS.get(version, f"HSRPv{version}")

        if version == 0:
            # HSRPv1 — 20-byte fixed header
            if len(rawPayload) < 20:
                return None
            opCode = int(rawPayload[1])
            state = int(rawPayload[2])
            helloTime = int(rawPayload[3])
            holdTime = int(rawPayload[4])
            priority = int(rawPayload[5])
            group = int(rawPayload[6])
            reserved = int(rawPayload[7])
            authData = rawPayload[8:16].decode(errors="ignore").rstrip("\x00")
            virtualIp = _formatIpv4(rawPayload[16:20])

            opName = HSRP_OPCODES.get(opCode, f"Unknown ({opCode})")
            stateName = HSRP_STATES.get(state, f"Unknown ({state})")

            return {
                "Version": versionName,
                "hsrp.version": versionName,
                "network.hsrp.version": versionName,
                "Op Code": opName,
                "hsrp.opcode": opName,
                "network.hsrp.opcode": opName,
                "State": stateName,
                "hsrp.state": stateName,
                "network.hsrp.state": stateName,
                "State Code": state,
                "hsrp.state_code": state,
                "network.hsrp.state_code": state,
                "Hello Time (s)": helloTime,
                "hsrp.hello_time": helloTime,
                "network.hsrp.hello_time": helloTime,
                "Hold Time (s)": holdTime,
                "hsrp.hold_time": holdTime,
                "network.hsrp.hold_time": holdTime,
                "Priority": priority,
                "hsrp.priority": priority,
                "network.hsrp.priority": priority,
                "Group": group,
                "hsrp.group": group,
                "network.hsrp.group": group,
                "Reserved": reserved,
                "hsrp.reserved": reserved,
                "network.hsrp.reserved": reserved,
                "Authentication": authData,
                "hsrp.auth": authData,
                "network.hsrp.auth": authData,
                "Virtual IP": virtualIp,
                "hsrp.virtual_ip": virtualIp,
                "network.hsrp.virtual_ip": virtualIp,
                "Wire length": len(rawPayload),
                "wire.len": len(rawPayload),
                "network.hsrp.wire.len": len(rawPayload),
            }
        else:
            # HSRPv2 (IPv4=version 1, IPv6=version 2)
            if len(rawPayload) < 8:
                return None
            opCode = int(rawPayload[1])
            state = int(rawPayload[2])
            helloTime = int(rawPayload[3])
            holdTime = int(rawPayload[4])
            priority = int(rawPayload[5])
            group = int(rawPayload[6])
            reserved = int(rawPayload[7])
            opName = HSRP_OPCODES.get(opCode, f"Unknown ({opCode})")
            stateName = HSRP_STATES.get(state, f"Unknown ({state})")

            result = {
                "Version": versionName,
                "hsrp.version": versionName,
                "network.hsrp.version": versionName,
                "Op Code": opName,
                "hsrp.opcode": opName,
                "network.hsrp.opcode": opName,
                "State": stateName,
                "hsrp.state": stateName,
                "network.hsrp.state": stateName,
                "State Code": state,
                "hsrp.state_code": state,
                "network.hsrp.state_code": state,
                "Hello Time (s)": helloTime,
                "hsrp.hello_time": helloTime,
                "network.hsrp.hello_time": helloTime,
                "Hold Time (s)": holdTime,
                "hsrp.hold_time": holdTime,
                "network.hsrp.hold_time": holdTime,
                "Priority": priority,
                "hsrp.priority": priority,
                "network.hsrp.priority": priority,
                "Group": group,
                "hsrp.group": group,
                "network.hsrp.group": group,
                "Reserved": reserved,
                "hsrp.reserved": reserved,
                "network.hsrp.reserved": reserved,
                "Wire length": len(rawPayload),
                "wire.len": len(rawPayload),
                "network.hsrp.wire.len": len(rawPayload),
            }

            # Parse HSRPv2 TLVs (offset 8 onwards)
            tlvs = []
            off = 8
            while off + 4 <= len(rawPayload):
                tlvType = struct.unpack_from(">H", rawPayload, off)[0]
                tlvLen = struct.unpack_from(">H", rawPayload, off + 2)[0]
                tlvName = HSRPV2_TLV_TYPES.get(tlvType, f"Unknown ({tlvType})")
                tlvValue = rawPayload[off + 4: off + 4 + tlvLen]
                if tlvType == 6 and len(tlvValue) >= 4:
                    # IPv4 Virtual IP TLV
                    vIp = _formatIpv4(tlvValue)
                    result["Virtual IP"] = vIp
                    result["hsrp.virtual_ip"] = vIp
                    result["network.hsrp.virtual_ip"] = vIp
                tlvs.append({"type": tlvName, "length": tlvLen})
                off += 4 + tlvLen
                if tlvLen == 0:
                    break
            if tlvs:
                result["TLVs"] = tlvs
                result["hsrp.tlvs"] = tlvs
                result["network.hsrp.tlvs"] = tlvs
            return result
    except Exception:
        return None