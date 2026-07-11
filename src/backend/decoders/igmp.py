import socket

try:
    import scapy.all as scapy
except ImportError:
    import scapy


def decodeIGMP(p, rawPayload):
    """
    Decode IGMP fields from a packet. Uses the scapy IGMP layer when available,
    otherwise falls back to parsing the first 8 bytes of the raw IP payload.
    """
    igmpTypeMap = {
        0x11: "Membership Query",
        0x12: "IGMPv1 Membership Report",
        0x16: "IGMPv2 Membership Report",
        0x17: "Leave Group",
        0x22: "IGMPv3 Membership Report",
    }

    igmpTypeNum = 0
    maxRespCode = 0
    checksumVal = 0
    groupAddr = "0.0.0.0"

    igmpClass = getattr(scapy, "IGMP", None)
    hasIgmpLayer = bool(igmpClass and p.haslayer(igmpClass)) or p.haslayer("IGMP")
    if hasIgmpLayer:
        igmpLayer = p[igmpClass] if igmpClass and p.haslayer(igmpClass) else p["IGMP"]
        try:
            igmpTypeNum = int(getattr(igmpLayer, "type", 0) or 0)
        except Exception:
            igmpTypeNum = 0
        try:
            maxRespCode = int(getattr(igmpLayer, "mrcode", 0) or 0)
        except Exception:
            maxRespCode = 0
        try:
            checksumVal = int(getattr(igmpLayer, "chksum", 0) or 0)
        except Exception:
            checksumVal = 0
        groupAddr = str(getattr(igmpLayer, "gaddr", "0.0.0.0") or "0.0.0.0")
    elif rawPayload and len(rawPayload) >= 8:
        igmpTypeNum = int(rawPayload[0])
        maxRespCode = int(rawPayload[1])
        checksumVal = int.from_bytes(rawPayload[2:4], byteorder="big", signed=False)
        try:
            groupAddr = socket.inet_ntoa(rawPayload[4:8])
        except Exception:
            groupAddr = "0.0.0.0"

    igmpType = igmpTypeMap.get(igmpTypeNum, f"Type {igmpTypeNum}")
    igmpVersion = "Unknown"
    if igmpTypeNum == 0x12:
        igmpVersion = "v1"
    elif igmpTypeNum in (0x16, 0x17, 0x11):
        igmpVersion = "v2"
    elif igmpTypeNum == 0x22:
        igmpVersion = "v3"

    return {
        "Type": igmpType,
        "igmp.type": igmpType,
        "network.igmp.type": igmpType,
        "Type Number": igmpTypeNum,
        "igmp.type_num": igmpTypeNum,
        "network.igmp.type_num": igmpTypeNum,
        "Version": igmpVersion,
        "igmp.version": igmpVersion,
        "network.igmp.version": igmpVersion,
        "Max Response Time (ds)": maxRespCode,
        "igmp.max_resp_time_ds": maxRespCode,
        "network.igmp.max_resp_time_ds": maxRespCode,
        "Group Address": groupAddr,
        "igmp.group_addr": groupAddr,
        "network.igmp.group_addr": groupAddr,
        "IGMP Checksum": hex(checksumVal),
        "igmp.chksum": hex(checksumVal),
        "network.igmp.chksum": hex(checksumVal),
        "Wire length": len(rawPayload) if rawPayload is not None else 0,
        "wire.len": len(rawPayload) if rawPayload is not None else 0,
        "network.igmp.wire.len": len(rawPayload) if rawPayload is not None else 0,
    }
