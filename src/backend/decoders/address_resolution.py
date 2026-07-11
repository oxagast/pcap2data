try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    import scapy.all as scapy
except ImportError:
    import scapy


def decodeAddressResolutionPacket(p):
    """
    Decode ARP/RARP packet fields from a scapy packet.
    Returns a tuple of (protocolName, sectionDict, srcIp, dstIp).
    """
    arpClass = getattr(scapy, "ARP", None)
    hasArpLayer = bool(arpClass and p.haslayer(arpClass)) or p.haslayer("ARP")
    if not hasArpLayer:
        return None

    arpLayer = p[arpClass] if arpClass and p.haslayer(arpClass) else p["ARP"]

    opMap = {
        1: "Request",
        2: "Reply",
        3: "RARP Request",
        4: "RARP Reply",
        8: "InARP Request",
        9: "InARP Reply",
    }

    try:
        opCode = int(getattr(arpLayer, "op", 0))
    except Exception:
        opCode = 0
    opLabel = opMap.get(opCode, f"Opcode {opCode}")

    etherType = None
    if p.haslayer("Ether"):
        try:
            etherType = int(p["Ether"].type)
        except Exception:
            etherType = None

    isRarp = opCode in (3, 4) or etherType == 0x8035
    protocolName = "RARP" if isRarp else "ARP"

    srcIp = str(getattr(arpLayer, "psrc", "0.0.0.0") or "0.0.0.0")
    dstIp = str(getattr(arpLayer, "pdst", "0.0.0.0") or "0.0.0.0")
    srcMac = str(getattr(arpLayer, "hwsrc", "N/A") or "N/A")
    dstMac = str(getattr(arpLayer, "hwdst", "N/A") or "N/A")

    hwTypeVal = int(getattr(arpLayer, "hwtype", 0) or 0)
    protoTypeVal = int(getattr(arpLayer, "ptype", 0) or 0)
    hwSizeVal = int(getattr(arpLayer, "hwlen", 0) or 0)
    protoSizeVal = int(getattr(arpLayer, "plen", 0) or 0)

    section = {
        "Operation": opLabel,
        "arp.op": opLabel,
        "rarp.op": opLabel,
        "link.rarp": opLabel,
        "link.arp.op": opLabel,
        "Opcode": opCode,
        "arp.opcode": opCode,
        "rarp.opcode": opCode,
        "link.arp.opcode": opCode,
        "link.rarp.opcode": opCode,
        "Sender MAC": srcMac,
        "arp.src.mac": srcMac,
        "rarp.src.mac": srcMac,
        "link.arp.src.mac": srcMac,
        "link.rarp.src.mac": srcMac,
        "Target MAC": dstMac,
        "arp.dst.mac": dstMac,
        "rarp.dst.mac": dstMac,
        "link.arp.dst.mac": dstMac,
        "link.rarp.dst.mac": dstMac,
        "Sender IP": srcIp,
        "arp.src.ip": srcIp,
        "rarp.src.ip": srcIp,
        "link.arp.src.ip": srcIp,
        "link.rarp.src.ip": srcIp,
        "Target IP": dstIp,
        "arp.dst.ip": dstIp,
        "rarp.dst.ip": dstIp,
        "link.arp.dst.ip": dstIp,
        "link.rarp.dst.ip": dstIp,
        "Hardware Type": hwTypeVal,
        "arp.hw.type": hwTypeVal,
        "link.arp.hw.type": hwTypeVal,
        "rarp.hw.type": hwTypeVal,
        "link.rarp.hw.type": hwTypeVal,
        "Protocol Type": f"0x{protoTypeVal:04x}",
        "arp.proto.type": f"0x{protoTypeVal:04x}",
        "link.arp.proto.type": f"0x{protoTypeVal:04x}",
        "rarp.proto.type": f"0x{protoTypeVal:04x}",
        "link.rarp.proto.type": f"0x{protoTypeVal:04x}",
        "Hardware Size": hwSizeVal,
        "arp.hw.size": hwSizeVal,
        "link.arp.hw.size": hwSizeVal,
        "rarp.hw.size": hwSizeVal,
        "link.rarp.hw.size": hwSizeVal,
        "Protocol Size": protoSizeVal,
        "arp.proto.size": protoSizeVal,
        "link.arp.proto.size": protoSizeVal,
        "rarp.proto.size": protoSizeVal,
        "link.rarp.proto.size": protoSizeVal,
        "link.proto": "ARP" if not isRarp else "RARP",
    }

    return protocolName, section, srcIp, dstIp
