def decodeDHCP(p):
    """
    Decode DHCP/BOOTP layer fields from a scapy packet.
    Returns a dict with both display-friendly keys and dot-notation keys for message
    type, transaction ID, and IP fields (Client IP, Your IP, Server IP), or None if
    the packet does not contain a DHCP layer or decoding fails.
    """
    if not p.haslayer("DHCP"):
        return None
    dhcpLayer = p["DHCP"]
    bootpLayer = p["BOOTP"] if p.haslayer("BOOTP") else None
    try:
        msgType = "Unknown"
        msgTypeMap = {
            1: "Discover",
            2: "Offer",
            3: "Request",
            4: "Decline",
            5: "ACK",
            6: "NAK",
            7: "Release",
            8: "Inform",
        }
        for opt in dhcpLayer.options:
            if isinstance(opt, tuple) and opt[0] == "message-type" and len(opt) > 1:
                msgType = msgTypeMap.get(opt[1], str(opt[1]))
                break
        result = {
            "Message Type": msgType,
            "dhcp.msg_type": msgType,
        }
        if bootpLayer:
            try:
                xid = hex(int(bootpLayer.xid)) if hasattr(bootpLayer, "xid") else "N/A"
            except (TypeError, ValueError):
                xid = "N/A"
            ciaddr = str(bootpLayer.ciaddr) if hasattr(bootpLayer, "ciaddr") else "N/A"
            yiaddr = str(bootpLayer.yiaddr) if hasattr(bootpLayer, "yiaddr") else "N/A"
            siaddr = str(bootpLayer.siaddr) if hasattr(bootpLayer, "siaddr") else "N/A"
            result["Transaction ID"] = xid
            result["dhcp.xid"] = xid
            result["Client IP"] = ciaddr
            result["dhcp.ciaddr"] = ciaddr
            result["Your IP"] = yiaddr
            result["dhcp.yiaddr"] = yiaddr
            result["Server IP"] = siaddr
            result["dhcp.siaddr"] = siaddr
        return result
    except Exception:
        return None
