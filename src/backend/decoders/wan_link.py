def decodeWanLinkProtocols(p):
    """
    Detect and decode WAN/link-control protocols from available scapy layers.
    """
    try:
        layerNames = [
            getattr(layer, "__name__", str(layer)).lower() for layer in p.layers()
        ]
    except Exception:
        layerNames = []

    if not layerNames:
        return None

    def hasLayerName(*names):
        return any(
            layerName == name or layerName.startswith(name + "_")
            for layerName in layerNames
            for name in names
        )

    detectedProtocols = []

    def mark(protoName, present):
        if present and protoName not in detectedProtocols:
            detectedProtocols.append(protoName)

    mark("ATM", hasLayerName("atm", "atmad", "atmmeta"))
    mark("ATM", hasLayerName("clip", "aal5", "pppoatm", "pppoa"))
    mark("Token Ring", hasLayerName("tokenring", "dot5"))
    mark("Frame Relay", hasLayerName("framerelay", "frame_relay"))
    mark("SDLC", hasLayerName("sdlc"))
    mark("HDLC", hasLayerName("hdlc"))
    mark("SLIP", hasLayerName("slip"))
    mark("PPP", hasLayerName("ppp", "pppoe"))
    mark("LCP", hasLayerName("lcp", "ppp_lcp"))
    mark("LAP", hasLayerName("lap", "lapb", "lapd"))
    mark("NCP", hasLayerName("ncp", "ipcp", "ipv6cp", "ppp_ncp"))

    pppProtocolHex = "N/A"
    pppProtocolName = "Unknown"
    if p.haslayer("PPP"):
        try:
            pppProtoVal = int(p["PPP"].proto)
            pppProtocolHex = f"0x{pppProtoVal:04x}"
            pppProtocolMap = {
                0x0021: "IPv4",
                0x0057: "IPv6",
                0x8021: "IPCP (NCP)",
                0x8057: "IPv6CP (NCP)",
                0x80FD: "CCP (NCP)",
                0xC021: "LCP",
                0xC023: "PAP (LCP Auth)",
                0xC223: "CHAP (LCP Auth)",
            }
            pppProtocolName = pppProtocolMap.get(pppProtoVal, f"0x{pppProtoVal:04x}")
            if pppProtoVal in (0xC021, 0xC023, 0xC223):
                mark("LCP", True)
            if pppProtoVal in (0x8021, 0x8057, 0x80FD):
                mark("NCP", True)
        except Exception:
            pass

    if not detectedProtocols:
        return None

    result = {
        "Detected Protocols": detectedProtocols,
        "wan.detected": detectedProtocols,
        "Layer Names": layerNames,
        "wan.layers": layerNames,
        "Primary WAN Protocol": detectedProtocols[0],
        "wan.primary": detectedProtocols[0],
        "link.proto": detectedProtocols[0].lower().replace(" ", "_"),
    }

    if pppProtocolHex != "N/A":
        result["PPP Protocol Field"] = f"{pppProtocolHex} ({pppProtocolName})"
        result["ppp.proto_field"] = f"{pppProtocolHex} ({pppProtocolName})"

    if hasLayerName("clip"):
        result["ATM Encapsulation"] = "Classical IP over ATM (CLIP)"
        result["atm.encapsulation"] = "Classical IP over ATM (CLIP)"
    elif hasLayerName("pppoatm", "pppoa"):
        result["ATM Encapsulation"] = "PPP over ATM (PPPoA)"
        result["atm.encapsulation"] = "PPP over ATM (PPPoA)"
    elif hasLayerName("aal5"):
        result["ATM Encapsulation"] = "ATM AAL5"
        result["atm.encapsulation"] = "ATM AAL5"

    for proto in detectedProtocols:
        protoKey = proto.lower().replace(" ", "_")
        result[f"wan.proto.{protoKey}"] = proto

    return result
