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

    def getLayer(*names):
        for layerName in names:
            try:
                if p.haslayer(layerName):
                    return p[layerName]
            except Exception:
                continue
        return None

    def toInt(value):
        try:
            return int(value)
        except Exception:
            return None

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
    mark("PPPoE", hasLayerName("pppoe", "pppoes", "pppoed", "pppoe_session", "pppoe_discovery"))
    mark("PPP", hasLayerName("ppp", "pppoe", "pppoes", "pppoed"))
    mark("LCP", hasLayerName("lcp", "ppp_lcp"))
    mark("LAP", hasLayerName("lap", "lapb", "lapd"))
    mark("NCP", hasLayerName("ncp", "ipcp", "ipv6cp", "ppp_ncp"))
    mark("LLDP", hasLayerName("lldp", "lldpdu", "lldp_chassis_id", "lldp_port_id", "lldp_ttl"))

    pppProtocolHex = "N/A"
    pppProtocolName = "Unknown"
    if p.haslayer("PPP"):
        try:
            pppProtoVal = int(p["PPP"].proto)
            pppProtocolHex = f"0x{pppProtoVal:04x}"
            pppProtocolMap = {
                0x0021: "IPv4",
                0x0057: "IPv6",
                0x0281: "MPLS Unicast",
                0x0283: "MPLS Multicast",
                0x8021: "IPCP (NCP)",
                0x8057: "IPv6CP (NCP)",
                0x80FD: "CCP (NCP)",
                0x8053: "ECP (NCP)",
                0xC025: "LQR",
                0xC021: "LCP",
                0xC023: "PAP (LCP Auth)",
                0xC223: "CHAP (LCP Auth)",
                0xC227: "EAP (LCP Auth)",
            }
            pppProtocolName = pppProtocolMap.get(pppProtoVal, f"0x{pppProtoVal:04x}")
            if pppProtoVal in (0xC021, 0xC023, 0xC223):
                mark("LCP", True)
            if pppProtoVal in (0x8021, 0x8057, 0x80FD):
                mark("NCP", True)
        except Exception:
            pass

    pppoeLayer = getLayer(
        "PPPoE",
        "PPPoES",
        "PPPoED",
        "PPPoE_Session",
        "PPPoE_Discovery",
        "pppoe",
        "pppoes",
        "pppoed",
    )
    pppoeCodeText = "N/A"
    pppoeSessionId = "N/A"
    pppoeStage = "N/A"
    if pppoeLayer is not None:
        try:
            pppoeCodeVal = toInt(getattr(pppoeLayer, "code", None))
            pppoeCodeMap = {
                0x00: "Session",
                0x07: "PADO",
                0x09: "PADI",
                0x19: "PADR",
                0x65: "PADS",
                0xA7: "PADT",
            }
            if pppoeCodeVal is not None:
                pppoeCodeText = f"0x{pppoeCodeVal:02x} ({pppoeCodeMap.get(pppoeCodeVal, 'Unknown')})"
                if pppoeCodeVal == 0x00:
                    pppoeStage = "Session"
                else:
                    pppoeStage = "Discovery"
            pppoeSessionVal = toInt(getattr(pppoeLayer, "sessionid", None))
            if pppoeSessionVal is not None:
                pppoeSessionId = f"0x{pppoeSessionVal:04x}"
        except Exception:
            pass

    lldpLayer = getLayer("LLDP", "LLDPDU", "lldp", "lldpdu")
    lldpChassisId = "N/A"
    lldpPortId = "N/A"
    lldpTtl = "N/A"
    if lldpLayer is not None:
        try:
            chassisValue = getattr(lldpLayer, "chassisid", None)
            if chassisValue is None:
                chassisValue = getattr(lldpLayer, "chassis_id", None)
            if chassisValue is not None:
                lldpChassisId = str(chassisValue)

            portValue = getattr(lldpLayer, "portid", None)
            if portValue is None:
                portValue = getattr(lldpLayer, "port_id", None)
            if portValue is not None:
                lldpPortId = str(portValue)

            ttlValue = toInt(getattr(lldpLayer, "ttl", None))
            if ttlValue is not None:
                lldpTtl = ttlValue
        except Exception:
            pass

    etherLayer = getLayer("Ether", "ether")
    etherTypeVal = toInt(getattr(etherLayer, "type", None)) if etherLayer is not None else None
    if etherTypeVal == 0x88CC:
        mark("LLDP", True)

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

    if pppoeCodeText != "N/A":
        result["PPPoE Code"] = pppoeCodeText
        result["pppoe.code"] = pppoeCodeText
    if pppoeSessionId != "N/A":
        result["PPPoE Session ID"] = pppoeSessionId
        result["pppoe.session_id"] = pppoeSessionId
    if pppoeStage != "N/A":
        result["PPPoE Stage"] = pppoeStage
        result["pppoe.stage"] = pppoeStage

    if etherTypeVal is not None:
        result["EtherType"] = f"0x{etherTypeVal:04x}"
        result["ether.type"] = f"0x{etherTypeVal:04x}"

    if lldpChassisId != "N/A":
        result["LLDP Chassis ID"] = lldpChassisId
        result["lldp.chassis_id"] = lldpChassisId
    if lldpPortId != "N/A":
        result["LLDP Port ID"] = lldpPortId
        result["lldp.port_id"] = lldpPortId
    if lldpTtl != "N/A":
        result["LLDP TTL"] = lldpTtl
        result["lldp.ttl"] = lldpTtl

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
