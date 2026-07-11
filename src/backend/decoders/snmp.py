def decodeSNMP(p):
    """
    Decode SNMP layer fields from a scapy packet.
    Returns a dict with both display-friendly keys (e.g., 'Version') and
    dot-notation keys (e.g., 'snmp.version') for version, community, and PDU type,
    or None if the packet does not contain an SNMP layer or decoding fails.
    """
    if not p.haslayer("SNMP"):
        return None
    snmpLayer = p["SNMP"]
    try:
        version = int(snmpLayer.version)
        versionMap = {0: "SNMPv1", 1: "SNMPv2c", 3: "SNMPv3"}
        versionStr = versionMap.get(version, f"Unknown({version})")
        community = ""
        if hasattr(snmpLayer, "community") and snmpLayer.community is not None:
            community = (
                snmpLayer.community.decode(errors="ignore")
                if isinstance(snmpLayer.community, bytes)
                else str(snmpLayer.community)
            )
        pduType = "Unknown"
        if hasattr(snmpLayer, "PDU") and snmpLayer.PDU is not None:
            pduType = snmpLayer.PDU.__class__.__name__
        return {
            "Version": versionStr,
            "snmp.version": versionStr,
            "Community": community,
            "snmp.community": community,
            "PDU Type": pduType,
            "snmp.pdu_type": pduType,
        }
    except Exception:
        return None
