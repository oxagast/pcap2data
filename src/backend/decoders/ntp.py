def decodeNTP(p):
    """
    Decode NTP layer fields from a scapy packet.
    Returns a dict with both display-friendly keys and dot-notation keys for leap
    indicator, version, mode, stratum, and reference ID, or None if the packet does
    not contain an NTP layer or decoding fails.
    """
    if not p.haslayer("NTP"):
        return None
    ntpLayer = p["NTP"]
    modeMap = {
        0: "Reserved",
        1: "Symmetric Active",
        2: "Symmetric Passive",
        3: "Client",
        4: "Server",
        5: "Broadcast",
        6: "NTP Control",
        7: "Private",
    }
    try:
        leap = int(ntpLayer.leap) if hasattr(ntpLayer, "leap") else 0
        version = int(ntpLayer.version) if hasattr(ntpLayer, "version") else 0
        mode = int(ntpLayer.mode) if hasattr(ntpLayer, "mode") else 0
        stratum = int(ntpLayer.stratum) if hasattr(ntpLayer, "stratum") else 0
        modeStr = modeMap.get(mode, f"Unknown({mode})")
        refId = str(ntpLayer.id) if hasattr(ntpLayer, "id") else "N/A"
        return {
            "Leap Indicator": leap,
            "ntp.leap": leap,
            "Version": version,
            "ntp.version": version,
            "Mode": modeStr,
            "ntp.mode": modeStr,
            "Stratum": stratum,
            "ntp.stratum": stratum,
            "Reference ID": refId,
            "ntp.ref_id": refId,
        }
    except Exception:
        return None
