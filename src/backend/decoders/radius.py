def decodeRADIUS(rawPayload):
    """
    Decode RADIUS packets from raw payload bytes.
    """
    import struct

    RADIUS_CODES = {
        1: "Access-Request",
        2: "Access-Accept",
        3: "Access-Reject",
        4: "Accounting-Request",
        5: "Accounting-Response",
        11: "Access-Challenge",
        12: "Status-Server",
        13: "Status-Client",
        255: "Reserved",
    }
    RADIUS_ATTRIBUTES = {
        1: "User-Name",
        2: "User-Password",
        3: "CHAP-Password",
        4: "NAS-IP-Address",
        5: "NAS-Port",
        6: "Service-Type",
        7: "Framed-Protocol",
        8: "Framed-IP-Address",
        18: "Reply-Message",
        24: "State",
        25: "Class",
        26: "Vendor-Specific",
        27: "Session-Timeout",
        28: "Idle-Timeout",
        30: "Called-Station-Id",
        31: "Calling-Station-Id",
        32: "NAS-Identifier",
        40: "Acct-Status-Type",
        41: "Acct-Delay-Time",
        42: "Acct-Input-Octets",
        43: "Acct-Output-Octets",
        44: "Acct-Session-Id",
        61: "NAS-Port-Type",
        77: "Connect-Info",
        79: "EAP-Message",
        80: "Message-Authenticator",
    }
    try:
        if len(rawPayload) < 20:
            return None
        code = rawPayload[0]
        identifier = rawPayload[1]
        length = struct.unpack_from(">H", rawPayload, 2)[0]
        if length < 20 or length > len(rawPayload):
            return None
        codeName = RADIUS_CODES.get(code, f"Unknown({code})")
        attributes = []
        idx = 20
        while idx + 2 <= length and idx + 2 <= len(rawPayload):
            attrType = rawPayload[idx]
            attrLen = rawPayload[idx + 1]
            if attrLen < 2:
                break
            attrValue = rawPayload[idx + 2 : idx + attrLen]
            attrName = RADIUS_ATTRIBUTES.get(attrType, f"Attr-{attrType}")
            if attrType == 1:
                attrValueStr = attrValue.decode(errors="ignore")
            elif attrType in (4, 8):
                attrValueStr = (
                    ".".join(str(b) for b in attrValue)
                    if len(attrValue) == 4
                    else attrValue.hex()
                )
            elif attrType in (2, 3):
                attrValueStr = "***"
            else:
                attrValueStr = (
                    attrValue.decode(errors="ignore")
                    if all(32 <= b <= 126 for b in attrValue)
                    else attrValue.hex()
                )
            attributes.append({"Type": attrName, "Value": attrValueStr})
            idx += attrLen
        return {
            "Code": codeName,
            "radius.code": codeName,
            "Identifier": identifier,
            "radius.id": identifier,
            "Length": length,
            "radius.length": length,
            "Attributes": attributes,
            "radius.attrs": attributes,
        }
    except Exception:
        return None
