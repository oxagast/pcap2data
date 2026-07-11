def decodeBGP(rawPayload):
    """
    Decode BGP messages from raw payload bytes.
    """
    import struct

    BGP_TYPES = {
        1: "OPEN",
        2: "UPDATE",
        3: "NOTIFICATION",
        4: "KEEPALIVE",
        5: "ROUTE-REFRESH",
    }
    BGP_ERRORS = {
        1: "Message Header Error",
        2: "OPEN Message Error",
        3: "UPDATE Message Error",
        4: "Hold Timer Expired",
        5: "Finite State Machine Error",
        6: "Cease",
    }
    try:
        if len(rawPayload) < 19:
            return None
        if rawPayload[:16] != b"\xff" * 16:
            return None
        msgLen = struct.unpack_from(">H", rawPayload, 16)[0]
        msgType = rawPayload[18]
        typeName = BGP_TYPES.get(msgType, f"Unknown({msgType})")
        result = {
            "Message Type": typeName,
            "bgp.type": typeName,
            "Message Length": msgLen,
            "bgp.length": msgLen,
        }
        if msgType == 1 and len(rawPayload) >= 29:
            version = rawPayload[19]
            asn = struct.unpack_from(">H", rawPayload, 20)[0]
            holdTime = struct.unpack_from(">H", rawPayload, 22)[0]
            routerId = ".".join(str(b) for b in rawPayload[24:28])
            result["BGP Version"] = version
            result["bgp.version"] = version
            result["ASN"] = asn
            result["bgp.asn"] = asn
            result["Hold Time"] = holdTime
            result["bgp.hold_time"] = holdTime
            result["Router ID"] = routerId
            result["bgp.router_id"] = routerId
        if msgType == 3 and len(rawPayload) >= 21:
            errCode = rawPayload[19]
            errSubcode = rawPayload[20]
            errName = BGP_ERRORS.get(errCode, f"Error {errCode}")
            result["Error Code"] = errCode
            result["bgp.error_code"] = errCode
            result["Error Name"] = errName
            result["bgp.error_name"] = errName
            result["Error Subcode"] = errSubcode
            result["bgp.error_subcode"] = errSubcode
        return result
    except Exception:
        return None
