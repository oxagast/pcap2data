def decodeLDAP(rawPayload):
    """
    Decode basic LDAP message fields from raw payload bytes using ASN.1 BER structure.
    Extracts message ID and operation type from the outer SEQUENCE.
    Returns a dict with message ID and operation, or None if the payload does not look like LDAP.
    """
    LDAP_OPERATIONS = {
        0x60: "BindRequest",
        0x61: "BindResponse",
        0x62: "UnbindRequest",
        0x63: "SearchRequest",
        0x64: "SearchResEntry",
        0x65: "SearchResDone",
        0x66: "SearchResRef",
        0x67: "ModifyRequest",
        0x68: "ModifyResponse",
        0x69: "AddRequest",
        0x6A: "AddResponse",
        0x6B: "DelRequest",
        0x6C: "DelResponse",
        0x6D: "ModDNRequest",
        0x6E: "ModDNResponse",
        0x6F: "CompareRequest",
        0x70: "CompareResponse",
        0x77: "ExtendedRequest",
        0x78: "ExtendedResponse",
        0x79: "IntermediateResponse",
    }
    try:
        if len(rawPayload) < 4:
            return None
        if rawPayload[0] != 0x30:
            return None
        idx = 1
        if rawPayload[idx] & 0x80:
            numBytes = rawPayload[idx] & 0x7F
            idx += 1 + numBytes
        else:
            idx += 1
        if idx >= len(rawPayload) or rawPayload[idx] != 0x02:
            return None
        idxLen = rawPayload[idx + 1]
        msgId = int.from_bytes(rawPayload[idx + 2 : idx + 2 + idxLen], "big")
        idx += 2 + idxLen
        if idx >= len(rawPayload):
            return None
        opTag = rawPayload[idx]
        opName = LDAP_OPERATIONS.get(opTag, f"0x{opTag:02X}")
        return {
            "Message ID": msgId,
            "ldap.msg_id": msgId,
            "Operation": opName,
            "ldap.operation": opName,
        }
    except Exception:
        return None
