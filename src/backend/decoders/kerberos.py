def decodeKerberos(rawPayload):
    """
    Decode Kerberos 5 messages from raw payload bytes.
    """
    KRB5_MSG_TYPES = {
        0x6A: "AS-REQ",
        0x6B: "AS-REP",
        0x6C: "TGS-REQ",
        0x6D: "TGS-REP",
        0x6E: "AP-REQ",
        0x6F: "AP-REP",
        0x74: "KRB-ERROR",
        0x79: "KRB-PRIV",
        0x7A: "KRB-CRED",
    }
    try:
        payload = rawPayload
        if len(payload) < 2:
            return None
        import struct
        if len(payload) >= 4:
            tcpLen = struct.unpack_from(">I", payload, 0)[0]
            if tcpLen + 4 == len(payload) and tcpLen > 0:
                payload = payload[4:]
        if len(payload) < 2:
            return None
        tag = payload[0]
        if tag not in KRB5_MSG_TYPES:
            return None
        msgTypeName = KRB5_MSG_TYPES[tag]
        result = {
            "Message Type": msgTypeName,
            "krb5.msg_type": msgTypeName,
        }
        try:
            idx = 1
            if payload[idx] & 0x80:
                numBytes = payload[idx] & 0x7F
                idx += 1 + numBytes
            else:
                idx += 1
            if idx < len(payload) and payload[idx] == 0x30:
                idx += 1
                if payload[idx] & 0x80:
                    numBytes = payload[idx] & 0x7F
                    idx += 1 + numBytes
                else:
                    idx += 1
                if idx < len(payload) and payload[idx] == 0xA0:
                    idx += 1
                    if payload[idx] & 0x80:
                        numBytes = payload[idx] & 0x7F
                        idx += 1 + numBytes
                    else:
                        idx += 1
                    if idx + 2 < len(payload) and payload[idx] == 0x02:
                        pvnoLen = payload[idx + 1]
                        pvno = int.from_bytes(payload[idx + 2: idx + 2 + pvnoLen], "big")
                        result["Protocol Version"] = pvno
                        result["krb5.pvno"] = pvno
        except Exception:
            pass
        return result
    except Exception:
        return None
