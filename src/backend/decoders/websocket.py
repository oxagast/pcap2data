def decodeWebSocket(rawPayload):
    """
    Decode WebSocket upgrade packets and frames.
    """
    WS_OPCODES = {
        0x0: "Continuation",
        0x1: "Text",
        0x2: "Binary",
        0x8: "Close",
        0x9: "Ping",
        0xA: "Pong",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        if "Upgrade: websocket" in text or "upgrade: websocket" in text.lower():
            normalised = text.replace("\r\n", "\n")
            lines = normalised.split("\n\n")[0].split("\n")
            headers = {}
            for line in lines[1:]:
                if ": " in line:
                    k, _, v = line.partition(": ")
                    headers[k.strip().lower()] = v.strip()
            return {
                "Type": "Upgrade",
                "ws.type": "Upgrade",
                "Upgrade": headers.get("upgrade", "websocket"),
                "ws.upgrade": headers.get("upgrade", "websocket"),
                "Host": headers.get("host", "Unknown"),
                "ws.host": headers.get("host", "Unknown"),
                "Sec-WebSocket-Key": headers.get("sec-websocket-key", "Unknown"),
                "ws.key": headers.get("sec-websocket-key", "Unknown"),
                "Sec-WebSocket-Version": headers.get("sec-websocket-version", "Unknown"),
                "ws.version": headers.get("sec-websocket-version", "Unknown"),
            }
        if len(rawPayload) < 2:
            return None
        firstByte = rawPayload[0]
        secondByte = rawPayload[1]
        fin = bool(firstByte & 0x80)
        rsv1 = bool(firstByte & 0x40)
        rsv2 = bool(firstByte & 0x20)
        rsv3 = bool(firstByte & 0x10)
        opcode = firstByte & 0x0F
        if (rsv1 or rsv2 or rsv3) and opcode not in WS_OPCODES:
            return None
        if opcode not in WS_OPCODES:
            return None
        masked = bool(secondByte & 0x80)
        payloadLen = secondByte & 0x7F
        opcodeName = WS_OPCODES[opcode]
        if payloadLen == 126:
            if len(rawPayload) < 4:
                return None
            import struct
            payloadLen = struct.unpack_from(">H", rawPayload, 2)[0]
        elif payloadLen == 127:
            if len(rawPayload) < 10:
                return None
            import struct
            payloadLen = struct.unpack_from(">Q", rawPayload, 2)[0]
        return {
            "Type": "Frame",
            "ws.type": "Frame",
            "Opcode": opcodeName,
            "ws.opcode": opcodeName,
            "FIN": fin,
            "ws.fin": fin,
            "Masked": masked,
            "ws.masked": masked,
            "ws.payload_len": payloadLen,
        }
    except Exception:
        return None
