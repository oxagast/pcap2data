HTTP2_PREFACE_BYTES = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def decodeHTTP2(rawPayload):
    """
    Decode HTTP/2 frames from raw payload bytes.
    """
    import struct

    HTTP2_FRAME_TYPES = {
        0x0: "DATA",
        0x1: "HEADERS",
        0x2: "PRIORITY",
        0x3: "RST_STREAM",
        0x4: "SETTINGS",
        0x5: "PUSH_PROMISE",
        0x6: "PING",
        0x7: "GOAWAY",
        0x8: "WINDOW_UPDATE",
        0x9: "CONTINUATION",
    }
    try:
        if len(rawPayload) < 9:
            return None
        hasPreface = rawPayload.startswith(HTTP2_PREFACE_BYTES)
        offset = len(HTTP2_PREFACE_BYTES) if hasPreface else 0
        if offset + 9 > len(rawPayload):
            if hasPreface:
                return {
                    "Connection Preface": True,
                    "http2.preface": True,
                    "Frame Type": "N/A",
                    "http2.frame_type": "N/A",
                }
            return None
        frameLen = struct.unpack_from(">I", b"\x00" + rawPayload[offset : offset + 3])[0]
        frameType = rawPayload[offset + 3]
        frameFlags = rawPayload[offset + 4]
        streamId = struct.unpack_from(">I", rawPayload, offset + 5)[0] & 0x7FFFFFFF
        if frameLen > 16384:
            return None
        if frameType in (0x4, 0x6, 0x7) and streamId != 0:
            return None
        if frameType in (0x0, 0x1, 0x5, 0x9) and streamId == 0:
            return None
        typeName = HTTP2_FRAME_TYPES.get(frameType, f"0x{frameType:02X}")
        return {
            "Connection Preface": hasPreface,
            "http2.preface": hasPreface,
            "Frame Type": typeName,
            "http2.frame_type": typeName,
            "Frame Length": frameLen,
            "http2.frame_length": frameLen,
            "Frame Flags": f"0x{frameFlags:02X}",
            "http2.frame_flags": f"0x{frameFlags:02X}",
            "Stream ID": streamId,
            "http2.stream_id": streamId,
        }
    except Exception:
        return None
