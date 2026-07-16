def _to_text_preview(data, max_len=96):
    if not data:
        return ""
    text = data.decode(errors="ignore").replace("\x00", "").strip()
    if not text:
        return ""
    return text[:max_len] + ("..." if len(text) > max_len else "")


def decodeSoulseek(rawPayload):
    """
    Decode Soulseek length-prefixed message envelopes.
    """

    try:
        if len(rawPayload) < 8:
            return None

        messageLength = int.from_bytes(rawPayload[0:4], "little", signed=False)
        messageCode = int.from_bytes(rawPayload[4:8], "little", signed=False)
        totalFrameLength = messageLength + 4

        if messageLength < 4 or totalFrameLength > len(rawPayload):
            return None

        if messageCode > 0x0000FFFF:
            return None

        body = rawPayload[8:totalFrameLength]
        preview = _to_text_preview(body)

        result = {
            "Message Length": int(messageLength),
            "soulseek.length": int(messageLength),
            "Message Code": int(messageCode),
            "soulseek.code": int(messageCode),
            "Message Code Hex": f"0x{messageCode:04X}",
            "soulseek.code_hex": f"0x{messageCode:04X}",
            "Body Length": int(len(body)),
            "soulseek.body_length": int(len(body)),
        }
        if preview:
            result["Payload Preview"] = preview
            result["soulseek.preview"] = preview
        return result
    except Exception:
        return None
