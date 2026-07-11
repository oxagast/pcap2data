def decodeRTSP(rawPayload):
    """
    Decode RTSP requests and responses.
    """
    RTSP_METHODS = {
        "OPTIONS",
        "DESCRIBE",
        "ANNOUNCE",
        "SETUP",
        "PLAY",
        "PAUSE",
        "RECORD",
        "TEARDOWN",
        "GET_PARAMETER",
        "SET_PARAMETER",
        "REDIRECT",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        normalised = text.replace("\r\n", "\n")
        headerSection = normalised.split("\n\n")[0]
        lines = headerSection.split("\n")
        if not lines:
            return None
        firstLine = lines[0].strip()
        isRtspResponse = firstLine.startswith("RTSP/")
        isRtspRequest = (
            firstLine.split(" ")[0].upper() in RTSP_METHODS
            if " " in firstLine
            else False
        )
        if not isRtspResponse and not isRtspRequest:
            return None
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                key, _, val = line.partition(": ")
                headers[key.strip().lower()] = val.strip()
        if isRtspRequest:
            parts = firstLine.split(" ", 2)
            method = parts[0].upper()
            url = parts[1] if len(parts) > 1 else "Unknown"
            rtspVersion = parts[2] if len(parts) > 2 else "Unknown"
            return {
                "Type": "Request",
                "rtsp.type": "Request",
                "Method": method,
                "rtsp.method": method,
                "URL": url,
                "rtsp.url": url,
                "RTSP Version": rtspVersion,
                "rtsp.version": rtspVersion,
                "CSeq": headers.get("cseq", "Unknown"),
                "rtsp.cseq": headers.get("cseq", "Unknown"),
                "Session": headers.get("session", "Unknown"),
                "rtsp.session": headers.get("session", "Unknown"),
                "Transport": headers.get("transport", "Unknown"),
                "rtsp.transport": headers.get("transport", "Unknown"),
            }
        parts = firstLine.split(" ", 2)
        rtspVersion = parts[0]
        statusCode = parts[1] if len(parts) > 1 else "Unknown"
        statusMsg = parts[2] if len(parts) > 2 else "Unknown"
        return {
            "Type": "Response",
            "rtsp.type": "Response",
            "RTSP Version": rtspVersion,
            "rtsp.version": rtspVersion,
            "Status Code": statusCode,
            "rtsp.status_code": statusCode,
            "Status Message": statusMsg,
            "rtsp.status_msg": statusMsg,
            "CSeq": headers.get("cseq", "Unknown"),
            "rtsp.cseq": headers.get("cseq", "Unknown"),
            "Session": headers.get("session", "Unknown"),
            "rtsp.session": headers.get("session", "Unknown"),
            "Content-Type": headers.get("content-type", "Unknown"),
            "rtsp.content_type": headers.get("content-type", "Unknown"),
            "Content-Length": headers.get("content-length", "Unknown"),
            "rtsp.content_length": headers.get("content-length", "Unknown"),
        }
    except Exception:
        return None
