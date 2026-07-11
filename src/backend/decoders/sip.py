def decodeSIP(rawPayload):
    """
    Decode SIP message fields from raw payload bytes.
    Parses the first line and common headers (From, To, Call-ID, Authorization).
    Returns a dict with both display-friendly keys and dot-notation keys for message
    type, method/status, and headers, or None if the payload is not a SIP message or
    decoding fails.
    """
    sipMethods = {
        "INVITE",
        "ACK",
        "BYE",
        "CANCEL",
        "REGISTER",
        "OPTIONS",
        "SUBSCRIBE",
        "NOTIFY",
        "REFER",
        "INFO",
        "UPDATE",
        "PRACK",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
        if not lines:
            return None
        firstLine = lines[0].strip()
        isSipResponse = firstLine.startswith("SIP/")
        isSipRequest = (
            firstLine.split(" ")[0] in sipMethods if " " in firstLine else False
        )
        if not isSipResponse and not isSipRequest:
            return None
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                key, _, val = line.partition(": ")
                headers[key.strip()] = val.strip()

        authorization = headers.get("Authorization", "")
        proxyAuthorization = headers.get("Proxy-Authorization", "")

        if isSipRequest:
            parts = firstLine.split(" ", 2)
            method = parts[0]
            requestUri = parts[1] if len(parts) > 1 else "Unknown"
            result = {
                "Type": "Request",
                "sip.type": "Request",
                "Method": method,
                "sip.method": method,
                "Request URI": requestUri,
                "sip.uri": requestUri,
                "From": headers.get("From", "Unknown"),
                "sip.from": headers.get("From", "Unknown"),
                "To": headers.get("To", "Unknown"),
                "sip.to": headers.get("To", "Unknown"),
                "Call-ID": headers.get("Call-ID", "Unknown"),
                "sip.call_id": headers.get("Call-ID", "Unknown"),
            }
            if authorization:
                result["Authorization"] = authorization
                result["sip.authorization"] = authorization
            if proxyAuthorization:
                result["Proxy-Authorization"] = proxyAuthorization
                result["sip.proxy_authorization"] = proxyAuthorization
            return result
        else:
            parts = firstLine.split(" ", 2)
            statusCode = parts[1] if len(parts) > 1 else "Unknown"
            statusMsg = parts[2] if len(parts) > 2 else "Unknown"
            result = {
                "Type": "Response",
                "sip.type": "Response",
                "Status Code": statusCode,
                "sip.status_code": statusCode,
                "Status Message": statusMsg,
                "sip.status_msg": statusMsg,
                "From": headers.get("From", "Unknown"),
                "sip.from": headers.get("From", "Unknown"),
                "To": headers.get("To", "Unknown"),
                "sip.to": headers.get("To", "Unknown"),
                "Call-ID": headers.get("Call-ID", "Unknown"),
                "sip.call_id": headers.get("Call-ID", "Unknown"),
            }
            if authorization:
                result["Authorization"] = authorization
                result["sip.authorization"] = authorization
            if proxyAuthorization:
                result["Proxy-Authorization"] = proxyAuthorization
                result["sip.proxy_authorization"] = proxyAuthorization
            return result
    except Exception:
        return None
