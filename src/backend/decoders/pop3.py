def decodePOP3(rawPayload):
    """
    Decode POP3 commands and responses from raw payload bytes.
    Returns a dict with Type (Command/Response), command/status, and argument/message,
    or None if the payload is not recognisable as POP3 traffic.
    """
    POP3_COMMANDS = {
        "USER",
        "PASS",
        "APOP",
        "QUIT",
        "STAT",
        "LIST",
        "RETR",
        "DELE",
        "NOOP",
        "RSET",
        "TOP",
        "UIDL",
        "CAPA",
        "AUTH",
        "STLS",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.replace("\r\n", "\n").split("\n")
        firstLine = lines[0].strip()
        if not firstLine:
            return None
        parts = firstLine.split(" ", 1)
        word = parts[0].upper()
        if word in POP3_COMMANDS:
            arg = parts[1].strip() if len(parts) > 1 else ""
            result = {
                "Type": "Command",
                "pop3.type": "Command",
                "Command": word,
                "pop3.command": word,
                "Argument": arg,
                "pop3.argument": arg,
            }
            if word == "USER" and arg:
                result["Credentials"] = {"username": arg}
            elif word == "PASS" and arg:
                result["Credentials"] = {"password": arg}
                result["Argument"] = "***"
                result["pop3.argument"] = "***"
            return result
        if word in ("+OK", "-ERR"):
            message = parts[1].strip() if len(parts) > 1 else ""
            return {
                "Type": "Response",
                "pop3.type": "Response",
                "Status": word,
                "pop3.status": word,
                "Message": message,
                "pop3.message": message,
            }
        return None
    except Exception:
        return None
