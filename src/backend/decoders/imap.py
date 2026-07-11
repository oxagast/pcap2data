def decodeIMAP(rawPayload):
    """
    Decode IMAP commands and server responses from raw payload bytes.
    Returns a dict with Type (Command/Response/Untagged), tag, command/status, and argument,
    or None if the payload is not recognisable as IMAP traffic.
    """
    IMAP_COMMANDS = {
        "CAPABILITY",
        "NOOP",
        "LOGOUT",
        "AUTHENTICATE",
        "LOGIN",
        "SELECT",
        "EXAMINE",
        "CREATE",
        "DELETE",
        "RENAME",
        "SUBSCRIBE",
        "UNSUBSCRIBE",
        "LIST",
        "LSUB",
        "STATUS",
        "APPEND",
        "CHECK",
        "CLOSE",
        "EXPUNGE",
        "SEARCH",
        "FETCH",
        "STORE",
        "COPY",
        "UID",
        "IDLE",
        "NAMESPACE",
        "STARTTLS",
        "ENABLE",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.replace("\r\n", "\n").split("\n")
        firstLine = lines[0].strip()
        if not firstLine:
            return None
        if firstLine.startswith("* "):
            rest = firstLine[2:].strip()
            restParts = rest.split(" ", 1)
            status = restParts[0]
            info = restParts[1].strip() if len(restParts) > 1 else ""
            return {
                "Type": "Untagged",
                "imap.type": "Untagged",
                "Status": status,
                "imap.status": status,
                "Info": info,
                "imap.info": info,
            }
        parts = firstLine.split(" ", 2)
        if len(parts) >= 2:
            tag = parts[0]
            word = parts[1].upper()
            arg = parts[2].strip() if len(parts) > 2 else ""
            if word in IMAP_COMMANDS:
                result = {
                    "Type": "Command",
                    "imap.type": "Command",
                    "Tag": tag,
                    "imap.tag": tag,
                    "Command": word,
                    "imap.command": word,
                    "Argument": arg,
                    "imap.argument": arg,
                }
                if word == "LOGIN" and arg:
                    argParts = arg.split(" ", 1)
                    username = argParts[0].strip('"')
                    if len(argParts) > 1:
                        password = argParts[1].strip('"')
                        result["Credentials"] = {
                            "username": username,
                            "password": password,
                        }
                        result["Argument"] = username + " ***"
                        result["imap.argument"] = username + " ***"
                    else:
                        result["Credentials"] = {"username": username}
                return result
            if word in ("OK", "NO", "BAD", "PREAUTH", "BYE"):
                return {
                    "Type": "Response",
                    "imap.type": "Response",
                    "Tag": tag,
                    "imap.tag": tag,
                    "Status": word,
                    "imap.status": word,
                    "Message": arg,
                    "imap.message": arg,
                }
        return None
    except Exception:
        return None
