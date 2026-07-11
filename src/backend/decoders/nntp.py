def decodeNNTP(rawPayload):
    """
    Decode NNTP commands and responses.
    """
    NNTP_COMMANDS = {
        "ARTICLE",
        "BODY",
        "DATE",
        "GROUP",
        "HDR",
        "HEAD",
        "HELP",
        "IHAVE",
        "LAST",
        "LIST",
        "LISTGROUP",
        "MODE",
        "NEWGROUPS",
        "NEWNEWS",
        "NEXT",
        "OVER",
        "POST",
        "QUIT",
        "READER",
        "STAT",
        "AUTHINFO",
        "COMPRESS",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.replace("\r\n", "\n").split("\n")
        firstLine = lines[0].strip()
        if not firstLine:
            return None
        parts = firstLine.split(" ", 1)
        word = parts[0].upper()
        if word in NNTP_COMMANDS:
            arg = parts[1].strip() if len(parts) > 1 else ""
            return {
                "Type": "Command",
                "nntp.type": "Command",
                "Command": word,
                "nntp.command": word,
                "Argument": arg,
                "nntp.argument": arg,
            }
        if len(word) == 3 and word.isdigit():
            message = parts[1].strip() if len(parts) > 1 else ""
            return {
                "Type": "Response",
                "nntp.type": "Response",
                "Status Code": word,
                "nntp.status_code": word,
                "Message": message,
                "nntp.message": message,
            }
        return None
    except Exception:
        return None
