import base64


def decodeSMTP(rawPayload):
    """
    Decode SMTP commands and responses from raw payload bytes.
    Returns a dict with Type (Command/Response), command/status code, and arguments/message,
    or None if the payload is not recognisable as SMTP traffic.
    """
    SMTP_COMMANDS = {
        "EHLO",
        "HELO",
        "MAIL",
        "RCPT",
        "DATA",
        "RSET",
        "VRFY",
        "EXPN",
        "HELP",
        "NOOP",
        "QUIT",
        "AUTH",
        "STARTTLS",
        "BDAT",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.replace("\r\n", "\n").split("\n")
        firstLine = lines[0].strip()
        if not firstLine:
            return None
        parts = firstLine.split(" ", 1)
        word = parts[0].upper()
        if word in SMTP_COMMANDS:
            arg = parts[1].strip() if len(parts) > 1 else ""
            result = {
                "Type": "Command",
                "smtp.type": "Command",
                "Command": word,
                "smtp.command": word,
                "Argument": arg,
                "smtp.argument": arg,
            }
            if word == "AUTH":
                argParts = arg.split()
                mechanism = argParts[0].upper() if argParts else ""
                creds = {}
                if mechanism == "PLAIN" and len(argParts) > 1:
                    try:
                        decoded = base64.b64decode(argParts[1]).decode(errors="replace")
                        segments = decoded.split("\x00")
                        segments = [s for s in segments if s]
                        if len(segments) >= 2:
                            creds["username"] = segments[0]
                            creds["password"] = segments[1]
                        elif len(segments) == 1:
                            creds["username"] = segments[0]
                    except Exception:
                        pass
                elif mechanism == "LOGIN":
                    if len(argParts) > 1:
                        try:
                            creds["username"] = base64.b64decode(argParts[1]).decode(
                                errors="replace"
                            )
                        except Exception:
                            pass
                    for extraLine in lines[1:]:
                        extraLine = extraLine.strip()
                        if extraLine:
                            try:
                                creds["password"] = base64.b64decode(extraLine).decode(
                                    errors="replace"
                                )
                            except Exception:
                                pass
                            break
                if len(argParts) > 1:
                    result["Argument"] = mechanism + " ***"
                    result["smtp.argument"] = mechanism + " ***"
                if creds:
                    result["Credentials"] = creds
            return result
        if len(word) == 3 and word.isdigit():
            statusCode = word
            message = parts[1].strip() if len(parts) > 1 else ""
            return {
                "Type": "Response",
                "smtp.type": "Response",
                "Status Code": statusCode,
                "smtp.status_code": statusCode,
                "Message": message,
                "smtp.message": message,
            }
        return None
    except Exception:
        return None
