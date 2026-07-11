def decodeFTP(rawPayload):
    """
    Decode FTP commands and responses from raw payload bytes.
    Returns a dict with Type (Command/Response), command/status, and argument/message,
    or None if the payload is not recognisable as FTP traffic.
    """
    FTP_COMMANDS = {
        "USER",
        "PASS",
        "ACCT",
        "CWD",
        "CDUP",
        "SMNT",
        "QUIT",
        "REIN",
        "PORT",
        "PASV",
        "TYPE",
        "STRU",
        "MODE",
        "RETR",
        "STOR",
        "STOU",
        "APPE",
        "ALLO",
        "REST",
        "RNFR",
        "RNTO",
        "ABOR",
        "DELE",
        "RMD",
        "MKD",
        "PWD",
        "LIST",
        "NLST",
        "SITE",
        "SYST",
        "STAT",
        "HELP",
        "NOOP",
        "FEAT",
        "OPTS",
        "MLST",
        "MLSD",
        "SIZE",
        "MDTM",
        "EPRT",
        "EPSV",
        "AUTH",
        "PBSZ",
        "PROT",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.replace("\r\n", "\n").split("\n")
        firstLine = lines[0].strip()
        if not firstLine:
            return None
        parts = firstLine.split(" ", 1)
        word = parts[0].upper()
        if word in FTP_COMMANDS:
            arg = parts[1].strip() if len(parts) > 1 else ""
            result = {
                "Type": "Command",
                "ftp.type": "Command",
                "Command": word,
                "ftp.command": word,
                "Argument": arg,
                "ftp.argument": arg,
            }
            if word == "USER" and arg:
                result["Credentials"] = {"username": arg}
            elif word == "PASS" and arg:
                result["Credentials"] = {"password": arg}
                result["Argument"] = "***"
                result["ftp.argument"] = "***"
            return result
        if len(word) == 3 and word.isdigit():
            statusCode = word
            message = parts[1].strip() if len(parts) > 1 else ""
            return {
                "Type": "Response",
                "ftp.type": "Response",
                "Status Code": statusCode,
                "ftp.status_code": statusCode,
                "Message": message,
                "ftp.message": message,
            }
        return None
    except Exception:
        return None
