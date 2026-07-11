def decodeIRC(rawPayload):
    """
    Decode IRC protocol messages from raw payload bytes.
    Parses prefix, command, and parameters per RFC 1459.
    Returns a dict with the IRC command and parameters, or None if not recognisable.
    """
    IRC_COMMANDS = {
        "NICK",
        "USER",
        "JOIN",
        "PART",
        "PRIVMSG",
        "NOTICE",
        "QUIT",
        "PING",
        "PONG",
        "MODE",
        "TOPIC",
        "NAMES",
        "LIST",
        "INVITE",
        "KICK",
        "WHOIS",
        "WHO",
        "WHOWAS",
        "MOTD",
        "LUSERS",
        "VERSION",
        "STATS",
        "LINKS",
        "TIME",
        "CONNECT",
        "TRACE",
        "ADMIN",
        "INFO",
        "SERVLIST",
        "SQUERY",
        "KILL",
        "PASS",
        "OPER",
        "REHASH",
        "DIE",
        "RESTART",
        "AWAY",
        "USERHOST",
        "ISON",
        "CAP",
        "AUTHENTICATE",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        messages = []
        for line in text.replace("\r\n", "\n").split("\n"):
            line = line.strip()
            if not line:
                continue
            prefix = ""
            if line.startswith(":"):
                pparts = line.split(" ", 1)
                prefix = pparts[0][1:]
                line = pparts[1] if len(pparts) > 1 else ""
            parts = line.split(" ", 1)
            command = parts[0].upper()
            params = parts[1] if len(parts) > 1 else ""
            if command in IRC_COMMANDS or (len(command) == 3 and command.isdigit()):
                messages.append(
                    {"Prefix": prefix, "Command": command, "Parameters": params}
                )
        if not messages:
            return None
        first = messages[0]
        return {
            "Command": first["Command"],
            "irc.command": first["Command"],
            "Prefix": first["Prefix"],
            "irc.prefix": first["Prefix"],
            "Parameters": first["Parameters"],
            "irc.params": first["Parameters"],
            "Message Count": len(messages),
            "irc.msg_count": len(messages),
        }
    except Exception:
        return None
