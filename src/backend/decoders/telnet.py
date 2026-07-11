import re


def decodeTelnet(rawPayload):
    """
    Decode Telnet IAC (Interpret As Command) negotiation bytes from raw payload.
    Returns a dict with negotiation options and any printable text found,
    or None if no Telnet IAC bytes are present.
    """
    IAC = 0xFF
    TELNET_COMMANDS = {
        0xF0: "SE",
        0xF1: "NOP",
        0xF2: "Data Mark",
        0xF3: "Break",
        0xF4: "Interrupt Process",
        0xF5: "Abort Output",
        0xF6: "Are You There",
        0xF7: "Erase Character",
        0xF8: "Erase Line",
        0xF9: "Go Ahead",
        0xFA: "SB",
        0xFB: "WILL",
        0xFC: "WONT",
        0xFD: "DO",
        0xFE: "DONT",
        0xFF: "IAC",
    }
    TELNET_OPTIONS = {
        0: "Binary",
        1: "Echo",
        2: "Reconnection",
        3: "Suppress GA",
        5: "Status",
        6: "Timing Mark",
        24: "Terminal Type",
        31: "Window Size",
        32: "Terminal Speed",
        33: "Remote Flow",
        34: "Linemode",
        36: "Environment",
        39: "New Environment",
    }
    try:
        if IAC not in rawPayload:
            return None
        negotiations = []
        i = 0
        while i < len(rawPayload):
            if rawPayload[i] == IAC and i + 1 < len(rawPayload):
                cmd = rawPayload[i + 1]
                cmdName = TELNET_COMMANDS.get(cmd, f"0x{cmd:02X}")
                if cmd in (0xFB, 0xFC, 0xFD, 0xFE) and i + 2 < len(rawPayload):
                    optByte = rawPayload[i + 2]
                    optName = TELNET_OPTIONS.get(optByte, f"Option-{optByte}")
                    negotiations.append(f"{cmdName} {optName}")
                    i += 3
                else:
                    negotiations.append(cmdName)
                    i += 2
            else:
                i += 1
        printableText = "".join(chr(b) for b in rawPayload if 32 <= b <= 126).strip()
        result = {
            "Negotiations": negotiations,
            "telnet.negotiations": negotiations,
            "Printable Text": printableText[:200] if printableText else "",
            "telnet.text": printableText[:200] if printableText else "",
        }
        creds = _extractTelnetCredentialText(printableText)
        if creds:
            result["Credentials"] = creds
        return result
    except Exception:
        return None


_TELNET_USER_RE = re.compile(r"(?:login|user(?:name)?)\s*:\s*(\S+)", re.IGNORECASE)
_TELNET_PASS_RE = re.compile(r"(?:pass(?:w(?:or)?d?)?|pw)\s*:\s*(\S+)", re.IGNORECASE)


def _extractTelnetCredentialText(text):
    """
    Scan a printable Telnet text snippet for login/password prompt-response patterns
    (e.g. ``login: alice`` or ``Password: s3cr3t``).
    Returns a dict of found credential fields, or an empty dict.
    """
    if not text:
        return {}
    creds = {}
    userMatch = _TELNET_USER_RE.search(text)
    passMatch = _TELNET_PASS_RE.search(text)
    if userMatch:
        creds["username"] = userMatch.group(1)
    if passMatch:
        creds["password"] = passMatch.group(1)
    return creds


def extractTelnetCredentials(rawPayload):
    """
    Detect cleartext Telnet login credentials from raw TCP port-23 payloads that
    do NOT necessarily contain IAC negotiation bytes.
    """
    try:
        printableText = "".join(chr(b) for b in rawPayload if 32 <= b <= 126).strip()
        if not printableText:
            return {}
        creds = _extractTelnetCredentialText(printableText)
        return creds
    except Exception:
        return {}
