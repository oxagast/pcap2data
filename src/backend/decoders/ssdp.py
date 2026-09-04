"""SSDP / UPnP discovery decoder for UDP port 1900."""

import re


_START_LINE_RE = re.compile(r"^(M-SEARCH|NOTIFY|HTTP/1\.1\s+\d{3})(?:\s+(.*))?$", re.IGNORECASE)
_UPNP_MARKERS = ("upnp:rootdevice", "urn:schemas-upnp-org:", "/rootdesc.xml")


def _parse_headers(raw_text):
    lines = raw_text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        return None
    start_line = lines[0].strip()
    if not _START_LINE_RE.match(start_line):
        return None
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        value = value.strip()
        if key and value:
            headers[key] = value
    return start_line, headers


def decodeSSDP(rawPayload):
    if rawPayload is None or not rawPayload:
        return None
    try:
        parsed = _parse_headers(rawPayload.decode("utf-8", errors="replace"))
        if parsed is None:
            return None
        start_line, headers = parsed
        combined = " ".join([start_line, *headers.values()]).lower()
        is_upnp = any(marker in combined for marker in _UPNP_MARKERS)
        result = {
            "Type": "Response" if start_line.upper().startswith("HTTP/") else start_line.split(" ", 1)[0].upper(),
            "ssdp.type": "Response" if start_line.upper().startswith("HTTP/") else start_line.split(" ", 1)[0].upper(),
            "Start Line": start_line,
            "ssdp.start_line": start_line,
            "Protocol Profile": "UPnP" if is_upnp else "SSDP",
            "ssdp.profile": "UPnP" if is_upnp else "SSDP",
            "Headers": headers,
            "ssdp.headers": headers,
            "Wire length": len(rawPayload),
            "wire.len": len(rawPayload),
        }
        header_aliases = {
            "cache-control": ("Cache-Control", "ssdp.cache_control"),
            "location": ("Location", "ssdp.location"),
            "server": ("Server", "ssdp.server"),
            "st": ("ST", "ssdp.st"),
            "nt": ("NT", "ssdp.nt"),
            "usn": ("USN", "ssdp.usn"),
            "man": ("MAN", "ssdp.man"),
            "mx": ("MX", "ssdp.mx"),
            "host": ("Host", "ssdp.host"),
        }
        for header_key, (display_key, dot_key) in header_aliases.items():
            value = headers.get(header_key)
            if value:
                result[display_key] = value
                result[dot_key] = value
        if is_upnp:
            result["UPnP"] = True
            result["upnp"] = True
            result["upnp.profile"] = "UPnP"
        return result
    except (AttributeError, UnicodeError):
        return None
