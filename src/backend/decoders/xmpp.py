import re


def decodeXMPP(rawPayload):
    """
    Decode XMPP (Extensible Messaging and Presence Protocol) XML stream data.
    Parses stream open tags, message, presence, and IQ stanzas.
    Returns a dict with the stanza type and attributes, or None if not XMPP.
    """
    try:
        text = rawPayload.decode(errors="ignore").strip()
        if not text:
            return None
        isXmpp = (
            text.startswith("<?xml")
            or "<stream:stream" in text
            or text.startswith("<message")
            or text.startswith("<presence")
            or text.startswith("<iq ")
            or text.startswith("<iq>")
            or "<message " in text
            or "<presence" in text
        )
        if not isXmpp:
            return None
        stanzaType = "Unknown"
        if "<stream:stream" in text:
            stanzaType = "StreamOpen"
        elif "</stream:stream>" in text:
            stanzaType = "StreamClose"
        elif "<message" in text:
            stanzaType = "Message"
        elif "<presence" in text:
            stanzaType = "Presence"
        elif "<iq " in text or "<iq>" in text:
            stanzaType = "IQ"
        toMatch = re.search(r'\bto=["\']([^"\']+)["\']', text)
        fromMatch = re.search(r'\bfrom=["\']([^"\']+)["\']', text)
        toAttr = toMatch.group(1) if toMatch else "Unknown"
        fromAttr = fromMatch.group(1) if fromMatch else "Unknown"
        return {
            "Stanza Type": stanzaType,
            "xmpp.stanza": stanzaType,
            "To": toAttr,
            "xmpp.to": toAttr,
            "From": fromAttr,
            "xmpp.from": fromAttr,
        }
    except Exception:
        return None
