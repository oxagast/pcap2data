"""mDNS decoder for DNS-wire messages on UDP port 5353."""

from .dns_wire import decode_dns_like


def decodeMDNS(rawPayload):
    result = decode_dns_like(rawPayload, "mDNS", "mdns")
    if result is None:
        return None
    result["Protocol"] = "mDNS"
    result["mdns.protocol"] = "mDNS"
    # Bonjour is Apple's DNS-SD service-discovery profile over mDNS. Keep a
    # separate label when the packet contains the service-record types used
    # by DNS-SD (PTR=12, SRV=33, TXT=16), while retaining mDNS for all
    # multicast DNS traffic.
    records = result.get("Records", [])
    questions = result.get("Questions", [])
    is_bonjour = any(
        " PTR " in record or " SRV " in record or " TXT " in record
        for record in records
    ) or any(
        "_tcp." in question or "_udp." in question or "_services." in question
        for question in questions
    )
    result["Bonjour"] = is_bonjour
    result["bonjour"] = is_bonjour
    if is_bonjour:
        result["bonjour.protocol"] = "Bonjour (DNS-SD)"
        result["Protocol Profile"] = "Bonjour (DNS-SD)"
    return result
