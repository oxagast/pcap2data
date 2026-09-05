"""LLMNR decoder for DNS-wire messages on UDP/TCP port 5355."""

from .dns_wire import decode_dns_like


def decodeLLMNR(rawPayload):
    result = decode_dns_like(rawPayload, "LLMNR", "llmnr")
    if result is None:
        return None
    result["Protocol"] = "LLMNR"
    result["llmnr.protocol"] = "LLMNR"
    return result
