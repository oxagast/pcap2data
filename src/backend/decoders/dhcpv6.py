"""DHCPv6 decoder for RFC 8415 messages on UDP ports 546/547."""

import ipaddress
import struct


MESSAGE_TYPES = {
    1: "SOLICIT", 2: "ADVERTISE", 3: "REQUEST", 4: "CONFIRM",
    5: "RENEW", 6: "REBIND", 7: "REPLY", 8: "RELEASE",
    9: "DECLINE", 10: "RECONFIGURE", 11: "INFORMATION-REQUEST",
    12: "RELAY-FORW", 13: "RELAY-REPL", 14: "LEASEQUERY",
    15: "LEASEQUERY-REPLY", 16: "LEASEQUERY-DATA", 17: "LEASEQUERY-ACK",
    18: "RECONFIGURE-REQUEST", 19: "RECONFIGURE-REPLY", 20: "DHCPV4-QUERY",
    21: "DHCPV4-RESPONSE", 22: "ACTIVE-LEASEQUERY", 23: "STARTTLS",
    24: "BULKLEASEQUERY", 25: "BULKLEASEQUERY-REPLY", 26: "LEASEQUERY-STATUS",
    27: "TLS-AKA",
}

OPTION_NAMES = {
    1: "client-id", 2: "server-id", 3: "ia-na", 4: "ia-ta", 5: "iaaddr",
    6: "oro", 7: "preference", 8: "elapsed-time", 9: "relay-msg",
    11: "status-code", 12: "rapid-commit", 13: "user-class", 14: "vendor-class",
    15: "vendor-opts", 16: "interface-id", 17: "reconf-msg", 18: "reconf-accept",
    21: "dns-servers", 22: "domain-list", 23: "ia-pd", 24: "ia-prefix",
    25: "nis-servers", 26: "nisp-servers", 27: "nis-domain-name",
    28: "nisp-domain-name", 29: "sntp-servers", 30: "information-refresh-time",
    31: "nsearch-list", 32: "vendor-specific", 33: "fully-qualified-domain-name",
    37: "echo-request", 38: "leasequery", 39: "lq-query", 40: "client-data",
    41: "clt-time", 42: "lq-relay-data", 43: "lq-client-link", 44: "vss",
    64: "captive-portal", 65: "ipv6-feature-profile", 66: "v6-captive-portal",
    67: "ipv6-captive-portal",
}


def _ipv6(raw):
    if len(raw) != 16:
        return None
    try:
        return str(ipaddress.IPv6Address(raw))
    except ValueError:
        return None


def _option_value(code, raw):
    if code in (3, 4) and len(raw) >= 12:
        iaid, t1, t2 = struct.unpack_from(">III", raw, 0)
        return f"IAID={iaid} T1={t1} T2={t2}"
    if code in (5, 24) and len(raw) >= 24:
        address = _ipv6(raw[:16])
        preferred, valid = struct.unpack_from(">II", raw, 16)
        return f"address={address or raw[:16].hex()} preferred={preferred} valid={valid}"
    if code in (1, 2) and len(raw) >= 2:
        return f"DUID type={struct.unpack_from('>H', raw, 0)[0]} body={raw[2:].hex()}"
    if code == 6:
        return ",".join(str(struct.unpack_from(">H", raw, i)[0]) for i in range(0, len(raw) - 1, 2))
    if code == 7 and len(raw) == 1:
        return str(raw[0])
    if code == 8 and len(raw) >= 2:
        return f"{struct.unpack_from('>H', raw, 0)[0]} (1/100s)"
    if code == 11 and len(raw) >= 2:
        status = struct.unpack_from(">H", raw, 0)[0]
        text = raw[2:].decode("utf-8", errors="replace").strip("\x00")
        return f"status={status}" + (f" ({text})" if text else "")
    if code == 21:
        addresses = [_ipv6(raw[i : i + 16]) for i in range(0, len(raw) - 15, 16)]
        return ",".join(address for address in addresses if address) or raw.hex()
    if code in (13, 14, 22, 27, 28, 31, 33, 35, 36, 53, 55):
        return raw.decode("utf-8", errors="replace").strip("\x00")
    return raw.hex()


def _walk_options(raw, start, end, result, depth=0):
    cursor = start
    count = 0
    while cursor + 4 <= end and count < 256:
        code, length = struct.unpack_from(">HH", raw, cursor)
        value_start = cursor + 4
        value_end = value_start + length
        if value_end > end:
            break
        name = OPTION_NAMES.get(code, f"option-{code}")
        prefix = f"{'  ' * depth}{name}"
        value = raw[value_start:value_end]
        result.append({"name": prefix, "code": code, "value": _option_value(code, value)})
        if code == 9 and value:
            nested = decodeDHCPv6(value)
            if nested:
                result.extend({"name": f"  relay-msg {item['name']}", "code": item.get("code"), "value": item["value"]} for item in nested.get("Options", []))
        cursor = value_end
        count += 1


def decodeDHCPv6(rawPayload):
    if rawPayload is None or len(rawPayload) < 4 or rawPayload[0] not in MESSAGE_TYPES:
        return None
    message_type = MESSAGE_TYPES[rawPayload[0]]
    options = []
    _walk_options(rawPayload, 4, len(rawPayload), options)
    return {
        "Message Type": message_type,
        "dhcpv6.msg_type": message_type,
        "Transaction ID": f"0x{rawPayload[1]:02x}{rawPayload[2]:02x}{rawPayload[3]:02x}",
        "dhcpv6.transaction_id": (rawPayload[1] << 16) | (rawPayload[2] << 8) | rawPayload[3],
        "Options": options,
        "dhcpv6.options": options,
        "Wire length": len(rawPayload),
        "wire.len": len(rawPayload),
    }
