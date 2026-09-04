"""Shared DNS-wire parser used by mDNS and LLMNR backend decoders."""

import ipaddress
import struct


_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}
_CLASS_NAMES = {1: "IN", 2: "CS", 3: "CH", 4: "HS", 255: "ANY"}


def _read_u16(data, offset):
    if offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from(">H", data, offset)[0]


def _read_u32(data, offset):
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from(">I", data, offset)[0]


def _decode_name(data, offset):
    """Return (name, next_offset), following RFC 1035 compression pointers."""
    if offset < 0 or offset >= len(data):
        return None, None
    labels = []
    cursor = offset
    next_offset = None
    visited = set()
    for _ in range(128):
        if cursor >= len(data):
            return None, None
        length = data[cursor]
        if length == 0:
            if next_offset is None:
                next_offset = cursor + 1
            return ".".join(labels) if labels else ".", next_offset
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                return None, None
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if pointer in visited or pointer >= len(data):
                return None, None
            visited.add(pointer)
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0 or length > 63 or cursor + 1 + length > len(data):
            return None, None
        label = data[cursor + 1 : cursor + 1 + length]
        labels.append(label.decode("utf-8", errors="replace"))
        cursor += 1 + length
    return None, None


def _format_ipv4(raw):
    return ".".join(str(value) for value in raw) if len(raw) == 4 else None


def _format_ipv6(raw):
    if len(raw) != 16:
        return None
    try:
        return str(ipaddress.IPv6Address(raw))
    except ValueError:
        return None


def _format_rdata(rr_type, raw, message, raw_offset):
    if rr_type == 1:
        return _format_ipv4(raw) or raw.hex()
    if rr_type == 28:
        return _format_ipv6(raw) or raw.hex()
    if rr_type in (2, 5, 12):
        name, _ = _decode_name(message, raw_offset)
        return name or raw.hex()
    if rr_type == 16:
        values = []
        cursor = 0
        while cursor < len(raw):
            length = raw[cursor]
            if cursor + 1 + length > len(raw):
                break
            values.append(raw[cursor + 1 : cursor + 1 + length].decode("utf-8", errors="replace"))
            cursor += 1 + length
        return " ".join(f'"{value}"' for value in values) if values else raw.hex()
    if rr_type == 33 and len(raw) >= 7:
        priority, weight, port = struct.unpack_from(">HHH", raw, 0)
        target, _ = _decode_name(message, raw_offset + 6)
        return f"priority={priority} weight={weight} port={port} target={target or raw[6:].hex()}"
    return raw.hex()


def decode_dns_like(raw_payload, protocol_name, key_prefix):
    """Decode one DNS-wire message as mDNS or LLMNR."""
    if raw_payload is None or len(raw_payload) < 12:
        return None
    try:
        message_id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack_from(">HHHHHH", raw_payload, 0)
        if qd_count + an_count + ns_count + ar_count == 0:
            return None
        cursor = 12
        questions = []
        for _ in range(min(qd_count, 256)):
            name, next_cursor = _decode_name(raw_payload, cursor)
            if name is None or next_cursor is None or next_cursor + 4 > len(raw_payload):
                if not questions:
                    return None
                break
            qtype, qclass = struct.unpack_from(">HH", raw_payload, next_cursor)
            questions.append(f"{name} {_QTYPE_NAMES.get(qtype, f'TYPE{qtype}')} {_CLASS_NAMES.get(qclass, f'CLASS{qclass}')}")
            cursor = next_cursor + 4

        records = []
        for section_name, count in (("Answer", an_count), ("Authority", ns_count), ("Additional", ar_count)):
            for _ in range(min(count, 256)):
                name, next_cursor = _decode_name(raw_payload, cursor)
                if name is None or next_cursor is None or next_cursor + 10 > len(raw_payload):
                    break
                rr_type, rr_class, ttl, rd_length = struct.unpack_from(">HHIH", raw_payload, next_cursor)
                rd_start = next_cursor + 10
                rd_end = rd_start + rd_length
                if rd_end > len(raw_payload):
                    break
                raw_rdata = raw_payload[rd_start:rd_end]
                rdata = _format_rdata(rr_type, raw_rdata, raw_payload, rd_start)
                records.append(
                    f"{section_name}: {name} {_QTYPE_NAMES.get(rr_type, f'TYPE{rr_type}')} "
                    f"{_CLASS_NAMES.get(rr_class, f'CLASS{rr_class}')} TTL={ttl} RDATA={rdata}"
                )
                cursor = rd_end

        if qd_count > 0 and not questions:
            return None
        if not questions and not records:
            return None
        result = {
            "Transaction ID": f"0x{message_id:04x}",
            f"{key_prefix}.id": message_id,
            "Is Response": bool(flags & 0x8000),
            f"{key_prefix}.qr": bool(flags & 0x8000),
            "Question Count": qd_count,
            f"{key_prefix}.qdcount": qd_count,
            "Answer Count": an_count,
            f"{key_prefix}.ancount": an_count,
            "Authority Count": ns_count,
            f"{key_prefix}.nscount": ns_count,
            "Additional Count": ar_count,
            f"{key_prefix}.arcount": ar_count,
            "Query Names": [question.split(" ", 1)[0] for question in questions],
            f"{key_prefix}.qnames": [question.split(" ", 1)[0] for question in questions],
            "Questions": questions,
            f"{key_prefix}.questions": questions,
            "Records": records,
            f"{key_prefix}.records": records,
            "Wire length": len(raw_payload),
            "wire.len": len(raw_payload),
        }
        if records:
            result["Answers"] = records
            result[f"{key_prefix}.answers"] = records
        return result
    except (IndexError, struct.error, ValueError):
        return None
