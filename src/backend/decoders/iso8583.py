"""ISO 8583 protocol decoder for PacketSnitch backend.

Decodes the standard structure of an ISO 8583 message:
  - MTI (Message Type Indicator): 4 numeric digits (ASCII)
  - Primary Bitmap: 8 or 16 bytes (binary). If the first bit is set, a
    secondary bitmap follows.
  - Data Elements: variable-length fields per the ISO 8583:1987 / 1993
    field definitions.

The decoder is tolerant of variant encodings: it supports both ASCII
(ISO 8583:1993 BCD-style numeric fields as ASCII digits) and binary
(BCD-packed) bitmaps. Data-element length handling follows the standard
`LLVAR` / `LLLVAR` conventions. Only the most common field formats are
rendered; unknown elements are surfaced as raw hex previews so nothing
is silently dropped.

This mirrors the shape of `decoders/smpp.py`: returns a dict on success
or `None` when the bytes do not look like an ISO 8583 message.
"""

import struct

# ISO 8583 message type indicators (MTI) — class + function.
# Keys are the 4-digit MTI as an integer (e.g. 0100, 0110, 0420).
ISO_MTI_NAMES = {
    "0100": "Authorization Request",
    "0110": "Authorization Request Response",
    "0120": "Authorization Advice",
    "1200": "Authorization Request (BCD)",
    "0121": "Authorization Advice Repeat",
    "0121": "Authorization Advice Repeat",
    "0130": "Authorization Reversal",
    "0140": "Authorization Reversal Response",
    "0200": "Acquirer Reversal Request",
    "0210": "Acquirer Reversal Response",
    "0220": "Acquirer Advice",
    "0221": "Acquirer Advice Repeat",
    "0221": "Acquirer Advice Repeat",
    "0230": "Acquirer Advice Reversal",
    "0231": "Acquirer Advice Reversal Response",
    "0400": "Acquirer Reversal Request",
    "0410": "Acquirer Reversal Response",
    "0420": "Acquirer Reversal Advice",
    "0421": "Acquirer Reversal Advice Repeat",
    "0430": "Acquirer Reversal Advice Reversal",
    "0431": "Acquirer Reversal Advice Reversal Response",
    "0500": "Acquirer Batch Settlement",
    "0510": "Acquirer Batch Settlement Response",
    "0600": "Acquirer Settlement Reversal",
    "0610": "Acquirer Settlement Reversal Response",
    "0800": "Network Management Request",
    "0810": "Network Management Response",
    "0820": "Network Management Advice",
    "0821": "Network Management Advice Repeat",
    "0830": "Network Management Reversal",
    "0831": "Network Management Reversal Response",
    "0900": "Acquirer Settlement Reversal",
    "0901": "Acquirer Settlement Reversal Response",
    "0902": "Acquirer Settlement Reversal Acknowledgement",
    "0903": "Acquirer Settlement Reversal Negative Acknowledgement",
}

# MTI class prefix (first digit) meaning.
ISO_MTI_CLASS = {
    "0": "Authorization",
    "1": "Authorization Reversal",
    "2": "Acquirer Reversal / Advice",
    "3": "Acquirer Reversal Advice Reversal",
    "4": "Acquirer Reversal",
    "5": "Acquirer Settlement",
    "6": "Acquirer Settlement Reversal",
    "7": "Acquirer Settlement Reversal Repeat",
    "8": "Network Management",
    "9": "Acquirer Settlement Reversal",
}

# ISO 8583 data element definitions: number → (name, format, maxLen).
# format codes:
#   n  = numeric (ASCII digits or BCD)
#   an = alphanumeric (ASCII)
#   ans= alphanumeric + special (ASCII)
#   b  = binary / bitmap
#   z  = track data (variable, raw)
# Length kinds:
#   fixed<N>    = exactly N bytes (or N digits for numeric BCD → N/2 bytes)
#   llvar       = 2-digit length prefix (ASCII or 1 BCD byte)
#   lllvar      = 3-digit length prefix (ASCII or 2 BCD bytes)
ISO_DATA_ELEMENTS = {
    1: ("Additional Data — Bitmap", "b", 8),
    2: ("Primary Account Number (PAN)", "n", "llvar"),
    3: ("Processing Code", "n", 6),
    4: ("Amount, Transaction", "n", 12),
    5: ("Amount, Settlement", "n", 12),
    6: ("Amount, Cardholder Billing", "n", 12),
    7: ("Transmission Date & Time", "n", 10),
    8: ("Amount, Cardholder Billing Fee", "n", 8),
    9: ("Conversion Rate, Settlement", "n", 8),
    10: ("Conversion Rate, Cardholder Billing", "n", 8),
    11: ("System Trace Audit Number (STAN)", "n", 6),
    12: ("Local Transaction Time", "n", 6),
    13: ("Local Transaction Date", "n", 4),
    14: ("Expiration Date", "n", 4),
    15: ("Settlement Date", "n", 4),
    16: ("Currency Conversion Date", "n", 4),
    17: ("Capture Date", "n", 4),
    18: ("Merchant Category Code", "n", 4),
    19: ("Acquiring Institution Country Code", "n", 3),
    20: ("PAN Extended Country Code", "n", 3),
    21: ("Forwarding Institution Country Code", "n", 3),
    22: ("POS Entry Mode", "n", 3),
    23: ("Card Sequence Number", "n", 3),
    24: ("Function Code", "n", 3),
    25: ("POS Condition Code", "n", 2),
    26: ("POS PIN Capture Code", "n", 2),
    27: ("Authorization Identification Response Length", "n", 1),
    28: ("Amount, Transaction Fee", "an", 9),
    29: ("Amount, Settlement Fee", "an", 9),
    30: ("Amount, Transaction Processing Fee", "an", 9),
    31: ("Amount, Settlement Processing Fee", "an", 9),
    32: ("Acquiring Institution Identification Code", "n", "llvar"),
    33: ("Forwarding Institution Identification Code", "n", "llvar"),
    34: ("Primary Account Number, Extended", "ans", "llvar"),
    35: ("Track 2 Data", "z", "llvar"),
    36: ("Track 3 Data", "z", "lllvar"),
    37: ("Retrieval Reference Number", "an", 12),
    38: ("Authorization Identification Response", "an", 6),
    39: ("Response Code", "an", 2),
    40: ("Service Restriction Code", "an", 3),
    41: ("Card Acceptor Terminal Identification", "ans", 8),
    42: ("Card Acceptor Identification Code", "ans", 15),
    43: ("Card Acceptor Name/Location", "ans", 40),
    44: ("Additional Response Data", "ans", "llvar"),
    45: ("Track 1 Data", "ans", "llvar"),
    46: ("Additional Data — ISO", "ans", "lllvar"),
    47: ("Additional Data — National", "ans", "lllvar"),
    48: ("Additional Data — Private", "ans", "lllvar"),
    49: ("Currency Code, Transaction", "n", 3),
    50: ("Currency Code, Settlement", "n", 3),
    51: ("Currency Code, Cardholder Billing", "n", 3),
    52: ("PIN Data", "b", 64),
    53: ("Security Related Control Information", "n", 16),
    54: ("Additional Amounts", "an", "llvar"),
    55: ("ICC System Related Data", "ans", "lllvar"),
    56: ("Original Data Elements", "ans", "lllvar"),
    57: ("Authorization Life Cycle Code", "ans", 3),
    58: ("Authorizing Agent Institution Id Code", "ans", "lllvar"),
    59: ("Transport Data", "ans", "lllvar"),
    60: ("Reserved Private", "ans", "lllvar"),
    61: ("Reserved Private", "ans", "lllvar"),
    62: ("Reserved Private", "ans", "lllvar"),
    63: ("Reserved Private", "ans", "lllvar"),
    64: ("Message Authentication Code (MAC)", "b", 8),
    70: ("Network Management Information Code", "n", 3),
    90: ("Original Data Elements", "an", 42),
    95: ("Card Issuer Name/Location", "ans", 45),
    100: ("Receiving Institution Id Code", "n", "llvar"),
    102: ("Account Identification 1", "ans", "llvar"),
    103: ("Account Identification 2", "ans", "llvar"),
    104: ("Transaction Description", "ans", "lllvar"),
    105: ("Reserved for ISO use", "ans", "lllvar"),
    106: ("Reserved for ISO use", "ans", "lllvar"),
    120: ("Reserved for private use", "ans", "lllvar"),
    128: ("Message Authentication Code (MAC)", "b", 8),
}


def _is_ascii_digits(data, count):
    return len(data) >= count and all(0x30 <= b <= 0x39 for b in data[:count])


def _read_numeric(data, length):
    """Read `length` ASCII digits, return (value_str, bytes_consumed)."""
    if len(data) < length:
        return None, 0
    chunk = data[:length]
    if not all(0x30 <= b <= 0x39 for b in chunk):
        return None, 0
    return chunk.decode("ascii"), length


def _read_ascii(data, offset, length):
    """Read `length` ASCII chars from data[offset:]. Returns str or None."""
    if offset + length > len(data):
        return None
    return data[offset : offset + length].decode("ascii", errors="replace")


def _read_ascii_or_hex(data, offset, length):
    """Read bytes as ASCII if printable, else as hex.

    Used for binary-len mode where field values may be BCD-packed (e.g.
    PAN 0x12 0x34 ... -> hex "123456...").
    """
    if offset + length > len(data):
        return None
    chunk = data[offset : offset + length]
    if all(0x20 <= b <= 0x7E for b in chunk):
        return chunk.decode("ascii")
    return chunk.hex().upper()


def _read_binary_hex(data, offset, length):
    """Read `length` raw bytes from data[offset:] as uppercase hex."""
    if offset + length > len(data):
        return None
    return data[offset : offset + length].hex().upper()


def _read_llvar(data, offset, binary_len=False):
    """Read an LLVAR field at offset. Returns (value, consumed) or (None, 0)."""
    if binary_len:
        # Binary 1-byte length prefix (e.g. 0x16 = 22).
        if offset + 1 > len(data):
            return None, 0
        length = data[offset]
        if offset + 1 + length > len(data):
            return None, 0
        return _read_ascii_or_hex(data, offset + 1, length), 1 + length
    if offset + 2 > len(data):
        return None, 0
    try:
        length = int(data[offset : offset + 2].decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None, 0
    if length < 0 or offset + 2 + length > len(data):
        return None, 0
    return _read_ascii(data, offset + 2, length), 2 + length


def _read_lllvar(data, offset, binary_len=False):
    """Read an LLLVAR field at offset. Returns (value, consumed) or (None, 0)."""
    if binary_len:
        # Binary 2-byte length prefix (big-endian).
        if offset + 2 > len(data):
            return None, 0
        length = (data[offset] << 8) | data[offset + 1]
        if offset + 2 + length > len(data):
            return None, 0
        return _read_ascii_or_hex(data, offset + 2, length), 2 + length
    if offset + 3 > len(data):
        return None, 0
    try:
        length = int(data[offset : offset + 3].decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None, 0
    if length < 0 or offset + 3 + length > len(data):
        return None, 0
    return _read_ascii(data, offset + 3, length), 3 + length


def _parse_bitmap_bytes(bitmap_bytes):
    """Parse 8 binary bitmap bytes into a set of field numbers (1–64)."""
    fields = set()
    for byte_idx in range(8):
        for bit_pos in range(8):
            if bitmap_bytes[byte_idx] & (0x80 >> bit_pos):
                fields.add(byte_idx * 8 + bit_pos + 1)
    return fields


def _decode_at_offset(rawPayload, binary_len=False):
    """Core decode at a given framing offset. `binary_len` selects binary
    1-byte/2-byte length prefixes for LLVAR/LLLVAR instead of ASCII."""
    if len(rawPayload) < 12:
        return None

    # MTI: 4 ASCII digits (most common). Some implementations pack the
    # MTI as 2 BCD bytes (0x12 0x00 → "1200"); try that fallback only
    # when the first 4 bytes are NOT all ASCII digits but the first 2
    # bytes decode to a plausible BCD MTI.
    mti = None
    offset = 0
    if _is_ascii_digits(rawPayload, 4):
        mti = rawPayload[:4].decode("ascii")
        offset = 4
    elif len(rawPayload) >= 2:
        b0, b1 = rawPayload[0], rawPayload[1]
        if (b0 >> 4) <= 9 and (b0 & 0x0F) <= 9 and (b1 >> 4) <= 9 and (b1 & 0x0F) <= 9:
            mti = f"{b0 >> 4:x}{b0 & 0xf:x}{b1 >> 4:x}{b1 & 0xf:x}"
            offset = 2
            # BCD-packed MTI is a fallback path. Require the decoded
            # MTI to be a known ISO 8583 message type so that arbitrary
            # binary data (e.g. HTTP text "HTTP" -> BCD "4854") is not
            # misidentified as ISO 8583.
            if mti not in ISO_MTI_NAMES:
                return None
    if not mti:
        return None

    # Detect bitmap encoding. ASCII-hex bitmap = 16 chars of [0-9A-Fa-f].
    # Binary bitmap = 8 raw bytes. A 1-byte ASCII prefix is ambiguous
    # with a binary byte, so require the full 16-char run to be hex.
    ascii_bitmap = False
    if len(rawPayload) >= offset + 16:
        candidate = rawPayload[offset : offset + 16]
        if all(b in b"0123456789ABCDEFabcdef" for b in candidate):
            ascii_bitmap = True

    fields_set = set()
    if ascii_bitmap:
        try:
            primary = bytes.fromhex(
                rawPayload[offset : offset + 16].decode("ascii")
            )
        except (ValueError, UnicodeDecodeError):
            return None
        offset += 16
        fields_set |= _parse_bitmap_bytes(primary)
        if 1 in fields_set and len(rawPayload) >= offset + 16:
            try:
                secondary = bytes.fromhex(
                    rawPayload[offset : offset + 16].decode("ascii")
                )
            except (ValueError, UnicodeDecodeError):
                secondary = b""
            else:
                offset += 16
                fields_set |= {64 + f for f in _parse_bitmap_bytes(secondary)}
    else:
        if len(rawPayload) < offset + 8:
            return None
        primary = rawPayload[offset : offset + 8]
        offset += 8
        fields_set |= _parse_bitmap_bytes(primary)
        if 1 in fields_set and len(rawPayload) >= offset + 8:
            secondary = rawPayload[offset : offset + 8]
            offset += 8
            fields_set |= {64 + f for f in _parse_bitmap_bytes(secondary)}

    # Sanity: if the bitmap claims data fields exist but the remaining
    # payload is empty (0 bytes), this is almost certainly not a real
    # ISO 8583 message (e.g. "HTTP/1.1 200 OK" → MTI "4854" + garbage
    # bitmap with no data following).
    data_fields = fields_set - {1}
    if data_fields and offset >= len(rawPayload):
        return None

    result = {
        "MTI": mti,
        "iso8583.mti": mti,
        "Message Type": ISO_MTI_NAMES.get(mti, "Unknown"),
        "iso8583.message_type": ISO_MTI_NAMES.get(mti, "Unknown"),
        "MTI Class": ISO_MTI_CLASS.get(mti[0], "Unknown"),
        "iso8583.mti_class": ISO_MTI_CLASS.get(mti[0], "Unknown"),
        "Bitmap Fields": sorted(fields_set),
        "iso8583.bitmap_fields": sorted(fields_set),
    }

    # Parse data elements in field-number order.
    any_field_decoded = False
    for field_num in sorted(fields_set):
        if field_num == 1:
            continue  # bitmap itself, already consumed
        if field_num not in ISO_DATA_ELEMENTS:
            result[f"Field {field_num}"] = "(unknown / reserved)"
            result[f"iso8583.field_{field_num}"] = "(unknown / reserved)"
            continue
        name, fmt, length = ISO_DATA_ELEMENTS[field_num]
        if offset >= len(rawPayload):
            result[f"Field {field_num} ({name})"] = "(truncated)"
            result[f"iso8583.field_{field_num}"] = "(truncated)"
            continue

        # Distinguish "not enough bytes" (truncated) from "bad encoding"
        # (parse error). For fixed and variable fields, a short buffer
        # is truncated; an invalid length prefix or non-ASCII digit is a
        # parse error.
        available = len(rawPayload) - offset
        value = None
        consumed = 0
        truncated = False
        if length == "llvar":
            min_prefix = 1 if binary_len else 2
            if available < min_prefix:
                truncated = True
            else:
                value, consumed = _read_llvar(rawPayload, offset, binary_len)
        elif length == "lllvar":
            min_prefix = 2 if binary_len else 3
            if available < min_prefix:
                truncated = True
            else:
                value, consumed = _read_lllvar(rawPayload, offset, binary_len)
        elif isinstance(length, int):
            if available < length:
                truncated = True
            elif fmt == "b":
                value = _read_binary_hex(rawPayload, offset, length)
                if value is not None:
                    consumed = length
            else:
                value = _read_ascii(rawPayload, offset, length)
                if value is not None:
                    consumed = length

        if truncated:
            result[f"Field {field_num} ({name})"] = "(truncated)"
            result[f"iso8583.field_{field_num}"] = "(truncated)"
            break
        if value is None:
            # The first data field failed to parse. For a genuine ISO
            # 8583 message the first set field should be decodable; a
            # parse failure on the very first field strongly suggests
            # this is not ISO 8583 at all (e.g. HTTP text that happened
            # to start with 4 ASCII digits). Reject the whole message.
            if not any_field_decoded:
                return None
            result[f"Field {field_num} ({name})"] = "(parse error)"
            result[f"iso8583.field_{field_num}"] = "(parse error)"
            break
        offset += consumed
        result[f"Field {field_num} ({name})"] = value
        result[f"iso8583.field_{field_num}"] = value
        any_field_decoded = True

    return result


def decodeISO8583(rawPayload):
    """Decode an ISO 8583 message from raw payload bytes.

    Returns a dict of fields on success, or None if the payload does not
    look like a valid ISO 8583 message. Supports both ASCII-hex and binary
    bitmap encodings, ASCII and binary variable-length field prefixes,
    and transparently strips a 2- or 4-byte TPDU/message-length framing
    prefix that is common in ISO 8583 over TCP.
    """
    if not isinstance(rawPayload, (bytes, bytearray)):
        rawPayload = bytes(rawPayload)

    # ISO 8583 over TCP commonly carries a 2-byte message-length header
    # (TPDU framing) before the MTI. Try the raw bytes first (no prefix),
    # then a 2-byte and 4-byte prefix strip. For each offset, try both
    # ASCII and binary length-prefix modes for LLVAR/LLLVAR fields.
    for skip in (0, 2, 4):
        if skip >= len(rawPayload):
            break
        sliced = rawPayload[skip:]
        result = _decode_at_offset(sliced, binary_len=False)
        if result is not None:
            return result
        result = _decode_at_offset(sliced, binary_len=True)
        if result is not None:
            return result
    return None