from src.backend.decoders.iso8583 import decodeISO8583


def test_decode_iso8583_ascii_authorization_request():
    """Decode an ASCII-encoded ISO 8583 0100 authorization request."""
    # MTI 0100 + ASCII bitmap (field 2,3,4,7,11) + data elements
    # bitmap 7220000000000000: f2,f3,f4,f7,f11
    payload = b"0100" + b"7220000000000000"
    payload += b"164111111111111111"  # field 2: LLVAR len=16, PAN
    payload += b"123456"  # field 3: Processing Code
    payload += b"000000001000"  # field 4: Amount
    payload += b"0131203030"  # field 7: Transmission Date
    payload += b"000001"  # field 11: STAN

    decoded = decodeISO8583(payload)

    assert decoded is not None
    assert decoded["MTI"] == "0100"
    assert decoded["Message Type"] == "Authorization Request"
    assert decoded["MTI Class"] == "Authorization"
    assert decoded["Field 2 (Primary Account Number (PAN))"] == "4111111111111111"
    assert decoded["Field 3 (Processing Code)"] == "123456"
    assert decoded["Field 4 (Amount, Transaction)"] == "000000001000"
    assert decoded["Field 7 (Transmission Date & Time)"] == "0131203030"
    assert decoded["Field 11 (System Trace Audit Number (STAN))"] == "000001"
    # Also check the dotted key variants
    assert decoded["iso8583.mti"] == "0100"
    assert decoded["iso8583.field_4"] == "000000001000"


def test_decode_iso8583_bcd_mti():
    """Decode a BCD-packed MTI (2 bytes, e.g. 0x08 0x00 -> 0800)."""
    # MTI 0800 as BCD, binary bitmap with field 11 only, STAN
    payload = bytes([0x08, 0x00]) + bytes([0x00, 0x20, 0, 0, 0, 0, 0, 0]) + b"000123"

    decoded = decodeISO8583(payload)

    assert decoded is not None
    assert decoded["MTI"] == "0800"
    assert decoded["Message Type"] == "Network Management Request"
    assert decoded["Field 11 (System Trace Audit Number (STAN))"] == "000123"


def test_decode_iso8583_secondary_bitmap():
    """Verify secondary bitmap (field 1 set) extends to fields 65-128."""
    # MTI 0100, bitmap with field 1 + field 2 set -> secondary bitmap follows
    # primary: 0xC0 0x00 ... (bit0=field1, bit1=field2)
    # secondary: 0x00...0x00 (no fields 65-128 set)
    payload = b"0100" + bytes([0xC0, 0, 0, 0, 0, 0, 0, 0]) + bytes(8)
    # field 2 LLVAR
    payload += b"041234"  # len=4, PAN="1234"

    decoded = decodeISO8583(payload)

    assert decoded is not None
    assert decoded["MTI"] == "0100"
    assert 1 in decoded["Bitmap Fields"]
    assert 2 in decoded["Bitmap Fields"]
    assert decoded["Field 2 (Primary Account Number (PAN))"] == "1234"


def test_decode_iso8583_truncated_field():
    """A short payload marks the next field as truncated, not parse error."""
    # MTI 0100 + bitmap with field 2 + field 3, but only provide field 2 data
    payload = b"0100" + b"6000000000000000"  # field 2 + field 3
    payload += b"041234"  # field 2: len=4, PAN="1234"
    # field 3 needs 6 bytes but we provide none

    decoded = decodeISO8583(payload)

    assert decoded is not None
    assert decoded["Field 3 (Processing Code)"] == "(truncated)"


def test_decode_iso8583_returns_none_for_non_iso():
    """Non-ISO 8583 bytes return None."""
    assert decodeISO8583(b"HTTP/1.1 200 OK") is None
    assert decodeISO8583(b"") is None
    assert decodeISO8583(b"GET /index.html HTTP/1.1") is None


def test_decode_iso8583_llvar_and_lllvar():
    """Test LLVAR and LLLVAR length prefixes."""
    # MTI 0100, bitmap with field 2 (LLVAR) and field 48 (LLLVAR)
    # field 2 -> bit1, field 48 -> bit47 -> byte5 bit7 -> 0x01
    # primary bitmap: byte0=0x40 (f2), byte5=0x01 (f48)
    payload = b"0100" + bytes([0x40, 0, 0, 0, 0, 0x01, 0, 0])
    # field 2: LLVAR len "08" + "41111111"
    payload += b"0841111111"
    # field 48: LLLVAR len "005" + "HELLO"
    payload += b"005HELLO"

    decoded = decodeISO8583(payload)

    assert decoded is not None
    assert decoded["Field 2 (Primary Account Number (PAN))"] == "41111111"
    assert decoded["Field 48 (Additional Data — Private)"] == "HELLO"