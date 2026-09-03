"""Modbus/TCP protocol decoder for PacketSnitch backend.

Decodes the Modbus Application Protocol (MBAP) header and PDU that
carries Modbus/TCP messages over TCP port 502 (RFC 502 / MB-AP.

MBAP header (7 bytes):
  - Transaction Identifier  (2 bytes, big-endian)
  - Protocol Identifier     (2 bytes, must be 0x0000 for Modbus)
  - Length                  (2 bytes, number of following bytes)
  - Unit Identifier         (1 byte)

PDU:
  - Function Code           (1 byte)
  - Data                    (variable, depends on function code)

This mirrors the shape of `decoders/mqtt.py`: returns a dict on
success or ``None`` when the bytes do not look like a Modbus/TCP PDU.
"""

import struct

# Modbus function codes (RFC 502 §5.1).
MODBUS_FUNCTION_CODES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    11: "Get Comm Event Counter",
    12: "Get Comm Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Encapsulated Interface Transport",
}

# Modbus exception codes (RFC 502 §7).
MODBUS_EXCEPTION_CODES = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Server Device Failure",
    5: "Acknowledge",
    6: "Server Device Busy",
    7: "Negative Acknowledge",
    8: "Memory Parity Error",
    9: "Gateway Path Unavailable",
    10: "Gateway Target Device Failed to Respond",
}


def _hex(data, max_len=64):
    """Return a hex string preview of *data*, truncated to *max_len* bytes."""
    if not data:
        return ""
    preview = data[:max_len]
    hex_str = preview.hex()
    if len(data) > max_len:
        hex_str += "…"
    return hex_str


def decodeModbus(rawPayload):
    """Decode a Modbus/TCP message from raw payload bytes.

    Returns a dict with human-readable and dotted keys, or ``None``
    if the payload does not match the Modbus/TCP wire format.
    """
    try:
        if len(rawPayload) < 8:
            return None

        # MBAP header — 7 bytes
        trans_id, proto_id, length, unit_id = struct.unpack_from(
            ">HHHB", rawPayload, 0
        )
        # Protocol identifier must be 0 for Modbus/TCP
        if proto_id != 0:
            return None
        # Length field covers Unit ID (1 byte) + PDU
        if length < 2:
            return None
        # Total payload must be at least 7 (MBAP) + 1 (function code)
        if len(rawPayload) < 7 + 1:
            return None
        # Length should not exceed remaining bytes
        if length > len(rawPayload) - 6:
            return None

        func_code = rawPayload[7]
        is_exception = bool(func_code & 0x80)
        base_func = func_code & 0x7F

        func_name = MODBUS_FUNCTION_CODES.get(
            base_func, "Unknown (0x{:02x})".format(base_func)
        )

        result = {
            "Transaction ID": trans_id,
            "modbus.trans_id": trans_id,
            "Protocol ID": proto_id,
            "modbus.proto_id": proto_id,
            "Length": length,
            "modbus.length": length,
            "Unit ID": unit_id,
            "modbus.unit_id": unit_id,
            "Function Code": base_func,
            "modbus.func_code": base_func,
            "Function Name": func_name,
            "modbus.func_name": func_name,
            "Type": "Exception Response" if is_exception else "Request/Response",
            "modbus.type": "exception" if is_exception else "normal",
        }

        pdu = rawPayload[8 : 6 + length]  # PDU after unit id

        if is_exception:
            if len(pdu) >= 1:
                exc_code = pdu[0]
                exc_name = MODBUS_EXCEPTION_CODES.get(
                    exc_code, "Unknown (0x{:02x})".format(exc_code)
                )
                result["Exception Code"] = exc_code
                result["modbus.exception_code"] = exc_code
                result["Exception Name"] = exc_name
                result["modbus.exception_name"] = exc_name
        else:
            # Decode function-specific data for common read/write functions
            if base_func in (1, 2, 3, 4):
                # Request: Starting Address (2) + Quantity (2)
                # Response: Byte Count (1) + Data
                if len(pdu) == 4:
                    start_addr, quantity = struct.unpack_from(">HH", pdu, 0)
                    result["Starting Address"] = start_addr
                    result["modbus.start_addr"] = start_addr
                    result["Quantity"] = quantity
                    result["modbus.quantity"] = quantity
                elif len(pdu) >= 1:
                    byte_count = pdu[0]
                    result["Byte Count"] = byte_count
                    result["modbus.byte_count"] = byte_count
                    data_bytes = pdu[1:]
                    result["Data"] = _hex(data_bytes)
                    result["modbus.data"] = _hex(data_bytes, 128)
            elif base_func == 5:
                # Write Single Coil: Address (2) + Value (2: 0xFF00=ON, 0x0000=OFF)
                if len(pdu) == 4:
                    addr, value = struct.unpack_from(">HH", pdu, 0)
                    result["Address"] = addr
                    result["modbus.address"] = addr
                    result["Value"] = "ON" if value == 0xFF00 else "OFF"
                    result["modbus.value"] = "ON" if value == 0xFF00 else "OFF"
            elif base_func == 6:
                # Write Single Register: Address (2) + Value (2)
                if len(pdu) == 4:
                    addr, value = struct.unpack_from(">HH", pdu, 0)
                    result["Address"] = addr
                    result["modbus.address"] = addr
                    result["Register Value"] = value
                    result["modbus.reg_value"] = value
            elif base_func in (15, 16):
                # Write Multiple: Request has Address(2)+Quantity(2)+ByteCount(1)+Data
                # Response has Address(2)+Quantity(2)
                if len(pdu) == 4:
                    addr, quantity = struct.unpack_from(">HH", pdu, 0)
                    result["Address"] = addr
                    result["modbus.address"] = addr
                    result["Quantity"] = quantity
                    result["modbus.quantity"] = quantity
                elif len(pdu) >= 5:
                    addr, quantity, byte_count = struct.unpack_from(">HHB", pdu, 0)
                    result["Address"] = addr
                    result["modbus.address"] = addr
                    result["Quantity"] = quantity
                    result["modbus.quantity"] = quantity
                    result["Byte Count"] = byte_count
                    result["modbus.byte_count"] = byte_count
                    data_bytes = pdu[5:]
                    result["Data"] = _hex(data_bytes)
                    result["modbus.data"] = _hex(data_bytes, 128)
            elif base_func == 23:
                # Read/Write Multiple Registers:
                # Read Starting Addr(2) + Qty to Read(2) + Write Starting Addr(2) + Qty to Write(2) + Byte Count(1) + Data
                if len(pdu) >= 8:
                    read_start, read_qty, write_start, write_qty = (
                        struct.unpack_from(">HHHH", pdu, 0)
                    )
                    result["Read Starting Address"] = read_start
                    result["modbus.read_start_addr"] = read_start
                    result["Read Quantity"] = read_qty
                    result["modbus.read_quantity"] = read_qty
                    result["Write Starting Address"] = write_start
                    result["modbus.write_start_addr"] = write_start
                    result["Write Quantity"] = write_qty
                    result["modbus.write_quantity"] = write_qty
                    if len(pdu) >= 9:
                        byte_count = pdu[8]
                        result["Write Byte Count"] = byte_count
                        result["modbus.write_byte_count"] = byte_count
                        data_bytes = pdu[9:]
                        result["Write Data"] = _hex(data_bytes)
                        result["modbus.write_data"] = _hex(data_bytes, 128)

        # Always include raw PDU hex for debugging
        result["PDU Hex"] = _hex(pdu, 128)
        result["modbus.pdu_hex"] = _hex(pdu, 128)

        return result
    except Exception:
        return None