"""DNP3 protocol decoder for PacketSnitch backend.

Decodes DNP3 (Distributed Network Protocol 3) messages as used in
SCADA / ICS environments over TCP port 20000 (and UDP 20000).

DNP3 link-layer frame:
  - Start Bytes       0x0564 (2 bytes, sync)
  - Length            (1 byte, number of bytes from Control to CRC inclusive)
  - Control           (1 byte, link-layer control field)
  - Destination       (2 bytes, little-endian)
  - Source            (2 bytes, little-endian)
  - CRC               (2 bytes, per-block checksum)

The transport and application layers carry function codes and object
group/variation references. This decoder focuses on the link-layer
header and the application-layer function code / object header when
present, following the same dual-key dict pattern as the other
decoders.

Returns a dict on success or ``None`` when the bytes do not match.
"""

import struct

# DNP3 link-layer control field: bit 7 = DIR, bit 6 = PRM, bits 3-4 = function
DNP3_LINK_FUNCTIONS = {
    0: "Reset Link States",
    1: "Reset User Process",
    2: "Test Link States",
    3: "User Data",
    4: "Unconfirmed User Data",
    9: "Request Link Status",
    10: "Response Link Status",
    11: "Ack (Not Positive/Positive)",
}

# DNP3 application-layer function codes (DNP3 Volume 2 §4.2).
DNP3_APP_FUNCTIONS = {
    0: "Confirm",
    1: "Read",
    2: "Write",
    3: "Select",
    4: "Operate",
    5: "Direct Operate",
    6: "Direct Operate No Ack",
    7: "Immediate Freeze",
    8: "Immediate Freeze No Ack",
    9: "Freeze Clear",
    10: "Freeze Clear No Ack",
    11: "Freeze at Time",
    12: "Freeze at Time No Ack",
    13: "Cold Restart",
    14: "Warm Restart",
    15: "Initialize Data",
    16: "Initialize Application",
    17: "Start Application",
    18: "Stop Application",
    19: "Save Configuration",
    20: "Enable Unsolicited",
    21: "Disable Unsolicited",
    22: "Assign Class",
    23: "Delay Measure",
    24: "Record Current Time",
    25: "Open File",
    26: "Close File",
    27: "Delete File",
    28: "Get File Info",
    29: "Rename File",
    30: "Authenticate",
    31: "Request Change",
    32: "Transfer Block",
    33: "Authenticate Status",
    34: "Authorized Request",
    35: "Request Key Status",
    36: "Change Key",
    129: "Response",
    130: "Unsolicited Response",
    131: "Authenticate Reply",
}

# DNP3 application-layer flags (byte 1 of the App Control field).
DNP3_APP_FIR = 0x80  # First fragment
DNP3_APP_FIN = 0x40  # Final fragment
DNP3_APP_CON = 0x20  # Confirmation required
DNP3_APP_UNS = 0x10  # Unsolicited
DNP3_APP_SEQ_MASK = 0x0F  # Application sequence number


def _dnp3_crc(data):
    """Compute the DNP3 CRC-16 checksum for a block of bytes."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return crc & 0xFFFF


def decodeDNP3(rawPayload):
    """Decode a DNP3 link-layer frame from raw payload bytes.

    Returns a dict with human-readable and dotted keys, or ``None``
    if the payload does not match the DNP3 wire format.
    """
    try:
        if len(rawPayload) < 10:
            return None

        # DNP3 frames always start with 0x05 0x64
        if rawPayload[0] != 0x05 or rawPayload[1] != 0x64:
            return None

        length = rawPayload[2]
        control = rawPayload[3]
        dest = struct.unpack_from("<H", rawPayload, 4)[0]
        src = struct.unpack_from("<H", rawPayload, 6)[0]

        # Validate length: at least 5 (control+dest+src) and the total frame
        # should be 2 (start) + 1 (length) + length + 2 (header CRC)
        if length < 5:
            return None

        dir_bit = bool(control & 0x80)
        prm_bit = bool(control & 0x40)
        # bits 3-4 → function code (but DNP3 spec uses bits 3-4 with some shifts)
        link_func = (control >> 2) & 0x0F
        link_func_name = DNP3_LINK_FUNCTIONS.get(
            link_func, "Unknown (0x{:02x})".format(link_func)
        )

        # FCB and FCV bits
        fcb = bool(control & 0x20)
        fcv = bool(control & 0x10)

        result = {
            "Start Bytes": "0x0564",
            "dnp3.start": "0x0564",
            "Length": length,
            "dnp3.length": length,
            "Control": "0x{:02x}".format(control),
            "dnp3.control": "0x{:02x}".format(control),
            "Direction": "Master→Outstation" if dir_bit else "Outstation→Master",
            "dnp3.direction": "master_to_outstation" if dir_bit else "outstation_to_master",
            "From Primary": prm_bit,
            "dnp3.prm": prm_bit,
            "Link Function": link_func_name,
            "dnp3.link_func": link_func_name,
            "FCB": fcb,
            "dnp3.fcb": fcb,
            "FCV": fcv,
            "dnp3.fcv": fcv,
            "Destination": dest,
            "dnp3.dest": dest,
            "Source": src,
            "dnp3.source": src,
        }

        # The header CRC covers bytes 0-9 (start + length + control + dest + src)
        # Check it if we have enough data
        if len(rawPayload) >= 12:
            header_crc_stored = struct.unpack_from("<H", rawPayload, 8)[0]
            header_crc_calc = _dnp3_crc(rawPayload[0:8])
            result["Header CRC"] = "0x{:04x}".format(header_crc_stored)
            result["dnp3.header_crc"] = "0x{:04x}".format(header_crc_stored)
            result["Header CRC Valid"] = header_crc_stored == header_crc_calc
            result["dnp3.header_crc_valid"] = header_crc_stored == header_crc_calc

        # Try to parse the application layer (transport + application)
        # The data block starts at byte 10, with its own CRC every 16 bytes.
        # The first byte of the first data block is the transport layer
        # header (FIR/FIN/SEQ), followed by the application control byte
        # and function code.
        data_start = 10
        if len(rawPayload) > data_start + 2:
            # Transport header (1 byte): FIR(1) | FIN(1) | SEQ(6)
            transport_header = rawPayload[data_start]
            app_offset = data_start + 1
            if app_offset + 1 < len(rawPayload):
                app_control = rawPayload[app_offset]
                app_func = rawPayload[app_offset + 1]
                app_func_name = DNP3_APP_FUNCTIONS.get(
                    app_func, "Unknown (0x{:02x})".format(app_func)
                )

                is_fir = bool(app_control & DNP3_APP_FIR)
                is_fin = bool(app_control & DNP3_APP_FIN)
                is_con = bool(app_control & DNP3_APP_CON)
                is_uns = bool(app_control & DNP3_APP_UNS)
                app_seq = app_control & DNP3_APP_SEQ_MASK

                result["Transport Header"] = "0x{:02x}".format(transport_header)
                result["dnp3.transport_header"] = "0x{:02x}".format(transport_header)
                result["App Control"] = "0x{:02x}".format(app_control)
                result["dnp3.app_control"] = "0x{:02x}".format(app_control)
                result["App Function Code"] = app_func
                result["dnp3.app_func_code"] = app_func
                result["App Function Name"] = app_func_name
                result["dnp3.app_func_name"] = app_func_name
                result["App FIR"] = is_fir
                result["dnp3.app_fir"] = is_fir
                result["App FIN"] = is_fin
                result["dnp3.app_fin"] = is_fin
                result["App Confirm"] = is_con
                result["dnp3.app_con"] = is_con
                result["App Unsolicited"] = is_uns
                result["dnp3.app_uns"] = is_uns
                result["App Sequence"] = app_seq
                result["dnp3.app_seq"] = app_seq

                # Try to parse object header (for Read/Write/Response etc.)
                # Object header: Group (1) + Variation (1) + Qualifier (1) + ...
                if app_offset + 4 < len(rawPayload) and app_func in (1, 2, 129, 130):
                    group = rawPayload[app_offset + 2]
                    variation = rawPayload[app_offset + 3]
                    qualifier = rawPayload[app_offset + 4]
                    result["Object Group"] = group
                    result["dnp3.obj_group"] = group
                    result["Object Variation"] = variation
                    result["dnp3.obj_variation"] = variation
                    result["Qualifier"] = "0x{:02x}".format(qualifier)
                    result["dnp3.qualifier"] = "0x{:02x}".format(qualifier)

        # Include a hex preview of the full frame
        result["Frame Hex"] = rawPayload[: min(len(rawPayload), 128)].hex()
        result["dnp3.frame_hex"] = rawPayload[: min(len(rawPayload), 128)].hex()

        return result
    except Exception:
        return None