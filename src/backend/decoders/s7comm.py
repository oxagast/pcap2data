"""S7comm (S7 Communication) protocol decoder for PacketSnitch backend.

Decodes Siemens S7comm protocol messages carried over ISO-on-TCP
(RFC 1006 TPKT + COTP), typically on TCP port 102.

Frame structure:
  - TPKT header (4 bytes): Version(1)=0x03, Reserved(1)=0x00, Length(2, BE)
  - COTP DT header (variable, typically 2-3 bytes for Class 0)
  - S7comm header:
    - Protocol ID  (1 byte, 0x32)
    - ROSCTR       (1 byte, job type: 1=Job, 2=Ack, 3=Ack-Data, 7=Userdata)
    - Redundancy   (2 bytes, reserved)
    - PDU Reference(2 bytes, sequence number)
    - Parameter    (variable, depending on header type)

This decoder follows the same dual-key dict pattern as the other
decoders, returning a dict on success or ``None`` on mismatch.
"""

import struct

# S7comm protocol types (ROSCTR field).
S7COMM_TYPES = {
    1: "Job (Request)",
    2: "Ack",
    3: "Ack-Data (Response)",
    7: "Userdata (Diagnostic)",
}

# S7comm parameter function codes (first byte of the parameter area).
S7COMM_PARAM_FUNCTIONS = {
    0x00: "Userdata / Cyclic Services",
    0x04: "Read Var",
    0x05: "Write Var",
    0xF0: "Setup Communication",
    0x28: "Request Download",
    0x29: "Download Block",
    0x2A: "Download Ended",
    0x2B: "Start Upload",
    0x2C: "Upload",
    0x2D: "End Upload",
    0x2E: "Start Program",
    0x2F: "Stop Program",
    0x38: "PI Service (Program Invoke)",
    0x39: "PPI Service (Program Invoke)",
    0x3C: "List Blocks",
    0x3D: "List Blocks of Type",
    0x3E: "Get Block Info",
}

# Transport size codes used in Read/Write parameter headers.
S7COMM_TRANSPORT_SIZES = {
    0x00: "BIT",
    0x01: "BYTE",
    0x02: "CHAR",
    0x03: "WORD",
    0x04: "INT",
    0x05: "DWORD",
    0x06: "DINT",
    0x07: "REAL",
    0x08: "DATE",
    0x09: "TIME_OF_DAY",
    0x0A: "TIME",
    0x0B: "S5TIME",
    0x0C: "DATE_AND_TIME",
    0x0D: "COUNTER",
    0x0E: "TIMER",
    0x1C: "IEC_COUNTER",
    0x1D: "IEC_TIMER",
    0x1E: "IEC_BCOUNTER",
    0x1F: "HTIMER (HH:MM:SS:MS)",
}

# Error codes from Ack-Data responses (S7comm error class 0x85).
S7COMM_ERROR_CODES = {
    0x01: "No S5 area defined for this address",
    0x02: "S5 area does not exist",
    0x03: "S5 area protected",
    0x04: "S5 area not available (module missing)",
    0x05: "S5 segment missing",
    0x06: "S5 subsystem not in current configuration",
    0x07: "S5 file not available",
    0x08: "S5 data block not available",
    0x09: "S5 data block exists already",
    0x0A: "S5 block exists already",
    0x0B: "S5 block exists, but is protected",
    0x0C: "S5 block exists, but block size mismatch",
    0x0D: "S5 block exists, but has wrong load format",
    0x0E: "S5 block exists, but has wrong type",
    0x0F: "S5 link already exists",
    0x10: "S5 link not available",
    0x11: "S5 no link available",
    0x12: "S5 operand range exceeded",
    0x13: "S5 access not permitted",
    0x14: "S5 data type not valid",
    0x85: "General error (see error code byte)",
    0xD2: "General error: block exists",
    0xD5: "General error: block does not exist",
    0xD6: "General error: block is not in correct state",
    0xD7: "General error: block is protected",
    0xDA: "General error: block not available",
    0xE2: "General error: access not permitted",
    0xED: "General error: password not entered",
    0xFC: "General error: access not permitted",
    0xFF: "General error: no password set",
}


def decodeS7comm(rawPayload):
    """Decode an S7comm message from raw payload bytes.

    The payload is expected to include the TPKT + COTP framing that
    wraps S7comm over TCP port 102. Returns a dict on success or
    ``None`` if the bytes do not match.
    """
    try:
        if len(rawPayload) < 10:
            return None

        # TPKT header: Version=3, Reserved=0, Length (2 bytes BE)
        tpkt_version = rawPayload[0]
        tpkt_reserved = rawPayload[1]
        tpkt_length = struct.unpack_from(">H", rawPayload, 2)[0]

        # TPKT version must be 3
        if tpkt_version != 0x03 or tpkt_reserved != 0x00:
            return None
        # Length must be at least 7 (TPKT 4 + COTP 2 + S7 header 1)
        if tpkt_length < 7:
            return None

        # COTP DT PDU header (typically 2 bytes for Class 0: length=2, PDU type=0xF0)
        cotp_len = rawPayload[4]
        cotp_type = rawPayload[5]

        # COTP DT PDU type 0xF0 = Data Transfer
        if cotp_type != 0xF0:
            # Could be a COTP connection request/confirm (CR/CC) — still valid S7 framing
            # but not an S7comm data message. We'll still parse the TPKT/COTP layer.
            result = {
                "TPKT Version": tpkt_version,
                "s7comm.tpkt_version": tpkt_version,
                "TPKT Length": tpkt_length,
                "s7comm.tpkt_length": tpkt_length,
                "COTP Length": cotp_len,
                "s7comm.cotp_length": cotp_len,
                "COTP Type": "0x{:02x}".format(cotp_type),
                "s7comm.cotp_type": "0x{:02x}".format(cotp_type),
                "COTP Type Name": _cotp_type_name(cotp_type),
                "s7comm.cotp_type_name": _cotp_type_name(cotp_type),
                "Type": "COTP (non-data)",
                "s7comm.type": "cotp_non_data",
            }
            # Include hex preview
            result["Frame Hex"] = rawPayload[: min(len(rawPayload), 128)].hex()
            result["s7comm.frame_hex"] = rawPayload[: min(len(rawPayload), 128)].hex()
            return result

        # COTP header length can be 2 (no extra bytes) or longer
        s7_start = 4 + 1 + cotp_len  # TPKT(4) + COTP length byte + COTP data
        if cotp_len < 2:
            s7_start = 6  # minimal: TPKT(4) + COTP(2)

        if len(rawPayload) < s7_start + 10:
            return None

        # S7comm header: Protocol ID (0x32) + ROSCTR + Redundancy(2) + PDU Ref(2) + ...
        proto_id = rawPayload[s7_start]
        if proto_id != 0x32:
            return None

        rosctr = rawPayload[s7_start + 1]
        redundancy = struct.unpack_from(">H", rawPayload, s7_start + 2)[0]
        pdu_ref = struct.unpack_from(">H", rawPayload, s7_start + 4)[0]

        rosctr_name = S7COMM_TYPES.get(
            rosctr, "Unknown (0x{:02x})".format(rosctr)
        )

        result = {
            "TPKT Version": tpkt_version,
            "s7comm.tpkt_version": tpkt_version,
            "TPKT Length": tpkt_length,
            "s7comm.tpkt_length": tpkt_length,
            "COTP Length": cotp_len,
            "s7comm.cotp_length": cotp_len,
            "COTP Type": "0x{:02x}".format(cotp_type),
            "s7comm.cotp_type": "0x{:02x}".format(cotp_type),
            "COTP Type Name": _cotp_type_name(cotp_type),
            "s7comm.cotp_type_name": _cotp_type_name(cotp_type),
            "Protocol ID": "0x32",
            "s7comm.proto_id": "0x32",
            "ROSCTR": rosctr,
            "s7comm.rosctr": rosctr,
            "Message Type": rosctr_name,
            "s7comm.msg_type": rosctr_name,
            "Redundancy": redundancy,
            "s7comm.redundancy": redundancy,
            "PDU Reference": pdu_ref,
            "s7comm.pdu_ref": pdu_ref,
            "Type": rosctr_name,
            "s7comm.type": "job" if rosctr == 1 else ("ack_data" if rosctr == 3 else "other"),
        }

        # Parse parameter area.
        # For both Job (1) and Ack-Data (3), the S7comm header has:
        #   ss+6..7: param_len (2 bytes BE)
        #   ss+8..9: data_len (2 bytes BE)
        # For Ack-Data (3) only, error_class and error_code follow:
        #   ss+10: error_class
        #   ss+11: error_code
        # The parameter data starts at ss+10 for Job, ss+12 for Ack-Data.
        param_offset = s7_start + 10
        if rosctr in (1, 3, 7):
            if len(rawPayload) >= s7_start + 10:
                param_len = struct.unpack_from(">H", rawPayload, s7_start + 6)[0]
                data_len = struct.unpack_from(">H", rawPayload, s7_start + 8)[0]
                result["Parameter Length"] = param_len
                result["s7comm.param_len"] = param_len
                result["Data Length"] = data_len
                result["s7comm.data_len"] = data_len

                # For Ack-Data (rosctr=3), parse error class and error code
                if rosctr == 3 and len(rawPayload) >= s7_start + 12:
                    error_class = rawPayload[s7_start + 10]
                    error_code = rawPayload[s7_start + 11]
                    param_offset = s7_start + 12
                    if error_class != 0x00 or error_code != 0x00:
                        error_name = S7COMM_ERROR_CODES.get(
                            error_code,
                            "Unknown (0x{:02x})".format(error_code),
                        )
                        result["Error Class"] = "0x{:02x}".format(error_class)
                        result["s7comm.error_class"] = "0x{:02x}".format(error_class)
                        result["Error Code"] = "0x{:02x}".format(error_code)
                        result["s7comm.error_code"] = "0x{:02x}".format(error_code)
                        result["Error Name"] = error_name
                        result["s7comm.error_name"] = error_name

                # Parse the parameter field for function code
                if len(rawPayload) > param_offset:
                    param_head = rawPayload[param_offset]
                    if param_head in S7COMM_PARAM_FUNCTIONS:
                        func_name = S7COMM_PARAM_FUNCTIONS[param_head]
                        result["Parameter Function"] = func_name
                        result["s7comm.param_func"] = func_name

                    # For Setup Communication (0xF0), parse the communication params
                    if param_head == 0xF0 and len(rawPayload) >= param_offset + 8:
                        # Reserved(1) + Reserved(1) + AMQ Caller(2) + AMQ Called(2) + PDU Size(2)
                        amq_caller = struct.unpack_from(">H", rawPayload, param_offset + 2)[0]
                        amq_called = struct.unpack_from(">H", rawPayload, param_offset + 4)[0]
                        pdu_size = struct.unpack_from(">H", rawPayload, param_offset + 6)[0]
                        result["Max AMQ Caller"] = amq_caller
                        result["s7comm.max_amq_caller"] = amq_caller
                        result["Max AMQ Called"] = amq_called
                        result["s7comm.max_amq_called"] = amq_called
                        result["Negotiated PDU Size"] = pdu_size
                        result["s7comm.pdu_size"] = pdu_size

        # Include hex preview
        result["Frame Hex"] = rawPayload[: min(len(rawPayload), 128)].hex()
        result["s7comm.frame_hex"] = rawPayload[: min(len(rawPayload), 128)].hex()

        return result
    except Exception:
        return None


def _cotp_type_name(cotp_type):
    """Return a human-readable name for a COTP PDU type."""
    names = {
        0xE0: "CR (Connection Request)",
        0xD0: "CC (Connection Confirm)",
        0x80: "DR (Disconnect Request)",
        0xC0: "DC (Disconnect Confirm)",
        0x70: "DT (Data Transfer)",
        0xF0: "DT (Data Transfer, Class 0)",
        0xA0: "DA (Data Ack)",
    }
    return names.get(cotp_type, "Unknown (0x{:02x})".format(cotp_type))