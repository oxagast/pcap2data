def decodeTFTP(rawPayload):
    """
    Decode TFTP packets from raw payload bytes.
    """
    import struct

    TFTP_OPCODES = {1: "RRQ", 2: "WRQ", 3: "DATA", 4: "ACK", 5: "ERROR"}
    TFTP_ERRORS = {
        0: "Not defined",
        1: "File not found",
        2: "Access violation",
        3: "Disk full",
        4: "Illegal operation",
        5: "Unknown TID",
        6: "File already exists",
        7: "No such user",
    }
    try:
        if len(rawPayload) < 4:
            return None
        opcode = struct.unpack_from(">H", rawPayload, 0)[0]
        if opcode not in TFTP_OPCODES:
            return None
        opName = TFTP_OPCODES[opcode]
        if opcode in (1, 2):
            rest = rawPayload[2:]
            nullIdx = rest.find(b"\x00")
            filename = (
                rest[:nullIdx].decode(errors="ignore")
                if nullIdx >= 0
                else rest.decode(errors="ignore")
            )
            modeStart = nullIdx + 1 if nullIdx >= 0 else len(rest)
            modeEnd = rest.find(b"\x00", modeStart)
            mode = (
                rest[modeStart:modeEnd].decode(errors="ignore")
                if modeEnd > modeStart
                else "Unknown"
            )
            return {
                "Opcode": opName,
                "tftp.opcode": opName,
                "Filename": filename,
                "tftp.filename": filename,
                "Mode": mode,
                "tftp.mode": mode,
            }
        if opcode == 3:
            block = struct.unpack_from(">H", rawPayload, 2)[0]
            return {
                "Opcode": opName,
                "tftp.opcode": opName,
                "Block Number": block,
                "tftp.block": block,
                "Data Length": len(rawPayload) - 4,
                "tftp.data_len": len(rawPayload) - 4,
            }
        if opcode == 4:
            block = struct.unpack_from(">H", rawPayload, 2)[0]
            return {
                "Opcode": opName,
                "tftp.opcode": opName,
                "Block Number": block,
                "tftp.block": block,
            }
        if opcode == 5:
            errCode = struct.unpack_from(">H", rawPayload, 2)[0]
            errMsg = rawPayload[4:].rstrip(b"\x00").decode(errors="ignore")
            errDesc = TFTP_ERRORS.get(errCode, f"Error {errCode}")
            return {
                "Opcode": opName,
                "tftp.opcode": opName,
                "Error Code": errCode,
                "tftp.error_code": errCode,
                "Error Description": errDesc,
                "tftp.error_desc": errDesc,
                "Error Message": errMsg,
                "tftp.error_msg": errMsg,
            }
        return None
    except Exception:
        return None
