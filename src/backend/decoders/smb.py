def decodeSMB(rawPayload):
    """
    Decode SMB (Server Message Block) protocol frames from raw payload bytes.
    Supports both SMBv1 and SMBv2/3.
    """
    import struct

    SMB1_COMMANDS = {
        0x00: "CREATE_DIRECTORY",
        0x01: "DELETE_DIRECTORY",
        0x02: "OPEN",
        0x03: "CREATE",
        0x04: "CLOSE",
        0x05: "FLUSH",
        0x06: "DELETE",
        0x07: "RENAME",
        0x08: "QUERY_INFORMATION",
        0x09: "SET_INFORMATION",
        0x0A: "READ",
        0x0B: "WRITE",
        0x24: "LOCKING_ANDX",
        0x25: "TRANSACTION",
        0x2D: "OPEN_ANDX",
        0x2E: "READ_ANDX",
        0x2F: "WRITE_ANDX",
        0x32: "TRANSACTION2",
        0x70: "TREE_CONNECT",
        0x71: "TREE_DISCONNECT",
        0x72: "NEGOTIATE",
        0x73: "SESSION_SETUP_ANDX",
        0x74: "LOGOFF_ANDX",
        0x75: "TREE_CONNECT_ANDX",
        0xA0: "NT_TRANSACT",
        0xA2: "NT_CREATE_ANDX",
        0xA4: "NT_CANCEL",
        0xFE: "INVALID",
        0xFF: "NO_ANDX",
    }
    SMB2_COMMANDS = {
        0x0000: "NEGOTIATE",
        0x0001: "SESSION_SETUP",
        0x0002: "LOGOFF",
        0x0003: "TREE_CONNECT",
        0x0004: "TREE_DISCONNECT",
        0x0005: "CREATE",
        0x0006: "CLOSE",
        0x0007: "FLUSH",
        0x0008: "READ",
        0x0009: "WRITE",
        0x000A: "LOCK",
        0x000B: "IOCTL",
        0x000C: "CANCEL",
        0x000D: "ECHO",
        0x000E: "QUERY_DIRECTORY",
        0x000F: "CHANGE_NOTIFY",
        0x0010: "QUERY_INFO",
        0x0011: "SET_INFO",
        0x0012: "OPLOCK_BREAK",
    }
    try:
        if len(rawPayload) < 8:
            return None
        if rawPayload[:4] == b"\xff\x53\x4d\x42":
            cmd = rawPayload[4]
            status = struct.unpack_from("<I", rawPayload, 5)[0]
            flags = rawPayload[9]
            cmdName = SMB1_COMMANDS.get(cmd, f"0x{cmd:02X}")
            isResponse = bool(flags & 0x80)
            return {
                "Version": "SMBv1",
                "smb.version": "SMBv1",
                "Command": cmdName,
                "smb.command": cmdName,
                "Status": f"0x{status:08X}",
                "smb.status": f"0x{status:08X}",
                "Is Response": isResponse,
                "smb.is_response": isResponse,
            }
        if rawPayload[:4] == b"\xfe\x53\x4d\x42":
            cmd = struct.unpack_from("<H", rawPayload, 12)[0]
            flags = struct.unpack_from("<I", rawPayload, 16)[0]
            status = struct.unpack_from("<I", rawPayload, 8)[0]
            cmdName = SMB2_COMMANDS.get(cmd, f"0x{cmd:04X}")
            isResponse = bool(flags & 0x00000001)
            return {
                "Version": "SMBv2/v3",
                "smb.version": "SMBv2/v3",
                "Command": cmdName,
                "smb.command": cmdName,
                "Status": f"0x{status:08X}",
                "smb.status": f"0x{status:08X}",
                "Is Response": isResponse,
                "smb.is_response": isResponse,
            }
        return None
    except Exception:
        return None
