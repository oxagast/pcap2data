def _decode_smb_text(raw_value, use_unicode=True):
    if not raw_value:
        return ""
    try:
        return raw_value.decode("utf-16le" if use_unicode else "ascii", errors="ignore").rstrip("\x00")
    except Exception:
        return ""


def _parse_ntlm_security_buffer(blob, field_offset):
    import struct

    if len(blob) < field_offset + 8:
        return b""
    value_length, _maximum_length, buffer_offset = struct.unpack_from("<HHI", blob, field_offset)
    if value_length <= 0:
        return b""
    buffer_end = buffer_offset + value_length
    if buffer_offset < 0 or buffer_end > len(blob):
        return b""
    return blob[buffer_offset:buffer_end]


def _parse_ntlmssp_blob(blob):
    import struct

    ntlm_index = blob.find(b"NTLMSSP\x00")
    if ntlm_index == -1:
        return {}

    ntlm_blob = blob[ntlm_index:]
    if len(ntlm_blob) < 12:
        return {}

    message_type = struct.unpack_from("<I", ntlm_blob, 8)[0]
    ntlm_info = {
        "NTLM Message Type": message_type,
        "smb.ntlm.message_type": message_type,
    }

    if message_type == 1:
        ntlm_info["NTLMSSP"] = "NEGOTIATE"
        ntlm_info["smb.ntlm.type"] = "NEGOTIATE"
        return ntlm_info

    if message_type == 2:
        ntlm_info["NTLMSSP"] = "CHALLENGE"
        ntlm_info["smb.ntlm.type"] = "CHALLENGE"
        target_name = _parse_ntlm_security_buffer(ntlm_blob, 12)
        if target_name:
            decoded_target = _decode_smb_text(target_name, use_unicode=True)
            if decoded_target:
                ntlm_info["Target Name"] = decoded_target
                ntlm_info["smb.ntlm.target_name"] = decoded_target
        return ntlm_info

    if message_type != 3:
        ntlm_info["NTLMSSP"] = f"TYPE_{message_type}"
        ntlm_info["smb.ntlm.type"] = f"TYPE_{message_type}"
        return ntlm_info

    flags = struct.unpack_from("<I", ntlm_blob, 60)[0] if len(ntlm_blob) >= 64 else 0
    use_unicode = bool(flags & 0x00000001)
    lm_response = _parse_ntlm_security_buffer(ntlm_blob, 12)
    nt_response = _parse_ntlm_security_buffer(ntlm_blob, 20)
    domain_name = _parse_ntlm_security_buffer(ntlm_blob, 28)
    user_name = _parse_ntlm_security_buffer(ntlm_blob, 36)
    workstation = _parse_ntlm_security_buffer(ntlm_blob, 44)

    ntlm_info["NTLMSSP"] = "AUTHENTICATE"
    ntlm_info["smb.ntlm.type"] = "AUTHENTICATE"

    decoded_domain = _decode_smb_text(domain_name, use_unicode=use_unicode)
    decoded_user = _decode_smb_text(user_name, use_unicode=use_unicode)
    decoded_workstation = _decode_smb_text(workstation, use_unicode=use_unicode)

    if decoded_domain:
        ntlm_info["Domain"] = decoded_domain
        ntlm_info["smb.auth.domain"] = decoded_domain
    if decoded_user:
        ntlm_info["Username"] = decoded_user
        ntlm_info["smb.auth.username"] = decoded_user
    if decoded_workstation:
        ntlm_info["Workstation"] = decoded_workstation
        ntlm_info["smb.auth.workstation"] = decoded_workstation
    if lm_response:
        ntlm_info["LM Response"] = lm_response.hex()
        ntlm_info["smb.auth.lm_response"] = lm_response.hex()
    if nt_response:
        ntlm_info["NTLM Response"] = nt_response.hex()
        ntlm_info["smb.auth.ntlm_response"] = nt_response.hex()
    return ntlm_info


def _normalize_smb_payload(raw_payload):
    if not raw_payload or len(raw_payload) < 4:
        return raw_payload
    if raw_payload[:4] in (b"\xffSMB", b"\xfeSMB"):
        return raw_payload
    if len(raw_payload) > 8 and raw_payload[0] == 0x00 and raw_payload[4:8] in (b"\xffSMB", b"\xfeSMB"):
        return raw_payload[4:]
    return raw_payload


def decodeSMB(rawPayload):
    """
    Decode SMB (Server Message Block) protocol frames from raw payload bytes.
    Supports both SMBv1 and SMBv2/3 and extracts NTLMSSP auth details when present.
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
        normalized_payload = _normalize_smb_payload(rawPayload)
        if len(normalized_payload) < 8:
            return None
        if normalized_payload[:4] == b"\xff\x53\x4d\x42":
            cmd = normalized_payload[4]
            status = struct.unpack_from("<I", normalized_payload, 5)[0]
            flags = normalized_payload[9]
            cmdName = SMB1_COMMANDS.get(cmd, f"0x{cmd:02X}")
            isResponse = bool(flags & 0x80)
            smb_info = {
                "Version": "SMBv1",
                "smb.version": "SMBv1",
                "Command": cmdName,
                "smb.command": cmdName,
                "Status": f"0x{status:08X}",
                "smb.status": f"0x{status:08X}",
                "Is Response": isResponse,
                "smb.is_response": isResponse,
            }
            smb_info.update(_parse_ntlmssp_blob(normalized_payload[32:]))
            return smb_info
        if normalized_payload[:4] == b"\xfe\x53\x4d\x42":
            cmd = struct.unpack_from("<H", normalized_payload, 12)[0]
            flags = struct.unpack_from("<I", normalized_payload, 16)[0]
            status = struct.unpack_from("<I", normalized_payload, 8)[0]
            cmdName = SMB2_COMMANDS.get(cmd, f"0x{cmd:04X}")
            isResponse = bool(flags & 0x00000001)
            smb_info = {
                "Version": "SMBv2/v3",
                "smb.version": "SMBv2/v3",
                "Command": cmdName,
                "smb.command": cmdName,
                "Status": f"0x{status:08X}",
                "smb.status": f"0x{status:08X}",
                "Is Response": isResponse,
                "smb.is_response": isResponse,
            }
            smb_info.update(_parse_ntlmssp_blob(normalized_payload[64:]))
            return smb_info
        return None
    except Exception:
        return None
