def decodeMTP(rawPayload):
    """
    Decode MTP/MMS (Microsoft Media Services over TCP, port 1755) packets.
    Checks for the MMS command identifier prefix (0x00000001 little-endian).
    Returns basic MTP/MMS info dict or None if not recognisable.
    """
    import struct

    MMS_COMMANDS = {
        0x00030001: "CONNECT_REQUEST",
        0x00030002: "CONNECT_RESPONSE",
        0x00030003: "TRANSPORT_INFO_REQUEST",
        0x00030004: "TRANSPORT_INFO_RESPONSE",
        0x00030005: "MEDIA_DETAILS_REQUEST",
        0x00030006: "PLAY_REQUEST",
        0x00030007: "STOP",
        0x00030009: "STREAM_STOPPED",
        0x0004001B: "HEADER",
        0x0004001A: "DATA",
    }
    try:
        if len(rawPayload) < 12:
            return None
        prefix = struct.unpack_from("<I", rawPayload, 0)[0]
        if prefix != 0x00000001:
            return None
        length = struct.unpack_from("<I", rawPayload, 4)[0]
        cmdId = struct.unpack_from("<I", rawPayload, 8)[0]
        cmdName = MMS_COMMANDS.get(cmdId, f"0x{cmdId:08X}")
        return {
            "Protocol": "MMS/MTP",
            "mtp.protocol": "MMS/MTP",
            "Command ID": f"0x{cmdId:08X}",
            "mtp.cmd_id": f"0x{cmdId:08X}",
            "Command": cmdName,
            "mtp.command": cmdName,
            "Length": length,
            "mtp.length": length,
        }
    except Exception:
        return None
