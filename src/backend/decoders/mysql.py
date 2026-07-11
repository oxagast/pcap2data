def decodeMySQL(rawPayload):
    """
    Decode MySQL protocol packets from raw payload bytes.
    Handles server greeting (handshake), OK, ERR, and client command packets.
    Returns a dict with packet type and relevant fields, or None if not recognisable.
    """
    import struct

    MYSQL_COMMANDS = {
        0x00: "Sleep",
        0x01: "Quit",
        0x02: "Init DB",
        0x03: "Query",
        0x04: "Field List",
        0x05: "Create DB",
        0x06: "Drop DB",
        0x07: "Refresh",
        0x08: "Shutdown",
        0x09: "Statistics",
        0x0A: "Process Info",
        0x0B: "Connect",
        0x0C: "Process Kill",
        0x0D: "Debug",
        0x0E: "Ping",
        0x0F: "Time",
        0x10: "Delayed Insert",
        0x11: "Change User",
        0x16: "Stmt Prepare",
        0x17: "Stmt Execute",
        0x19: "Stmt Close",
        0x1A: "Stmt Reset",
        0x1C: "Set Option",
        0x1D: "Stmt Fetch",
    }
    try:
        if len(rawPayload) < 5:
            return None
        seqNum = rawPayload[3]
        payload = rawPayload[4:]
        if not payload:
            return None
        firstByte = payload[0]
        if firstByte == 0x0A:
            versionEnd = payload.find(b"\x00", 1)
            version = (
                payload[1:versionEnd].decode(errors="ignore")
                if versionEnd > 1
                else "Unknown"
            )
            return {
                "Type": "Server Greeting",
                "mysql.type": "Server Greeting",
                "Protocol Version": 10,
                "mysql.proto_version": 10,
                "Server Version": version,
                "mysql.server_version": version,
                "Sequence": seqNum,
                "mysql.seq": seqNum,
            }
        if firstByte == 0x00:
            return {
                "Type": "OK",
                "mysql.type": "OK",
                "Sequence": seqNum,
                "mysql.seq": seqNum,
            }
        if firstByte == 0xFF:
            errCode = (
                struct.unpack_from("<H", payload, 1)[0] if len(payload) >= 3 else 0
            )
            errMsg = payload[9:].decode(errors="ignore") if len(payload) > 9 else ""
            return {
                "Type": "Error",
                "mysql.type": "Error",
                "Error Code": errCode,
                "mysql.error_code": errCode,
                "Error Message": errMsg[:100],
                "mysql.error_msg": errMsg[:100],
                "Sequence": seqNum,
                "mysql.seq": seqNum,
            }
        if seqNum == 0 and firstByte in MYSQL_COMMANDS:
            cmdName = MYSQL_COMMANDS[firstByte]
            query = (
                payload[1:].decode(errors="ignore")[:200] if len(payload) > 1 else ""
            )
            return {
                "Type": "Command",
                "mysql.type": "Command",
                "Command": cmdName,
                "mysql.command": cmdName,
                "Query": query,
                "mysql.query": query,
                "Sequence": seqNum,
                "mysql.seq": seqNum,
            }
        return None
    except Exception:
        return None
