def decodePostgreSQL(rawPayload):
    """
    Decode PostgreSQL frontend/backend protocol messages from raw payload bytes.
    Returns a dict with message type and relevant fields, or None if not recognisable.
    """
    import struct

    PG_BACKEND_TYPES = {
        b"R": "Authentication",
        b"K": "BackendKeyData",
        b"2": "BindComplete",
        b"3": "CloseComplete",
        b"C": "CommandComplete",
        b"d": "CopyData",
        b"c": "CopyDone",
        b"f": "CopyFail",
        b"G": "CopyInResponse",
        b"H": "CopyOutResponse",
        b"D": "DataRow",
        b"I": "EmptyQueryResponse",
        b"E": "ErrorResponse",
        b"V": "FunctionCallResponse",
        b"n": "NoData",
        b"N": "NoticeResponse",
        b"A": "NotificationResponse",
        b"t": "ParameterDescription",
        b"S": "ParameterStatus",
        b"1": "ParseComplete",
        b"s": "PortalSuspended",
        b"Z": "ReadyForQuery",
        b"T": "RowDescription",
    }
    PG_FRONTEND_TYPES = {
        b"B": "Bind",
        b"C": "Close",
        b"d": "CopyData",
        b"c": "CopyDone",
        b"f": "CopyFail",
        b"D": "Describe",
        b"E": "Execute",
        b"H": "Flush",
        b"F": "FunctionCall",
        b"P": "Parse",
        b"p": "Password",
        b"Q": "Query",
        b"S": "Sync",
        b"X": "Terminate",
    }
    try:
        if len(rawPayload) < 5:
            return None
        firstInt = struct.unpack_from(">I", rawPayload, 0)[0]
        if firstInt == len(rawPayload) and len(rawPayload) >= 8:
            protoMajor = struct.unpack_from(">H", rawPayload, 4)[0]
            protoMinor = struct.unpack_from(">H", rawPayload, 6)[0]
            return {
                "Type": "StartupMessage",
                "pg.type": "StartupMessage",
                "Protocol Version": f"{protoMajor}.{protoMinor}",
                "pg.proto_version": f"{protoMajor}.{protoMinor}",
            }
        msgType = rawPayload[0:1]
        if msgType in PG_BACKEND_TYPES:
            typeName = PG_BACKEND_TYPES[msgType]
            msgLen = struct.unpack_from(">I", rawPayload, 1)[0]
            return {
                "Type": typeName,
                "pg.type": typeName,
                "Direction": "Backend",
                "pg.direction": "Backend",
                "Message Length": msgLen,
                "pg.msg_length": msgLen,
            }
        if msgType in PG_FRONTEND_TYPES:
            typeName = PG_FRONTEND_TYPES[msgType]
            msgLen = struct.unpack_from(">I", rawPayload, 1)[0]
            body = (
                rawPayload[5 : 5 + min(msgLen - 4, 200)].decode(errors="ignore")
                if msgLen > 4
                else ""
            )
            return {
                "Type": typeName,
                "pg.type": typeName,
                "Direction": "Frontend",
                "pg.direction": "Frontend",
                "Message Length": msgLen,
                "pg.msg_length": msgLen,
                "Body": body,
                "pg.body": body,
            }
        return None
    except Exception:
        return None
