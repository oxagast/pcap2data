def decodeNFS(rawPayload):
    """
    Decode NFS/RPC packets from raw payload bytes.
    """
    import struct

    RPC_MSG_TYPES = {0: "Call", 1: "Reply"}
    NFS_PROCEDURES = {
        0: "NULL", 1: "GETATTR", 2: "SETATTR", 3: "LOOKUP", 4: "ACCESS", 5: "READLINK",
        6: "READ", 7: "WRITE", 8: "CREATE", 9: "MKDIR", 10: "SYMLINK", 11: "MKNOD",
        12: "REMOVE", 13: "RMDIR", 14: "RENAME", 15: "LINK", 16: "READDIR", 17: "READDIRPLUS",
        18: "FSSTAT", 19: "FSINFO", 20: "PATHCONF", 21: "COMMIT",
    }
    PORTMAP_PROCEDURES = {0: "NULL", 1: "SET", 2: "UNSET", 3: "GETPORT", 4: "DUMP", 5: "CALLIT"}
    RPC_PROGRAMS = {100000: "Portmapper", 100003: "NFS", 100005: "Mount", 100021: "NLM", 100227: "NFS_ACL"}
    try:
        if len(rawPayload) < 8:
            return None
        offset = 0
        if len(rawPayload) >= 4:
            recordMark = struct.unpack_from(">I", rawPayload, 0)[0]
            if recordMark & 0x80000000:
                fragLen = recordMark & 0x7FFFFFFF
                if fragLen > 0 and fragLen + 4 <= len(rawPayload):
                    offset = 4
        if len(rawPayload) < offset + 8:
            return None
        xid = struct.unpack_from(">I", rawPayload, offset)[0]
        msgType = struct.unpack_from(">I", rawPayload, offset + 4)[0]
        if msgType not in RPC_MSG_TYPES:
            return None
        msgTypeName = RPC_MSG_TYPES[msgType]
        result = {
            "XID": f"0x{xid:08X}",
            "rpc.xid": f"0x{xid:08X}",
            "Message Type": msgTypeName,
            "rpc.msg_type": msgTypeName,
        }
        if msgType == 0:
            if len(rawPayload) < offset + 24:
                return None
            rpcVersion = struct.unpack_from(">I", rawPayload, offset + 8)[0]
            program = struct.unpack_from(">I", rawPayload, offset + 12)[0]
            progVersion = struct.unpack_from(">I", rawPayload, offset + 16)[0]
            procedure = struct.unpack_from(">I", rawPayload, offset + 20)[0]
            progName = RPC_PROGRAMS.get(program, f"Prog-{program}")
            if program == 100003:
                procName = NFS_PROCEDURES.get(procedure, f"Proc-{procedure}")
            elif program == 100000:
                procName = PORTMAP_PROCEDURES.get(procedure, f"Proc-{procedure}")
            else:
                procName = f"Proc-{procedure}"
            result.update({
                "RPC Version": rpcVersion,
                "rpc.version": rpcVersion,
                "Program": progName,
                "rpc.program": progName,
                "Program Version": progVersion,
                "rpc.prog_version": progVersion,
                "Procedure": procName,
                "rpc.procedure": procName,
            })
        elif msgType == 1:
            if len(rawPayload) < offset + 12:
                return None
            replyStatus = struct.unpack_from(">I", rawPayload, offset + 8)[0]
            statusName = "Accepted" if replyStatus == 0 else "Denied"
            result["Reply Status"] = statusName
            result["rpc.reply_status"] = statusName
        return result
    except Exception:
        return None
