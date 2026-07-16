def decodeSMPP(rawPayload):
    """
    Decode SMPP PDU headers from raw payload bytes.
    """
    import struct

    SMPP_COMMANDS = {
        0x00000001: "bind_receiver",
        0x00000002: "bind_transmitter",
        0x00000003: "query_sm",
        0x00000004: "submit_sm",
        0x00000005: "deliver_sm",
        0x00000006: "unbind",
        0x00000007: "replace_sm",
        0x00000008: "cancel_sm",
        0x00000009: "bind_transceiver",
        0x0000000B: "outbind",
        0x00000015: "enquire_link",
        0x00000021: "submit_multi",
        0x00000102: "alert_notification",
        0x00000103: "data_sm",
    }

    try:
        if len(rawPayload) < 16:
            return None

        commandLength, commandId, commandStatus, sequenceNumber = struct.unpack(
            ">IIII", rawPayload[:16]
        )

        if commandLength < 16 or commandLength > len(rawPayload):
            return None

        baseCommandId = commandId & 0x7FFFFFFF
        commandName = SMPP_COMMANDS.get(baseCommandId)
        if not commandName:
            return None

        isResponse = bool(commandId & 0x80000000)
        payloadLength = commandLength - 16

        return {
            "Command Length": int(commandLength),
            "smpp.command_length": int(commandLength),
            "Command ID": f"0x{commandId:08X}",
            "smpp.command_id": f"0x{commandId:08X}",
            "Command": commandName,
            "smpp.command": commandName,
            "Is Response": isResponse,
            "smpp.is_response": isResponse,
            "Command Status": int(commandStatus),
            "smpp.command_status": int(commandStatus),
            "Sequence Number": int(sequenceNumber),
            "smpp.sequence": int(sequenceNumber),
            "Body Length": int(payloadLength),
            "smpp.body_length": int(payloadLength),
        }
    except Exception:
        return None
