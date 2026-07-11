SIGTRAN_PORT_PROTOCOLS = {
    2904: "M2UA",
    2905: "M3UA",
    2906: "SUA",
    3565: "M2PA",
    9900: "IUA",
}

SCTP_CHUNK_TYPE_NAMES = {
    0: "DATA",
    1: "INIT",
    2: "INIT ACK",
    3: "SACK",
    4: "HEARTBEAT",
    5: "HEARTBEAT ACK",
    6: "ABORT",
    7: "SHUTDOWN",
    8: "SHUTDOWN ACK",
    9: "ERROR",
    10: "COOKIE ECHO",
    11: "COOKIE ACK",
    12: "ECNE",
    13: "CWR",
    14: "SHUTDOWN COMPLETE",
}

M3UA_MESSAGE_CLASS_NAMES = {
    0: "Transfer Messages",
    1: "SS7 Signalling Network Management",
    2: "ASP State Maintenance",
    3: "ASP Traffic Maintenance",
    4: "Routing Key Management",
    5: "ASP Interface Management",
    6: "Error Messages",
    7: "Reserved",
    8: "Network Appearance Management",
}


def _decodeSctpChunks(chunkBytes):
    chunks = []
    firstDataPayload = None
    offset = 0

    while offset + 4 <= len(chunkBytes):
        chunkType = int(chunkBytes[offset])
        chunkFlags = int(chunkBytes[offset + 1])
        chunkLength = int.from_bytes(chunkBytes[offset + 2 : offset + 4], "big")
        if chunkLength < 4 or offset + chunkLength > len(chunkBytes):
            break

        chunkPayload = chunkBytes[offset + 4 : offset + chunkLength]
        chunkName = SCTP_CHUNK_TYPE_NAMES.get(chunkType, f"Type {chunkType}")
        chunkInfo = {
            "sctp.chunk.type": chunkType,
            "sctp.chunk.flags": chunkFlags,
            "sctp.chunk.length": chunkLength,
            "sctp.chunk.type_name": chunkName,
            "sctp.chunk.payload.len": len(chunkPayload),
        }
        if chunkPayload:
            preview = chunkPayload[:32].hex()
            chunkInfo["sctp.chunk.payload.preview"] = preview
        chunks.append(chunkInfo)
        if chunkType == 0 and firstDataPayload is None:
            firstDataPayload = chunkPayload

        offset += (chunkLength + 3) & ~3

    return chunks, firstDataPayload


def decodeSctpPacket(p):
    """
    Decode SCTP transport headers and rudimentary SIGTRAN/M3UA metadata.
    """

    sctpLayer = None
    try:
        if p.haslayer("SCTP"):
            sctpLayer = p["SCTP"]
    except Exception:
        sctpLayer = None

    try:
        if sctpLayer is not None:
            sctpBytes = bytes(sctpLayer)
        else:
            sctpBytes = bytes(p["IP"].payload)
    except Exception:
        return None

    if len(sctpBytes) < 12:
        return None

    try:
        srcPort = int(getattr(sctpLayer, "sport", int.from_bytes(sctpBytes[0:2], "big")))
    except Exception:
        srcPort = int.from_bytes(sctpBytes[0:2], "big")
    try:
        dstPort = int(getattr(sctpLayer, "dport", int.from_bytes(sctpBytes[2:4], "big")))
    except Exception:
        dstPort = int.from_bytes(sctpBytes[2:4], "big")

    verificationTag = int.from_bytes(sctpBytes[4:8], "big")
    checksum = f"0x{sctpBytes[8:12].hex()}"
    chunkBytes = sctpBytes[12:]
    chunks, firstDataPayload = _decodeSctpChunks(chunkBytes)

    sigtranProto = SIGTRAN_PORT_PROTOCOLS.get(srcPort) or SIGTRAN_PORT_PROTOCOLS.get(dstPort)
    if sigtranProto is None and firstDataPayload and len(firstDataPayload) >= 8 and firstDataPayload[0] == 1:
        sigtranProto = "M3UA"

    sigtranSection = None
    if sigtranProto is not None:
        sigtranSection = {
            "sigtran.proto": sigtranProto,
            "sigtran.signaling": "SS7 over SCTP" if sigtranProto in ("M2UA", "M3UA", "SUA", "M2PA", "IUA") else "SCTP adaptation",
        }
        if sigtranProto == "M3UA" and firstDataPayload and len(firstDataPayload) >= 8 and firstDataPayload[0] == 1:
            messageClass = int(firstDataPayload[2])
            messageType = int(firstDataPayload[3])
            messageLength = int.from_bytes(firstDataPayload[4:8], "big")
            sigtranSection.update(
                {
                    "sigtran.version": int(firstDataPayload[0]),
                    "sigtran.reserved": int(firstDataPayload[1]),
                    "sigtran.message.class": messageClass,
                    "sigtran.message.type": messageType,
                    "sigtran.length": messageLength,
                    "sigtran.message.class_name": M3UA_MESSAGE_CLASS_NAMES.get(messageClass, f"Class {messageClass}"),
                }
            )
            if len(firstDataPayload) > 8:
                preview = firstDataPayload[8 : min(len(firstDataPayload), 40)].hex()
                sigtranSection["sigtran.payload.preview"] = preview
                sigtranSection["sigtran.payload.len"] = len(firstDataPayload) - 8
        elif firstDataPayload:
            preview = firstDataPayload[:32].hex()
            sigtranSection["sigtran.payload.len"] = len(firstDataPayload)
            sigtranSection["sigtran.payload.preview"] = preview

    section = {
        "sctp.src.port": srcPort,
        "sctp.dst.port": dstPort,
        "sctp.vtag": verificationTag,
        "sctp.chksum": checksum,
        "sctp.chunk.count": len(chunks),
        "sctp.chunks": [chunk["sctp.chunk.type_name"] for chunk in chunks],
        "wire.len": len(sctpBytes),
        "transport.len": len(sctpBytes),
        "transport.proto": "SCTP",
    }
    if chunks:
        section["sctp.chunk.details"] = chunks
    if sigtranSection is not None:
        section["SIGTRAN"] = sigtranSection

    return section
