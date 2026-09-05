"""gRPC message-envelope decoder for HTTP/2 payloads and port 50051."""

import struct


def _decode_envelopes(raw_payload):
    envelopes = []
    cursor = 0
    while cursor + 5 <= len(raw_payload) and len(envelopes) < 64:
        compressed = raw_payload[cursor]
        length = struct.unpack_from(">I", raw_payload, cursor + 1)[0]
        end = cursor + 5 + length
        if compressed not in (0, 1) or end > len(raw_payload):
            return None
        message = raw_payload[cursor + 5 : end]
        envelopes.append({
            "compressed": bool(compressed),
            "length": length,
            "payload.hex": message[:256].hex(),
            "payload.preview": message[:256].decode("utf-8", errors="replace"),
        })
        cursor = end
    if not envelopes or cursor != len(raw_payload):
        return None
    return envelopes


def decodeGRPC(rawPayload, contentType=""):
    if rawPayload is None or len(rawPayload) < 5:
        return None
    try:
        envelopes = _decode_envelopes(rawPayload)
        if envelopes is None:
            return None
        normalized_type = str(contentType or "").lower()
        result = {
            "Message Count": len(envelopes),
            "grpc.message_count": len(envelopes),
            "Content-Type": contentType or "application/grpc",
            "grpc.content_type": contentType or "application/grpc",
            "Messages": envelopes,
            "grpc.messages": envelopes,
            "Wire length": len(rawPayload),
            "wire.len": len(rawPayload),
        }
        if "grpc-web" in normalized_type:
            result["Profile"] = "gRPC-Web"
            result["grpc.profile"] = "gRPC-Web"
        else:
            result["Profile"] = "gRPC"
            result["grpc.profile"] = "gRPC"
        return result
    except (IndexError, struct.error, TypeError, ValueError):
        return None


def decodeGRPCFromHTTP2(rawPayload):
    """Extract gRPC bytes from HTTP/2 DATA frames and decode their envelopes.

    The capture path delivers individual HTTP/2 frames, so the payload handed
    to this function may be a complete frame rather than a bare gRPC message.
    This intentionally handles the common unpadded DATA-frame form used by
    gRPC over HTTP/2 and rejects malformed/non-DATA input.
    """
    if rawPayload is None or len(rawPayload) < 9:
        return None
    try:
        cursor = 0
        if rawPayload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
            cursor = 24
        data_payload = bytearray()
        data_frame_count = 0
        while cursor + 9 <= len(rawPayload):
            length = int.from_bytes(rawPayload[cursor : cursor + 3], "big")
            frame_type = rawPayload[cursor + 3]
            flags = rawPayload[cursor + 4]
            stream_id = int.from_bytes(rawPayload[cursor + 5 : cursor + 9], "big") & 0x7FFFFFFF
            frame_end = cursor + 9 + length
            if frame_end > len(rawPayload):
                return None
            if frame_type == 0x0 and stream_id != 0:
                frame_payload = rawPayload[cursor + 9 : frame_end]
                if flags & 0x08:
                    if not frame_payload:
                        return None
                    padding_length = frame_payload[0]
                    if padding_length + 1 > len(frame_payload):
                        return None
                    frame_payload = frame_payload[1 : len(frame_payload) - padding_length]
                data_payload.extend(frame_payload)
                data_frame_count += 1
            cursor = frame_end
        if cursor != len(rawPayload) or data_frame_count == 0:
            return None
        return decodeGRPC(bytes(data_payload), "application/grpc")
    except (IndexError, TypeError, ValueError):
        return None
