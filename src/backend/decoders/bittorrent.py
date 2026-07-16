def _decode_peer_id(peer_id_bytes):
    try:
        text = peer_id_bytes.decode("latin-1", errors="ignore")
    except Exception:
        return ""
    cleaned = "".join(ch if 32 <= ord(ch) <= 126 else "." for ch in text)
    return cleaned.strip(".") or ""


def decodeBitTorrent(rawPayload):
    """
    Decode common BitTorrent payload formats.

    Supports:
      - TCP handshake messages
      - TCP peer-wire length-prefixed messages
      - UDP DHT KRPC bencoded messages
    """

    PEER_WIRE_TYPES = {
        0: "choke",
        1: "unchoke",
        2: "interested",
        3: "not interested",
        4: "have",
        5: "bitfield",
        6: "request",
        7: "piece",
        8: "cancel",
        9: "port",
        20: "extended",
    }

    try:
        if not rawPayload:
            return None

        if len(rawPayload) >= 68 and rawPayload[0] == 19:
            proto = rawPayload[1:20]
            if proto == b"BitTorrent protocol":
                reserved = rawPayload[20:28]
                info_hash = rawPayload[28:48]
                peer_id = rawPayload[48:68]
                decoded_peer_id = _decode_peer_id(peer_id)

                result = {
                    "Type": "Handshake",
                    "bittorrent.type": "handshake",
                    "Protocol": "BitTorrent protocol",
                    "bittorrent.protocol": "BitTorrent protocol",
                    "Reserved": reserved.hex(),
                    "bittorrent.reserved": reserved.hex(),
                    "Info Hash": info_hash.hex(),
                    "bittorrent.info_hash": info_hash.hex(),
                    "Peer ID Hex": peer_id.hex(),
                    "bittorrent.peer_id_hex": peer_id.hex(),
                    "bittorrent.signature": "handshake",
                }
                if decoded_peer_id:
                    result["Peer ID"] = decoded_peer_id
                    result["bittorrent.peer_id"] = decoded_peer_id
                return result

        if len(rawPayload) >= 4:
            messageLength = int.from_bytes(rawPayload[0:4], "big", signed=False)
            if messageLength == 0:
                return {
                    "Type": "Peer Wire",
                    "bittorrent.type": "peer_wire",
                    "Message": "keepalive",
                    "bittorrent.message": "keepalive",
                    "Message Length": 0,
                    "bittorrent.length": 0,
                    "bittorrent.signature": "peer_wire",
                }
            if 1 <= messageLength <= len(rawPayload) - 4:
                messageId = int(rawPayload[4])
                messageName = PEER_WIRE_TYPES.get(messageId, f"id_{messageId}")
                return {
                    "Type": "Peer Wire",
                    "bittorrent.type": "peer_wire",
                    "Message": messageName,
                    "bittorrent.message": messageName,
                    "Message ID": int(messageId),
                    "bittorrent.message_id": int(messageId),
                    "Message Length": int(messageLength),
                    "bittorrent.length": int(messageLength),
                    "bittorrent.signature": "peer_wire",
                }

        if len(rawPayload) >= 10:
            text = rawPayload[:256].decode(errors="ignore")
            if text.startswith("d") and ("1:y1:" in text and ("1:q" in text or "1:r" in text)):
                y_value = ""
                y_token = "1:y1:"
                y_pos = text.find(y_token)
                if y_pos >= 0 and y_pos + len(y_token) < len(text):
                    y_value = text[y_pos + len(y_token)]
                query_name = ""
                q_token = "1:q"
                q_pos = text.find(q_token)
                if q_pos >= 0:
                    suffix = text[q_pos + len(q_token) :]
                    colon_pos = suffix.find(":")
                    if colon_pos > 0:
                        try:
                            name_len = int(suffix[:colon_pos])
                            candidate = suffix[colon_pos + 1 : colon_pos + 1 + name_len]
                            if candidate:
                                query_name = candidate
                        except Exception:
                            query_name = ""

                result = {
                    "Type": "DHT KRPC",
                    "bittorrent.type": "dht",
                    "Transaction Type": y_value or "unknown",
                    "bittorrent.transaction_type": y_value or "unknown",
                    "bittorrent.signature": "dht",
                }
                if query_name:
                    result["Query"] = query_name
                    result["bittorrent.query"] = query_name
                return result

        return None
    except Exception:
        return None
