def decodeMQTT(rawPayload):
    """
    Decode MQTT protocol messages from raw payload bytes.
    """
    import struct

    MQTT_TYPES = {
        1: "CONNECT",
        2: "CONNACK",
        3: "PUBLISH",
        4: "PUBACK",
        5: "PUBREC",
        6: "PUBREL",
        7: "PUBCOMP",
        8: "SUBSCRIBE",
        9: "SUBACK",
        10: "UNSUBSCRIBE",
        11: "UNSUBACK",
        12: "PINGREQ",
        13: "PINGRESP",
        14: "DISCONNECT",
    }
    try:
        if len(rawPayload) < 2:
            return None
        firstByte = rawPayload[0]
        msgType = (firstByte >> 4) & 0x0F
        if msgType not in MQTT_TYPES:
            return None
        flags = firstByte & 0x0F
        qos = (flags >> 1) & 0x03
        dup = bool(flags & 0x08)
        retain = bool(flags & 0x01)
        typeName = MQTT_TYPES[msgType]
        result = {
            "Message Type": typeName,
            "mqtt.msg_type": typeName,
            "QoS": qos,
            "mqtt.qos": qos,
            "DUP Flag": dup,
            "mqtt.dup": dup,
            "Retain Flag": retain,
            "mqtt.retain": retain,
        }
        if msgType == 3 and len(rawPayload) > 4:
            idx = 1
            shift = 0
            while idx < len(rawPayload):
                b = rawPayload[idx]
                idx += 1
                shift += 7
                if not (b & 0x80):
                    break
            if idx + 2 <= len(rawPayload):
                topicLen = struct.unpack_from(">H", rawPayload, idx)[0]
                topic = rawPayload[idx + 2 : idx + 2 + topicLen].decode(errors="ignore")
                result["Topic"] = topic
                result["mqtt.topic"] = topic
        return result
    except Exception:
        return None
