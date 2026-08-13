import re


def decodeSSH(rawPayload, srcPort=None, dstPort=None):
    """
    Decode SSH protocol metadata from raw TCP payload bytes.
    """
    SSH_MESSAGE_TYPES = {
        1: "DISCONNECT",
        2: "IGNORE",
        3: "UNIMPLEMENTED",
        4: "DEBUG",
        5: "SERVICE_REQUEST",
        6: "SERVICE_ACCEPT",
        20: "KEXINIT",
        21: "NEWKEYS",
        30: "KEXDH_INIT",
        31: "KEXDH_REPLY",
        50: "USERAUTH_REQUEST",
        51: "USERAUTH_FAILURE",
        52: "USERAUTH_SUCCESS",
        53: "USERAUTH_BANNER",
        80: "GLOBAL_REQUEST",
        81: "REQUEST_SUCCESS",
        82: "REQUEST_FAILURE",
        90: "CHANNEL_OPEN",
        91: "CHANNEL_OPEN_CONFIRMATION",
        92: "CHANNEL_OPEN_FAILURE",
        93: "CHANNEL_WINDOW_ADJUST",
        94: "CHANNEL_DATA",
        95: "CHANNEL_EXTENDED_DATA",
        96: "CHANNEL_EOF",
        97: "CHANNEL_CLOSE",
        98: "CHANNEL_REQUEST",
        99: "CHANNEL_SUCCESS",
        100: "CHANNEL_FAILURE",
    }

    try:
        if not rawPayload or len(rawPayload) == 0:
            return None

        payloadPrefix = rawPayload[:4]
        isBanner = rawPayload.startswith(b"SSH-")

        if isBanner:
            firstLineRaw = rawPayload.split(b"\n", 1)[0].rstrip(b"\r")
            banner = firstLineRaw.decode(errors="ignore").strip()
            m = re.match(r"^SSH-(\d+\.\d+)-([^\s]+)(?:\s+(.*))?$", banner)

            # Infer direction from ports when possible. Prefer explicit SSH
            # ports (22,2222), otherwise use well-known port heuristic
            # (ports <= 1024 are likely servers).
            direction = "Unknown"
            if srcPort in (22, 2222):
                direction = "Server Identification"
            elif dstPort in (22, 2222):
                direction = "Client Identification"
            else:
                try:
                    if srcPort is not None and dstPort is not None:
                        if srcPort <= 1024 and dstPort > 1024:
                            direction = "Server Identification"
                        elif dstPort <= 1024 and srcPort > 1024:
                            direction = "Client Identification"
                except Exception:
                    # fall back to Unknown if ports aren't integers
                    direction = "Unknown"

            if not m:
                return {
                    "Type": "Identification",
                    "ssh.type": "Identification",
                    "Banner": banner,
                    "ssh.banner": banner,
                    "Direction": direction,
                    "ssh.direction": direction,
                }

            protoVersion = m.group(1)
            softwareVersion = m.group(2)
            comments = m.group(3).strip() if m.group(3) else ""
            result = {
                "Type": "Identification",
                "ssh.type": "Identification",
                "Banner": banner,
                "ssh.banner": banner,
                "Protocol Version": protoVersion,
                "ssh.protocol_version": protoVersion,
                "Software Version": softwareVersion,
                "ssh.software_version": softwareVersion,
                "Direction": direction,
                "ssh.direction": direction,
            }
            if comments:
                result["Comments"] = comments
                result["ssh.comments"] = comments
            return result

        if len(rawPayload) < 6:
            return None

        packetLength = int.from_bytes(payloadPrefix, byteorder="big", signed=False)
        if packetLength <= 0 or packetLength > 35000:
            return None

        paddingLength = int(rawPayload[4])
        if paddingLength < 4 or packetLength < (paddingLength + 1):
            return None

        msgTypeNum = int(rawPayload[5])
        msgTypeName = SSH_MESSAGE_TYPES.get(msgTypeNum, f"Unknown({msgTypeNum})")
        knownClearMessage = msgTypeNum in SSH_MESSAGE_TYPES
        return {
            "Type": "Binary Packet",
            "ssh.type": "Binary Packet",
            "Packet Length": packetLength,
            "ssh.packet_length": packetLength,
            "Padding Length": paddingLength,
            "ssh.padding_length": paddingLength,
            "Message Type": msgTypeName,
            "ssh.msg_type": msgTypeName,
            "Message Type Number": msgTypeNum,
            "ssh.msg_type_num": msgTypeNum,
            "Likely Encrypted": not knownClearMessage,
            "ssh.likely_encrypted": not knownClearMessage,
        }
    except Exception:
        return None
