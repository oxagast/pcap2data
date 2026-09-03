// MNDP Conv decoder: parses MikroTik Neighbor Discovery Protocol frames
// carried over UDP port 5678 (broadcast). Identifies messages by the
// 4-byte header (2 unknown + 2 seqno) and the mandatory first TLV type 1
// (MAC Address, length 6) heuristic, then decodes the TLV payload.
//
// Unlike CDP, the MNDP TLV length field is the value length only (it does
// NOT include the 4-byte Type+Length header).

const MNDP_TLV_TYPES = {
    0x0001: "MAC Address",
    0x0005: "Identity",
    0x0007: "Version",
    0x0008: "Platform",
    0x000a: "Uptime",
    0x000b: "Software ID",
    0x000c: "Board",
    0x000e: "Unpack",
    0x000f: "IPv6 Address",
    0x0010: "Interface Name",
    0x0011: "IPv4 Address",
};

const MNDP_UNPACK_VALUES = {
    1: "None",
};

function readUint16BE(bytes, offset) {
    return (bytes[offset] << 8) | bytes[offset + 1];
}

function readUint32BE(bytes, offset) {
    return (
        ((bytes[offset] << 24) |
            (bytes[offset + 1] << 16) |
            (bytes[offset + 2] << 8) |
            bytes[offset + 3]) >>>
        0
    );
}

function formatMac(bytes, offset) {
    const parts = [];
    for (let i = 0; i < 6; i++) {
        parts.push(bytes[offset + i].toString(16).padStart(2, "0"));
    }
    return parts.join(":");
}

function formatIpv4(bytes, offset) {
    return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

function formatIpv6(bytes, offset) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
        parts.push(((bytes[offset + i] << 8) | bytes[offset + i + 1]).toString(16));
    }
    return parts.join(":");
}

function formatUptime(value) {
    // Uptime TLV: 4-byte big-endian centiseconds (1/100 s)
    if (value.length < 4) return null;
    const centis = readUint32BE(value, 0);
    const seconds = centis / 100;
    return `${seconds.toFixed(2)}s`;
}

function decodeMndpFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 8) return null;

    // MNDP header: 2 bytes unknown/preamble + 2 bytes sequence number (BE)
    const seqNo = readUint16BE(bytes, 2);

    const fields = [
        { name: "SeqNo", value: seqNo },
        { name: "Header Unknown", value: Array.from(bytes.slice(0, 2)).map((b) => b.toString(16).padStart(2, "0")).join("") },
    ];

    // Parse TLVs. MNDP TLV length is value-only (excludes the 4-byte T+L).
    let tlvOff = 4;
    let tlvCount = 0;
    let firstTlvType = null;
    while (tlvOff + 4 <= bytes.length) {
        const tlvType = readUint16BE(bytes, tlvOff);
        const tlvLen = readUint16BE(bytes, tlvOff + 2);
        if (tlvOff + 4 + tlvLen > bytes.length) break;
        const tlvValue = bytes.slice(tlvOff + 4, tlvOff + 4 + tlvLen);
        if (firstTlvType === null) firstTlvType = tlvType;
        const tlvName = MNDP_TLV_TYPES[tlvType] || `Unknown (0x${tlvType.toString(16).padStart(4, "0")})`;

        if (tlvType === 0x0001) {
            if (tlvValue.length >= 6) {
                fields.push({ name: "MAC Address", value: formatMac(tlvValue, 0) });
            }
        } else if (tlvType === 0x0005) {
            fields.push({ name: "Identity", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x0007) {
            fields.push({ name: "Version", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x0008) {
            fields.push({ name: "Platform", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x000a) {
            const uptime = formatUptime(tlvValue);
            if (uptime) fields.push({ name: "Uptime", value: uptime });
        } else if (tlvType === 0x000b) {
            fields.push({ name: "Software ID", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x000c) {
            fields.push({ name: "Board", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x000e && tlvValue.length >= 1) {
            const unpackVal = tlvValue[0];
            const unpackName = MNDP_UNPACK_VALUES[unpackVal] || `Unknown (${unpackVal})`;
            fields.push({ name: "Unpack", value: unpackName });
        } else if (tlvType === 0x000f) {
            if (tlvValue.length >= 16) {
                fields.push({ name: "IPv6 Address", value: formatIpv6(tlvValue, 0) });
            }
        } else if (tlvType === 0x0010) {
            fields.push({ name: "Interface Name", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x0011) {
            if (tlvValue.length >= 4) {
                fields.push({ name: "IPv4 Address", value: formatIpv4(tlvValue, 0) });
            }
        }
        tlvOff += 4 + tlvLen;
        tlvCount += 1;
    }

    // Strict gate (mirrors Wireshark's heuristic): the first TLV must be
    // the MAC Address TLV (type 1) with length 6. This prevents random
    // binary data from being accepted as MNDP.
    if (firstTlvType !== 0x0001) return null;

    // A real MNDP frame must have at least one TLV.
    if (tlvCount === 0) return null;

    return { protocol: "MNDP", fields };
}

module.exports = { decodeMndpFromBytes };