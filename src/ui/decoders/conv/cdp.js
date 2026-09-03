// CDP Conv decoder: parses Cisco Discovery Protocol frames carried directly
// over Ethernet EtherType 0x88cc (or over 802.2 LLC/SNAP). Identifies messages
// by the version + TTL + checksum header and decodes the TLV payload.

const CDP_TLV_TYPES = {
    0x0001: "Device ID",
    0x0002: "Addresses",
    0x0003: "Port ID",
    0x0004: "Capabilities",
    0x0005: "Software Version",
    0x0006: "Platform",
    0x0007: "IP Network Prefix",
    0x0009: "VTP Management Domain",
    0x000a: "Native VLAN",
    0x000b: "Duplex",
    0x000f: "MTU",
    0x0012: "System Name",
    0x0014: "Management Address",
    0x0015: "Location",
};

const CDP_CAPABILITY_BITS = {
    0x01: "Router",
    0x02: "Transparent Bridge",
    0x04: "Source-Route Bridge",
    0x08: "Network Switch",
    0x10: "Host",
    0x20: "IGMP Capable",
    0x40: "Repeater",
    0x80: "VoIP Phone",
};

const ADDRESS_PROTOCOL_IDS = {
    1: "IPv4",
    2: "802.2 (MAC)",
    6: "IPv6",
    0x11: "IPv4",
    0x0c: "Novell IPX",
};

function readUint16BE(bytes, offset) {
    return (bytes[offset] << 8) | bytes[offset + 1];
}

function readUint32BE(bytes, offset) {
    return (
        (bytes[offset] << 24) |
        (bytes[offset + 1] << 16) |
        (bytes[offset + 2] << 8) |
        bytes[offset + 3]
    );
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

function decodeCapabilitiesTlv(value) {
    if (value.length < 4) return "None";
    const capValue = readUint32BE(value, 0);
    const caps = [];
    for (const bit of Object.keys(CDP_CAPABILITY_BITS)) {
        const mask = parseInt(bit, 10);
        if (capValue & mask) caps.push(CDP_CAPABILITY_BITS[bit]);
    }
    return caps.length ? caps.join(" | ") : "None";
}

function decodeAddressesTlv(value) {
    if (value.length < 4) return [];
    const count = readUint32BE(value, 0);
    const addresses = [];
    let off = 4;
    for (let i = 0; i < count && off + 2 <= value.length; i++) {
        const protoType = value[off];
        const protoLen = value[off + 1];
        if (off + 2 + protoLen + 2 > value.length) break;
        const addrLen = readUint16BE(value, off + 2 + protoLen);
        const addrStart = off + 2 + protoLen + 2;
        const addrValue = value.slice(addrStart, addrStart + addrLen);
        const protoName = ADDRESS_PROTOCOL_IDS[protoType] || `Proto ${protoType}`;
        let addrStr = "";
        if ((protoType === 1 || protoType === 0x11) && addrValue.length >= 4) {
            addrStr = formatIpv4(addrValue, 0);
        } else if (protoType === 6 && addrValue.length >= 16) {
            addrStr = formatIpv6(addrValue, 0);
        } else {
            addrStr = Array.from(addrValue).map((b) => b.toString(16).padStart(2, "0")).join("");
        }
        addresses.push(`${protoName}: ${addrStr}`);
        off = addrStart + addrLen;
    }
    return addresses;
}

function decodeCdpFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4) return null;

    // Skip a SNAP header if present (DSAP=0xAA SSAP=0xAA Control=0x03 OUI 00:00:0C)
    let offset = 0;
    if (bytes.length >= 8 && bytes[0] === 0xaa && bytes[1] === 0xaa && bytes[2] === 0x03) {
        offset = 8;
    }
    if (bytes.length < offset + 4) return null;

    const version = bytes[offset];
    const ttl = bytes[offset + 1];
    const checksum = readUint16BE(bytes, offset + 2);

    // Strict gate for auto-detection: CDP version is always 1 or 2 (per
    // Cisco's spec). Any other value is not a valid CDP frame. This
    // prevents random binary data from being accepted as CDP just
    // because the first 4 bytes happen to parse as a header.
    if (version !== 1 && version !== 2) return null;

    const fields = [
        { name: "Version", value: version },
        { name: "TTL (s)", value: ttl },
        { name: "Checksum", value: `0x${checksum.toString(16).padStart(4, "0")}` },
    ];

    // Parse TLVs
    let tlvOff = offset + 4;
    let tlvCount = 0;
    while (tlvOff + 4 <= bytes.length) {
        const tlvType = readUint16BE(bytes, tlvOff);
        const tlvLen = readUint16BE(bytes, tlvOff + 2);
        if (tlvLen < 4 || tlvOff + tlvLen > bytes.length) break;
        const tlvValue = bytes.slice(tlvOff + 4, tlvOff + tlvLen);
        const tlvName = CDP_TLV_TYPES[tlvType] || `Unknown (0x${tlvType.toString(16).padStart(4, "0")})`;

        if (tlvType === 0x0001) {
            fields.push({ name: "Device ID", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x0002) {
            const addrs = decodeAddressesTlv(tlvValue);
            fields.push({ name: "Addresses", value: addrs.join(", ") || "None" });
        } else if (tlvType === 0x0003) {
            fields.push({ name: "Port ID", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x0004) {
            fields.push({ name: "Capabilities", value: decodeCapabilitiesTlv(tlvValue) });
        } else if (tlvType === 0x0005) {
            fields.push({ name: "Software Version", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x0006) {
            fields.push({ name: "Platform", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x0009) {
            fields.push({ name: "VTP Management Domain", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x000a && tlvValue.length >= 2) {
            fields.push({ name: "Native VLAN", value: readUint16BE(tlvValue, 0) });
        } else if (tlvType === 0x000b && tlvValue.length >= 1) {
            const duplex = tlvValue[0];
            fields.push({ name: "Duplex", value: duplex === 0 ? "Half" : duplex === 1 ? "Full" : `Unknown (${duplex})` });
        } else if (tlvType === 0x000f && tlvValue.length >= 4) {
            fields.push({ name: "MTU", value: readUint32BE(tlvValue, 0) });
        } else if (tlvType === 0x0012) {
            fields.push({ name: "System Name", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        } else if (tlvType === 0x0014) {
            const addrs = decodeAddressesTlv(tlvValue);
            fields.push({ name: "Management Address", value: addrs.join(", ") || "None" });
        } else if (tlvType === 0x0015) {
            fields.push({ name: "Location", value: new TextDecoder().decode(tlvValue).replace(/\x00+$/, "") });
        }
        tlvOff += tlvLen;
        tlvCount += 1;
    }

    // Strict gate: a real CDP frame must have at least one TLV. A frame
    // with just a version/TTL/checksum header and no TLVs is almost
    // certainly not a real CDP message.
    if (tlvCount === 0 && bytes.length > offset + 4) return null;

    return { protocol: "CDP", fields };
}

module.exports = { decodeCdpFromBytes };