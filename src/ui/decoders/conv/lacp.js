// LACP Conv decoder: parses LACP / Marker frames (IEEE 802.3ad / 802.1AX)
// carried directly over Ethernet EtherType 0x8809. Identifies messages by the
// Slow Protocols subtype (0x01=LACP, 0x02=Marker) and decodes the Actor,
// Partner, and Collector TLVs.

const LACP_SUBTYPES = {
    0x01: "LACP",
    0x02: "Marker Protocol",
};

const LACP_STATE_BITS = {
    0x01: "Activity",
    0x02: "Timeout",
    0x04: "Aggregation",
    0x08: "Synchronization",
    0x10: "Collecting",
    0x20: "Distributing",
    0x40: "Defaulted",
    0x80: "Expired",
};

function readUint16BE(bytes, offset) {
    return (bytes[offset] << 8) | bytes[offset + 1];
}

function decodeStateFlags(state) {
    const flags = [];
    for (const bit of Object.keys(LACP_STATE_BITS)) {
        const mask = parseInt(bit, 10);
        if (state & mask) flags.push(LACP_STATE_BITS[bit]);
    }
    return flags.length ? flags.join(" | ") : "None";
}

function decodeActorPartnerTlv(bytes, offset, role) {
    if (bytes.length < offset + 20) return [];
    const sysPriority = readUint16BE(bytes, offset + 2);
    const system = bytes.slice(offset + 4, offset + 10);
    const systemStr = Array.from(system).map((b) => b.toString(16).padStart(2, "0")).join(":");
    const key = readUint16BE(bytes, offset + 10);
    const portPriority = readUint16BE(bytes, offset + 12);
    const port = readUint16BE(bytes, offset + 14);
    const state = bytes[offset + 16];
    return [
        { name: `${role} TLV Type`, value: bytes[offset] },
        { name: `${role} TLV Length`, value: bytes[offset + 1] },
        { name: `${role} System Priority`, value: sysPriority },
        { name: `${role} System`, value: systemStr },
        { name: `${role} Key`, value: key },
        { name: `${role} Port Priority`, value: portPriority },
        { name: `${role} Port`, value: port },
        { name: `${role} State`, value: decodeStateFlags(state) },
        { name: `${role} State Code`, value: `0x${state.toString(16).padStart(2, "0")}` },
    ];
}

function decodeLacpFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 2) return null;

    const subtype = bytes[0];
    if (subtype !== 0x01 && subtype !== 0x02) return null;

    const version = bytes[1];
    const subtypeName = LACP_SUBTYPES[subtype] || `Unknown (0x${subtype.toString(16).padStart(2, "0")})`;
    const fields = [
        { name: "Subtype", value: subtypeName },
        { name: "Version", value: version },
    ];

    if (bytes.length >= 4) {
        fields.push(...decodeActorPartnerTlv(bytes, 2, "Actor"));
    }
    if (bytes.length >= 42) {
        fields.push(...decodeActorPartnerTlv(bytes, 22, "Partner"));
    }
    // Collector TLV (LACP only, at offset 42)
    if (subtype === 0x01 && bytes.length >= 62) {
        const colType = bytes[42];
        const colLen = bytes[43];
        const maxDelay = readUint16BE(bytes, 44);
        fields.push(
            { name: "Collector TLV Type", value: colType },
            { name: "Collector TLV Length", value: colLen },
            { name: "Collector Max Delay", value: maxDelay },
        );
    }
    return { protocol: "LACP", fields };
}

module.exports = { decodeLacpFromBytes };