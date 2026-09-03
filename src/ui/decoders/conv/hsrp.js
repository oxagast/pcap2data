// HSRP Conv decoder: parses HSRPv1 (RFC 2281) and HSRPv2 messages carried
// over UDP port 1985. HSRPv1 uses a fixed 20-byte header; HSRPv2 carries a
// TLV payload. Identifies messages by the version byte (0=HSRPv1, 1=HSRPv2
// IPv4, 2=HSRPv2 IPv6).

const HSRP_VERSIONS = { 0: "HSRPv1", 1: "HSRPv2 (IPv4)", 2: "HSRPv2 (IPv6)" };

const HSRP_OPCODES = {
    0: "Hello",
    1: "Coup",
    2: "Resign",
    3: "Advertise",
};

const HSRP_STATES = {
    0: "Initial",
    1: "Learn",
    2: "Listen",
    4: "Speak",
    8: "Standby",
    16: "Active",
};

function readUint16BE(bytes, offset) {
    return (bytes[offset] << 8) | bytes[offset + 1];
}

function formatIpv4(bytes, offset) {
    return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

function hexPreview(bytes, maxLen = 128) {
    if (!bytes || bytes.length === 0) return "";
    const slice = bytes.slice(0, maxLen);
    let hex = "";
    for (let i = 0; i < slice.length; i++) {
        hex += slice[i].toString(16).padStart(2, "0");
    }
    if (bytes.length > maxLen) hex += "…";
    return hex;
}

function decodeHsrpFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 1) return null;

    const version = bytes[0];
    if (version !== 0 && version !== 1 && version !== 2) return null;

    const versionName = HSRP_VERSIONS[version] || `HSRPv${version}`;
    const fields = [{ name: "Version", value: versionName }];

    if (version === 0) {
        // HSRPv1 — 20-byte fixed header
        if (bytes.length < 20) return null;
        const opCode = bytes[1];
        const state = bytes[2];
        const helloTime = bytes[3];
        const holdTime = bytes[4];
        const priority = bytes[5];
        const group = bytes[6];
        const opName = HSRP_OPCODES[opCode] || `Unknown (${opCode})`;
        const stateName = HSRP_STATES[state] || `Unknown (${state})`;
        const authData = new TextDecoder().decode(bytes.slice(8, 16)).replace(/\x00+$/, "");
        const virtualIp = formatIpv4(bytes, 16);
        fields.push(
            { name: "Op Code", value: opName },
            { name: "State", value: stateName },
            { name: "State Code", value: state },
            { name: "Hello Time (s)", value: helloTime },
            { name: "Hold Time (s)", value: holdTime },
            { name: "Priority", value: priority },
            { name: "Group", value: group },
            { name: "Authentication", value: authData || "(empty)" },
            { name: "Virtual IP", value: virtualIp },
        );
    } else {
        // HSRPv2
        if (bytes.length < 8) return null;
        const opCode = bytes[1];
        const state = bytes[2];
        const helloTime = bytes[3];
        const holdTime = bytes[4];
        const priority = bytes[5];
        const group = bytes[6];
        const opName = HSRP_OPCODES[opCode] || `Unknown (${opCode})`;
        const stateName = HSRP_STATES[state] || `Unknown (${state})`;
        fields.push(
            { name: "Op Code", value: opName },
            { name: "State", value: stateName },
            { name: "State Code", value: state },
            { name: "Hello Time (s)", value: helloTime },
            { name: "Hold Time (s)", value: holdTime },
            { name: "Priority", value: priority },
            { name: "Group", value: group },
        );
        // Parse TLVs
        let off = 8;
        let tlvIndex = 0;
        while (off + 4 <= bytes.length) {
            const tlvType = readUint16BE(bytes, off);
            const tlvLen = readUint16BE(bytes, off + 2);
            if (tlvLen === 0) break;
            const value = bytes.slice(off + 4, off + 4 + tlvLen);
            // IPv4 Virtual IP TLV (type 6)
            if (tlvType === 6 && value.length >= 4) {
                fields.push({ name: "Virtual IP", value: formatIpv4(value, 0) });
            }
            tlvIndex++;
            off += 4 + tlvLen;
        }
        if (tlvIndex) {
            fields.push({ name: "TLV Count", value: tlvIndex });
        }
    }

    fields.push({ name: "Frame Hex", value: hexPreview(bytes) });
    return { protocol: "HSRP", fields };
}

module.exports = { decodeHsrpFromBytes };