// OSPF Conv decoder: parses OSPFv2 (RFC 2328) and OSPFv3 (RFC 5340) messages
// carried directly over IP (protocol number 89). Identifies messages by the
// version byte (2 for OSPFv2, 3 for OSPFv3) and decodes the header plus
// Hello / Database Description / Link State Update specifics.

const OSPF_VERSIONS = { 2: "OSPFv2", 3: "OSPFv3" };

const OSPF_TYPES = {
    1: "Hello",
    2: "Database Description",
    3: "Link State Request",
    4: "Link State Update",
    5: "Link State ACK",
};

const OSPF_AUTH_TYPES = {
    0: "None",
    1: "Simple Password",
    2: "Cryptographic (MD5)",
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

function decodeOspfFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 16) return null;

    const version = bytes[0];
    if (version !== 2 && version !== 3) return null;

    const versionName = OSPF_VERSIONS[version] || `OSPFv${version}`;
    const msgType = bytes[1];
    const typeName = OSPF_TYPES[msgType] || `Unknown (${msgType})`;
    const pktLen = readUint16BE(bytes, 2);

    const fields = [
        { name: "Version", value: versionName },
        { name: "Type", value: typeName },
        { name: "Packet Length", value: pktLen },
    ];

    if (version === 2) {
        if (bytes.length < 24) return null;
        const routerId = formatIpv4(bytes, 4);
        const areaId = formatIpv4(bytes, 8);
        const checksum = readUint16BE(bytes, 12);
        const authType = readUint16BE(bytes, 14);
        const authTypeName = OSPF_AUTH_TYPES[authType] || `Unknown (${authType})`;
        fields.push(
            { name: "Router ID", value: routerId },
            { name: "Area ID", value: areaId },
            { name: "Checksum", value: `0x${checksum.toString(16).padStart(4, "0")}` },
            { name: "Auth Type", value: authTypeName },
        );

        // Hello
        if (msgType === 1 && bytes.length >= 44) {
            const networkMask = formatIpv4(bytes, 24);
            const helloInterval = readUint16BE(bytes, 28);
            const options = bytes[30];
            const priority = bytes[31];
            const deadInterval = readUint32BE(bytes, 32);
            const dr = formatIpv4(bytes, 36);
            const bdr = formatIpv4(bytes, 40);
            fields.push(
                { name: "Network Mask", value: networkMask },
                { name: "Hello Interval (s)", value: helloInterval },
                { name: "Options", value: `0x${options.toString(16).padStart(2, "0")}` },
                { name: "Router Priority", value: priority },
                { name: "Dead Interval (s)", value: deadInterval },
                { name: "Designated Router", value: dr },
                { name: "Backup Designated Router", value: bdr },
            );
            // Active neighbors
            const neighbors = [];
            let off = 44;
            while (off + 4 <= bytes.length) {
                neighbors.push(formatIpv4(bytes, off));
                off += 4;
            }
            if (neighbors.length) {
                fields.push({ name: "Neighbor Count", value: neighbors.length });
                neighbors.forEach((n, i) => {
                    fields.push({ name: `Neighbor ${i + 1}`, value: n });
                });
            }
        } else if (msgType === 2 && bytes.length >= 32) {
            // Database Description
            const mtu = readUint16BE(bytes, 24);
            const options = bytes[26];
            const flags = bytes[27];
            const seqNum = readUint32BE(bytes, 28);
            const flagNames = [];
            if (flags & 0x01) flagNames.push("MS");
            if (flags & 0x02) flagNames.push("M");
            if (flags & 0x04) flagNames.push("I");
            fields.push(
                { name: "Interface MTU", value: mtu },
                { name: "Options", value: `0x${options.toString(16).padStart(2, "0")}` },
                { name: "DD Flags", value: flagNames.length ? flagNames.join(" | ") : "None" },
                { name: "DD Sequence", value: seqNum },
            );
        } else if (msgType === 4 && bytes.length >= 28) {
            const lsaCount = readUint32BE(bytes, 24);
            fields.push({ name: "LSA Count", value: lsaCount });
        }
    } else {
        // OSPFv3 (16-byte header)
        if (bytes.length < 16) return null;
        const routerId = formatIpv4(bytes, 4);
        const areaId = formatIpv4(bytes, 8);
        const checksum = readUint16BE(bytes, 12);
        const instanceId = bytes[14];
        fields.push(
            { name: "Router ID", value: routerId },
            { name: "Area ID", value: areaId },
            { name: "Checksum", value: `0x${checksum.toString(16).padStart(4, "0")}` },
            { name: "Instance ID", value: instanceId },
        );
        // OSPFv3 Hello
        if (msgType === 1 && bytes.length >= 36) {
            const interfaceId = readUint32BE(bytes, 16);
            const priority = bytes[20];
            const options = readUint32BE(bytes, 21) & 0x00ffffff;
            const helloInterval = readUint16BE(bytes, 24);
            const deadInterval = readUint16BE(bytes, 26);
            const dr = formatIpv4(bytes, 28);
            const bdr = formatIpv4(bytes, 32);
            fields.push(
                { name: "Interface ID", value: interfaceId },
                { name: "Router Priority", value: priority },
                { name: "Options", value: `0x${options.toString(16).padStart(6, "0")}` },
                { name: "Hello Interval (s)", value: helloInterval },
                { name: "Dead Interval (s)", value: deadInterval },
                { name: "Designated Router", value: dr },
                { name: "Backup Designated Router", value: bdr },
            );
        } else if (msgType === 4 && bytes.length >= 20) {
            const lsaCount = readUint32BE(bytes, 16);
            fields.push({ name: "LSA Count", value: lsaCount });
        }
    }

    fields.push({ name: "Frame Hex", value: hexPreview(bytes) });
    return { protocol: "OSPF", fields };
}

module.exports = { decodeOspfFromBytes };