// SMB Conv decoder: handles both SMBv1 (0xFF 'SMB' magic) and SMBv2/v3
// (0xFE 'SMB' magic) headers, and adds an NTLMSSP section when the message
// contains a Session Setup auth blob.

const {
    NTLMSSP_MARKER,
    normalizeSmbDecoderBytes,
    findBytesSubsequence,
    parseSmbNtlmSecurityBuffer,
    decodeSmbTextBytes,
    bytesToHexLower,
} = require("./smb-helpers");

const SMB1_COMMANDS = {
    0x70: "TREE_CONNECT",
    0x72: "NEGOTIATE",
    0x73: "SESSION_SETUP_ANDX",
    0x74: "LOGOFF_ANDX",
    0x75: "TREE_CONNECT_ANDX",
};

const SMB2_COMMANDS = {
    0x0000: "NEGOTIATE",
    0x0001: "SESSION_SETUP",
    0x0002: "LOGOFF",
    0x0003: "TREE_CONNECT",
    0x0004: "TREE_DISCONNECT",
    0x0005: "CREATE",
    0x0008: "READ",
    0x0009: "WRITE",
    0x0010: "QUERY_INFO",
    0x0011: "SET_INFO",
};

function decodeSmbFromBytes(bytes) {
    const normalized = normalizeSmbDecoderBytes(bytes);
    if (!(normalized instanceof Uint8Array) || normalized.length < 8) return null;

    const view = new DataView(
        normalized.buffer,
        normalized.byteOffset,
        normalized.byteLength,
    );
    let result = null;
    let blobStart = 0;

    if (
        normalized[0] === 0xff && normalized[1] === 0x53 && normalized[2] === 0x4d && normalized[3] === 0x42
    ) {
        const commandCode = normalized[4];
        const status = view.getUint32(5, true);
        const isResponse = Boolean(normalized[9] & 0x80);
        result = {
            protocol: "SMB",
            fields: [
                { name: "Version", value: "SMBv1" },
                { name: "Command", value: SMB1_COMMANDS[commandCode] || `0x${commandCode.toString(16).padStart(2, "0")}` },
                { name: "Status", value: `0x${status.toString(16).padStart(8, "0")}` },
                { name: "Is Response", value: isResponse ? "Yes" : "No" },
            ],
        };
        blobStart = 32;
    } else if (
        normalized[0] === 0xfe && normalized[1] === 0x53 && normalized[2] === 0x4d && normalized[3] === 0x42
    ) {
        const commandCode = view.getUint16(12, true);
        const status = view.getUint32(8, true);
        const isResponse = Boolean(view.getUint32(16, true) & 0x00000001);
        result = {
            protocol: "SMB",
            fields: [
                { name: "Version", value: "SMBv2/v3" },
                { name: "Command", value: SMB2_COMMANDS[commandCode] || `0x${commandCode.toString(16).padStart(4, "0")}` },
                { name: "Status", value: `0x${status.toString(16).padStart(8, "0")}` },
                { name: "Is Response", value: isResponse ? "Yes" : "No" },
            ],
        };
        blobStart = 64;
    }

    if (!result) return null;

    const blob = normalized.slice(blobStart);
    const ntlmIndex = findBytesSubsequence(blob, NTLMSSP_MARKER);
    if (ntlmIndex === -1) return result;
    const ntlmBlob = blob.slice(ntlmIndex);
    if (ntlmBlob.length < 12) return result;

    const ntlmView = new DataView(ntlmBlob.buffer, ntlmBlob.byteOffset, ntlmBlob.byteLength);
    const messageType = ntlmView.getUint32(8, true);
    const pushField = (name, value) => {
        if (typeof value === "string" && value) result.fields.push({ name, value });
    };

    if (messageType === 1) {
        pushField("NTLMSSP", "NEGOTIATE");
        return result;
    }
    if (messageType === 2) {
        pushField("NTLMSSP", "CHALLENGE");
        pushField(
            "Target Name",
            decodeSmbTextBytes(parseSmbNtlmSecurityBuffer(ntlmBlob, 12), true),
        );
        return result;
    }
    if (messageType !== 3) {
        pushField("NTLMSSP", `TYPE_${messageType}`);
        return result;
    }

    const flags = ntlmBlob.length >= 64 ? ntlmView.getUint32(60, true) : 0;
    const useUnicode = Boolean(flags & 0x00000001);
    const lmResponse = parseSmbNtlmSecurityBuffer(ntlmBlob, 12);
    const ntlmResponse = parseSmbNtlmSecurityBuffer(ntlmBlob, 20);
    const domain = parseSmbNtlmSecurityBuffer(ntlmBlob, 28);
    const username = parseSmbNtlmSecurityBuffer(ntlmBlob, 36);
    const workstation = parseSmbNtlmSecurityBuffer(ntlmBlob, 44);

    pushField("NTLMSSP", "AUTHENTICATE");
    pushField("Domain", decodeSmbTextBytes(domain, useUnicode));
    pushField("Username", decodeSmbTextBytes(username, useUnicode));
    pushField("Workstation", decodeSmbTextBytes(workstation, useUnicode));
    if (lmResponse.length) pushField("LM Response", bytesToHexLower(lmResponse));
    if (ntlmResponse.length) pushField("NTLM Response", bytesToHexLower(ntlmResponse));
    return result;
}

module.exports = { decodeSmbFromBytes };
