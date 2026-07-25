// Shared helpers used by the SMB Conv decoder:
//   - normalizeSmbDecoderBytes: strip optional NetBIOS session header so the
//     payload starts at the SMB magic (0xFF 'SMB' or 0xFE 'SMB').
//   - findBytesSubsequence: locate a byte pattern inside a Uint8Array.
//   - parseSmbNtlmSecurityBuffer: read an NTLMSSP length/offset pair and
//     return the referenced slice (empty Uint8Array on out-of-bounds).
//   - decodeSmbTextBytes: decode UTF-16LE (default) or UTF-8 and strip trailing
//     NULs/whitespace.
//   - bytesToHexLower: hex-encode bytes as a lowercase string.

const NTLMSSP_MARKER = new Uint8Array([0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00]);

function normalizeSmbDecoderBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4) return bytes;
    for (let offset = 0; offset <= Math.min(bytes.length - 4, 16); offset += 1) {
        const first = bytes[offset];
        if (
            (first === 0xff || first === 0xfe) &&
            bytes[offset + 1] === 0x53 &&
            bytes[offset + 2] === 0x4d &&
            bytes[offset + 3] === 0x42
        ) {
            return bytes.slice(offset);
        }
    }
    return bytes;
}

function findBytesSubsequence(bytes, subsequence) {
    if (!(bytes instanceof Uint8Array) || !(subsequence instanceof Uint8Array)) return -1;
    if (!subsequence.length || subsequence.length > bytes.length) return -1;
    for (let index = 0; index <= bytes.length - subsequence.length; index += 1) {
        let matched = true;
        for (let offset = 0; offset < subsequence.length; offset += 1) {
            if (bytes[index + offset] !== subsequence[offset]) {
                matched = false;
                break;
            }
        }
        if (matched) return index;
    }
    return -1;
}

function parseSmbNtlmSecurityBuffer(bytes, fieldOffset) {
    if (!(bytes instanceof Uint8Array) || bytes.length < fieldOffset + 8) return new Uint8Array();
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const valueLength = view.getUint16(fieldOffset, true);
    const bufferOffset = view.getUint32(fieldOffset + 4, true);
    if (valueLength <= 0 || bufferOffset + valueLength > bytes.length) return new Uint8Array();
    return bytes.slice(bufferOffset, bufferOffset + valueLength);
}

function decodeSmbTextBytes(bytes, useUnicode = true) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return "";
    try {
        const decoder = new TextDecoder(useUnicode ? "utf-16le" : "utf-8", {
            fatal: false,
        });
        return decoder.decode(bytes).replace(/\u0000+$/g, "").trim();
    } catch {
        return "";
    }
}

function bytesToHexLower(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return "";
    return Array.from(bytes, (byteValue) =>
        byteValue.toString(16).padStart(2, "0"),
    ).join("");
}

module.exports = {
    NTLMSSP_MARKER,
    normalizeSmbDecoderBytes,
    findBytesSubsequence,
    parseSmbNtlmSecurityBuffer,
    decodeSmbTextBytes,
    bytesToHexLower,
};
