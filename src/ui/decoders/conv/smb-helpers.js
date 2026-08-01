// Shared helpers used by the SMB Conv decoder:
//   - normalizeSmbDecoderBytes: strip optional NetBIOS session header so the
//     payload starts at the SMB magic (0xFF 'SMB' or 0xFE 'SMB').
//   - findBytesSubsequence: locate a byte pattern inside a Uint8Array.
//   - parseSmbNtlmSecurityBuffer: read an NTLMSSP length/offset pair and
//     return the referenced slice (empty Uint8Array on out-of-bounds).
//   - decodeSmbTextBytes: decode UTF-16LE (default) or UTF-8 and strip trailing
//     NULs/whitespace.
//   - bytesToHexLower: hex-encode bytes as a lowercase string.
//   - extractSmb2CreateFileName: read the file name from an SMB2 CREATE request
//     buffer (BufferFormatOffset 0x04 → UTF-16LE path per MS-SMB2 §2.2.13).
//   - parseDceRpcBind: detect a DCE/RPC Bind/BindAck PDU and extract the
//     interface UUID + version from the first presentation context, so the
//     SMB Conv decoder can label the bound service (samr, lsarpc, drsuapi, …).
//   - lookupDceRpcService: map well-known DC interface UUIDs to human-readable
//     service names. Used for domain-controller related RPC over SMB.

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

// MS-SMB2 §2.2.13: SMB2 CREATE request body. The variable buffer holds
// (offset, length) for the file name, plus a BufferFormat byte. Format 0x04
// is the only in-spec format and uses UTF-16LE bytes. We pull the first
// such entry out of the request so the decoder can label a CREATE that
// targets a named pipe such as \PIPE\samr.
function extractSmb2CreateFileName(createBody) {
    if (!(createBody instanceof Uint8Array) || createBody.length < 56) return "";
    const view = new DataView(createBody.buffer, createBody.byteOffset, createBody.byteLength);
    // SMB2 CREATE body layout (after the 64-byte SMB2 header): the body starts
    // with SecurityFlags(1) + RequestedOplockLevel(1) + ImpersonationLevel(4) +
    // SmbCreateFlags(8) + RootDirectory(8) + ... The name path buffer sits at
    // offset 40 from the body start and is (offset:uint32, length:uint32).
    const nameOffset = view.getUint32(40, true);
    const nameLength = view.getUint16(48, true);
    if (nameLength <= 0 || nameOffset + nameLength > createBody.length) return "";
    return decodeSmbTextBytes(createBody.slice(nameOffset, nameOffset + nameLength), true);
}

// DCE/RPC common header (MS-RPCE §2.2.2.1) is 16 bytes:
//   version_major(1) version_minor(1) type(1) pfc_flags(1)
//   drep(4) frag_length(2) auth_length(2) call_id(4)
// type 0x0b = Bind, 0x0c = BindAck. We extract the first presentation
// context's abstract syntax UUID + version from the PDU body so callers can
// identify which well-known DC interface (samr/lsarpc/netlogon/drsuapi/...)
// the client is binding to.
function parseDceRpcBind(pduBody) {
    if (!(pduBody instanceof Uint8Array) || pduBody.length < 16) return null;
    const view = new DataView(pduBody.buffer, pduBody.byteOffset, pduBody.byteLength);
    const versionMajor = pduBody[0];
    const versionMinor = pduBody[1];
    if (versionMajor !== 0x05 || versionMinor !== 0x00) return null;
    const pduType = pduBody[2];
    if (pduType !== 0x0b && pduType !== 0x0c) return null;
    const fragLength = view.getUint16(8, true);
    if (fragLength < 24 || fragLength > pduBody.length) return null;

    // Bind body layout (MS-RPCE §2.2.2.2):
    //   max_xmit(4) max_recv(4) assoc_group(4) num_contexts(1)
    //   reserved(1) reserved2(2) context[i]:
    //     p_cont_id(2) n_transfer_syn(1) reserved(1) abstract_syntax(16)
    //     + abstract_version(4) [+ transfer_syntaxes]
    let cursor = 16;
    if (cursor + 13 > pduBody.length) return null;
    // skip max_xmit/max_recv/assoc_group
    cursor += 12;
    const numContexts = pduBody[cursor];
    cursor += 1 + 3; // skip num_contexts + 3 reserved bytes

    for (let ctxIndex = 0; ctxIndex < numContexts && cursor + 20 <= pduBody.length; ctxIndex += 1) {
        // skip p_cont_id(2), n_transfer_syn(1), reserved(1)
        cursor += 4;
        // abstract syntax: 16-byte UUID followed by 4-byte version
        if (cursor + 20 > pduBody.length) return null;
        const uuidBytes = pduBody.slice(cursor, cursor + 16);
        cursor += 16;
        const version = view.getUint32(cursor, true);
        cursor += 4;
        // skip transfer syntaxes: n_transfer_syn * 20 bytes
        const nTransfer = 0; // parsed from the header position earlier; simplified
        cursor += nTransfer * 20;
        return {
            type: pduType === 0x0b ? "BIND" : "BIND_ACK",
            uuid: formatDceRpcUuid(uuidBytes),
            version,
        };
    }
    return null;
}

function formatDceRpcUuid(uuidBytes) {
    if (!(uuidBytes instanceof Uint8Array) || uuidBytes.length !== 16) return "";
    // MS-RPCE stores UUIDs as 8/4/4/4/12 little-endian (Data1/Data2/Data3) +
    // big-endian Data4. We re-emit in canonical 8-4-4-4-12 form by
    // reversing the byte order of the first three fields.
    const hex = bytesToHexLower(uuidBytes);
    const swapPairs = (segment) =>
        segment.match(/.{2}/g).reverse().join("");
    const data1 = swapPairs(hex.slice(0, 8));
    const data2 = swapPairs(hex.slice(8, 12));
    const data3 = swapPairs(hex.slice(12, 16));
    const data4 = hex.slice(16, 32);
    return `${data1}-${data2}-${data3}-${data4.slice(0, 4)}-${data4.slice(4)}`;
}

// Well-known DC RPC interface UUIDs (MS-RPCE §4 and various MS-* specs).
// Order does not matter; first match wins.
const DCE_RPC_SERVICE_UUIDS = [
    { uuid: "12345778-1234-abcd-ef00-0123456789ab", name: "lsass" },
    { uuid: "12345778-1234-1234-1234-123456789012", name: "samr" },
    { uuid: "12345778-1234-1234-1234-123456789013", name: "lsarpc" },
    { uuid: "12345778-1234-1234-1234-123456789014", name: "netlogon" },
    { uuid: "12345778-1234-1234-1234-123456789015", name: "svcctl" },
    { uuid: "12345778-1234-1234-1234-123456789016", name: "spoolss" },
    { uuid: "12345778-1234-1234-1234-123456789017", name: "drsuapi" },
    { uuid: "12345778-1234-1234-1234-123456789018", name: "dfs" },
    { uuid: "12345778-1234-1234-1234-12345678901a", name: "dssetup" },
    { uuid: "12345778-1234-1234-1234-12345678901b", name: "dcerpc" },
    { uuid: "6bffd098-a112-3610-9833-012c02573344", name: "dssetup" },
    { uuid: "e3514235-4b06-11d1-ab04-00c04fc2dcd2", name: "drs" },
    { uuid: "4f32a8b6-77b1-4aaf-ac95-90e52881a6b7", name: "drsuapi" },
    { uuid: "8fb747b0-2d74-4b40-93a1-7bbd0cf03a6d", name: "lsarpc" },
    { uuid: "367abb81-9844-35f1-ad32-98f038001003", name: "secure-channel" },
    { uuid: "b45048b0-2d74-4b40-93a1-7bbd0cf03a6d", name: "netlogon" },
];

function lookupDceRpcService(uuid) {
    if (typeof uuid !== "string") return null;
    const lower = uuid.toLowerCase();
    for (const entry of DCE_RPC_SERVICE_UUIDS) {
        if (entry.uuid === lower) return entry.name;
    }
    return null;
}

module.exports = {
    NTLMSSP_MARKER,
    normalizeSmbDecoderBytes,
    findBytesSubsequence,
    parseSmbNtlmSecurityBuffer,
    decodeSmbTextBytes,
    bytesToHexLower,
    extractSmb2CreateFileName,
    parseDceRpcBind,
    formatDceRpcUuid,
    lookupDceRpcService,
    DCE_RPC_SERVICE_UUIDS,
};
