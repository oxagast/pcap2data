// NetBIOS Name Service (NetBIOS-NS) Conv decoder: parses the
// RFC 1001 / RFC 1002 / RFC 1008 wire format. NetBIOS-NS is a query /
// response protocol that runs on UDP/137 and is used to map a NetBIOS
// name to an IP address (or vice versa via the NBSTAT adapter status
// query).
//
// The decoder surfaces the 12-byte NetBIOS-NS header (NAME_TRN_ID,
// FLAGS, QDCOUNT / ANCOUNT / NSCOUNT / ARCOUNT), the question section
// (a QNAME that uses the NetBIOS First-Level Encoding and a QTYPE /
// QCLASS pair), and the per-RR resource records in the answer /
// authority / additional sections with typed rdata previews for the
// most common NetBIOS-NS RR types (NB, NBSTAT, A, NS, NULL, CNAME).

const { bytesToHexLower } = require("./smb-helpers");

const NBNS_MAX_RR = 64;
const NBNS_LABEL_VALUE_LIMIT = 220;
const NBNS_RDATA_VALUE_LIMIT = 220;

// NetBIOS-NS opcode and response-code maps (RFC 1002 §4.2.1.1 / §4.2.1.3).
const NBNS_OPCODE_NAMES = {
    0: "Query",
    1: "Registration",
    2: "Release",
    4: "WACK",
    5: "Refresh",
    6: "Refresh-alt",
    7: "Multi-homed Registration",
    8: "Multi-homed Deregistration",
};

const NBNS_RCODE_NAMES = {
    0: "No Error",
    1: "Format Error",
    2: "Server Failure",
    3: "Name Error (NXDOMAIN)",
    4: "Unsupported Request Error",
    5: "Refused",
    6: "Active Error",
    7: "Name in Conflict Error",
};

// NBSTAT RDATA bitmap bit names. The NBSTAT "RESOURCE" RR (type 0x002a)
// encodes the node status reply as a series of bitmaps, each describing
// the names / services active on the queried node. The 16-bit fields
// that follow the name are per RFC 1002 §4.2.2.
const NBNS_NAME_FLAGS = {
    G: "Group",
    ON: "Owner Node",
    P: "Permanent",
    A: "Active",
    C: "Conflict",
    D: "Deregister",
    H: "Hybrid",
    RR: "Record-Released",
};

const NBNS_NAME_TYPES = [
    { code: 0x00, label: "Workstation" },
    { code: 0x01, label: "Messenger" },
    { code: 0x02, label: "RAS Server" },
    { code: 0x03, label: "RPC Server" },
    { code: 0x06, label: "File Server" },
    { code: 0x1b, label: "Domain Master Browser" },
    { code: 0x1c, label: "Domain Controller" },
    { code: 0x1d, label: "Local Master Browser" },
    { code: 0x1e, label: "Browser" },
    { code: 0x1f, label: "Network Monitor" },
    { code: 0x20, label: "File Server (LAN Manager)" },
    { code: 0x21, label: "Xenix Server" },
    { code: 0x22, label: "Workstation (LAN Manager)" },
    { code: 0x23, label: "LMU Server" },
    { code: 0x24, label: "LAN Manager UNIX" },
    { code: 0x30, label: "Modem Sharing Server" },
    { code: 0x31, label: "Modem Sharing Client" },
    { code: 0x87, label: "MS Exchange STORE" },
    { code: 0xbe, label: "MS Exchange Directory" },
    { code: 0xbf, label: "MS Exchange MTA" },
];

const NBNS_QTYPE_NAMES = {
    0x0020: "NB",
    0x0021: "NBSTAT",
};

function pushTruncated(fields, name, value, limit) {
    if (typeof value !== "string" || !value) return;
    const trimmed = value.length > limit ? `${value.slice(0, limit)}...` : value;
    fields.push({ name, value: trimmed });
}

function readUint16(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 2 > bytes.length) return null;
    return (bytes[offset] << 8) | bytes[offset + 1];
}

function readUint32(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 4 > bytes.length) return null;
    return ((bytes[offset] << 24) |
        (bytes[offset + 1] << 16) |
        (bytes[offset + 2] << 8) |
        bytes[offset + 3]) >>> 0;
}

// Convert a NetBIOS First-Level Encoded name to a printable form. The
// encoded form is 32 bytes, where each pair of nibbles encodes a single
// character of the 16-character NetBIOS name (e.g. 'A' -> 0x41).
// The trailing byte carries the length (in bytes) of the label.
//
// Per RFC 1001 §14.1 the encoded form pads the name with spaces (0x20)
// to 15 bytes and then appends a "scope" suffix character; the final
// length byte holds the wire-format offset of the trailing space so the
// decoder can recover the original name.
//
// The caller passes the full NetBIOS label bytes (label length byte
// followed by the encoded body) and we return { name, endIndex, ok }.
function decodeNetbiosEncodedName(bytes, startIndex) {
    if (!(bytes instanceof Uint8Array) || startIndex < 1) {
        return { name: "", endIndex: startIndex, ok: false };
    }
    const labelLength = bytes[startIndex];
    // The on-wire label length is encoded with the high two bits set as a
    // "compressed label" indicator (RFC 1001 §4). For names the high two
    // bits are always 11 (0xC0). We mask them off to recover the actual
    // body length.
    const bodyLength = labelLength === 0x20 ? 32 : labelLength & 0x3f;
    const bodyStart = startIndex + 1;
    const bodyEnd = bodyStart + bodyLength;
    if (bodyEnd > bytes.length) {
        return { name: "", endIndex: startIndex, ok: false };
    }
    // The body is 32 bytes of two-nibble-per-character ASCII encoding.
    if (bodyLength !== 32) {
        // The decoder accepts 32-byte encodings; anything else is
        // treated as raw bytes so we still surface something.
        const raw = bytesToHexLower(bytes.slice(bodyStart, bodyEnd));
        return { name: `0x${raw}`, endIndex: bodyEnd, ok: true };
    }
    const chars = [];
    for (let offset = bodyStart; offset < bodyEnd - 1; offset += 2) {
        const hi = bytes[offset] & 0x0f;
        const lo = bytes[offset + 1] & 0x0f;
        const value = (hi << 4) | lo;
        if (value === 0x20) chars.push(" ");
        else if (value >= 0x21 && value <= 0x7e) chars.push(String.fromCharCode(value));
        else chars.push(`\\x${value.toString(16).padStart(2, "0")}`);
    }
    // The last byte is the offset of the trailing space inside the name.
    // Anything before the trailing space is the visible NetBIOS name.
    const visibleLength = bytes[bodyEnd - 1];
    const visible = chars.slice(0, visibleLength).join("").trim();
    return { name: visible, endIndex: bodyEnd, ok: true };
}

// Decode a NetBIOS "name" label. A NetBIOS-NS QNAME / RR-name is a single
// label carrying the encoded form, terminated by a 0x00 length byte.
// Returns { name, endIndex, ok } where endIndex points to the byte after
// the trailing 0x00.
function decodeNetbiosNameLabel(bytes, startIndex) {
    const encoded = decodeNetbiosEncodedName(bytes, startIndex);
    if (!encoded.ok) return encoded;
    if (encoded.endIndex >= bytes.length) {
        return { name: encoded.name, endIndex: encoded.endIndex, ok: false };
    }
    if (bytes[encoded.endIndex] !== 0x00) {
        // No terminator: treat as a label-only walk, do not advance.
        return { name: encoded.name, endIndex: startIndex, ok: false };
    }
    return { name: encoded.name, endIndex: encoded.endIndex + 1, ok: true };
}

function formatA(rdBytes) {
    if (!(rdBytes instanceof Uint8Array) || rdBytes.length !== 4) return null;
    return `${rdBytes[0]}.${rdBytes[1]}.${rdBytes[2]}.${rdBytes[3]}`;
}

function formatNbFlags(flags) {
    const entries = [];
    Object.entries(NBNS_NAME_FLAGS).forEach(([bit, label]) => {
        if (((flags >>> 0) & (1 << NBNS_NAME_FLAG_BITS[bit])) !== 0) {
            entries.push(label);
        }
    });
    if (!entries.length) return "0x0000";
    return entries.join(" ");
}

// Map human-readable flag bit names to their position in the 16-bit word.
const NBNS_NAME_FLAG_BITS = {
    G: 7, // group
    ON: 9, // owner-node
    P: 10, // permanent
    A: 11, // active
    C: 12, // conflict
    D: 13, // deregister
    H: 14, // hybrid
    RR: 15, // record-released
};

function formatNbNameType(code) {
    const entry = NBNS_NAME_TYPES.find((candidate) => candidate.code === code);
    return entry ? entry.label : `0x${code.toString(16).padStart(2, "0")}`;
}

function decodeNbstatRdata(rdBytes) {
    if (!(rdBytes instanceof Uint8Array) || rdBytes.length < 1) return null;
    // RFC 1002 §4.2.2: NBSTAT RDATA is a single NetBIOS encoded name
    // (the queried NODE name) followed by the statistics block. The
    // statistics block begins with a 1-byte "number of names" count,
    // then `count` NAME_ENTRY records, then a 0-bytes "MAC" trailer.
    // We surface the queried name + per-name flags/types so the user
    // can recognize a "*SMBSERVER" style "node status" reply.
    const nameResult = decodeNetbiosEncodedName(rdBytes, 0);
    if (!nameResult.ok) return null;
    const statStart = nameResult.endIndex;
    if (statStart + 1 > rdBytes.length) return null;
    const nameCount = rdBytes[statStart];
    const fields = [];
    fields.push({ name: "Node Name", value: nameResult.name });
    fields.push({ name: "Name Count", value: String(nameCount) });
    const entriesStart = statStart + 1;
    const entrySize = 18; // 16 bytes name + 2 bytes flags
    const maxEntries = Math.min(nameCount, NBNS_MAX_RR);
    for (let i = 0; i < maxEntries; i += 1) {
        const entryOffset = entriesStart + i * entrySize;
        if (entryOffset + entrySize > rdBytes.length) break;
        const entryNameBytes = rdBytes.slice(entryOffset, entryOffset + 16);
        const nameResult2 = decodeNetbiosEncodedName(entryNameBytes, 0);
        const flags = (rdBytes[entryOffset + 16] << 8) | rdBytes[entryOffset + 17];
        fields.push({
            name: `Name ${i + 1}`,
            value: `${nameResult2.ok ? nameResult2.name : "?"} flags=${formatNbFlags(flags)}`,
        });
    }
    if (maxEntries < nameCount) {
        fields.push({
            name: "Notice",
            value: `Truncated ${nameCount - maxEntries} additional name entries.`,
        });
    }
    return fields;
}

function decodeNbnsRrRdata(rrType, rdBytes, messageEnd) {
    if (!(rdBytes instanceof Uint8Array)) return { preview: bytesToHexLower(rdBytes) };
    const rdLength = rdBytes.length;
    switch (rrType) {
        case 0x0020: {
            // NB (NetBIOS general name service) RDATA: 2-byte flags,
            // 4-byte IP address.
            if (rdLength < 6) {
                return { preview: bytesToHexLower(rdBytes) };
            }
            const flags = (rdBytes[0] << 8) | rdBytes[1];
            const ip = formatA(rdBytes.slice(2, 6));
            const flagLabel = formatNbFlags(flags);
            return { preview: ip ? `flags=${flagLabel} addr=${ip}` : `flags=0x${flags.toString(16).padStart(4, "0")}` };
        }
        case 0x0021: {
            // NBSTAT: structured statistics block. Render via the helper.
            const stats = decodeNbstatRdata(rdBytes);
            if (!stats) return { preview: bytesToHexLower(rdBytes) };
            return { preview: "see fields below", stats };
        }
        case 0x0001: {
            // A (rare on NetBIOS-NS but legal): 4-byte IPv4 address.
            if (rdLength !== 4) return { preview: bytesToHexLower(rdBytes) };
            return { preview: formatA(rdBytes) || bytesToHexLower(rdBytes) };
        }
        default: {
            void messageEnd;
            return { preview: bytesToHexLower(rdBytes) };
        }
    }
}

function decodeNbnsRr(bytes, cursor, count) {
    const fields = [];
    for (let i = 0; i < count && i < NBNS_MAX_RR && cursor < bytes.length; i += 1) {
        const nameResult = decodeNetbiosNameLabel(bytes, cursor);
        if (!nameResult.ok || !nameResult.endIndex) {
            cursor = bytes.length;
            break;
        }
        cursor = nameResult.endIndex;
        if (cursor + 10 > bytes.length) break;
        const rrType = readUint16(bytes, cursor);
        const rrClass = readUint16(bytes, cursor + 2);
        const ttl = readUint32(bytes, cursor + 4);
        const rdLength = readUint16(bytes, cursor + 8);
        if (rrType === null || rrClass === null || ttl === null || rdLength === null) break;
        const rdStart = cursor + 10;
        const rdEnd = rdStart + rdLength;
        if (rdEnd > bytes.length) break;
        const rdBytes = bytes.slice(rdStart, rdEnd);
        const decoded = decodeNbnsRrRdata(rrType, rdBytes, bytes.length);
        const typeName = NBNS_QTYPE_NAMES[rrType] || `TYPE${rrType}`;
        let value = `${nameResult.name} ${typeName} CLASS=0x${rrClass.toString(16).padStart(4, "0")} TTL=${ttl} RDATA=${decoded.preview}`;
        if (value.length > NBNS_RDATA_VALUE_LIMIT) {
            value = `${value.slice(0, NBNS_RDATA_VALUE_LIMIT)}...`;
        }
        fields.push({ name: `RR ${i + 1}`, value });
        if (decoded.stats) {
            decoded.stats.forEach((entry) => {
                const entryName = `RR ${i + 1} ${entry.name}`;
                if (entry.name.length > NBNS_LABEL_VALUE_LIMIT) {
                    fields.push({ name: entryName, value: `${entry.value}...` });
                } else {
                    fields.push({ name: entryName, value: entry.value });
                }
            });
        }
        cursor = rdEnd;
    }
    return { fields, cursor };
}

function decodeNbnsMessage(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 12) return null;
    const nameTrnId = readUint16(bytes, 0);
    const flags = readUint16(bytes, 2);
    const qdCount = readUint16(bytes, 4);
    const anCount = readUint16(bytes, 6);
    const nsCount = readUint16(bytes, 8);
    const arCount = readUint16(bytes, 10);
    if (
        nameTrnId === null || flags === null ||
        qdCount === null || anCount === null ||
        nsCount === null || arCount === null
    ) {
        return null;
    }

    const fields = [];
    pushTruncated(
        fields,
        "Transaction ID",
        `0x${nameTrnId.toString(16).padStart(4, "0")}`,
        NBNS_LABEL_VALUE_LIMIT,
    );
    const isResponse = (flags & 0x8000) !== 0;
    const opcode = (flags >> 11) & 0x0f;
    const rcode = flags & 0x000f;
    fields.push({ name: "Type", value: isResponse ? "Response" : "Query" });
    fields.push({ name: "Opcode", value: NBNS_OPCODE_NAMES[opcode] || `OPCODE${opcode}` });
    fields.push({ name: "Rcode", value: NBNS_RCODE_NAMES[rcode] || `RCODE${rcode}` });

    const flagBits = [
        [0x0400, "AA", "authoritative"],
        [0x0200, "TC", "truncated"],
        [0x0100, "RD", "recursion-desired"],
        [0x0080, "RA", "recursion-available"],
        [0x0010, "B", "broadcast"],
    ];
    flagBits.forEach(([mask, label, longLabel]) => {
        const enabled = (flags & mask) !== 0;
        fields.push({ name: `Flag ${label} (${longLabel})`, value: enabled ? "set" : "clear" });
    });

    fields.push({ name: "Question Count", value: String(qdCount) });
    fields.push({ name: "Answer Count", value: String(anCount) });
    fields.push({ name: "Authority Count", value: String(nsCount) });
    fields.push({ name: "Additional Count", value: String(arCount) });

    let cursor = 12;
    let questionIndex = 0;
    while (questionIndex < qdCount && questionIndex < NBNS_MAX_RR && cursor < bytes.length) {
        const nameResult = decodeNetbiosNameLabel(bytes, cursor);
        if (!nameResult.ok) {
            cursor = bytes.length;
            break;
        }
        cursor = nameResult.endIndex;
        if (cursor + 4 > bytes.length) break;
        const qtype = readUint16(bytes, cursor);
        const qclass = readUint16(bytes, cursor + 2);
        if (qtype === null || qclass === null) break;
        questionIndex += 1;
        const typeName = NBNS_QTYPE_NAMES[qtype] || `TYPE${qtype}`;
        fields.push({
            name: `Question ${questionIndex}`,
            value: `${nameResult.name} ${typeName} CLASS=0x${qclass.toString(16).padStart(4, "0")}`,
        });
        cursor += 4;
    }

    if (anCount) {
        const answer = decodeNbnsRr(bytes, cursor, anCount);
        answer.fields.forEach((field) => fields.push({ name: `Answer ${field.name}`, value: field.value }));
        cursor = answer.cursor;
    }
    if (nsCount) {
        const auth = decodeNbnsRr(bytes, cursor, nsCount);
        auth.fields.forEach((field) => fields.push({ name: `Authority ${field.name}`, value: field.value }));
        cursor = auth.cursor;
    }
    if (arCount) {
        const additional = decodeNbnsRr(bytes, cursor, arCount);
        additional.fields.forEach((field) => fields.push({ name: `Additional ${field.name}`, value: field.value }));
        cursor = additional.cursor;
    }

    return { id: nameTrnId, fields };
}

function decodeNbnsFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 2) return null;
    try {
        const decoded = decodeNbnsMessage(bytes);
        if (!decoded) return null;
        return { protocol: "NetBIOS-NS", fields: decoded.fields };
    } catch {
        return null;
    }
}

module.exports = { decodeNbnsFromBytes };
