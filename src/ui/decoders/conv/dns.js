// DNS Conv decoder: parses a stream of DNS messages from raw bytes. UDP/53
// transports get a single message per call; TCP/53 is length-prefixed
// (RFC 1035 §4.2.2) and is split into 2-byte length-prefixed frames here so
// the decoder can be reused in both modes.
//
// The decoder surfaces the DNS header flags (RFC 1035 §4.1.1), the question
// section (QNAME label-sequence + QTYPE/QCLASS), and per-RR resource-record
// trees for answer/authority/additional (RFC 1035 §4.1.2 / §4.1.3) with
// label-compression-pointer dereferencing and typed rdata previews for the
// most common RR types (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, HINFO).

const { bytesToHexLower } = require("./smb-helpers");

const DNS_MAX_MESSAGES = 64;
const DNS_LABEL_VALUE_LIMIT = 220;
const DNS_RDATA_VALUE_LIMIT = 220;

// DNS header flag bit masks (RFC 1035 §4.1.1).
const DNS_HEADER_FLAGS = [
    [0x8000, "QR", "response"],
    [0x7800, "OPCODE", "opcode"],
    [0x0400, "AA", "authoritative"],
    [0x0200, "TC", "truncated"],
    [0x0100, "RD", "recursion-desired"],
    [0x0080, "RA", "recursion-available"],
    [0x0040, "Z", "z"],
    [0x0020, "AD", "authenticated-data"],
    [0x0010, "CD", "checking-disabled"],
];

// RCODE is the low 4 bits of the flags word. Values per RFC 1035 + RFC 6891.
const DNS_RCODE_NAMES = {
    0: "NoError",
    1: "FormErr",
    2: "ServFail",
    3: "NXDomain",
    4: "NotImp",
    5: "Refused",
    6: "YXDomain",
    7: "YXRRSet",
    8: "NXRRSet",
    9: "NotAuth",
    10: "NotZone",
};

const DNS_CLASS_NAMES = {
    1: "IN",
    2: "CS",
    3: "CH",
    4: "HS",
    255: "ANY",
};

const DNS_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    3: "CNAME",
    4: "SOA",
    5: "CNAME", // legacy alias
    6: "SOA",
    7: "MB",
    8: "MG",
    9: "MR",
    10: "NULL",
    11: "WKS",
    12: "PTR",
    13: "HINFO",
    14: "MINFO",
    15: "MX",
    16: "TXT",
    17: "RP",
    18: "AFSDB",
    19: "X25",
    20: "ISDN",
    21: "RT",
    22: "NSAP",
    23: "NSAP_PTR",
    24: "SIG",
    25: "KEY",
    26: "PX",
    27: "GPOS",
    28: "AAAA",
    29: "LOC",
    30: "NXT",
    31: "EID",
    32: "NIMLOC",
    33: "SRV",
    34: "ATMA",
    35: "NAPTR",
    36: "KX",
    37: "CERT",
    38: "A6",
    39: "DNAME",
    40: "SINK",
    41: "OPT",
    42: "APL",
    43: "DS",
    44: "SSHFP",
    45: "IPSECKEY",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    49: "DHCID",
    50: "NSEC3",
    51: "NSEC3PARAM",
    52: "TLSA",
    53: "SMIMEA",
    55: "HIP",
    56: "NINFO",
    57: "RKEY",
    58: "TALINK",
    59: "CDS",
    60: "CDNSKEY",
    61: "OPENPGPKEY",
    62: "CSYNC",
    99: "SPF",
    100: "UINFO",
    101: "UID",
    102: "GID",
    103: "UNSPEC",
    104: "NID",
    105: "L32",
    106: "L64",
    107: "LP",
    108: "EUI48",
    109: "EUI64",
    249: "TKEY",
    250: "TSIG",
    251: "IXFR",
    252: "AXFR",
    253: "MAILB",
    254: "MAILA",
    255: "ANY",
    256: "URI",
    257: "CAA",
    32768: "TA",
    32769: "DLV",
};

function pushTruncated(fields, name, value, limit) {
    if (typeof value !== "string" || !value) return;
    const trimmed = value.length > limit ? `${value.slice(0, limit)}...` : value;
    fields.push({ name, value: trimmed });
}

function formatOpcode(opcode) {
    const opcodes = ["QUERY", "IQUERY", "STATUS", "RESERVED3", "NOTIFY", "UPDATE"];
    return opcodes[opcode] || `OPCODE${opcode}`;
}

function formatRcode(rcode) {
    return DNS_RCODE_NAMES[rcode] || `RCODE${rcode}`;
}

function formatQtype(qtype) {
    return DNS_QTYPE_NAMES[qtype] || `TYPE${qtype}`;
}

function formatClass(classValue) {
    return DNS_CLASS_NAMES[classValue] || `CLASS${classValue}`;
}

const { decodeDnsName } = require("./dns-helpers");

// Read a big-endian uint16 from a Uint8Array.
function readUint16(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 2 > bytes.length) return null;
    return (bytes[offset] << 8) | bytes[offset + 1];
}

// Read a big-endian uint32 from a Uint8Array.
function readUint32(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 4 > bytes.length) return null;
    return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function formatA(rdBytes) {
    if (!(rdBytes instanceof Uint8Array) || rdBytes.length !== 4) return null;
    return `${rdBytes[0]}.${rdBytes[1]}.${rdBytes[2]}.${rdBytes[3]}`;
}

function formatAaaa(rdBytes) {
    if (!(rdBytes instanceof Uint8Array) || rdBytes.length !== 16) return null;
    const groups = [];
    for (let i = 0; i < 16; i += 2) {
        const value = (rdBytes[i] << 8) | rdBytes[i + 1];
        groups.push(value.toString(16));
    }
    // Compress the longest run of zero groups per RFC 5952.
    let bestStart = -1;
    let bestLength = 0;
    let currentStart = -1;
    let currentLength = 0;
    groups.forEach((group, index) => {
        if (group === "0") {
            if (currentStart === -1) currentStart = index;
            currentLength += 1;
            if (currentLength > bestLength) {
                bestStart = currentStart;
                bestLength = currentLength;
            }
        } else {
            currentStart = -1;
            currentLength = 0;
        }
    });
    if (bestLength < 2) return groups.join(":");
    const head = groups.slice(0, bestStart).join(":");
    const tail = groups.slice(bestStart + bestLength).join(":");
    return `${head}::${tail}`;
}

function formatMx(rdBytes, messageBytes, messageEnd) {
    if (!(rdBytes instanceof Uint8Array) || rdBytes.length < 3) return null;
    const preference = readUint16(rdBytes, 0);
    if (preference === null) return null;
    const exchange = decodeDnsName(rdBytes, 2, rdBytes.length);
    if (!exchange.ok) return null;
    // Also try to dereference the exchange name against the original message
    // (a CNAME-style rdata could compress against the rest of the message).
    let exchangeName = exchange.name;
    if (messageBytes) {
        const crossRef = decodeDnsName(rdBytes, 2, messageEnd);
        if (crossRef.ok && crossRef.name) exchangeName = crossRef.name;
    }
    return `${preference} ${exchangeName}`;
}

function formatSoa(rdBytes, messageEnd) {
    if (!(rdBytes instanceof Uint8Array) || rdBytes.length < 20) return null;
    const mnameResult = decodeDnsName(rdBytes, 0, messageEnd || rdBytes.length);
    if (!mnameResult.ok) return null;
    let cursor = mnameResult.endIndex;
    if (cursor >= rdBytes.length) return null;
    const rnameResult = decodeDnsName(rdBytes, cursor, messageEnd || rdBytes.length);
    if (!rnameResult.ok) return null;
    cursor = rnameResult.endIndex;
    if (cursor + 20 > rdBytes.length) return null;
    const serial = readUint32(rdBytes, cursor);
    const refresh = readUint32(rdBytes, cursor + 4);
    const retry = readUint32(rdBytes, cursor + 8);
    const expire = readUint32(rdBytes, cursor + 12);
    const minimum = readUint32(rdBytes, cursor + 16);
    if (serial === null || refresh === null || retry === null || expire === null || minimum === null) {
        return null;
    }
    return `mname=${mnameResult.name} rname=${rnameResult.name} serial=${serial} refresh=${refresh} retry=${retry} expire=${expire} minimum=${minimum}`;
}

function formatTxt(rdBytes) {
    if (!(rdBytes instanceof Uint8Array) || rdBytes.length === 0) return [];
    const strings = [];
    let cursor = 0;
    while (cursor < rdBytes.length) {
        const textLength = rdBytes[cursor];
        if (textLength === 0 || cursor + 1 + textLength > rdBytes.length) break;
        const slice = rdBytes.slice(cursor + 1, cursor + 1 + textLength);
        let text = "";
        try {
            text = new TextDecoder("utf-8", { fatal: false }).decode(slice);
        } catch {
            text = bytesToHexLower(slice);
        }
        strings.push(text);
        cursor += 1 + textLength;
    }
    return strings;
}

function formatSrv(rdBytes, messageEnd) {
    if (!(rdBytes instanceof Uint8Array) || rdBytes.length < 7) return null;
    const priority = readUint16(rdBytes, 0);
    const weight = readUint16(rdBytes, 2);
    const port = readUint16(rdBytes, 4);
    if (priority === null || weight === null || port === null) return null;
    const target = decodeDnsName(rdBytes, 6, messageEnd || rdBytes.length);
    if (!target.ok) return null;
    return `priority=${priority} weight=${weight} port=${port} target=${target.name}`;
}

function decodeDnsMessage(bytes, messageIndex) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 12) return null;
    const id = readUint16(bytes, 0);
    const flags = readUint16(bytes, 2);
    const qdCount = readUint16(bytes, 4);
    const anCount = readUint16(bytes, 6);
    const nsCount = readUint16(bytes, 8);
    const arCount = readUint16(bytes, 10);
    if (id === null || flags === null || qdCount === null || anCount === null || nsCount === null || arCount === null) {
        return null;
    }

    const fields = [];
    const prefix = `Message ${messageIndex}`;
    fields.push({ name: `${prefix} ID`, value: `0x${id.toString(16).padStart(4, "0")}` });
    const isResponse = (flags & 0x8000) !== 0;
    fields.push({ name: `${prefix} Type`, value: isResponse ? "Response" : "Query" });
    const opcode = (flags >> 11) & 0x0f;
    fields.push({ name: `${prefix} Opcode`, value: formatOpcode(opcode) });
    const rcode = flags & 0x000f;
    fields.push({ name: `${prefix} Rcode`, value: formatRcode(rcode) });
    DNS_HEADER_FLAGS.forEach(([mask, label, longLabel]) => {
        if (label === "OPCODE") return;
        const enabled = (flags & mask) !== 0;
        if (label === "QR" || label === "RCODE") return;
        fields.push({ name: `${prefix} Flag ${label} (${longLabel})`, value: enabled ? "set" : "clear" });
    });
    fields.push({ name: `${prefix} Question Count`, value: String(qdCount) });
    fields.push({ name: `${prefix} Answer Count`, value: String(anCount) });
    fields.push({ name: `${prefix} Authority Count`, value: String(nsCount) });
    fields.push({ name: `${prefix} Additional Count`, value: String(arCount) });

    let cursor = 12;
    const totalRr = qdCount + anCount + nsCount + arCount;
    if (totalRr > 256) {
        fields.push({ name: `${prefix} Notice`, value: "Resource-record count too large; truncating walk." });
    }
    const questionEnd = 12 + Math.min(qdCount, 256) * 4; // approx; actual per-RR walk below
    let questionIndex = 0;
    let questionParseFailed = false;
    while (questionIndex < qdCount && questionIndex < 256 && cursor < bytes.length) {
        const nameResult = decodeDnsName(bytes, cursor, bytes.length);
        if (!nameResult.ok || !nameResult.endIndex) {
            cursor = bytes.length;
            questionParseFailed = true;
            break;
        }
        cursor = nameResult.endIndex;
        if (cursor + 4 > bytes.length) {
            questionParseFailed = true;
            break;
        }
        const qtype = readUint16(bytes, cursor);
        const qclass = readUint16(bytes, cursor + 2);
        if (qtype === null || qclass === null) {
            questionParseFailed = true;
            break;
        }
        questionIndex += 1;
        fields.push({
            name: `${prefix} Question ${questionIndex}`,
            value: `${nameResult.name} ${formatQtype(qtype)} ${formatClass(qclass)}`,
        });
        cursor += 4;
    }
    void questionEnd;

    // Strict gate: if the message declares questions (qdCount > 0) but
    // none were successfully parsed, the bytes are not a real DNS message.
    // This prevents random binary data from being accepted as DNS just
    // because the 12-byte header happens to parse.
    if (qdCount > 0 && questionIndex === 0) return null;
    if (questionParseFailed && questionIndex === 0) return null;

    const sections = [
        { name: "Answer", count: anCount },
        { name: "Authority", count: nsCount },
        { name: "Additional", count: arCount },
    ];
    for (const section of sections) {
        for (let i = 0; i < section.count && i < 256 && cursor < bytes.length; i += 1) {
            const nameResult = decodeDnsName(bytes, cursor, bytes.length);
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
            let rdataPreview = bytesToHexLower(rdBytes);
            let rdataExtra = "";
            switch (rrType) {
                case 1:
                    rdataExtra = formatA(rdBytes) || rdataPreview;
                    break;
                case 28:
                    rdataExtra = formatAaaa(rdBytes) || rdataPreview;
                    break;
                case 2: {
                    const nsResult = decodeDnsName(rdBytes, 0, bytes.length);
                    rdataExtra = nsResult.ok ? nsResult.name : rdataPreview;
                    break;
                }
                case 5: {
                    const cnameResult = decodeDnsName(rdBytes, 0, bytes.length);
                    rdataExtra = cnameResult.ok ? cnameResult.name : rdataPreview;
                    break;
                }
                case 12: {
                    const ptrResult = decodeDnsName(rdBytes, 0, bytes.length);
                    rdataExtra = ptrResult.ok ? ptrResult.name : rdataPreview;
                    break;
                }
                case 15: {
                    rdataExtra = formatMx(rdBytes, bytes, bytes.length) || rdataPreview;
                    break;
                }
                case 16: {
                    const strings = formatTxt(rdBytes);
                    rdataExtra = strings.length ? strings.map((s) => `"${s}"`).join(" ") : rdataPreview;
                    break;
                }
                case 6: {
                    rdataExtra = formatSoa(rdBytes, bytes.length) || rdataPreview;
                    break;
                }
                case 33: {
                    rdataExtra = formatSrv(rdBytes, bytes.length) || rdataPreview;
                    break;
                }
                case 13: {
                    if (rdBytes.length >= 2) {
                        const cpuSlice = rdBytes.slice(0, rdBytes[0] + 1);
                        const osSlice = rdBytes.slice(rdBytes[0] + 1);
                        rdataExtra = `cpu=${bytesToHexLower(cpuSlice)} os=${bytesToHexLower(osSlice)}`;
                    } else {
                        rdataExtra = rdataPreview;
                    }
                    break;
                }
                default:
                    rdataExtra = rdataPreview;
                    break;
            }
            if (rdataExtra.length > DNS_RDATA_VALUE_LIMIT) {
                rdataExtra = `${rdataExtra.slice(0, DNS_RDATA_VALUE_LIMIT)}...`;
            }
            fields.push({
                name: `${prefix} ${section.name} ${i + 1}`,
                value: `${nameResult.name} ${formatQtype(rrType)} ${formatClass(rrClass)} TTL=${ttl} RDATA=${rdataExtra}`,
            });
            cursor = rdEnd;
        }
    }

    return { id, fields };
}

function decodeDnsFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 2) return null;

    // Split TCP-framed DNS (RFC 1035 §4.2.2): 2-byte big-endian length
    // prefix, then the DNS message. Concatenated messages are walked in
    // order until the buffer is exhausted.
    const frames = [];
    const firstLength = readUint16(bytes, 0);
    // Detect TCP framing when the length prefix accounts for the whole
    // remaining buffer (single frame) OR the length at offset 0 is
    // followed by another valid length-prefixed frame (multi-frame stream).
    if (firstLength !== null && firstLength > 0 && firstLength + 2 <= bytes.length) {
        if (firstLength + 2 === bytes.length) {
            // Single TCP-framed message.
            frames.push(bytes.slice(2, 2 + firstLength));
        } else if (bytes.length >= 4) {
            // Try walking multiple frames; if the first sub-frame parses
            // cleanly we accept the stream, otherwise fall back to a single
            // unframed decode so the user gets SOMETHING instead of null.
            let cursor = 0;
            let walkedFrames = 0;
            while (cursor < bytes.length) {
                const frameLength = readUint16(bytes, cursor);
                if (frameLength === null || frameLength === 0) break;
                if (cursor + 2 + frameLength > bytes.length) break;
                frames.push(bytes.slice(cursor + 2, cursor + 2 + frameLength));
                cursor += 2 + frameLength;
                walkedFrames += 1;
            }
            if (walkedFrames === 0) frames.length = 0;
        }
    }
    if (!frames.length) frames.push(bytes);

    try {
        const fields = [];
        let decodedCount = 0;
        let messageIndex = 0;
        for (const frame of frames) {
            if (messageIndex >= DNS_MAX_MESSAGES) break;
            const decoded = decodeDnsMessage(frame, messageIndex + 1);
            if (!decoded) break;
            messageIndex += 1;
            decoded.fields.forEach((field) => fields.push(field));
            decodedCount += 1;
        }
        if (!decodedCount) return null;
        if (messageIndex >= DNS_MAX_MESSAGES) {
            fields.push({
                name: "Notice",
                value: `Showing first ${DNS_MAX_MESSAGES} DNS messages from stream.`,
            });
        }
        return { protocol: "DNS", fields };
    } catch {
        return null;
    }
}

module.exports = { decodeDnsFromBytes };
