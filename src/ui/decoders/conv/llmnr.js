// LLMNR Conv decoder: parses LLMNR (Link-Local Multicast Name Resolution,
// RFC 4795) messages from raw bytes. LLMNR is a near-clone of the DNS
// wire format, so the decoder mirrors the DNS layout (ID, flags, QD/AN/NS/AR
// counts, label-sequence QNAME, QTYPE/QCLASS, and per-RR resource records).
//
// The decoder accepts:
//   * UDP/5355 single-message payloads (no length prefix),
//   * TCP/5355 length-prefixed messages (RFC 1035 §4.2.2 framing; RFC 4795
//     §2.5 calls this out as well), and
//   * Concatenated TCP-framed messages, walked in order until the buffer is
//     exhausted.
//
// Differences from DNS that we surface explicitly:
//   * QR bit semantics (C bit), and the LLMNR-specific opcode mapping
//     (0 = standard query, 1 = inverse query, 2 = obsolete).
//   * The LLMNR response code space (0=success, 1=unspecified error,
//     2=server failure, 3=refused) per RFC 4795 §2.1.2.
//   * LLMNR is always class IN (QCLASS=1); we still surface the class so
//     the user can see when something unusual arrives.

const { bytesToHexLower } = require("./smb-helpers");

const LLMNR_MAX_MESSAGES = 64;
const LLMNR_LABEL_VALUE_LIMIT = 220;
const LLMNR_RDATA_VALUE_LIMIT = 220;

// DNS-class names that LLMNR re-uses for the QCLASS/RR CLASS fields. LLMNR
// is always IN in practice, but we keep the same map as the DNS decoder so
// a non-IN class is reported with the same label.
const LLMNR_CLASS_NAMES = {
    1: "IN",
    2: "CS",
    3: "CH",
    4: "HS",
    255: "ANY",
};

// RFC 4795 §2.1.1: LLMNR uses the same QTYPE / RR type space as DNS.
// We only need a subset for the inline label, so we share the DNS qtype
// map by trimming it to the most common types and fall back to TYPE<num>.
const LLMNR_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
};

// LLMNR defines only four response codes (RFC 4795 §2.1.2). We map them
// here and report anything else as RCODE<num>.
const LLMNR_RCODE_NAMES = {
    0: "Success",
    1: "Unspecified Error",
    2: "Server Failure",
    3: "Refused",
};

// LLMNR uses the same DNS label / compression-pointer encoding, so we
// share the DNS name decoder rather than duplicating the walk. The DNS
// decoder is small and side-effect-free, so requiring it here keeps the
// LLMNR decoder self-contained.
const { decodeDnsName } = require("./dns-helpers");

// Read a big-endian uint16 from a Uint8Array.
function readUint16(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 2 > bytes.length) return null;
    return (bytes[offset] << 8) | bytes[offset + 1];
}

// Read a big-endian uint32 from a Uint8Array.
function readUint32(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 4 > bytes.length) return null;
    return ((bytes[offset] << 24) |
        (bytes[offset + 1] << 16) |
        (bytes[offset + 2] << 8) |
        bytes[offset + 3]) >>> 0;
}

function pushTruncated(fields, name, value, limit) {
    if (typeof value !== "string" || !value) return;
    const trimmed = value.length > limit ? `${value.slice(0, limit)}...` : value;
    fields.push({ name, value: trimmed });
}

function formatClass(classValue) {
    return LLMNR_CLASS_NAMES[classValue] || `CLASS${classValue}`;
}

function formatQtype(qtype) {
    return LLMNR_QTYPE_NAMES[qtype] || `TYPE${qtype}`;
}

function formatRcode(rcode) {
    return LLMNR_RCODE_NAMES[rcode] || `RCODE${rcode}`;
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

function formatMx(rdBytes, messageBytes) {
    if (!(rdBytes instanceof Uint8Array) || rdBytes.length < 3) return null;
    const preference = readUint16(rdBytes, 0);
    if (preference === null) return null;
    const exchange = decodeDnsName(rdBytes, 2, messageBytes ? messageBytes.length : rdBytes.length);
    if (!exchange.ok) return null;
    return `${preference} ${exchange.name}`;
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

function decodeLlmnrMessage(bytes, messageIndex) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 12) return null;
    const id = readUint16(bytes, 0);
    const flags = readUint16(bytes, 2);
    const qdCount = readUint16(bytes, 4);
    const anCount = readUint16(bytes, 6);
    const nsCount = readUint16(bytes, 8);
    const arCount = readUint16(bytes, 10);
    if (
        id === null || flags === null ||
        qdCount === null || anCount === null ||
        nsCount === null || arCount === null
    ) {
        return null;
    }

    const fields = [];
    const prefix = `Message ${messageIndex}`;
    pushTruncated(
        fields,
        `${prefix} ID`,
        `0x${id.toString(16).padStart(4, "0")}`,
        LLMNR_LABEL_VALUE_LIMIT,
    );
    const isResponse = (flags & 0x8000) !== 0;
    fields.push({ name: `${prefix} Type`, value: isResponse ? "Response" : "Query" });

    // RFC 4795 §2.1.1: LLMNR only defines three opcodes (0=standard,
    // 1=inverse, 2=obsolete). We surface the raw value with a label.
    const opcode = (flags >> 11) & 0x0f;
    const opcodeLabel = ["Standard Query", "Inverse Query", "Obsolete"][opcode] || `OPCODE${opcode}`;
    fields.push({ name: `${prefix} Opcode`, value: opcodeLabel });

    const rcode = flags & 0x000f;
    fields.push({ name: `${prefix} Rcode`, value: formatRcode(rcode) });

    // LLMNR re-uses the DNS header flag bits with slightly different
    // semantics for AA / TC / RD / RA / Z / AD / CD.
    const flagBits = [
        [0x0400, "AA", "authoritative"],
        [0x0200, "TC", "truncated"],
        [0x0100, "RD", "recursion-desired"],
        [0x0080, "RA", "recursion-available"],
        [0x0040, "Z", "z"],
        [0x0020, "AD", "authenticated-data"],
        [0x0010, "CD", "checking-disabled"],
    ];
    flagBits.forEach(([mask, label, longLabel]) => {
        const enabled = (flags & mask) !== 0;
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

    let questionIndex = 0;
    while (questionIndex < qdCount && questionIndex < 256 && cursor < bytes.length) {
        const nameResult = decodeDnsName(bytes, cursor, bytes.length);
        if (!nameResult.ok || !nameResult.endIndex) {
            cursor = bytes.length;
            break;
        }
        cursor = nameResult.endIndex;
        if (cursor + 4 > bytes.length) break;
        const qtype = readUint16(bytes, cursor);
        const qclass = readUint16(bytes, cursor + 2);
        if (qtype === null || qclass === null) break;
        questionIndex += 1;
        fields.push({
            name: `${prefix} Question ${questionIndex}`,
            value: `${nameResult.name} ${formatQtype(qtype)} ${formatClass(qclass)}`,
        });
        cursor += 4;
    }

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
            let rdataExtra = rdataPreview;
            switch (rrType) {
                case 1:
                    rdataExtra = formatA(rdBytes) || rdataPreview;
                    break;
                case 28:
                    rdataExtra = formatAaaa(rdBytes) || rdataPreview;
                    break;
                case 2:
                case 5:
                case 12: {
                    const nameRef = decodeDnsName(rdBytes, 0, bytes.length);
                    rdataExtra = nameRef.ok ? nameRef.name : rdataPreview;
                    break;
                }
                case 15:
                    rdataExtra = formatMx(rdBytes, bytes) || rdataPreview;
                    break;
                case 16: {
                    const strings = formatTxt(rdBytes);
                    rdataExtra = strings.length ? strings.map((s) => `"${s}"`).join(" ") : rdataPreview;
                    break;
                }
                case 33:
                    rdataExtra = formatSrv(rdBytes, bytes.length) || rdataPreview;
                    break;
                default:
                    rdataExtra = rdataPreview;
                    break;
            }
            if (rdataExtra.length > LLMNR_RDATA_VALUE_LIMIT) {
                rdataExtra = `${rdataExtra.slice(0, LLMNR_RDATA_VALUE_LIMIT)}...`;
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

function decodeLlmnrFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 2) return null;

    // LLMNR mirrors DNS, so TCP framing (RFC 1035 §4.2.2) carries over:
    // 2-byte big-endian length prefix, then the LLMNR message. We walk
    // any concatenated frames before falling back to a single unframed
    // decode so the user always gets SOMETHING instead of null.
    const frames = [];
    const firstLength = readUint16(bytes, 0);
    if (firstLength !== null && firstLength > 0 && firstLength + 2 <= bytes.length) {
        if (firstLength + 2 === bytes.length) {
            frames.push(bytes.slice(2, 2 + firstLength));
        } else if (bytes.length >= 4) {
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
            if (messageIndex >= LLMNR_MAX_MESSAGES) break;
            const decoded = decodeLlmnrMessage(frame, messageIndex + 1);
            if (!decoded) break;
            messageIndex += 1;
            decoded.fields.forEach((field) => fields.push(field));
            decodedCount += 1;
        }
        if (!decodedCount) return null;
        if (messageIndex >= LLMNR_MAX_MESSAGES) {
            fields.push({
                name: "Notice",
                value: `Showing first ${LLMNR_MAX_MESSAGES} LLMNR messages from stream.`,
            });
        }
        return { protocol: "LLMNR", fields };
    } catch {
        return null;
    }
}

module.exports = { decodeLlmnrFromBytes };
