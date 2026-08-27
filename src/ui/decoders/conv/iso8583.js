// ISO 8583 Conv decoder: parses the Message Type Indicator (MTI),
// primary/secondary bitmap, and standard data elements from an ISO 8583
// financial message. Mirrors the shape of smpp.js — returns
// { protocol, fields } or null.

const ISO_MTI_NAMES = {
    "0100": "Authorization Request",
    "0110": "Authorization Request Response",
    "0120": "Authorization Advice",
    "1200": "Authorization Request (BCD)",
    "0121": "Authorization Advice Repeat",
    "0121": "Authorization Advice Repeat",
    "0130": "Authorization Reversal",
    "0140": "Authorization Reversal Response",
    "0200": "Acquirer Reversal Request",
    "0210": "Acquirer Reversal Response",
    "0220": "Acquirer Advice",
    "0221": "Acquirer Advice Repeat",
    "0230": "Acquirer Advice Reversal",
    "0400": "Acquirer Reversal Request",
    "0410": "Acquirer Reversal Response",
    "0420": "Acquirer Reversal Advice",
    "0500": "Acquirer Batch Settlement",
    "0510": "Acquirer Batch Settlement Response",
    "0600": "Acquirer Settlement Reversal",
    "0800": "Network Management Request",
    "0810": "Network Management Response",
    "0820": "Network Management Advice",
    "0830": "Network Management Reversal",
    "0900": "Acquirer Settlement Reversal",
};

const ISO_MTI_CLASS = {
    "0": "Authorization",
    "1": "Authorization Reversal",
    "2": "Acquirer Reversal / Advice",
    "4": "Acquirer Reversal",
    "5": "Acquirer Settlement",
    "8": "Network Management",
    "9": "Acquirer Settlement Reversal",
};

// MTI class prefix (first digit) meaning.
const ISO_MTI_CLASS_FALLBACK = {
    "0": "Authorization",
    "1": "Authorization Reversal",
    "2": "Acquirer Reversal / Advice",
    "3": "Acquirer Reversal Advice Reversal",
    "4": "Acquirer Reversal",
    "5": "Acquirer Settlement",
    "6": "Acquirer Settlement Reversal",
    "7": "Acquirer Settlement Reversal Repeat",
    "8": "Network Management",
    "9": "Acquirer Settlement Reversal",
};
// Merge ISO_MTI_CLASS into the primary class map for display.
Object.assign(ISO_MTI_CLASS, ISO_MTI_CLASS_FALLBACK);

// field number → { name, fmt, len }
//   fmt: "n" numeric, "an" alphanumeric, "ans" alphanumeric+special,
//        "b" binary, "z" track data
//   len: number (fixed chars/bytes), "llvar", "lllvar"
const ISO_DATA_ELEMENTS = {
    2: { name: "Primary Account Number (PAN)", fmt: "n", len: "llvar" },
    3: { name: "Processing Code", fmt: "n", len: 6 },
    4: { name: "Amount, Transaction", fmt: "n", len: 12 },
    5: { name: "Amount, Settlement", fmt: "n", len: 12 },
    6: { name: "Amount, Cardholder Billing", fmt: "n", len: 12 },
    7: { name: "Transmission Date & Time", fmt: "n", len: 10 },
    9: { name: "Conversion Rate, Settlement", fmt: "n", len: 8 },
    10: { name: "Conversion Rate, Cardholder Billing", fmt: "n", len: 8 },
    11: { name: "System Trace Audit Number (STAN)", fmt: "n", len: 6 },
    12: { name: "Local Transaction Time", fmt: "n", len: 6 },
    13: { name: "Local Transaction Date", fmt: "n", len: 4 },
    14: { name: "Expiration Date", fmt: "n", len: 4 },
    15: { name: "Settlement Date", fmt: "n", len: 4 },
    18: { name: "Merchant Category Code", fmt: "n", len: 4 },
    22: { name: "POS Entry Mode", fmt: "n", len: 3 },
    23: { name: "Card Sequence Number", fmt: "n", len: 3 },
    24: { name: "Function Code", fmt: "n", len: 3 },
    25: { name: "POS Condition Code", fmt: "n", len: 2 },
    26: { name: "POS PIN Capture Code", fmt: "n", len: 2 },
    32: { name: "Acquiring Institution Id Code", fmt: "n", len: "llvar" },
    33: { name: "Forwarding Institution Id Code", fmt: "n", len: "llvar" },
    35: { name: "Track 2 Data", fmt: "z", len: "llvar" },
    36: { name: "Track 3 Data", fmt: "z", len: "lllvar" },
    37: { name: "Retrieval Reference Number", fmt: "an", len: 12 },
    38: { name: "Authorization Identification Response", fmt: "an", len: 6 },
    39: { name: "Response Code", fmt: "an", len: 2 },
    41: { name: "Card Acceptor Terminal Id", fmt: "ans", len: 8 },
    42: { name: "Card Acceptor Id Code", fmt: "ans", len: 15 },
    43: { name: "Card Acceptor Name/Location", fmt: "ans", len: 40 },
    44: { name: "Additional Response Data", fmt: "ans", len: "llvar" },
    45: { name: "Track 1 Data", fmt: "ans", len: "llvar" },
    48: { name: "Additional Data — Private", fmt: "ans", len: "lllvar" },
    49: { name: "Currency Code, Transaction", fmt: "n", len: 3 },
    50: { name: "Currency Code, Settlement", fmt: "n", len: 3 },
    52: { name: "PIN Data", fmt: "b", len: 8 },
    53: { name: "Security Related Control Info", fmt: "n", len: 16 },
    54: { name: "Additional Amounts", fmt: "an", len: "llvar" },
    55: { name: "ICC System Related Data", fmt: "ans", len: "lllvar" },
    64: { name: "Message Authentication Code (MAC)", fmt: "b", len: 8 },
    70: { name: "Network Mgmt Info Code", fmt: "n", len: 3 },
    90: { name: "Original Data Elements", fmt: "an", len: 42 },
    95: { name: "Card Issuer Name/Location", fmt: "ans", len: 45 },
    100: { name: "Receiving Institution Id Code", fmt: "n", len: "llvar" },
    102: { name: "Account Identification 1", fmt: "ans", len: "llvar" },
    103: { name: "Account Identification 2", fmt: "ans", len: "llvar" },
    128: { name: "Message Authentication Code (MAC)", fmt: "b", len: 8 },
};

function isAsciiDigits(bytes, count) {
    if (bytes.length < count) return false;
    for (let i = 0; i < count; i++) {
        if (bytes[i] < 0x30 || bytes[i] > 0x39) return false;
    }
    return true;
}

function readAscii(bytes, offset, count) {
    if (offset + count > bytes.length) return null;
    let s = "";
    for (let i = 0; i < count; i++) {
        s += String.fromCharCode(bytes[offset + i]);
    }
    return s;
}

// Read bytes as ASCII if printable, otherwise as hex. Used for binary-len
// mode where field values may be BCD-packed (e.g. PAN 0x12 0x34 ... → hex
// "123456...").
function readAsciiOrHex(bytes, offset, count) {
    if (offset + count > bytes.length) return null;
    let ascii = "";
    let allPrintable = true;
    for (let i = 0; i < count; i++) {
        const b = bytes[offset + i];
        if (b < 0x20 || b > 0x7e) {
            allPrintable = false;
            break;
        }
        ascii += String.fromCharCode(b);
    }
    if (allPrintable) return ascii;
    // Fallback: render as hex
    return readBinaryHex(bytes, offset, count);
}

function readBinaryHex(bytes, offset, count) {
    if (offset + count > bytes.length) return null;
    let s = "";
    for (let i = 0; i < count; i++) {
        s += bytes[offset + i].toString(16).padStart(2, "0").toUpperCase();
    }
    return s;
}

function readLlvar(bytes, offset, binaryLen) {
    if (binaryLen) {
        // Binary 1-byte length prefix (e.g. 0x16 = 22).
        if (offset + 1 > bytes.length) return null;
        const length = bytes[offset];
        if (offset + 1 + length > bytes.length) return null;
        return { value: readAsciiOrHex(bytes, offset + 1, length), consumed: 1 + length };
    }
    if (offset + 2 > bytes.length) return null;
    const lenStr = readAscii(bytes, offset, 2);
    if (lenStr === null) return null;
    const length = parseInt(lenStr, 10);
    if (!Number.isFinite(length) || offset + 2 + length > bytes.length) return null;
    return { value: readAsciiOrHex(bytes, offset + 2, length), consumed: 2 + length };
}

function readLllvar(bytes, offset, binaryLen) {
    if (binaryLen) {
        // Binary 2-byte length prefix (big-endian).
        if (offset + 2 > bytes.length) return null;
        const length = (bytes[offset] << 8) | bytes[offset + 1];
        if (offset + 2 + length > bytes.length) return null;
        return { value: readAsciiOrHex(bytes, offset + 2, length), consumed: 2 + length };
    }
    if (offset + 3 > bytes.length) return null;
    const lenStr = readAscii(bytes, offset, 3);
    if (lenStr === null) return null;
    const length = parseInt(lenStr, 10);
    if (!Number.isFinite(length) || offset + 3 + length > bytes.length) return null;
    return { value: readAsciiOrHex(bytes, offset + 3, length), consumed: 3 + length };
}

function parseBitmap(bytes, offset, asciiBitmap) {
    // Returns { fields: Set<number>, consumed: number } or null.
    const fields = new Set();
    let consumed = 0;
    let primary;
    if (asciiBitmap) {
        if (offset + 16 > bytes.length) return null;
        let hexStr = "";
        for (let i = 0; i < 16; i++) {
            hexStr += String.fromCharCode(bytes[offset + i]);
        }
        primary = new Uint8Array(8);
        for (let i = 0; i < 8; i++) {
            primary[i] = parseInt(hexStr.substr(i * 2, 2), 16);
        }
        consumed = 16;
    } else {
        if (offset + 8 > bytes.length) return null;
        primary = bytes.slice(offset, offset + 8);
        consumed = 8;
    }
    for (let byteIdx = 0; byteIdx < 8; byteIdx++) {
        for (let bitPos = 0; bitPos < 8; bitPos++) {
            if (primary[byteIdx] & (0x80 >> bitPos)) {
                fields.add(byteIdx * 8 + bitPos + 1);
            }
        }
    }
    // Secondary bitmap if field 1 is set.
    if (fields.has(1)) {
        let secondary;
        if (asciiBitmap) {
            if (offset + consumed + 16 > bytes.length) return { fields, consumed };
            let hexStr = "";
            for (let i = 0; i < 16; i++) {
                hexStr += String.fromCharCode(bytes[offset + consumed + i]);
            }
            secondary = new Uint8Array(8);
            for (let i = 0; i < 8; i++) {
                secondary[i] = parseInt(hexStr.substr(i * 2, 2), 16);
            }
            consumed += 16;
        } else {
            if (offset + consumed + 8 > bytes.length) return { fields, consumed };
            secondary = bytes.slice(offset + consumed, offset + consumed + 8);
            consumed += 8;
        }
        for (let byteIdx = 0; byteIdx < 8; byteIdx++) {
            for (let bitPos = 0; bitPos < 8; bitPos++) {
                if (secondary[byteIdx] & (0x80 >> bitPos)) {
                    fields.add(64 + byteIdx * 8 + bitPos + 1);
                }
            }
        }
    }
    return { fields, consumed };
}

// Core decode logic extracted so we can retry with different framing offsets.
// `binaryLen` selects binary 1-byte/2-byte length prefixes for LLVAR/LLLVAR
// instead of ASCII 2-digit/3-digit.
function decodeAtOffset(bytes, binaryLen) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 12) return null;

    // MTI: 4 ASCII digits (most common). Some implementations pack the
    // MTI as 2 BCD bytes (0x12 0x00 -> "1200"); try that fallback only
    // when the first 4 bytes are NOT all ASCII digits but the first 2
    // bytes decode to a plausible BCD MTI.
    let mti = null;
    let offset = 0;
    if (isAsciiDigits(bytes, 4)) {
        mti = readAscii(bytes, 0, 4);
        offset = 4;
    } else if (bytes.length >= 2) {
        const b0 = bytes[0], b1 = bytes[1];
        if ((b0 >> 4) <= 9 && (b0 & 0x0f) <= 9 && (b1 >> 4) <= 9 && (b1 & 0x0f) <= 9) {
            mti = `${b0 >> 4}${b0 & 0xf}${b1 >> 4}${b1 & 0xf}`;
            offset = 2;
            // BCD-packed MTI is a fallback path. Require the decoded MTI
            // to be a known ISO 8583 message type so that arbitrary binary
            // data (e.g. HTTP text "HTTP" -> BCD "4854") is not
            // misidentified as ISO 8583.
            if (!ISO_MTI_NAMES[mti]) return null;
        }
    }
    if (!mti) return null;

    // Detect ASCII (hex-digit) vs binary bitmap.
    let asciiBitmap = false;
    if (offset + 16 <= bytes.length) {
        let allHex = true;
        for (let i = 0; i < 16; i++) {
            const b = bytes[offset + i];
            if (!((b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66))) {
                allHex = false;
                break;
            }
        }
        if (allHex) asciiBitmap = true;
    }

    const bitmapResult = parseBitmap(bytes, offset, asciiBitmap);
    if (!bitmapResult) return null;
    offset += bitmapResult.consumed;
    const fieldsSet = bitmapResult.fields;

    // Sanity: if the bitmap claims data fields exist but the remaining
    // payload is empty (0 bytes), this is almost certainly not a real
    // ISO 8583 message (e.g. "HTTP/1.1 200 OK" -> MTI "4854" + garbage
    // bitmap with no data following).
    const dataFields = Array.from(fieldsSet).filter((f) => f !== 1);
    if (dataFields.length > 0 && offset >= bytes.length) return null;

    const fields = [
        { name: "MTI", value: mti },
        { name: "Message Type", value: ISO_MTI_NAMES[mti] || "Unknown" },
        { name: "MTI Class", value: ISO_MTI_CLASS[mti[0]] || "Unknown" },
        {
            name: "Bitmap Fields",
            value: Array.from(fieldsSet).sort((a, b) => a - b).join(", "),
        },
    ];

    const fieldNums = Array.from(fieldsSet).sort((a, b) => a - b);
    let anyFieldDecoded = false;
    for (const fieldNum of fieldNums) {
        if (fieldNum === 1) continue;
        const def = ISO_DATA_ELEMENTS[fieldNum];
        if (!def) {
            fields.push({ name: `Field ${fieldNum}`, value: "(unknown / reserved)" });
            continue;
        }
        if (offset >= bytes.length) {
            fields.push({ name: `Field ${fieldNum} (${def.name})`, value: "(truncated)" });
            break;
        }

        const available = bytes.length - offset;
        let value = null;
        let consumed = 0;
        let truncated = false;
        if (def.len === "llvar") {
            const minPrefix = binaryLen ? 1 : 2;
            if (available < minPrefix) {
                truncated = true;
            } else {
                const r = readLlvar(bytes, offset, binaryLen);
                if (r) { value = r.value; consumed = r.consumed; }
            }
        } else if (def.len === "lllvar") {
            const minPrefix = binaryLen ? 2 : 3;
            if (available < minPrefix) {
                truncated = true;
            } else {
                const r = readLllvar(bytes, offset, binaryLen);
                if (r) { value = r.value; consumed = r.consumed; }
            }
        } else if (typeof def.len === "number") {
            if (available < def.len) {
                truncated = true;
            } else if (def.fmt === "b") {
                value = readBinaryHex(bytes, offset, def.len);
                if (value !== null) consumed = def.len;
            } else {
                value = readAsciiOrHex(bytes, offset, def.len);
                if (value !== null) consumed = def.len;
            }
        }

        if (truncated) {
            fields.push({ name: `Field ${fieldNum} (${def.name})`, value: "(truncated)" });
            break;
        }
        if (value === null) {
            // The first data field failed to parse. For a genuine ISO 8583
            // message the first set field should be decodable; a parse
            // failure on the very first field strongly suggests this is
            // not ISO 8583 at all (e.g. HTTP text that started with 4
            // ASCII digits). Reject the whole message.
            if (!anyFieldDecoded) return null;
            fields.push({ name: `Field ${fieldNum} (${def.name})`, value: "(parse error)" });
            break;
        }
        offset += consumed;
        anyFieldDecoded = true;
        fields.push({ name: `Field ${fieldNum} (${def.name})`, value });
    }

    return { protocol: "ISO 8583", fields };
}

function decodeIso8583FromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 12) return null;

    // ISO 8583 over TCP commonly carries a 2-byte message-length header
    // (TPDU framing) before the MTI. Try the raw bytes first (no prefix),
    // then a 2-byte prefix strip. For each offset, try both ASCII and
    // binary length-prefix modes for LLVAR/LLLVAR fields.
    const candidates = [0, 2, 4];
    for (const skip of candidates) {
        if (skip >= bytes.length) break;
        const sliced = skip > 0 ? bytes.slice(skip) : bytes;
        // Try ASCII length prefixes first (most common), then binary.
        let result = decodeAtOffset(sliced, false);
        if (result) return result;
        result = decodeAtOffset(sliced, true);
        if (result) return result;
    }
    return null;
}

module.exports = { decodeIso8583FromBytes };