// NetBIOS Datagram Service (NetBIOS-DGM) Conv decoder: parses the
// RFC 1002 §4.4 datagram payload that runs over UDP/138. A NetBIOS
// datagram message is wrapped in an 8-byte NetBIOS session header
// (MSG_TYPE byte + 7-byte LENGTH field) and contains:
//   * 1-byte datagram TYPE (message / broadcast / error / etc.),
//   * 1-byte FLAGS (more / first / only datagram + node type),
//   * 2-byte datagram ID,
//   * 34-byte source name (1-byte label length + 32-byte encoded body
//     + 1-byte scope suffix byte),
//   * 34-byte destination name (same layout),
//   * variable-length DATA (1+ byte).
//
// The decoder surfaces the message-level TYPE / FLAGS / DGM_ID, the
// decoded source and destination NetBIOS names, the data length, and
// a hex preview of the data block so the user can see what was being
// broadcast. When the supplied buffer does not start with a valid
// NetBIOS session header (TYPE byte 0x10/0x11/0x12/0x13/0x14/0x15/0x16)
// the decoder returns null so the auto-detect chain can move on.

const { bytesToHexLower } = require("./smb-helpers");

const NBDGM_MIN_LENGTH = 8 /* session header */ + 1 /* type */ +
    1 /* flags */ + 2 /* id */ + 34 /* source */ + 34 /* dest */;
const NBDGM_MAX_DATA_PREVIEW = 220;

// NetBIOS Datagram Service message types (RFC 1002 §4.4.1.1).
const NBDGM_TYPE_NAMES = {
    0x10: "Datagram",
    0x11: "Datagram Broadcast",
    0x12: "Datagram Error",
    0x13: "Request Name Query",
    0x14: "Positive Name Query Response",
    0x15: "Negative Name Query Response",
};

// NetBIOS Datagram Service FLAGS byte (RFC 1002 §4.4.1.2).
const NBDGM_NODE_TYPE_NAMES = {
    0: "B-node",
    1: "P-node",
    2: "M-node",
    3: "NBDD",
};

function readUint16(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 2 > bytes.length) return null;
    return (bytes[offset] << 8) | bytes[offset + 1];
}

function pushTruncated(fields, name, value, limit) {
    if (typeof value !== "string" || !value) return;
    const trimmed = value.length > limit ? `${value.slice(0, limit)}...` : value;
    fields.push({ name, value: trimmed });
}

// Read a 1-byte label length + 32-byte encoded body + 1-byte scope byte
// starting at `startIndex`. Returns { name, endIndex, ok } where
// endIndex points to the byte after the scope byte.
function decodeNetbiosEncodedName(bytes, startIndex) {
    if (!(bytes instanceof Uint8Array) || startIndex < 1) {
        return { name: "", endIndex: startIndex, ok: false };
    }
    const labelLength = bytes[startIndex];
    const bodyLength = labelLength === 0x20 ? 32 : labelLength & 0x3f;
    const bodyStart = startIndex + 1;
    const bodyEnd = bodyStart + bodyLength;
    if (bodyEnd > bytes.length) {
        return { name: "", endIndex: startIndex, ok: false };
    }
    if (bodyLength !== 32) {
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
    const visibleLength = bytes[bodyEnd - 1];
    const visible = chars.slice(0, visibleLength).join("").trim();
    return { name: visible, endIndex: bodyEnd, ok: true };
}

// Walk over a 34-byte source/destination name block. The first byte is
// a length byte (always 0x20 for a 32-byte body), the next 32 bytes
// are the encoded name, and the 34th byte is the scope suffix byte.
function decodeNetbiosNameBlock(bytes, startIndex) {
    const encoded = decodeNetbiosEncodedName(bytes, startIndex);
    if (!encoded.ok) return encoded;
    // The name block is always exactly 34 bytes (length + 32 + scope).
    const blockEnd = startIndex + 34;
    if (blockEnd > bytes.length) {
        return { name: encoded.name, endIndex: startIndex, ok: false };
    }
    return { name: encoded.name, endIndex: blockEnd, ok: true };
}

function decodeNbdgmFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < NBDGM_MIN_LENGTH) return null;
    const msgType = bytes[0];
    if (!Object.prototype.hasOwnProperty.call(NBDGM_TYPE_NAMES, msgType)) {
        return null;
    }
    // Datagram data starts immediately after the 8-byte session header.
    const typeByte = bytes[8];
    const flags = bytes[9];
    const dgmId = readUint16(bytes, 10);
    if (dgmId === null) return null;
    const sourceNameResult = decodeNetbiosNameBlock(bytes, 12);
    if (!sourceNameResult.ok) return null;
    const destNameResult = decodeNetbiosNameBlock(bytes, sourceNameResult.endIndex);
    if (!destNameResult.ok) return null;
    const dataStart = destNameResult.endIndex;
    const dataLength = bytes.length - dataStart;

    const fields = [];
    fields.push({ name: "Message Type", value: NBDGM_TYPE_NAMES[typeByte] || `0x${typeByte.toString(16).padStart(2, "0")}` });
    const more = (flags & 0x01) !== 0;
    const first = (flags & 0x02) !== 0;
    let fragmentLabel = "Intermediate";
    if (first && more) fragmentLabel = "First of Fragmented Group";
    else if (first && !more) fragmentLabel = "Only Datagram";
    else if (!first && more) fragmentLabel = "Middle of Fragmented Group";
    fields.push({ name: "Fragment", value: fragmentLabel });
    const nodeType = (flags >> 2) & 0x03;
    fields.push({ name: "Source Node Type", value: NBDGM_NODE_TYPE_NAMES[nodeType] || `0x${nodeType.toString(16)}` });
    fields.push({ name: "Datagram ID", value: `0x${dgmId.toString(16).padStart(4, "0")}` });
    fields.push({ name: "Source Name", value: sourceNameResult.name || "(empty)" });
    fields.push({ name: "Destination Name", value: destNameResult.name || "(empty)" });
    fields.push({ name: "Data Length", value: String(dataLength) });
    if (dataLength > 0) {
        const dataBytes = bytes.slice(dataStart, Math.min(dataStart + NBDGM_MAX_DATA_PREVIEW, bytes.length));
        pushTruncated(fields, "Data Preview (hex)", bytesToHexLower(dataBytes), NBDGM_MAX_DATA_PREVIEW);
        const textPreview = new TextDecoder("utf-8", { fatal: false })
            .decode(dataBytes)
            .replace(/[^\x20-\x7e]/g, "");
        if (textPreview) {
            pushTruncated(fields, "Data Preview (text)", textPreview, NBDGM_MAX_DATA_PREVIEW);
        }
    }
    return { protocol: "NetBIOS-DGM", fields };
}

module.exports = { decodeNbdgmFromBytes };
