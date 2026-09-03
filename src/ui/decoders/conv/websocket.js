// WebSocket Conv decoder: parses RFC 6455 WebSocket frames and HTTP
// Upgrade handshake packets out of byte streams and emits a curated
// set of fields for the Conv Decoders panel.
//
// This decoder handles two WebSocket payloads:
//
//   1. HTTP Upgrade handshake — a text request/response containing
//      "Upgrade: websocket" and the Sec-WebSocket-Key/Accept headers.
//      Detected by the "Upgrade: websocket" header anywhere in the
//      first 512 bytes of text.
//
//   2. RFC 6455 frames — one or more binary frames with the standard
//      byte-0 FIN/RSV/opcode layout, byte-1 mask/length, extended
//      16/64-bit lengths, and optional 4-byte masking key. Multiple
//      concatenated frames in a single payload are all decoded (cap
//      at MAX_FRAMES = 25).
//
// Content-based detection: the Upgrade handshake is text-based and
// caught by the HTTP detector first in most cases (it IS an HTTP
// request/response). The frame detector must run BEFORE the
// low-confidence decoders (msgpack/protobuf) because a WebSocket
// frame's first two bytes can look like a valid msgpack/protobuf
// header. We validate strictly: opcode must be in the known set,
// RSV bits must be clear (unless opcode is valid — extensions are
// rare in captures), and the payload length must not exceed the
// remaining bytes.

const MAX_FRAMES = 25;
const MAX_PAYLOAD_PREVIEW = 128;

const WS_OPCODES = {
    0x0: "Continuation",
    0x1: "Text",
    0x2: "Binary",
    0x8: "Close",
    0x9: "Ping",
    0xA: "Pong",
};

// Close-frame status codes (RFC 6455 §7.4.1) — used to annotate
// Close-control frames that carry a body.
const CLOSE_CODES = {
    1000: "Normal Closure",
    1001: "Going Away",
    1002: "Protocol Error",
    1003: "Unsupported Data",
    1005: "No Status Received",
    1006: "Abnormal Closure",
    1007: "Invalid frame Payload Data",
    1008: "Policy Violation",
    1009: "Message Too Big",
    1010: "Mandatory Extension",
    1011: "Internal Server Error",
    1015: "TLS Handshake",
};

const UPGRADE_HEADER_NAMES = [
    "Host",
    "Upgrade",
    "Connection",
    "Sec-WebSocket-Key",
    "Sec-WebSocket-Accept",
    "Sec-WebSocket-Version",
    "Sec-WebSocket-Protocol",
    "Sec-WebSocket-Extensions",
    "Origin",
];

function readUint16BE(bytes, offset) {
    return ((bytes[offset] << 8) | bytes[offset + 1]) >>> 0;
}

function readUint32BE(bytes, offset) {
    return (
        ((bytes[offset] << 24) | (bytes[offset + 1] << 16) |
            (bytes[offset + 2] << 8) | bytes[offset + 3])
    ) >>> 0;
}

// Reads a 64-bit big-endian unsigned integer. Returns a Number (safe
// for payload lengths up to 2^53, which covers all realistic frames).
function readUint64BE(bytes, offset) {
    const high = readUint32BE(bytes, offset);
    const low = readUint32BE(bytes, offset + 4);
    return high * 0x100000000 + low;
}

// Decodes the HTTP Upgrade handshake (request or response) and emits
// the relevant WebSocket-specific headers. Returns null if this is not
// a WebSocket upgrade handshake.
function decodeUpgradeHandshake(text) {
    const lower = text.slice(0, 512).toLowerCase();
    if (!lower.includes("upgrade: websocket") && !lower.includes("upgrade:websockets")) {
        return null;
    }

    // Split into headers. Handle both \r\n and \n line endings.
    const lines = text.split(/\r?\n/);
    if (!lines.length) return null;

    const startLine = (lines[0] || "").trim();
    const isRequest = /^(GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH)\s+\S+\s+HTTP\/[\d.]+$/i.test(startLine);
    const isResponse = /^HTTP\/[\d.]+\s+\d{3}/i.test(startLine);
    if (!isRequest && !isResponse) return null;

    const headers = {};
    for (let i = 1; i < lines.length; i += 1) {
        const line = lines[i];
        if (!line || !line.trim()) break;
        const colonIndex = line.indexOf(":");
        if (colonIndex > 0) {
            const name = line.slice(0, colonIndex).trim().toLowerCase();
            const value = line.slice(colonIndex + 1).trim();
            // Handle folded (continuation) header lines.
            if (line.startsWith(" ") || line.startsWith("\t")) {
                // Continuation of previous header — append.
                const lastKey = Object.keys(headers).pop();
                if (lastKey) headers[lastKey] += " " + value;
            } else {
                headers[name] = value;
            }
        }
    }

    const fields = [];
    fields.push({
        name: "Type",
        value: isRequest ? "Upgrade Request" : "Upgrade Response",
    });
    if (isRequest) {
        const match = startLine.match(/^(\S+)\s+(\S+)\s+(HTTP\/[\d.]+)/i);
        if (match) {
            fields.push(
                { name: "Method", value: match[1] },
                { name: "URL", value: match[2] },
                { name: "Version", value: match[3] },
            );
        }
    } else {
        const match = startLine.match(/^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)/i);
        if (match) {
            fields.push(
                { name: "Version", value: match[1] },
                { name: "Status Code", value: match[2] },
                { name: "Status Message", value: match[3] || "—" },
            );
        }
    }

    UPGRADE_HEADER_NAMES.forEach((headerName) => {
        const value = headers[headerName.toLowerCase()];
        if (value) fields.push({ name: headerName, value });
    });

    return { protocol: "WebSocket", fields };
}

// Parses a single WebSocket frame starting at `offset` in `bytes`.
// Returns { frame, nextOffset } where `frame` is the decoded frame
// object and `nextOffset` is the byte offset of the next frame (or
// bytes.length if this is the last frame). Returns null if the bytes
// at `offset` do not form a valid frame.
function parseFrame(bytes, offset) {
    if (offset + 2 > bytes.length) return null;

    const firstByte = bytes[offset];
    const secondByte = bytes[offset + 1];

    const fin = (firstByte & 0x80) !== 0;
    const rsv1 = (firstByte & 0x40) !== 0;
    const rsv2 = (firstByte & 0x20) !== 0;
    const rsv3 = (firstByte & 0x10) !== 0;
    const opcode = firstByte & 0x0f;

    // Validate opcode — must be one of the known values.
    if (!(opcode in WS_OPCODES)) return null;

    // RSV bits must be zero unless negotiated extensions are present.
    // In captures without extension negotiation, non-zero RSV on a
    // valid opcode is suspicious — reject to avoid false positives.
    if ((rsv1 || rsv2 || rsv3) && opcode < 0x8) return null;

    const masked = (secondByte & 0x80) !== 0;
    let payloadLen = secondByte & 0x7f;
    let cursor = offset + 2;

    if (payloadLen === 126) {
        if (cursor + 2 > bytes.length) return null;
        payloadLen = readUint16BE(bytes, cursor);
        cursor += 2;
    } else if (payloadLen === 127) {
        if (cursor + 8 > bytes.length) return null;
        payloadLen = readUint64BE(bytes, cursor);
        cursor += 8;
    }

    // Sanity-check: payload length must not exceed remaining bytes.
    // This rejects garbage that happens to have a valid opcode byte.
    if (payloadLen < 0 || payloadLen > bytes.length - cursor) return null;

    let maskKey = null;
    if (masked) {
        if (cursor + 4 > bytes.length) return null;
        maskKey = bytes.subarray(cursor, cursor + 4);
        cursor += 4;
    }

    const payloadStart = cursor;
    const payloadEnd = cursor + payloadLen;
    if (payloadEnd > bytes.length) return null;

    let payloadBytes = bytes.subarray(payloadStart, payloadEnd);
    let payloadText = null;
    let payloadPreview = null;

    if (masked && maskKey && payloadLen > 0) {
        const unmasked = new Uint8Array(payloadLen);
        for (let i = 0; i < payloadLen; i += 1) {
            unmasked[i] = payloadBytes[i] ^ maskKey[i % 4];
        }
        payloadBytes = unmasked;
    }

    // Build a preview of the payload (text or hex).
    if (opcode === 0x1) {
        // Text frame — try to decode as UTF-8.
        payloadText = new TextDecoder("utf-8", { fatal: false }).decode(payloadBytes);
        payloadPreview = payloadText.slice(0, MAX_PAYLOAD_PREVIEW);
        if (payloadText.length > MAX_PAYLOAD_PREVIEW) {
            payloadPreview += "...";
        }
    } else if (opcode === 0x8) {
        // Close frame — first 2 bytes are the status code (if present).
        if (payloadLen >= 2) {
            const closeCode = readUint16BE(payloadBytes, 0);
            const closeReason = CLOSE_CODES[closeCode] || "Unknown";
            const closeText = payloadLen > 2
                ? new TextDecoder("utf-8", { fatal: false }).decode(payloadBytes.subarray(2))
                : "";
            payloadPreview = `${closeCode} (${closeReason})`;
            if (closeText) payloadPreview += ` — "${closeText}"`;
        } else {
            payloadPreview = "No status code";
        }
    } else if (opcode === 0x9 || opcode === 0xa) {
        // Ping/Pong — payload is typically empty or a small opaque value.
        if (payloadLen > 0) {
            const hex = [];
            for (let i = 0; i < Math.min(payloadLen, 16); i += 1) {
                hex.push(payloadBytes[i].toString(16).padStart(2, "0"));
            }
            payloadPreview = "0x" + hex.join("");
            if (payloadLen > 16) payloadPreview += "...";
        } else {
            payloadPreview = "(empty)";
        }
    } else if (payloadLen > 0) {
        // Binary / continuation — show hex preview.
        const hex = [];
        for (let i = 0; i < Math.min(payloadLen, 16); i += 1) {
            hex.push(payloadBytes[i].toString(16).padStart(2, "0"));
        }
        payloadPreview = "0x" + hex.join("");
        if (payloadLen > 16) payloadPreview += "...";
    }

    return {
        frame: {
            fin,
            rsv1,
            rsv2,
            rsv3,
            opcode,
            opcodeName: WS_OPCODES[opcode],
            masked,
            payloadLen,
            payloadPreview,
            payloadText,
        },
        nextOffset: payloadEnd,
    };
}

function decodeWebSocketFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

    // First, check for HTTP Upgrade handshake (text-based).
    // This is the most common WebSocket-related payload in captures.
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(0, 512));
    const handshake = decodeUpgradeHandshake(text);
    if (handshake) return handshake;

    // Try parsing as RFC 6455 frames. We require at least one valid
    // frame to return a result.
    const fields = [];
    let offset = 0;
    let frameCount = 0;
    let firstFrame = null;

    while (offset < bytes.length && frameCount < MAX_FRAMES) {
        const result = parseFrame(bytes, offset);
        if (!result) break;

        const f = result.frame;
        if (frameCount === 0) firstFrame = f;

        const prefix = frameCount > 0 ? `Frame ${frameCount + 1} ` : "";
        fields.push({
            name: `${prefix}Type`,
            value: "Frame",
        });
        fields.push({
            name: `${prefix}Opcode`,
            value: `${f.opcodeName} (0x${f.opcode.toString(16)})`,
        });
        fields.push({
            name: `${prefix}FIN`,
            value: f.fin ? "Yes" : "No (fragmented)",
        });
        if (f.masked) {
            fields.push({ name: `${prefix}Masked`, value: "Yes (client→server)" });
        } else {
            fields.push({ name: `${prefix}Masked`, value: "No (server→client)" });
        }
        fields.push({
            name: `${prefix}Payload Length`,
            value: String(f.payloadLen),
        });
        if (f.payloadPreview) {
            fields.push({
                name: `${prefix}Payload Preview`,
                value: f.payloadPreview,
            });
        }

        frameCount += 1;
        const prevOffset = offset;
        offset = result.nextOffset;
        // Guard against infinite loops: if the frame consumed zero bytes,
        // stop rather than re-parsing the same position.
        if (offset <= prevOffset) break;
    }

    if (frameCount === 0) return null;

    return { protocol: "WebSocket", fields };
}

module.exports = { decodeWebSocketFromBytes };