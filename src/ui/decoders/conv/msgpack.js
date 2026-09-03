// MessagePack Conv decoder: classifies the first byte by the MessagePack
// format spec, validates the full byte stream against the spec, and
// reports a hex preview of the input.
//
// The decoder is intentionally strict: the MessagePack first-byte range
// is extremely permissive (any byte 0x00–0xFF is valid), so merely
// classifying the first byte is not enough to distinguish real
// MessagePack from arbitrary binary data. To avoid producing
// meaningless "decoded" output for every byte blob, we walk the entire
// input as a sequence of MessagePack values and only return a non-null
// result when the **entire** input is consumed without structural
// errors. This makes the decoder suitable for auto-detection without a
// "force" flag: random binary data will fail the walk at some point
// (truncated string length, out-of-range ext size, etc.) and the
// decoder will return null.

const PREVIEW_HEX_LIMIT = 48;

function classifyMessagePackType(firstByte) {
    if ((firstByte & 0x80) === 0x00 || (firstByte & 0xe0) === 0xe0) return "int";
    if ((firstByte & 0xe0) === 0xa0 || firstByte === 0xd9 || firstByte === 0xda || firstByte === 0xdb) return "string";
    if ((firstByte & 0xf0) === 0x90 || firstByte === 0xdc || firstByte === 0xdd) return "array";
    if ((firstByte & 0xf0) === 0x80 || firstByte === 0xde || firstByte === 0xdf) return "map";
    if ((firstByte & 0xe0) === 0xc0) return "misc/bin/ext/float";
    return "unknown";
}

// Walk a single MessagePack value starting at `index`. Returns the index
// after the value, or -1 if the bytes don't form a valid MessagePack value.
function walkMessagePackValue(bytes, index) {
    if (index >= bytes.length) return -1;
    const firstByte = bytes[index];

    // Positive / negative fixint: 1 byte.
    if (firstByte <= 0x7f || firstByte >= 0xe0) return index + 1;

    // fixstr (0xa0–0xbf): length = firstByte & 0x1f
    if ((firstByte & 0xe0) === 0xa0) {
        const len = firstByte & 0x1f;
        return index + 1 + len <= bytes.length ? index + 1 + len : -1;
    }
    // str 8 / str 16 / str 32
    if (firstByte === 0xd9 || firstByte === 0xda || firstByte === 0xdb) {
        let len;
        let next = index + 1;
        if (firstByte === 0xd9) {
            if (next + 1 > bytes.length) return -1;
            len = bytes[next];
            next += 1;
        } else if (firstByte === 0xda) {
            if (next + 2 > bytes.length) return -1;
            len = (bytes[next] << 8) | bytes[next + 1];
            next += 2;
        } else {
            if (next + 4 > bytes.length) return -1;
            len = (bytes[next] << 24) | (bytes[next + 1] << 16) | (bytes[next + 2] << 8) | bytes[next + 3];
            next += 4;
        }
        // Cap to avoid integer overflow / excessive lengths.
        if (len < 0 || len > bytes.length) return -1;
        return next + len <= bytes.length ? next + len : -1;
    }

    // fixarray (0x90–0x9f): count = firstByte & 0x0f elements
    if ((firstByte & 0xf0) === 0x90) {
        const count = firstByte & 0x0f;
        let pos = index + 1;
        for (let i = 0; i < count; i++) {
            pos = walkMessagePackValue(bytes, pos);
            if (pos === -1) return -1;
        }
        return pos;
    }
    // array 16 / array 32
    if (firstByte === 0xdc || firstByte === 0xdd) {
        let count;
        let next = index + 1;
        if (firstByte === 0xdc) {
            if (next + 2 > bytes.length) return -1;
            count = (bytes[next] << 8) | bytes[next + 1];
            next += 2;
        } else {
            if (next + 4 > bytes.length) return -1;
            count = (bytes[next] << 24) | (bytes[next + 1] << 16) | (bytes[next + 2] << 8) | bytes[next + 3];
            next += 4;
        }
        // Cap to avoid excessive iteration.
        if (count < 0 || count > 100000) return -1;
        let pos = next;
        for (let i = 0; i < count; i++) {
            pos = walkMessagePackValue(bytes, pos);
            if (pos === -1) return -1;
        }
        return pos;
    }

    // fixmap (0x80–0x8f): count = firstByte & 0x0f key-value pairs
    if ((firstByte & 0xf0) === 0x80) {
        const count = firstByte & 0x0f;
        let pos = index + 1;
        for (let i = 0; i < count; i++) {
            pos = walkMessagePackValue(bytes, pos); // key
            if (pos === -1) return -1;
            pos = walkMessagePackValue(bytes, pos); // value
            if (pos === -1) return -1;
        }
        return pos;
    }
    // map 16 / map 32
    if (firstByte === 0xde || firstByte === 0xdf) {
        let count;
        let next = index + 1;
        if (firstByte === 0xde) {
            if (next + 2 > bytes.length) return -1;
            count = (bytes[next] << 8) | bytes[next + 1];
            next += 2;
        } else {
            if (next + 4 > bytes.length) return -1;
            count = (bytes[next] << 24) | (bytes[next + 1] << 16) | (bytes[next + 2] << 8) | bytes[next + 3];
            next += 4;
        }
        if (count < 0 || count > 100000) return -1;
        let pos = next;
        for (let i = 0; i < count; i++) {
            pos = walkMessagePackValue(bytes, pos); // key
            if (pos === -1) return -1;
            pos = walkMessagePackValue(bytes, pos); // value
            if (pos === -1) return -1;
        }
        return pos;
    }

    // nil (0xc0), true (0xc2), false (0xc3)
    if (firstByte === 0xc0 || firstByte === 0xc2 || firstByte === 0xc3) return index + 1;

    // float 32 (0xca) / float 64 (0xcb)
    if (firstByte === 0xca) return index + 1 + 4 <= bytes.length ? index + 5 : -1;
    if (firstByte === 0xcb) return index + 1 + 8 <= bytes.length ? index + 9 : -1;

    // uint 8/16/32/64, int 8/16/32/64
    if (firstByte >= 0xcc && firstByte <= 0xd3) {
        const sizes = { 0xcc: 1, 0xcd: 2, 0xce: 4, 0xcf: 8, 0xd0: 1, 0xd1: 2, 0xd2: 4, 0xd3: 8 };
        const size = sizes[firstByte];
        return index + 1 + size <= bytes.length ? index + 1 + size : -1;
    }

    // bin 8 (0xc4) / bin 16 (0xc5) / bin 32 (0xc6)
    if (firstByte === 0xc4 || firstByte === 0xc5 || firstByte === 0xc6) {
        let len;
        let next = index + 1;
        if (firstByte === 0xc4) {
            if (next + 1 > bytes.length) return -1;
            len = bytes[next];
            next += 1;
        } else if (firstByte === 0xc5) {
            if (next + 2 > bytes.length) return -1;
            len = (bytes[next] << 8) | bytes[next + 1];
            next += 2;
        } else {
            if (next + 4 > bytes.length) return -1;
            len = (bytes[next] << 24) | (bytes[next + 1] << 16) | (bytes[next + 2] << 8) | bytes[next + 3];
            next += 4;
        }
        if (len < 0 || len > bytes.length) return -1;
        return next + len <= bytes.length ? next + len : -1;
    }

    // ext 8 (0xc7) / ext 16 (0xc8) / ext 32 (0xc9): 1-byte type + data
    if (firstByte === 0xc7 || firstByte === 0xc8 || firstByte === 0xc9) {
        let len;
        let next = index + 1;
        if (firstByte === 0xc7) {
            if (next + 1 > bytes.length) return -1;
            len = bytes[next];
            next += 1;
        } else if (firstByte === 0xc8) {
            if (next + 2 > bytes.length) return -1;
            len = (bytes[next] << 8) | bytes[next + 1];
            next += 2;
        } else {
            if (next + 4 > bytes.length) return -1;
            len = (bytes[next] << 24) | (bytes[next + 1] << 16) | (bytes[next + 2] << 8) | bytes[next + 3];
            next += 4;
        }
        // ext has a 1-byte type followed by `len` data bytes.
        if (len < 0 || len > bytes.length) return -1;
        return next + 1 + len <= bytes.length ? next + 1 + len : -1;
    }

    // fixext 1/2/4/8/16 (0xd4–0xd8)
    if (firstByte >= 0xd4 && firstByte <= 0xd8) {
        const sizes = { 0xd4: 1, 0xd5: 2, 0xd6: 4, 0xd7: 8, 0xd8: 16 };
        const size = sizes[firstByte];
        return index + 1 + 1 + size <= bytes.length ? index + 2 + size : -1;
    }

    // timestamp 32/64/96 (0xd6 ext type -1 / 0xd7 ext type -1 / 0xc7 len=8/12)
    // These overlap with fixext/ext above, so they're already handled.

    return -1; // unknown byte — not valid MessagePack
}

function decodeMessagePackFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

    const firstByte = bytes[0];
    const byteLength = bytes.length;
    const classification = classifyMessagePackType(firstByte);
    if (classification === "unknown") return null;

    // Strict full-walk validation: the entire input must be consumed as a
    // sequence of valid MessagePack values. If any value is truncated or
    // structurally invalid, reject the input. This prevents the decoder
    // from accepting arbitrary binary data (which the MessagePack
    // first-byte space would otherwise allow).
    //
    // Additionally, we require at least one "structurally interesting"
    // value (string, array, map, binary, ext, float, etc.) in the stream.
    // A stream of only fixints (0x00–0x7f, 0xe0–0xff) is technically valid
    // MessagePack but provides no useful information — any byte sequence
    // where every byte is ≤ 0x7f or ≥ 0xe0 would be "decoded" as a series
    // of fixints. This gate prevents that false positive.
    let index = 0;
    let valueCount = 0;
    let hasStructuralValue = false;
    const MAX_VALUES = 10000;
    while (index < byteLength && valueCount < MAX_VALUES) {
        const valueByte = bytes[index];
        // Check if this value is more than just a fixint (which any byte
        // can be). If we see at least one non-fixint value, the stream
        // has structural content worth reporting.
        const isFixint = valueByte <= 0x7f || valueByte >= 0xe0;
        const next = walkMessagePackValue(bytes, index);
        if (next === -1 || next <= index) return null;
        if (!isFixint) hasStructuralValue = true;
        index = next;
        valueCount += 1;
    }
    // Every byte must be consumed; trailing garbage means it's not real
    // MessagePack.
    if (index !== byteLength) return null;

    // If the entire stream is just fixints, it's almost certainly random
    // binary data, not a real MessagePack document. Reject it unless the
    // stream is a single value (a single fixint is a degenerate but
    // technically valid msgpack document).
    if (!hasStructuralValue && valueCount > 1) return null;

    const previewHex = Array.from(bytes.slice(0, PREVIEW_HEX_LIMIT), (byteValue) =>
        byteValue.toString(16).padStart(2, "0"),
    ).join(" ");
    return {
        protocol: "MessagePack",
        fields: [
            { name: "First byte", value: `0x${firstByte.toString(16).padStart(2, "0").toUpperCase()}` },
            { name: "Likely type", value: classification },
            { name: "Byte length", value: String(byteLength) },
            { name: "Top-level values", value: String(valueCount) },
            { name: "Preview (hex)", value: byteLength > PREVIEW_HEX_LIMIT ? `${previewHex} …` : previewHex },
        ],
    };
}

module.exports = { decodeMessagePackFromBytes };
