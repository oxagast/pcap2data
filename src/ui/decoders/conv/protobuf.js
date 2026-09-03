// Protobuf Conv decoder: walks wire-format fields using a shared LEB128-style
// varint reader and reports each (field, wire type, value) row.
//
// The decoder is intentionally strict for auto-detection: the Protobuf wire
// format is extremely permissive (almost any byte sequence can be parsed as
// a series of varint-tagged fields), so merely producing fields is not
// sufficient to distinguish real Protobuf from arbitrary binary data. To
// avoid false positives, we require:
//
//   1. The **entire** input must be consumed — no trailing bytes.
//   2. At least 1 field must be successfully parsed.
//   3. All wire types must be valid (0, 1, 2, or 5; types 3/4 are deprecated
//      start/end group markers that aren't used in proto3).
//   4. Field numbers must be in a sane range (1–536870911 per spec, but we
//      also cap to avoid pathological varint expansions).
//
// This makes the decoder suitable for auto-detection without a "force" flag:
// random binary data will almost always leave trailing bytes or produce
// an invalid wire type at some point, causing the decoder to return null.

const MAX_FIELDS = 100;
const MAX_FIELD_NUMBER = 536870911; // 2^29 - 1, per protobuf spec

function readVarint(bytes, startIndex) {
    let value = 0;
    let shift = 0;
    let index = startIndex;
    while (index < bytes.length && shift < 35) {
        const byteValue = bytes[index];
        value |= (byteValue & 0x7f) << shift;
        index += 1;
        if ((byteValue & 0x80) === 0) {
            return { value, nextIndex: index };
        }
        shift += 7;
    }
    return null;
}

function decodeProtobufFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

    const fields = [];
    let index = 0;
    let parsedFields = 0;

    while (index < bytes.length && parsedFields < MAX_FIELDS) {
        const keyInfo = readVarint(bytes, index);
        if (!keyInfo || keyInfo.value <= 0) break;
        index = keyInfo.nextIndex;

        const fieldNumber = keyInfo.value >> 3;
        const wireType = keyInfo.value & 0x07;
        if (fieldNumber <= 0 || fieldNumber > MAX_FIELD_NUMBER) break;

        // Valid wire types: 0 (varint), 1 (fixed64), 2 (length-delimited),
        // 5 (fixed32). Types 3/4 (start/end group) are deprecated and not
        // used in proto3; type 6/7 are reserved/invalid.
        if (wireType !== 0 && wireType !== 1 && wireType !== 2 && wireType !== 5) break;

        let valueLabel = "";
        if (wireType === 0) {
            const valueInfo = readVarint(bytes, index);
            if (!valueInfo) break;
            index = valueInfo.nextIndex;
            valueLabel = `varint=${valueInfo.value}`;
        } else if (wireType === 1) {
            if (index + 8 > bytes.length) break;
            const raw = bytes.slice(index, index + 8);
            index += 8;
            valueLabel = `fixed64=${Array.from(raw).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
        } else if (wireType === 2) {
            const lengthInfo = readVarint(bytes, index);
            if (!lengthInfo) break;
            index = lengthInfo.nextIndex;
            const length = lengthInfo.value;
            if (length < 0 || length > bytes.length) break;
            if (index + length > bytes.length) break;
            const raw = bytes.slice(index, index + length);
            index += length;
            const previewHex = Array.from(raw.slice(0, 24), (b) => b.toString(16).padStart(2, "0")).join(" ");
            valueLabel = `len=${length} data=${raw.length > 24 ? `${previewHex} …` : previewHex}`;
        } else if (wireType === 5) {
            if (index + 4 > bytes.length) break;
            const raw = bytes.slice(index, index + 4);
            index += 4;
            valueLabel = `fixed32=${Array.from(raw).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
        }

        parsedFields += 1;
        fields.push({ name: `Field ${fieldNumber} (wire ${wireType})`, value: valueLabel || "(empty)" });
    }

    if (!fields.length) return null;

    // Strict: the entire input must be consumed. Trailing bytes mean the
    // input isn't a clean Protobuf message — it's probably some other
    // binary format that happened to parse partially.
    if (index !== bytes.length) return null;

    return { protocol: "Protobuf", fields };
}

module.exports = { decodeProtobufFromBytes, readVarint };
