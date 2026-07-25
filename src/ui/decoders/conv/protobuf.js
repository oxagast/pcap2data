// Protobuf Conv decoder: walks wire-format fields using a shared LEB128-style
// varint reader and reports each (field, wire type, value) row.

const MAX_FIELDS = 100;

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
        if (fieldNumber <= 0) break;

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
        } else {
            break;
        }

        parsedFields += 1;
        fields.push({ name: `Field ${fieldNumber} (wire ${wireType})`, value: valueLabel || "(empty)" });
    }

    if (!fields.length) return null;
    return { protocol: "Protobuf", fields };
}

module.exports = { decodeProtobufFromBytes, readVarint };
