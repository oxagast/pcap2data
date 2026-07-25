// BSON Conv decoder: walks a BSON document, reporting each element's name
// and type, and skipping values by their declared length.

const BSON_TYPE_NAMES = {
    0x01: "double",
    0x02: "string",
    0x03: "document",
    0x04: "array",
    0x05: "binary",
    0x08: "boolean",
    0x09: "datetime",
    0x0a: "null",
    0x10: "int32",
    0x12: "int64",
};

const MAX_ELEMENTS = 100;

function decodeBsonFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 5) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const totalLength = view.getInt32(0, true);
    if (totalLength < 5 || totalLength > bytes.length) return null;
    if (bytes[totalLength - 1] !== 0x00) return null;

    const fields = [{ name: "Document length", value: String(totalLength) }];
    let index = 4;
    let elementCount = 0;
    while (index < totalLength - 1 && elementCount < MAX_ELEMENTS) {
        const typeByte = bytes[index++];
        if (typeByte === 0x00) break;

        let keyEnd = index;
        while (keyEnd < totalLength && bytes[keyEnd] !== 0x00) keyEnd += 1;
        if (keyEnd >= totalLength) break;
        const key = new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(index, keyEnd));
        index = keyEnd + 1;

        const typeName = BSON_TYPE_NAMES[typeByte] || `0x${typeByte.toString(16).padStart(2, "0")}`;
        fields.push({ name: `Element ${elementCount + 1}`, value: `${key || "(empty-key)"}: ${typeName}` });
        elementCount += 1;

        if (typeByte === 0x01) index += 8;
        else if (typeByte === 0x02) {
            if (index + 4 > totalLength) break;
            const strLen = new DataView(bytes.buffer, bytes.byteOffset + index, 4).getInt32(0, true);
            index += 4 + Math.max(0, strLen);
        } else if (typeByte === 0x03 || typeByte === 0x04) {
            if (index + 4 > totalLength) break;
            const docLen = new DataView(bytes.buffer, bytes.byteOffset + index, 4).getInt32(0, true);
            index += Math.max(0, docLen);
        } else if (typeByte === 0x05) {
            if (index + 4 > totalLength) break;
            const binLen = new DataView(bytes.buffer, bytes.byteOffset + index, 4).getInt32(0, true);
            index += 4 + 1 + Math.max(0, binLen);
        } else if (typeByte === 0x08) index += 1;
        else if (typeByte === 0x09) index += 8;
        else if (typeByte === 0x0a) index += 0;
        else if (typeByte === 0x10) index += 4;
        else if (typeByte === 0x12) index += 8;
        else break;

        if (index > totalLength) break;
    }

    if (elementCount === 0) return null;
    if (elementCount >= MAX_ELEMENTS) {
        fields.push({ name: "Notice", value: `Showing first ${MAX_ELEMENTS} BSON elements.` });
    }
    return { protocol: "BSON", fields };
}

module.exports = { decodeBsonFromBytes };
