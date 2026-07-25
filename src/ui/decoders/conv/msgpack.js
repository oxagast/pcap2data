// MessagePack Conv decoder: classifies the first byte by the MessagePack
// format spec and reports a hex preview of the input.

const PREVIEW_HEX_LIMIT = 48;

function classifyMessagePackType(firstByte) {
    if ((firstByte & 0x80) === 0x00 || (firstByte & 0xe0) === 0xe0) return "int";
    if ((firstByte & 0xe0) === 0xa0 || firstByte === 0xd9 || firstByte === 0xda || firstByte === 0xdb) return "string";
    if ((firstByte & 0xf0) === 0x90 || firstByte === 0xdc || firstByte === 0xdd) return "array";
    if ((firstByte & 0xf0) === 0x80 || firstByte === 0xde || firstByte === 0xdf) return "map";
    if ((firstByte & 0xe0) === 0xc0) return "misc/bin/ext/float";
    return "unknown";
}

function decodeMessagePackFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

    const firstByte = bytes[0];
    const byteLength = bytes.length;
    const classification = classifyMessagePackType(firstByte);
    if (classification === "unknown") return null;

    const previewHex = Array.from(bytes.slice(0, PREVIEW_HEX_LIMIT), (byteValue) =>
        byteValue.toString(16).padStart(2, "0"),
    ).join(" ");
    return {
        protocol: "MessagePack",
        fields: [
            { name: "First byte", value: `0x${firstByte.toString(16).padStart(2, "0").toUpperCase()}` },
            { name: "Likely type", value: classification },
            { name: "Byte length", value: String(byteLength) },
            { name: "Preview (hex)", value: byteLength > PREVIEW_HEX_LIMIT ? `${previewHex} …` : previewHex },
        ],
    };
}

module.exports = { decodeMessagePackFromBytes };
