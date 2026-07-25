// Soulseek Conv decoder: walks the little-endian Soulseek message header
// (message_length, message_code) and emits a payload preview when printable.

const SOULSEEK_BODY_PREVIEW_LIMIT = 120;

function decodeSoulseekFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 8) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const messageLength = view.getUint32(0, true);
    const messageCode = view.getUint32(4, true);
    const totalLength = messageLength + 4;

    if (messageLength < 4 || totalLength > bytes.length || messageCode > 0xffff) {
        return null;
    }

    const body = bytes.slice(8, totalLength);
    const preview = new TextDecoder("utf-8", { fatal: false })
        .decode(body)
        .replace(/\u0000+/g, "")
        .trim();

    const fields = [
        { name: "Message Code", value: String(messageCode) },
        { name: "Message Code Hex", value: `0x${messageCode.toString(16).padStart(4, "0")}` },
        { name: "Message Length", value: String(messageLength) },
        { name: "Body Length", value: String(body.length) },
    ];
    if (preview) {
        fields.push({
            name: "Payload Preview",
            value: preview.length > SOULSEEK_BODY_PREVIEW_LIMIT
                ? `${preview.slice(0, SOULSEEK_BODY_PREVIEW_LIMIT)}...`
                : preview,
        });
    }

    return { protocol: "Soulseek", fields };
}

module.exports = { decodeSoulseekFromBytes };
