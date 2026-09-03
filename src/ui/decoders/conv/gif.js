// GIF Conv decoder: GIF has no EXIF metadata support, so this just reports
// the format/byte length and renders the GIF as an inline data URL.

const MIME = "image/gif";
const PROTOCOL_LABEL = "GIF";
const { createImageDecodeResult } = require("./image-helpers");

function decodeGifFromBytes(bytes) {
    const fields = [
        { name: "Format", value: "Graphics Interchange Format" },
        { name: "Byte Length", value: String(bytes.length) },
    ];
    return createImageDecodeResult(bytes, "gif", PROTOCOL_LABEL, fields, MIME);
}

module.exports = { decodeGifFromBytes };
