// GIF Conv decoder: GIF has no EXIF metadata support, so this just reports
// the format/byte length and renders the GIF as an inline data URL.

const MIME = "image/gif";
const PROTOCOL_LABEL = "GIF";

function decodeGifFromBytes(bytes) {
    return {
        protocol: PROTOCOL_LABEL,
        fields: [
            { name: "Format", value: "Graphics Interchange Format" },
            { name: "Byte Length", value: String(bytes.length) },
        ],
        imageDataUrl: `data:${MIME};base64,${Buffer.from(bytes).toString("base64")}`,
    };
}

module.exports = { decodeGifFromBytes };
