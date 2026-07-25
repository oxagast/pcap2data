// WebP Conv decoder: extracts EXIF metadata via ExifReader and renders the
// WebP bytes as an inline data URL for the panel's image preview.

const ExifReader = require("exifreader");

const MIME = "image/webp";
const PROTOCOL_LABEL = "WebP";

function loadExifFields(bytes) {
    try {
        const tags = ExifReader.load(
            bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
        );
        const exifFields = [];
        for (const [name, tag] of Object.entries(tags)) {
            if (name === "Thumbnail" || name.startsWith("Thumbnail")) continue;
            if (tag.value !== undefined) {
                exifFields.push({
                    name,
                    value: Array.isArray(tag.value) ? tag.value.join(", ") : String(tag.value),
                });
            }
        }
        return exifFields;
    } catch {
        // No EXIF data is fine; many WebPs have none.
        return [];
    }
}

function decodeWebpFromBytes(bytes) {
    return {
        protocol: PROTOCOL_LABEL,
        fields: loadExifFields(bytes),
        imageDataUrl: `data:${MIME};base64,${Buffer.from(bytes).toString("base64")}`,
    };
}

module.exports = { decodeWebpFromBytes };
