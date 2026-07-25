// PNG Conv decoder: extracts EXIF metadata via ExifReader and renders the
// PNG bytes as an inline data URL for the panel's image preview.

const MIME = "image/png";
const PROTOCOL_LABEL = "PNG";

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
        // No EXIF data is fine; many PNGs have none.
        return [];
    }
}

function decodePngFromBytes(bytes) {
    return {
        protocol: PROTOCOL_LABEL,
        fields: loadExifFields(bytes),
        imageDataUrl: `data:${MIME};base64,${Buffer.from(bytes).toString("base64")}`,
    };
}

module.exports = { decodePngFromBytes };
