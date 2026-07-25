// ExifReader-backed helpers for the image Conv decoders:
//   - EXIF_FILE_TYPE_TO_PROTO: maps ExifReader's fileType ext / mime / expanded
//     FileType.value into the Conv decoder key (jpeg / png / gif / webp).
//   - getImageTypeFromExifReader: asks ExifReader what format these bytes are.
//     Returns a decoder key or null if ExifReader cannot identify them.

const EXIF_FILE_TYPE_TO_PROTO = {
    jpg: "jpeg",
    jpeg: "jpeg",
    png: "png",
    gif: "gif",
    webp: "webp",
    "image/jpeg": "jpeg",
    "image/jpg": "jpeg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
};

function getImageTypeFromExifReader(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
    try {
        // ExifReader has two shapes:
        //   - tags.fileType { ext, mime } in default mode
        //   - tags.file['FileType'].value in expanded mode
        const tagsDefault = ExifReader.load(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
        if (tagsDefault) {
            const fileType = tagsDefault.fileType;
            if (fileType) {
                const ext = String(fileType.ext || "").toLowerCase().trim();
                const mime = String(fileType.mime || "").toLowerCase().split(";")[0].trim();
                const mapped = EXIF_FILE_TYPE_TO_PROTO[ext] || EXIF_FILE_TYPE_TO_PROTO[mime];
                if (mapped) return mapped;
            }
        }
        const tagsExpanded = ExifReader.load(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength), { expanded: true });
        const expandedFileType = tagsExpanded?.file?.["FileType"];
        if (expandedFileType && expandedFileType.value !== undefined) {
            const val = String(expandedFileType.value).toLowerCase().trim();
            if (EXIF_FILE_TYPE_TO_PROTO[val]) return EXIF_FILE_TYPE_TO_PROTO[val];
        }
        return null;
    } catch {
        return null;
    }
}

module.exports = {
    EXIF_FILE_TYPE_TO_PROTO,
    getImageTypeFromExifReader,
};
