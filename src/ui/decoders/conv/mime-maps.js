// Maps common MIME types and variant spellings to the proto-decoder key used
// by the data-tools protocol switch.

const MIME_TO_PROTO = {
    "image/jpeg": "jpeg",
    "image/jpg": "jpeg",
    "jpeg": "jpeg",
    "jpg": "jpeg",
    "image/png": "png",
    "png": "png",
    "image/gif": "gif",
    "gif": "gif",
    "image/webp": "webp",
    "webp": "webp",
    "text/html": "html",
    "html": "html",
};

module.exports = { MIME_TO_PROTO };
