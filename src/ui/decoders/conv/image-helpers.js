// Shared validation helpers for the image Conv decoders.
//
// Image decoders intentionally accept a valid image prefix without requiring
// the end marker. Browsers can often render useful pixels from a truncated
// image, which is preferable to discarding the only data available from a
// capture. The renderer uses `incomplete` to annotate that best-effort view.

const IMAGE_PROTOCOLS = new Set(["jpeg", "png", "gif", "webp"]);

function hasBytes(bytes, values) {
    if (!(bytes instanceof Uint8Array) || bytes.length < values.length) return false;
    return values.every((value, index) => bytes[index] === value);
}

function hasJpegEndMarker(bytes) {
    for (let index = bytes.length - 2; index >= 0; index -= 1) {
        if (bytes[index] === 0xff && bytes[index + 1] === 0xd9) return true;
    }
    return false;
}

function hasPngEndMarker(bytes) {
    const marker = [
        0x00, 0x00, 0x00, 0x00,
        0x49, 0x45, 0x4e, 0x44,
        0xae, 0x42, 0x60, 0x82,
    ];
    return bytes.length >= marker.length &&
        hasBytes(bytes.subarray(bytes.length - marker.length), marker);
}

function hasGifTrailer(bytes) {
    return bytes.length > 0 && bytes[bytes.length - 1] === 0x3b;
}

function getWebpDeclaredLength(bytes) {
    if (bytes.length < 8) return null;
    return bytes[4] |
        (bytes[5] << 8) |
        (bytes[6] << 16) |
        (bytes[7] << 24);
}

function validateImageBytes(bytes, protocol) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0 || !IMAGE_PROTOCOLS.has(protocol)) {
        return { valid: false, incomplete: false };
    }

    switch (protocol) {
        case "jpeg":
            return {
                valid: hasBytes(bytes, [0xff, 0xd8]),
                incomplete: !hasJpegEndMarker(bytes),
            };
        case "png":
            return {
                valid: hasBytes(bytes, [
                    0x89, 0x50, 0x4e, 0x47,
                    0x0d, 0x0a, 0x1a, 0x0a,
                ]),
                incomplete: !hasPngEndMarker(bytes),
            };
        case "gif":
            return {
                valid: hasBytes(bytes, [0x47, 0x49, 0x46, 0x38]) &&
                    (bytes[4] === 0x37 || bytes[4] === 0x39) && bytes[5] === 0x61,
                incomplete: !hasGifTrailer(bytes),
            };
        case "webp": {
            const valid = hasBytes(bytes, [0x52, 0x49, 0x46, 0x46]) &&
                hasBytes(bytes.subarray(8), [0x57, 0x45, 0x42, 0x50]);
            const declaredLength = getWebpDeclaredLength(bytes);
            return {
                valid,
                incomplete: valid && (declaredLength === null || bytes.length < declaredLength + 8),
            };
        }
        default:
            return { valid: false, incomplete: false };
    }
}

function createImageDecodeResult(bytes, protocol, protocolLabel, fields, mime) {
    const validation = validateImageBytes(bytes, protocol);
    if (!validation.valid) {
        return {
            protocol: protocolLabel,
            fields: [],
            imageError: "No valid image data is available to display.",
        };
    }
    return {
        protocol: protocolLabel,
        fields: Array.isArray(fields) ? fields : [],
        imageDataUrl: `data:${mime};base64,${Buffer.from(bytes).toString("base64")}`,
        imageIncomplete: validation.incomplete,
    };
}

module.exports = {
    createImageDecodeResult,
    validateImageBytes,
};
