// Byte-level transformations used by the Conv output panel.

function reverseBytes(bytes) {
    return Uint8Array.from(bytes).reverse();
}

function reverseBitsInByte(byte) {
    let value = byte;
    let reversed = 0;
    for (let bit = 0; bit < 8; bit += 1) {
        reversed = (reversed << 1) | (value & 1);
        value >>= 1;
    }
    return reversed;
}

function reverseBitOrder(bytes) {
    return Uint8Array.from(bytes, reverseBitsInByte);
}

// Reverse complete fixed-width words. A trailing partial word is left in its
// original order because it does not contain a complete value to byte-swap.
function swapEndianness(bytes, wordSize) {
    const width = Number(wordSize);
    if (!Number.isInteger(width) || width <= 0) {
        throw new Error("Endianness word size must be a positive integer.");
    }

    const result = Uint8Array.from(bytes);
    for (let start = 0; start + width <= result.length; start += width) {
        for (let left = start, right = start + width - 1; left < right; left += 1, right -= 1) {
            const value = result[left];
            result[left] = result[right];
            result[right] = value;
        }
    }
    return result;
}

// Read the bytes as a row-major matrix with `columns` columns, then emit the
// matrix column-major. The final short row is supported without padding.
function transposeBytes(bytes, columns) {
    const width = Number(columns);
    if (!Number.isInteger(width) || width <= 0) {
        throw new Error("Transpose columns must be a positive integer.");
    }

    const result = [];
    const rowCount = Math.ceil(bytes.length / width);
    for (let column = 0; column < width; column += 1) {
        for (let row = 0; row < rowCount; row += 1) {
            const index = row * width + column;
            if (index < bytes.length) result.push(bytes[index]);
        }
    }
    return Uint8Array.from(result);
}

function applyDataToolsTransforms(bytes, options = {}) {
    if (!(bytes instanceof Uint8Array)) {
        throw new Error("Transform input must be a Uint8Array.");
    }

    let transformed = Uint8Array.from(bytes);
    if (options.reverse) transformed = reverseBytes(transformed);
    if (options.endianSwap) {
        transformed = swapEndianness(transformed, options.endianWidth || 2);
    }
    if (options.bitOrder) transformed = reverseBitOrder(transformed);
    if (options.transpose) {
        transformed = transposeBytes(transformed, options.transposeColumns || 1);
    }
    return transformed;
}

module.exports = {
    applyDataToolsTransforms,
    reverseBytes,
    reverseBitOrder,
    reverseBitsInByte,
    swapEndianness,
    transposeBytes,
};
