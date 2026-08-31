const {
    applyDataToolsTransforms,
    reverseBitOrder,
    reverseBytes,
    swapEndianness,
    transposeBytes,
} = require("../src/ui/data-transformations");

describe("Conv data transformations", () => {
    test("inverts the complete byte sequence", () => {
        expect(Array.from(reverseBytes(Uint8Array.from([1, 2, 3, 4])))).toEqual([4, 3, 2, 1]);
    });

    test("swaps bytes inside complete words and preserves a trailing partial word", () => {
        expect(Array.from(swapEndianness(Uint8Array.from([1, 2, 3, 4, 5]), 2))).toEqual([
            2, 1, 4, 3, 5,
        ]);
        expect(Array.from(swapEndianness(Uint8Array.from([1, 2, 3, 4, 5]), 4))).toEqual([
            4, 3, 2, 1, 5,
        ]);
    });

    test("reverses bit order inside each byte", () => {
        expect(Array.from(reverseBitOrder(Uint8Array.from([0b00000001, 0b10110000])))).toEqual([
            0b10000000,
            0b00001101,
        ]);
    });

    test("transposes a row-major byte matrix", () => {
        expect(Array.from(transposeBytes(Uint8Array.from([1, 2, 3, 4, 5, 6]), 3))).toEqual([
            1, 4, 2, 5, 3, 6,
        ]);
        expect(Array.from(transposeBytes(Uint8Array.from([1, 2, 3, 4, 5]), 3))).toEqual([
            1, 4, 2, 5, 3,
        ]);
    });

    test("applies selected transforms in documented order", () => {
        const result = applyDataToolsTransforms(Uint8Array.from([1, 2, 3, 4]), {
            reverse: true,
            endianSwap: true,
            endianWidth: 2,
        });
        expect(Array.from(result)).toEqual([3, 4, 1, 2]);
    });
});
