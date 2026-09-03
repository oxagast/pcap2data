const {
    createImageDecodeResult,
    validateImageBytes,
} = require("../src/ui/decoders/conv/image-helpers");

describe("Conv image decoder byte validation", () => {
    test.each([
        ["jpeg", [0x00, 0x01]],
        ["png", [0x89, 0x50, 0x4e]],
        ["gif", [0x47, 0x49, 0x46, 0x38, 0x39]],
        ["webp", [0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00]],
    ])("rejects data without a valid %s signature", (protocol, values) => {
        const result = createImageDecodeResult(
            new Uint8Array(values),
            protocol,
            protocol.toUpperCase(),
            [],
            `image/${protocol}`,
        );

        expect(result.imageDataUrl).toBeUndefined();
        expect(result.imageError).toBe("No valid image data is available to display.");
        expect(result.fields).toEqual([]);
    });

    test("does not report GIF metadata when the GIF bytes are invalid", () => {
        const result = createImageDecodeResult(
            new Uint8Array([0x00, 0x01, 0x02]),
            "gif",
            "GIF",
            [
                { name: "Format", value: "Graphics Interchange Format" },
                { name: "Byte Length", value: "3" },
            ],
            "image/gif",
        );

        expect(result.imageDataUrl).toBeUndefined();
        expect(result.imageError).toBe("No valid image data is available to display.");
        expect(result.fields).toEqual([]);
    });

    test("accepts a truncated JPEG so the renderer can attempt a partial preview", () => {
        const result = createImageDecodeResult(
            new Uint8Array([0xff, 0xd8, 0xff, 0xdb, 0x00]),
            "jpeg",
            "JPEG",
            [],
            "image/jpeg",
        );

        expect(result.imageDataUrl).toMatch(/^data:image\/jpeg;base64,/);
        expect(result.imageIncomplete).toBe(true);
        expect(result.imageError).toBeUndefined();
    });

    test.each([
        ["jpeg", [0xff, 0xd8, 0xff, 0xd9]],
        ["png", [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44,
            0xae, 0x42, 0x60, 0x82]],
        ["gif", [0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x3b]],
        ["webp", [0x52, 0x49, 0x46, 0x46, 0x04, 0x00, 0x00, 0x00,
            0x57, 0x45, 0x42, 0x50]],
    ])("marks a complete %s container as complete", (protocol, values) => {
        expect(validateImageBytes(new Uint8Array(values), protocol)).toEqual({
            valid: true,
            incomplete: false,
        });
    });
});
