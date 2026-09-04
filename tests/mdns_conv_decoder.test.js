const path = require("path");

function encodeName(labels) {
    const bytes = [];
    for (const label of labels) {
        const encoded = Buffer.from(label, "utf8");
        bytes.push(encoded.length, ...encoded);
    }
    bytes.push(0);
    return bytes;
}

function buildBonjourQuery() {
    const name = encodeName(["_http", "_tcp", "local"]);
    const question = [...name, 0x00, 0x0c, 0x00, 0x01];
    return Uint8Array.from([
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        ...question,
    ]);
}

describe("mDNS / Bonjour Conv decoder wiring", () => {
    test("decodes Bonjour DNS-SD query", () => {
        const convDecoders = require(path.join(
            path.resolve(__dirname, ".."),
            "src/ui/decoders/conv",
        ));
        const decoded = convDecoders.decodeMdnsFromBytes(buildBonjourQuery());
        expect(decoded).not.toBeNull();
        expect(decoded.protocol).toBe("Bonjour (mDNS/DNS-SD)");
        expect(decoded.fields).toEqual(
            expect.arrayContaining([
                { name: "Protocol Profile", value: "Bonjour (DNS-SD)" },
            ]),
        );
        expect(decoded.fields.find((field) => field.name === "Message 1 Question 1").value).toContain(
            "_http._tcp.local",
        );
    });

    test("maps Bonjour and mDNS hints to the mDNS decoder", () => {
        const hints = require(path.join(
            path.resolve(__dirname, ".."),
            "src/ui/decoders/conv/protocol-hints",
        ));
        expect(hints.PROTOCOL_DECODER_HINTS.get("bonjour")).toBe("mdns");
        expect(hints.PROTOCOL_DECODER_HINTS.get("dnssd")).toBe("mdns");
        expect(hints.PORT_DECODER_HINTS.get(5353)).toBe("mdns");
    });

    test("registers mDNS and Bonjour in the decoder registry", () => {
        const { SUPPORTED_DECODER_PROTOS } = require(path.join(
            path.resolve(__dirname, ".."),
            "src/ui/decoders/conv/mime-maps",
        ));
        expect(SUPPORTED_DECODER_PROTOS.has("mdns")).toBe(true);
        expect(SUPPORTED_DECODER_PROTOS.has("bonjour")).toBe(true);
    });
});
