const path = require("path");

describe("SSDP / UPnP and gRPC Conv decoders", () => {
    const conv = require(path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv"));

    test("decodes SSDP UPnP discovery response", () => {
        const payload = Buffer.from([
            "HTTP/1.1 200 OK",
            "CACHE-CONTROL: max-age=1800",
            "LOCATION: http://192.0.2.10:80/rootDesc.xml",
            "ST: upnp:rootdevice",
            "USN: uuid:device::upnp:rootdevice",
            "",
            "",
        ].join("\r\n"));
        const decoded = conv.decodeSsdpFromBytes(payload);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "UPnP" }));
        expect(decoded.fields).toEqual(expect.arrayContaining([
            { name: "Profile", value: "UPnP" },
            { name: "Location", value: "http://192.0.2.10:80/rootDesc.xml" },
        ]));
    });

    test("decodes a gRPC envelope and nested protobuf field", () => {
        const protobuf = Uint8Array.from([0x0a, 0x03, 0x66, 0x6f, 0x6f]);
        const payload = Uint8Array.from([0x00, 0x00, 0x00, 0x00, protobuf.length, ...protobuf]);
        const decoded = conv.decodeGrpcFromBytes(payload);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "gRPC" }));
        expect(decoded.fields).toEqual(expect.arrayContaining([
            { name: "Message 1 Compressed", value: "no" },
            { name: "Message 1 Length", value: "5" },
            expect.objectContaining({ name: "Message 1 Field 1 (wire 2)" }),
        ]));
    });

    test("rejects malformed gRPC envelopes", () => {
        expect(conv.decodeGrpcFromBytes(Uint8Array.from([0, 0, 0, 0, 4, 1]))).toBeNull();
        expect(conv.decodeGrpcFromBytes(new Uint8Array())).toBeNull();
    });

    test("registers aliases and port hints", () => {
        const hints = require(path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/protocol-hints"));
        const { SUPPORTED_DECODER_PROTOS } = require(path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/mime-maps"));
        expect(hints.PROTOCOL_DECODER_HINTS.get("upnp")).toBe("ssdp");
        expect(hints.PROTOCOL_DECODER_HINTS.get("grpc")).toBe("grpc");
        expect(hints.PORT_DECODER_HINTS.get(1900)).toBe("ssdp");
        expect(hints.PORT_DECODER_HINTS.get(50051)).toBe("grpc");
        expect(SUPPORTED_DECODER_PROTOS.has("ssdp")).toBe(true);
        expect(SUPPORTED_DECODER_PROTOS.has("grpc")).toBe(true);
    });
});
