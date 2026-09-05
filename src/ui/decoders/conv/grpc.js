// gRPC Conv decoder: parses one or more 5-byte gRPC message envelopes.
// Envelope: Compressed-Flag(1) + Message-Length(4, big-endian) + payload.

const { decodeProtobufFromBytes } = require("./protobuf");

function readUint32Be(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 4 > bytes.length) return null;
    return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function decodeGrpcEnvelopeBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 5) return null;
    const fields = [];
    let cursor = 0;
    let messageIndex = 0;
    while (cursor + 5 <= bytes.length && messageIndex < 64) {
        const compressed = bytes[cursor];
        const length = readUint32Be(bytes, cursor + 1);
        if ((compressed !== 0 && compressed !== 1) || length === null) return null;
        const start = cursor + 5;
        const end = start + length;
        if (end > bytes.length) return null;
        const payload = bytes.slice(start, end);
        fields.push({ name: `Message ${messageIndex + 1} Compressed`, value: compressed ? "yes" : "no" });
        fields.push({ name: `Message ${messageIndex + 1} Length`, value: String(length) });
        fields.push({
            name: `Message ${messageIndex + 1} Payload`,
            value: Array.from(payload.slice(0, 256), (byteValue) => byteValue.toString(16).padStart(2, "0")).join(""),
        });
        if (!compressed && payload.length > 0) {
            const protobuf = decodeProtobufFromBytes(payload);
            if (protobuf) {
                protobuf.fields.slice(0, 32).forEach((field) => {
                    fields.push({ name: `Message ${messageIndex + 1} ${field.name}`, value: field.value });
                });
            }
        }
        cursor = end;
        messageIndex += 1;
    }
    if (!messageIndex || cursor !== bytes.length) return null;
    return { protocol: "gRPC", fields };
}

function decodeGrpcFromHttp2Bytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 9) return null;
    let cursor = 0;
    const preface = new TextEncoder().encode("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    if (bytes.length >= preface.length && preface.every((value, index) => bytes[index] === value)) {
        cursor = preface.length;
    }
    const grpcBytes = [];
    let dataFrameCount = 0;
    while (cursor + 9 <= bytes.length) {
        const length = (bytes[cursor] << 16) | (bytes[cursor + 1] << 8) | bytes[cursor + 2];
        const frameType = bytes[cursor + 3];
        const flags = bytes[cursor + 4];
        const streamId = (((bytes[cursor + 5] & 0x7f) << 24) |
            (bytes[cursor + 6] << 16) |
            (bytes[cursor + 7] << 8) |
            bytes[cursor + 8]) >>> 0;
        const frameEnd = cursor + 9 + length;
        if (frameEnd > bytes.length) return null;
        if (frameType === 0x0 && streamId !== 0) {
            let start = cursor + 9;
            let end = frameEnd;
            if (flags & 0x08) {
                if (start >= end) return null;
                const paddingLength = bytes[start];
                start += 1;
                if (start + paddingLength > end) return null;
                end -= paddingLength;
            }
            for (let index = start; index < end; index += 1) grpcBytes.push(bytes[index]);
            dataFrameCount += 1;
        }
        cursor = frameEnd;
    }
    if (cursor !== bytes.length || dataFrameCount === 0) return null;
    return decodeGrpcEnvelopeBytes(Uint8Array.from(grpcBytes));
}

function decodeGrpcFromBytes(bytes) {
    return decodeGrpcEnvelopeBytes(bytes) || decodeGrpcFromHttp2Bytes(bytes);
}

module.exports = { decodeGrpcFromBytes };
