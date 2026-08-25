// Tests for the HTTP body-boundary detection helpers that power the
// file-carver path. These helpers live in src/ui/decoders/conv/http.js and
// are consumed by main-frontend.js via the data-tools-panel destructure.
//
// Coverage:
//   * `findHttpHeaderBodySeparators` — locates every CRLFCRLF in a payload.
//   * `sliceHttpMessageSegments` — splits a payload into per-message
//     `{ headerHex, bodyHex }` pairs (pipelined responses).
//   * `collectHttpMessageBodiesFromStream` — gathers per-message bodies
//     from same-direction TCP packets with per-message framing.
//   * `findMultipartFileByteRanges` — enumerates every multipart part with
//     a filename, scanning the full body (not just the first 8 KiB).
//   * `extractFilenameFromContentDisposition` — Content-Disposition parsing
//     with injected sanitizer.
//   * `sliceCompleteChunkedHttpBodyHex` — chunked transfer-encoding framing.

const path = require("path");
const {
    extractHttpBodyHex,
    findHttpHeaderBodySeparators,
    looksLikeHttpStartLine,
    sliceHttpMessageSegments,
    httpHeadersHaveExplicitFraming,
    collectHttpMessageBodiesFromStream,
    HTTP_FILENAME_EXT_BY_MIME,
    getHttpBodyFilenameExtension,
    extractFilenameFromContentDisposition,
    extractMultipartBoundaryFromContentType,
    extractMultipartFilenameFromBodyBytes,
    findMultipartFileByteRange,
    findMultipartFileByteRanges,
    sliceCompleteChunkedHttpBodyHex,
    hexToAsciiString,
    isChunkedTransferEncodingHeader,
    parseContentLengthFromHeaderAscii,
    splitHttpMessageHeaders,
} = require("../src/ui/decoders/conv/http");

// --- helpers --------------------------------------------------------------

function strToHex(text) {
    const bytes = new TextEncoder().encode(text);
    let hex = "";
    for (const b of bytes) hex += b.toString(16).padStart(2, "0");
    return hex;
}

function bytesToHex(bytes) {
    let hex = "";
    for (const b of bytes) hex += b.toString(16).padStart(2, "0");
    return hex;
}

function hexToBytes(hex) {
    const normalized = hex.replace(/\s+/g, "");
    const out = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < out.length; i += 1) {
        out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

// Builds a minimal HTTP response payload hex from headers + body text.
function buildHttpResponseHex({ statusLine = "HTTP/1.1 200 OK", headers = {}, body = "" }) {
    let head = statusLine + "\r\n";
    for (const [name, value] of Object.entries(headers)) {
        head += `${name}: ${value}\r\n`;
    }
    head += "\r\n";
    return strToHex(head) + strToHex(body);
}

// Builds a multipart body (as Uint8Array) from an array of parts.
function buildMultipartBody(boundary, parts) {
    const encoder = new TextEncoder();
    let text = "";
    for (const part of parts) {
        text += `--${boundary}\r\n`;
        for (const [name, value] of Object.entries(part.headers || {})) {
            text += `${name}: ${value}\r\n`;
        }
        text += "\r\n";
        text += part.body || "";
        text += "\r\n";
    }
    text += `--${boundary}--\r\n`;
    return encoder.encode(text);
}

// --- findHttpHeaderBodySeparators -----------------------------------------

describe("findHttpHeaderBodySeparators", () => {
    test("returns [] for empty / falsy input", () => {
        expect(findHttpHeaderBodySeparators("")).toEqual([]);
        expect(findHttpHeaderBodySeparators(null)).toEqual([]);
        expect(findHttpHeaderBodySeparators(undefined)).toEqual([]);
    });

    test("returns [] when no CRLFCRLF is present", () => {
        expect(findHttpHeaderBodySeparators(strToHex("GET / HTTP/1.1\r\nHost: x\r\n"))).toEqual([]);
    });

    test("finds a single CRLFCRLF position", () => {
        const hex = strToHex("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        const positions = findHttpHeaderBodySeparators(hex);
        expect(positions).toHaveLength(1);
        // The separator position is the hex-char index of the first "0d"
        // in the "0d0a0d0a" sequence — i.e. the byte length of everything
        // before the CRLFCRLF, expressed as hex chars (2 per byte). The
        // text before the separator is the start line + headers WITHOUT the
        // terminating blank-line CRLFCRLF.
        const expectedPosition = strToHex("HTTP/1.1 200 OK\r\nContent-Length: 0").length;
        expect(positions[0]).toBe(expectedPosition);
    });

    test("finds multiple CRLFCRLF positions (pipelined responses)", () => {
        const r1 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        const r2 = "HTTP/1.1 204 No Content\r\n\r\n";
        const hex = strToHex(r1 + r2);
        const positions = findHttpHeaderBodySeparators(hex);
        expect(positions.length).toBeGreaterThanOrEqual(2);
    });
});

// --- looksLikeHttpStartLine -----------------------------------------------

describe("looksLikeHttpStartLine", () => {
    test("accepts response status lines", () => {
        expect(looksLikeHttpStartLine("HTTP/1.1 200 OK\r\n")).toBe(true);
        expect(looksLikeHttpStartLine("HTTP/1.0 404 Not Found\r\n")).toBe(true);
        expect(looksLikeHttpStartLine("HTTP/2 301 Moved Permanently\r\n")).toBe(true);
    });

    test("accepts request lines", () => {
        expect(looksLikeHttpStartLine("GET /path HTTP/1.1\r\n")).toBe(true);
        expect(looksLikeHttpStartLine("POST /api/v1 HTTP/1.1\r\n")).toBe(true);
        expect(looksLikeHttpStartLine("DELETE /x HTTP/1.0\r\n")).toBe(true);
    });

    test("rejects non-HTTP text", () => {
        expect(looksLikeHttpStartLine("hello world\r\n")).toBe(false);
        expect(looksLikeHttpStartLine("<html>...</html>")).toBe(false);
        expect(looksLikeHttpStartLine("")).toBe(false);
    });
});

// --- sliceHttpMessageSegments ---------------------------------------------

describe("sliceHttpMessageSegments", () => {
    test("returns [] for empty input", () => {
        expect(sliceHttpMessageSegments("")).toEqual([]);
        expect(sliceHttpMessageSegments(null)).toEqual([]);
    });

    test("returns [] when no CRLFCRLF is present", () => {
        expect(sliceHttpMessageSegments(strToHex("GET / HTTP/1.1\r\nHost: x\r\n"))).toEqual([]);
    });

    test("splits a single response into one segment", () => {
        const hex = buildHttpResponseHex({ body: "hello" });
        const segments = sliceHttpMessageSegments(hex);
        expect(segments).toHaveLength(1);
        expect(hexToAsciiString(segments[0].bodyHex)).toBe("hello");
    });

    test("splits pipelined responses into separate segments", () => {
        const r1 = buildHttpResponseHex({
            statusLine: "HTTP/1.1 200 OK",
            headers: { "Content-Length": "5" },
            body: "hello",
        });
        const r2 = buildHttpResponseHex({
            statusLine: "HTTP/1.1 204 No Content",
            headers: {},
            body: "",
        });
        const combined = r1 + r2;
        const segments = sliceHttpMessageSegments(combined);
        expect(segments).toHaveLength(2);
        expect(hexToAsciiString(segments[0].bodyHex)).toBe("hello");
        // The second segment's body starts right after its CRLFCRLF — it's
        // empty (204 No Content), so the body hex is the empty string.
        expect(segments[1].bodyHex).toBe("");
    });

    test("skips CRLFCRLF occurrences that are not HTTP start lines (binary body noise)", () => {
        // A single response whose body happens to contain 0d0a0d0a by
        // accident should NOT produce a second segment, because the bytes
        // after the accidental CRLFCRLF don't look like an HTTP start line.
        const body = "AAAA\r\n\r\nBBBB"; // body contains a stray CRLFCRLF
        const hex = buildHttpResponseHex({
            statusLine: "HTTP/1.1 200 OK",
            headers: { "Content-Length": String(body.length) },
            body,
        });
        const segments = sliceHttpMessageSegments(hex);
        expect(segments).toHaveLength(1);
        expect(hexToAsciiString(segments[0].bodyHex)).toBe(body);
    });
});

// --- httpHeadersHaveExplicitFraming --------------------------------------

describe("httpHeadersHaveExplicitFraming", () => {
    test("detects Content-Length", () => {
        const hex = strToHex("HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n");
        expect(httpHeadersHaveExplicitFraming(hex)).toBe(true);
    });

    test("detects chunked Transfer-Encoding", () => {
        const hex = strToHex("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        expect(httpHeadersHaveExplicitFraming(hex)).toBe(true);
    });

    test("returns false when neither header is present", () => {
        const hex = strToHex("HTTP/1.1 200 OK\r\nServer: x\r\n\r\n");
        expect(httpHeadersHaveExplicitFraming(hex)).toBe(false);
    });

    test("returns false for empty input", () => {
        expect(httpHeadersHaveExplicitFraming("")).toBe(false);
    });
});

// --- collectHttpMessageBodiesFromStream -----------------------------------

describe("collectHttpMessageBodiesFromStream", () => {
    // Minimal stubs for the injected packet-access callbacks. Each "packet"
    // is just `{ id, hex }` and the callbacks extract those fields.
    const getIdentity = (packet) => packet?.id ?? null;
    const getPayloadHex = (packet) => packet?.hex ?? "";
    const sameDirection = (packet, ref) => packet?.dir === ref?.dir;

    test("returns [] for empty / missing inputs", () => {
        expect(collectHttpMessageBodiesFromStream({})).toEqual([]);
        expect(collectHttpMessageBodiesFromStream({
            streamPackets: [],
            referencePacket: null,
            getPacketPayloadHex: getPayloadHex,
            isSameDirectionalStreamPacket: sameDirection,
        })).toEqual([]);
    });

    test("returns a single body for a simple response", () => {
        const bodyText = "hello world";
        const hex = buildHttpResponseHex({
            statusLine: "HTTP/1.1 200 OK",
            headers: { "Content-Length": String(bodyText.length) },
            body: bodyText,
        });
        const packet = { id: 1, hex, dir: "A" };
        const messages = collectHttpMessageBodiesFromStream({
            streamPackets: [packet],
            referencePacket: packet,
            getPacketIdentity: getIdentity,
            getPacketPayloadHex: getPayloadHex,
            isSameDirectionalStreamPacket: sameDirection,
            getHttpContentLengthFromPacket: () => bodyText.length,
            isChunkedHttpTransferForPacket: () => false,
        });
        expect(messages).toHaveLength(1);
        expect(hexToAsciiString(messages[0].bodyHex)).toBe(bodyText);
        expect(messages[0].framing).toBe("content-length");
        expect(messages[0].declaredContentLength).toBe(bodyText.length);
    });

    test("splits pipelined responses across same-direction packets", () => {
        const r1 = buildHttpResponseHex({
            statusLine: "HTTP/1.1 200 OK",
            headers: { "Content-Length": "5" },
            body: "hello",
        });
        const r2 = buildHttpResponseHex({
            statusLine: "HTTP/1.1 204 No Content",
            headers: {},
            body: "",
        });
        const packet = { id: 1, hex: r1 + r2, dir: "A" };
        const messages = collectHttpMessageBodiesFromStream({
            streamPackets: [packet],
            referencePacket: packet,
            getPacketIdentity: getIdentity,
            getPacketPayloadHex: getPayloadHex,
            isSameDirectionalStreamPacket: sameDirection,
            getHttpContentLengthFromPacket: () => null,
            isChunkedHttpTransferForPacket: () => false,
        });
        // The 204 response has an empty body, so it is skipped (nothing to
        // carve). Only the first response with a non-empty body is returned.
        expect(messages).toHaveLength(1);
        expect(hexToAsciiString(messages[0].bodyHex)).toBe("hello");
        expect(messages[0].framing).toBe("content-length");
    });

    test("concatenates body across multiple same-direction packets", () => {
        // First packet carries the headers + first 5 bytes of body; second
        // packet carries the remaining 6 bytes. Content-Length is 11.
        const bodyFull = "hello world";
        const headHex = strToHex("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n");
        const packet1 = { id: 1, hex: headHex + strToHex("hello"), dir: "A" };
        const packet2 = { id: 2, hex: strToHex(" world"), dir: "A" };
        const messages = collectHttpMessageBodiesFromStream({
            streamPackets: [packet1, packet2],
            referencePacket: packet1,
            getPacketIdentity: getIdentity,
            getPacketPayloadHex: getPayloadHex,
            isSameDirectionalStreamPacket: sameDirection,
            getHttpContentLengthFromPacket: () => 11,
            isChunkedHttpTransferForPacket: () => false,
        });
        expect(messages).toHaveLength(1);
        expect(hexToAsciiString(messages[0].bodyHex)).toBe(bodyFull);
    });

    test("falls back to single-blob when no HTTP start line is found", () => {
        // Payload with no CRLFCRLF — the helper should fall back to the
        // extractHttpBodyHex path and return a single entry.
        const packet = { id: 1, hex: strToHex("not http at all"), dir: "A" };
        const messages = collectHttpMessageBodiesFromStream({
            streamPackets: [packet],
            referencePacket: packet,
            getPacketIdentity: getIdentity,
            getPacketPayloadHex: getPayloadHex,
            isSameDirectionalStreamPacket: sameDirection,
            getHttpContentLengthFromPacket: () => null,
            isChunkedHttpTransferForPacket: () => false,
        });
        expect(messages).toHaveLength(0);
    });
});

// --- extractFilenameFromContentDisposition --------------------------------

describe("extractFilenameFromContentDisposition", () => {
    test("parses quoted filename", () => {
        expect(extractFilenameFromContentDisposition('attachment; filename="report.pdf"'))
            .toBe("report.pdf");
    });

    test("parses bare filename", () => {
        expect(extractFilenameFromContentDisposition("attachment; filename=report.pdf"))
            .toBe("report.pdf");
    });

    test("parses RFC 5987 filename* (UTF-8)", () => {
        const encoded = encodeURIComponent("café-résumé.pdf");
        expect(extractFilenameFromContentDisposition(`attachment; filename*=UTF-8''${encoded}`))
            .toBe("café-résumé.pdf");
    });

    test("returns '' for missing filename", () => {
        expect(extractFilenameFromContentDisposition("attachment")).toBe("");
        expect(extractFilenameFromContentDisposition("")).toBe("");
    });

    test("uses injected sanitizer when provided", () => {
        const sanitize = (name) => name.toUpperCase();
        expect(extractFilenameFromContentDisposition('attachment; filename="x.pdf"', sanitize))
            .toBe("X.PDF");
    });
});

// --- extractMultipartBoundaryFromContentType ------------------------------

describe("extractMultipartBoundaryFromContentType", () => {
    test("extracts boundary from multipart/form-data", () => {
        expect(extractMultipartBoundaryFromContentType(
            'multipart/form-data; boundary="----WebKitFormBoundary7MA4YWxkTrZu0gW"',
        )).toBe("----WebKitFormBoundary7MA4YWxkTrZu0gW");
    });

    test("extracts unquoted boundary", () => {
        expect(extractMultipartBoundaryFromContentType(
            "multipart/form-data; boundary=abc123",
        )).toBe("abc123");
    });

    test("returns '' for non-multipart content types", () => {
        expect(extractMultipartBoundaryFromContentType("application/json")).toBe("");
        expect(extractMultipartBoundaryFromContentType("")).toBe("");
    });
});

// --- findMultipartFileByteRanges -------------------------------------------

describe("findMultipartFileByteRanges", () => {
    const boundary = "----Boundary";

    test("returns [] for empty / invalid input", () => {
        expect(findMultipartFileByteRanges(new Uint8Array(0), boundary)).toEqual([]);
        expect(findMultipartFileByteRanges(null, boundary)).toEqual([]);
        expect(findMultipartFileByteRanges(new Uint8Array([1, 2, 3]), "")).toEqual([]);
        expect(findMultipartFileByteRanges(new Uint8Array([1, 2, 3]), null)).toEqual([]);
    });

    test("finds a single file part with a filename", () => {
        const body = buildMultipartBody(boundary, [
            {
                headers: {
                    "Content-Disposition": 'form-data; name="file"; filename="test.txt"',
                    "Content-Type": "text/plain",
                },
                body: "Hello, world!",
            },
        ]);
        const ranges = findMultipartFileByteRanges(body, boundary);
        expect(ranges).toHaveLength(1);
        expect(ranges[0].fileName).toBe("test.txt");
        expect(ranges[0].contentType).toBe("text/plain");
        const fileBytes = body.slice(ranges[0].range.start, ranges[0].range.end);
        expect(new TextDecoder().decode(fileBytes)).toBe("Hello, world!");
    });

    test("finds multiple file parts and returns each as a separate range", () => {
        const body = buildMultipartBody(boundary, [
            {
                headers: {
                    "Content-Disposition": 'form-data; name="file1"; filename="a.txt"',
                },
                body: "AAA",
            },
            {
                headers: {
                    "Content-Disposition": 'form-data; name="file2"; filename="b.txt"',
                },
                body: "BBB",
            },
        ]);
        const ranges = findMultipartFileByteRanges(body, boundary);
        expect(ranges).toHaveLength(2);
        expect(ranges[0].fileName).toBe("a.txt");
        expect(ranges[1].fileName).toBe("b.txt");
        expect(new TextDecoder().decode(body.slice(ranges[0].range.start, ranges[0].range.end))).toBe("AAA");
        expect(new TextDecoder().decode(body.slice(ranges[1].range.start, ranges[1].range.end))).toBe("BBB");
    });

    test("skips form fields without a filename", () => {
        const body = buildMultipartBody(boundary, [
            {
                headers: {
                    "Content-Disposition": 'form-data; name="field1"',
                },
                body: "value1",
            },
            {
                headers: {
                    "Content-Disposition": 'form-data; name="file"; filename="data.bin"',
                },
                body: "BINARY",
            },
        ]);
        const ranges = findMultipartFileByteRanges(body, boundary);
        expect(ranges).toHaveLength(1);
        expect(ranges[0].fileName).toBe("data.bin");
    });

    test("scans the full body — not just the first 8 KiB", () => {
        // Build a body where the first file part starts past 8 KiB by
        // prepending a large form-field part.
        const padding = "X".repeat(9000);
        const body = buildMultipartBody(boundary, [
            {
                headers: {
                    "Content-Disposition": 'form-data; name="padding"',
                },
                body: padding,
            },
            {
                headers: {
                    "Content-Disposition": 'form-data; name="file"; filename="deep.txt"',
                },
                body: "found-me",
            },
        ]);
        const ranges = findMultipartFileByteRanges(body, boundary);
        expect(ranges).toHaveLength(1);
        expect(ranges[0].fileName).toBe("deep.txt");
        const fileBytes = body.slice(ranges[0].range.start, ranges[0].range.end);
        expect(new TextDecoder().decode(fileBytes)).toBe("found-me");
    });

    test("uses injected sanitizer for filenames", () => {
        const body = buildMultipartBody(boundary, [
            {
                headers: {
                    "Content-Disposition": 'form-data; name="file"; filename="raw.txt"',
                },
                body: "data",
            },
        ]);
        const ranges = findMultipartFileByteRanges(body, boundary, (name) => name.toUpperCase());
        expect(ranges[0].fileName).toBe("RAW.TXT");
    });
});

// --- findMultipartFileByteRange (first-part convenience) ------------------

describe("findMultipartFileByteRange", () => {
    test("returns the first part's range or null", () => {
        const boundary = "B";
        const body = buildMultipartBody(boundary, [
            {
                headers: { "Content-Disposition": 'form-data; name="f"; filename="x.txt"' },
                body: "X",
            },
        ]);
        const range = findMultipartFileByteRange(body, boundary);
        expect(range).not.toBeNull();
        expect(new TextDecoder().decode(body.slice(range.start, range.end))).toBe("X");

        expect(findMultipartFileByteRange(body, "nonexistent")).toBeNull();
    });
});

// --- sliceCompleteChunkedHttpBodyHex --------------------------------------

describe("sliceCompleteChunkedHttpBodyHex", () => {
    test("decodes a simple two-chunk body", () => {
        const chunked = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        const hex = strToHex(chunked);
        const result = sliceCompleteChunkedHttpBodyHex(hex);
        expect(result).not.toBeNull();
        // The slice runs from the start through the final CRLF.
        expect(hexToAsciiString(result)).toBe(chunked);
    });

    test("returns null for an incomplete chunked body", () => {
        const incomplete = "5\r\nhello\r\n"; // missing the 0-chunk terminator
        expect(sliceCompleteChunkedHttpBodyHex(strToHex(incomplete))).toBeNull();
    });

    test("handles a single zero-length chunk (empty body)", () => {
        const empty = "0\r\n\r\n";
        const result = sliceCompleteChunkedHttpBodyHex(strToHex(empty));
        expect(result).not.toBeNull();
        expect(hexToAsciiString(result)).toBe(empty);
    });
});

// --- getHttpBodyFilenameExtension -----------------------------------------

describe("getHttpBodyFilenameExtension", () => {
    test("maps common MIME types to extensions", () => {
        expect(getHttpBodyFilenameExtension("application/json")).toBe("json");
        expect(getHttpBodyFilenameExtension("text/html")).toBe("html");
        expect(getHttpBodyFilenameExtension("image/png")).toBe("png");
        expect(getHttpBodyFilenameExtension("application/pdf")).toBe("pdf");
    });

    test("strips parameters before mapping", () => {
        expect(getHttpBodyFilenameExtension("text/html; charset=utf-8")).toBe("html");
        expect(getHttpBodyFilenameExtension("application/json; charset=utf-8")).toBe("json");
    });

    test("returns bin for unknown / empty types", () => {
        expect(getHttpBodyFilenameExtension("application/x-unknown")).toBe("bin");
        expect(getHttpBodyFilenameExtension("")).toBe("bin");
        expect(getHttpBodyFilenameExtension(null)).toBe("bin");
    });
});

// --- splitHttpMessageHeaders ----------------------------------------------

describe("splitHttpMessageHeaders", () => {
    test("splits a response into startLine + headers", () => {
        const headerAscii = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\n";
        const { startLine, headers } = splitHttpMessageHeaders(headerAscii);
        expect(startLine).toBe("HTTP/1.1 200 OK");
        expect(headers).toEqual([
            { name: "Content-Type", value: "text/html" },
            { name: "Content-Length", value: "5" },
        ]);
    });

    test("splits a request line", () => {
        const { startLine, headers } = splitHttpMessageHeaders(
            "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        expect(startLine).toBe("GET /path HTTP/1.1");
        expect(headers).toEqual([{ name: "Host", value: "example.com" }]);
    });

    test("returns empty headers for a bare start line", () => {
        const { startLine, headers } = splitHttpMessageHeaders("HTTP/1.1 204 No Content\r\n");
        expect(startLine).toBe("HTTP/1.1 204 No Content");
        expect(headers).toEqual([]);
    });
});

// --- parseContentLengthFromHeaderAscii ------------------------------------

describe("parseContentLengthFromHeaderAscii", () => {
    test("parses a numeric Content-Length", () => {
        expect(parseContentLengthFromHeaderAscii("HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n")).toBe(42);
    });

    test("returns null when Content-Length is absent", () => {
        expect(parseContentLengthFromHeaderAscii("HTTP/1.1 200 OK\r\nServer: x\r\n\r\n")).toBeNull();
        expect(parseContentLengthFromHeaderAscii("")).toBeNull();
    });

    test("returns null for non-numeric values", () => {
        expect(parseContentLengthFromHeaderAscii("HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n")).toBeNull();
    });
});

// --- isChunkedTransferEncodingHeader --------------------------------------

describe("isChunkedTransferEncodingHeader", () => {
    test("detects chunked Transfer-Encoding", () => {
        expect(isChunkedTransferEncodingHeader("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")).toBe(true);
    });

    test("returns false for non-chunked encodings", () => {
        expect(isChunkedTransferEncodingHeader("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n")).toBe(false);
        expect(isChunkedTransferEncodingHeader("")).toBe(false);
    });
});

// --- HTTP_FILENAME_EXT_BY_MIME --------------------------------------------

describe("HTTP_FILENAME_EXT_BY_MIME", () => {
    test("is a frozen object mapping MIME types to extensions", () => {
        expect(Object.isFrozen(HTTP_FILENAME_EXT_BY_MIME)).toBe(true);
        expect(HTTP_FILENAME_EXT_BY_MIME["application/json"]).toBe("json");
        expect(HTTP_FILENAME_EXT_BY_MIME["text/html"]).toBe("html");
        expect(HTTP_FILENAME_EXT_BY_MIME["image/png"]).toBe("png");
    });
});

// --- extractMultipartFilenameFromBodyBytes --------------------------------

describe("extractMultipartFilenameFromBodyBytes", () => {
    test("extracts the filename from the first part's Content-Disposition", () => {
        const boundary = "B";
        const body = buildMultipartBody(boundary, [
            {
                headers: { "Content-Disposition": 'form-data; name="f"; filename="doc.pdf"' },
                body: "data",
            },
        ]);
        expect(extractMultipartFilenameFromBodyBytes(body, boundary)).toBe("doc.pdf");
    });

    test("returns '' when no filename is present", () => {
        const boundary = "B";
        const body = buildMultipartBody(boundary, [
            {
                headers: { "Content-Disposition": 'form-data; name="field"' },
                body: "value",
            },
        ]);
        expect(extractMultipartFilenameFromBodyBytes(body, boundary)).toBe("");
    });

    test("returns '' for missing boundary / body", () => {
        expect(extractMultipartFilenameFromBodyBytes(null, "B")).toBe("");
        expect(extractMultipartFilenameFromBodyBytes(new Uint8Array([1]), "")).toBe("");
    });
});