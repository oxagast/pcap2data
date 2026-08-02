// Tests for the DNS Conv decoder wiring. Mirrors the style of
// kerberos_conv_decoder.test.js: hand-build DNS fixtures using
// simple byte helpers so the test exercises the same call shape the
// UI uses through autoDetectProtoFromBytes and the per-decoder switch
// in data-tools-panel.js / main-frontend/protocol-decoding.js.

const fs = require("fs");
const path = require("path");
const vm = require("vm");

function extractFunctionSource(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    const bodyStart = sourceText.indexOf("{", startIndex);
    if (bodyStart === -1) {
        throw new Error(`Could not find body for ${functionName}`);
    }
    let depth = 0;
    let cursor = bodyStart;
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inTemplate = false;
    let inLineComment = false;
    let inBlockComment = false;
    let inRegex = false;
    let escaped = false;

    while (cursor < sourceText.length) {
        const char = sourceText[cursor];
        const next = sourceText[cursor + 1];

        if (inLineComment) {
            if (char === "\n") inLineComment = false;
            cursor += 1;
            continue;
        }
        if (inBlockComment) {
            if (char === "*" && next === "/") {
                inBlockComment = false;
                cursor += 2;
                continue;
            }
            cursor += 1;
            continue;
        }
        if (inSingleQuote || inDoubleQuote || inTemplate || inRegex) {
            if (escaped) {
                escaped = false;
                cursor += 1;
                continue;
            }
            if (char === "\\") {
                escaped = true;
                cursor += 1;
                continue;
            }
            if (inSingleQuote && char === "'") inSingleQuote = false;
            else if (inDoubleQuote && char === '"') inDoubleQuote = false;
            else if (inTemplate && char === "`") inTemplate = false;
            else if (inRegex && char === "/") inRegex = false;
            cursor += 1;
            continue;
        }

        if (char === "/" && next === "/") {
            inLineComment = true;
            cursor += 2;
            continue;
        }
        if (char === "/" && next === "*") {
            inBlockComment = true;
            cursor += 2;
            continue;
        }
        if (char === "'") {
            inSingleQuote = true;
            cursor += 1;
            continue;
        }
        if (char === '"') {
            inDoubleQuote = true;
            cursor += 1;
            continue;
        }
        if (char === "`") {
            inTemplate = true;
            cursor += 1;
            continue;
        }
        if (char === "/") {
            const prev = sourceText[cursor - 1];
            if (!prev || /[=(:,!&|?{};\s]/.test(prev)) {
                inRegex = true;
                cursor += 1;
                continue;
            }
        }

        if (char === "{") depth += 1;
        if (char === "}") {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
        cursor += 1;
    }
    throw new Error(`Could not parse function ${functionName}`);
}

function loadDecoderFunctions(filePath) {
    const sourceText = fs.readFileSync(filePath, "utf8");
    const convDecoders = require(
        path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv")
    );
    let extractedSource = "";
    if (sourceText.includes("function autoDetectProtoFromBytes")) {
        extractedSource = extractFunctionSource(
            sourceText,
            "autoDetectProtoFromBytes"
        );
    } else {
        const autoDetectSource = fs.readFileSync(
            path.join(
                path.resolve(__dirname, ".."),
                "src/ui/decoders/conv/auto-detect.js"
            ),
            "utf8"
        );
        extractedSource = extractFunctionSource(
            autoDetectSource,
            "autoDetectProtoFromBytes"
        );
    }
    const alwaysNull = () => null;
    const context = {
        Uint8Array,
        DataView,
        TextDecoder,
        Buffer,
        getImageTypeFromExifReader: alwaysNull,
        decodeHtmlFromBytes: alwaysNull,
        decodeJsonFromBytes: alwaysNull,
        decodeXmlFromBytes: alwaysNull,
        decodeBerFromBytes: alwaysNull,
        decodeDerFromBytes: alwaysNull,
        decodeYamlFromBytes: alwaysNull,
        decodeLdapFromBytes: alwaysNull,
        decodeSmbFromBytes: alwaysNull,
        decodeSipFromBytes: alwaysNull,
        decodeSmppFromBytes: alwaysNull,
        decodeBittorrentFromBytes: alwaysNull,
        decodeBsonFromBytes: alwaysNull,
        decodeMessagePackFromBytes: alwaysNull,
        decodeProtobufFromBytes: alwaysNull,
        decodeKerberosFromBytes: alwaysNull,
        decodeDnsFromBytes: convDecoders.decodeDnsFromBytes,
        decodeSnmpFromBytes: convDecoders.decodeSnmpFromBytes,
        decodeDhcpFromBytes: convDecoders.decodeDhcpFromBytes,
        decodeDhcpv6FromBytes: convDecoders.decodeDhcpv6FromBytes,
        bytesToHexLower: convDecoders.bytesToHexLower,
        normalizeSmbDecoderBytes: convDecoders.normalizeSmbDecoderBytes,
        findBytesSubsequence: convDecoders.findBytesSubsequence,
        parseSmbNtlmSecurityBuffer: convDecoders.parseSmbNtlmSecurityBuffer,
        decodeSmbTextBytes: convDecoders.decodeSmbTextBytes,
        autoDetectProtoFromBytes: convDecoders.autoDetectProtoFromBytes,
    };
    vm.createContext(context);
    vm.runInContext(extractedSource, context);
    return {
        decodeDnsFromBytes: context.decodeDnsFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// ---- DNS fixture helpers --------------------------------------------------

// Encode a single DNS name (label sequence). The trailing root label is
// implicit — caller passes an array of labels like ["example", "com"].
function encodeDnsName(labels) {
    const parts = [];
    for (const label of labels) {
        const bytes = Buffer.from(label, "utf8");
        if (bytes.length === 0 || bytes.length > 63) {
            throw new Error(`bad label length ${bytes.length}`);
        }
        parts.push(Uint8Array.from([bytes.length, ...bytes]));
    }
    parts.push(Uint8Array.from([0]));
    return Buffer.concat(parts.map((p) => Buffer.from(p)));
}

function buildQuery() {
    // Header: id=0x1234, flags=0x0100 (RD), qd=1, an=0, ns=0, ar=0
    // Question: example.com A IN
    const qname = encodeDnsName(["example", "com"]);
    const question = Buffer.concat([
        Buffer.from(qname),
        Uint8Array.from([0x00, 0x01, 0x00, 0x01]), // QTYPE=A, QCLASS=IN
    ]);
    return Uint8Array.from([
        0x12, 0x34, // id
        0x01, 0x00, // flags RD
        0x00, 0x01, // qdcount
        0x00, 0x00, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
        ...question,
    ]);
}

function buildResponseWithCompression() {
    // Header: id=0x4321, flags=0x8180 (QR + RD + RA), qd=1, an=1, ns=0, ar=0
    // Question: example.com A IN
    // Answer: example.com A IN TTL=300 RDATA=93.184.216.34
    //         name uses compression pointer to offset 12 (the question name).
    const qname = encodeDnsName(["example", "com"]);
    const question = Buffer.concat([
        Buffer.from(qname),
        Uint8Array.from([0x00, 0x01, 0x00, 0x01]),
    ]);
    // Answer RDATA: 4-byte IPv4 address.
    const rdata = Uint8Array.from([93, 184, 216, 34]);
    // Compressed answer name: 0xC0 0x0C points to offset 12 (start of question).
    const answer = Uint8Array.from([
        0xc0, 0x0c,
        0x00, 0x01, // TYPE=A
        0x00, 0x01, // CLASS=IN
        0x00, 0x00, 0x01, 0x2c, // TTL=300
        0x00, 0x04, // RDLENGTH=4
        ...rdata,
    ]);
    return Uint8Array.from([
        0x43, 0x21,
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        ...question,
        ...answer,
    ]);
}

function buildTcpFramed() {
    // 2-byte length prefix + DNS message, exactly matching RFC 1035 §4.2.2.
    const inner = Buffer.from(buildQuery());
    const length = inner.length;
    return Uint8Array.from([
        (length >>> 8) & 0xff,
        length & 0xff,
        ...inner,
    ]);
}

// ---- Tests ---------------------------------------------------------------

describe("DNS Conv decoder wiring", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const decoderFiles = [
        path.join(projectRoot, "src/ui/panels/data-tools-panel.js"),
        path.join(projectRoot, "src/ui/main-frontend.js"),
    ];

    test.each(decoderFiles)("decodes a DNS query from %s", (filePath) => {
        const { decodeDnsFromBytes, autoDetectProtoFromBytes } =
            loadDecoderFunctions(filePath);
        const bytes = buildQuery();
        const decoded = decodeDnsFromBytes(bytes);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "DNS" })
        );
        expect(getFieldValue(decoded, "Message 1 ID")).toBe("0x1234");
        expect(getFieldValue(decoded, "Message 1 Type")).toBe("Query");
        expect(getFieldValue(decoded, "Message 1 Question Count")).toBe("1");
        expect(getFieldValue(decoded, "Message 1 Answer Count")).toBe("0");
        expect(getFieldValue(decoded, "Message 1 Question 1")).toBe(
            "example.com A IN"
        );
        const portHint = { decoder: "dns" };
        expect(autoDetectProtoFromBytes(bytes, { portHint })).toBe("dns");
    });

    test.each(decoderFiles)(
        "decodes a DNS response with compression pointer from %s",
        (filePath) => {
            const { decodeDnsFromBytes } = loadDecoderFunctions(filePath);
            const bytes = buildResponseWithCompression();
            const decoded = decodeDnsFromBytes(bytes);
            expect(decoded).toEqual(
                expect.objectContaining({ protocol: "DNS" })
            );
            expect(getFieldValue(decoded, "Message 1 Type")).toBe("Response");
            expect(getFieldValue(decoded, "Message 1 Rcode")).toBe("NoError");
            expect(getFieldValue(decoded, "Message 1 Question 1")).toBe(
                "example.com A IN"
            );
            const answer = getFieldValue(decoded, "Message 1 Answer 1");
            expect(answer).toContain("example.com");
            expect(answer).toContain("A");
            expect(answer).toContain("TTL=300");
            expect(answer).toContain("93.184.216.34");
        }
    );

    test.each(decoderFiles)(
        "decodes a TCP-framed DNS message from %s",
        (filePath) => {
            const { decodeDnsFromBytes } = loadDecoderFunctions(filePath);
            const bytes = buildTcpFramed();
            const decoded = decodeDnsFromBytes(bytes);
            expect(decoded).toEqual(
                expect.objectContaining({ protocol: "DNS" })
            );
            expect(getFieldValue(decoded, "Message 1 ID")).toBe("0x1234");
            expect(getFieldValue(decoded, "Message 1 Question 1")).toBe(
                "example.com A IN"
            );
        }
    );

    test.each(decoderFiles)(
        "returns null for trivially short or invalid bytes from %s",
        (filePath) => {
            const { decodeDnsFromBytes } = loadDecoderFunctions(filePath);
            expect(decodeDnsFromBytes(null)).toBeNull();
            expect(decodeDnsFromBytes(new Uint8Array(0))).toBeNull();
            // Anything 12+ bytes gets a header parse back; verify the
            // question walk returns null because there is no QNAME
            // (just a zero terminator would consume the whole buffer).
            const random = Uint8Array.from(Array.from({ length: 11 }, () => 0));
            expect(decodeDnsFromBytes(random)).toBeNull();
        }
    );
});

describe("DNS protocol/port hints", () => {
    const {
        PROTOCOL_DECODER_HINTS,
        PORT_DECODER_HINTS,
    } = require(
        path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/protocol-hints")
    );

    test("maps dns protocol string to the dns decoder", () => {
        expect(PROTOCOL_DECODER_HINTS.get("dns")).toBe("dns");
    });

    test("maps port 53 to the dns decoder", () => {
        expect(PORT_DECODER_HINTS.get(53)).toBe("dns");
    });
});

describe("DNS registry + dropdown wiring", () => {
    test("dns is registered as a supported decoder protocol", () => {
        const { SUPPORTED_DECODER_PROTOS } = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/mime-maps")
        );
        expect(SUPPORTED_DECODER_PROTOS.has("dns")).toBe(true);
    });

    test("decodeDnsFromBytes is exported from the conv barrel", () => {
        const convDecoders = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv")
        );
        expect(typeof convDecoders.decodeDnsFromBytes).toBe("function");
    });
});
