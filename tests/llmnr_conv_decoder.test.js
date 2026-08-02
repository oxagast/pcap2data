// Tests for the LLMNR Conv decoder wiring. Mirrors dns_conv_decoder.test.js:
// hand-build LLMNR fixtures using simple byte helpers so the test exercises
// the same call shape the UI uses through autoDetectProtoFromBytes and the
// per-decoder switch in data-tools-panel.js / main-frontend/protocol-decoding.js.

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
        decodeDnsFromBytes: alwaysNull,
        decodeLlmnrFromBytes: convDecoders.decodeLlmnrFromBytes,
        decodeNbnsFromBytes: alwaysNull,
        decodeNbdgmFromBytes: alwaysNull,
        decodeSnmpFromBytes: alwaysNull,
        decodeDhcpFromBytes: alwaysNull,
        decodeDhcpv6FromBytes: alwaysNull,
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
        decodeLlmnrFromBytes: context.decodeLlmnrFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// ---- LLMNR fixture helpers -----------------------------------------------

// Encode a DNS name (label sequence) used by the LLMNR question / answer
// QNAME fields. Caller passes an array of labels like ["example", "com"].
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
    // Header: id=0xabcd, flags=0x0000 (standard query), qd=1, an=0, ns=0, ar=0
    // Question: myhost.local A IN
    const qname = encodeDnsName(["myhost", "local"]);
    const question = Buffer.concat([
        Buffer.from(qname),
        Uint8Array.from([0x00, 0x01, 0x00, 0x01]), // QTYPE=A, QCLASS=IN
    ]);
    return Uint8Array.from([
        0xab, 0xcd, // id
        0x00, 0x00, // flags (standard query)
        0x00, 0x01, // qdcount
        0x00, 0x00, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
        ...question,
    ]);
}

function buildResponse() {
    // Header: id=0x4321, flags=0x8400 (QR + RD), qd=1, an=1, ns=0, ar=0
    // Question: myhost.local A IN
    // Answer: myhost.local A IN TTL=120 RDATA=10.0.0.7
    const qname = encodeDnsName(["myhost", "local"]);
    const question = Buffer.concat([
        Buffer.from(qname),
        Uint8Array.from([0x00, 0x01, 0x00, 0x01]),
    ]);
    const rdata = Uint8Array.from([10, 0, 0, 7]);
    const answer = Uint8Array.from([
        ...encodeDnsName(["myhost", "local"]),
        0x00, 0x01, // TYPE=A
        0x00, 0x01, // CLASS=IN
        0x00, 0x00, 0x00, 0x78, // TTL=120
        0x00, 0x04, // RDLENGTH=4
        ...rdata,
    ]);
    return Uint8Array.from([
        0x43, 0x21,
        0x84, 0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        ...question,
        ...answer,
    ]);
}

// ---- Tests ---------------------------------------------------------------

describe("LLMNR Conv decoder wiring", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const decoderFiles = [
        path.join(projectRoot, "src/ui/panels/data-tools-panel.js"),
        path.join(projectRoot, "src/ui/main-frontend.js"),
    ];

    test.each(decoderFiles)("decodes an LLMNR query from %s", (filePath) => {
        const { decodeLlmnrFromBytes, autoDetectProtoFromBytes } =
            loadDecoderFunctions(filePath);
        const bytes = buildQuery();
        const decoded = decodeLlmnrFromBytes(bytes);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "LLMNR" })
        );
        expect(getFieldValue(decoded, "Message 1 ID")).toBe("0xabcd");
        expect(getFieldValue(decoded, "Message 1 Type")).toBe("Query");
        expect(getFieldValue(decoded, "Message 1 Question Count")).toBe("1");
        expect(getFieldValue(decoded, "Message 1 Question 1")).toBe(
            "myhost.local A IN"
        );
        const portHint = { decoder: "llmnr" };
        expect(autoDetectProtoFromBytes(bytes, { portHint })).toBe("llmnr");
    });

    test.each(decoderFiles)("decodes an LLMNR response from %s", (filePath) => {
        const { decodeLlmnrFromBytes } = loadDecoderFunctions(filePath);
        const bytes = buildResponse();
        const decoded = decodeLlmnrFromBytes(bytes);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "LLMNR" })
        );
        expect(getFieldValue(decoded, "Message 1 Type")).toBe("Response");
        expect(getFieldValue(decoded, "Message 1 Rcode")).toBe("Success");
        const answer = getFieldValue(decoded, "Message 1 Answer 1");
        expect(answer).toContain("myhost.local");
        expect(answer).toContain("A");
        expect(answer).toContain("TTL=120");
        expect(answer).toContain("10.0.0.7");
    });

    test.each(decoderFiles)(
        "returns null for invalid bytes from %s",
        (filePath) => {
            const { decodeLlmnrFromBytes } = loadDecoderFunctions(filePath);
            expect(decodeLlmnrFromBytes(null)).toBeNull();
            expect(decodeLlmnrFromBytes(new Uint8Array(0))).toBeNull();
            // 11 bytes (less than DNS header) → null.
            const short = Uint8Array.from(Array.from({ length: 11 }, () => 0));
            expect(decodeLlmnrFromBytes(short)).toBeNull();
        }
    );
});

describe("LLMNR protocol/port hints", () => {
    const {
        PROTOCOL_DECODER_HINTS,
        PORT_DECODER_HINTS,
    } = require(
        path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/protocol-hints")
    );

    test("maps llmnr protocol string to the llmnr decoder", () => {
        expect(PROTOCOL_DECODER_HINTS.get("llmnr")).toBe("llmnr");
    });

    test("maps port 5355 to the llmnr decoder", () => {
        expect(PORT_DECODER_HINTS.get(5355)).toBe("llmnr");
    });
});

describe("LLMNR registry + dropdown wiring", () => {
    test("llmnr is registered as a supported decoder protocol", () => {
        const { SUPPORTED_DECODER_PROTOS } = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/mime-maps")
        );
        expect(SUPPORTED_DECODER_PROTOS.has("llmnr")).toBe(true);
    });

    test("decodeLlmnrFromBytes is exported from the conv barrel", () => {
        const convDecoders = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv")
        );
        expect(typeof convDecoders.decodeLlmnrFromBytes).toBe("function");
    });
});
