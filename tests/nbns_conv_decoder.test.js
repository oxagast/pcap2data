// Tests for the NetBIOS-NS (NetBIOS Name Service) Conv decoder wiring.
// Mirrors dns_conv_decoder.test.js: hand-build NBNS fixtures using
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
        decodeDnsFromBytes: alwaysNull,
        decodeLlmnrFromBytes: alwaysNull,
        decodeNbnsFromBytes: convDecoders.decodeNbnsFromBytes,
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
        decodeNbnsFromBytes: context.decodeNbnsFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// ---- NetBIOS-NS fixture helpers ------------------------------------------

// Encode a NetBIOS name in RFC 1001 First-Level Encoding (32-byte body).
// Each ASCII char in `name` is encoded as a 1-byte value where the high
// and low nibbles are 0x4 and 0x1 (i.e. 'A' = 0x41). Names shorter than
// 15 characters are padded with spaces (0x20) and the final scope byte
// records the visible length.
function encodeNetbiosName(name) {
    if (typeof name !== "string" || name.length === 0 || name.length > 15) {
        throw new Error(`bad netbios name length ${name.length}`);
    }
    const padded = name.padEnd(15, " ");
    const visible = name.length;
    const bodyBytes = [];
    for (let i = 0; i < 15; i += 1) {
        const ch = padded.charCodeAt(i);
        bodyBytes.push((ch >> 4) | 0x40);
        bodyBytes.push((ch & 0x0f) | 0x40);
    }
    // 16th character is the scope suffix (space = 0x20).
    bodyBytes.push(0x20);
    bodyBytes.push(visible);
    return Uint8Array.from([0x20, ...bodyBytes]);
}

function buildQuery() {
    // Header: NAME_TRN_ID=0x1234, FLAGS=0x0110 (RD + B), QD=1, AN=0, NS=0, AR=0
    // Question: WORKSTATION      <00> NB IN
    const qname = encodeNetbiosName("WORKSTATION");
    // QTYPE=0x0020 (NB), QCLASS=0x0001 (IN).
    return Uint8Array.from([
        0x12, 0x34, // NAME_TRN_ID
        0x01, 0x10, // FLAGS: RD + B
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        ...qname,
        0x00, // label terminator
        0x00, 0x20, // QTYPE=NB
        0x00, 0x01, // QCLASS=IN
    ]);
}

function buildResponse() {
    // Header: NAME_TRN_ID=0x4321, FLAGS=0x8500 (QR + RD + RA), QD=1, AN=1, NS=0, AR=0
    // Question: WORKSTATION      <00> NB IN
    // Answer: WORKSTATION       <00> NB IN TTL=300000, RDATA = flags=0x6000 (G + ON) + IP 10.0.0.7
    const qname = encodeNetbiosName("WORKSTATION");
    const answerName = encodeNetbiosName("WORKSTATION");
    const rdata = Uint8Array.from([
        0x00, 0x80, // flags: G (group, bit 7)
        10, 0, 0, 7, // IPv4
    ]);
    const answer = Uint8Array.from([
        ...answerName,
        0x00, // label terminator
        0x00, 0x20, // TYPE=NB
        0x00, 0x01, // CLASS=IN
        0x00, 0x04, 0x93, 0xe0, // TTL=300000
        0x00, 0x06, // RDLENGTH=6
        ...rdata,
    ]);
    return Uint8Array.from([
        0x43, 0x21,
        0x85, 0x00,
        0x00, 0x01, // QDCOUNT
        0x00, 0x01, // ANCOUNT
        0x00, 0x00,
        0x00, 0x00,
        ...qname,
        0x00,
        0x00, 0x20,
        0x00, 0x01,
        ...answer,
    ]);
}

// ---- Tests ---------------------------------------------------------------

describe("NetBIOS-NS Conv decoder wiring", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const decoderFiles = [
        path.join(projectRoot, "src/ui/panels/data-tools-panel.js"),
        path.join(projectRoot, "src/ui/main-frontend.js"),
    ];

    test.each(decoderFiles)("decodes an NBNS query from %s", (filePath) => {
        const { decodeNbnsFromBytes, autoDetectProtoFromBytes } =
            loadDecoderFunctions(filePath);
        const bytes = buildQuery();
        const decoded = decodeNbnsFromBytes(bytes);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "NetBIOS-NS" })
        );
        expect(getFieldValue(decoded, "Transaction ID")).toBe("0x1234");
        expect(getFieldValue(decoded, "Type")).toBe("Query");
        expect(getFieldValue(decoded, "Opcode")).toBe("Query");
        expect(getFieldValue(decoded, "Question Count")).toBe("1");
        expect(getFieldValue(decoded, "Question 1")).toBe(
            "WORKSTATION NB CLASS=0x0001"
        );
        const portHint = { decoder: "nbns" };
        expect(autoDetectProtoFromBytes(bytes, { portHint })).toBe("nbns");
    });

    test.each(decoderFiles)(
        "decodes an NBNS response with NB rdata from %s",
        (filePath) => {
            const { decodeNbnsFromBytes } = loadDecoderFunctions(filePath);
            const bytes = buildResponse();
            const decoded = decodeNbnsFromBytes(bytes);
            expect(decoded).toEqual(
                expect.objectContaining({ protocol: "NetBIOS-NS" })
            );
            expect(getFieldValue(decoded, "Type")).toBe("Response");
            expect(getFieldValue(decoded, "Answer Count")).toBe("1");
            const answer = getFieldValue(decoded, "Answer RR 1");
            expect(answer).toContain("WORKSTATION");
            expect(answer).toContain("NB");
            expect(answer).toContain("TTL=300000");
            expect(answer).toContain("10.0.0.7");
            expect(answer).toContain("Group");
        }
    );

    test.each(decoderFiles)(
        "returns null for invalid bytes from %s",
        (filePath) => {
            const { decodeNbnsFromBytes } = loadDecoderFunctions(filePath);
            expect(decodeNbnsFromBytes(null)).toBeNull();
            expect(decodeNbnsFromBytes(new Uint8Array(0))).toBeNull();
            const short = Uint8Array.from(Array.from({ length: 11 }, () => 0));
            expect(decodeNbnsFromBytes(short)).toBeNull();
        }
    );
});

describe("NetBIOS-NS protocol/port hints", () => {
    const {
        PROTOCOL_DECODER_HINTS,
        PORT_DECODER_HINTS,
    } = require(
        path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/protocol-hints")
    );

    test("maps nbns + aliases to the nbns decoder", () => {
        expect(PROTOCOL_DECODER_HINTS.get("nbns")).toBe("nbns");
        expect(PROTOCOL_DECODER_HINTS.get("netbios-ns")).toBe("nbns");
        expect(PROTOCOL_DECODER_HINTS.get("netbios-name-service")).toBe("nbns");
    });

    test("maps port 137 to the nbns decoder", () => {
        expect(PORT_DECODER_HINTS.get(137)).toBe("nbns");
    });
});

describe("NetBIOS-NS registry + dropdown wiring", () => {
    test("nbns is registered as a supported decoder protocol", () => {
        const { SUPPORTED_DECODER_PROTOS } = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/mime-maps")
        );
        expect(SUPPORTED_DECODER_PROTOS.has("nbns")).toBe(true);
    });

    test("decodeNbnsFromBytes is exported from the conv barrel", () => {
        const convDecoders = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv")
        );
        expect(typeof convDecoders.decodeNbnsFromBytes).toBe("function");
    });
});
