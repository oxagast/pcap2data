// Tests for the Telnet Conv decoder wiring. Mirrors the style of
// snmp_conv_decoder.test.js: hand-build Telnet fixtures so the test
// exercises the same call shape the UI uses through
// autoDetectProtoFromBytes and the per-decoder switch in
// data-tools-panel.js / main-frontend/protocol-decoding.js.

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
    const sourceText = require("fs").readFileSync(filePath, "utf8");
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
        const autoDetectSource = require("fs").readFileSync(
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
        decodeNbnsFromBytes: alwaysNull,
        decodeNbdgmFromBytes: alwaysNull,
        decodeSnmpFromBytes: alwaysNull,
        decodeDhcpFromBytes: alwaysNull,
        decodeDhcpv6FromBytes: alwaysNull,
        decodeTelnetFromBytes: convDecoders.decodeTelnetFromBytes,
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
        decodeTelnetFromBytes: context.decodeTelnetFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// ---- Telnet fixture helpers ----------------------------------------------

// Build a Telnet-like payload with IAC negotiations and text.
function buildTelnetWithNegotiations() {
    // IAC WILL ECHO + "login: " text
    const text = "login: ";
    const bytes = [];
    // IAC WILL ECHO
    bytes.push(0xff, 0xfb, 0x01);
    // IAC DO SUPRESS-GO-AHEAD
    bytes.push(0xff, 0xfd, 0x03);
    // Text bytes
    for (let i = 0; i < text.length; i++) {
        bytes.push(text.charCodeAt(i));
    }
    return Uint8Array.from(bytes);
}

// Build a plain text payload that looks like Telnet (no IAC).
function buildPlainTextTelnet() {
    const text = "Password: ";
    return Uint8Array.from(text.split("").map((c) => c.charCodeAt(0)));
}

// Build a payload that is mostly garbage binary (should be rejected).
function buildGarbageBinary() {
    const bytes = [];
    // 10% printable text
    bytes.push(0x50, 0x61, 0x73, 0x73); // "Pass"
    // 90% garbage binary (0x00-0x1f except newline, 0x80-0xff)
    for (let i = 0; i < 36; i++) {
        bytes.push(0x00);
    }
    bytes.push(0xc0, 0xa0, 0xff, 0xfe);
    for (let i = 0; i < 50; i++) {
        bytes.push(0x80 | (i & 0x7f));
    }
    return Uint8Array.from(bytes);
}

// ---- Tests ---------------------------------------------------------------

describe("Telnet Conv decoder wiring", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const decoderFiles = [
        path.join(projectRoot, "src/ui/panels/data-tools-panel.js"),
        path.join(projectRoot, "src/ui/main-frontend.js"),
    ];

    test.each(decoderFiles)(
        "decodes Telnet with IAC negotiations from %s",
        (filePath) => {
            const { decodeTelnetFromBytes } = loadDecoderFunctions(filePath);
            const bytes = buildTelnetWithNegotiations();
            const decoded = decodeTelnetFromBytes(bytes);
            expect(decoded).not.toBeNull();
            expect(decoded.protocol).toBe("Telnet");
            expect(getFieldValue(decoded, "Negotiations")).toContain("WILL Echo");
            expect(getFieldValue(decoded, "Text")).toContain("login:");
        }
    );

    test.each(decoderFiles)(
        "decodes plain text that looks like Telnet from %s",
        (filePath) => {
            const { decodeTelnetFromBytes } = loadDecoderFunctions(filePath);
            const bytes = buildPlainTextTelnet();
            const decoded = decodeTelnetFromBytes(bytes);
            expect(decoded).not.toBeNull();
            expect(decoded.protocol).toBe("Telnet");
            expect(getFieldValue(decoded, "Text")).toBe("Password:");
        }
    );

    test.each(decoderFiles)(
        "rejects garbage binary payloads from %s",
        (filePath) => {
            const { decodeTelnetFromBytes } = loadDecoderFunctions(filePath);
            const bytes = buildGarbageBinary();
            // The garbage ratio is way over 30%, so it should be rejected.
            expect(decodeTelnetFromBytes(bytes)).toBeNull();
        }
    );

    test.each(decoderFiles)(
        "rejects pure null bytes from %s",
        (filePath) => {
            const { decodeTelnetFromBytes } = loadDecoderFunctions(filePath);
            const bytes = new Uint8Array(20);
            expect(decodeTelnetFromBytes(bytes)).toBeNull();
        }
    );

    test.each(decoderFiles)(
        "returns null for null/undefined input from %s",
        (filePath) => {
            const { decodeTelnetFromBytes } = loadDecoderFunctions(filePath);
            expect(decodeTelnetFromBytes(null)).toBeNull();
            expect(decodeTelnetFromBytes(undefined)).toBeNull();
        }
    );

    test.each(decoderFiles)(
        "auto-detects Telnet with port hint from %s",
        (filePath) => {
            const { decodeTelnetFromBytes, autoDetectProtoFromBytes } =
                loadDecoderFunctions(filePath);
            const bytes = buildTelnetWithNegotiations();
            const portHint = { decoder: "telnet" };
            expect(autoDetectProtoFromBytes(bytes, { portHint })).toBe("telnet");
        }
    );
});

describe("Telnet protocol/port hints", () => {
    const {
        PROTOCOL_DECODER_HINTS,
        PORT_DECODER_HINTS,
    } = require(
        path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/protocol-hints")
    );

    test("maps telnet protocol string to the telnet decoder", () => {
        expect(PROTOCOL_DECODER_HINTS.get("telnet")).toBe("telnet");
    });

    test("maps port 23 to the telnet decoder", () => {
        expect(PORT_DECODER_HINTS.get(23)).toBe("telnet");
    });
});

describe("Telnet registry + dropdown wiring", () => {
    test("telnet is registered as a supported decoder protocol", () => {
        const { SUPPORTED_DECODER_PROTOS } = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/mime-maps")
        );
        expect(SUPPORTED_DECODER_PROTOS.has("telnet")).toBe(true);
    });

    test("decodeTelnetFromBytes is exported from the conv barrel", () => {
        const convDecoders = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv")
        );
        expect(typeof convDecoders.decodeTelnetFromBytes).toBe("function");
    });
});
