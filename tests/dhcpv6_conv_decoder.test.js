// Tests for the DHCPv6 Conv decoder wiring. Mirrors the style of
// kerberos_conv_decoder.test.js: hand-build DHCPv6 fixtures using simple
// byte builders so the test exercises the same call shape the UI uses
// through autoDetectProtoFromBytes and the per-decoder switch in
// data-tools-panel.js / main-frontend/protocol-decoding.js.

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
        decodeSnmpFromBytes: alwaysNull,
        decodeDhcpFromBytes: alwaysNull,
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
        decodeDhcpv6FromBytes: context.decodeDhcpv6FromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// ---- DHCPv6 fixture builders ---------------------------------------------

function option(code, value) {
    const valueBytes = value instanceof Uint8Array ? value : Buffer.from(value);
    return Uint8Array.from([
        (code >>> 8) & 0xff,
        code & 0xff,
        (valueBytes.length >>> 8) & 0xff,
        valueBytes.length & 0xff,
        ...valueBytes,
    ]);
}

function ipv6(groups) {
    // groups is an array of 8 hex strings.
    const bytes = [];
    for (const g of groups) {
        const value = parseInt(g, 16);
        bytes.push((value >>> 8) & 0xff, value & 0xff);
    }
    return Uint8Array.from(bytes);
}

function buildSolicit() {
    // Message: SOLICIT (1), transaction-id 0x00aabb, IA_NA option, ORO option.
    // IA_NA: IAID=1, T1=0, T2=0, no nested options.
    const iaNaBody = Uint8Array.from([
        0x00, 0x00, 0x00, 0x01, // IAID
        0x00, 0x00, 0x00, 0x00, // T1
        0x00, 0x00, 0x00, 0x00, // T2
    ]);
    // ORO: requested option codes 23 (DNS), 24 (domain-list).
    const oroBody = Uint8Array.from([
        0x00, 0x17, // 23
        0x00, 0x18, // 24
    ]);
    return Uint8Array.from([
        0x01, // SOLICIT
        0x00, 0xaa, 0xbb, // transaction id
        ...option(3, iaNaBody), // IA_NA
        ...option(6, oroBody), // ORO
    ]);
}

function buildReply() {
    // Reply with DNS server option 21 carrying two IPv6 addresses.
    const dnsServers = Uint8Array.from([
        ...ipv6(["20", "01", "48", "60", "00", "00", "00", "00"]),
        ...ipv6(["20", "01", "48", "60", "00", "00", "00", "01"]),
    ]);
    return Uint8Array.from([
        0x07, // REPLY
        0x00, 0xaa, 0xbb,
        ...option(21, dnsServers),
    ]);
}

function buildRelayForw() {
    // RELAY-FORW wraps another DHCPv6 message via option 9 (relay-msg).
    const inner = buildSolicit();
    return Uint8Array.from([
        0x0c, // RELAY-FORW
        0x11, 0x22, 0x33,
        ...option(9, inner),
    ]);
}

// ---- Tests ---------------------------------------------------------------

describe("DHCPv6 Conv decoder wiring", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const decoderFiles = [
        path.join(projectRoot, "src/ui/panels/data-tools-panel.js"),
        path.join(projectRoot, "src/ui/main-frontend.js"),
    ];

    test.each(decoderFiles)("decodes a DHCPv6 SOLICIT from %s", (filePath) => {
        const { decodeDhcpv6FromBytes, autoDetectProtoFromBytes } =
            loadDecoderFunctions(filePath);
        const bytes = buildSolicit();
        const decoded = decodeDhcpv6FromBytes(bytes);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "DHCPv6" })
        );
        expect(getFieldValue(decoded, "Message Type")).toBe("SOLICIT");
        expect(getFieldValue(decoded, "Transaction ID")).toBe("0x00aabb");
        // IA_NA surface: IAID + nested walk (T1/T2 fields appear as part of
        // the IA_NA option preview).
        expect(getFieldValue(decoded, "ia-na IAID")).toBe("1");
        expect(getFieldValue(decoded, "oro")).toBe("23,24");
        const portHint = { decoder: "dhcpv6" };
        expect(autoDetectProtoFromBytes(bytes, { portHint })).toBe("dhcpv6");
    });

    test.each(decoderFiles)("decodes a DHCPv6 REPLY with DNS servers from %s", (filePath) => {
        const { decodeDhcpv6FromBytes } = loadDecoderFunctions(filePath);
        const bytes = buildReply();
        const decoded = decodeDhcpv6FromBytes(bytes);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "DHCPv6" })
        );
        expect(getFieldValue(decoded, "Message Type")).toBe("REPLY");
        // option 21 is dns-servers; two IPv6 addresses joined with commas.
        // The formatter drops leading zeros per RFC 5952.
        expect(getFieldValue(decoded, "dns-servers")).toBe(
            "20:1:48:60::,20:1:48:60::1"
        );
    });

    test.each(decoderFiles)("recurses into relay-msg option from %s", (filePath) => {
        const { decodeDhcpv6FromBytes } = loadDecoderFunctions(filePath);
        const bytes = buildRelayForw();
        const decoded = decodeDhcpv6FromBytes(bytes);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "DHCPv6" })
        );
        expect(getFieldValue(decoded, "Message Type")).toBe("RELAY-FORW");
        // The inner SOLICIT message type appears after recursion.
        const innerType = (decoded.fields || []).find(
            (field) => typeof field.name === "string" && field.name.includes("Message Type"),
        );
        // First "Message Type" is RELAY-FORW; at least one more should be
        // SOLICIT from the recursion.
        expect(innerType).toBeDefined();
        const allValues = (decoded.fields || []).map((f) => f.value);
        expect(allValues).toContain("SOLICIT");
    });

    test.each(decoderFiles)(
        "returns null for too-short input from %s",
        (filePath) => {
            const { decodeDhcpv6FromBytes } = loadDecoderFunctions(filePath);
            expect(decodeDhcpv6FromBytes(null)).toBeNull();
            expect(decodeDhcpv6FromBytes(new Uint8Array(0))).toBeNull();
            expect(decodeDhcpv6FromBytes(new Uint8Array(3))).toBeNull();
        }
    );
});

describe("DHCPv6 protocol/port hints", () => {
    const {
        PROTOCOL_DECODER_HINTS,
        PORT_DECODER_HINTS,
    } = require(
        path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/protocol-hints")
    );

    test("maps dhcpv6 protocol string to the dhcpv6 decoder", () => {
        expect(PROTOCOL_DECODER_HINTS.get("dhcpv6")).toBe("dhcpv6");
    });

    test("maps DHCPv6 ports 546/547 to the dhcpv6 decoder", () => {
        expect(PORT_DECODER_HINTS.get(546)).toBe("dhcpv6");
        expect(PORT_DECODER_HINTS.get(547)).toBe("dhcpv6");
    });
});

describe("DHCPv6 registry + dropdown wiring", () => {
    test("dhcpv6 is registered as a supported decoder protocol", () => {
        const { SUPPORTED_DECODER_PROTOS } = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/mime-maps")
        );
        expect(SUPPORTED_DECODER_PROTOS.has("dhcpv6")).toBe(true);
    });

    test("decodeDhcpv6FromBytes is exported from the conv barrel", () => {
        const convDecoders = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv")
        );
        expect(typeof convDecoders.decodeDhcpv6FromBytes).toBe("function");
    });
});
