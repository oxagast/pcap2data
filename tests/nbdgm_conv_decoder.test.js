// Tests for the NetBIOS-DGM (NetBIOS Datagram Service) Conv decoder
// wiring. Mirrors dns_conv_decoder.test.js: hand-build NetBIOS-DGM
// fixtures using simple byte helpers so the test exercises the same
// call shape the UI uses through autoDetectProtoFromBytes and the
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
        decodeLlmnrFromBytes: alwaysNull,
        decodeNbnsFromBytes: alwaysNull,
        decodeNbdgmFromBytes: convDecoders.decodeNbdgmFromBytes,
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
        decodeNbdgmFromBytes: context.decodeNbdgmFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// ---- NetBIOS-DGM fixture helpers -----------------------------------------

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

// Build a 34-byte NetBIOS name block (1-byte length + 32-byte body + 1-byte
// scope byte) that is what the NetBIOS-DGM message carries inline for both
// the source and destination name fields.
function buildNameBlock(name) {
    const encoded = encodeNetbiosName(name);
    // The NetBIOS-DGM wire format uses a full 34-byte block; the
    // encodeNetbiosName helper emits length + 32 bytes = 33 bytes, so
    // append the trailing scope byte to round it out.
    return Uint8Array.from([...encoded, 0x00]);
}

function buildBroadcastDatagram() {
    // 8-byte NetBIOS session header: type=0x11 (broadcast), length=0x4d.
    // Then a 1-byte MSG_TYPE=0x11 (broadcast), 1-byte FLAGS=0x05 (first
    // fragment + B-node), 2-byte DGM_ID=0x0001, 34-byte source name
    // (WORKSTATION), 34-byte destination name (*SMBSERVER), 1-byte
    // data ("X").
    const session = Uint8Array.from([
        0x11, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    const dgmHeader = Uint8Array.from([
        0x11, // MSG_TYPE = broadcast
        0x03, // FLAGS = first + more fragment + B-node (node type 0)
        0x00, 0x01, // DGM_ID
    ]);
    const source = buildNameBlock("WORKSTATION");
    const dest = buildNameBlock("*SMBSERVER");
    const data = Uint8Array.from([0x58]); // 'X'
    return Uint8Array.from([
        ...session,
        ...dgmHeader,
        ...source,
        ...dest,
        ...data,
    ]);
}

function buildUnicastDatagram() {
    const session = Uint8Array.from([
        0x10, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    const dgmHeader = Uint8Array.from([
        0x10, // MSG_TYPE = unicast datagram
        0x06, // FLAGS = only fragment (FIRST=1, MORE=0) + P-node
        0x00, 0x02, // DGM_ID
    ]);
    const source = buildNameBlock("SENDER");
    const dest = buildNameBlock("RECEIVER");
    const data = Uint8Array.from([0x68, 0x65, 0x6c, 0x6c, 0x6f]); // "hello"
    return Uint8Array.from([
        ...session,
        ...dgmHeader,
        ...source,
        ...dest,
        ...data,
    ]);
}

// ---- Tests ---------------------------------------------------------------

describe("NetBIOS-DGM Conv decoder wiring", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const decoderFiles = [
        path.join(projectRoot, "src/ui/panels/data-tools-panel.js"),
        path.join(projectRoot, "src/ui/main-frontend.js"),
    ];

    test.each(decoderFiles)(
        "decodes a NetBIOS-DGM broadcast datagram from %s",
        (filePath) => {
            const { decodeNbdgmFromBytes, autoDetectProtoFromBytes } =
                loadDecoderFunctions(filePath);
            const bytes = buildBroadcastDatagram();
            const decoded = decodeNbdgmFromBytes(bytes);
            expect(decoded).toEqual(
                expect.objectContaining({ protocol: "NetBIOS-DGM" })
            );
            expect(getFieldValue(decoded, "Message Type")).toBe(
                "Datagram Broadcast"
            );
            expect(getFieldValue(decoded, "Fragment")).toBe(
                "First of Fragmented Group"
            );
            expect(getFieldValue(decoded, "Source Node Type")).toBe("B-node");
            expect(getFieldValue(decoded, "Datagram ID")).toBe("0x0001");
            expect(getFieldValue(decoded, "Source Name")).toBe("WORKSTATION");
            expect(getFieldValue(decoded, "Destination Name")).toBe(
                "*SMBSERVER"
            );
            const portHint = { decoder: "nbdgm" };
            expect(autoDetectProtoFromBytes(bytes, { portHint })).toBe(
                "nbdgm"
            );
        }
    );

    test.each(decoderFiles)(
        "decodes a NetBIOS-DGM unicast datagram from %s",
        (filePath) => {
            const { decodeNbdgmFromBytes } = loadDecoderFunctions(filePath);
            const bytes = buildUnicastDatagram();
            const decoded = decodeNbdgmFromBytes(bytes);
            expect(decoded).toEqual(
                expect.objectContaining({ protocol: "NetBIOS-DGM" })
            );
            expect(getFieldValue(decoded, "Message Type")).toBe("Datagram");
            expect(getFieldValue(decoded, "Fragment")).toBe("Only Datagram");
            expect(getFieldValue(decoded, "Source Node Type")).toBe("P-node");
            expect(getFieldValue(decoded, "Datagram ID")).toBe("0x0002");
            expect(getFieldValue(decoded, "Source Name")).toBe("SENDER");
            expect(getFieldValue(decoded, "Destination Name")).toBe("RECEIVER");
            expect(getFieldValue(decoded, "Data Length")).toBe("5");
            expect(getFieldValue(decoded, "Data Preview (text)")).toContain(
                "hello"
            );
        }
    );

    test.each(decoderFiles)(
        "returns null for invalid bytes from %s",
        (filePath) => {
            const { decodeNbdgmFromBytes } = loadDecoderFunctions(filePath);
            expect(decodeNbdgmFromBytes(null)).toBeNull();
            expect(decodeNbdgmFromBytes(new Uint8Array(0))).toBeNull();
            // Anything < 80 bytes cannot be a valid datagram.
            const short = Uint8Array.from(
                Array.from({ length: 50 }, () => 0x10)
            );
            expect(decodeNbdgmFromBytes(short)).toBeNull();
            // Type byte 0x00 is not a NetBIOS-DGM message type.
            const wrong = Uint8Array.from(
                Array.from({ length: 100 }, () => 0x00)
            );
            expect(decodeNbdgmFromBytes(wrong)).toBeNull();
        }
    );
});

describe("NetBIOS-DGM protocol/port hints", () => {
    const {
        PROTOCOL_DECODER_HINTS,
        PORT_DECODER_HINTS,
    } = require(
        path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/protocol-hints")
    );

    test("maps nbdgm + aliases to the nbdgm decoder", () => {
        expect(PROTOCOL_DECODER_HINTS.get("nbdgm")).toBe("nbdgm");
        expect(PROTOCOL_DECODER_HINTS.get("netbios-dgm")).toBe("nbdgm");
        expect(PROTOCOL_DECODER_HINTS.get("netbios-datagram-service")).toBe(
            "nbdgm"
        );
    });

    test("maps port 138 to the nbdgm decoder", () => {
        expect(PORT_DECODER_HINTS.get(138)).toBe("nbdgm");
    });
});

describe("NetBIOS-DGM registry + dropdown wiring", () => {
    test("nbdgm is registered as a supported decoder protocol", () => {
        const { SUPPORTED_DECODER_PROTOS } = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/mime-maps")
        );
        expect(SUPPORTED_DECODER_PROTOS.has("nbdgm")).toBe(true);
    });

    test("decodeNbdgmFromBytes is exported from the conv barrel", () => {
        const convDecoders = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv")
        );
        expect(typeof convDecoders.decodeNbdgmFromBytes).toBe("function");
    });
});
