// Tests for the DHCP Conv decoder wiring. Mirrors the style of
// kerberos_conv_decoder.test.js: hand-build DHCP fixtures using simple
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
        decodeDhcpFromBytes: convDecoders.decodeDhcpFromBytes,
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
        decodeDhcpFromBytes: context.decodeDhcpFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// ---- DHCP fixture builders ------------------------------------------------

const DHCP_MAGIC_COOKIE = [0x63, 0x82, 0x53, 0x63];

function option(code, value) {
    const valueBytes = value instanceof Uint8Array ? value : Buffer.from(value);
    return Uint8Array.from([code, valueBytes.length, ...valueBytes]);
}

function buildDhcpDiscover() {
    // 240-byte fixed header fields + magic cookie + options.
    const header = new Uint8Array(240);
    header[0] = 1; // op: BOOTREQUEST
    header[1] = 1; // htype: Ethernet
    header[2] = 6; // hlen: 6
    header[3] = 0; // hops
    // xid: 0x12345678
    header[4] = 0x12;
    header[5] = 0x34;
    header[6] = 0x56;
    header[7] = 0x78;
    // secs, flags: leave 0
    // chaddr at offset 28, 16 bytes total; fill first 6 with MAC
    header[28] = 0xaa;
    header[29] = 0xbb;
    header[30] = 0xcc;
    header[31] = 0xdd;
    header[32] = 0xee;
    header[33] = 0xff;
    // Magic cookie at offset 236
    header[236] = DHCP_MAGIC_COOKIE[0];
    header[237] = DHCP_MAGIC_COOKIE[1];
    header[238] = DHCP_MAGIC_COOKIE[2];
    header[239] = DHCP_MAGIC_COOKIE[3];

    const options = Buffer.concat([
        Buffer.from(option(53, Uint8Array.from([1]))), // DHCP message type: DISCOVER
        Buffer.from(option(55, Uint8Array.from([1, 3, 6, 15]))), // parameter request: mask, router, DNS, domain-name
        Buffer.from(option(12, Buffer.from("client-host", "utf8"))), // host-name
        Buffer.from(option(255, Uint8Array.from([]))), // END
    ]);

    return Uint8Array.from([...header, ...options]);
}

function buildDhcpOffer() {
    const header = new Uint8Array(240);
    header[0] = 2; // op: BOOTREPLY
    header[1] = 1; // htype
    header[2] = 6; // hlen
    // yiaddr at offset 16: 192.168.1.100
    header[16] = 192;
    header[17] = 168;
    header[18] = 1;
    header[19] = 100;
    // siaddr at offset 20: 192.168.1.1
    header[20] = 192;
    header[21] = 168;
    header[22] = 1;
    header[23] = 1;
    header[28] = 0xaa;
    header[29] = 0xbb;
    header[30] = 0xcc;
    header[31] = 0xdd;
    header[32] = 0xee;
    header[33] = 0xff;
    header[236] = DHCP_MAGIC_COOKIE[0];
    header[237] = DHCP_MAGIC_COOKIE[1];
    header[238] = DHCP_MAGIC_COOKIE[2];
    header[239] = DHCP_MAGIC_COOKIE[3];

    const options = Buffer.concat([
        Buffer.from(option(53, Uint8Array.from([2]))), // DHCPOFFER
        Buffer.from(option(1, Uint8Array.from([255, 255, 255, 0]))), // subnet mask
        Buffer.from(option(3, Uint8Array.from([192, 168, 1, 1]))), // router
        Buffer.from(option(6, Uint8Array.from([8, 8, 8, 8, 1, 1, 1, 1]))), // DNS (2x 4-byte)
        Buffer.from(option(58, Uint8Array.from([0, 0, 0, 60]))), // T1
        Buffer.from(option(59, Uint8Array.from([0, 0, 1, 44]))), // T2
        Buffer.from(option(51, Uint8Array.from([0, 0, 0, 0x0e, 0x10]))), // IP lease time
        Buffer.from(option(255, Uint8Array.from([]))), // END
    ]);

    return Uint8Array.from([...header, ...options]);
}

// ---- Tests ---------------------------------------------------------------

describe("DHCP Conv decoder wiring", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const decoderFiles = [
        path.join(projectRoot, "src/ui/panels/data-tools-panel.js"),
        path.join(projectRoot, "src/ui/main-frontend.js"),
    ];

    test.each(decoderFiles)("decodes a DHCPDISCOVER from %s", (filePath) => {
        const { decodeDhcpFromBytes, autoDetectProtoFromBytes } =
            loadDecoderFunctions(filePath);
        const bytes = buildDhcpDiscover();
        const decoded = decodeDhcpFromBytes(bytes);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "DHCP" })
        );
        expect(getFieldValue(decoded, "Op")).toBe("BOOTREQUEST");
        expect(getFieldValue(decoded, "Hardware Type")).toBe("1");
        expect(getFieldValue(decoded, "Hardware Address Length")).toBe("6");
        expect(getFieldValue(decoded, "Transaction ID")).toBe("0x12345678");
        expect(getFieldValue(decoded, "Client MAC (chaddr)")).toBe(
            "aa:bb:cc:dd:ee:ff:00:00:00:00:00:00:00:00:00:00"
        );
        // Option 53: DHCP message type
        expect(getFieldValue(decoded, "dhcp-message-type")).toBe("DHCPDISCOVER");
        // Option 55: parameter request list
        expect(getFieldValue(decoded, "parameter-request-list")).toBe("1,3,6,15");
        // Option 12: host-name
        expect(getFieldValue(decoded, "host-name")).toBe("client-host");
        // Option 255: END marker
        expect(getFieldValue(decoded, "End")).toBe("yes");
        const portHint = { decoder: "dhcp" };
        expect(autoDetectProtoFromBytes(bytes, { portHint })).toBe("dhcp");
    });

    test.each(decoderFiles)("decodes a DHCPOFFER from %s", (filePath) => {
        const { decodeDhcpFromBytes } = loadDecoderFunctions(filePath);
        const bytes = buildDhcpOffer();
        const decoded = decodeDhcpFromBytes(bytes);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "DHCP" })
        );
        expect(getFieldValue(decoded, "Op")).toBe("BOOTREPLY");
        expect(getFieldValue(decoded, "Your IP (yiaddr)")).toBe("192.168.1.100");
        expect(getFieldValue(decoded, "Server IP (siaddr)")).toBe("192.168.1.1");
        expect(getFieldValue(decoded, "dhcp-message-type")).toBe("DHCPOFFER");
        expect(getFieldValue(decoded, "subnet-mask")).toBe("255.255.255.0");
        expect(getFieldValue(decoded, "router")).toBe("192.168.1.1");
        // DNS option 6 with > 4 bytes falls through to the generic hex
        // formatter; surface that as the expected rendered value here.
        expect(getFieldValue(decoded, "domain-name-servers")).toBe(
            "0808080801010101"
        );
    });

    test.each(decoderFiles)(
        "returns null when the magic cookie is missing from %s",
        (filePath) => {
            const { decodeDhcpFromBytes } = loadDecoderFunctions(filePath);
            const bytes = buildDhcpDiscover();
            // Corrupt the magic cookie so the decoder rejects the message.
            bytes[236] = 0x00;
            expect(decodeDhcpFromBytes(bytes)).toBeNull();
        }
    );

    test.each(decoderFiles)(
        "returns null for too-short input from %s",
        (filePath) => {
            const { decodeDhcpFromBytes } = loadDecoderFunctions(filePath);
            expect(decodeDhcpFromBytes(null)).toBeNull();
            expect(decodeDhcpFromBytes(new Uint8Array(0))).toBeNull();
            expect(decodeDhcpFromBytes(new Uint8Array(100))).toBeNull();
        }
    );
});

describe("DHCP protocol/port hints", () => {
    const {
        PROTOCOL_DECODER_HINTS,
        PORT_DECODER_HINTS,
    } = require(
        path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/protocol-hints")
    );

    test("maps dhcp protocol string to the dhcp decoder", () => {
        expect(PROTOCOL_DECODER_HINTS.get("dhcp")).toBe("dhcp");
    });

    test("maps DHCP ports 67/68 to the dhcp decoder", () => {
        expect(PORT_DECODER_HINTS.get(67)).toBe("dhcp");
        expect(PORT_DECODER_HINTS.get(68)).toBe("dhcp");
    });
});

describe("DHCP registry + dropdown wiring", () => {
    test("dhcp is registered as a supported decoder protocol", () => {
        const { SUPPORTED_DECODER_PROTOS } = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/mime-maps")
        );
        expect(SUPPORTED_DECODER_PROTOS.has("dhcp")).toBe(true);
    });

    test("decodeDhcpFromBytes is exported from the conv barrel", () => {
        const convDecoders = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv")
        );
        expect(typeof convDecoders.decodeDhcpFromBytes).toBe("function");
    });
});
