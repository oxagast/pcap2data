// Tests for the SNMP Conv decoder wiring. Mirrors the style of
// kerberos_conv_decoder.test.js: hand-build SNMP fixtures using simple
// ASN.1 helpers so the test exercises the same call shape the UI uses
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
        decodeSnmpFromBytes: convDecoders.decodeSnmpFromBytes,
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
        decodeSnmpFromBytes: context.decodeSnmpFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// ---- ASN.1 helpers --------------------------------------------------------

function asn1Length(length) {
    if (length < 0x80) return Uint8Array.from([length]);
    const bytes = [];
    let remaining = length;
    while (remaining > 0) {
        bytes.unshift(remaining & 0xff);
        remaining >>>= 8;
    }
    return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, value) {
    const valueBytes = value instanceof Uint8Array ? value : Buffer.from(value);
    return Uint8Array.from([tag, ...asn1Length(valueBytes.length), ...valueBytes]);
}

function integer(value) {
    if (value < 0 || value > 0x7fffffff) {
        throw new Error("test helper only supports small non-negative integers");
    }
    // Single-byte for <= 127; otherwise 4 bytes (sufficient for test data).
    if (value <= 0x7f) return tlv(0x02, Uint8Array.from([value]));
    const bytes = [
        (value >>> 24) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 8) & 0xff,
        value & 0xff,
    ];
    return tlv(0x02, Uint8Array.from(bytes));
}

function octetString(text) {
    return tlv(0x04, Buffer.from(text, "utf8"));
}

function oid(components) {
    // First two components encoded as 40 * first + second (RFC 2578 §3).
    const first = components[0] * 40 + components[1];
    const bytes = [first];
    for (let i = 2; i < components.length; i += 1) {
        let value = components[i];
        const stack = [];
        stack.push(value & 0x7f);
        value >>>= 7;
        while (value > 0) {
            stack.push((value & 0x7f) | 0x80);
            value >>>= 7;
        }
        stack.reverse().forEach((b) => bytes.push(b));
    }
    return tlv(0x06, Uint8Array.from(bytes));
}

function sequence(...children) {
    return tlv(0x30, Buffer.concat(children.map((c) => Buffer.from(c))));
}

// ---- Fixture builders -----------------------------------------------------

function buildGetRequest() {
    // OID for sysDescr.0: 1.3.6.1.2.1.1.1.0
    const varBind = sequence(
        oid([1, 3, 6, 1, 2, 1, 1, 1, 0]),
        tlv(0x05, Uint8Array.from([])), // NULL value
    );
    const varBindList = sequence(varBind);
    // GetRequest-PDU = [0] IMPLICIT SEQUENCE { request-id, error-status, error-index, var-bind-list }
    const pdu = tlv(0xa0, Buffer.concat([
        Buffer.from(integer(12345)),
        Buffer.from(integer(0)), // noError
        Buffer.from(integer(0)), // error-index
        Buffer.from(varBindList),
    ]));
    const message = sequence(
        integer(1), // SNMPv2c version
        octetString("public"),
        pdu,
    );
    return message;
}

function buildResponse() {
    // OID for sysUpTime.0: 1.3.6.1.2.1.1.3.0, value is TimeTicks (INTEGER 1234567).
    const varBind = sequence(
        oid([1, 3, 6, 1, 2, 1, 1, 3, 0]),
        integer(1234567),
    );
    const varBindList = sequence(varBind);
    const pdu = tlv(0xa2, Buffer.concat([
        Buffer.from(integer(99)), // request-id
        Buffer.from(integer(0)), // noError
        Buffer.from(integer(0)), // error-index
        Buffer.from(varBindList),
    ]));
    const message = sequence(
        integer(1), // SNMPv2c version
        octetString("private"),
        pdu,
    );
    return message;
}

// ---- Tests ---------------------------------------------------------------

describe("SNMP Conv decoder wiring", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const decoderFiles = [
        path.join(projectRoot, "src/ui/panels/data-tools-panel.js"),
        path.join(projectRoot, "src/ui/main-frontend.js"),
    ];

    test.each(decoderFiles)("decodes an SNMPv2c GetRequest from %s", (filePath) => {
        const { decodeSnmpFromBytes, autoDetectProtoFromBytes } =
            loadDecoderFunctions(filePath);
        const bytes = buildGetRequest();
        const decoded = decodeSnmpFromBytes(bytes);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "SNMP" })
        );
        expect(getFieldValue(decoded, "SNMP Version")).toBe("SNMPv2c");
        expect(getFieldValue(decoded, "Community")).toBe("public");
        expect(getFieldValue(decoded, "PDU Type")).toBe("GetRequest");
        expect(getFieldValue(decoded, "Request ID")).toBe("12345");
        expect(getFieldValue(decoded, "Error Status")).toBe("noError (0)");
        expect(getFieldValue(decoded, "Error Index")).toBe("0");
        // sysDescr.0 is a named MIB → label should appear in field name.
        const varBindField = (decoded.fields || []).find(
            (field) => typeof field.name === "string" && field.name.startsWith("VarBind 1"),
        );
        expect(varBindField).toBeDefined();
        expect(varBindField.value).toContain("sysDescr.0");
        expect(varBindField.value).toContain("1.3.6.1.2.1.1.1.0");
        const portHint = { decoder: "snmp" };
        expect(autoDetectProtoFromBytes(bytes, { portHint })).toBe("snmp");
    });

    test.each(decoderFiles)("decodes an SNMPv2c Response from %s", (filePath) => {
        const { decodeSnmpFromBytes } = loadDecoderFunctions(filePath);
        const bytes = buildResponse();
        const decoded = decodeSnmpFromBytes(bytes);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "SNMP" })
        );
        expect(getFieldValue(decoded, "PDU Type")).toBe("Response");
        expect(getFieldValue(decoded, "Community")).toBe("private");
        expect(getFieldValue(decoded, "Request ID")).toBe("99");
        const varBindField = (decoded.fields || []).find(
            (field) => typeof field.name === "string" && field.name.startsWith("VarBind 1"),
        );
        expect(varBindField).toBeDefined();
        expect(varBindField.value).toContain("sysUpTime.0");
        expect(varBindField.value).toContain("1234567");
    });

    test.each(decoderFiles)(
        "returns null for non-SNMP bytes from %s",
        (filePath) => {
            const { decodeSnmpFromBytes } = loadDecoderFunctions(filePath);
            expect(decodeSnmpFromBytes(null)).toBeNull();
            expect(decodeSnmpFromBytes(new Uint8Array(0))).toBeNull();
            // Random ASCII — won't start with the SEQUENCE tag (0x30) preceded
            // by an ASN.1 length header that decodes sensibly.
            const noise = Uint8Array.from(Buffer.from("hello, not snmp"));
            expect(decodeSnmpFromBytes(noise)).toBeNull();
        }
    );
});

describe("SNMP protocol/port hints", () => {
    const {
        PROTOCOL_DECODER_HINTS,
        PORT_DECODER_HINTS,
    } = require(
        path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/protocol-hints")
    );

    test("maps snmp protocol string to the snmp decoder", () => {
        expect(PROTOCOL_DECODER_HINTS.get("snmp")).toBe("snmp");
    });

    test("maps SNMP ports 161/162 to the snmp decoder", () => {
        expect(PORT_DECODER_HINTS.get(161)).toBe("snmp");
        expect(PORT_DECODER_HINTS.get(162)).toBe("snmp");
    });
});

describe("SNMP registry + dropdown wiring", () => {
    test("snmp is registered as a supported decoder protocol", () => {
        const { SUPPORTED_DECODER_PROTOS } = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/mime-maps")
        );
        expect(SUPPORTED_DECODER_PROTOS.has("snmp")).toBe(true);
    });

    test("decodeSnmpFromBytes is exported from the conv barrel", () => {
        const convDecoders = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv")
        );
        expect(typeof convDecoders.decodeSnmpFromBytes).toBe("function");
    });
});
