// Tests for the Kerberos 5 Conv decoder wiring. Mirrors the style of
// sip_conv_decoder.test.js / smb_conv_decoder.test.js: use vm to load
// autoDetectProtoFromBytes from the panel file (or its legacy test
// fixture copy) so the test exercises the same call shape the UI uses.
//
// Fixture bytes are built by hand using simple ASN.1 helpers so we
// don't pull in a third-party ASN.1 library just to encode RFC 4120
// messages.

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
        decodeKerberosFromBytes: convDecoders.decodeKerberosFromBytes,
        normalizeSmbDecoderBytes: convDecoders.normalizeSmbDecoderBytes,
        findBytesSubsequence: convDecoders.findBytesSubsequence,
        parseSmbNtlmSecurityBuffer: convDecoders.parseSmbNtlmSecurityBuffer,
        decodeSmbTextBytes: convDecoders.decodeSmbTextBytes,
        bytesToHexLower: convDecoders.bytesToHexLower,
        autoDetectProtoFromBytes: convDecoders.autoDetectProtoFromBytes,
    };
    vm.createContext(context);
    vm.runInContext(extractedSource, context);
    return {
        decodeKerberosFromBytes: context.decodeKerberosFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// ---- Minimal ASN.1 helpers for building RFC 4120 fixtures ---------------

function tlv(tag, value) {
    const valueBytes = value instanceof Uint8Array ? value : Buffer.from(value);
    const length = valueBytes.length;
    const lengthBytes = [];
    if (length < 0x80) {
        lengthBytes.push(length);
    } else {
        const stack = [];
        let remaining = length;
        while (remaining > 0) {
            stack.unshift(remaining & 0xff);
            remaining >>>= 8;
        }
        lengthBytes.push(0x80 | stack.length);
        lengthBytes.push(...stack);
    }
    return Uint8Array.from([tag, ...lengthBytes, ...valueBytes]);
}

function seq(...children) {
    return tlv(0x30, Buffer.concat(children.map((c) => Buffer.from(c))));
}

function integer(value) {
    // Single-byte positive INTEGER for values that fit in one byte.
    if (value < 0 || value > 0x7f) {
        throw new Error("test helper only supports 0-127 integers");
    }
    return tlv(0x02, Uint8Array.from([value]));
}

function generalString(text) {
    return tlv(0x1b, Buffer.from(text, "utf8"));
}

function principalName(nameType, components) {
    return seq(
        integer(nameType),
        seq(...components.map((c) => generalString(c)))
    );
}

function context(tagNumber, value, constructed = false) {
    // Context-specific tag: 0x80 | tagNumber for primitive, or 0xa0 |
    // tagNumber for constructed. RFC 4120 wraps realm (GeneralString),
    // nonce (OCTET STRING), generalized times, etc. as primitive
    // context-specific tags, but ticket/enc-part/etc. as constructed.
    const constructedBit = constructed ? 0x20 : 0;
    return tlv(0x80 | constructedBit | tagNumber, value);
}

// BIT STRING with the given number of unused leading bits (0 for our tests).
function bitString(unusedBits, ...bytes) {
    return tlv(0x03, Uint8Array.from([unusedBits, ...bytes]));
}

function generalizedTime(text) {
    return tlv(0x18, Buffer.from(text, "utf8"));
}

// ---- Fixture builders -----------------------------------------------------

function buildAsReq() {
    // RFC 4120 §5.4.1: kdc-options [0], cname [1] OPTIONAL, realm [2],
    // sname [3], from [4] OPTIONAL, till [5], rtime [6] OPTIONAL,
    // nonce [7], etype [8] OPTIONAL.
    const realm = context(2, generalString("EXAMPLE.COM"), false);
    const sname = context(3, principalName(2, ["krbtgt", "EXAMPLE.COM"]), true);
    // KDCOptions: forwardable (bit 1) + renewable-ok (bit 27).
    // BIT STRING layout: 1 byte unused-bits + N bytes of payload. Bits are
    // big-endian; bit 0 is the high bit of byte 0.
    const kdcBytes = [
        0x40, // bit 1 (forwardable) — high bit of byte 0
        0x00,
        0x00,
        0x10, // bit 27 (renewable-ok) — bit 4 of byte 3
    ];
    const kdcOptions = context(0, bitString(0, ...kdcBytes), false);
    const till = context(5, generalizedTime("20300101000000Z"), false);
    const nonceBytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    const nonce = context(7, tlv(0x02, Uint8Array.from(nonceBytes)), false);
    const etypeList = context(8, seq(integer(23), integer(18), integer(17)), true);
    const body = seq(
        integer(5),
        integer(0x6a),
        kdcOptions,
        realm,
        sname,
        till,
        nonce,
        etypeList
    );
    return tlv(0x6a, body);
}

function buildAsRep() {
    // RFC 4120 §5.3.2: pvno [0], msg-type [1], padata [2] OPTIONAL,
    // crealm [3] OPTIONAL, cname [4], ticket [5], enc-part [6].
    const realm = context(3, generalString("EXAMPLE.COM"), false);
    const cname = context(4, principalName(1, ["alice"]), true);
    const ticketInner = seq(
        integer(5), // tkt-vno
        context(0, generalString("EXAMPLE.COM"), false),
        context(1, principalName(2, ["krbtgt", "EXAMPLE.COM"]), true)
    );
    const ticket = context(5, ticketInner, true);
    // EncryptedData SEQUENCE { [0] etype INTEGER, [2] cipher OCTET STRING }
    const encPart = seq(
        context(0, integer(18), false),
        context(2, tlv(0x04, Uint8Array.from([0xde, 0xad, 0xbe, 0xef])), false)
    );
    const encPartWrapped = context(6, encPart, true);
    const body = seq(integer(5), integer(0x6b), realm, cname, ticket, encPartWrapped);
    return tlv(0x6b, body);
}

function buildKrbError() {
    // RFC 4120 §5.9.1: pvno [0], msg-type [1], stime [2] OPTIONAL,
    // susec [3] OPTIONAL, error-code [4], crealm [5] OPTIONAL,
    // cname [6] OPTIONAL, e-text [9] OPTIONAL, e-data [10] OPTIONAL.
    const stime = context(2, generalizedTime("20300101000000Z"), false);
    const susec = context(3, integer(0), false);
    const errorCode = context(4, integer(6), false); // KDC_ERR_S_PRINCIPAL_UNKNOWN
    const cname = context(6, principalName(1, ["alice"]), true);
    const eText = context(9, generalString("Principal not known"), false);
    const body = seq(
        integer(5),
        integer(0x7e), // KRB-ERROR = APPLICATION 30
        stime,
        susec,
        errorCode,
        cname,
        eText
    );
    return tlv(0x7e, body);
}

// ---- Tests ---------------------------------------------------------------

describe("Kerberos 5 Conv decoder wiring", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const decoderFiles = [
        path.join(projectRoot, "src/ui/panels/data-tools-panel.js"),
        path.join(projectRoot, "src/ui/main-frontend.js"),
    ];

    test.each(decoderFiles)("decodes an AS-REQ from %s", (filePath) => {
        const { decodeKerberosFromBytes, autoDetectProtoFromBytes } =
            loadDecoderFunctions(filePath);
        const bytes = buildAsReq();
        expect(decodeKerberosFromBytes(bytes)).toEqual(
            expect.objectContaining({ protocol: "Kerberos" })
        );
        const decoded = decodeKerberosFromBytes(bytes);
        expect(getFieldValue(decoded, "Message 1 Message Type")).toBe("AS-REQ");
        expect(getFieldValue(decoded, "Message 1 Protocol Version")).toBe("5");
        expect(getFieldValue(decoded, "Message 1 Realm")).toBe("EXAMPLE.COM");
        expect(getFieldValue(decoded, "Message 1 Sname")).toBe(
            "2:krbtgt/EXAMPLE.COM"
        );
        expect(getFieldValue(decoded, "KDC Options")).toContain("forwardable");
        expect(getFieldValue(decoded, "KDC Options")).toContain("renewable-ok");
        expect(getFieldValue(decoded, "Till")).toBe("20300101000000Z");
        expect(getFieldValue(decoded, "Nonce")).toBe("0102030405060708");
        expect(getFieldValue(decoded, "Etype List")).toContain("23");
        // auto-detect must pick kerberos from port 88 hint or pure bytes.
        const portHint = { decoder: "kerberos" };
        expect(autoDetectProtoFromBytes(bytes, { portHint })).toBe("kerberos");
    });

    test.each(decoderFiles)("decodes an AS-REP from %s", (filePath) => {
        const { decodeKerberosFromBytes } = loadDecoderFunctions(filePath);
        const bytes = buildAsRep();
        const decoded = decodeKerberosFromBytes(bytes);
        expect(getFieldValue(decoded, "Message 1 Message Type")).toBe("AS-REP");
        expect(getFieldValue(decoded, "Message 1 Cname")).toBe("1:alice");
        expect(getFieldValue(decoded, "Message 1 Ticket tkt-vno")).toBe("5");
        expect(getFieldValue(decoded, "Message 1 Ticket Realm")).toBe(
            "EXAMPLE.COM"
        );
        expect(getFieldValue(decoded, "Encrypted Part Etype")).toContain(
            "0x12 (18)"
        );
        expect(getFieldValue(decoded, "Encrypted Part Cipher Preview")).toBe(
            "deadbeef"
        );
    });

    test.each(decoderFiles)("decodes a KRB-ERROR from %s", (filePath) => {
        const { decodeKerberosFromBytes } = loadDecoderFunctions(filePath);
        const bytes = buildKrbError();
        const decoded = decodeKerberosFromBytes(bytes);
        expect(getFieldValue(decoded, "Message 1 Message Type")).toBe(
            "KRB-ERROR"
        );
        expect(getFieldValue(decoded, "Error Code")).toBe("6");
        expect(getFieldValue(decoded, "Message 1 Error Text")).toBe(
            "Principal not known"
        );
    });

    test.each(decoderFiles)("strips a 4-byte TCP record length prefix from %s", (filePath) => {
        const { decodeKerberosFromBytes } = loadDecoderFunctions(filePath);
        const inner = buildAsReq();
        const recordLength = inner.length;
        const wrapped = Uint8Array.from([
            (recordLength >>> 24) & 0xff,
            (recordLength >>> 16) & 0xff,
            (recordLength >>> 8) & 0xff,
            recordLength & 0xff,
            ...inner,
        ]);
        const decoded = decodeKerberosFromBytes(wrapped);
        expect(decoded).toEqual(
            expect.objectContaining({ protocol: "Kerberos" })
        );
        expect(getFieldValue(decoded, "Message 1 Realm")).toBe("EXAMPLE.COM");
    });

    test.each(decoderFiles)("decodes a stream of multiple messages from %s", (filePath) => {
        const { decodeKerberosFromBytes } = loadDecoderFunctions(filePath);
        const asReq = buildAsReq();
        const asRep = buildAsRep();
        const stream = Buffer.concat([Buffer.from(asReq), Buffer.from(asRep)]);
        const decoded = decodeKerberosFromBytes(new Uint8Array(stream));
        expect(getFieldValue(decoded, "Message 1 Message Type")).toBe("AS-REQ");
        expect(getFieldValue(decoded, "Message 2 Message Type")).toBe("AS-REP");
    });

    test.each(decoderFiles)("returns null for non-Kerberos bytes from %s", (filePath) => {
        const { decodeKerberosFromBytes } = loadDecoderFunctions(filePath);
        expect(decodeKerberosFromBytes(null)).toBeNull();
        expect(decodeKerberosFromBytes(new Uint8Array(0))).toBeNull();
        // Random ASCII — no APPLICATION tag at byte 0.
        const noise = new Uint8Array(Buffer.from("not kerberos"));
        expect(decodeKerberosFromBytes(noise)).toBeNull();
    });
});

describe("Kerberos protocol/port hints", () => {
    const {
        PROTOCOL_DECODER_HINTS,
        PORT_DECODER_HINTS,
    } = require(
        path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/protocol-hints")
    );

    test("maps krb5 protocol strings to the kerberos decoder", () => {
        expect(PROTOCOL_DECODER_HINTS.get("kerberos")).toBe("kerberos");
        expect(PROTOCOL_DECODER_HINTS.get("krb5")).toBe("kerberos");
        expect(PROTOCOL_DECODER_HINTS.get("krb5sec")).toBe("kerberos");
    });

    test("maps krb5 ports 88/464/750 to the kerberos decoder", () => {
        expect(PORT_DECODER_HINTS.get(88)).toBe("kerberos");
        expect(PORT_DECODER_HINTS.get(464)).toBe("kerberos");
        expect(PORT_DECODER_HINTS.get(750)).toBe("kerberos");
    });
});

describe("Kerberos registry + dropdown wiring", () => {
    test("kerberos is registered as a supported decoder protocol", () => {
        const { SUPPORTED_DECODER_PROTOS } = require(
            path.join(path.resolve(__dirname, ".."), "src/ui/decoders/conv/mime-maps")
        );
        expect(SUPPORTED_DECODER_PROTOS.has("kerberos")).toBe(true);
    });

    test("src/index.html dropdown contains a kerberos option", () => {
        const html = fs.readFileSync(
            path.join(path.resolve(__dirname, ".."), "src/index.html"),
            "utf8"
        );
        expect(html).toMatch(/value="kerberos"[^>]*>\s*Kerberos/);
    });

    test("data-tools-panel.js wires kerberos in the runProtoDecoder switch", () => {
        const source = fs.readFileSync(
            path.join(path.resolve(__dirname, ".."), "src/ui/panels/data-tools-panel.js"),
            "utf8"
        );
        expect(source).toMatch(/case\s+"kerberos":/);
        expect(source).toMatch(/decodeKerberosFromBytes\(bytes\)/);
    });
});
