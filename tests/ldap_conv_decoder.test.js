// Tests for the LDAP Conv decoder. Mirrors the style of dns_conv_decoder.test.js
// and kerberos_conv_decoder.test.js: hand-build LDAP fixtures using
// lightweight BER helpers so the test exercises the same call shape the UI
// uses through autoDetectProtoFromBytes and the per-decoder switch in
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
        decodeLdapFromBytes: convDecoders.decodeLdapFromBytes,
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
        decodeLdapFromBytes: context.decodeLdapFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// ---- Minimal BER helpers for building LDAP fixtures ----------------------

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

const INTEGER = 0x02;
const OCTET_STRING = 0x04;
const SEQUENCE = 0x30;
const SET = 0x31;
const ENUMERATED = 0x0a;
const BOOLEAN = 0x01;

// Application tag numbers (RFC 4511 §4).
const APP_BIND_REQUEST = 0x60;
const APP_BIND_RESPONSE = 0x61;
const APP_UNBIND_REQUEST = 0x62;
const APP_SEARCH_REQUEST = 0x63;
const APP_SEARCH_RES_ENTRY = 0x64;
const APP_SEARCH_RES_DONE = 0x65;
const APP_MODIFY_REQUEST = 0x67;
const APP_MODIFY_RESPONSE = 0x68;
const APP_ADD_REQUEST = 0x69;
const APP_DEL_REQUEST = 0x6b;
const APP_MODDN_REQUEST = 0x6d;
const APP_COMPARE_REQUEST = 0x6f;
const APP_ABANDON_REQUEST = 0x71;
const APP_EXTENDED_REQUEST = 0x77;
const APP_EXTENDED_RESPONSE = 0x78;

function appTlv(tag, value) {
    return tlv(tag, value);
}

function ldapMessage(messageId, appTag, appValueBytes) {
    return tlv(SEQUENCE, Buffer.concat([
        tlv(INTEGER, Uint8Array.from([messageId])),
        appTlv(appTag, appValueBytes),
    ]));
}

// LDAPDN is just an OCTET STRING containing UTF-8 text.
function ldapDn(text) {
    return tlv(OCTET_STRING, Buffer.from(text, "utf8"));
}

// LDAPString is encoded as OCTET STRING (per RFC 4511 §4.1.2).
function ldapString(text) {
    return tlv(OCTET_STRING, Buffer.from(text, "utf8"));
}

function ldapResult(code, matchedDn, errorMessage) {
    return tlv(SEQUENCE, Buffer.concat([
        tlv(ENUMERATED, Uint8Array.from([code])),
        ldapDn(matchedDn || ""),
        ldapString(errorMessage || ""),
    ]));
}

// LDAPOID is an OCTET STRING containing the dotted-decimal OID.
function ldapOid(oidText) {
    return tlv(OCTET_STRING, Buffer.from(oidText, "utf8"));
}

// Context-specific constructed tag wraps the value.
function ctxConstructed(tagNumber, value) {
    return tlv(0xa0 | (tagNumber & 0x1f), value);
}

// Context-specific primitive tag wraps the value (used for filter choices).
function ctxPrimitive(tagNumber, value) {
    return tlv(0x80 | (tagNumber & 0x1f), value);
}

// Equality filter: ([3] SEQUENCE { attrDesc, assertionValue })
function eqFilter(attr, value) {
    return ctxPrimitive(3, tlv(SEQUENCE, Buffer.concat([
        tlv(OCTET_STRING, Buffer.from(attr, "utf8")),
        tlv(OCTET_STRING, Buffer.from(value, "utf8")),
    ])));
}

// Present filter: ([7] AttributeDescription)
function presentFilter(attr) {
    return ctxPrimitive(7, tlv(OCTET_STRING, Buffer.from(attr, "utf8")));
}

// AND/OR/NOT compound filter: ([0/1/2] SEQUENCE OF Filter)
function andFilter(children) {
    return ctxConstructed(0, tlv(SEQUENCE, Buffer.concat(children)));
}

// ---- Tests ---------------------------------------------------------------

describe("LDAP Conv decoder wiring", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const decoderFiles = [
        path.join(projectRoot, "src/ui/panels/data-tools-panel.js"),
        path.join(projectRoot, "src/ui/main-frontend.js"),
    ];

    test.each(decoderFiles)("decodes a BindRequest from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        // BindRequest SEQUENCE { version=3, name="cn=admin,dc=example,dc=com",
        //                          auth=[0] OCTET STRING "hunter2" }
        const auth = ctxPrimitive(0, Buffer.from("hunter2", "utf8"));
        const bindValue = Buffer.concat([
            tlv(INTEGER, Uint8Array.from([3])),
            ldapDn("cn=admin,dc=example,dc=com"),
            auth,
        ]);
        const bytes = ldapMessage(7, APP_BIND_REQUEST, bindValue);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 ID")).toBe("7");
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("BindRequest");
        expect(getFieldValue(decoded, "Message 1 Version")).toBe("3");
        expect(getFieldValue(decoded, "Message 1 Bind DN")).toBe(
            "cn=admin,dc=example,dc=com"
        );
        // We do not surface the cleartext password; we only say it's a simple
        // auth with N bytes so analysts see the bind type without leaking it
        // into copies of the rendered table.
        expect(getFieldValue(decoded, "Message 1 Auth")).toMatch(/^simple \(\d+ byte\(s\)\)$/);
        // Hex/ASCII sidecar rows exist for the Bind DN (decodeable text).
        expect(getFieldValue(decoded, "Message 1 Bind DN ↳ Hex")).toBe(
            "636e3d61646d696e2c64633d6578616d706c652c64633d636f6d"
        );
        expect(getFieldValue(decoded, "Message 1 Bind DN ↳ ASCII")).toBe(
            "cn=admin,dc=example,dc=com"
        );
    });

    test.each(decoderFiles)("decodes a BindResponse from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        const result = ldapResult(49, "", "Invalid credentials");
        const bytes = ldapMessage(7, APP_BIND_RESPONSE, result);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("BindResponse");
        expect(getFieldValue(decoded, "Message 1 Result Code")).toBe("49 (invalidCredentials)");
        expect(getFieldValue(decoded, "Message 1 Error Message")).toBe("Invalid credentials");
    });

    test.each(decoderFiles)("decodes a SearchRequest with a compound filter from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        // SearchRequest SEQUENCE { base, scope=2, deref=0, sizeLimit=0,
        // timeLimit=0, typesOnly=FALSE,
        // filter=(& (objectClass=person) (uid=alice)),
        // attrs SEQUENCE OF { cn, mail } }
        const filter = andFilter([
            eqFilter("objectClass", "person"),
            eqFilter("uid", "alice"),
        ]);
        const attrs = tlv(SEQUENCE, Buffer.concat([
            tlv(OCTET_STRING, Buffer.from("cn", "utf8")),
            tlv(OCTET_STRING, Buffer.from("mail", "utf8")),
        ]));
        const value = Buffer.concat([
            ldapDn("ou=users,dc=example,dc=com"),
            tlv(ENUMERATED, Uint8Array.from([2])),
            tlv(ENUMERATED, Uint8Array.from([0])),
            tlv(INTEGER, Uint8Array.from([0])),
            tlv(INTEGER, Uint8Array.from([0])),
            tlv(BOOLEAN, Uint8Array.from([0])),
            filter,
            attrs,
        ]);
        const bytes = ldapMessage(11, APP_SEARCH_REQUEST, value);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("SearchRequest");
        expect(getFieldValue(decoded, "Message 1 Base DN")).toBe("ou=users,dc=example,dc=com");
        expect(getFieldValue(decoded, "Message 1 Scope")).toBe("2 (wholeSubtree)");
        expect(getFieldValue(decoded, "Message 1 Deref Aliases")).toBe("0 (neverDerefAliases)");
        expect(getFieldValue(decoded, "Message 1 Filter")).toBe(
            "(&(objectClass=person)(uid=alice))"
        );
        expect(getFieldValue(decoded, "Message 1 Attributes")).toBe("2 (cn, mail)");
    });

    test.each(decoderFiles)("decodes a SearchResEntry from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        // PartialAttributeList: SEQUENCE OF { SEQUENCE { "cn", SET { "Alice" } } }
        const partial = tlv(SEQUENCE, Buffer.concat([
            tlv(SEQUENCE, Buffer.concat([
                tlv(OCTET_STRING, Buffer.from("cn", "utf8")),
                tlv(SET, Buffer.concat([
                    tlv(OCTET_STRING, Buffer.from("Alice", "utf8")),
                ])),
            ])),
        ]));
        const value = Buffer.concat([
            ldapDn("uid=alice,ou=users,dc=example,dc=com"),
            partial,
        ]);
        const bytes = ldapMessage(11, APP_SEARCH_RES_ENTRY, value);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("SearchResEntry");
        expect(getFieldValue(decoded, "Message 1 Object Name")).toBe(
            "uid=alice,ou=users,dc=example,dc=com"
        );
        expect(getFieldValue(decoded, "Message 1 Attributes")).toBe("cn=Alice");
    });

    test.each(decoderFiles)("decodes a SearchResDone from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        const result = ldapResult(0, "", "");
        const bytes = ldapMessage(11, APP_SEARCH_RES_DONE, result);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Result Code")).toBe("0 (success)");
    });

    test.each(decoderFiles)("decodes a ModifyRequest from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        // ModifyRequest SEQUENCE { object, changes SEQUENCE OF change } where
        // each change is SEQUENCE { operation ENUM, partialAttr }.
        const change = tlv(SEQUENCE, Buffer.concat([
            tlv(ENUMERATED, Uint8Array.from([2])), // replace
            tlv(SEQUENCE, Buffer.concat([
                tlv(OCTET_STRING, Buffer.from("mail", "utf8")),
                tlv(SET, Buffer.concat([
                    tlv(OCTET_STRING, Buffer.from("[email protected]", "utf8")),
                ])),
            ])),
        ]));
        const changes = tlv(SEQUENCE, Buffer.from(change));
        const value = Buffer.concat([
            ldapDn("uid=alice,ou=users,dc=example,dc=com"),
            changes,
        ]);
        const bytes = ldapMessage(13, APP_MODIFY_REQUEST, value);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("ModifyRequest");
        expect(getFieldValue(decoded, "Message 1 Object")).toBe(
            "uid=alice,ou=users,dc=example,dc=com"
        );
        expect(getFieldValue(decoded, "Message 1 Changes")).toBe("replace:mail");
    });

    test.each(decoderFiles)("decodes an AddRequest from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        // AddRequest SEQUENCE { entry, attrs SEQUENCE OF attr }.
        const attr = tlv(SEQUENCE, Buffer.concat([
            tlv(OCTET_STRING, Buffer.from("objectClass", "utf8")),
            tlv(SET, Buffer.concat([
                tlv(OCTET_STRING, Buffer.from("person", "utf8")),
            ])),
        ]));
        const attrs = tlv(SEQUENCE, Buffer.from(attr));
        const value = Buffer.concat([
            ldapDn("uid=bob,ou=users,dc=example,dc=com"),
            attrs,
        ]);
        const bytes = ldapMessage(15, APP_ADD_REQUEST, value);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("AddRequest");
        expect(getFieldValue(decoded, "Message 1 Entry")).toBe(
            "uid=bob,ou=users,dc=example,dc=com"
        );
        expect(getFieldValue(decoded, "Message 1 Attributes")).toBe("objectClass=person");
    });

    test.each(decoderFiles)("decodes a DelRequest from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        const bytes = ldapMessage(17, APP_DEL_REQUEST,
            ldapDn("uid=carol,ou=users,dc=example,dc=com"));
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("DelRequest");
        expect(getFieldValue(decoded, "Message 1 DN")).toBe("uid=carol,ou=users,dc=example,dc=com");
    });

    test.each(decoderFiles)("decodes a ModDNRequest with newSuperior from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        // ModDNRequest SEQUENCE { entry, newrdn, deleteoldrdn, [0] newsuperior }
        const value = Buffer.concat([
            ldapDn("uid=alice,ou=users,dc=example,dc=com"),
            ldapDn("uid=alicia"),
            tlv(BOOLEAN, Uint8Array.from([1])),
            ctxConstructed(0, ldapDn("ou=admins,dc=example,dc=com")),
        ]);
        const bytes = ldapMessage(19, APP_MODDN_REQUEST, value);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("ModDNRequest");
        expect(getFieldValue(decoded, "Message 1 Entry")).toBe(
            "uid=alice,ou=users,dc=example,dc=com"
        );
        expect(getFieldValue(decoded, "Message 1 New RDN")).toBe("uid=alicia");
        expect(getFieldValue(decoded, "Message 1 Delete Old RDN")).toBe("true");
        expect(getFieldValue(decoded, "Message 1 New Superior")).toBe("ou=admins,dc=example,dc=com");
    });

    test.each(decoderFiles)("decodes a CompareRequest from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        // CompareRequest SEQUENCE { entry, ava SEQUENCE { attr, value } }
        const ava = tlv(SEQUENCE, Buffer.concat([
            tlv(OCTET_STRING, Buffer.from("userPassword", "utf8")),
            tlv(OCTET_STRING, Buffer.from("secret", "utf8")),
        ]));
        const value = Buffer.concat([
            ldapDn("uid=alice,ou=users,dc=example,dc=com"),
            ava,
        ]);
        const bytes = ldapMessage(21, APP_COMPARE_REQUEST, value);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("CompareRequest");
        expect(getFieldValue(decoded, "Message 1 Entry")).toBe(
            "uid=alice,ou=users,dc=example,dc=com"
        );
        expect(getFieldValue(decoded, "Message 1 Assertion")).toBe("userPassword=secret");
    });

    test.each(decoderFiles)("decodes an AbandonRequest from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        // AbandonRequest [APPLICATION 17] holds just the message ID being abandoned.
        const bytes = ldapMessage(99, APP_ABANDON_REQUEST,
            tlv(INTEGER, Uint8Array.from([11])));
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("AbandonRequest");
        expect(getFieldValue(decoded, "Message 1 Abandoned Message ID")).toBe("11");
    });

    test.each(decoderFiles)("decodes an ExtendedRequest from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        // ExtendedRequest [APP 23] SEQUENCE { [0] requestName=1.3.6.1.4.1.4203.1.11.1,
        //                                    [1] requestValue = "0\x01\x01\x00\x00\x00" }
        const oidWrapped = ctxConstructed(0, ldapOid("1.3.6.1.4.1.4203.1.11.1"));
        const valueWrapped = ctxConstructed(1,
            tlv(OCTET_STRING, Buffer.from([0x30, 0x01, 0x01, 0x00, 0x00, 0x00])));
        const value = Buffer.concat([oidWrapped, valueWrapped]);
        const bytes = ldapMessage(23, APP_EXTENDED_REQUEST, value);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("ExtendedRequest");
        expect(getFieldValue(decoded, "Message 1 Request OID")).toBe("1.3.6.1.4.1.4203.1.11.1");
        expect(getFieldValue(decoded, "Message 1 Request Value")).toMatch(/^300101000000 \(\d+ byte\(s\)\)$/);
    });

    test.each(decoderFiles)("decodes an ExtendedResponse with responseName from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        // ExtendedResponse LDAPResult + [10] responseName + [11] responseValue
        const result = ldapResult(0, "", "");
        const oidWrapped = ctxConstructed(10,
            ldapOid("1.3.6.1.4.1.4203.1.11.3"));
        const valueWrapped = ctxConstructed(11,
            tlv(OCTET_STRING, Buffer.from([0x0a, 0x01, 0x00])));
        const value = Buffer.concat([result, oidWrapped, valueWrapped]);
        const bytes = ldapMessage(23, APP_EXTENDED_RESPONSE, value);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("ExtendedResponse");
        expect(getFieldValue(decoded, "Message 1 Result Code")).toBe("0 (success)");
        expect(getFieldValue(decoded, "Message 1 Response OID")).toBe("1.3.6.1.4.1.4203.1.11.3");
        expect(getFieldValue(decoded, "Message 1 Response Value")).toMatch(/^0a0100 \(\d+ byte\(s\)\)$/);
    });

    test.each(decoderFiles)("decodes a ModifyResponse with noSuchObject from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        const result = ldapResult(32, "ou=missing,dc=example,dc=com", "no such object");
        const bytes = ldapMessage(13, APP_MODIFY_RESPONSE, result);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("ModifyResponse");
        expect(getFieldValue(decoded, "Message 1 Result Code")).toBe("32 (noSuchObject)");
        expect(getFieldValue(decoded, "Message 1 Matched DN")).toBe(
            "ou=missing,dc=example,dc=com"
        );
        expect(getFieldValue(decoded, "Message 1 Error Message")).toBe("no such object");
    });

    test.each(decoderFiles)("decodes a present filter from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        const filter = presentFilter("objectClass");
        const value = Buffer.concat([
            ldapDn("dc=example,dc=com"),
            tlv(ENUMERATED, Uint8Array.from([0])),
            tlv(ENUMERATED, Uint8Array.from([0])),
            tlv(INTEGER, Uint8Array.from([0])),
            tlv(INTEGER, Uint8Array.from([0])),
            tlv(BOOLEAN, Uint8Array.from([0])),
            filter,
            tlv(SEQUENCE, Buffer.alloc(0)),
        ]);
        const bytes = ldapMessage(31, APP_SEARCH_REQUEST, value);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Filter")).toBe("(objectClass)");
    });

    test.each(decoderFiles)("decodes UnbindRequest with no body from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        // UnbindRequest [APP 2] has an empty SEQUENCE body.
        const bytes = ldapMessage(33, APP_UNBIND_REQUEST, Buffer.alloc(0));
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("UnbindRequest");
    });

    test.each(decoderFiles)("walks multiple LDAP messages in one stream from %s", (filePath) => {
        const { decodeLdapFromBytes } = loadDecoderFunctions(filePath);
        const bindValue = Buffer.concat([
            tlv(INTEGER, Uint8Array.from([3])),
            ldapDn(""),
            ctxPrimitive(0, Buffer.alloc(0)),
        ]);
        const bindReq = ldapMessage(7, APP_BIND_REQUEST, bindValue);
        const bindResp = ldapMessage(7, APP_BIND_RESPONSE,
            ldapResult(0, "", ""));
        const bytes = Buffer.concat([bindReq, bindResp]);
        const decoded = decodeLdapFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: "LDAP" }));
        expect(getFieldValue(decoded, "Message 1 ID")).toBe("7");
        expect(getFieldValue(decoded, "Message 1 Operation")).toBe("BindRequest");
        expect(getFieldValue(decoded, "Message 2 ID")).toBe("7");
        expect(getFieldValue(decoded, "Message 2 Operation")).toBe("BindResponse");
        expect(getFieldValue(decoded, "Message 2 Result Code")).toBe("0 (success)");
    });

    test.each(decoderFiles)("auto-detects LDAP from %s", (filePath) => {
        const { decodeLdapFromBytes, autoDetectProtoFromBytes } =
            loadDecoderFunctions(filePath);
        const bindValue = Buffer.concat([
            tlv(INTEGER, Uint8Array.from([3])),
            ldapDn(""),
            ctxPrimitive(0, Buffer.alloc(0)),
        ]);
        const bytes = ldapMessage(7, APP_BIND_REQUEST, bindValue);
        expect(decodeLdapFromBytes(bytes)).toEqual(
            expect.objectContaining({ protocol: "LDAP" })
        );
        const portHint = { decoder: "ldap" };
        expect(autoDetectProtoFromBytes(bytes, { portHint })).toBe("ldap");
    });

    test("returns null for non-LDAP bytes", () => {
        const projectRoot = path.resolve(__dirname, "..");
        const { decodeLdapFromBytes } = loadDecoderFunctions(
            path.join(projectRoot, "src/ui/main-frontend.js")
        );
        // Garbage payload that lacks a SEQUENCE header.
        expect(decodeLdapFromBytes(new Uint8Array([0, 1, 2, 3]))).toBeNull();
        // Sequence without an LDAP application tag.
        expect(decodeLdapFromBytes(new Uint8Array([0x30, 0x02, 0x02, 0x00]))).toBeNull();
    });
});
