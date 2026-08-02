// LDAP Conv decoder: walks a stream of ASN.1 SEQUENCE-wrapped LDAP messages
// (RFC 4511) and surfaces operation-specific fields for each one.
//
// Wire framing:
//   SEQUENCE { messageID INTEGER, protocolOp APPLICATION <tag>, controls ... }
//
// Per-operation structure (RFC 4511 §4.x):
//   BindRequest     [APPLICATION 0]  : version INTEGER, name LDAPDN, auth AuthenticationChoice
//   BindResponse    [APPLICATION 1]  : ENUMERATED resultCode, matchedDN, errorMessage, [7] serverSaslCreds
//   UnbindRequest   [APPLICATION 2]  : (no payload)
//   SearchRequest   [APPLICATION 3]  : baseDN, scope ENUM, derefAliases ENUM, sizeLimit INTEGER, timeLimit INTEGER, typesOnly BOOLEAN, filter Filter, attrs SEQUENCE
//   SearchResEntry  [APPLICATION 4]  : objectName LDAPDN, attributes PartialAttributeList
//   SearchResDone   [APPLICATION 5]  : same shape as BindResponse
//   SearchResRef    [APPLICATION 6]  : SEQUENCE OF LDAPURL
//   ModifyRequest   [APPLICATION 7]  : object LDAPDN, changes SEQUENCE OF { operation ENUM, partialAttr }
//   ModifyResponse  [APPLICATION 8]  : same shape as BindResponse
//   AddRequest      [APPLICATION 9]  : entry LDAPDN, attributes AttributeList
//   AddResponse     [APPLICATION 10] : same shape as BindResponse
//   DelRequest      [APPLICATION 11] : dn LDAPDN
//   DelResponse     [APPLICATION 12] : same shape as BindResponse
//   ModDNRequest    [APPLICATION 13] : entry, newrdn, deleteoldrdn BOOLEAN, [0] newsuperior OPTIONAL
//   ModDNResponse   [APPLICATION 14] : same shape as BindResponse
//   CompareRequest  [APPLICATION 15] : entry LDAPDN, ava SEQUENCE { AttributeDescription, AssertionValue }
//   CompareResponse [APPLICATION 16] : same shape as BindResponse
//   AbandonRequest  [APPLICATION 17] : messageID INTEGER
//   ExtendedRequest [APPLICATION 23] : [0] requestName LDAPOID, [1] requestValue OCTET STRING OPTIONAL
//   ExtendedResponse[APPLICATION 24]: same shape as BindResponse with [10] responseName, [11] responseValue
//   IntermediateResponse [APP 25]    : [0] responseName, [1] responseValue
//
// The decoder surfaces a compact, human-readable field set per message:
// Message N ID, Operation, plus operation-specific rows (BindDN, Auth,
// Result, Scope/Filter/BaseDN for searches, etc.). Each byte-backed row also
// shows a small companion hex/ASCII view of just the bytes backing that row,
// so analysts can confirm case-sensitive values, non-printable characters,
// and ASN.1 boundary interpretation.
//
// IMPORTANT: LDAP wire format uses IMPLICIT tagging for the per-operation
// SEQUENCE wrapper. The APPLICATION tag (0x60..0x79) is followed directly by
// the SEQUENCE contents — no inner 0x30 SEQUENCE tag is present on the wire.
// Renderers below therefore parse fields directly from the application tag's
// value bytes; we never expect an inner 0x30.

const { parseAsn1Length, getAsn1TagDescription } = require("./asn1");
const { bytesToHexLower } = require("./smb-helpers");

const MAX_LDAP_MESSAGES = 100;
const LDAP_VALUE_LIMIT = 220;
const LDAP_ATTR_LIMIT = 6;
const LDAP_FILTER_DEPTH_LIMIT = 8;
// Cap companion hex/ASCII so very long DNs / filters don't blow up the UI.
const HEX_COMPANION_LIMIT = 64;

// LDAP application tags (RFC 4511 §4). Listed in canonical wire order so we
// can format unknown ops with their hex tag for clarity.
const LDAP_OPERATIONS = {
    0x60: "BindRequest",
    0x61: "BindResponse",
    0x62: "UnbindRequest",
    0x63: "SearchRequest",
    0x64: "SearchResEntry",
    0x65: "SearchResDone",
    0x66: "SearchResRef",
    0x67: "ModifyRequest",
    0x68: "ModifyResponse",
    0x69: "AddRequest",
    0x6a: "AddResponse",
    0x6b: "DelRequest",
    0x6c: "DelResponse",
    0x6d: "ModDNRequest",
    0x6e: "ModDNResponse",
    0x6f: "CompareRequest",
    0x70: "CompareResponse",
    0x71: "AbandonRequest",
    0x77: "ExtendedRequest",
    0x78: "ExtendedResponse",
    0x79: "IntermediateResponse",
};

// LDAP result codes (RFC 4511 §4.1.9 + RFC 4511 §4.1.10).
const LDAP_RESULT_CODES = {
    0: "success",
    1: "operationsError",
    2: "protocolError",
    3: "timeLimitExceeded",
    4: "sizeLimitExceeded",
    5: "compareFalse",
    6: "compareTrue",
    7: "authMethodNotSupported",
    8: "strongerAuthRequired",
    10: "referral",
    11: "adminLimitExceeded",
    12: "unavailableCriticalExtension",
    13: "confidentialityRequired",
    14: "saslBindInProgress",
    16: "noSuchAttribute",
    17: "undefinedAttributeType",
    18: "inappropriateMatching",
    19: "constraintViolation",
    20: "attributeOrValueExists",
    21: "invalidAttributeSyntax",
    32: "noSuchObject",
    33: "aliasProblem",
    34: "invalidDNSyntax",
    36: "aliasDereferencingProblem",
    48: "inappropriateAuthentication",
    49: "invalidCredentials",
    50: "insufficientAccessRights",
    51: "busy",
    52: "unavailable",
    53: "unwillingToPerform",
    54: "loopDetect",
    64: "namingViolation",
    65: "objectClassViolation",
    66: "notAllowedOnNonLeaf",
    67: "notAllowedOnRDN",
    68: "entryAlreadyExists",
    69: "objectClassModsProhibited",
    80: "other",
};

// Search scope enum (RFC 4511 §4.5.1).
const LDAP_SCOPE_NAMES = {
    0: "baseObject",
    1: "singleLevel",
    2: "wholeSubtree",
};

// DerefAliases enum (RFC 4511 §4.6).
const LDAP_DEREF_NAMES = {
    0: "neverDerefAliases",
    1: "derefInSearching",
    2: "derefFindingBaseObj",
    3: "derefAlways",
};

// Modify-operation enum (RFC 4511 §4.6).
const LDAP_MODIFY_OPS = {
    0: "add",
    1: "delete",
    2: "replace",
};

// Filter choice tag numbers (RFC 4511 §4.5.1.7). Each value is the
// context-specific tag that wraps either a leaf `AttributeValueAssertion` or
// a SEQUENCE OF filter children.
const LDAP_FILTER_TAGS = {
    0: { name: "and", constructed: true },
    1: { name: "or", constructed: true },
    2: { name: "not", constructed: true },
    3: { name: "equalityMatch", constructed: false },
    4: { name: "substrings", constructed: true },
    5: { name: "greaterOrEqual", constructed: false },
    6: { name: "lessOrEqual", constructed: false },
    7: { name: "present", constructed: false },
    8: { name: "approxMatch", constructed: false },
    9: { name: "extensibleMatch", constructed: true },
};

// Substring choice tags inside SubstringFilter (RFC 4511 §4.5.1.7.4).
const LDAP_SUBSTRING_TAGS = {
    0: "initial",
    1: "any",
    2: "final",
};

// AuthenticationChoice tag numbers (RFC 4511 §4.2).
const LDAP_AUTH_TAGS = {
    0: "simple",
    3: "sasl",
};

// Push a string value with a length cap; truncate with an ellipsis when
// exceeded. Used for friendly human-readable summaries.
function pushTruncated(fields, name, value, limit) {
    if (typeof value !== "string" || !value) return;
    const trimmed = value.length > limit ? `${value.slice(0, limit)}…` : value;
    fields.push({ name, value: trimmed });
}

// Decode an OCTET STRING / LDAPString as printable text. Non-printable
// bytes are dropped. Used for DN, error message, and similar fields.
function decodeAsn1Text(bytes, valueStart, valueEnd) {
    if (valueEnd <= valueStart) return "";
    try {
        return new TextDecoder("utf-8", { fatal: false })
            .decode(bytes.slice(valueStart, valueEnd))
            .replace(/[^\x20-\x7e]/g, "");
    } catch {
        return "";
    }
}

// Short hex preview used inline (no truncation suffix). Returns "" on
// invalid ranges.
function hexPreview(bytes, valueStart, valueEnd, byteLimit) {
    if (!(bytes instanceof Uint8Array)) return "";
    if (valueEnd <= valueStart) return "";
    const cap = byteLimit || 24;
    const end = Math.min(valueEnd, valueStart + cap);
    return bytesToHexLower(bytes.slice(valueStart, end));
}

// Push a friendly value followed by two companion rows showing the
// underlying bytes for just that range:
//
//   "Bind DN"            "cn=admin,dc=example,dc=com"
//   "Bind DN ↳ Hex"      "63 6e 3d 61 64 6d 69 6e …(36 total bytes)"
//   "Bind DN ↳ ASCII"    "cn=admin,dc=example,dc=com"
//
// The companion rows are deliberately scoped to the bytes backing the row
// (e.g. just the DN), not the whole LDAP message. For long fields we
// truncate to `maxBytes` and append a suffix indicating the original length.
function pushTextWithBytes(
    fields,
    label,
    textValue,
    bytes,
    valueStart,
    valueEnd,
    maxBytes,
) {
    fields.push({ name: label, value: textValue });
    pushBytesOnly(fields, label, bytes, valueStart, valueEnd, maxBytes);
}

// Push just the hex + ASCII companion rows for a byte range, without the
// friendly-value row. Useful for things like passwords or arbitrary blobs
// where there's no printable friendly value to show.
function pushBytesOnly(fields, label, bytes, valueStart, valueEnd, maxBytes) {
    if (!(bytes instanceof Uint8Array)) return;
    if (valueEnd <= valueStart) return;
    const cap = maxBytes || HEX_COMPANION_LIMIT;
    const sliceEnd = Math.min(valueEnd, valueStart + cap);
    const totalBytes = valueEnd - valueStart;
    const truncatedSuffix =
        totalBytes > cap ? ` …(${totalBytes} total bytes)` : "";

    const hexStr = bytesToHexLower(bytes.slice(valueStart, sliceEnd));
    fields.push({
        name: `${label} ↳ Hex`,
        value: `${hexStr}${truncatedSuffix}`,
    });

    let asciiStr = "";
    for (let cursor = valueStart; cursor < sliceEnd; cursor += 1) {
        const byte = bytes[cursor];
        asciiStr += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
    }
    fields.push({
        name: `${label} ↳ ASCII`,
        value: `${asciiStr}${truncatedSuffix}`,
    });
}

// Low-level TLV reader. Reads a tag + length at `startIndex` and returns a
// record describing the parsed element, or null if it can't be parsed.
//
// `tagInfo` is the parsed tag byte so callers can route on constructed /
// class / tag-number without re-parsing.
function readTlv(bytes, startIndex, endIndex) {
    if (!(bytes instanceof Uint8Array)) return null;
    if (startIndex >= endIndex) return null;
    const tagByte = bytes[startIndex];
    const lengthInfo = parseAsn1Length(bytes, startIndex + 1, endIndex);
    if (!lengthInfo) return null;
    const valueStart = lengthInfo.nextIndex;
    const valueEnd = valueStart + lengthInfo.length;
    if (valueEnd > endIndex) return null;
    return {
        tag: tagByte,
        tagInfo: getAsn1TagDescription(tagByte),
        length: lengthInfo.length,
        headerEnd: valueStart,
        valueStart,
        valueEnd,
    };
}

// Read an INTEGER or ENUMERATED (tag 0x02 or 0x0a) at `startIndex`.
// Returns { value, tlv } on success or null if the bytes don't look like
// either type. ENUMERATED is treated identically to INTEGER for value
// purposes; LDAP uses it for result codes, search scope, deref, etc.
function readInteger(bytes, startIndex, endIndex) {
    const tlv = readTlv(bytes, startIndex, endIndex);
    if (!tlv || (tlv.tag !== 0x02 && tlv.tag !== 0x0a) || tlv.length < 1) {
        return null;
    }
    let value = 0;
    for (let offset = tlv.valueStart; offset < tlv.valueEnd; offset += 1) {
        value = (value << 8) | bytes[offset];
    }
    // If the high bit is set, sign-extend to a negative JS number. LDAP
    // integers are non-negative in practice but be safe.
    if (bytes[tlv.valueStart] & 0x80) {
        value -= 1 << tlv.length * 8;
    }
    return { value, tlv };
}

// Read an LDAP DN: a single OCTET STRING (tag 0x04) holding the UTF-8
// distinguished name. Returns { text, tlv } or null.
function readLdapDn(bytes, startIndex, endIndex) {
    const tlv = readTlv(bytes, startIndex, endIndex);
    if (!tlv || tlv.tag !== 0x04) return null;
    return {
        text: decodeAsn1Text(bytes, tlv.valueStart, tlv.valueEnd),
        tlv,
    };
}

// Read an LDAPOID at `startIndex`. Handles four wire shapes we see in
// practice:
//   - LDAPOID (tag 0x06) holding multi-byte arc encodings (RFC 4511)
//   - OCTET STRING (tag 0x04) holding dotted-decimal text (some impls)
//   - A context-specific wrapper ([0], [10]) around either of the above
//
// Returns { text, tlv } or null. `tlv` is the outermost parsed TLV so
// callers can advance past it.
function readOid(bytes, startIndex, endIndex) {
    const outer = readTlv(bytes, startIndex, endIndex);
    if (!outer) return null;

    // If the outer is a context-specific tag (or anything that's not 0x06
    // and not 0x04), peek inside for the actual OID-bearing TLV.
    let oidTlv = outer;
    if (outer.tag !== 0x06 && outer.tag !== 0x04) {
        const inner = readTlv(bytes, outer.valueStart, outer.valueEnd);
        if (!inner) return null;
        oidTlv = inner;
    }
    if (oidTlv.tag === 0x06) {
        return decodeOidArcs(bytes, oidTlv.valueStart, oidTlv.valueEnd, outer);
    }
    if (oidTlv.tag === 0x04) {
        const text = decodeAsn1Text(
            bytes,
            oidTlv.valueStart,
            oidTlv.valueEnd,
        );
        if (!text) return null;
        return { text, tlv: outer };
    }
    return null;
}

// Decode the multi-byte arc encoding per ITU-T X.690 into dotted notation.
// `outerTlv` is the TLV the caller should advance past; it's returned
// alongside the dotted string.
function decodeOidArcs(bytes, valueStart, valueEnd, outerTlv) {
    if (valueEnd <= valueStart) return null;
    const arcs = [];
    let value = 0;
    for (let offset = valueStart; offset < valueEnd; offset += 1) {
        value = (value << 7) | (bytes[offset] & 0x7f);
        if ((bytes[offset] & 0x80) === 0) {
            arcs.push(value);
            value = 0;
        }
    }
    if (arcs.length === 0) return null;
    // First two arcs share the first byte.
    const firstByte = arcs.shift();
    const firstArc = Math.floor(firstByte / 40);
    const secondArc = firstByte % 40;
    const text = [firstArc, secondArc, ...arcs].join(".");
    return { text, tlv: outerTlv };
}

// Format a numeric LDAP result code as "<number> (<name>)".
function formatResultCode(code) {
    const name = LDAP_RESULT_CODES[code];
    return name ? `${code} (${name})` : String(code);
}

// Read a SearchFilter (RFC 4511 §4.5.1.7) starting at `startIndex`.
// Recurses into nested AND/OR/NOT/extensibleMatch up to LDAP_FILTER_DEPTH_LIMIT.
//
// Returns { text, tlv, endIndex } where tlv is the outer context-specific
// filter tag TLV and endIndex is the cursor position after the filter.
function readFilter(bytes, startIndex, endIndex, depth) {
    if (depth > LDAP_FILTER_DEPTH_LIMIT) return null;
    const outer = readTlv(bytes, startIndex, endIndex);
    if (!outer) return null;
    const tagNumber = outer.tagInfo.tagNumber;
    const info = LDAP_FILTER_TAGS[tagNumber];
    if (!info) return null;

    if (info.name === "present") {
        // present takes an AttributeDescription (OCTET STRING) directly.
        // Per RFC 4511 §4.5.1.7.6 the canonical rendering is "(attr)"
        // without an "=*" suffix.
        const attrTlv = readTlv(bytes, outer.valueStart, outer.valueEnd);
        if (!attrTlv || attrTlv.tag !== 0x04) return null;
        return {
            text: `(${decodeAsn1Text(bytes, attrTlv.valueStart, attrTlv.valueEnd)})`,
            tlv: outer,
            endIndex: outer.valueEnd,
        };
    }

    if (info.constructed) {
        // AND / OR / NOT / substrings / extensibleMatch
        if (info.name === "and" || info.name === "or") {
            // The wire format wraps the SEQUENCE OF Filter inside an
            // explicit SEQUENCE tag (constructed bit set on the context-
            // specific tag means the value is *another* constructed TLV).
            const inner = readTlv(bytes, outer.valueStart, outer.valueEnd);
            if (!inner) return null;
            const partStart =
                inner.tag === 0x30 ? inner.valueStart : outer.valueStart;
            const partEnd =
                inner.tag === 0x30 ? inner.valueEnd : outer.valueEnd;
            const parts = [];
            let cursor = partStart;
            while (cursor < partEnd) {
                const child = readFilter(bytes, cursor, partEnd, depth + 1);
                if (!child) break;
                parts.push(child.text);
                cursor = child.endIndex;
            }
            const joiner = info.name === "and" ? "&" : "|";
            const joined = parts.join("");
            const text = `(${joiner}${joined})`;
            return { text, tlv: outer, endIndex: outer.valueEnd };
        }
        if (info.name === "not") {
            const child = readFilter(bytes, outer.valueStart, outer.valueEnd, depth + 1);
            if (!child) return null;
            return {
                text: `(!${child.text})`,
                tlv: outer,
                endIndex: outer.valueEnd,
            };
        }
        if (info.name === "substrings") {
            // SubstringFilter ::= SEQUENCE { type, SEQUENCE OF substrings }
            const inner = readTlv(bytes, outer.valueStart, outer.valueEnd);
            if (!inner || inner.tag !== 0x30) return null;
            const typeTlv = readTlv(bytes, inner.valueStart, inner.valueEnd);
            if (!typeTlv || typeTlv.tag !== 0x04) return null;
            const typeText = decodeAsn1Text(
                bytes,
                typeTlv.valueStart,
                typeTlv.valueEnd,
            );
            const seqTlv = readTlv(bytes, typeTlv.valueEnd, inner.valueEnd);
            if (!seqTlv || seqTlv.tag !== 0x30) return null;
            let cursor = seqTlv.valueStart;
            let initial = "";
            let finalStr = "";
            const anyParts = [];
            while (cursor < seqTlv.valueEnd) {
                const subTlv = readTlv(bytes, cursor, seqTlv.valueEnd);
                if (!subTlv) break;
                const subTag = subTlv.tagInfo.tagNumber;
                const subText = decodeAsn1Text(
                    bytes,
                    subTlv.valueStart,
                    subTlv.valueEnd,
                );
                if (subTag === 0) initial = subText;
                else if (subTag === 2) finalStr = subText;
                else if (subTag === 1) anyParts.push(subText);
                cursor = subTlv.valueEnd;
            }
            return {
                text: `(${typeText}=${initial}*${anyParts.join("*")}*${finalStr})`,
                tlv: outer,
                endIndex: outer.valueEnd,
            };
        }
        if (info.name === "extensibleMatch") {
            // MatchingRuleAssertion — keep it compact.
            const parts = [];
            let cursor = outer.valueStart;
            while (cursor < outer.valueEnd) {
                const tlv = readTlv(bytes, cursor, outer.valueEnd);
                if (!tlv) break;
                if (
                    tlv.tagInfo.classLabel === "Context-specific" &&
                    tlv.tagInfo.tagNumber === 1
                ) {
                    parts.push(`:dn:`);
                } else if (tlv.tag === 0x04) {
                    parts.push(decodeAsn1Text(bytes, tlv.valueStart, tlv.valueEnd));
                } else if (tlv.tag === 0x06) {
                    const oid = readOid(bytes, cursor, outer.valueEnd);
                    if (oid) parts.push(`:${oid.text}:`);
                }
                cursor = tlv.valueEnd;
            }
            return {
                text: `(${parts.join("")})`,
                tlv: outer,
                endIndex: outer.valueEnd,
            };
        }
    }

    // Leaf: equalityMatch / greaterOrEqual / lessOrEqual / approxMatch.
    // Each wraps an AttributeValueAssertion: SEQUENCE { attr, value }.
    const ava = readTlv(bytes, outer.valueStart, outer.valueEnd);
    if (!ava || ava.tag !== 0x30) return null;
    const attrTlv = readTlv(bytes, ava.valueStart, ava.valueEnd);
    if (!attrTlv || attrTlv.tag !== 0x04) return null;
    const attrText = decodeAsn1Text(bytes, attrTlv.valueStart, attrTlv.valueEnd);
    const valueText = decodeAsn1Text(bytes, attrTlv.valueEnd, ava.valueEnd);
    const op =
        info.name === "equalityMatch"
            ? "="
            : info.name === "greaterOrEqual"
            ? ">="
            : info.name === "lessOrEqual"
            ? "<="
            : info.name === "approxMatch"
            ? "~="
            : "=";
    return {
        text: `(${attrText}${op}${valueText})`,
        tlv: outer,
        endIndex: outer.valueEnd,
    };
}

// Render a BindRequest body. RFC 4511 §4.2:
//
// BindRequest ::= [APPLICATION 0] SEQUENCE {
//     version    INTEGER (1 .. 127),
//     name       LDAPDN,
//     authentication AuthenticationChoice }
//
// AuthenticationChoice CHOICE {
//     simple [0] OCTET STRING,
//     sasl   [3] SaslCredentials }
function appendBindRequestFields(fields, bytes, startIndex, endIndex) {
    let cursor = startIndex;
    const version = readInteger(bytes, cursor, endIndex);
    if (version) {
        fields.push({ name: "Version", value: String(version.value) });
        cursor = version.tlv.valueEnd;
    } else {
        fields.push({ name: "Version", value: "?" });
    }
    const dn = readLdapDn(bytes, cursor, endIndex);
    if (dn) {
        pushTextWithBytes(
            fields,
            "Bind DN",
            dn.text || "(empty)",
            bytes,
            dn.tlv.valueStart,
            dn.tlv.valueEnd,
        );
        cursor = dn.tlv.valueEnd;
    } else {
        fields.push({ name: "Bind DN", value: "?" });
    }
    const auth = readTlv(bytes, cursor, endIndex);
    if (auth) {
        const authKind = LDAP_AUTH_TAGS[auth.tagInfo.tagNumber] || `tag${auth.tagInfo.tagNumber}`;
        if (authKind === "simple") {
            const pwd = decodeAsn1Text(bytes, auth.valueStart, auth.valueEnd);
            if (pwd) {
                fields.push({
                    name: "Auth",
                    value: `simple (${pwd.length} byte(s))`,
                });
                pushBytesOnly(
                    fields,
                    "Auth",
                    bytes,
                    auth.valueStart,
                    auth.valueEnd,
                    32,
                );
            } else {
                fields.push({ name: "Auth", value: "simple (empty)" });
                pushBytesOnly(
                    fields,
                    "Auth",
                    bytes,
                    auth.valueStart,
                    auth.valueEnd,
                    32,
                );
            }
        } else if (authKind === "sasl") {
            // SASL credentials are SEQUENCE { mechanism LDAPOID, [1] OCTET STRING }
            // but the APPLICATION wrapper is implicit so the SEQUENCE tag is
            // omitted on the wire. Inspect what comes after the OID tag.
            const mech = readOid(bytes, auth.valueStart, auth.valueEnd);
            if (mech) {
                pushTextWithBytes(
                    fields,
                    "SASL Mechanism",
                    mech.text,
                    bytes,
                    mech.tlv.valueStart,
                    mech.tlv.valueEnd,
                );
            }
            const credsTlv = readTlv(
                bytes,
                mech ? mech.tlv.valueEnd : auth.valueStart,
                auth.valueEnd,
            );
            if (credsTlv && credsTlv.tag === 0x04) {
                fields.push({
                    name: "SASL Credentials",
                    value: `${hexPreview(
                        bytes,
                        credsTlv.valueStart,
                        credsTlv.valueEnd,
                        16,
                    )} (${credsTlv.length} byte(s))`,
                });
                pushBytesOnly(
                    fields,
                    "SASL Credentials",
                    bytes,
                    credsTlv.valueStart,
                    credsTlv.valueEnd,
                    32,
                );
            } else if (!mech) {
                fields.push({
                    name: "Auth",
                    value: `sasl (${hexPreview(bytes, auth.valueStart, auth.valueEnd, 16)})`,
                });
                pushBytesOnly(
                    fields,
                    "Auth",
                    bytes,
                    auth.valueStart,
                    auth.valueEnd,
                    32,
                );
            }
        } else {
            fields.push({
                name: "Auth",
                value: `${authKind} (${hexPreview(bytes, auth.valueStart, auth.valueEnd, 16)})`,
            });
            pushBytesOnly(
                fields,
                "Auth",
                bytes,
                auth.valueStart,
                auth.valueEnd,
                32,
            );
        }
    }
}

// Render a generic LDAPResult body. RFC 4511 §4.1.9:
//
// LDAPResult ::= SEQUENCE {
//     resultCode    ENUMERATED,
//     matchedDN     LDAPDN,
//     errorMessage  LDAPString,
//     referral      [3] SEQUENCE OF LDAPURI OPTIONAL }
//
// Used for BindResponse, SearchResDone, ModifyResponse, AddResponse,
// DelResponse, ModDNResponse, and CompareResponse.
//
// Unlike REQUEST ops (which use IMPLICIT tagging), RESPONSE ops wrap an
// LDAPResult SEQUENCE explicitly. The APPLICATION tag (0x61, 0x65, 0x68,
// 0x6a, 0x6c, 0x6e, 0x70) is therefore followed by an inner 0x30 SEQUENCE
// tag, and we descend into it.
function appendLdapResultFields(fields, bytes, startIndex, endIndex, prefix) {
    const pre = prefix || "";
    const seq = readTlv(bytes, startIndex, endIndex);
    let bodyStart = startIndex;
    let bodyEnd = endIndex;
    if (seq && seq.tag === 0x30) {
        bodyStart = seq.valueStart;
        bodyEnd = seq.valueEnd;
    }
    let cursor = bodyStart;
    const code = readInteger(bytes, cursor, bodyEnd);
    if (code) {
        fields.push({
            name: `${pre}Result Code`,
            value: formatResultCode(code.value),
        });
        cursor = code.tlv.valueEnd;
    } else {
        fields.push({ name: `${pre}Result Code`, value: "?" });
    }
    const matched = readLdapDn(bytes, cursor, bodyEnd);
    if (matched) {
        pushTextWithBytes(
            fields,
            `${pre}Matched DN`,
            matched.text || "(empty)",
            bytes,
            matched.tlv.valueStart,
            matched.tlv.valueEnd,
        );
        cursor = matched.tlv.valueEnd;
    }
    const errMsg = readTlv(bytes, cursor, bodyEnd);
    if (errMsg && errMsg.tag === 0x04) {
        const text = decodeAsn1Text(bytes, errMsg.valueStart, errMsg.valueEnd);
        pushTextWithBytes(
            fields,
            `${pre}Error Message`,
            text || "(empty)",
            bytes,
            errMsg.valueStart,
            errMsg.valueEnd,
        );
        cursor = errMsg.valueEnd;
    }
    // Optional referral ([3]) — just note presence with a length so users
    // can drill in manually if they need to.
    const referral = readTlv(bytes, cursor, bodyEnd);
    if (
        referral &&
        referral.tagInfo.classLabel === "Context-specific" &&
        referral.tagInfo.tagNumber === 3
    ) {
        fields.push({
            name: `${pre}Referral`,
            value: `present (${referral.length} byte(s))`,
        });
        pushBytesOnly(
            fields,
            `${pre}Referral`,
            bytes,
            referral.valueStart,
            referral.valueEnd,
            64,
        );
    }
}

// Render an ExtendedRequest body. RFC 4511 §4.12:
//
// ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
//     requestName   [0] LDAPOID,
//     requestValue  [1] OCTET STRING OPTIONAL }
//
// LDAP wire format uses IMPLICIT tagging: the [0] and [1] context-specific
// tags are wrapped in an EXPLICIT SEQUENCE tag for ASN.1 strictness but
// implementations typically send them without the outer SEQUENCE. We handle
// either case — if a SEQUENCE is present, descend into it; otherwise parse
// the [0] / [1] tags directly from the value bytes.
function appendExtendedRequestFields(fields, bytes, startIndex, endIndex) {
    // Look for an inner SEQUENCE — if present, descend into it. Otherwise
    // treat the value bytes as the [0]/[1] tag stream directly.
    const innerSeq = readTlv(bytes, startIndex, endIndex);
    let cursor = startIndex;
    let limit = endIndex;
    if (innerSeq && innerSeq.tag === 0x30) {
        cursor = innerSeq.valueStart;
        limit = innerSeq.valueEnd;
    }
    const nameTlv = readTlv(bytes, cursor, limit);
    if (
        nameTlv &&
        nameTlv.tagInfo.classLabel === "Context-specific" &&
        nameTlv.tagInfo.tagNumber === 0
    ) {
        const oid = readOid(bytes, nameTlv.valueStart, nameTlv.valueEnd);
        if (oid) {
            pushTextWithBytes(
                fields,
                "Request OID",
                oid.text,
                bytes,
                oid.tlv.valueStart,
                oid.tlv.valueEnd,
            );
        }
        cursor = nameTlv.valueEnd;
    }
    const valTlv = readTlv(bytes, cursor, limit);
    if (
        valTlv &&
        valTlv.tagInfo.classLabel === "Context-specific" &&
        valTlv.tagInfo.tagNumber === 1
    ) {
        // The value bytes are wrapped as `[1] OCTET STRING`. Show the
        // OCTET STRING contents in the friendly preview, not the wrapper.
        const inner = readTlv(bytes, valTlv.valueStart, valTlv.valueEnd);
        const valueBytesStart =
            inner && inner.tag === 0x04 ? inner.valueStart : valTlv.valueStart;
        const valueBytesEnd =
            inner && inner.tag === 0x04 ? inner.valueEnd : valTlv.valueEnd;
        const valueLength = valueBytesEnd - valueBytesStart;
        fields.push({
            name: "Request Value",
            value: `${hexPreview(
                bytes,
                valueBytesStart,
                valueBytesEnd,
                16,
            )} (${valueLength} byte(s))`,
        });
        pushBytesOnly(
            fields,
            "Request Value",
            bytes,
            valueBytesStart,
            valueBytesEnd,
            64,
        );
    }
}

// Render an ExtendedResponse body. Same as LDAPResult with two extra
// context-specific trailing fields: responseName [10] LDAPOID and
// responseValue [11] OCTET STRING (RFC 4511 §4.12).
//
// RESPONSE ops wrap LDAPResult in an explicit inner SEQUENCE, so we descend
// into it for the result code / matched DN / error message. The trailing
// [10] / [11] tags sit AFTER the inner SEQUENCE (no outer SEQUENCE around
// them).
function appendExtendedResponseFields(fields, bytes, startIndex, endIndex) {
    const seq = readTlv(bytes, startIndex, endIndex);
    let bodyStart = startIndex;
    let bodyEnd = endIndex;
    let cursor = startIndex;
    if (seq && seq.tag === 0x30) {
        bodyStart = seq.valueStart;
        bodyEnd = seq.valueEnd;
    }
    const code = readInteger(bytes, bodyStart, bodyEnd);
    if (code) {
        fields.push({
            name: "Result Code",
            value: formatResultCode(code.value),
        });
        cursor = code.tlv.valueEnd;
    } else {
        fields.push({ name: "Result Code", value: "?" });
    }
    const matched = readLdapDn(bytes, cursor, bodyEnd);
    if (matched) {
        pushTextWithBytes(
            fields,
            "Matched DN",
            matched.text || "(empty)",
            bytes,
            matched.tlv.valueStart,
            matched.tlv.valueEnd,
        );
        cursor = matched.tlv.valueEnd;
    }
    const errMsg = readTlv(bytes, cursor, bodyEnd);
    if (errMsg && errMsg.tag === 0x04) {
        const text = decodeAsn1Text(bytes, errMsg.valueStart, errMsg.valueEnd);
        pushTextWithBytes(
            fields,
            "Error Message",
            text || "(empty)",
            bytes,
            errMsg.valueStart,
            errMsg.valueEnd,
        );
        cursor = errMsg.valueEnd;
    }
    // After the LDAPResult SEQUENCE, scan for [10] / [11] tags in the
    // remaining bytes.
    let trailingCursor = bodyEnd;
    const nameTlv = readTlv(bytes, trailingCursor, endIndex);
    if (
        nameTlv &&
        nameTlv.tagInfo.classLabel === "Context-specific" &&
        nameTlv.tagInfo.tagNumber === 10
    ) {
        const oid = readOid(bytes, nameTlv.valueStart, nameTlv.valueEnd);
        if (oid) {
            pushTextWithBytes(
                fields,
                "Response OID",
                oid.text,
                bytes,
                oid.tlv.valueStart,
                oid.tlv.valueEnd,
            );
        }
        trailingCursor = nameTlv.valueEnd;
    }
    const valTlv = readTlv(bytes, trailingCursor, endIndex);
    if (
        valTlv &&
        valTlv.tagInfo.classLabel === "Context-specific" &&
        valTlv.tagInfo.tagNumber === 11
    ) {
        // The value bytes are wrapped as `[11] OCTET STRING`. Show the
        // OCTET STRING contents in the friendly preview, not the wrapper.
        const inner = readTlv(bytes, valTlv.valueStart, valTlv.valueEnd);
        const valueBytesStart =
            inner && inner.tag === 0x04 ? inner.valueStart : valTlv.valueStart;
        const valueBytesEnd =
            inner && inner.tag === 0x04 ? inner.valueEnd : valTlv.valueEnd;
        const valueLength = valueBytesEnd - valueBytesStart;
        fields.push({
            name: "Response Value",
            value: `${hexPreview(
                bytes,
                valueBytesStart,
                valueBytesEnd,
                16,
            )} (${valueLength} byte(s))`,
        });
        pushBytesOnly(
            fields,
            "Response Value",
            bytes,
            valueBytesStart,
            valueBytesEnd,
            64,
        );
    }
}

// Render an IntermediateResponse body. Same shape as ExtendedResponse
// without the LDAPResult prefix (RFC 4511 §4.13).
function appendIntermediateResponseFields(fields, bytes, startIndex, endIndex) {
    let cursor = startIndex;
    const nameTlv = readTlv(bytes, cursor, endIndex);
    if (
        nameTlv &&
        nameTlv.tagInfo.classLabel === "Context-specific" &&
        nameTlv.tagInfo.tagNumber === 0
    ) {
        const oid = readOid(bytes, nameTlv.valueStart, nameTlv.valueEnd);
        if (oid) {
            pushTextWithBytes(
                fields,
                "Response OID",
                oid.text,
                bytes,
                oid.tlv.valueStart,
                oid.tlv.valueEnd,
            );
        }
        cursor = nameTlv.valueEnd;
    }
    const valTlv = readTlv(bytes, cursor, endIndex);
    if (
        valTlv &&
        valTlv.tagInfo.classLabel === "Context-specific" &&
        valTlv.tagInfo.tagNumber === 1
    ) {
        // The value bytes are wrapped as `[1] OCTET STRING`. Show the
        // OCTET STRING contents in the friendly preview, not the wrapper.
        const inner = readTlv(bytes, valTlv.valueStart, valTlv.valueEnd);
        const valueBytesStart =
            inner && inner.tag === 0x04 ? inner.valueStart : valTlv.valueStart;
        const valueBytesEnd =
            inner && inner.tag === 0x04 ? inner.valueEnd : valTlv.valueEnd;
        const valueLength = valueBytesEnd - valueBytesStart;
        fields.push({
            name: "Response Value",
            value: `${hexPreview(
                bytes,
                valueBytesStart,
                valueBytesEnd,
                16,
            )} (${valueLength} byte(s))`,
        });
        pushBytesOnly(
            fields,
            "Response Value",
            bytes,
            valueBytesStart,
            valueBytesEnd,
            64,
        );
    }
}

// Render a SearchRequest body. RFC 4511 §4.5.1:
//
// SearchRequest ::= [APPLICATION 3] SEQUENCE {
//     baseDN       LDAPDN,
//     scope        ENUMERATED,
//     derefAliases ENUMERATED,
//     sizeLimit    INTEGER,
//     timeLimit    INTEGER,
//     typesOnly    BOOLEAN,
//     filter       Filter,
//     attributes   SEQUENCE OF AttributeDescription }
function appendSearchRequestFields(fields, bytes, startIndex, endIndex) {
    let cursor = startIndex;
    const baseDn = readLdapDn(bytes, cursor, endIndex);
    if (baseDn) {
        pushTextWithBytes(
            fields,
            "Base DN",
            baseDn.text || "(root)",
            bytes,
            baseDn.tlv.valueStart,
            baseDn.tlv.valueEnd,
        );
        cursor = baseDn.tlv.valueEnd;
    }
    const scopeEnum = readTlv(bytes, cursor, endIndex);
    if (scopeEnum && scopeEnum.tag === 0x0a) {
        const scopeVal = scopeEnum.length > 0 ? bytes[scopeEnum.valueStart] : 0;
        fields.push({
            name: "Scope",
            value: `${scopeVal} (${LDAP_SCOPE_NAMES[scopeVal] || "?"})`,
        });
        cursor = scopeEnum.valueEnd;
    }
    const derefEnum = readTlv(bytes, cursor, endIndex);
    if (derefEnum && derefEnum.tag === 0x0a) {
        const derefVal = derefEnum.length > 0 ? bytes[derefEnum.valueStart] : 0;
        fields.push({
            name: "Deref Aliases",
            value: `${derefVal} (${LDAP_DEREF_NAMES[derefVal] || "?"})`,
        });
        cursor = derefEnum.valueEnd;
    }
    const sizeLimit = readInteger(bytes, cursor, endIndex);
    if (sizeLimit) {
        fields.push({ name: "Size Limit", value: String(sizeLimit.value) });
        cursor = sizeLimit.tlv.valueEnd;
    }
    const timeLimit = readInteger(bytes, cursor, endIndex);
    if (timeLimit) {
        fields.push({ name: "Time Limit", value: String(timeLimit.value) });
        cursor = timeLimit.tlv.valueEnd;
    }
    const typesOnly = readTlv(bytes, cursor, endIndex);
    if (typesOnly && typesOnly.tag === 0x01) {
        const flag =
            typesOnly.length > 0 ? bytes[typesOnly.valueStart] !== 0 : false;
        fields.push({ name: "Types Only", value: flag ? "true" : "false" });
        cursor = typesOnly.valueEnd;
    }
    const filter = readFilter(bytes, cursor, endIndex, 0);
    if (filter) {
        pushTextWithBytes(
            fields,
            "Filter",
            filter.text,
            bytes,
            filter.tlv.valueStart,
            filter.tlv.valueEnd,
        );
        cursor = filter.endIndex;
    } else {
        fields.push({ name: "Filter", value: "?" });
    }
    // attributes SEQUENCE OF AttributeDescription
    const attrsTlv = readTlv(bytes, cursor, endIndex);
    if (attrsTlv && attrsTlv.tag === 0x30) {
        const attrs = [];
        let ac = attrsTlv.valueStart;
        let count = 0;
        while (ac < attrsTlv.valueEnd) {
            const attrTlv = readTlv(bytes, ac, attrsTlv.valueEnd);
            if (!attrTlv || attrTlv.tag !== 0x04) break;
            attrs.push(
                decodeAsn1Text(bytes, attrTlv.valueStart, attrTlv.valueEnd),
            );
            ac = attrTlv.valueEnd;
            count += 1;
            if (count >= LDAP_ATTR_LIMIT) break;
        }
        const remaining = count >= LDAP_ATTR_LIMIT ? "+more" : "";
        pushTruncated(
            fields,
            "Attributes",
            `${count} (${attrs.filter(Boolean).slice(0, LDAP_ATTR_LIMIT).join(", ")})${remaining}`,
            LDAP_VALUE_LIMIT,
        );
    }
}

// Render a SearchResEntry body. RFC 4511 §4.5.2:
//
// SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
//     objectName  LDAPDN,
//     attributes  PartialAttributeList }
// PartialAttributeList ::= SEQUENCE OF partialAttribute PartialAttribute
// PartialAttribute ::= SEQUENCE { type AttributeDescription, vals SET OF value AttributeValue }
function appendSearchResEntryFields(fields, bytes, startIndex, endIndex) {
    let cursor = startIndex;
    const dn = readLdapDn(bytes, cursor, endIndex);
    if (dn) {
        pushTextWithBytes(
            fields,
            "Object Name",
            dn.text || "(empty)",
            bytes,
            dn.tlv.valueStart,
            dn.tlv.valueEnd,
        );
        cursor = dn.tlv.valueEnd;
    }
    const partialList = readTlv(bytes, cursor, endIndex);
    if (!partialList || partialList.tag !== 0x30) return;
    const attrs = [];
    let pc = partialList.valueStart;
    let total = 0;
    while (pc < partialList.valueEnd) {
        const partTlv = readTlv(bytes, pc, partialList.valueEnd);
        if (!partTlv || partTlv.tag !== 0x30) break;
        const attrType = readTlv(bytes, partTlv.valueStart, partTlv.valueEnd);
        if (!attrType || attrType.tag !== 0x04) {
            pc = partTlv.valueEnd;
            continue;
        }
        const typeText = decodeAsn1Text(
            bytes,
            attrType.valueStart,
            attrType.valueEnd,
        );
        const valSet = readTlv(bytes, attrType.valueEnd, partTlv.valueEnd);
        const values = [];
        if (valSet && valSet.tag === 0x31) {
            let vc = valSet.valueStart;
            while (vc < valSet.valueEnd) {
                const valTlv = readTlv(bytes, vc, valSet.valueEnd);
                if (!valTlv || valTlv.tag !== 0x04) break;
                values.push(
                    decodeAsn1Text(bytes, valTlv.valueStart, valTlv.valueEnd),
                );
                vc = valTlv.valueEnd;
            }
        }
        attrs.push(`${typeText}=${values.slice(0, 2).join("|")}`);
        pc = partTlv.valueEnd;
        total += 1;
        if (total >= LDAP_ATTR_LIMIT) break;
    }
    pushTruncated(
        fields,
        "Attributes",
        attrs.filter(Boolean).join("; ") || "(empty)",
        LDAP_VALUE_LIMIT,
    );
}

// Render a ModifyRequest body. RFC 4511 §4.6:
//
// ModifyRequest ::= [APPLICATION 7] SEQUENCE {
//     object  LDAPDN,
//     changes SEQUENCE OF change SEQUENCE {
//         operation ENUMERATED,
//         modification PartialAttribute } }
function appendModifyRequestFields(fields, bytes, startIndex, endIndex) {
    let cursor = startIndex;
    const dn = readLdapDn(bytes, cursor, endIndex);
    if (dn) {
        pushTextWithBytes(
            fields,
            "Object",
            dn.text || "(empty)",
            bytes,
            dn.tlv.valueStart,
            dn.tlv.valueEnd,
        );
        cursor = dn.tlv.valueEnd;
    }
    const changesSeq = readTlv(bytes, cursor, endIndex);
    if (!changesSeq || changesSeq.tag !== 0x30) return;
    let cc = changesSeq.valueStart;
    let total = 0;
    const summaries = [];
    while (cc < changesSeq.valueEnd) {
        const change = readTlv(bytes, cc, changesSeq.valueEnd);
        if (!change || change.tag !== 0x30) break;
        const opEnum = readTlv(bytes, change.valueStart, change.valueEnd);
        let opText = "?";
        let attrCursor = change.valueEnd;
        if (opEnum && opEnum.tag === 0x0a) {
            const opVal =
                opEnum.length > 0 ? bytes[opEnum.valueStart] : -1;
            opText = LDAP_MODIFY_OPS[opVal] || `op${opVal}`;
            attrCursor = opEnum.valueEnd;
        }
        const partTlv = readTlv(bytes, attrCursor, change.valueEnd);
        if (partTlv && partTlv.tag === 0x30) {
            const attrType = readTlv(bytes, partTlv.valueStart, partTlv.valueEnd);
            if (attrType && attrType.tag === 0x04) {
                const typeText = decodeAsn1Text(
                    bytes,
                    attrType.valueStart,
                    attrType.valueEnd,
                );
                summaries.push(`${opText}:${typeText}`);
            }
        }
        cc = change.valueEnd;
        total += 1;
        if (total >= LDAP_ATTR_LIMIT) break;
    }
    pushTruncated(
        fields,
        "Changes",
        summaries.join(", ") || "(empty)",
        LDAP_VALUE_LIMIT,
    );
}

// Render an AddRequest body. RFC 4511 §4.7:
//
// AddRequest ::= [APPLICATION 9] SEQUENCE {
//     entry      LDAPDN,
//     attributes AttributeList }
// AttributeList ::= SEQUENCE OF attribute Attribute
// Attribute ::= SEQUENCE { type AttributeDescription, vals SET OF value AttributeValue }
function appendAddRequestFields(fields, bytes, startIndex, endIndex) {
    let cursor = startIndex;
    const dn = readLdapDn(bytes, cursor, endIndex);
    if (dn) {
        pushTextWithBytes(
            fields,
            "Entry",
            dn.text || "(empty)",
            bytes,
            dn.tlv.valueStart,
            dn.tlv.valueEnd,
        );
        cursor = dn.tlv.valueEnd;
    }
    const attrList = readTlv(bytes, cursor, endIndex);
    if (!attrList || attrList.tag !== 0x30) return;
    const attrs = [];
    let ac = attrList.valueStart;
    let total = 0;
    while (ac < attrList.valueEnd) {
        const attr = readTlv(bytes, ac, attrList.valueEnd);
        if (!attr || attr.tag !== 0x30) break;
        const attrType = readTlv(bytes, attr.valueStart, attr.valueEnd);
        if (!attrType || attrType.tag !== 0x04) {
            ac = attr.valueEnd;
            continue;
        }
        const typeText = decodeAsn1Text(
            bytes,
            attrType.valueStart,
            attrType.valueEnd,
        );
        const valSet = readTlv(bytes, attrType.valueEnd, attr.valueEnd);
        const values = [];
        if (valSet && valSet.tag === 0x31) {
            let vc = valSet.valueStart;
            while (vc < valSet.valueEnd) {
                const valTlv = readTlv(bytes, vc, valSet.valueEnd);
                if (!valTlv || valTlv.tag !== 0x04) break;
                values.push(
                    decodeAsn1Text(bytes, valTlv.valueStart, valTlv.valueEnd),
                );
                vc = valTlv.valueEnd;
            }
        }
        attrs.push(`${typeText}=${values.slice(0, 2).join("|")}`);
        ac = attr.valueEnd;
        total += 1;
        if (total >= LDAP_ATTR_LIMIT) break;
    }
    pushTruncated(
        fields,
        "Attributes",
        attrs.filter(Boolean).join("; ") || "(empty)",
        LDAP_VALUE_LIMIT,
    );
}

// Render a ModDNRequest body. RFC 4511 §4.9:
//
// ModifyDNRequest ::= [APPLICATION 13] SEQUENCE {
//     entry          LDAPDN,
//     newrdn         RelativeLDAPDN,
//     deleteoldrdn   BOOLEAN,
//     newsuperior    [0] LDAPDN OPTIONAL }
function appendModDnRequestFields(fields, bytes, startIndex, endIndex) {
    let cursor = startIndex;
    const entry = readLdapDn(bytes, cursor, endIndex);
    if (entry) {
        pushTextWithBytes(
            fields,
            "Entry",
            entry.text || "(empty)",
            bytes,
            entry.tlv.valueStart,
            entry.tlv.valueEnd,
        );
        cursor = entry.tlv.valueEnd;
    }
    const newRdn = readLdapDn(bytes, cursor, endIndex);
    if (newRdn) {
        pushTextWithBytes(
            fields,
            "New RDN",
            newRdn.text || "(empty)",
            bytes,
            newRdn.tlv.valueStart,
            newRdn.tlv.valueEnd,
        );
        cursor = newRdn.tlv.valueEnd;
    }
    const deleteOld = readTlv(bytes, cursor, endIndex);
    if (deleteOld && deleteOld.tag === 0x01) {
        const flag =
            deleteOld.length > 0 ? bytes[deleteOld.valueStart] !== 0 : false;
        fields.push({ name: "Delete Old RDN", value: flag ? "true" : "false" });
        cursor = deleteOld.valueEnd;
    }
    const newSup = readTlv(bytes, cursor, endIndex);
    if (
        newSup &&
        newSup.tagInfo.classLabel === "Context-specific" &&
        newSup.tagInfo.tagNumber === 0
    ) {
        const sup = decodeAsn1Text(bytes, newSup.valueStart, newSup.valueEnd);
        pushTextWithBytes(
            fields,
            "New Superior",
            sup || "(empty)",
            bytes,
            newSup.valueStart,
            newSup.valueEnd,
        );
    }
}

// Render a CompareRequest body. RFC 4511 §4.10:
//
// CompareRequest ::= [APPLICATION 15] SEQUENCE {
//     entry   LDAPDN,
//     ava     AttributeValueAssertion }
// AttributeValueAssertion ::= SEQUENCE {
//     attributeDesc   AttributeDescription,
//     assertionValue  AssertionValue }
function appendCompareRequestFields(fields, bytes, startIndex, endIndex) {
    let cursor = startIndex;
    const dn = readLdapDn(bytes, cursor, endIndex);
    if (dn) {
        pushTextWithBytes(
            fields,
            "Entry",
            dn.text || "(empty)",
            bytes,
            dn.tlv.valueStart,
            dn.tlv.valueEnd,
        );
        cursor = dn.tlv.valueEnd;
    }
    const ava = readTlv(bytes, cursor, endIndex);
    if (!ava || ava.tag !== 0x30) return;
    const attrTlv = readTlv(bytes, ava.valueStart, ava.valueEnd);
    if (attrTlv && attrTlv.tag === 0x04) {
        const attrText = decodeAsn1Text(
            bytes,
            attrTlv.valueStart,
            attrTlv.valueEnd,
        );
        const valText = decodeAsn1Text(bytes, attrTlv.valueEnd, ava.valueEnd);
        fields.push({ name: "Assertion", value: `${attrText}=${valText}` });
        // Surface hex/ASCII of the value (after the attribute) so users can
        // confirm what they read for case-insensitive comparisons.
        pushBytesOnly(
            fields,
            "Assertion Value",
            bytes,
            attrTlv.valueEnd,
            ava.valueEnd,
            64,
        );
    }
}

// Render a DelRequest body. RFC 4511 §4.8: just a single LDAPDN.
function appendDelRequestFields(fields, bytes, startIndex, endIndex) {
    const dn = readLdapDn(bytes, startIndex, endIndex);
    if (dn) {
        pushTextWithBytes(
            fields,
            "DN",
            dn.text || "(empty)",
            bytes,
            dn.tlv.valueStart,
            dn.tlv.valueEnd,
        );
    } else {
        fields.push({ name: "DN", value: hexPreview(bytes, startIndex, endIndex) });
        pushBytesOnly(fields, "DN", bytes, startIndex, endIndex, 64);
    }
}

// Render an AbandonRequest body. RFC 4511 §4.11: a single INTEGER holding
// the message ID of the request being abandoned.
function appendAbandonRequestFields(fields, bytes, startIndex, endIndex) {
    const id = readInteger(bytes, startIndex, endIndex);
    if (id) {
        fields.push({ name: "Abandoned Message ID", value: String(id.value) });
        pushBytesOnly(
            fields,
            "Abandoned Message ID",
            bytes,
            id.tlv.valueStart,
            id.tlv.valueEnd,
            32,
        );
    } else {
        fields.push({
            name: "Abandoned Message ID",
            value: hexPreview(bytes, startIndex, endIndex),
        });
    }
}

// Render a SearchResRef body. RFC 4511 §4.5.3:
//
// SearchResultReference ::= [APPLICATION 6] SEQUENCE SIZE (1..MAX) OF uri LDAPURI
function appendSearchResRefFields(fields, bytes, startIndex, endIndex) {
    let cursor = startIndex;
    const uris = [];
    while (cursor < endIndex) {
        const uri = readTlv(bytes, cursor, endIndex);
        if (!uri || uri.tag !== 0x04) break;
        uris.push(decodeAsn1Text(bytes, uri.valueStart, uri.valueEnd));
        cursor = uri.valueEnd;
    }
    pushTruncated(
        fields,
        "Referrals",
        uris.filter(Boolean).join(", ") || "(empty)",
        LDAP_VALUE_LIMIT,
    );
}

// Dispatch on the application tag at `cursor` and append operation-specific
// fields to `fields`. The application tag's value bytes are at
// `bytes[cursor + headerLength .. cursor + headerLength + length]`. After
// the renderer returns, all newly added fields are prefixed with
// `Message <messageNumber> ` so they group with their parent message.
function appendOperationFields(
    fields,
    bytes,
    opStart,
    opEnd,
    messageNumber,
) {
    const beforeCount = fields.length;
    const opTag = bytes[opStart];
    switch (opTag) {
        case 0x60: // BindRequest
            appendBindRequestFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x61: // BindResponse
            appendLdapResultFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x62: // UnbindRequest — no payload
            break;
        case 0x63: // SearchRequest
            appendSearchRequestFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x64: // SearchResEntry
            appendSearchResEntryFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x65: // SearchResDone
            appendLdapResultFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x66: // SearchResRef
            appendSearchResRefFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x67: // ModifyRequest
            appendModifyRequestFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x68: // ModifyResponse
            appendLdapResultFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x69: // AddRequest
            appendAddRequestFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x6a: // AddResponse
            appendLdapResultFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x6b: // DelRequest
            appendDelRequestFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x6c: // DelResponse
            appendLdapResultFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x6d: // ModDNRequest
            appendModDnRequestFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x6e: // ModDNResponse
            appendLdapResultFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x6f: // CompareRequest
            appendCompareRequestFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x70: // CompareResponse
            appendLdapResultFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x71: // AbandonRequest
            appendAbandonRequestFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x77: // ExtendedRequest
            appendExtendedRequestFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x78: // ExtendedResponse
            appendExtendedResponseFields(fields, bytes, opStart + 2, opEnd);
            break;
        case 0x79: // IntermediateResponse
            appendIntermediateResponseFields(
                fields,
                bytes,
                opStart + 2,
                opEnd,
            );
            break;
        default:
            // Unknown op — surface the tag and a hex preview of the bytes.
            fields.push({
                name: "Unknown Operation",
                value: `tag 0x${opTag.toString(16).padStart(2, "0").toUpperCase()}`,
            });
            pushBytesOnly(
                fields,
                "Unknown Operation",
                bytes,
                opStart,
                opEnd,
                64,
            );
            break;
    }
    // Prefix every newly added field name with "Message N " so each
    // operation's rows group with their parent message (handy in
    // multi-message streams).
    const messagePrefix = `Message ${messageNumber} `;
    for (let i = beforeCount; i < fields.length; i += 1) {
        fields[i].name = `${messagePrefix}${fields[i].name}`;
    }
}

function decodeLdapFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4) return null;

    try {
        const fields = [];
        let parsedMessages = 0;
        let index = 0;

        while (index < bytes.length && parsedMessages < MAX_LDAP_MESSAGES) {
            while (index < bytes.length && bytes[index] !== 0x30) {
                index += 1;
            }
            if (index >= bytes.length) break;

            const sequenceStart = index;
            const sequenceLengthInfo = parseAsn1Length(
                bytes,
                sequenceStart + 1,
                bytes.length,
            );
            if (!sequenceLengthInfo) {
                index = sequenceStart + 1;
                continue;
            }

            const sequenceValueStart = sequenceLengthInfo.nextIndex;
            const sequenceEnd = sequenceValueStart + sequenceLengthInfo.length;
            if (sequenceEnd > bytes.length) break;

            let cursor = sequenceValueStart;
            if (cursor >= sequenceEnd || bytes[cursor] !== 0x02) {
                index = sequenceStart + 1;
                continue;
            }

            const messageIdLengthInfo = parseAsn1Length(
                bytes,
                cursor + 1,
                sequenceEnd,
            );
            if (!messageIdLengthInfo) {
                index = sequenceStart + 1;
                continue;
            }

            const messageIdStart = messageIdLengthInfo.nextIndex;
            const messageIdEnd = messageIdStart + messageIdLengthInfo.length;
            if (messageIdLengthInfo.length < 1 || messageIdEnd > sequenceEnd) {
                index = sequenceStart + 1;
                continue;
            }

            let messageId = 0;
            for (
                let offset = messageIdStart;
                offset < messageIdEnd;
                offset += 1
            ) {
                messageId = (messageId << 8) | bytes[offset];
            }

            cursor = messageIdEnd;
            if (cursor >= sequenceEnd) {
                index = Math.max(sequenceEnd, sequenceStart + 1);
                continue;
            }

            const opTagByte = bytes[cursor];
            if (opTagByte < 0x60 || opTagByte > 0x7f) {
                index = sequenceStart + 1;
                continue;
            }

            const opLengthInfo = parseAsn1Length(
                bytes,
                cursor + 1,
                sequenceEnd,
            );
            if (!opLengthInfo) {
                index = sequenceStart + 1;
                continue;
            }

            const opValueStart = opLengthInfo.nextIndex;
            const opValueEnd = opValueStart + opLengthInfo.length;
            if (opValueEnd > sequenceEnd) {
                index = sequenceStart + 1;
                continue;
            }

            parsedMessages += 1;
            fields.push({
                name: `Message ${parsedMessages} ID`,
                value: String(messageId),
            });
            fields.push({
                name: `Message ${parsedMessages} Operation`,
                value:
                    LDAP_OPERATIONS[opTagByte] ||
                    `0x${opTagByte
                        .toString(16)
                        .padStart(2, "0")
                        .toUpperCase()}`,
            });

            appendOperationFields(
                fields,
                bytes,
                cursor,
                opValueEnd,
                parsedMessages,
            );

            index = Math.max(sequenceEnd, sequenceStart + 1);
        }

        if (!fields.length) return null;
        if (parsedMessages >= MAX_LDAP_MESSAGES && index < bytes.length) {
            fields.push({
                name: "Notice",
                value: `Showing first ${MAX_LDAP_MESSAGES} LDAP messages from stream.`,
            });
        }

        return {
            protocol: "LDAP",
            fields,
        };
    } catch {
        return null;
    }
}

module.exports = { decodeLdapFromBytes };
