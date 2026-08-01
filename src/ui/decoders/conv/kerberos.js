// Kerberos Conv decoder: parses Kerberos 5 application-layer messages from
// raw bytes. Kerberos framing is the standard ASN.1 APPLICATION tag for the
// message type at offset 0, optionally preceded by a 4-byte big-endian
// length record-length header on TCP transports (RFC 4120 §5.1). This
// decoder is intentionally narrower than decodeAsn1GenericFromBytes: it
// pulls out the small set of fields users actually look at when triaging
// AS-REQ / AS-REP / TGS-REQ / TGS-REP / AP-REQ / AP-REP / KRB-ERROR traffic
// (realm, principal, KDC options, ticket etype, error code) and falls back
// to a tag/byte summary when the inner structure cannot be safely walked.

const { parseAsn1Length, getAsn1TagDescription } = require("./asn1");
const { bytesToHexLower } = require("./smb-helpers");

const MAX_KRB5_MESSAGES = 64;
const PRINCIPAL_VALUE_LIMIT = 220;
const KRB_OCTET_STRING_VALUE_LIMIT = 220;

// Kerberos 5 message types keyed by their ASN.1 APPLICATION tag (RFC 4120
// §5.1). The tag byte is class=01 (Application), constructed=1, with the
// 5-bit tag number indicating which Kerberos message this is.
const KRB5_MSG_TYPES = {
    0x6a: "AS-REQ",   // APPLICATION 10
    0x6b: "AS-REP",   // APPLICATION 11
    0x6c: "TGS-REQ",  // APPLICATION 12
    0x6d: "TGS-REP",  // APPLICATION 13
    0x6e: "AP-REQ",   // APPLICATION 14
    0x6f: "AP-REP",   // APPLICATION 15
    0x74: "KRB-SAFE", // APPLICATION 20
    0x75: "KRB-PRIV", // APPLICATION 21
    0x76: "KRB-CRED", // APPLICATION 22
    0x7e: "KRB-ERROR",// APPLICATION 30
};

// Curated subset of the KDCOptions bit flags. Source: RFC 4120 §5.2.8.
const KDC_OPTION_BITS = [
    [0, "reserved"],
    [1, "forwardable"],
    [2, "forwarded"],
    [3, "proxiable"],
    [4, "proxy"],
    [5, "may-postdate"],
    [6, "postdated"],
    [7, "invalid"],
    [8, "renewable"],
    [9, "initial"],
    [10, "pre-authent"],
    [11, "hw-authent"],
    [12, "transited-policy-checked"],
    [13, "ok-as-delegate"],
    [14, "unused-14"],
    [15, "unused-15"],
    [16, "unused-16"],
    [17, "unused-17"],
    [18, "unused-18"],
    [19, "unused-19"],
    [20, "unused-20"],
    [21, "unused-21"],
    [22, "unused-22"],
    [23, "unused-23"],
    [24, "unused-24"],
    [25, "unused-25"],
    [26, "disable-transited-check"],
    [27, "renewable-ok"],
    [28, "enc-tkt-in-skey"],
    [29, "renew"],
    [30, "validate"],
];

// Decode a single ASN.1 TLV; returns { tag, tagInfo, valueStart, valueEnd, length } or null.
function readAsn1Tlv(bytes, startIndex) {
    if (!(bytes instanceof Uint8Array) || startIndex < 0 || startIndex + 2 > bytes.length) {
        return null;
    }
    const tag = bytes[startIndex];
    const lengthInfo = parseAsn1Length(bytes, startIndex + 1, bytes.length);
    if (!lengthInfo) return null;
    const valueStart = lengthInfo.nextIndex;
    const valueEnd = valueStart + lengthInfo.length;
    if (valueEnd > bytes.length) return null;
    return {
        tag,
        tagInfo: getAsn1TagDescription(tag),
        valueStart,
        valueEnd,
        length: lengthInfo.length,
    };
}

// Read an ASN.1 INTEGER as a non-negative number. Returns null when the
// integer does not fit in a regular JS number (large unsigned values) or
// is malformed.
function readAsn1Integer(bytes, startIndex) {
    const tlv = readAsn1Tlv(bytes, startIndex);
    if (!tlv || tlv.tag !== 0x02 || tlv.length < 1) return null;
    // Reject negative integers (top bit set in the first content byte) and
    // trivially-overlong encodings (DER permits only the minimum number of
    // bytes; we accept BER shapes too).
    if (tlv.length > 6) return null;
    if (tlv.length > 1 && (bytes[tlv.valueStart] & 0x80) !== 0) return null;
    let value = 0;
    for (let offset = tlv.valueStart; offset < tlv.valueEnd; offset += 1) {
        value = (value << 8) | bytes[offset];
    }
    return { value, tlv };
}

// Read an ASN.1 OCTET STRING and decode it as a printable UTF-8 preview.
// Returns { text, hex } or null when the TLV is not an OCTET STRING.
function readAsn1OctetString(bytes, startIndex) {
    const tlv = readAsn1Tlv(bytes, startIndex);
    if (!tlv || tlv.tag !== 0x04 || tlv.length < 0) return null;
    const slice = bytes.slice(tlv.valueStart, tlv.valueEnd);
    const hex = bytesToHexLower(slice);
    let text = "";
    try {
        text = new TextDecoder("utf-8", { fatal: false }).decode(slice);
    } catch {
        text = "";
    }
    text = text.replace(/[^\x20-\x7e]/g, "");
    return { text, hex, tlv };
}

// Read an ASN.1 GeneralizedTime (tag 0x18) as a UTC string.
function readAsn1GeneralizedTime(bytes, startIndex) {
    const tlv = readAsn1Tlv(bytes, startIndex);
    if (!tlv || tlv.tag !== 0x18 || tlv.length < 8) return null;
    const raw = new TextDecoder("utf-8", { fatal: false })
        .decode(bytes.slice(tlv.valueStart, tlv.valueEnd))
        .replace(/[^\x20-\x7e]/g, "");
    return { text: raw, tlv };
}

// Walk a Kerberos PrincipalName (SEQUENCE OF { name-type, name-string })
// starting at a SEQUENCE header. Returns { nameType, nameStrings, endIndex }
// or null when the structure does not look like a principal.
function readPrincipalName(bytes, startIndex) {
    const tlv = readAsn1Tlv(bytes, startIndex);
    if (!tlv || tlv.tag !== 0x30) return null;
    // The Kerberos PrincipalName is SEQUENCE { name-type INTEGER, name-string
    // SEQUENCE OF GeneralString }. We only scan the top-level SEQUENCE for
    // one INTEGER and one SEQUENCE OF GeneralString; deeper structures
    // (tagged contexts) are reported as raw hex.
    let cursor = tlv.valueStart;
    const nameTypeInfo = readAsn1Integer(bytes, cursor);
    if (!nameTypeInfo) return null;
    cursor = nameTypeInfo.tlv.valueEnd;
    if (cursor >= tlv.valueEnd) {
        return { nameType: nameTypeInfo.value, nameStrings: [], endIndex: tlv.valueEnd };
    }
    const stringSeq = readAsn1Tlv(bytes, cursor);
    if (!stringSeq || stringSeq.tag !== 0x30) {
        return { nameType: nameTypeInfo.value, nameStrings: [], endIndex: tlv.valueEnd };
    }
    const strings = [];
    let sCursor = stringSeq.valueStart;
    while (sCursor < stringSeq.valueEnd) {
        const stringTlv = readAsn1Tlv(bytes, sCursor);
        if (!stringTlv) break;
        const slice = bytes.slice(stringTlv.valueStart, stringTlv.valueEnd);
        const text = new TextDecoder("utf-8", { fatal: false })
            .decode(slice)
            .replace(/[^\x20-\x7e]/g, "");
        strings.push(text);
        sCursor = stringTlv.valueEnd;
    }
    return { nameType: nameTypeInfo.value, nameStrings: strings, endIndex: tlv.valueEnd };
}

function formatPrincipal(nameStrings) {
    if (!Array.isArray(nameStrings) || !nameStrings.length) return "(empty)";
    return nameStrings.join("/");
}

function pushTruncated(fields, name, value, limit) {
    if (typeof value !== "string" || !value) return;
    const trimmed = value.length > limit ? `${value.slice(0, limit)}...` : value;
    fields.push({ name, value: trimmed });
}

function formatKdcOptions(bigIntValue) {
    if (typeof bigIntValue !== "bigint") return null;
    const flags = [];
    // RFC 4120 §5.2.8: KDCOptions is a BIT STRING where bit 0 is the most
    // significant bit of the first byte. Walk bits from MSB (bit 0) down.
    KDC_OPTION_BITS.forEach(([bit, label]) => {
        const mask = 1n << BigInt(31 - bit);
        if ((bigIntValue & mask) !== 0n) {
            flags.push(label);
        }
    });
    return flags.length ? flags.join(", ") : "none";
}

function appendEtypeList(fields, bytes, startIndex) {
    // The etype list is a SEQUENCE OF INTEGER wrapped in a context-specific
    // [8] constructed tag (RFC 4120 §5.2.9). Read the context tag first,
    // then unwrap the SEQUENCE before iterating.
    const ctx = readAsn1Tlv(bytes, startIndex);
    if (!ctx || ctx.tagInfo.classLabel !== "Context-specific" || ctx.tagInfo.tagNumber !== 8) return;
    const seqTlv = readAsn1Tlv(bytes, ctx.valueStart);
    if (!seqTlv || seqTlv.tag !== 0x30) return;
    const etypes = [];
    let cursor = seqTlv.valueStart;
    while (cursor < seqTlv.valueEnd) {
        const entry = readAsn1Integer(bytes, cursor);
        if (!entry) break;
        etypes.push(`0x${entry.value.toString(16).padStart(2, "0")} (${entry.value})`);
        cursor = entry.tlv.valueEnd;
    }
    if (etypes.length) {
        fields.push({ name: "Etype List", value: etypes.join(", ") });
    }
}

function appendKdcOptions(fields, bytes, startIndex) {
    const tlv = readAsn1Tlv(bytes, startIndex);
    if (!tlv) return;
    if (
        tlv.tagInfo.classLabel !== "Context-specific" ||
        tlv.tagInfo.tagNumber !== 0
    ) return;
    // KDCOptions is a BIT STRING (0x03) wrapped directly inside the
    // context tag [0] value bytes. Locate the BIT STRING TLV and read
    // its payload: 1 unused-bits byte followed by N bytes of flag material.
    const inner = readAsn1Tlv(bytes, tlv.valueStart);
    if (!inner || inner.tag !== 0x03) return;
    const slice = bytes.slice(inner.valueStart, inner.valueEnd);
    if (!slice.length) return;
    const unusedBits = slice[0];
    const flagBytes = slice.slice(1);
    if (flagBytes.length > 4) return;
    let combined = 0n;
    for (let offset = 0; offset < flagBytes.length; offset += 1) {
        combined = (combined << 8n) | BigInt(flagBytes[offset]);
    }
    if (unusedBits >= 8) return;
    combined = combined >> BigInt(unusedBits);
    const flagText = formatKdcOptions(combined);
    if (flagText !== null) {
        fields.push({ name: "KDC Options", value: flagText });
    }
}

function appendBodyChecksum(fields, bytes, startIndex) {
    const tlv = readAsn1Tlv(bytes, startIndex);
    if (!tlv) return;
    if (
        tlv.tagInfo.classLabel !== "Context-specific" ||
        tlv.tagInfo.tagNumber !== 7
    ) return;
    const inner = readAsn1Tlv(bytes, tlv.valueStart);
    if (!inner || inner.tag !== 0x02) return;
    const slice = bytes.slice(inner.valueStart, inner.valueEnd);
    fields.push({ name: "Nonce", value: bytesToHexLower(slice) });
}

// Read a context-specific KerberosTime [N] primitive tag and surface it.
// Caller passes the desired label (e.g. "Till", "From", "Rtime") so the same
// helper can handle the three KerberosTime slots in KDC-REQ-BODY.
function appendKerberosTime(fields, bytes, startIndex, label) {
    const tlv = readAsn1Tlv(bytes, startIndex);
    if (!tlv || tlv.tagInfo.classLabel !== "Context-specific") return;
    // The KerberosTime value is a GeneralizedTime TLV (0x18) embedded in the
    // context-tag value bytes.
    const gt = readAsn1GeneralizedTime(bytes, tlv.valueStart);
    if (!gt) return;
    fields.push({ name: label, value: gt.text });
}

function appendTill(fields, bytes, startIndex) {
    // KDC-REQ's `till` is wrapped in a context-specific [5] primitive tag
    // (RFC 4120 §5.4.1). Some legacy encoders also emit it under [4]; the
    // [4] case is already handled by the From scanner, so we only handle
    // [5] here to avoid double-emit.
    const tlv = readAsn1Tlv(bytes, startIndex);
    if (!tlv || tlv.tagInfo.classLabel !== "Context-specific" || tlv.tagInfo.tagNumber !== 5) return;
    const gt = readAsn1GeneralizedTime(bytes, tlv.valueStart);
    if (!gt) return;
    fields.push({ name: "Till", value: gt.text });
}

function appendErrorCode(fields, bytes, startIndex) {
    const tlv = readAsn1Tlv(bytes, startIndex);
    if (!tlv) return;
    if (
        tlv.tagInfo.classLabel !== "Context-specific" ||
        tlv.tagInfo.tagNumber !== 4
    ) return;
    // KRB-ERROR's error-code is wrapped in a context-specific [4] tag and
    // contains an INTEGER (RFC 4120 §5.9.1). We accept either an INTEGER
    // child or a raw primitive payload for robustness.
    const inner = readAsn1Tlv(bytes, tlv.valueStart);
    let valueStart = tlv.valueStart;
    let valueEnd = tlv.valueEnd;
    if (inner && inner.tag === 0x02) {
        valueStart = inner.valueStart;
        valueEnd = inner.valueEnd;
    }
    const length = valueEnd - valueStart;
    if (length >= 1 && length <= 4) {
        let code = 0;
        for (let offset = valueStart; offset < valueEnd; offset += 1) {
            code = (code << 8) | bytes[offset];
        }
        fields.push({ name: "Error Code", value: String(code) });
    } else {
        const text = new TextDecoder("utf-8", { fatal: false })
            .decode(bytes.slice(valueStart, valueEnd))
            .replace(/[^\x20-\x7e]/g, "");
        if (text) {
            pushTruncated(fields, "Error Code", text, KRB_OCTET_STRING_VALUE_LIMIT);
        }
    }
}

function appendEtypeInfo(fields, bytes, startIndex) {
    // ETYPE-INFO2-ENTRY (RFC 4120 §5.2.10) is SEQUENCE { etype [0] INTEGER,
    // salt [1] UTF8String, s2kparams [2] OCTET STRING OPTIONAL }. We only
    // surface etype and salt here so the table stays compact.
    const tlv = readAsn1Tlv(bytes, startIndex);
    if (!tlv || tlv.tag !== 0x30) return;
    let cursor = tlv.valueStart;
    while (cursor < tlv.valueEnd) {
        const inner = readAsn1Tlv(bytes, cursor);
        if (!inner) break;
        if (inner.tagInfo.tagNumber === 0 && inner.tagInfo.classLabel === "Context-specific") {
            const etype = readAsn1Integer(bytes, inner.valueStart);
            if (etype) {
                fields.push({
                    name: "ETYPE-INFO Etype",
                    value: `0x${etype.value.toString(16).padStart(2, "0")} (${etype.value})`,
                });
            }
        } else if (inner.tagInfo.tagNumber === 1 && inner.tagInfo.classLabel === "Context-specific") {
            const salt = new TextDecoder("utf-8", { fatal: false })
                .decode(bytes.slice(inner.valueStart, inner.valueEnd))
                .replace(/[^\x20-\x7e]/g, "");
            if (salt) {
                pushTruncated(fields, "ETYPE-Info Salt", salt, KRB_OCTET_STRING_VALUE_LIMIT);
            }
        }
        cursor = inner.valueEnd;
    }
}

function appendEncryptedPartSummary(fields, bytes, startIndex) {
    // EncryptedData (RFC 4120 §5.2.5) is SEQUENCE { etype [0] INTEGER,
    // kvno [1] INTEGER OPTIONAL, cipher [2] OCTET STRING }. We report
    // etype + a hex preview of the ciphertext.
    const tlv = readAsn1Tlv(bytes, startIndex);
    if (!tlv || tlv.tag !== 0x30) return;
    let cursor = tlv.valueStart;
    while (cursor < tlv.valueEnd) {
        const inner = readAsn1Tlv(bytes, cursor);
        if (!inner) break;
        if (inner.tagInfo.tagNumber === 0 && inner.tagInfo.classLabel === "Context-specific") {
            const etype = readAsn1Integer(bytes, inner.valueStart);
            if (etype) {
                fields.push({
                    name: "Encrypted Part Etype",
                    value: `0x${etype.value.toString(16).padStart(2, "0")} (${etype.value})`,
                });
            }
        } else if (inner.tagInfo.tagNumber === 2 && inner.tagInfo.classLabel === "Context-specific") {
            // cipher is OCTET STRING; the context tag wraps a 0x04 TLV whose
            // value bytes are the actual ciphertext.
            const cipherTlv = readAsn1Tlv(bytes, inner.valueStart);
            const slice = cipherTlv && cipherTlv.tag === 0x04
                ? bytes.slice(cipherTlv.valueStart, cipherTlv.valueEnd)
                : bytes.slice(inner.valueStart, inner.valueEnd);
            const hex = bytesToHexLower(slice);
            const preview = hex.length > 64 ? `${hex.slice(0, 64)}...` : hex;
            fields.push({ name: "Encrypted Part Cipher Preview", value: preview });
        }
        cursor = inner.valueEnd;
    }
}

// Decode a single Kerberos 5 message. Returns an object describing the
// message or null when the bytes don't look like a Kerberos message.
function decodeSingleKerberosMessage(bytes, messageIndex) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 2) return null;
    const tag = bytes[0];
    const msgTypeName = KRB5_MSG_TYPES[tag];
    if (!msgTypeName) return null;

    const tlv = readAsn1Tlv(bytes, 0);
    if (!tlv || tlv.valueEnd > bytes.length) return null;
    const inner = bytes.slice(tlv.valueStart, tlv.valueEnd);

    // The APPLICATION tag wraps a SEQUENCE whose contents (pvno, msg-type,
    // realm, sname, ...) are what we surface. Skip the SEQUENCE header so
    // reads below operate on the SEQUENCE body.
    const seqTlv = readAsn1Tlv(inner, 0);
    const body = seqTlv && seqTlv.tag === 0x30
        ? inner.slice(seqTlv.valueStart, seqTlv.valueEnd)
        : inner;

    // pvno (INTEGER 5) lives at the start of every Kerberos 5 message.
    const pvnoInfo = readAsn1Integer(body, 0);
    const pvno = pvnoInfo ? pvnoInfo.value : null;
    const msgTypeInteger = readAsn1Integer(
        body,
        pvnoInfo ? pvnoInfo.tlv.valueEnd : 0,
    );

    const prefix = `Message ${messageIndex}`;
    const fields = [
        { name: `${prefix} Message Type`, value: msgTypeName },
    ];
    if (pvno !== null) {
        fields.push({ name: `${prefix} Protocol Version`, value: String(pvno) });
    }
    if (msgTypeInteger) {
        const wire = msgTypeInteger.value;
        if (wire >= 0x6a && wire <= 0x7a) {
            fields.push({
                name: `${prefix} Wire Msg-Type`,
                value: `0x${wire.toString(16).padStart(2, "0").toUpperCase()} (${KRB5_MSG_TYPES[wire] || "unknown"})`,
            });
        }
    }

    // Walk the rest of the inner bytes looking for high-value fields
    // without trying to enforce the full RFC 4120 grammar.
    let cursor = pvnoInfo ? pvnoInfo.tlv.valueEnd : 0;
    if (msgTypeInteger) {
        cursor = Math.max(cursor, msgTypeInteger.tlv.valueEnd);
    }

    // KDC-REQ-BODY: kdc-options [0] BIT STRING, cname [1] PrincipalName
    // OPTIONAL, realm [2] GeneralString, sname [3] PrincipalName,
    // from [4] KerberosTime OPTIONAL, till [5] KerberosTime,
    // rtime [6] KerberosTime OPTIONAL, nonce [7] UInt32,
    // etype [8] SEQUENCE OF Int32 OPTIONAL (RFC 4120 §5.4.1).
    //
    // We walk the body linearly: every context-specific tag in [0..8] is
    // matched against the KDC-REQ-BODY slot, with a small tolerance for
    // misordered or legacy encodings.
    if (msgTypeName === "AS-REQ" || msgTypeName === "TGS-REQ") {
        const principalTagNumbers = new Set([1, 3]); // cname [1] / sname [3]
        const scanEnd = Math.min(body.length, cursor + 220);
        for (let scan = cursor; scan < scanEnd;) {
            const t = readAsn1Tlv(body, scan);
            if (!t) break;
            if (t.tagInfo.classLabel !== "Context-specific") {
                scan = t.valueEnd;
                continue;
            }
            if (t.tagInfo.tagNumber === 0) {
                appendKdcOptions(fields, body, scan);
            } else if (principalTagNumbers.has(t.tagInfo.tagNumber)) {
                const principal = readPrincipalName(body, t.valueStart);
                if (principal && principal.nameStrings.length) {
                    const slot = t.tagInfo.tagNumber;
                    const labelName = slot === 1 ? "Cname" : "Sname";
                    pushTruncated(
                        fields,
                        `${prefix} ${labelName}`,
                        `${principal.nameType}:${formatPrincipal(principal.nameStrings)}`,
                        PRINCIPAL_VALUE_LIMIT,
                    );
                }
            } else if (t.tagInfo.tagNumber === 2) {
                const realm = new TextDecoder("utf-8", { fatal: false })
                    .decode(body.slice(t.valueStart, t.valueEnd))
                    .replace(/[^\x20-\x7e]/g, "");
                if (realm) {
                    fields.push({ name: `${prefix} Realm`, value: realm });
                }
            } else if (t.tagInfo.tagNumber === 4) {
                appendKerberosTime(fields, body, scan, "From");
            } else if (t.tagInfo.tagNumber === 5) {
                appendKerberosTime(fields, body, scan, "Till");
            } else if (t.tagInfo.tagNumber === 6) {
                appendKerberosTime(fields, body, scan, "Rtime");
            } else if (t.tagInfo.tagNumber === 7) {
                appendBodyChecksum(fields, body, scan);
            } else if (t.tagInfo.tagNumber === 8) {
                appendEtypeList(fields, body, scan);
            } else if (t.tagInfo.tagNumber > 8) {
                // Past the optional etype list the KDC-REQ-BODY has addresses [9],
                // enc-authorization [10], additional-tickets [11]. Stop scanning
                // so we don't mislabel them.
                break;
            }
            scan = t.valueEnd;
        }
    } else if (msgTypeName === "AS-REP" || msgTypeName === "TGS-REP") {
        // KDC-REP after pvno/msg-type: crealm [3] Realm OPTIONAL,
        // cname [4] PrincipalName, ticket [5] Ticket,
        // enc-part [6] EncryptedData (RFC 4120 §5.3.2).
        const tagCursorEnd = Math.min(cursor + 220, body.length);
        for (let scan = cursor; scan < tagCursorEnd;) {
            const t = readAsn1Tlv(body, scan);
            if (!t) break;
            if (t.tagInfo.classLabel !== "Context-specific") {
                scan = t.valueEnd;
                continue;
            }
            if (t.tagInfo.tagNumber === 3) {
                const realm = new TextDecoder("utf-8", { fatal: false })
                    .decode(body.slice(t.valueStart, t.valueEnd))
                    .replace(/[^\x20-\x7e]/g, "");
                if (realm) {
                    fields.push({ name: `${prefix} Realm`, value: realm });
                }
            } else if (t.tagInfo.tagNumber === 4) {
                const principal = readPrincipalName(body, t.valueStart);
                if (principal && principal.nameStrings.length) {
                    pushTruncated(
                        fields,
                        `${prefix} Cname`,
                        `${principal.nameType}:${formatPrincipal(principal.nameStrings)}`,
                        PRINCIPAL_VALUE_LIMIT,
                    );
                }
            } else if (t.tagInfo.tagNumber === 5) {
                // Ticket (APPLICATION 0 SEQUENCE) — surface its tkt-vno/realm.
                const ticketRaw = t.valueEnd <= t.valueStart
                    ? new Uint8Array(0)
                    : body.slice(t.valueStart, t.valueEnd);
                const ticketSeqTlv = readAsn1Tlv(ticketRaw, 0);
                const ticketInner = ticketSeqTlv && ticketSeqTlv.tag === 0x30
                    ? ticketRaw.slice(ticketSeqTlv.valueStart, ticketSeqTlv.valueEnd)
                    : ticketRaw;
                const ticketPvno = readAsn1Integer(ticketInner, 0);
                if (ticketPvno) {
                    fields.push({ name: `${prefix} Ticket tkt-vno`, value: String(ticketPvno.value) });
                }
                // Ticket SEQUENCE OF { tkt-vno, realm [0], sname [1] ... }
                const ticketRealmTlv = readAsn1Tlv(ticketInner, ticketPvno ? ticketPvno.tlv.valueEnd : 0);
                if (ticketRealmTlv && ticketRealmTlv.tagInfo.classLabel === "Context-specific" && ticketRealmTlv.tagInfo.tagNumber === 0) {
                    const ticketRealm = new TextDecoder("utf-8", { fatal: false })
                        .decode(ticketInner.slice(ticketRealmTlv.valueStart, ticketRealmTlv.valueEnd))
                        .replace(/[^\x20-\x7e]/g, "");
                    if (ticketRealm) {
                        fields.push({ name: `${prefix} Ticket Realm`, value: ticketRealm });
                    }
                }
            } else if (t.tagInfo.tagNumber === 6) {
                const encPartInner = t.valueEnd <= t.valueStart
                    ? new Uint8Array(0)
                    : body.slice(t.valueStart, t.valueEnd);
                const etypeInfoEntryTlv = readAsn1Tlv(encPartInner, 0);
                if (etypeInfoEntryTlv && etypeInfoEntryTlv.tag === 0x30) {
                    appendEncryptedPartSummary(fields, encPartInner, 0);
                }
            } else if (t.tagInfo.tagNumber > 6) {
                // enc-kdc-rep-part [7] only appears in a KDC-REP context, and is
                // not surfaced here. Stop scanning so we don't mislabel.
                break;
            }
            scan = t.valueEnd;
        }
    } else if (msgTypeName === "AP-REQ") {
        // AP-REQ after pvno/msg-type: ap-options [2] APOptions,
        // ticket [3] Ticket, authenticator [4] EncryptedData
        // (RFC 4120 §5.5.1).
        const tagCursorEnd = Math.min(cursor + 220, body.length);
        for (let scan = cursor; scan < tagCursorEnd;) {
            const t = readAsn1Tlv(body, scan);
            if (!t) break;
            if (t.tagInfo.classLabel === "Context-specific") {
                if (t.tagInfo.tagNumber === 2) {
                    fields.push({ name: `${prefix} AP Options Present`, value: "yes" });
                } else if (t.tagInfo.tagNumber === 3) {
                    fields.push({ name: `${prefix} Ticket Present`, value: "yes" });
                } else if (t.tagInfo.tagNumber === 4) {
                    const encPartInner = t.valueEnd <= t.valueStart
                        ? new Uint8Array(0)
                        : body.slice(t.valueStart, t.valueEnd);
                    const etypeInfoEntryTlv = readAsn1Tlv(encPartInner, 0);
                    if (etypeInfoEntryTlv && etypeInfoEntryTlv.tag === 0x30) {
                        appendEncryptedPartSummary(fields, encPartInner, 0);
                    }
                } else if (t.tagInfo.tagNumber > 4) {
                    break;
                }
            }
            scan = t.valueEnd;
        }
    } else if (msgTypeName === "AP-REP" || msgTypeName === "KRB-PRIV" || msgTypeName === "KRB-CRED") {
        // For these, the enc-part etype + a hex preview is the most useful
        // information users can act on. RFC 4120 §5.4.2 / §5.7.1 / §5.8.1
        // place enc-part at varying context tags; we scan a small window and
        // pick the last context-specific tag that wraps a SEQUENCE.
        const tagCursorEnd = Math.min(cursor + 220, body.length);
        let lastEncPartTlv = null;
        for (let scan = cursor; scan < tagCursorEnd;) {
            const t = readAsn1Tlv(body, scan);
            if (!t) break;
            if (t.tagInfo.classLabel === "Context-specific") {
                const inner = t.valueEnd <= t.valueStart
                    ? new Uint8Array(0)
                    : body.slice(t.valueStart, t.valueEnd);
                const seqPeek = readAsn1Tlv(inner, 0);
                if (seqPeek && seqPeek.tag === 0x30) {
                    lastEncPartTlv = t;
                }
                if (t.tagInfo.tagNumber > 8) {
                    break;
                }
            }
            scan = t.valueEnd;
        }
        if (lastEncPartTlv) {
            const encPartInner = lastEncPartTlv.valueEnd <= lastEncPartTlv.valueStart
                ? new Uint8Array(0)
                : body.slice(lastEncPartTlv.valueStart, lastEncPartTlv.valueEnd);
            appendEncryptedPartSummary(fields, encPartInner, 0);
        }
    } else if (msgTypeName === "KRB-ERROR") {
        // KRB-ERROR after pvno/msg-type: error-code [4] Int32, cname [6]
        // PrincipalName OPTIONAL, e-text [9] GeneralString, e-data [10] OCTET
        // STRING (RFC 4120 §5.9.1).
        const tagCursorEnd = Math.min(cursor + 220, body.length);
        for (let scan = cursor; scan < tagCursorEnd;) {
            const t = readAsn1Tlv(body, scan);
            if (!t) break;
            if (t.tagInfo.classLabel === "Context-specific") {
                if (t.tagInfo.tagNumber === 4) {
                    appendErrorCode(fields, body, scan);
                } else if (t.tagInfo.tagNumber === 6) {
                    const principal = readPrincipalName(body, t.valueStart);
                    if (principal && principal.nameStrings.length) {
                        pushTruncated(
                            fields,
                            `${prefix} Cname`,
                            `${principal.nameType}:${formatPrincipal(principal.nameStrings)}`,
                            PRINCIPAL_VALUE_LIMIT,
                        );
                    }
                } else if (t.tagInfo.tagNumber === 9) {
                    const text = new TextDecoder("utf-8", { fatal: false })
                        .decode(body.slice(t.valueStart, t.valueEnd))
                        .replace(/[^\x20-\x7e]/g, "");
                    if (text) {
                        pushTruncated(fields, `${prefix} Error Text`, text, KRB_OCTET_STRING_VALUE_LIMIT);
                    }
                } else if (t.tagInfo.tagNumber === 10) {
                    // e-data is typically an ETYPE-INFO2 sequence.
                    appendEtypeInfo(fields, body, scan);
                } else if (t.tagInfo.tagNumber > 10) {
                    break;
                }
            }
            scan = t.valueEnd;
        }
    }

    return { msgTypeName, fields };
}

function decodeKerberosFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 2) return null;

    // Detect a TCP length-record prefix (RFC 4120 §5.1): if the first 4
    // bytes look like a big-endian record length and they account for the
    // remainder of the payload, strip them.
    let payload = bytes;
    if (bytes.length >= 5) {
        const recordLength =
            (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
        if (
            recordLength > 0 &&
            recordLength + 4 === bytes.length &&
            KRB5_MSG_TYPES[bytes[4]]
        ) {
            payload = bytes.slice(4);
        }
    }

    if (!KRB5_MSG_TYPES[payload[0]]) return null;

    try {
        const fields = [];
        let messageCount = 0;
        let cursor = 0;
        while (cursor < payload.length && messageCount < MAX_KRB5_MESSAGES) {
            const decoded = decodeSingleKerberosMessage(
                payload.subarray(cursor),
                messageCount + 1,
            );
            if (!decoded) break;
            messageCount += 1;
            decoded.fields.forEach((field) => fields.push(field));
            // Advance past the message we just decoded. The single-message
            // helper already validated that the TLV fits in the slice.
            const tlv = readAsn1Tlv(payload, cursor);
            if (!tlv) break;
            cursor = tlv.valueEnd;
        }

        if (!messageCount) return null;
        if (messageCount >= MAX_KRB5_MESSAGES && cursor < payload.length) {
            fields.push({
                name: "Notice",
                value: `Showing first ${MAX_KRB5_MESSAGES} Kerberos messages from stream.`,
            });
        }

        return {
            protocol: "Kerberos",
            fields,
        };
    } catch {
        return null;
    }
}

module.exports = { decodeKerberosFromBytes };
