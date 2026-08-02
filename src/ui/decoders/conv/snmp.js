// SNMP Conv decoder: parses BER-encoded SNMPv1/v2c/v3 PDUs from raw bytes.
// The decoder uses the shared parseAsn1Length + decodeBerFromBytes helpers
// for length / TLV walking, then layers the SNMP message grammar on top
// (RFC 3411 / RFC 3416 / RFC 3417 / RFC 3418): a SEQUENCE-wrapped
// message whose first INTEGER is the version, followed by the community
// string (v1/v2c) or msgSecurityParameters (v3), then a PDU (request-id,
// error-status, error-index, VarBind list).

const { parseAsn1Length } = require("./asn1");
const { bytesToHexLower } = require("./smb-helpers");

const MAX_OID_LENGTH = 256;
const MAX_VARBINDS = 64;
const SNMP_OCTET_STRING_VALUE_LIMIT = 220;
const SNMP_OID_VALUE_LIMIT = 220;

// Common MIB OID prefixes used to shorten common VarBind OIDs.
const MIB_PREFIXES = [
    { prefix: "1.3.6.1.2.1.1", label: "system" },
    { prefix: "1.3.6.1.2.1.2", label: "interfaces" },
    { prefix: "1.3.6.1.2.1.3", label: "at" },
    { prefix: "1.3.6.1.2.1.4", label: "ip" },
    { prefix: "1.3.6.1.2.1.5", label: "icmp" },
    { prefix: "1.3.6.1.2.1.6", label: "tcp" },
    { prefix: "1.3.6.1.2.1.7", label: "udp" },
    { prefix: "1.3.6.1.2.1.10", label: "transmission" },
    { prefix: "1.3.6.1.2.1.11", label: "snmp" },
    { prefix: "1.3.6.1.4.1", label: "enterprise" },
];

// A small named-MIB lookup for system + interfaces OIDs that show up in
// nearly every SNMP walk. Values are taken from RFC 1213 + RFC 3418.
const MIB_NAMED_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr.0",
    "1.3.6.1.2.1.1.2.0": "sysObjectID.0",
    "1.3.6.1.2.1.1.3.0": "sysUpTime.0",
    "1.3.6.1.2.1.1.4.0": "sysContact.0",
    "1.3.6.1.2.1.1.5.0": "sysName.0",
    "1.3.6.1.2.1.1.6.0": "sysLocation.0",
    "1.3.6.1.2.1.1.7.0": "sysServices.0",
    "1.3.6.1.2.1.2.1.0": "ifNumber.0",
    "1.3.6.1.2.1.2.2.1.1": "ifIndex",
    "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    "1.3.6.1.2.1.2.2.1.3": "ifType",
    "1.3.6.1.2.1.2.2.1.4": "ifMtu",
    "1.3.6.1.2.1.2.2.1.5": "ifSpeed",
    "1.3.6.1.2.1.2.2.1.6": "ifPhysAddress",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    "1.3.6.1.2.1.4.1.0": "ipForwarding.0",
    "1.3.6.1.2.1.4.2.0": "ipDefaultTTL.0",
    "1.3.6.1.2.1.4.3.0": "ipInReceives.0",
    "1.3.6.1.2.1.5.1.0": "icmpInMsgs.0",
    "1.3.6.1.2.1.6.1.0": "tcpRtoAlgorithm.0",
    "1.3.6.1.2.1.6.2.0": "tcpRtoMin.0",
    "1.3.6.1.2.1.7.1.0": "udpInDatagrams.0",
    "1.3.6.1.2.1.11.1.0": "snmpInPkts.0",
    "1.3.6.1.2.1.11.2.0": "snmpOutPkts.0",
    "1.3.6.1.2.1.11.3.0": "snmpInBadVersions.0",
    "1.3.6.1.2.1.11.4.0": "snmpInBadCommunityNames.0",
    "1.3.6.1.2.1.11.5.0": "snmpInBadCommunityUses.0",
};

const SNMP_PDU_TYPES = {
    0xa0: "GetRequest",
    0xa1: "GetNextRequest",
    0xa2: "Response",
    0xa3: "SetRequest",
    0xa4: "Trap",
    0xa5: "GetBulkRequest",
    0xa6: "InformRequest",
    0xa7: "SNMPv2-Trap",
    0xa8: "Report",
};

const SNMP_ERROR_STATUS_NAMES = {
    0: "noError",
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "noSuchObject",
    13: "noSuchInstance",
    14: "endOfMibView",
    15: "inconsistentValue",
    16: "resourceUnavailable",
    17: "commitFailed",
    18: "undoFailed",
    19: "authorizationError",
    20: "notWritable",
    21: "inconsistentName",
};

const SNMP_ASN1_TAGS = {
    BOOLEAN: 0x01,
    INTEGER: 0x02,
    BIT_STRING: 0x03,
    OCTET_STRING: 0x04,
    NULL: 0x05,
    OID: 0x06,
    SEQUENCE: 0x30,
};

const SNMP_VERSION_NAMES = {
    0: "SNMPv1",
    1: "SNMPv2c",
    2: "SNMPv2u",
    3: "SNMPv3",
};

function pushTruncated(fields, name, value, limit) {
    if (typeof value !== "string" || !value) return;
    const trimmed = value.length > limit ? `${value.slice(0, limit)}...` : value;
    fields.push({ name, value: trimmed });
}

// Read an ASN.1 TLV (TL + value slice) at startIndex. Returns
// { tag, valueStart, valueEnd, length } or null on out-of-bounds.
function readTlv(bytes, startIndex) {
    if (!(bytes instanceof Uint8Array) || startIndex < 0 || startIndex + 2 > bytes.length) {
        return null;
    }
    const tag = bytes[startIndex];
    const lengthInfo = parseAsn1Length(bytes, startIndex + 1, bytes.length);
    if (!lengthInfo) return null;
    const valueStart = lengthInfo.nextIndex;
    const valueEnd = valueStart + lengthInfo.length;
    if (valueEnd > bytes.length) return null;
    return { tag, valueStart, valueEnd, length: lengthInfo.length };
}

function readAsn1Integer(bytes, startIndex) {
    const tlv = readTlv(bytes, startIndex);
    if (!tlv || tlv.tag !== SNMP_ASN1_TAGS.INTEGER) return null;
    if (tlv.length < 1 || tlv.length > 6) return null;
    if (tlv.length > 1 && (bytes[tlv.valueStart] & 0x80) !== 0) return null;
    let value = 0;
    for (let offset = tlv.valueStart; offset < tlv.valueEnd; offset += 1) {
        value = (value << 8) | bytes[offset];
    }
    return { value, tlv };
}

function readOctetString(bytes, startIndex) {
    const tlv = readTlv(bytes, startIndex);
    if (!tlv || tlv.tag !== SNMP_ASN1_TAGS.OCTET_STRING) return null;
    const slice = bytes.slice(tlv.valueStart, tlv.valueEnd);
    let text = "";
    try {
        text = new TextDecoder("utf-8", { fatal: false }).decode(slice);
    } catch {
        text = "";
    }
    text = text.replace(/[^\x20-\x7e]/g, "");
    return { text, hex: bytesToHexLower(slice), tlv };
}

function decodeOid(bytes, startIndex) {
    const tlv = readTlv(bytes, startIndex);
    if (!tlv || tlv.tag !== SNMP_ASN1_TAGS.OID) return null;
    if (tlv.length < 1) return null;
    // First two components are encoded as 40 * first + second (RFC 2578 §3).
    const firstByte = bytes[tlv.valueStart];
    const firstComponent = Math.floor(firstByte / 40);
    const secondComponent = firstByte % 40;
    const components = [firstComponent, secondComponent];
    let value = 0;
    for (let offset = tlv.valueStart + 1; offset < tlv.valueEnd; offset += 1) {
        const byte = bytes[offset];
        value = (value << 7) | (byte & 0x7f);
        if ((byte & 0x80) === 0) {
            components.push(value);
            value = 0;
            if (components.length > MAX_OID_LENGTH) break;
        }
    }
    const oid = components.join(".");
    return { oid, tlv };
}

function lookupMibName(oid) {
    if (!oid) return "";
    if (Object.prototype.hasOwnProperty.call(MIB_NAMED_OIDS, oid)) {
        return MIB_NAMED_OIDS[oid];
    }
    for (const entry of MIB_PREFIXES) {
        if (oid === entry.prefix) return entry.label;
        if (oid.startsWith(`${entry.prefix}.`)) {
            return `${entry.label}.${oid.slice(entry.prefix.length + 1)}`;
        }
    }
    return "";
}

function formatIntegerValue(bytes, valueStart, valueEnd) {
    let value = 0n;
    for (let offset = valueStart; offset < valueEnd; offset += 1) {
        value = (value << 8n) | BigInt(bytes[offset]);
    }
    return value.toString(10);
}

function formatValuePreview(bytes, tlv) {
    if (!tlv) return "";
    switch (tlv.tag) {
        case SNMP_ASN1_TAGS.INTEGER:
            return formatIntegerValue(bytes, tlv.valueStart, tlv.valueEnd);
        case SNMP_ASN1_TAGS.OCTET_STRING: {
            const slice = bytes.slice(tlv.valueStart, tlv.valueEnd);
            let text = "";
            try {
                text = new TextDecoder("utf-8", { fatal: false }).decode(slice);
            } catch {
                text = "";
            }
            if (/^[\x20-\x7e]+$/.test(text)) return `"${text}"`;
            return bytesToHexLower(slice);
        }
        case SNMP_ASN1_TAGS.OID: {
            const result = decodeOid(bytes, tlv.valueStart - 1);
            if (result) return result.oid;
            return bytesToHexLower(bytes.slice(tlv.valueStart, tlv.valueEnd));
        }
        case SNMP_ASN1_TAGS.NULL:
            return "NULL";
        case SNMP_ASN1_TAGS.BOOLEAN:
            return tlv.length > 0 && bytes[tlv.valueStart] !== 0 ? "true" : "false";
        case SNMP_ASN1_TAGS.BIT_STRING: {
            if (tlv.length < 1) return "";
            const unused = bytes[tlv.valueStart];
            const slice = bytes.slice(tlv.valueStart + 1, tlv.valueEnd);
            return `bits(unused=${unused}) ${bytesToHexLower(slice)}`;
        }
        default:
            return bytesToHexLower(bytes.slice(tlv.valueStart, tlv.valueEnd));
    }
}

function decodeSnmpFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4) return null;

    // The outermost container must be a SEQUENCE.
    const outer = readTlv(bytes, 0);
    if (!outer || outer.tag !== SNMP_ASN1_TAGS.SEQUENCE) return null;
    const inner = bytes.slice(outer.valueStart, outer.valueEnd);

    // Version: INTEGER immediately after the outer SEQUENCE.
    const versionInfo = readAsn1Integer(inner, 0);
    if (!versionInfo) return null;
    const version = versionInfo.value;
    const versionName = SNMP_VERSION_NAMES[version] || `version(${version})`;

    const fields = [];
    fields.push({ name: "SNMP Version", value: versionName });
    if (version === 0 || version === 1) {
        // SNMPv1 / SNMPv2c: OCTET STRING community follows.
        const community = readOctetString(inner, versionInfo.tlv.valueEnd);
        if (community) {
            pushTruncated(fields, "Community", community.text || community.hex, SNMP_OCTET_STRING_VALUE_LIMIT);
        }
    } else if (version === 3) {
        // SNMPv3 message SEQUENCE { msgVersion, msgGlobalData, msgSecurityParameters, ... }
        // We surface a hex preview of the security parameters and let the rest
        // fall through to the standard PDU walk.
        const globalDataTlv = readTlv(inner, versionInfo.tlv.valueEnd);
        if (globalDataTlv) {
            const globalDataSlice = inner.slice(globalDataTlv.valueStart, globalDataTlv.valueEnd);
            pushTruncated(
                fields,
                "Global Data (hex)",
                bytesToHexLower(globalDataSlice),
                SNMP_OCTET_STRING_VALUE_LIMIT,
            );
        }
        if (globalDataTlv) {
            const secParamsTlv = readTlv(inner, globalDataTlv.valueEnd);
            if (secParamsTlv && secParamsTlv.tag === SNMP_ASN1_TAGS.OCTET_STRING) {
                const secSlice = inner.slice(secParamsTlv.valueStart, secParamsTlv.valueEnd);
                pushTruncated(
                    fields,
                    "Security Parameters (hex)",
                    bytesToHexLower(secSlice),
                    SNMP_OCTET_STRING_VALUE_LIMIT,
                );
            }
        }
    }

    // Walk forward to the next PDU. PDU tags are context-specific constructed
    // (0xA0..0xA8). We scan the inner bytes for the first such tag that has
    // a parseable INTEGER (request-id) following it.
    let pduStart = versionInfo.tlv.valueEnd;
    if (version === 3) {
        // Skip the SNMPv3 message header: globalData OCTET STRING, security
        // params OCTET STRING, then optionally a scoped PDU SEQUENCE wrapper.
        // We advance one byte at a time until we hit a recognizable PDU tag.
        let pduScan = pduStart;
        while (pduScan < inner.length) {
            const tlv = readTlv(inner, pduScan);
            if (!tlv) break;
            if (SNMP_PDU_TYPES[tlv.tag]) {
                pduStart = pduScan;
                break;
            }
            pduScan = tlv.valueEnd;
        }
    } else {
        // v1/v2c: skip the community OCTET STRING then we should be on a PDU.
        const community = readTlv(inner, pduStart);
        if (community && SNMP_PDU_TYPES[community.tag]) {
            // The community was actually a (malformed) PDU tag; back up.
        } else if (community) {
            pduStart = community.valueEnd;
        }
    }

    const pduTlv = readTlv(inner, pduStart);
    if (!pduTlv || !SNMP_PDU_TYPES[pduTlv.tag]) return null;
    const pduTypeName = SNMP_PDU_TYPES[pduTlv.tag];
    fields.push({ name: "PDU Type", value: pduTypeName });

    const pduBody = inner.slice(pduTlv.valueStart, pduTlv.valueEnd);
    const requestIdInfo = readAsn1Integer(pduBody, 0);
    if (requestIdInfo) {
        fields.push({ name: "Request ID", value: String(requestIdInfo.value) });
    }
    const errorStatusInfo = readAsn1Integer(
        pduBody,
        requestIdInfo ? requestIdInfo.tlv.valueEnd : 0,
    );
    if (errorStatusInfo) {
        const name = SNMP_ERROR_STATUS_NAMES[errorStatusInfo.value] || `errorStatus(${errorStatusInfo.value})`;
        fields.push({ name: "Error Status", value: `${name} (${errorStatusInfo.value})` });
    }
    const errorIndexInfo = readAsn1Integer(
        pduBody,
        errorStatusInfo ? errorStatusInfo.tlv.valueEnd : 0,
    );
    if (errorIndexInfo) {
        fields.push({ name: "Error Index", value: String(errorIndexInfo.value) });
    }

    // VarBind list: SEQUENCE OF VarBind (SEQUENCE { name OID, value ANY }).
    const varBindsTlv = readTlv(
        pduBody,
        errorIndexInfo ? errorIndexInfo.tlv.valueEnd : 0,
    );
    if (varBindsTlv && varBindsTlv.tag === SNMP_ASN1_TAGS.SEQUENCE) {
        let cursor = varBindsTlv.valueStart;
        let varBindIndex = 0;
        while (cursor < varBindsTlv.valueEnd && varBindIndex < MAX_VARBINDS) {
            const varBindTlv = readTlv(pduBody, cursor);
            if (!varBindTlv || varBindTlv.tag !== SNMP_ASN1_TAGS.SEQUENCE) break;
            const oidResult = decodeOid(pduBody, varBindTlv.valueStart);
            if (!oidResult) break;
            const namedMib = lookupMibName(oidResult.oid);
            const valueTlv = readTlv(pduBody, oidResult.tlv.valueEnd);
            if (!valueTlv) break;
            const valuePreview = formatValuePreview(pduBody, valueTlv);
            varBindIndex += 1;
            const labelName = namedMib
                ? `VarBind ${varBindIndex} (${namedMib})`
                : `VarBind ${varBindIndex}`;
            let summary = `${oidResult.oid} = ${valuePreview}`;
            if (namedMib) {
                summary = `${namedMib} (${oidResult.oid}) = ${valuePreview}`;
            }
            pushTruncated(fields, labelName, summary, SNMP_OID_VALUE_LIMIT);
            cursor = varBindTlv.valueEnd;
        }
        if (varBindIndex >= MAX_VARBINDS) {
            fields.push({
                name: "Notice",
                value: `Showing first ${MAX_VARBINDS} VarBinds from stream.`,
            });
        }
    }

    return { protocol: "SNMP", fields };
}

module.exports = { decodeSnmpFromBytes };
