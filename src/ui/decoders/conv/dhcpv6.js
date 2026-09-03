// DHCPv6 Conv decoder: walks an RFC 8415/3315 DHCPv6 message stream. The
// first 4 bytes are msg-type (1) + transaction-id (3) followed by a TLV
// option stream where each option is 16-bit option-code + 16-bit option-
// length. Nested options (IA_NA, IA_TA, IAADDR, relay-message) are walked
// recursively with proper length handling, and status-code sub-options are
// resolved to their symbolic name.

const { bytesToHexLower } = require("./smb-helpers");

const DHCPV6_MAX_OPTIONS = 256;
const DHCPV6_TEXT_LIMIT = 220;

const DHCPV6_MESSAGE_TYPES = {
    1: "SOLICIT",
    2: "ADVERTISE",
    3: "REQUEST",
    4: "CONFIRM",
    5: "RENEW",
    6: "REBIND",
    7: "REPLY",
    8: "RELEASE",
    9: "DECLINE",
    10: "RECONFIGURE",
    11: "INFORMATION-REQUEST",
    12: "RELAY-FORW",
    13: "RELAY-REPL",
    14: "LEASEQUERY",
    15: "LEASEQUERY-REPLY",
    16: "LEASEQUERY-DATA",
    17: "LEASEQUERY-ACKNOW",
    18: "RECONFIGURE-REQUEST",
    19: "RECONFIGURE-REPLY",
    20: "DHCPV4-QUERY",
    21: "DHCPV4-RESPONSE",
    22: "ACTIVE-LEASEQUERY",
    23: "STARTTLS",
    24: "BULKLEASEQUERY",
    25: "BULKLEASEQUERY-REPLY",
    26: "LEASEQUERY-STATUS",
    27: "TLS-AKA",
};

const DHCPV6_STATUS_CODE_NAMES = {
    0: "Success",
    1: "UnspecFail",
    2: "NoAddrsAvail",
    3: "NoBinding",
    4: "NotOnLink",
    5: "UseMulticast",
    6: "NoPrefixAvail",
    7: "UnknownQueryType",
    8: "MalformedQuery",
    9: "NotConfigured",
    10: "NotAllowed",
    11: "QueryTerminated",
    12: "DataMissing",
    13: "CatchUpComplete",
    14: "NotSupported",
    15: "TLSConnectionRefused",
};

const DHCPV6_OPTION_NAMES = {
    1: "client-id",
    2: "server-id",
    3: "ia-na",
    4: "ia-ta",
    5: "iaaddr",
    6: "oro",
    7: "preference",
    8: "elapsed-time",
    9: "relay-msg",
    10: "unicast",
    11: "status-code",
    12: "rapid-commit",
    13: "user-class",
    14: "vendor-class",
    15: "vendor-opts",
    16: "interface-id",
    17: "reconf-msg",
    18: "reconf-accept",
    19: "sip-server-domain-name-list",
    20: "sip-server-address-list",
    21: "dns-servers",
    22: "domain-list",
    23: "ia-pd",
    24: "ia-prefix",
    25: "nis-servers",
    26: "nisp-servers",
    27: "nis-domain-name",
    28: "nisp-domain-name",
    29: "sntp-servers",
    30: "information-refresh-time",
    31: "nsearch-list",
    32: "vendor-specific",
    33: "fully-qualified-domain-name",
    34: "pana-agent",
    35: "new-posix-timezone",
    36: "new-posix-timezone-name",
    37: "echo-request",
    38: "leasequery",
    39: "lq-query",
    40: "client-data",
    41: "clt-time",
    42: "lq-relay-data",
    43: "lq-client-link",
    44: "vss",
    45: "reconfigure-accept",
    46: "sip-server-address-list",
    47: "ipv6-address-orset",
    48: "ipv6-address-moset",
    49: "ipv6-address-rset",
    50: "dns-servers-search-list",
    51: "lease-information",
    52: "client-link-address",
    53: "sysname",
    54: "client-last-transaction-time",
    55: "fqdn-name",
    56: "ipv6-routing",
    57: "interface-id",
    58: "reconfigure-msg",
    59: "reconfigure-accept",
    60: "auth",
    64: "captive-portal",
    65: "ipv6-feature-profile",
    66: "v6-captive-portal",
    67: "ipv6-captive-portal",
};

const DHCPV6_IA_NA_OPTION_CODES = new Set([3]);
const DHCPV6_IA_TA_OPTION_CODES = new Set([4]);
const DHCPV6_IAADDR_OPTION_CODES = new Set([5]);
const DHCPV6_RELAY_MSG_OPTION_CODES = new Set([9]);
const DHCPV6_VENDOR_OPTS_OPTION_CODES = new Set([15, 17]);
const DHCPV6_PREFIX_OPTION_CODES = new Set([24]);

function pushTruncated(fields, name, value, limit) {
    if (typeof value !== "string" || !value) return;
    const trimmed = value.length > limit ? `${value.slice(0, limit)}...` : value;
    fields.push({ name, value: trimmed });
}

function formatTextBytes(bytes, offset, length) {
    if (!(bytes instanceof Uint8Array)) return "";
    const slice = bytes.slice(offset, offset + length);
    let text = "";
    try {
        text = new TextDecoder("utf-8", { fatal: false }).decode(slice);
    } catch {
        text = bytesToHexLower(slice);
    }
    return text.replace(/[^\x20-\x7e]/g, "");
}

function formatHexBytes(bytes, offset, length) {
    if (!(bytes instanceof Uint8Array)) return "";
    return bytesToHexLower(bytes.slice(offset, offset + length));
}

function formatIpv6(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 16 > bytes.length) return null;
    const groups = [];
    for (let i = 0; i < 16; i += 2) {
        groups.push(((bytes[offset + i] << 8) | bytes[offset + i + 1]).toString(16));
    }
    let bestStart = -1;
    let bestLength = 0;
    let currentStart = -1;
    let currentLength = 0;
    groups.forEach((group, index) => {
        if (group === "0") {
            if (currentStart === -1) currentStart = index;
            currentLength += 1;
            if (currentLength > bestLength) {
                bestStart = currentStart;
                bestLength = currentLength;
            }
        } else {
            currentStart = -1;
            currentLength = 0;
        }
    });
    if (bestLength < 2) return groups.join(":");
    const head = groups.slice(0, bestStart).join(":");
    const tail = groups.slice(bestStart + bestLength).join(":");
    return `${head}::${tail}`;
}

function readUint16(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 2 > bytes.length) return null;
    return (bytes[offset] << 8) | bytes[offset + 1];
}

function readUint32(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 4 > bytes.length) return null;
    return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function formatOptionValue(optionCode, bytes, offset, length) {
    if (!(bytes instanceof Uint8Array)) return "";
    if (length === 0) return "(empty)";
    // IA_NA / IA_TA / IA_PD: 32-bit IAID + 32-bit T1 + 32-bit T2 + nested
    if (DHCPV6_IA_NA_OPTION_CODES.has(optionCode) || DHCPV6_IA_TA_OPTION_CODES.has(optionCode)) {
        if (length < 12) return formatHexBytes(bytes, offset, length);
        const iaid = readUint32(bytes, offset);
        const t1 = readUint32(bytes, offset + 4);
        const t2 = readUint32(bytes, offset + 8);
        if (iaid === null || t1 === null || t2 === null) return formatHexBytes(bytes, offset, length);
        return `IAID=${iaid} T1=${t1} T2=${t2}`;
    }
    if (DHCPV6_IAADDR_OPTION_CODES.has(optionCode) || DHCPV6_PREFIX_OPTION_CODES.has(optionCode)) {
        if (length < 24) return formatHexBytes(bytes, offset, length);
        const address = formatIpv6(bytes, offset);
        const preferredLifetime = readUint32(bytes, offset + 16);
        const validLifetime = readUint32(bytes, offset + 20);
        if (!address || preferredLifetime === null || validLifetime === null) {
            return formatHexBytes(bytes, offset, length);
        }
        return `address=${address} preferred=${preferredLifetime} valid=${validLifetime}`;
    }
    if (optionCode === 1 || optionCode === 2) {
        // DUID with a 2-byte DUID type + variable body.
        if (length < 2) return formatHexBytes(bytes, offset, length);
        const duidType = readUint16(bytes, offset);
        return `DUID type=${duidType} body=${formatHexBytes(bytes, offset + 2, length - 2)}`;
    }
    if (optionCode === 6) {
        const codes = [];
        for (let i = 0; i + 2 <= length; i += 2) {
            const opt = readUint16(bytes, offset + i);
            if (opt === null) break;
            codes.push(String(opt));
        }
        return codes.join(",");
    }
    if (optionCode === 7 && length === 1) {
        return String(bytes[offset]);
    }
    if (optionCode === 8 && length >= 2) {
        return `${readUint16(bytes, offset)} (1/100s)`;
    }
    if (optionCode === 11 && length >= 2) {
        const statusCode = readUint16(bytes, offset);
        const name = DHCPV6_STATUS_CODE_NAMES[statusCode] || `STATUS${statusCode}`;
        const text = length > 2 ? formatTextBytes(bytes, offset + 2, length - 2) : "";
        return text ? `${name} (${text})` : name;
    }
    if (optionCode === 21) {
        const addrs = [];
        for (let i = 0; i + 16 <= length; i += 16) {
            const ip = formatIpv6(bytes, offset + i);
            if (ip) addrs.push(ip);
        }
        return addrs.length ? addrs.join(",") : formatHexBytes(bytes, offset, length);
    }
    if ([13, 14, 22, 27, 28, 31, 33, 35, 36, 53, 55].includes(optionCode)) {
        return formatTextBytes(bytes, offset, length);
    }
    if (optionCode === 30 && length === 4) {
        const t = readUint32(bytes, offset);
        return t === null ? formatHexBytes(bytes, offset, length) : String(t);
    }
    return formatHexBytes(bytes, offset, length);
}

function walkOptions(bytes, startOffset, endOffset, fields, depthLabel, allowNested) {
    let cursor = startOffset;
    let count = 0;
    while (cursor + 4 <= endOffset && count < DHCPV6_MAX_OPTIONS) {
        const optionCode = readUint16(bytes, cursor);
        const optionLength = readUint16(bytes, cursor + 2);
        if (optionCode === null || optionLength === null) break;
        if (cursor + 4 + optionLength > endOffset) break;
        const valueOffset = cursor + 4;
        const optionName = DHCPV6_OPTION_NAMES[optionCode] || `option-${optionCode}`;
        const labelPrefix = depthLabel ? `${depthLabel} ` : "";

        if (allowNested && DHCPV6_IA_NA_OPTION_CODES.has(optionCode) && optionLength >= 4) {
            // IA_NA: 4-byte IAID + 4-byte T1 + 4-byte T2 + nested options.
            const iaid = readUint32(bytes, valueOffset);
            fields.push({
                name: `${labelPrefix}${optionName} IAID`,
                value: iaid === null ? formatHexBytes(bytes, valueOffset, 4) : String(iaid),
            });
            walkOptions(bytes, valueOffset + 12, valueOffset + optionLength, fields, `${labelPrefix}${optionName}`, true);
        } else if (allowNested && DHCPV6_IA_TA_OPTION_CODES.has(optionCode)) {
            // IA_TA: 4-byte IAID + nested options.
            const iaid = readUint32(bytes, valueOffset);
            fields.push({
                name: `${labelPrefix}${optionName} IAID`,
                value: iaid === null ? formatHexBytes(bytes, valueOffset, 4) : String(iaid),
            });
            walkOptions(bytes, valueOffset + 4, valueOffset + optionLength, fields, `${labelPrefix}${optionName}`, true);
        } else if (allowNested && DHCPV6_RELAY_MSG_OPTION_CODES.has(optionCode)) {
            // Recursively walk the encapsulated DHCPv6 message.
            const relayFields = [];
            const relayDecoded = decodeDhcpv6FromBytes(
                bytes.slice(valueOffset, valueOffset + optionLength),
                relayFields,
            );
            if (relayDecoded) {
                fields.push({ name: `${labelPrefix}${optionName}`, value: relayDecoded });
                relayFields.forEach((field) => fields.push(field));
            } else {
                fields.push({ name: `${labelPrefix}${optionName}`, value: formatHexBytes(bytes, valueOffset, optionLength) });
            }
        } else {
            const value = formatOptionValue(optionCode, bytes, valueOffset, optionLength);
            fields.push({ name: `${labelPrefix}${optionName}`, value });
        }
        cursor += 4 + optionLength;
        count += 1;
    }
    if (count >= DHCPV6_MAX_OPTIONS) {
        fields.push({
            name: `${depthLabel || ""}Notice`.trim(),
            value: `Showing first ${DHCPV6_MAX_OPTIONS} DHCPv6 options from message.`,
        });
    }
}

function decodeDhcpv6FromBytes(bytes, fields) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4) return null;
    const msgType = bytes[0];
    // Strict gate: DHCPv6 message types are defined in RFC 8415/3315 as
    // values 1–27 (with relay messages 12–13). Any other value is not a
    // valid DHCPv6 message type. This prevents random binary data from
    // being accepted as DHCPv6 just because the first 4 bytes happen to
    // parse as a header.
    if (!DHCPV6_MESSAGE_TYPES[msgType]) return null;
    const msgTypeName = DHCPV6_MESSAGE_TYPES[msgType];
    if (!fields) return msgTypeName; // relay-message recursion check
    fields.push({ name: "Message Type", value: msgTypeName });
    const transactionId = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    fields.push({ name: "Transaction ID", value: `0x${transactionId.toString(16).padStart(6, "0")}` });
    walkOptions(bytes, 4, bytes.length, fields, "", true);
    return msgTypeName;
}

function decodeDhcpv6FromBytesOuter(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4) return null;
    const fields = [];
    const decoded = decodeDhcpv6FromBytes(bytes, fields);
    if (!decoded) return null;
    return { protocol: "DHCPv6", fields };
}

module.exports = { decodeDhcpv6FromBytes: decodeDhcpv6FromBytesOuter };
