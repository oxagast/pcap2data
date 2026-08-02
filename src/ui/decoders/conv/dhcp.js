// DHCP Conv decoder: parses the RFC 2131 BOOTP/DHCP header and the
// DHCP option stream that follows. The decoder surfaces the per-field
// header values (op, htype, hlen, hops, xid, secs, flags, ciaddr/yiaddr/
// siaddr/giaddr, chaddr, sname, file, magic cookie) and decodes every
// option from the registry (RFC 2132 + RFC 2131 message-type values)
// in declaration order, including vendor-encapsulated options and
// unknown options as raw hex.

const { bytesToHexLower } = require("./smb-helpers");

const DHCP_MAGIC_COOKIE = [0x63, 0x82, 0x53, 0x63];
const DHCP_HEADER_FIELDS_BEFORE_OPTIONS = 240;
const DHCP_MAX_OPTIONS = 128;
const DHCP_TEXT_LIMIT = 220;

const DHCP_MESSAGE_TYPES = {
    1: "DHCPDISCOVER",
    2: "DHCPOFFER",
    3: "DHCPREQUEST",
    4: "DHCPDECLINE",
    5: "DHCPACK",
    6: "DHCPNAK",
    7: "DHCPRELEASE",
    8: "DHCPINFORM",
    9: "DHCPFORCERENEW",
    10: "DHCPLEASEQUERY",
    11: "DHCPLEASEUNASSIGNED",
    12: "DHCPLEASEUNKNOWN",
    13: "DHCPLEASEACTIVE",
    14: "DHCPBULKLEASEQUERY",
    15: "DHCPLEASEQUERYDONE",
};

const DHCP_OPTION_NAMES = {
    0: "pad",
    1: "subnet-mask",
    2: "time-offset",
    3: "router",
    4: "time-servers",
    5: "name-server",
    6: "domain-name-servers",
    7: "log-server",
    8: "cookie-server",
    9: "lpr-server",
    10: "impress-server",
    11: "resource-location-server",
    12: "host-name",
    13: "boot-file-size",
    14: "merit-dump-file",
    15: "domain-name",
    16: "swap-server",
    17: "root-path",
    18: "extensions-path",
    19: "ip-forwarding",
    20: "non-local-source-routing",
    21: "policy-filter",
    22: "max-datagram-reassembly-size",
    23: "default-ip-ttl",
    24: "interface-mtu",
    25: "all-subnets-local",
    26: "broadcast-address",
    27: "router-discovery",
    28: "router-solicitation",
    29: "static-routes",
    30: "trailer-encapsulation",
    31: "arp-cache-timeout",
    32: "ethernet-encapsulation",
    33: "tcp-default-ttl",
    34: "tcp-keepalive-interval",
    35: "tcp-keepalive-garbage",
    36: "nis-domain",
    37: "nis-servers",
    38: "ntp-servers",
    39: "vendor-specific",
    40: "netbios-name-servers",
    41: "netbios-dd-server",
    42: "netbios-node-type",
    43: "netbios-scope",
    44: "x-window-fs",
    45: "x-window-dm",
    46: "netbios-node-type", // duplicate alias
    47: "netbios-scope", // duplicate alias
    48: "x-window-fs", // duplicate alias
    49: "x-window-dm", // duplicate alias
    50: "requested-ip-address",
    51: "ip-address-lease-time",
    52: "option-overload",
    53: "dhcp-message-type",
    54: "server-id",
    55: "parameter-request-list",
    56: "message",
    57: "max-message-size",
    58: "renewal-time",
    59: "rebinding-time",
    60: "vendor-class-id",
    61: "client-id",
    62: "netwareip-domain",
    63: "netwareip-information",
    64: "nis+-domain",
    65: "nis+-servers",
    66: "tftp-server-name",
    67: "bootfile-name",
    68: "mobile-ip-home-agent",
    69: "smtp-server",
    70: "pop3-server",
    71: "nntp-server",
    72: "www-server",
    73: "finger-server",
    74: "irc-server",
    75: "streettalk-server",
    76: "streettalk-directory-assistance-server",
    77: "user-class",
    78: "directory-agent",
    79: "service-scope",
    80: "rapid-commit",
    81: "client-fqdn",
    82: "relay-agent-information",
    83: "internet-storage-name-service",
    84: "unassigned",
    85: "nds-servers",
    86: "nds-tree-name",
    87: "nds-context",
    88: "bcms-controller",
    89: "bcms-controller-domain",
    90: "authentication",
    91: "client-last-transaction-time",
    92: "associated-ip",
    93: "client-system-architecture",
    94: "client-network-interface-id",
    95: "ldap",
    96: "uuid-guid",
    97: "user-auth",
    98: "geoconf",
    99: "vendor-encapsulated-options",
    100: "tz-posix",
    101: "tz-database",
    102: "ipv6-only-preferred",
    103: "option-119",
    104: "option-120",
    105: "civic-address",
    108: "ipv6-pxe",
    112: "netinfo-address",
    113: "netinfo-tag",
    114: "url",
    116: "auto-config",
    117: "name-service-search",
    118: "subnet-selection",
    119: "domain-search",
    120: "sip-servers",
    121: "classless-static-routes",
    122: "cablelabs-client-configuration",
    123: "geospatial-location",
    124: "tftp-server-address",
    125: "v6-only-preferred",
    128: "ethernet",
    129: "ipxe",
    130: "pxe-uuid",
    131: "pxe-64",
    132: "pxe-64-group",
    133: "pxe-64-menu",
    134: "pxe-boot-file",
    135: "pxe-magic",
    136: "pxe-configuration",
    137: "pxe-path-prefix",
    138: "pxe-reboot-time",
    139: "option-139",
    140: "option-140",
    141: "option-141",
    142: "option-142",
    150: "tftp-server-address-echo",
    151: "ethernet-boot",
    152: "option-152",
    153: "option-153",
    154: "option-154",
    155: "option-155",
    156: "option-156",
    157: "option-157",
    158: "option-158",
    159: "option-159",
    160: "option-160",
    161: "option-161",
    162: "option-162",
    163: "option-163",
    164: "option-164",
    165: "option-165",
    176: "ip-pbx",
    177: "packetcable-cms",
    178: "packetcable-gtwy",
    179: "subnet-allocation",
    180: "subnet-selection",
    181: "vrf",
    184: "captive-portal",
    186: "option-186",
    187: "option-187",
    188: "option-188",
    189: "option-189",
    190: "authentication",
    191: "option-191",
    192: "option-192",
    193: "option-193",
    194: "option-194",
    195: "option-195",
    200: "option-200",
    201: "option-201",
    202: "option-202",
    203: "option-203",
    208: "pxelinux-magic",
    209: "pxelinux-config-file",
    210: "pxelinux-path-prefix",
    211: "pxelinux-reboot-time",
    212: "option-212",
    213: "option-213",
    214: "option-214",
    215: "option-215",
    220: "subnet-allocation-option",
    221: "virtual-subnet-selection",
    222: "option-222",
    223: "option-223",
    224: "option-224",
    225: "option-225",
    226: "option-226",
    227: "option-227",
    228: "option-228",
    229: "option-229",
    230: "option-230",
    231: "option-231",
    232: "option-232",
    233: "option-233",
    234: "option-234",
    235: "option-235",
    236: "option-236",
    237: "option-237",
    238: "option-238",
    239: "option-239",
    240: "option-240",
    241: "option-241",
    242: "option-242",
    243: "option-243",
    244: "option-244",
    245: "option-245",
    246: "option-246",
    247: "option-247",
    248: "option-248",
    249: "option-249",
    250: "option-250",
    251: "option-251",
    252: "option-252",
    253: "option-253",
    254: "option-254",
    255: "end",
};

const DHCP_BOOL_FLAGS = new Set([
    19, 20, 25, 27, 30, 32, 34, 35, 80, 102, 125,
]);

function pushTruncated(fields, name, value, limit) {
    if (typeof value !== "string" || !value) return;
    const trimmed = value.length > limit ? `${value.slice(0, limit)}...` : value;
    fields.push({ name, value: trimmed });
}

function formatIpv4(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 4 > bytes.length) return null;
    return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

function formatChaddr(bytes) {
    if (!(bytes instanceof Uint8Array)) return "";
    // 6-byte MAC is the common case; surface as colon-hex. Pad with the full
    // 16-byte hardware address slice so 10-byte / longer link-layers render
    // correctly without truncation.
    const slice = bytes.slice(0, 16);
    const parts = [];
    for (let i = 0; i < slice.length; i += 1) {
        parts.push(slice[i].toString(16).padStart(2, "0"));
    }
    return parts.join(":");
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

function formatOptionValue(optionCode, bytes, offset, length) {
    if (!(bytes instanceof Uint8Array) || length === 0) return "";
    if (length === 4 && [
        1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 26, 28, 32, 40, 41, 50, 54, 58, 59, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
    ].includes(optionCode)) {
        return formatIpv4(bytes, offset);
    }
    if (length === 4 && [2, 13, 22, 23, 24, 27, 31, 33, 35, 36, 37, 38, 51, 57, 91, 92].includes(optionCode)) {
        return String((bytes[offset] << 24 | bytes[offset + 1] << 16 | bytes[offset + 2] << 8 | bytes[offset + 3]) >>> 0);
    }
    if (optionCode === 53 && length === 1) {
        const code = bytes[offset];
        return DHCP_MESSAGE_TYPES[code] || `TYPE${code}`;
    }
    if (optionCode === 52 && length === 1) {
        const value = bytes[offset];
        const flags = [];
        if (value & 0x01) flags.push("file");
        if (value & 0x02) flags.push("sname");
        return flags.length ? flags.join("+") : "none";
    }
    if (optionCode === 46 && length === 1) {
        const nodes = ["B-node", "P-node", "M-node", "H-node"];
        return nodes[bytes[offset]] || `node-${bytes[offset]}`;
    }
    if (DHCP_BOOL_FLAGS.has(optionCode) && length === 1) {
        return bytes[offset] !== 0 ? "true" : "false";
    }
    if (optionCode === 55) {
        const codes = [];
        for (let i = 0; i < length; i += 1) {
            codes.push(String(bytes[offset + i]));
        }
        return codes.join(",");
    }
    if ([12, 15, 17, 18, 56, 60, 66, 67, 81, 114, 118, 119, 120, 124, 150, 252, 254].includes(optionCode)) {
        return formatTextBytes(bytes, offset, length);
    }
    if ([61, 82, 90, 99, 121, 125, 212, 213, 220, 221].includes(optionCode)) {
        return formatHexBytes(bytes, offset, length);
    }
    return formatHexBytes(bytes, offset, length);
}

function decodeDhcpFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < DHCP_HEADER_FIELDS_BEFORE_OPTIONS + 4) {
        return null;
    }
    const op = bytes[0];
    if (op !== 1 && op !== 2) return null; // BOOTREQUEST or BOOTREPLY
    const htype = bytes[1];
    const hlen = bytes[2];
    const hops = bytes[3];
    const xid = (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
    const secs = (bytes[8] << 8) | bytes[9];
    const flags = (bytes[10] << 8) | bytes[11];
    const ciaddr = formatIpv4(bytes, 12);
    const yiaddr = formatIpv4(bytes, 16);
    const siaddr = formatIpv4(bytes, 20);
    const giaddr = formatIpv4(bytes, 24);
    const chaddr = formatChaddr(bytes.slice(28, 44));
    const sname = formatTextBytes(bytes, 44, 64);
    const file = formatTextBytes(bytes, 108, 128);
    const magicOk =
        bytes[236] === DHCP_MAGIC_COOKIE[0] &&
        bytes[237] === DHCP_MAGIC_COOKIE[1] &&
        bytes[238] === DHCP_MAGIC_COOKIE[2] &&
        bytes[239] === DHCP_MAGIC_COOKIE[3];
    if (!magicOk) return null;

    const fields = [];
    fields.push({ name: "Op", value: op === 1 ? "BOOTREQUEST" : "BOOTREPLY" });
    fields.push({ name: "Hardware Type", value: String(htype) });
    fields.push({ name: "Hardware Address Length", value: String(hlen) });
    fields.push({ name: "Hops", value: String(hops) });
    fields.push({ name: "Transaction ID", value: `0x${xid.toString(16).padStart(8, "0")}` });
    fields.push({ name: "Seconds", value: String(secs) });
    const broadcast = (flags & 0x8000) !== 0;
    fields.push({ name: "Flags BROADCAST", value: broadcast ? "set" : "clear" });
    if (ciaddr) fields.push({ name: "Client IP (ciaddr)", value: ciaddr });
    if (yiaddr) fields.push({ name: "Your IP (yiaddr)", value: yiaddr });
    if (siaddr) fields.push({ name: "Server IP (siaddr)", value: siaddr });
    if (giaddr) fields.push({ name: "Relay IP (giaddr)", value: giaddr });
    if (chaddr) fields.push({ name: "Client MAC (chaddr)", value: chaddr });
    if (sname) pushTruncated(fields, "Server Hostname (sname)", sname, DHCP_TEXT_LIMIT);
    if (file) pushTruncated(fields, "Boot File (file)", file, DHCP_TEXT_LIMIT);

    let optionCursor = 240;
    let optionCount = 0;
    while (optionCursor < bytes.length && optionCount < DHCP_MAX_OPTIONS) {
        const optionCode = bytes[optionCursor];
        if (optionCode === 255) {
            fields.push({ name: "End", value: "yes" });
            break;
        }
        if (optionCode === 0) {
            fields.push({ name: "Pad", value: "yes" });
            optionCursor += 1;
            optionCount += 1;
            continue;
        }
        if (optionCursor + 1 >= bytes.length) break;
        const optionLength = bytes[optionCursor + 1];
        if (optionCursor + 2 + optionLength > bytes.length) break;
        const optionValueOffset = optionCursor + 2;
        const optionValue = formatOptionValue(optionCode, bytes, optionValueOffset, optionLength);
        const optionName = DHCP_OPTION_NAMES[optionCode] || `option-${optionCode}`;
        fields.push({ name: optionName, value: optionValue });
        optionCursor += 2 + optionLength;
        optionCount += 1;
    }

    if (optionCount >= DHCP_MAX_OPTIONS) {
        fields.push({
            name: "Notice",
            value: `Showing first ${DHCP_MAX_OPTIONS} DHCP options from message.`,
        });
    }

    return { protocol: "DHCP", fields };
}

module.exports = { decodeDhcpFromBytes };
