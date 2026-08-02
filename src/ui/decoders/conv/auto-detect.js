// Pure auto-detect / hint logic for the Conv Decoders subtab. These helpers
// have no DOM dependencies and no module-level state, so they can be safely
// required from data-tools-panel.js (and from unit tests via vm).

const { MIME_TO_PROTO } = require("./mime-maps");
const { PROTOCOL_DECODER_HINTS, PORT_DECODER_HINTS } = require("./protocol-hints");

const { normalizeSmbDecoderBytes } = require("./smb-helpers");
const { getImageTypeFromExifReader } = require("./exif-helpers");

// Per-protocol decode*FromBytes functions used by the byte-heuristic
// fall-through. We pull them in directly from each file to avoid a circular
// require chain through the conv/index.js barrel.
const { decodeJsonFromBytes } = require("./json");
const { decodeXmlFromBytes } = require("./xml");
const { decodeHtmlFromBytes } = require("./html");
const { decodeYamlFromBytes } = require("./yaml");
const { decodeBsonFromBytes } = require("./bson");
const { decodeMessagePackFromBytes } = require("./msgpack");
const { decodeProtobufFromBytes } = require("./protobuf");
const { decodeBerFromBytes } = require("./ber");
const { decodeDerFromBytes } = require("./der");
const { decodeLdapFromBytes } = require("./ldap");
const { decodeEpmapFromBytes } = require("./epmap");
const { decodeSmppFromBytes } = require("./smpp");
const { decodeSoulseekFromBytes } = require("./soulseek");
const { decodeBittorrentFromBytes } = require("./bittorrent");
const { decodeKerberosFromBytes } = require("./kerberos");
const { decodeDnsFromBytes } = require("./dns");
const { decodeSnmpFromBytes } = require("./snmp");
const { decodeDhcpFromBytes } = require("./dhcp");
const { decodeDhcpv6FromBytes } = require("./dhcpv6");

// Extracts a decoder hint for a packet from its application protocol and
// transport ports. The result can be passed to autoDetectProtoFromBytes as
// { protocolHint, portHint } to prefer packet metadata over byte heuristics.
function getPacketProtocolDecoderHint(packet) {
    if (!packet || typeof packet !== "object") {
        return { protocolHint: null, portHint: null };
    }

    const packetInfo = packet["packet.info"] || packet.packetInfo || {};
    const extraInfo = packet["extra.info"] || packet.extraInfo || {};

    const appProtoCandidates = [
        extraInfo?.["application.proto"],
        extraInfo?.["app.proto"],
        extraInfo?.["Traits"]?.["Network Data"]?.["Port Protocol"],
        extraInfo?.["Traits"]?.["Network Data"]?.["Port Protcol"],
        extraInfo?.["traits"]?.["network.data"]?.["port.protocol"],
        packetInfo?.["application.proto"],
        packetInfo?.["app.proto"],
    ];

    let protocolHint = null;
    for (const candidate of appProtoCandidates) {
        const raw = typeof candidate === "string" ? candidate.trim() : "";
        if (!raw) continue;
        const normalized = raw.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (PROTOCOL_DECODER_HINTS.has(normalized)) {
            protocolHint = PROTOCOL_DECODER_HINTS.get(normalized);
            break;
        }
        const baseMime = raw.toLowerCase().trim().split(";")[0].trim();
        if (MIME_TO_PROTO[baseMime]) {
            protocolHint = MIME_TO_PROTO[baseMime];
            break;
        }
    }

    const transportName = String(
        packetInfo?.["packet.proto"] ??
        packetInfo?.["protocol"] ??
        packetInfo?.["Protocol"] ??
        "",
    ).toUpperCase();
    const transportData =
        typeof packetInfo[transportName] === "object"
            ? packetInfo[transportName]
            : typeof packetInfo[transportName.toLowerCase()] === "object"
                ? packetInfo[transportName.toLowerCase()]
                : {};

    const portCandidates = [
        transportData?.["tcp.dst.port"],
        transportData?.["udp.dst.port"],
        transportData?.["sctp.dst.port"],
        transportData?.["destination.port"],
        packetInfo?.["tcp.dst.port"],
        packetInfo?.["udp.dst.port"],
        packetInfo?.["sctp.dst.port"],
        packetInfo?.["destination.port"],
    ];

    let firstPort = null;
    for (const candidate of portCandidates) {
        const value = Number(candidate);
        if (Number.isFinite(value) && value > 0) {
            firstPort = value;
            break;
        }
    }

    const portHint = firstPort && PORT_DECODER_HINTS.has(firstPort)
        ? PORT_DECODER_HINTS.get(firstPort)
        : null;

    return { protocolHint, portHint };
}

// Handles auto detect proto from bytes.
// Accepts an optional { protocolHint, portHint } object so callers can ask
// the decoder to try a packet's known application protocol, then its port,
// before falling back to byte-heuristic detection.
function autoDetectProtoFromBytes(bytes, options) {
    const { protocolHint = null, portHint = null } = options || {};
    if (protocolHint && typeof protocolHint === "string") {
        const baseMime = protocolHint.toLowerCase().trim().split(";")[0].trim();
        return MIME_TO_PROTO[baseMime] || protocolHint;
    }
    if (portHint && typeof portHint === "string") {
        return portHint;
    }

    // EPMAP (Microsoft RPC Endpoint Mapper on port 135) is best checked
    // before the BSON / MessagePack / Protobuf detectors: the EPM Bind
    // PDU starts with 0x05 0x00 0x0b and may otherwise look like a
    // valid msgpack/protobuf frame.
    if (typeof decodeEpmapFromBytes === "function" && decodeEpmapFromBytes(bytes)) {
        return "epmap";
    }

    const normalizedSmbBytes = normalizeSmbDecoderBytes(bytes);
    if (
        normalizedSmbBytes instanceof Uint8Array &&
        normalizedSmbBytes.length >= 4 &&
        ((normalizedSmbBytes[0] === 0xff && normalizedSmbBytes[1] === 0x53 && normalizedSmbBytes[2] === 0x4d && normalizedSmbBytes[3] === 0x42) ||
            (normalizedSmbBytes[0] === 0xfe && normalizedSmbBytes[1] === 0x53 && normalizedSmbBytes[2] === 0x4d && normalizedSmbBytes[3] === 0x42))
    ) {
        return "smb";
    }
    // Image format detection
    if (bytes.length >= 3 && bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return "jpeg";
    if (bytes.length >= 4 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return "png";
    if (bytes.length >= 4 && bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) return "gif";
    if (bytes.length >= 12 && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return "webp";

    // ExifReader's fileType tag is authoritative for image payloads.
    const exifImageType = getImageTypeFromExifReader(bytes);
    if (exifImageType) {
        return exifImageType;
    }

    const text = new TextDecoder("utf-8", { fatal: false }).decode(
        bytes.slice(0, 256),
    );
    if (/^SSH-/.test(text)) return "ssh";
    const trimmedText = text.trimStart();
    if ((trimmedText.startsWith("{") || trimmedText.startsWith("[")) && decodeJsonFromBytes(bytes)) {
        return "json";
    }
    if (trimmedText.startsWith("<") && decodeXmlFromBytes(bytes)) return "xml";
    if (decodeHtmlFromBytes(bytes)) return "html";
    if (decodeBsonFromBytes(bytes)) return "bson";
    if (decodeMessagePackFromBytes(bytes)) return "msgpack";
    if (decodeProtobufFromBytes(bytes)) return "protobuf";
    if (decodeBerFromBytes(bytes)) return "ber";
    if (decodeDerFromBytes(bytes)) return "der";
    if (decodeYamlFromBytes(bytes)) return "yaml";
    if (
        /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s/.test(text) ||
        /^HTTP\/[\d.]+ \d{3}/.test(text)
    )
        return "http";
    if (
        /^(HELO|EHLO|MAIL FROM|RCPT TO|DATA|QUIT)\b/i.test(text) ||
        /^\d{3}[\s-]/.test(text)
    )
        return "smtp";
    if (
        /^(USER|PASS|ACCT|CWD|CDUP|PWD|TYPE|PASV|EPSV|PORT|EPRT|LIST|NLST|RETR|STOR|DELE|RNFR|RNTO|MKD|RMD|SYST|STAT|FEAT|AUTH|NOOP|QUIT)\b/i.test(
            text,
        ) ||
        /^220[\s-].*ftp/i.test(text)
    )
        return "ftp";
    if (
        /^\+OK/.test(text) ||
        /^-ERR/.test(text) ||
        /^(USER|PASS|STAT|LIST|RETR|DELE|QUIT)\b/i.test(text)
    )
        return "pop3";
    if (
        /^\* /.test(text) ||
        /^\+ /.test(text) ||
        /^\S+ (OK|NO|BAD|PREAUTH|BYE)\b/i.test(text) ||
        /^\S+ (SELECT|LOGIN|FETCH|AUTHENTICATE)\b/i.test(text)
    )
        return "imap";
    if (decodeLdapFromBytes(bytes)) return "ldap";
    try {
        if (typeof decodeEpmapFromBytes === "function" && decodeEpmapFromBytes(bytes)) {
            return "epmap";
        }
        if (typeof decodeSmppFromBytes === "function" && decodeSmppFromBytes(bytes)) {
            return "smpp";
        }
        if (typeof decodeSoulseekFromBytes === "function" && decodeSoulseekFromBytes(bytes)) {
            return "soulseek";
        }
        if (typeof decodeBittorrentFromBytes === "function" && decodeBittorrentFromBytes(bytes)) {
            return "bittorrent";
        }
        if (typeof decodeKerberosFromBytes === "function" && decodeKerberosFromBytes(bytes)) {
            return "kerberos";
        }
        if (typeof decodeDnsFromBytes === "function" && decodeDnsFromBytes(bytes)) {
            return "dns";
        }
        if (typeof decodeSnmpFromBytes === "function" && decodeSnmpFromBytes(bytes)) {
            return "snmp";
        }
        if (typeof decodeDhcpFromBytes === "function" && decodeDhcpFromBytes(bytes)) {
            return "dhcp";
        }
        if (typeof decodeDhcpv6FromBytes === "function" && decodeDhcpv6FromBytes(bytes)) {
            return "dhcpv6";
        }
    } catch {
        // Keep auto-detect resilient; one decoder failure must not abort the whole chain.
    }
    if (
        /^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|SUBSCRIBE|NOTIFY|REFER|INFO|UPDATE|PRACK|MESSAGE|PUBLISH)\s+\S+\s+SIP\/[\d.]+/i.test(
            trimmedText,
        ) ||
        /^SIP\/[\d.]+\s+\d{3}(?:\s|$)/i.test(trimmedText)
    )
        return "sip";
    // Telnet: require IAC (0xFF) followed by a valid command byte (0xF0–0xFF)
    const TELNET_COMMANDS = new Set([
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
        0xfc, 0xfd, 0xfe, 0xff,
    ]);
    for (let i = 0; i + 1 < bytes.length; i++) {
        if (bytes[i] === 0xff && TELNET_COMMANDS.has(bytes[i + 1])) return "telnet";
    }
    return null;
}

module.exports = {
    getPacketProtocolDecoderHint,
    autoDetectProtoFromBytes,
};
