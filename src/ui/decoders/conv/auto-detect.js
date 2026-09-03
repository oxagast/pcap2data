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
const { decodeLlmnrFromBytes } = require("./llmnr");
const { decodeNbnsFromBytes } = require("./nbns");
const { decodeNbdgmFromBytes } = require("./nbdgm");
const { decodeSnmpFromBytes } = require("./snmp");
const { decodeDhcpFromBytes } = require("./dhcp");
const { decodeDhcpv6FromBytes } = require("./dhcpv6");
const { decodeIso8583FromBytes } = require("./iso8583");
const { decodeModbusFromBytes } = require("./modbus");
const { decodeDnp3FromBytes } = require("./dnp3");
const { decodeS7commFromBytes } = require("./s7comm");
const { decodeOspfFromBytes } = require("./ospf");
const { decodeHsrpFromBytes } = require("./hsrp");
const { decodeLacpFromBytes } = require("./lacp");
const { decodeCdpFromBytes } = require("./cdp");
const { decodeMndpFromBytes } = require("./mndp");
const { decodeWebSocketFromBytes } = require("./websocket");

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
//
// Low-confidence decoders: MessagePack, Protobuf, BER/DER (ASN.1), and YAML
// have wire formats so permissive that almost any byte sequence or text
// file can be "decoded" by them. To prevent the autoselect from falling
// through to these decoders and producing meaningless output, they are
// treated specially:
//
//   1. They are moved to the END of the detection cascade, after every
//      high-confidence decoder has been tried.
//   2. They are only returned when a metadata hint (protocolHint or
//      portHint) corroborates the match, OR when no other decoder matched.
//      This means "it's better to not decode than to decode gibberish."
//
// Each low-confidence decoder has also been strengthened individually (see
// msgpack.js, protobuf.js, asn1.js, yaml.js) to require full structural
// validation rather than just a first-byte classification.

const LOW_CONFIDENCE_DECODERS = new Set([
    "msgpack",
    "protobuf",
    "ber",
    "der",
    "yaml",
]);

// Maps a low-confidence decoder key to the set of metadata hints that
// would corroborate it (i.e., make us trust the match). If a hint is
// present and the decoder succeeds, we return it; otherwise we skip.
const LOW_CONFIDENCE_CORROBORATING_HINTS = {
    msgpack: ["msgpack", "message-pack", "messagepack"],
    protobuf: ["protobuf", "proto", "protobuf3", "grpc"],
    ber: ["ber", "asn1", "asn.1", "snmp", "ldap", "kerberos", "x509", "certificate"],
    der: ["der", "asn1", "asn.1", "x509", "certificate", "ssl", "tls"],
    yaml: ["yaml", "yml"],
};

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

    // ICS/SCADA protocol detection by magic bytes:
    // DNP3 frames start with 0x05 0x64 sync bytes.
    if (bytes.length >= 2 && bytes[0] === 0x05 && bytes[1] === 0x64) return "dnp3";
    // S7comm over TPKT starts with version 0x03, reserved 0x00.
    if (bytes.length >= 2 && bytes[0] === 0x03 && bytes[1] === 0x00) return "s7comm";
    // Modbus/TCP: protocol ID 0x0000 at offset 2-3 with valid length.
    if (
        bytes.length >= 8 &&
        bytes[2] === 0x00 &&
        bytes[3] === 0x00 &&
        bytes[4] >= 2
    ) {
        try {
            if (typeof decodeModbusFromBytes === "function" && decodeModbusFromBytes(bytes)) {
                return "modbus";
            }
        } catch {
            // keep going
        }
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
    // ISO 8583 binary messages can look like msgpack (binary length
    // prefixes, non-ASCII bytes), so check ISO 8583 before msgpack.
    try {
        if (typeof decodeIso8583FromBytes === "function" && decodeIso8583FromBytes(bytes)) {
            return "iso8583";
        }
    } catch {
        // resilient — keep going
    }
    // ── HIGH-CONFIDENCE text-protocol detection ──────────────────────
    // These decoders have strong structural signatures (command keywords,
    // status codes, specific byte patterns) and are safe to use for
    // auto-detection.
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
        if (typeof decodeLlmnrFromBytes === "function" && decodeLlmnrFromBytes(bytes)) {
            return "llmnr";
        }
        if (typeof decodeNbnsFromBytes === "function" && decodeNbnsFromBytes(bytes)) {
            return "nbns";
        }
        if (typeof decodeNbdgmFromBytes === "function" && decodeNbdgmFromBytes(bytes)) {
            return "nbdgm";
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
        if (typeof decodeIso8583FromBytes === "function" && decodeIso8583FromBytes(bytes)) {
            return "iso8583";
        }
        if (typeof decodeModbusFromBytes === "function" && decodeModbusFromBytes(bytes)) {
            return "modbus";
        }
        if (typeof decodeDnp3FromBytes === "function" && decodeDnp3FromBytes(bytes)) {
            return "dnp3";
        }
        if (typeof decodeS7commFromBytes === "function" && decodeS7commFromBytes(bytes)) {
            return "s7comm";
        }
        // Routing-protocol byte heuristics. These ride directly on IP
        // (OSPF) or link-layer (LACP/CDP), so the bytes handed to the
        // Conv Decodes subtab are the protocol payload without any
        // TCP/UDP framing. HSRP is carried in UDP/1985 but a user may
        // paste the raw HSRP PDU here.
        if (typeof decodeOspfFromBytes === "function" && decodeOspfFromBytes(bytes)) {
            return "ospf";
        }
        if (typeof decodeHsrpFromBytes === "function" && decodeHsrpFromBytes(bytes)) {
            return "hsrp";
        }
        if (typeof decodeLacpFromBytes === "function" && decodeLacpFromBytes(bytes)) {
            return "lacp";
        }
        if (typeof decodeCdpFromBytes === "function" && decodeCdpFromBytes(bytes)) {
            return "cdp";
        }
        if (typeof decodeMndpFromBytes === "function" && decodeMndpFromBytes(bytes)) {
            return "mndp";
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
    // WebSocket frames: the first byte encodes FIN/RSV/opcode. A valid
    // frame must have a known opcode (0x0-0x2, 0x8-0xA) and the payload
    // length must not exceed the remaining bytes. This runs BEFORE the
    // low-confidence decoders because a WebSocket frame header can look
    // like a valid msgpack/protobuf prefix.
    try {
        if (typeof decodeWebSocketFromBytes === "function" && decodeWebSocketFromBytes(bytes)) {
            return "websocket";
        }
    } catch {
        // keep going
    }
    // Telnet: require IAC (0xFF) followed by a valid command byte (0xF0–0xFF)
    const TELNET_COMMANDS = new Set([
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
        0xfc, 0xfd, 0xfe, 0xff,
    ]);
    for (let i = 0; i + 1 < bytes.length; i++) {
        if (bytes[i] === 0xff && TELNET_COMMANDS.has(bytes[i + 1])) return "telnet";
    }

    // ── LOW-CONFIDENCE decoders (last resort) ─────────────────────────
    // MessagePack, Protobuf, BER/DER, and YAML have permissive wire formats
    // that can "decode" almost any byte sequence. Even with the strengthened
    // individual validators, these are still more likely to produce false
    // positives than the high-confidence decoders above. We only return a
    // low-confidence match if a metadata hint corroborates it, or if no
    // high-confidence decoder matched at all.
    //
    // The individual decoders have been strengthened to require full
    // structural validation (entire input consumed, valid wire types,
    // proper nesting, etc.), so even this last-resort path is much more
    // conservative than before.
    const hints = [
        protocolHint,
        portHint,
    ].filter(Boolean);

    function isCorroborated(decoderKey) {
        const corroborating = LOW_CONFIDENCE_CORROBORATING_HINTS[decoderKey];
        if (!corroborating) return false;
        return hints.some((h) =>
            corroborating.includes(h.toLowerCase()),
        );
    }

    // Try each low-confidence decoder. If a metadata hint corroborates the
    // match, return it immediately. Otherwise, hold onto the first match
    // and only return it at the very end (no high-confidence decoder won).
    let lowConfidenceMatch = null;
    try {
        if (typeof decodeMessagePackFromBytes === "function" && decodeMessagePackFromBytes(bytes)) {
            if (isCorroborated("msgpack")) return "msgpack";
            lowConfidenceMatch = lowConfidenceMatch || "msgpack";
        }
    } catch { /* keep going */ }
    try {
        if (typeof decodeProtobufFromBytes === "function" && decodeProtobufFromBytes(bytes)) {
            if (isCorroborated("protobuf")) return "protobuf";
            lowConfidenceMatch = lowConfidenceMatch || "protobuf";
        }
    } catch { /* keep going */ }
    try {
        if (typeof decodeBerFromBytes === "function" && decodeBerFromBytes(bytes)) {
            if (isCorroborated("ber")) return "ber";
            lowConfidenceMatch = lowConfidenceMatch || "ber";
        }
    } catch { /* keep going */ }
    try {
        if (typeof decodeDerFromBytes === "function" && decodeDerFromBytes(bytes)) {
            if (isCorroborated("der")) return "der";
            lowConfidenceMatch = lowConfidenceMatch || "der";
        }
    } catch { /* keep going */ }
    try {
        if (typeof decodeYamlFromBytes === "function" && decodeYamlFromBytes(bytes)) {
            if (isCorroborated("yaml")) return "yaml";
            lowConfidenceMatch = lowConfidenceMatch || "yaml";
        }
    } catch { /* keep going */ }

    // It's better to not decode than to decode meaningless gibberish.
    // If we only have a low-confidence match with no corroborating hint,
    // return null so the UI shows "No known protocol detected" instead of
    // misleading the user.
    return lowConfidenceMatch || null;
}

module.exports = {
    getPacketProtocolDecoderHint,
    autoDetectProtoFromBytes,
    LOW_CONFIDENCE_DECODERS,
    LOW_CONFIDENCE_CORROBORATING_HINTS,
};
