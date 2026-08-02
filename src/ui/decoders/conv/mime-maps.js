// Maps common MIME types and variant spellings to the proto-decoder key used
// by the data-tools protocol switch.

const MIME_TO_PROTO = {
    "image/jpeg": "jpeg",
    "image/jpg": "jpeg",
    "jpeg": "jpeg",
    "jpg": "jpeg",
    "image/png": "png",
    "png": "png",
    "image/gif": "gif",
    "gif": "gif",
    "image/webp": "webp",
    "webp": "webp",
    "text/html": "html",
    "html": "html",
};

// Maps common file extensions (without the leading dot) to the proto-decoder
// key used by the data-tools protocol switch. The keys here line up with the
// values that appear in the <select id="data-tools-proto-select"> dropdown so
// that callers (e.g. the "Load carved file into Decoders" context-menu entry)
// can hint the decoder by extension without any extra UI plumbing.
const FILE_EXTENSION_TO_PROTO = {
    // Images — already covered by MIME_TO_PROTO via image/* aliases, but we
    // include the file extensions directly so callers can hint from a
    // carved-file candidate whose name is the only reliable metadata.
    jpg: "jpeg",
    jpeg: "jpeg",
    jpe: "jpeg",
    jfif: "jpeg",
    png: "png",
    gif: "gif",
    webp: "webp",
    bmp: "jpeg",
    tif: "jpeg",
    tiff: "jpeg",

    // Text / markup / data formats.
    html: "html",
    htm: "html",
    xhtml: "html",
    json: "json",
    geojson: "json",
    xml: "xml",
    svg: "xml",
    rss: "xml",
    atom: "xml",
    xsl: "xml",
    xslt: "xml",
    yaml: "yaml",
    yml: "yaml",

    // Common text/encoding files — these decode cleanly through the
    // "plaintext" path when the file is text. The explicit mapping lets
    // callers land on a stable decoder rather than "auto".
    txt: "plaintext",
    log: "plaintext",
    csv: "plaintext",
    tsv: "plaintext",
    ini: "plaintext",
    conf: "plaintext",
    cfg: "plaintext",
    env: "plaintext",
    md: "plaintext",
};

const SUPPORTED_DECODER_PROTOS = new Set([
    "auto",
    "plaintext",
    "http",
    "ftp",
    "smb",
    "telnet",
    "ssh",
    "pop3",
    "imap",
    "smtp",
    "json",
    "xml",
    "html",
    "yaml",
    "protobuf",
    "msgpack",
    "bson",
    "ber",
    "der",
    "ldap",
    "sip",
    "smpp",
    "soulseek",
    "bittorrent",
    "kerberos",
    "dns",
    "llmnr",
    "nbns",
    "nbdgm",
    "snmp",
    "dhcp",
    "dhcpv6",
    "jpeg",
    "png",
    "gif",
    "webp",
]);

// Extracts the lowercased file extension (without the leading dot) from a
// filename. Returns "" when no extension is present or the input is empty.
function extractFileExtension(fileName) {
    if (typeof fileName !== "string" || !fileName.trim()) return "";
    const cleaned = fileName.trim().replace(/[\\/]+$/, "");
    const baseName = cleaned.split(/[\\/]/).pop() || "";
    if (!baseName || baseName.startsWith(".")) return "";
    const lastDotIndex = baseName.lastIndexOf(".");
    if (lastDotIndex < 0 || lastDotIndex === baseName.length - 1) return "";
    return baseName.slice(lastDotIndex + 1).toLowerCase();
}

// Returns the proto-decoder key hinted at by the file extension of `fileName`,
// or "" when no hint is available. Only proto keys supported by the
// data-tools decoder dropdown are returned, so callers can safely set
// `selectEl.value` without further validation.
function getProtoDecoderHintForFileName(fileName) {
    const extension = extractFileExtension(fileName);
    if (!extension) return "";
    const protoHint = FILE_EXTENSION_TO_PROTO[extension];
    if (!protoHint || !SUPPORTED_DECODER_PROTOS.has(protoHint)) return "";
    return protoHint;
}

module.exports = {
    MIME_TO_PROTO,
    FILE_EXTENSION_TO_PROTO,
    SUPPORTED_DECODER_PROTOS,
    extractFileExtension,
    getProtoDecoderHintForFileName,
};
