// Packet → decoder-key hint maps. Used by the Conv Decoders orchestrator to
// prefer the packet's known application protocol / port before falling back
// to byte-heuristic detection in autoDetectProtoFromBytes.

// Application-protocol names (as they appear in packet info) → decoder key.
const PROTOCOL_DECODER_HINTS = new Map([
    ["http", "http"],
    ["http2", "http"],
    ["https", "http"],
    ["ssh", "ssh"],
    ["telnet", "telnet"],
    ["smtp", "smtp"],
    ["ftp", "ftp"],
    ["pop3", "pop3"],
    ["imap", "imap"],
    ["ldap", "ldap"],
    ["smb", "smb"],
    ["sip", "sip"],
    ["smpp", "smpp"],
    ["soulseek", "soulseek"],
    ["bittorrent", "bittorrent"],
    ["kerberos", "kerberos"],
    ["krb5", "kerberos"],
    ["krb5sec", "kerberos"],
    ["jpeg", "jpeg"],
    ["png", "png"],
    ["gif", "gif"],
    ["webp", "webp"],
    ["imagejpeg", "jpeg"],
    ["imagepng", "png"],
    ["imagegif", "gif"],
    ["imagewebp", "webp"],
    ["plaintext", "plaintext"],
]);

// Well-known transport ports → decoder key.
const PORT_DECODER_HINTS = new Map([
    [21, "ftp"],
    [22, "ssh"],
    [23, "telnet"],
    [25, "smtp"],
    [80, "http"],
    [110, "pop3"],
    [143, "imap"],
    [389, "ldap"],
    [443, "http"],
    [445, "smb"],
    [587, "smtp"],
    [8080, "http"],
    [5060, "sip"],
    [5061, "sip"],
    [2775, "smpp"],
    [88, "kerberos"],
    [750, "kerberos"],
    [464, "kerberos"],
    [2234, "soulseek"],
    [2242, "soulseek"],
    [6881, "bittorrent"],
    [6882, "bittorrent"],
    [6883, "bittorrent"],
    [6884, "bittorrent"],
    [6885, "bittorrent"],
    [6886, "bittorrent"],
    [6887, "bittorrent"],
    [6888, "bittorrent"],
    [6889, "bittorrent"],
]);

module.exports = { PROTOCOL_DECODER_HINTS, PORT_DECODER_HINTS };
