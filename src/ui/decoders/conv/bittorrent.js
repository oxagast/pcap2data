// BitTorrent Conv decoder: handles three BitTorrent payload shapes:
//   1. Handshake (length 68, leading 0x13, then "BitTorrent protocol")
//   2. Peer Wire (4-byte big-endian length + message ID)
//   3. DHT KRPC bencode (e.g. "d1:..." with "1:y1:q"/"1:q..." queries)

const { bytesToHexLower } = require("./smb-helpers");

const BITTORRENT_PEER_WIRE_MESSAGES = {
    0: "choke",
    1: "unchoke",
    2: "interested",
    3: "not interested",
    4: "have",
    5: "bitfield",
    6: "request",
    7: "piece",
    8: "cancel",
    9: "port",
    20: "extended",
};

function decodeBittorrentHandshake(bytes) {
    const protocol = new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(1, 20));
    if (protocol !== "BitTorrent protocol") return null;
    const infoHash = bytesToHexLower(bytes.slice(28, 48));
    const peerIdBytes = bytes.slice(48, 68);
    const peerIdHex = bytesToHexLower(peerIdBytes);
    const peerId = Array.from(peerIdBytes, (value) =>
        value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : ".",
    )
        .join("")
        .replace(/^\.+|\.+$/g, "");
    const fields = [
        { name: "Type", value: "Handshake" },
        { name: "Protocol", value: "BitTorrent protocol" },
        { name: "Info Hash", value: infoHash },
        { name: "Peer ID Hex", value: peerIdHex },
    ];
    if (peerId) fields.push({ name: "Peer ID", value: peerId });
    return { protocol: "BitTorrent", fields };
}

function decodeBittorrentPeerWire(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const messageLength = view.getUint32(0, false);
    if (messageLength === 0) {
        return {
            protocol: "BitTorrent",
            fields: [
                { name: "Type", value: "Peer Wire" },
                { name: "Message", value: "keepalive" },
                { name: "Message Length", value: "0" },
            ],
        };
    }
    if (messageLength < 1 || messageLength > bytes.length - 4) return null;
    const messageId = bytes[4];
    const messageName = BITTORRENT_PEER_WIRE_MESSAGES[messageId] || `id_${messageId}`;
    return {
        protocol: "BitTorrent",
        fields: [
            { name: "Type", value: "Peer Wire" },
            { name: "Message", value: messageName },
            { name: "Message ID", value: String(messageId) },
            { name: "Message Length", value: String(messageLength) },
        ],
    };
}

function decodeBittorrentDhtKrpc(bytes) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(0, 256));
    if (!(text.startsWith("d") && text.includes("1:y1:") && (text.includes("1:q") || text.includes("1:r")))) {
        return null;
    }
    const txMatch = text.match(/1:y1:([qre])/);
    const queryMatch = text.match(/1:q(\d+):([a-z_]+)/i);
    const fields = [
        { name: "Type", value: "DHT KRPC" },
        { name: "Transaction Type", value: txMatch?.[1] || "unknown" },
    ];
    if (queryMatch?.[2]) fields.push({ name: "Query", value: queryMatch[2] });
    return { protocol: "BitTorrent", fields };
}

function decodeBittorrentFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

    try {
        if (bytes.length >= 68 && bytes[0] === 19) {
            const result = decodeBittorrentHandshake(bytes);
            if (result) return result;
        }

        if (bytes.length >= 4) {
            const result = decodeBittorrentPeerWire(bytes);
            if (result) return result;
        }

        return decodeBittorrentDhtKrpc(bytes);
    } catch {
        return null;
    }
}

module.exports = { decodeBittorrentFromBytes };
