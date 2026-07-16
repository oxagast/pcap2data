// Renders BitTorrent packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderBitTorrentTable(transportData) {
    const btData = transportData["BitTorrent"];
    if (!btData) return;

    const rows = [
        { name: "Type", value: dotField(btData, "bittorrent.type", "Type") },
    ];

    const message = dotField(btData, "bittorrent.message", "Message", "");
    if (message) rows.push({ name: "Message", value: message });

    const query = dotField(btData, "bittorrent.query", "Query", "");
    if (query) rows.push({ name: "Query", value: query });

    const txType = dotField(btData, "bittorrent.transaction_type", "Transaction Type", "");
    if (txType) rows.push({ name: "Transaction Type", value: txType });

    const infoHash = dotField(btData, "bittorrent.info_hash", "Info Hash", "");
    if (infoHash) rows.push({ name: "Info Hash", value: infoHash });

    const peerId = dotField(btData, "bittorrent.peer_id", "Peer ID", "");
    if (peerId) rows.push({ name: "Peer ID", value: peerId });

    const peerIdHex = dotField(btData, "bittorrent.peer_id_hex", "Peer ID Hex", "");
    if (peerIdHex) rows.push({ name: "Peer ID Hex", value: peerIdHex });

    const msgLength = dotField(btData, "bittorrent.length", "Message Length", "");
    if (msgLength !== "") rows.push({ name: "Message Length", value: msgLength });

    createTable(rows, ["BitTorrent Field", "Value"], "sidedatatable");
}

module.exports = { renderBitTorrentTable };
