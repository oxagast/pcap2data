// Renders Soulseek packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderSoulseekTable(transportData) {
    const soulseekData = transportData["Soulseek"];
    if (!soulseekData) return;

    const rows = [
        { name: "Message Code", value: dotField(soulseekData, "soulseek.code", "Message Code") },
        { name: "Message Code Hex", value: dotField(soulseekData, "soulseek.code_hex", "Message Code Hex") },
        { name: "Message Length", value: dotField(soulseekData, "soulseek.length", "Message Length") },
        { name: "Body Length", value: dotField(soulseekData, "soulseek.body_length", "Body Length") },
    ];

    const preview = dotField(soulseekData, "soulseek.preview", "Payload Preview", "");
    if (preview) rows.push({ name: "Payload Preview", value: preview });

    createTable(rows, ["Soulseek Field", "Value"], "sidedatatable");
}

module.exports = { renderSoulseekTable };
