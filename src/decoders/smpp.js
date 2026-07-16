// Renders SMPP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderSmppTable(transportData) {
    const smppData = transportData["SMPP"];
    if (!smppData) return;

    const smppRows = [
        { name: "Command", value: dotField(smppData, "smpp.command", "Command") },
        { name: "Command ID", value: dotField(smppData, "smpp.command_id", "Command ID") },
        { name: "Is Response", value: (smppData["smpp.is_response"] ?? smppData["Is Response"]) ? "Yes" : "No" },
        { name: "Command Status", value: dotField(smppData, "smpp.command_status", "Command Status") },
        { name: "Sequence Number", value: dotField(smppData, "smpp.sequence", "Sequence Number") },
        { name: "Body Length", value: dotField(smppData, "smpp.body_length", "Body Length") },
    ];

    createTable(smppRows, ["SMPP Field", "Value"], "sidedatatable");
}

module.exports = { renderSmppTable };
