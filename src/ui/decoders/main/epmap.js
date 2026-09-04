// Renders Microsoft RPC Endpoint Mapper details into the sidebar table UI.

const { createTable } = require("./shared");

function renderEpmapTable(transportData) {
    const data = transportData?.["EPMAP"];
    if (!data || typeof data !== "object") return;
    const fields = data.Fields || data["epmap.fields"];
    const rows = [];
    if (Array.isArray(fields)) {
        fields.forEach((field) => {
            if (!field || typeof field !== "object") return;
            rows.push({ name: field.name || "Field", value: field.value ?? "—" });
        });
    }
    if (!rows.length && data.Protocol) rows.push({ name: "Protocol", value: data.Protocol });
    if (rows.length) createTable(rows, ["EPMAP Field", "Value"], "sidedatatable");
}

module.exports = { renderEpmapTable };