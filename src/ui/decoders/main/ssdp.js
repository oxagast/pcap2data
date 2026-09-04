// Renders SSDP / UPnP discovery details in the Host Data sidebar.

const { createTable, dotField } = require("./shared");

function renderSsdpTable(transportData) {
    const data = transportData?.["SSDP"] || transportData?.["UPnP"];
    if (!data || typeof data !== "object") return;
    const rows = [
        { name: "Profile", value: dotField(data, "ssdp.profile", "Protocol Profile") },
        { name: "Type", value: dotField(data, "ssdp.type", "Type") },
        { name: "Start Line", value: dotField(data, "ssdp.start_line", "Start Line") },
    ];
    ["Host", "Cache-Control", "Location", "Server", "ST", "NT", "USN", "MAN", "MX"].forEach((name) => {
        if (data[name]) rows.push({ name, value: data[name] });
    });
    createTable(rows, ["SSDP / UPnP Field", "Value"], "sidedatatable");
}

module.exports = { renderSsdpTable };
