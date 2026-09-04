// Renders DHCPv6 packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderDhcpv6Table(transportData) {
    const data = transportData?.["DHCPv6"];
    if (!data || typeof data !== "object") return;
    const rows = [
        { name: "Message Type", value: dotField(data, "dhcpv6.msg_type", "Message Type") },
        { name: "Transaction ID", value: dotField(data, "dhcpv6.transaction_id", "Transaction ID") },
    ];
    const options = data.Options || data["dhcpv6.options"];
    if (Array.isArray(options)) {
        options.forEach((option) => {
            if (!option || typeof option !== "object") return;
            rows.push({
                name: option.name || `Option ${option.code ?? ""}`,
                value: option.value ?? "—",
            });
        });
    }
    createTable(rows, ["DHCPv6 Field", "Value"], "sidedatatable");
}

module.exports = { renderDhcpv6Table };