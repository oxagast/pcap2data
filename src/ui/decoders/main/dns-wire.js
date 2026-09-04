// Shared sidebar renderer for DNS-wire protocols (mDNS and LLMNR).

const { createTable, dotField } = require("./shared");

function renderDnsWireTable(transportData, sectionName, label) {
    const data = transportData?.[sectionName];
    if (!data || typeof data !== "object") return;
    const rows = [
        { name: "Transaction ID", value: dotField(data, `${sectionName.toLowerCase()}.id`, "Transaction ID") },
        { name: "Type", value: data["Is Response"] ? "Response" : "Query" },
        { name: "Questions", value: dotField(data, `${sectionName.toLowerCase()}.qdcount`, "Question Count") },
        { name: "Answers", value: dotField(data, `${sectionName.toLowerCase()}.ancount`, "Answer Count") },
        { name: "Authority", value: dotField(data, `${sectionName.toLowerCase()}.nscount`, "Authority Count") },
        { name: "Additional", value: dotField(data, `${sectionName.toLowerCase()}.arcount`, "Additional Count") },
    ];
    const queryNames = data["Query Names"] || data[`${sectionName.toLowerCase()}.qnames`];
    if (Array.isArray(queryNames) && queryNames.length) {
        rows.push({ name: "Query Names", value: queryNames.join(", ") });
    }
    const records = data.Records || data.Answers || data[`${sectionName.toLowerCase()}.records`];
    if (Array.isArray(records) && records.length) {
        rows.push({ name: "Records", value: records.join(" | ") });
    }
    const profile = data["Protocol Profile"] || data["mdns.protocol.profile"] ||
        (data.Bonjour ? "Bonjour (DNS-SD)" : "");
    if (profile) rows.unshift({ name: "Profile", value: profile });
    createTable(rows, [`${label} Field`, "Value"], "sidedatatable");
}

function renderMdnsTable(transportData) {
    renderDnsWireTable(transportData, "mDNS", "mDNS");
}

function renderLlmnrTable(transportData) {
    renderDnsWireTable(transportData, "LLMNR", "LLMNR");
}

module.exports = { renderMdnsTable, renderLlmnrTable };
