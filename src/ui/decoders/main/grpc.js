// Renders gRPC envelope details in the Host Data sidebar.

const { createTable } = require("./shared");

function renderGrpcTable(transportData) {
    const data = transportData?.["gRPC"];
    if (!data || typeof data !== "object") return;
    const messages = data.Messages || data["grpc.messages"];
    const rows = [
        { name: "Profile", value: data.Profile || data["grpc.profile"] || "gRPC" },
        { name: "Message Count", value: data["Message Count"] ?? data["grpc.message_count"] ?? "—" },
    ];
    if (Array.isArray(messages)) {
        messages.forEach((message, index) => {
            rows.push({ name: `Message ${index + 1} Length`, value: message.length ?? "—" });
            rows.push({ name: `Message ${index + 1} Compressed`, value: message.compressed ? "yes" : "no" });
            if (message["payload.preview"]) {
                rows.push({ name: `Message ${index + 1} Preview`, value: message["payload.preview"] });
            }
        });
    }
    createTable(rows, ["gRPC Field", "Value"], "sidedatatable");
}

module.exports = { renderGrpcTable };
