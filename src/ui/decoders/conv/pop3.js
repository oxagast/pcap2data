// POP3 Conv decoder: parses +OK / -ERR responses and recognized POP3 commands.

const POP3_COMMANDS = new Set([
    "USER",
    "PASS",
    "STAT",
    "LIST",
    "RETR",
    "DELE",
    "NOOP",
    "RSET",
    "QUIT",
    "APOP",
    "TOP",
    "UIDL",
]);

function decodePop3FromBytes(bytes) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    const lines = text.split(/\r?\n/).filter((l) => l.trim());
    if (!lines.length) return null;
    const fields = [];
    let detected = false;
    for (const line of lines) {
        if (line.startsWith("+OK")) {
            fields.push({ name: "Response", value: "+OK" });
            const msg = line.slice(3).trim();
            if (msg) fields.push({ name: "Message", value: msg });
            detected = true;
        } else if (line.startsWith("-ERR")) {
            fields.push({ name: "Response", value: "-ERR" });
            const msg = line.slice(4).trim();
            if (msg) fields.push({ name: "Error", value: msg });
            detected = true;
        } else {
            const parts = line.split(/\s+/);
            const cmd = parts[0].toUpperCase();
            if (POP3_COMMANDS.has(cmd)) {
                fields.push({ name: "Command", value: cmd });
                if (parts.length > 1) {
                    fields.push({ name: "Argument", value: parts.slice(1).join(" ") });
                }
                detected = true;
            }
        }
    }
    if (!detected) return null;
    return { protocol: "POP3", fields };
}

module.exports = { decodePop3FromBytes };
