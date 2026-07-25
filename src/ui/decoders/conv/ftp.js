// FTP Conv decoder: parses "NNN " / "NNN-" response codes and recognized
// FTP commands (USER, PASS, LIST, RETR, STOR, PASV, PORT, etc.).

const FTP_COMMANDS = new Set([
    "USER",
    "PASS",
    "ACCT",
    "CWD",
    "CDUP",
    "PWD",
    "TYPE",
    "PASV",
    "EPSV",
    "PORT",
    "EPRT",
    "LIST",
    "NLST",
    "RETR",
    "STOR",
    "DELE",
    "RNFR",
    "RNTO",
    "MKD",
    "RMD",
    "SYST",
    "STAT",
    "FEAT",
    "AUTH",
    "QUIT",
    "NOOP",
]);

const FTP_RESPONSE_RE = /^(\d{3})([\s-])(.*)/;

function decodeFtpFromBytes(bytes) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    const lines = text.split(/\r?\n/).filter((line) => line.trim());
    if (!lines.length) return null;

    const fields = [];
    let detected = false;
    for (const line of lines) {
        const responseMatch = line.match(FTP_RESPONSE_RE);
        if (responseMatch) {
            const code = responseMatch[1];
            const suffix = responseMatch[2] === "-" ? " (cont.)" : "";
            fields.push({
                name: `Response ${code}${suffix}`,
                value: responseMatch[3] || "—",
            });
            detected = true;
        } else {
            const parts = line.trim().split(/\s+/);
            const command = (parts[0] || "").toUpperCase();
            if (FTP_COMMANDS.has(command)) {
                fields.push({ name: "Command", value: command });
                if (parts.length > 1) {
                    const argument = parts.slice(1).join(" ");
                    fields.push({
                        name: "Argument",
                        value: argument.length > 160 ? argument.slice(0, 160) + "…" : argument,
                    });
                }
                detected = true;
            }
        }
    }

    if (!detected) return null;
    return { protocol: "FTP", fields };
}

module.exports = { decodeFtpFromBytes };
