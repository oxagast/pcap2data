// SMTP Conv decoder: parses "NNN " / "NNN-" response codes and recognized
// SMTP commands (HELO, EHLO, MAIL FROM, RCPT TO, DATA, etc.).

const SMTP_COMMANDS = new Set([
    "HELO",
    "EHLO",
    "MAIL",
    "RCPT",
    "DATA",
    "RSET",
    "VRFY",
    "EXPN",
    "NOOP",
    "QUIT",
    "AUTH",
    "STARTTLS",
]);

const SMTP_RESPONSE_RE = /^(\d{3})([\s-])(.*)/;

function decodeSmtpFromBytes(bytes) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    const lines = text.split(/\r?\n/).filter((l) => l.trim());
    if (!lines.length) return null;
    const fields = [];
    let detected = false;
    for (const line of lines) {
        const rm = line.match(SMTP_RESPONSE_RE);
        if (rm) {
            const label = `Response ${rm[1]}${rm[2] === "-" ? " (cont.)" : ""}`;
            fields.push({ name: label, value: rm[3] });
            detected = true;
        } else {
            const parts = line.split(/\s+/);
            const cmd = parts[0].toUpperCase();
            if (SMTP_COMMANDS.has(cmd)) {
                fields.push({ name: "Command", value: cmd });
                if (parts.length > 1) {
                    const arg = parts.slice(1).join(" ");
                    fields.push({
                        name: "Argument",
                        value: arg.length > 100 ? arg.slice(0, 100) + "…" : arg,
                    });
                }
                detected = true;
            }
        }
    }
    if (!detected) return null;
    return { protocol: "SMTP", fields };
}

module.exports = { decodeSmtpFromBytes };
