// IMAP Conv decoder: parses untagged responses, server continuations, and
// tagged commands / statuses (OK / NO / BAD / PREAUTH / BYE).

const IMAP_STATUSES = new Set(["OK", "NO", "BAD", "PREAUTH", "BYE"]);
const IMAP_COMMANDS = new Set([
    "CAPABILITY",
    "NOOP",
    "LOGOUT",
    "AUTHENTICATE",
    "LOGIN",
    "SELECT",
    "EXAMINE",
    "CREATE",
    "DELETE",
    "RENAME",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "LIST",
    "LSUB",
    "STATUS",
    "APPEND",
    "CHECK",
    "CLOSE",
    "EXPUNGE",
    "SEARCH",
    "FETCH",
    "STORE",
    "COPY",
    "UID",
    "IDLE",
]);

function decodeImapFromBytes(bytes) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    const lines = text.split(/\r?\n/).filter((l) => l.trim());
    if (!lines.length) return null;
    const fields = [];
    let detected = false;
    for (const line of lines) {
        if (line.startsWith("* ")) {
            const val = line.slice(2).trim();
            fields.push({
                name: "Untagged",
                value: val.length > 100 ? val.slice(0, 100) + "…" : val,
            });
            detected = true;
        } else if (line.startsWith("+ ")) {
            fields.push({ name: "Continuation", value: line.slice(2).trim() });
            detected = true;
        } else {
            const m = line.match(/^(\S+)\s+(\S+)\s*(.*)/);
            if (m) {
                const tag = m[1];
                const word = m[2].toUpperCase();
                const rest = m[3];
                if (IMAP_STATUSES.has(word)) {
                    const val = `${word} ${rest}`.trim();
                    fields.push({
                        name: `[${tag}] Status`,
                        value: val.length > 100 ? val.slice(0, 100) + "…" : val,
                    });
                    detected = true;
                } else if (IMAP_COMMANDS.has(word)) {
                    fields.push({ name: `[${tag}] Command`, value: word });
                    if (rest) {
                        fields.push({
                            name: "Arguments",
                            value: rest.length > 100 ? rest.slice(0, 100) + "…" : rest,
                        });
                    }
                    detected = true;
                }
            }
        }
    }
    if (!detected) return null;
    return { protocol: "IMAP", fields };
}

module.exports = { decodeImapFromBytes };
