// Telnet Conv decoder: scans for IAC negotiations and printable text,
// emitting the captured options and any extracted text preview.

const IAC = 0xff;
const WILL = 0xfb;
const WONT = 0xfc;
const DO = 0xfd;
const DONT = 0xfe;
const SB = 0xfa;
const SE = 0xf0;

const OPTION_NAMES = {
    0: "Binary",
    1: "Echo",
    3: "Suppress Go Ahead",
    5: "Status",
    24: "Terminal Type",
    31: "Window Size",
    32: "Terminal Speed",
    34: "Linemode",
    39: "New Environment",
};

// Allowed control characters beyond newline/carriage return.
const TELNET_VALID_CTRL = new Set([0x09]); // tab

function isGarbageByte(b) {
    // IAC is the telnet command prefix — not garbage.
    if (b === IAC) return false;
    // Printable ASCII.
    if (b >= 0x20 && b <= 0x7e) return false;
    // Newline, carriage return, tab.
    if (b === 10 || b === 13 || b === 9) return false;
    return true;
}

function decodeTelnetFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
    const negotiations = [];
    let text = "";
    let i = 0;
    let hasIac = false;
    let garbageCount = 0;
    while (i < bytes.length) {
        if (bytes[i] === IAC) {
            hasIac = true;
            i++;
            if (i >= bytes.length) break;
            const cmd = bytes[i++];
            if (cmd === WILL || cmd === WONT || cmd === DO || cmd === DONT) {
                if (i < bytes.length) {
                    const opt = bytes[i++];
                    const cmdName =
                        cmd === WILL
                            ? "WILL"
                            : cmd === WONT
                                ? "WONT"
                                : cmd === DO
                                    ? "DO"
                                    : "DONT";
                    negotiations.push(`${cmdName} ${OPTION_NAMES[opt] ?? `Option ${opt}`}`);
                }
            } else if (cmd === SB) {
                while (i < bytes.length) {
                    if (bytes[i] === IAC && i + 1 < bytes.length && bytes[i + 1] === SE) {
                        i += 2;
                        break;
                    }
                    i++;
                }
            }
        } else {
            const b = bytes[i++];
            if (isGarbageByte(b)) {
                garbageCount++;
                continue;
            }
            if (b >= 32 && b < 127) text += String.fromCharCode(b);
            else if (b === 10) text += "\n";
            else if (b === 13) text += "\r";
            else if (b === 9) text += "\t";
        }
    }

    // Reject payloads that are mostly binary garbage (>30% garbage bytes).
    // This prevents random binary protocols from being mis-identified as Telnet.
    const garbageRatio = garbageCount / bytes.length;
    if (garbageRatio > 0.3) return null;

    if (!hasIac && !text.trim()) return null;
    const fields = [];
    if (negotiations.length) {
        fields.push({ name: "Negotiations", value: negotiations.join(", ") });
    }
    if (text.trim()) {
        const t = text.trim();
        fields.push({
            name: "Text",
            value: t.length > 500 ? t.slice(0, 500) + "…" : t,
        });
    }
    if (!fields.length) return null;
    return { protocol: "Telnet", fields };
}

module.exports = { decodeTelnetFromBytes };
