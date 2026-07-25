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

function decodeTelnetFromBytes(bytes) {
    const negotiations = [];
    let text = "";
    let i = 0;
    let hasIac = false;
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
            if (b >= 32 && b < 127) text += String.fromCharCode(b);
            else if (b === 10) text += "\n";
            else if (b === 13) text += "\r";
        }
    }
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
