// SIP Conv decoder: parses the first line of a SIP message (request or
// response) and a curated set of common headers, with support for compact
// header forms ("f:" = From, "t:" = To, etc.).

const SIP_METHODS = new Set([
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "REGISTER",
    "OPTIONS",
    "SUBSCRIBE",
    "NOTIFY",
    "REFER",
    "INFO",
    "UPDATE",
    "PRACK",
    "MESSAGE",
    "PUBLISH",
]);

const COMPACT_HEADER_NAMES = {
    f: "from",
    t: "to",
    i: "call-id",
    m: "contact",
    v: "via",
    l: "content-length",
    c: "content-type",
    r: "refer-to",
};

const INTERESTING_HEADERS = [
    ["from", "From"],
    ["to", "To"],
    ["call-id", "Call-ID"],
    ["cseq", "CSeq"],
    ["via", "Via"],
    ["contact", "Contact"],
    ["max-forwards", "Max-Forwards"],
    ["user-agent", "User-Agent"],
    ["authorization", "Authorization"],
    ["proxy-authorization", "Proxy-Authorization"],
    ["route", "Route"],
    ["record-route", "Record-Route"],
    ["content-type", "Content-Type"],
    ["content-length", "Content-Length"],
    ["expires", "Expires"],
];

const REQUEST_LINE_RE = /^([A-Z]+)\s+(\S+)\s+SIP\/([\d.]+)$/i;
const RESPONSE_LINE_RE = /^SIP\/([\d.]+)\s+(\d{3})(?:\s+(.*))?$/i;
const BODY_PREVIEW_LIMIT = 220;
const HEADER_VALUE_LIMIT = 180;

function truncateField(value, limit) {
    if (typeof value !== "string") return "";
    const trimmed = value.trim();
    if (!trimmed) return "";
    return trimmed.length > limit ? `${trimmed.slice(0, limit)}...` : trimmed;
}

function decodeSipFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    const lines = text.split(/\r?\n/);
    if (!lines.length) return null;

    const firstLine = (lines[0] || "").trim();
    if (!firstLine) return null;

    const requestMatch = firstLine.match(REQUEST_LINE_RE);
    const responseMatch = firstLine.match(RESPONSE_LINE_RE);
    const isRequest = Boolean(requestMatch && SIP_METHODS.has(requestMatch[1].toUpperCase()));
    const isResponse = Boolean(responseMatch);
    if (!isRequest && !isResponse) return null;

    const headerLines = [];
    let bodyStartIndex = lines.length;
    for (let i = 1; i < lines.length; i += 1) {
        const rawLine = lines[i] || "";
        if (!rawLine.trim()) {
            bodyStartIndex = i + 1;
            break;
        }
        if (/^[ \t]/.test(rawLine) && headerLines.length) {
            headerLines[headerLines.length - 1] += ` ${rawLine.trim()}`;
            continue;
        }
        headerLines.push(rawLine);
    }

    const headerMap = new Map();
    headerLines.forEach((line) => {
        const separator = line.indexOf(":");
        if (separator <= 0) return;
        const rawName = line.slice(0, separator).trim();
        const value = line.slice(separator + 1).trim();
        if (!rawName || !value) return;
        const lowered = rawName.toLowerCase();
        const normalizedName = COMPACT_HEADER_NAMES[lowered] || lowered;
        if (!headerMap.has(normalizedName)) headerMap.set(normalizedName, []);
        headerMap.get(normalizedName).push(value);
    });

    const getHeaderValue = (name) => {
        const values = headerMap.get(String(name || "").toLowerCase());
        if (!Array.isArray(values) || !values.length) return "";
        return values.join(" | ");
    };

    const fields = [];
    if (isRequest && requestMatch) {
        fields.push(
            { name: "Type", value: "Request" },
            { name: "Method", value: requestMatch[1].toUpperCase() },
            { name: "Request URI", value: requestMatch[2] || "N/A" },
            { name: "SIP Version", value: requestMatch[3] || "N/A" },
        );
    }
    if (isResponse && responseMatch) {
        fields.push(
            { name: "Type", value: "Response" },
            { name: "SIP Version", value: responseMatch[1] || "N/A" },
            { name: "Status Code", value: responseMatch[2] || "N/A" },
            { name: "Reason Phrase", value: responseMatch[3] || "N/A" },
        );
    }

    INTERESTING_HEADERS.forEach(([headerKey, label]) => {
        const value = truncateField(getHeaderValue(headerKey), HEADER_VALUE_LIMIT);
        if (value) fields.push({ name: label, value });
    });

    const bodyText = lines.slice(bodyStartIndex).join("\n").trim();
    if (bodyText) {
        fields.push({
            name: "Body Preview",
            value: truncateField(bodyText, BODY_PREVIEW_LIMIT),
        });
    }

    return fields.length ? { protocol: "SIP", fields } : null;
}

module.exports = { decodeSipFromBytes };
