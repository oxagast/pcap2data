// HTTP Conv decoder: parses HTTP request/response blocks out of byte streams
// and emits the request line / response status plus a curated set of common
// headers. Caps results at maxBlocks (25) to keep the panel responsive.

const MAX_BLOCKS = 25;
const REQUEST_HEADER_NAMES = [
    "Host",
    "User-Agent",
    "Content-Type",
    "Content-Length",
    "Accept",
    "Accept-Encoding",
    "Connection",
    "Authorization",
    "Referer",
    "Cookie",
];
const RESPONSE_HEADER_NAMES = [
    "Server",
    "Content-Type",
    "Content-Length",
    "Content-Encoding",
    "Transfer-Encoding",
    "Connection",
    "Location",
    "Set-Cookie",
    "Cache-Control",
    "Date",
];
const REQUEST_LINE_RE = /^([A-Z]+)\s+(\S+)\s+(HTTP\/[\d.]+)$/;
const RESPONSE_LINE_RE = /^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)/;

function isHttpStartLine(line) {
    return REQUEST_LINE_RE.test(line) || RESPONSE_LINE_RE.test(line);
}

function decodeHttpFromBytes(bytes) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    const lines = text.split(/\r?\n/);
    if (!lines.length) return null;

    const startIndexes = [];
    lines.forEach((rawLine, index) => {
        const trimmed = rawLine.trim();
        if (trimmed && isHttpStartLine(trimmed)) {
            startIndexes.push(index);
        }
    });
    if (!startIndexes.length) return null;

    const fields = [];
    for (let blockIndex = 0; blockIndex < startIndexes.length && blockIndex < MAX_BLOCKS; blockIndex += 1) {
        const startLineIndex = startIndexes[blockIndex];
        const nextStartLineIndex =
            blockIndex + 1 < startIndexes.length ? startIndexes[blockIndex + 1] : lines.length;
        const firstLine = (lines[startLineIndex] || "").trim();
        const requestMatch = firstLine.match(REQUEST_LINE_RE);
        const responseMatch = firstLine.match(RESPONSE_LINE_RE);
        if (!requestMatch && !responseMatch) continue;

        const headerEndIndex = lines
            .slice(startLineIndex + 1, nextStartLineIndex)
            .findIndex((line) => line.trim() === "");
        const absoluteHeaderEndIndex =
            headerEndIndex >= 0
                ? startLineIndex + 1 + headerEndIndex
                : nextStartLineIndex;
        const headerLines = lines.slice(startLineIndex + 1, absoluteHeaderEndIndex);
        const headers = {};
        headerLines.forEach((headerLine) => {
            const separatorIndex = headerLine.indexOf(":");
            if (separatorIndex > 0) {
                headers[headerLine.slice(0, separatorIndex).trim()] =
                    headerLine.slice(separatorIndex + 1).trim();
            }
        });

        fields.push({ name: `Block ${blockIndex + 1}`, value: requestMatch ? "HTTP Request" : "HTTP Response" });
        if (requestMatch) {
            fields.push(
                { name: "Type", value: "Request" },
                { name: "Method", value: requestMatch[1] },
                { name: "URL", value: requestMatch[2] },
                { name: "Version", value: requestMatch[3] },
            );
            REQUEST_HEADER_NAMES.forEach((headerName) => {
                if (headers[headerName]) fields.push({ name: headerName, value: headers[headerName] });
            });
        } else {
            fields.push(
                { name: "Type", value: "Response" },
                { name: "Version", value: responseMatch[1] },
                { name: "Status Code", value: responseMatch[2] },
                { name: "Status Message", value: responseMatch[3] || "—" },
            );
            RESPONSE_HEADER_NAMES.forEach((headerName) => {
                if (headers[headerName]) fields.push({ name: headerName, value: headers[headerName] });
            });
        }

        const bodyStartIndex = absoluteHeaderEndIndex < nextStartLineIndex
            ? absoluteHeaderEndIndex + 1
            : absoluteHeaderEndIndex;
        if (bodyStartIndex < nextStartLineIndex) {
            const bodyPreview = lines
                .slice(bodyStartIndex, nextStartLineIndex)
                .join("\n")
                .trim();
            if (bodyPreview) {
                fields.push({
                    name: "Body (preview)",
                    value: bodyPreview.length > 200 ? bodyPreview.slice(0, 200) + "…" : bodyPreview,
                });
            }
        }
    }

    if (startIndexes.length > MAX_BLOCKS) {
        fields.push({
            name: "Notice",
            value: `Showing first ${MAX_BLOCKS} HTTP blocks out of ${startIndexes.length}.`,
        });
    }

    if (!fields.length) return null;
    return { protocol: "HTTP", fields };
}

module.exports = { decodeHttpFromBytes };
