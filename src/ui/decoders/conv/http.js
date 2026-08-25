// HTTP Conv decoder: parses HTTP request/response blocks out of byte streams
// and emits the request line / response status plus a curated set of common
// headers. Caps results at maxBlocks (25) to keep the panel responsive.
//
// This file also owns the HTTP body-boundary detection helpers used by the
// file-carver path in src/ui/main-frontend.js — see the helpers below
// `decodeHttpFromBytes`. The carve pipeline consumes:
//
//   * `extractHttpBodyHex` / `findHttpHeaderBodySeparators` — locate header
//     terminators inside a raw payload (handles pipelined responses).
//   * `sliceHttpMessageSegments` — split a payload hex into per-message
//     `{ headerHex, bodyHex }` pairs.
//   * `collectHttpMessageBodiesFromStream` — gather per-message bodies
//     from same-direction TCP packets, applying per-message
//     Content-Length / chunked framing.
//   * `extractFilenameFromContentDisposition` /
//     `extractMultipartBoundaryFromContentType` — Content-Disposition /
//     Content-Type helpers for filename inference and multipart detection.
//   * `findMultipartFileByteRanges` — enumerate every multipart part that
//     carries a filename; each becomes its own carvable candidate.
//
// All helpers are pure functions of their inputs and return new objects,
// so callers can compose them without worrying about shared state.
//
// NOTE: keep the `module.exports` block at the BOTTOM of this file. Some
// of the helpers are declared with `const` further down, and module
// initialisation order matters: an exports block placed before the consts
// will hit JavaScript's temporal dead zone and throw
// "Cannot access 'HTTP_FILENAME_EXT_BY_MIME' before initialization".

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

// ---------------------------------------------------------------------------
// HTTP body-boundary detection helpers (consumed by the file-carver path)
// ---------------------------------------------------------------------------

const HTTP_FILENAME_EXT_BY_MIME = Object.freeze({
    "application/json": "json",
    "application/pdf": "pdf",
    "application/zip": "zip",
    "application/gzip": "gz",
    "application/x-7z-compressed": "7z",
    "application/x-rar-compressed": "rar",
    "application/xml": "xml",
    "text/plain": "txt",
    "text/html": "html",
    "text/css": "css",
    "text/javascript": "js",
    "text/csv": "csv",
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
    "audio/mpeg": "mp3",
    "video/mp4": "mp4",
});

// Default filename sanitizer — strips directory separators and characters
// that would be unsafe in a carve filename. The renderer passes its own
// `sanitizeCarveFilename` (which preserves the existing extension-based
// filename behaviour) so this default keeps the helper safe to call in
// isolation (e.g. from unit tests).
function defaultSanitizeCarveFilename(name) {
    return String(name || "").replace(/[\u0000-\u001f\u007f<>:"/\\|?*]+/g, "_");
}

// Extracts the HTTP body hex from a single packet's payload hex. This is the
// raw slice after the first CRLFCRLF separator — callers that need to handle
// pipelined responses (multiple messages in one packet) should use
// `sliceHttpMessageSegments` instead.
function extractHttpBodyHex(payloadHex) {
    if (!payloadHex) return "";
    // Locate the HTTP header/body separator in hex space.
    // RFC 7230 mandates \r\n\r\n which encodes as "0d0a0d0a".
    const normalized = payloadHex.replace(/\s+/g, "");
    const lower = normalized.toLowerCase();
    const sepIdx = lower.indexOf("0d0a0d0a");
    if (sepIdx === -1) return "";
    const bodyStart = sepIdx + 8; // skip past the 4-byte CRLFCRLF separator
    if (bodyStart >= normalized.length) return "";
    return normalized.slice(bodyStart);
}

// Returns every CRLFCRLF position (in hex chars) inside a payload. Used to
// detect HTTP/1.x message boundaries — including pipelined requests /
// responses packed into a single TCP segment. Each returned position is the
// index of the "0d0a0d0a" separator; the body of the message immediately
// preceding it starts at `position + 8`.
function findHttpHeaderBodySeparators(payloadHex) {
    if (!payloadHex) return [];
    const normalized = payloadHex.replace(/\s+/g, "");
    const lower = normalized.toLowerCase();
    const SEP_HEX = "0d0a0d0a";
    const SEP_LEN = SEP_HEX.length;
    if (normalized.length < SEP_LEN) return [];

    const positions = [];
    let cursor = 0;
    while (cursor <= lower.length - SEP_LEN) {
        const nextIdx = lower.indexOf(SEP_HEX, cursor);
        if (nextIdx === -1) break;
        positions.push(nextIdx);
        cursor = nextIdx + SEP_LEN;
    }
    return positions;
}

// Heuristic: does a slice of decoded HTTP-ish text look like the start of a
// new HTTP/1.x message? We accept a request line ("GET / HTTP/1.1\r") or
// response status line ("HTTP/1.1 200 OK\r"). This is intentionally lenient —
// the carve path is best-effort and falls back gracefully when it is wrong.
function looksLikeHttpStartLine(asciiText) {
    const head = String(asciiText || "").slice(0, 4096);
    if (!head) return false;
    // Response status line — accept HTTP/<digits> or HTTP/<digits>.<digits>
    if (/^HTTP\/\d+(?:\.\d+)?\s+\d{3}[^\r\n]*/.test(head)) return true;
    // Common request methods
    const requestLineMatch = head.match(
        /^(GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/\d(?:\.\d)?\r?\n/,
    );
    return Boolean(requestLineMatch);
}

// Splits a payload hex string into the individual HTTP/1.x message segments
// it carries. Returns an array of `{ headerHex, bodyHex, bodyStart, bodyEnd,
// index }` describing each message. `bodyStart` / `bodyEnd` are hex offsets
// relative to the start of the input (NOT byte offsets), suitable for
// slicing the original hex string. Returns an empty array when the payload
// has no recognizable HTTP framing.
//
// A segment is included only when:
//   1. A CRLFCRLF separator is found (mandatory per RFC 7230).
//   2. The text preceding the separator (the start line + headers) decodes
//      as something that looks like an HTTP start line. This filters out
//      accidental CRLFCRLF occurrences inside binary body data.
//
// For pipelined responses (HTTP/1.1 keep-alive with multiple responses per
// TCP segment), each response becomes a separate segment.
function sliceHttpMessageSegments(payloadHex) {
    const normalized = typeof payloadHex === "string" ? payloadHex.replace(/\s+/g, "") : "";
    if (normalized.length < 8) return [];

    const separators = findHttpHeaderBodySeparators(normalized);
    if (!separators.length) return [];

    // Pre-compute the ASCII-decoded payload once so we can search for HTTP
    // start lines inside body regions without re-decoding the whole payload
    // for every segment. The decoded text is indexed by hex-char position / 2
    // (i.e. byte offsets), and we map back to hex positions when slicing.
    let fullAscii = "";
    try {
        fullAscii = hexToAsciiString(normalized);
    } catch {
        fullAscii = "";
    }

    // Helper: find the byte offset of the next HTTP start line at or after
    // `fromByteOffset`. Returns -1 when none is found. We scan the decoded
    // ASCII for HTTP/ or common request methods. In pipelined HTTP, the
    // next message begins immediately after the previous body (no line
    // break), so we do NOT require a preceding \n.
    const findNextStartLineByteOffset = (fromByteOffset) => {
        if (!fullAscii) return -1;
        const searchStart = Math.max(fromByteOffset, 0);
        // Match a response status line ("HTTP/x.y <3digits>") or a request
        // method line ("GET / HTTP/1.1"). The match may begin anywhere
        // after the body starts.
        const startLineRe = /(?:HTTP\/\d+(?:\.\d+)?\s+\d{3}|(?:GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/\d(?:\.\d)?)/g;
        startLineRe.lastIndex = searchStart;
        const match = startLineRe.exec(fullAscii);
        return match ? match.index : -1;
    };

    const segments = [];
    let headerStartHex = 0;
    for (let i = 0; i < separators.length; i += 1) {
        const separatorPos = separators[i];
        const headerHex = normalized.slice(headerStartHex, separatorPos);
        const headerBytesLength = separatorPos - headerStartHex;
        if (headerBytesLength <= 0) {
            // Empty headers between consecutive separators — skip. This can
            // happen when a body contains the byte sequence 0d0a0d0a by
            // accident; we'll keep searching forward rather than emit a bogus
            // segment.
            continue;
        }
        let headerText = "";
        try {
            headerText = hexToAsciiString(headerHex).slice(0, 4096);
        } catch {
            headerText = "";
        }
        if (!looksLikeHttpStartLine(headerText)) {
            // The CRLFCRLF is inside a body or some other binary blob. Skip and
            // keep scanning forward so we still find real boundaries after the
            // noise.
            continue;
        }
        const bodyStartHex = separatorPos + 8;
        const bodyStartByte = bodyStartHex / 2;

        // Determine where this body ends. Two strategies, in priority order:
        //
        //   1. If the header block has a Content-Length, the body extends
        //      exactly that many bytes. This is authoritative per RFC 7230
        //      and prevents false start-line matches inside binary body
        //      data (e.g. a BMP file whose pixels happen to contain the
        //      bytes "HTTP/1.1 200").
        //
        //   2. Otherwise (HTTP/1.0 without Content-Length, or
        //      until-close framing), scan for the next HTTP start line to
        //      find where the next message begins.
        let bodyEndHex = normalized.length;
        const contentLengthFromHeader = parseContentLengthFromHeaderAscii(headerText);
        if (contentLengthFromHeader !== null) {
            bodyEndHex = Math.min(normalized.length, bodyStartHex + contentLengthFromHeader * 2);
        } else {
            const nextStartLineByte = findNextStartLineByteOffset(bodyStartByte);
            if (nextStartLineByte !== -1) {
                bodyEndHex = nextStartLineByte * 2;
            }
        }

        const bodyHex = normalized.slice(bodyStartHex, bodyEndHex);
        segments.push({
            headerHex,
            bodyHex,
            bodyStart: bodyStartHex,
            bodyEnd: bodyEndHex,
            index: segments.length,
        });
        // The next segment's header begins where this body ended.
        headerStartHex = bodyEndHex;
    }
    return segments;
}

// Returns whether a Content-Length or Transfer-Encoding header appears in a
// header hex slice. Used to distinguish a definitive length from an
// implicit "until next message" framing when detecting message boundaries.
function httpHeadersHaveExplicitFraming(headerHex) {
    const headerText = hexToAsciiString(headerHex).toLowerCase();
    if (!headerText) return false;
    return /\r?\ncontent-length\s*:/.test(headerText) ||
        /\r?\ntransfer-encoding\s*:\s*[^\r\n]*chunked\b/.test(headerText);
}

// Splits the ASCII-decoded HTTP headers into `{ startLine, headers }` where
// `headers` is an array of `{ name, value }` pairs in wire order. Used by
// `collectHttpMessageBodiesFromStream` to derive per-message framing
// information without forcing callers to re-implement header parsing.
function splitHttpMessageHeaders(headerAscii) {
    const text = String(headerAscii || "");
    if (!text) return { startLine: "", headers: [] };
    const lines = text.split(/\r?\n/);
    const startLine = (lines.shift() || "").trim();
    const headers = [];
    for (const rawLine of lines) {
        if (!rawLine) break; // blank line terminates the header block
        const colonIdx = rawLine.indexOf(":");
        if (colonIdx <= 0) continue;
        headers.push({
            name: rawLine.slice(0, colonIdx).trim(),
            value: rawLine.slice(colonIdx + 1).trim(),
        });
    }
    return { startLine, headers };
}

// Walks the same-direction TCP stream starting at `referencePacket` and
// returns one entry per HTTP/1.x message body in the concatenated payload.
// `getPacketPayloadHex(packet)` and `isSameDirectionalStreamPacket` are
// injected so the helper stays free of UI / DOM dependencies.
//
// Each entry in the returned array has the shape:
//   {
//     bodyHex,                // hex string of the message body
//     headerHex,              // hex string of the message headers (incl. start line)
//     messageIndex,           // 0-based order within the stream
//     sourcePacket,           // the first packet that carried bytes for this message
//     framing,                // 'content-length' | 'chunked' | 'until-next-message'
//     declaredContentLength,  // numeric Content-Length or null
//   }
function collectHttpMessageBodiesFromStream({
    streamPackets,
    referencePacket,
    getPacketIdentity,
    getPacketPayloadHex,
    isSameDirectionalStreamPacket,
    getHttpContentLengthFromPacket,
    isChunkedHttpTransferForPacket,
}) {
    if (
        !Array.isArray(streamPackets) ||
        !streamPackets.length ||
        !referencePacket ||
        typeof getPacketPayloadHex !== "function" ||
        typeof isSameDirectionalStreamPacket !== "function"
    ) {
        return [];
    }
    const referenceIdentity =
        typeof getPacketIdentity === "function"
            ? getPacketIdentity(referencePacket)
            : null;
    const referenceIndex = streamPackets.findIndex((packet) => {
        return (
            typeof getPacketIdentity === "function" &&
            getPacketIdentity(packet) === referenceIdentity
        );
    });
    if (referenceIndex === -1) return [];

    const firstPacket = streamPackets[referenceIndex];
    const firstPayload = getPacketPayloadHex(firstPacket);
    if (!firstPayload) return [];

    // Concatenate the payloads of every same-direction packet starting at the
    // reference packet. This preserves the order in which the bytes arrived
    // on the wire, which is what RFC 7230 assumes when it talks about
    // pipelining.
    const payloadParts = [];
    for (
        let packetIndex = referenceIndex;
        packetIndex < streamPackets.length;
        packetIndex += 1
    ) {
        const packet = streamPackets[packetIndex];
        if (!isSameDirectionalStreamPacket(packet, firstPacket)) continue;
        const payloadHex = getPacketPayloadHex(packet).replace(/\s+/g, "");
        if (payloadHex) payloadParts.push(payloadHex);
    }
    if (!payloadParts.length) return [];
    const combinedHex = payloadParts.join("");

    // First try: split the combined payload at HTTP start-line boundaries.
    let segments = sliceHttpMessageSegments(combinedHex);

    // When the first packet has explicit framing (Content-Length or chunked
    // Transfer-Encoding) but the payload has only one HTTP start line, the
    // boundary split above is equivalent to clamping to that single message.
    // We preserve any extra framing-aware body slicing (chunked trailers) for
    // that first message.
    if (!segments.length) {
        const fallbackHex = extractHttpBodyHex(firstPayload);
        if (!fallbackHex) return [];
        return [{
            bodyHex: fallbackHex,
            headerHex: "",
            messageIndex: 0,
            sourcePacket: firstPacket,
            framing:
                typeof isChunkedHttpTransferForPacket === "function" &&
                    isChunkedHttpTransferForPacket(firstPacket)
                    ? "chunked"
                    : "until-next-message",
            declaredContentLength:
                typeof getHttpContentLengthFromPacket === "function"
                    ? getHttpContentLengthFromPacket(firstPacket)
                    : null,
        }];
    }

    // Walk the segments and apply per-message framing constraints. For each
    // segment:
    //   - if its header has Content-Length, clamp bodyHex to that length;
    //   - else if its header advertises chunked, replace bodyHex with the
    //     chunked-decoded slice (which strips chunk-size / CRLF framing);
    //   - else, the bodyHex is already correctly bounded to the next
    //     start line (until-next-message framing).
    const framed = [];
    for (let i = 0; i < segments.length; i += 1) {
        const segment = segments[i];
        let { bodyHex } = segment;
        let framing = "until-next-message";
        let declaredContentLength = null;

        if (httpHeadersHaveExplicitFraming(segment.headerHex)) {
            const headerText = hexToAsciiString(segment.headerHex).toLowerCase();
            const clMatch = headerText.match(/\r?\ncontent-length\s*:\s*(\d+)/);
            if (clMatch) {
                const contentLength = Number.parseInt(clMatch[1], 10);
                if (Number.isFinite(contentLength) && contentLength >= 0) {
                    declaredContentLength = contentLength;
                    framing = "content-length";
                    bodyHex = bodyHex.slice(0, contentLength * 2);
                }
            } else if (
                /\r?\ntransfer-encoding\s*:\s*[^\r\n]*chunked\b/.test(headerText)
            ) {
                framing = "chunked";
                const decoded = sliceCompleteChunkedHttpBodyHex(bodyHex);
                if (decoded !== null) bodyHex = decoded;
            }
        }

        if (!bodyHex) continue;
        framed.push({
            bodyHex,
            headerHex: segment.headerHex,
            messageIndex: i,
            sourcePacket: firstPacket,
            framing,
            declaredContentLength,
        });
    }

    return framed;
}

// Returns the file extension that matches a Content-Type value, or "bin".
function getHttpBodyFilenameExtension(contentTypeValue) {
    const normalizedType = String(contentTypeValue || "")
        .split(";")[0]
        .trim()
        .toLowerCase();
    if (!normalizedType) return "bin";
    return HTTP_FILENAME_EXT_BY_MIME[normalizedType] || "bin";
}

// Extracts a filename from a Content-Disposition header value, falling
// back through RFC 5987 (filename*), quoted (filename="..."), and bare
// (filename=...) forms. The `sanitize` argument is the caller-supplied
// filename sanitizer (typically `sanitizeCarveFilename`); when omitted, a
// permissive default is used so this helper stays unit-test friendly.
function extractFilenameFromContentDisposition(dispositionValue, sanitize) {
    const sanitizeFn = typeof sanitize === "function" ? sanitize : defaultSanitizeCarveFilename;
    const rawValue = String(dispositionValue || "").trim();
    if (!rawValue) return "";

    const utf8Match = rawValue.match(/filename\*=UTF-8''([^;]+)/i);
    if (utf8Match?.[1]) {
        try {
            return sanitizeFn(decodeURIComponent(utf8Match[1]));
        } catch {
            return sanitizeFn(utf8Match[1]);
        }
    }

    const quotedMatch = rawValue.match(/filename\s*=\s*"([^"]+)"/i);
    if (quotedMatch?.[1]) {
        return sanitizeFn(quotedMatch[1]);
    }

    const bareMatch = rawValue.match(/filename\s*=\s*([^;\s]+)/i);
    if (bareMatch?.[1]) {
        return sanitizeFn(bareMatch[1]);
    }

    return "";
}

// Extracts the multipart boundary token from a Content-Type header value.
function extractMultipartBoundaryFromContentType(contentTypeValue) {
    const rawValue = String(contentTypeValue || "").trim();
    if (!rawValue) return "";
    if (!rawValue.toLowerCase().includes("multipart")) return "";
    const boundaryMatch = rawValue.match(
        /\bboundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i,
    );
    return boundaryMatch?.[1] || boundaryMatch?.[2] || "";
}

// Extracts a filename from the first Content-Disposition header inside a
// multipart boundary block. The boundary parameter must include the leading
// "--" per RFC 2046.
function extractMultipartFilenameFromBodyBytes(bodyBytes, boundaryToken, sanitize) {
    if (!bodyBytes || !(bodyBytes instanceof Uint8Array) || bodyBytes.length === 0) {
        return "";
    }
    if (!boundaryToken || typeof boundaryToken !== "string") return "";

    const boundaryBytes = new TextEncoder().encode(`--${boundaryToken}`);
    // Scan the full body — not just the first 8 KiB. Real-world multipart
    // uploads may sit well past 8 KiB before the first boundary when a
    // gateway prepends a preamble, and the original 8192-byte cap silently
    // dropped any file the user actually cared about.
    let boundaryIndex = -1;
    for (let i = 0; i <= bodyBytes.length - boundaryBytes.length; i += 1) {
        let match = true;
        for (let j = 0; j < boundaryBytes.length; j += 1) {
            if (bodyBytes[i + j] !== boundaryBytes[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            boundaryIndex = i;
            break;
        }
    }
    if (boundaryIndex === -1) return "";

    const headerEndLimit = Math.min(
        bodyBytes.length,
        boundaryIndex + 4096,
    );
    const headerBytes = bodyBytes.slice(boundaryIndex, headerEndLimit);
    const headerText = new TextDecoder("utf-8", { fatal: false }).decode(
        headerBytes,
    );
    const firstCrlfCrlf = headerText.indexOf("\r\n\r\n");
    const dispositionText =
        firstCrlfCrlf !== -1 ? headerText.slice(0, firstCrlfCrlf) : headerText;

    const dispositionMatch = dispositionText.match(
        /Content-Disposition\s*:([^\r\n]*)/i,
    );
    if (!dispositionMatch?.[1]) return "";

    return extractFilenameFromContentDisposition(dispositionMatch[1].trim(), sanitize);
}

// Returns the byte range of the first multipart file payload inside a
// multipart body. The returned range is [start, end) where end points to the
// byte before the closing boundary marker.
function findMultipartFileByteRange(bodyBytes, boundaryToken) {
    const ranges = findMultipartFileByteRanges(bodyBytes, boundaryToken);
    return ranges.length ? ranges[0].range : null;
}

// Walks every multipart part inside a body and returns one entry per part
// that carries a `Content-Disposition` with a filename. Each entry has the
// shape:
//   {
//     range:     { start, end },   // byte offsets inside bodyBytes
//     fileName:  string,           // sanitized via extractFilenameFromContentDisposition
//     partIndex: number,           // 0-based index among ALL parts (not just file parts)
//     contentType: string,         // from the part's Content-Type header, or ''
//   }
//
// Boundaries inside a multipart body come in two flavors:
//   * `--<boundary>\r\n`     — opens a part (followed by part headers + body)
//   * `--<boundary>--`       — closing marker; everything after it is the
//                              epilogue and is ignored
//
// The returned byte ranges cover only the part payload (after the blank line
// that terminates the part headers), so callers can hand them straight to
// `bodyBytes.slice(start, end)` to get the file bytes.
function findMultipartFileByteRanges(bodyBytes, boundaryToken, sanitize) {
    if (!bodyBytes || !(bodyBytes instanceof Uint8Array) || bodyBytes.length === 0) {
        return [];
    }
    if (!boundaryToken || typeof boundaryToken !== "string") return [];

    const boundaryBytes = new TextEncoder().encode(`--${boundaryToken}`);
    const sanitizeFn = typeof sanitize === "function" ? sanitize : defaultSanitizeCarveFilename;

    // Locate every part boundary by scanning the full body.
    // We collect all boundary marker positions and then classify each one as
    // an opener (`--<boundary>\r\n`), a closer (`--<boundary>--`), or noise
    // (boundary token appears inside a body payload as raw bytes).
    const markerPositions = [];
    for (let i = 0; i <= bodyBytes.length - boundaryBytes.length; i += 1) {
        let match = true;
        for (let j = 0; j < boundaryBytes.length; j += 1) {
            if (bodyBytes[i + j] !== boundaryBytes[j]) {
                match = false;
                break;
            }
        }
        if (!match) continue;
        const afterBoundary = i + boundaryBytes.length;
        if (
            afterBoundary < bodyBytes.length &&
            bodyBytes[afterBoundary] === 0x2d /* '-' */ &&
            afterBoundary + 1 < bodyBytes.length &&
            bodyBytes[afterBoundary + 1] === 0x2d
        ) {
            // Closing boundary `--<boundary>--`
            markerPositions.push({ offset: i, kind: "close" });
            i = afterBoundary + 1; // skip past the trailing dashes
            continue;
        }
        // An opener must be followed by CRLF or LF (otherwise the token is just
        // a substring coincidence). Anything else is treated as body noise.
        if (
            afterBoundary < bodyBytes.length &&
            (bodyBytes[afterBoundary] === 0x0d /* \r */ ||
                bodyBytes[afterBoundary] === 0x0a /* \n */)
        ) {
            markerPositions.push({ offset: i, kind: "open" });
            i = afterBoundary; // skip past the \r or \n that follows
        }
    }
    if (!markerPositions.length) return [];

    const openerIndices = markerPositions
        .map((marker, index) => (marker.kind === "open" ? index : -1))
        .filter((idx) => idx !== -1);
    if (!openerIndices.length) return [];

    const fileRanges = [];
    for (let openerCursor = 0; openerCursor < openerIndices.length; openerCursor += 1) {
        const openerIdx = openerIndices[openerCursor];
        const opener = markerPositions[openerIdx];
        const openerEnd = opener.offset + boundaryBytes.length;
        // Skip the line terminator that immediately follows the opener marker.
        let headerStart = openerEnd;
        if (headerStart < bodyBytes.length && bodyBytes[headerStart] === 0x0d) {
            headerStart += 1;
        }
        if (headerStart < bodyBytes.length && bodyBytes[headerStart] === 0x0a) {
            headerStart += 1;
        }

        // Find the blank line (\r\n\r\n or \n\n) that terminates part headers.
        const headerWindowEnd = Math.min(bodyBytes.length, headerStart + 8192);
        let headerTerminatorEnd = -1;
        let headerTerminatorLength = 0;
        for (let i = headerStart; i <= headerWindowEnd - 4; i += 1) {
            if (
                bodyBytes[i] === 0x0d && bodyBytes[i + 1] === 0x0a &&
                bodyBytes[i + 2] === 0x0d && bodyBytes[i + 3] === 0x0a
            ) {
                headerTerminatorEnd = i + 4;
                headerTerminatorLength = 4;
                break;
            }
        }
        if (headerTerminatorEnd === -1) {
            // No blank line found within the part-header window — try a LF-only
            // terminator (lenient fallback for non-conformant bodies).
            for (let i = headerStart; i <= headerWindowEnd - 2; i += 1) {
                if (bodyBytes[i] === 0x0a && bodyBytes[i + 1] === 0x0a) {
                    headerTerminatorEnd = i + 2;
                    headerTerminatorLength = 2;
                    break;
                }
            }
        }
        if (headerTerminatorEnd === -1) continue;

        const headerBytes = bodyBytes.slice(
            headerStart,
            headerTerminatorEnd - headerTerminatorLength,
        );
        const headerText = new TextDecoder("utf-8", { fatal: false }).decode(headerBytes);

        const dispositionMatch = headerText.match(
            /Content-Disposition\s*:([^\r\n]*)/i,
        );
        if (!dispositionMatch?.[1]) continue;
        const dispositionValue = dispositionMatch[1].trim();
        const isFormField =
            /\bform-data\s*;/i.test(dispositionValue) &&
            !/filename\s*=\s*"?[^";]+"?/i.test(dispositionValue);
        if (isFormField) continue;
        const fileName = extractFilenameFromContentDisposition(dispositionValue, sanitizeFn);
        if (!fileName) continue;

        const contentTypeMatch = headerText.match(/Content-Type\s*:\s*([^\r\n]+)/i);
        const partContentType = contentTypeMatch ? contentTypeMatch[1].trim() : "";

        // The payload ends at the next boundary marker (opener or closer), or
        // at end-of-body if no further marker is present.
        const nextOpenerIdx = openerIndices[openerCursor + 1];
        const endSearchStart = headerTerminatorEnd;
        let payloadEnd = bodyBytes.length;

        const limitByMarker = (nextMarkerIdx) => {
            if (nextMarkerIdx === undefined) return;
            const marker = markerPositions[nextMarkerIdx];
            const candidateEnd = marker.offset;
            // Part bodies end with CRLF immediately before the boundary, so the
            // payload we want to keep stops just before the \r\n that precedes
            // the marker. We do a tiny scan back from `candidateEnd` to strip a
            // trailing \r\n (and an extra trailing \n for LF-only terminators).
            let trimEnd = candidateEnd;
            while (trimEnd > endSearchStart) {
                const b = bodyBytes[trimEnd - 1];
                if (b === 0x0a || b === 0x0d) {
                    trimEnd -= 1;
                    continue;
                }
                break;
            }
            if (trimEnd < candidateEnd) {
                payloadEnd = Math.min(payloadEnd, trimEnd);
            } else {
                payloadEnd = Math.min(payloadEnd, candidateEnd);
            }
        };

        // The closer marker terminates the final part, but only if no further
        // opener comes between this opener and the closer. We always check the
        // next marker regardless of kind, since opacities in the wire order
        // would otherwise leave dangling bytes.
        const nextMarkerIdx =
            nextOpenerIdx !== undefined
                ? nextOpenerIdx
                : (() => {
                    const afterIdx = openerIdx + 1;
                    return afterIdx < markerPositions.length ? afterIdx : undefined;
                })();
        limitByMarker(nextMarkerIdx);

        if (payloadEnd <= headerTerminatorEnd) continue;

        fileRanges.push({
            range: { start: headerTerminatorEnd, end: payloadEnd },
            fileName,
            partIndex: openerCursor,
            contentType: partContentType,
        });
    }

    return fileRanges;
}

// Decodes a hex string to ASCII text. Operates byte-by-byte so any hex
// string of even length is a valid input.
function hexToAsciiString(hex) {
    const normalized = typeof hex === "string" ? hex.replace(/\s+/g, "") : "";
    let result = "";
    for (let idx = 0; idx + 1 < normalized.length; idx += 2) {
        result += String.fromCharCode(
            Number.parseInt(normalized.slice(idx, idx + 2), 16),
        );
    }
    return result;
}

// Returns true when a (decoded) header block advertises
// `Transfer-Encoding: chunked`. Accepts LF or CRLF line endings.
function isChunkedTransferEncodingHeader(headerAscii) {
    const text = String(headerAscii || "").toLowerCase();
    if (!text) return false;
    return /\r?\ntransfer-encoding\s*:\s*[^\r\n]*chunked\b/.test(text);
}

// Parses the first numeric Content-Length value out of a header block.
function parseContentLengthFromHeaderAscii(headerAscii) {
    const text = String(headerAscii || "");
    if (!text) return null;
    const match = text.match(/\r?\ncontent-length\s*:\s*(\d+)/i);
    if (!match) return null;
    const value = Number.parseInt(match[1], 10);
    return Number.isFinite(value) && value >= 0 ? value : null;
}

// Decodes a chunked-transfer-encoded body hex. Returns the body hex slice
// that runs from the start of the input up to (and including) the CRLF that
// terminates the final `0\r\n\r\n` chunk. Returns null when the body is
// incomplete (caller can fall back to the raw concatenated body).
//
// This keeps the original behavior expected by callers in main-frontend.js,
// which treat the return value as a hex slice of the original payload.
function sliceCompleteChunkedHttpBodyHex(bodyHex) {
    const normalized = typeof bodyHex === "string" ? bodyHex.replace(/\s+/g, "") : "";
    let cursor = 0;
    while (cursor < normalized.length) {
        const lineEnd = normalized.indexOf("0d0a", cursor);
        if (lineEnd === -1) return null;
        const chunkSizeLine = hexToAsciiString(normalized.slice(cursor, lineEnd)).trim();
        const chunkSizeToken = chunkSizeLine.split(";", 1)[0].trim();
        if (!/^[0-9a-fA-F]+$/.test(chunkSizeToken)) return null;
        const chunkSize = Number.parseInt(chunkSizeToken, 16);
        if (!Number.isFinite(chunkSize) || chunkSize < 0) return null;
        cursor = lineEnd + 4;
        if (chunkSize === 0) {
            // Last-chunk: the rest of the body is an optional trailer block
            // terminated by a blank line (\r\n). The trailer block may be
            // empty, in which case the bytes immediately following the
            // chunk-size line are the final \r\n. Scan for the empty line.
            let trailerCursor = cursor;
            while (trailerCursor <= normalized.length) {
                const trailerEnd = normalized.indexOf("0d0a", trailerCursor);
                if (trailerEnd === -1) return null;
                if (trailerEnd === trailerCursor) {
                    // Empty line — the body is complete up to and including
                    // this CRLF.
                    return normalized.slice(0, trailerEnd + 4);
                }
                trailerCursor = trailerEnd + 4;
            }
            return null;
        }
        const chunkDataEnd = cursor + chunkSize * 2;
        if (chunkDataEnd > normalized.length) return null;
        cursor = chunkDataEnd;
        if (normalized.slice(cursor, cursor + 4).toLowerCase() !== "0d0a") return null;
        cursor += 4;
    }
    return null;
}

module.exports = {
    decodeHttpFromBytes,
    extractHttpBodyHex,
    findHttpHeaderBodySeparators,
    looksLikeHttpStartLine,
    sliceHttpMessageSegments,
    httpHeadersHaveExplicitFraming,
    collectHttpMessageBodiesFromStream,
    HTTP_FILENAME_EXT_BY_MIME,
    getHttpBodyFilenameExtension,
    extractFilenameFromContentDisposition,
    extractMultipartBoundaryFromContentType,
    extractMultipartFilenameFromBodyBytes,
    findMultipartFileByteRange,
    findMultipartFileByteRanges,
    sliceCompleteChunkedHttpBodyHex,
    hexToAsciiString,
    isChunkedTransferEncodingHeader,
    parseContentLengthFromHeaderAscii,
    splitHttpMessageHeaders,
};
