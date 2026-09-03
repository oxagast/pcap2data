// Tests for the WebSocket Conv decoder. Exercises both the HTTP Upgrade
// handshake detection path and the RFC 6455 frame parsing path using
// byte fixtures derived from the segmented WebSocket pcap at
// samples/pcaps/ipv4-websocket-segmented.pcap plus synthetic frames
// for each opcode.
//
// The test structure mirrors tests/sip_conv_decoder.test.js: it uses
// the shared VM-extraction helpers to load autoDetectProtoFromBytes
// with sibling decoders stubbed to () => null, and also loads the
// real decodeWebSocketFromBytes from the conv barrel.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const convDecoders = require('../src/ui/decoders/conv');

// ── Helpers ──────────────────────────────────────────────────────────

function hexToBytes(hex) {
    const clean = hex.replace(/\s+/g, '');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
        bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// Find a field whose name contains the given substring (case-sensitive).
// Useful for fields prefixed with "Frame 2 " etc.
function findFieldValue(result, nameContains) {
    const item = (result.fields || []).find((field) => field.name.includes(nameContains));
    return item ? item.value : null;
}

// Loads autoDetectProtoFromBytes from auto-detect.js via VM with all
// sibling decoders stubbed to () => null except decodeWebSocketFromBytes.
// This mirrors the approach in tests/sip_conv_decoder.test.js.
function loadAutoDetectWithWebSocket() {
    const projectRoot = path.resolve(__dirname, '..');
    const autoDetectSource = fs.readFileSync(
        path.join(projectRoot, 'src/ui/decoders/conv/auto-detect.js'),
        'utf8',
    );
    const extractedSource = extractFunctionSource(autoDetectSource, 'autoDetectProtoFromBytes');

    const alwaysNull = () => null;
    const context = {
        Uint8Array,
        DataView,
        TextDecoder,
        getImageTypeFromExifReader: alwaysNull,
        decodeJsonFromBytes: alwaysNull,
        decodeXmlFromBytes: alwaysNull,
        decodeHtmlFromBytes: alwaysNull,
        decodeBsonFromBytes: alwaysNull,
        decodeMessagePackFromBytes: alwaysNull,
        decodeProtobufFromBytes: alwaysNull,
        decodeBerFromBytes: alwaysNull,
        decodeDerFromBytes: alwaysNull,
        decodeYamlFromBytes: alwaysNull,
        decodeLdapFromBytes: alwaysNull,
        normalizeSmbDecoderBytes: convDecoders.normalizeSmbDecoderBytes,
        decodeEpmapFromBytes: alwaysNull,
        decodeSmppFromBytes: alwaysNull,
        decodeSoulseekFromBytes: alwaysNull,
        decodeBittorrentFromBytes: alwaysNull,
        decodeKerberosFromBytes: alwaysNull,
        decodeDnsFromBytes: alwaysNull,
        decodeLlmnrFromBytes: alwaysNull,
        decodeNbnsFromBytes: alwaysNull,
        decodeNbdgmFromBytes: alwaysNull,
        decodeSnmpFromBytes: alwaysNull,
        decodeDhcpFromBytes: alwaysNull,
        decodeDhcpv6FromBytes: alwaysNull,
        decodeIso8583FromBytes: alwaysNull,
        decodeModbusFromBytes: alwaysNull,
        decodeDnp3FromBytes: alwaysNull,
        decodeS7commFromBytes: alwaysNull,
        decodeOspfFromBytes: alwaysNull,
        decodeHsrpFromBytes: alwaysNull,
        decodeLacpFromBytes: alwaysNull,
        decodeCdpFromBytes: alwaysNull,
        decodeWebSocketFromBytes: convDecoders.decodeWebSocketFromBytes,
        MIME_TO_PROTO: convDecoders.MIME_TO_PROTO,
        PROTOCOL_DECODER_HINTS: convDecoders.PROTOCOL_DECODER_HINTS,
        PORT_DECODER_HINTS: convDecoders.PORT_DECODER_HINTS,
    };
    vm.createContext(context);
    vm.runInContext(extractedSource, context);
    return context.autoDetectProtoFromBytes;
}

// Extracted from the shared helper in tests/sip_conv_decoder.test.js —
// extracts a named function's source from a file for VM execution.
function extractFunctionSource(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    const bodyStart = sourceText.indexOf('{', startIndex);
    if (bodyStart === -1) {
        throw new Error(`Could not find body for ${functionName}`);
    }
    let depth = 0;
    let cursor = bodyStart;
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inTemplate = false;
    let inLineComment = false;
    let inBlockComment = false;
    let inRegex = false;
    let escaped = false;

    while (cursor < sourceText.length) {
        const char = sourceText[cursor];
        const next = sourceText[cursor + 1];

        if (inLineComment) {
            if (char === '\n') inLineComment = false;
            cursor += 1;
            continue;
        }
        if (inBlockComment) {
            if (char === '*' && next === '/') {
                inBlockComment = false;
                cursor += 2;
                continue;
            }
            cursor += 1;
            continue;
        }
        if (inSingleQuote || inDoubleQuote || inTemplate || inRegex) {
            if (escaped) {
                escaped = false;
                cursor += 1;
                continue;
            }
            if (char === '\\') {
                escaped = true;
                cursor += 1;
                continue;
            }
            if (inSingleQuote && char === "'") inSingleQuote = false;
            else if (inDoubleQuote && char === '"') inDoubleQuote = false;
            else if (inTemplate && char === '`') inTemplate = false;
            else if (inRegex && char === '/') inRegex = false;
            cursor += 1;
            continue;
        }

        if (char === '/' && next === '/') {
            inLineComment = true;
            cursor += 2;
            continue;
        }
        if (char === '/' && next === '*') {
            inBlockComment = true;
            cursor += 2;
            continue;
        }
        if (char === "'") {
            inSingleQuote = true;
            cursor += 1;
            continue;
        }
        if (char === '"') {
            inDoubleQuote = true;
            cursor += 1;
            continue;
        }
        if (char === '`') {
            inTemplate = true;
            cursor += 1;
            continue;
        }
        if (char === '/') {
            const prev = sourceText[cursor - 1];
            if (!prev || /[=(:,!&|?{};\s]/.test(prev)) {
                inRegex = true;
            }
            cursor += 1;
            continue;
        }
        if (char === '{') {
            depth += 1;
        } else if (char === '}') {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
        cursor += 1;
    }
    throw new Error(`Could not parse function ${functionName}`);
}

const { decodeWebSocketFromBytes } = convDecoders;

// ── Test fixtures ────────────────────────────────────────────────────

// Real HTTP Upgrade request from samples/pcaps/ipv4-websocket-segmented.pcap
// (frame 12, abbreviated to key headers for fixture brevity).
const UPGRADE_REQUEST =
    'GET / HTTP/1.1\r\n' +
    'Host: spurs.cs.ucla.edu:9696\r\n' +
    'Connection: Upgrade\r\n' +
    'Upgrade: websocket\r\n' +
    'Sec-WebSocket-Version: 13\r\n' +
    'Sec-WebSocket-Key: sgD1adxQ3mk6BbBqab7owA==\r\n' +
    'Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n' +
    'Origin: null\r\n' +
    '\r\n';

// Real HTTP Upgrade response from the same pcap (frame 14).
const UPGRADE_RESPONSE =
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Connection: upgrade\r\n' +
    'Sec-WebSocket-Accept: FRh9fmH0UaoLdY5BSFO4hP2Pcjw=\r\n' +
    'Server: WebSocket++/0.5.1\r\n' +
    'Upgrade: websocket\r\n' +
    '\r\n';

// Real masked binary frame from the pcap (frame 16): opcode 0x2, masked,
// 39-byte payload, mask key = a79a1f24.
const REAL_MASKED_BINARY = hexToBytes(
    '82a79a1f24839f3a2396921841fbfb7254efff1723f7ff6c50c2ea6f2c82ae1626919a1520c8c2528c8f981084',
);

// Real unmasked binary frame header from the pcap (frame 17): opcode 0x2,
// extended 16-bit length = 5379 (0x1503). We only use the header portion.
const REAL_EXT16_HEADER = hexToBytes('827e1503');

// Synthetic frames
const TEXT_FRAME = hexToBytes('810548656c6c6f'); // "Hello"
const MASKED_TEXT_FRAME = hexToBytes('81851122334459475f287e'); // masked "Hello"
const CLOSE_FRAME = hexToBytes('880203e8'); // close, status 1000
const PING_FRAME = hexToBytes('890470696e67'); // ping "ping"
const PONG_FRAME = hexToBytes('8a04706f6e67'); // pong "pong"
const EXT16_FRAME_200 = hexToBytes('827e00c8' + '68'.repeat(200)); // 200 bytes of 0x68
const CONCAT_TEXT_PING = hexToBytes('810548656c6c6f890470696e67'); // text + ping
const GARBAGE = hexToBytes('ff00ff00deadbeef'); // not a valid WS frame

// ── Tests ────────────────────────────────────────────────────────────

describe('WebSocket Conv decoder — upgrade handshake', () => {
    test('decodes HTTP Upgrade request', () => {
        const bytes = new TextEncoder().encode(UPGRADE_REQUEST);
        const decoded = decodeWebSocketFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'WebSocket' }));
        expect(getFieldValue(decoded, 'Type')).toBe('Upgrade Request');
        expect(getFieldValue(decoded, 'Method')).toBe('GET');
        expect(getFieldValue(decoded, 'URL')).toBe('/');
        expect(getFieldValue(decoded, 'Upgrade')).toBe('websocket');
        expect(getFieldValue(decoded, 'Sec-WebSocket-Key')).toBe('sgD1adxQ3mk6BbBqab7owA==');
        expect(getFieldValue(decoded, 'Sec-WebSocket-Version')).toBe('13');
        expect(getFieldValue(decoded, 'Sec-WebSocket-Extensions')).toContain('permessage-deflate');
    });

    test('decodes HTTP Upgrade response (101)', () => {
        const bytes = new TextEncoder().encode(UPGRADE_RESPONSE);
        const decoded = decodeWebSocketFromBytes(bytes);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'WebSocket' }));
        expect(getFieldValue(decoded, 'Type')).toBe('Upgrade Response');
        expect(getFieldValue(decoded, 'Status Code')).toBe('101');
        expect(getFieldValue(decoded, 'Status Message')).toBe('Switching Protocols');
        expect(getFieldValue(decoded, 'Sec-WebSocket-Accept')).toBe('FRh9fmH0UaoLdY5BSFO4hP2Pcjw=');
        expect(getFieldValue(decoded, 'Upgrade')).toBe('websocket');
    });

    test('returns null for non-websocket HTTP', () => {
        const plainHttp = new TextEncoder().encode(
            'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
        );
        expect(decodeWebSocketFromBytes(plainHttp)).toBeNull();
    });
});

describe('WebSocket Conv decoder — RFC 6455 frames', () => {
    test('decodes unmasked text frame', () => {
        const decoded = decodeWebSocketFromBytes(TEXT_FRAME);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'WebSocket' }));
        expect(getFieldValue(decoded, 'Type')).toBe('Frame');
        expect(getFieldValue(decoded, 'Opcode')).toContain('Text');
        expect(getFieldValue(decoded, 'FIN')).toBe('Yes');
        expect(getFieldValue(decoded, 'Masked')).toContain('No');
        expect(getFieldValue(decoded, 'Payload Length')).toBe('5');
        expect(getFieldValue(decoded, 'Payload Preview')).toBe('Hello');
    });

    test('decodes masked text frame and unmasks payload', () => {
        const decoded = decodeWebSocketFromBytes(MASKED_TEXT_FRAME);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'WebSocket' }));
        expect(getFieldValue(decoded, 'Opcode')).toContain('Text');
        expect(getFieldValue(decoded, 'Masked')).toContain('Yes');
        // The payload preview should show the unmasked text "Hello".
        expect(getFieldValue(decoded, 'Payload Preview')).toBe('Hello');
    });

    test('decodes masked binary frame from real pcap', () => {
        const decoded = decodeWebSocketFromBytes(REAL_MASKED_BINARY);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'WebSocket' }));
        expect(getFieldValue(decoded, 'Opcode')).toContain('Binary');
        expect(getFieldValue(decoded, 'FIN')).toBe('Yes');
        expect(getFieldValue(decoded, 'Masked')).toContain('Yes');
        expect(getFieldValue(decoded, 'Payload Length')).toBe('39');
    });

    test('decodes close frame with status code 1000', () => {
        const decoded = decodeWebSocketFromBytes(CLOSE_FRAME);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'WebSocket' }));
        expect(getFieldValue(decoded, 'Opcode')).toContain('Close');
        expect(getFieldValue(decoded, 'Payload Preview')).toContain('1000');
        expect(getFieldValue(decoded, 'Payload Preview')).toContain('Normal Closure');
    });

    test('decodes ping frame', () => {
        const decoded = decodeWebSocketFromBytes(PING_FRAME);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'WebSocket' }));
        expect(getFieldValue(decoded, 'Opcode')).toContain('Ping');
        expect(getFieldValue(decoded, 'Payload Length')).toBe('4');
    });

    test('decodes pong frame', () => {
        const decoded = decodeWebSocketFromBytes(PONG_FRAME);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'WebSocket' }));
        expect(getFieldValue(decoded, 'Opcode')).toContain('Pong');
    });

    test('decodes frame with extended 16-bit length', () => {
        const decoded = decodeWebSocketFromBytes(EXT16_FRAME_200);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'WebSocket' }));
        expect(getFieldValue(decoded, 'Opcode')).toContain('Binary');
        expect(getFieldValue(decoded, 'Payload Length')).toBe('200');
    });

    test('decodes real pcap extended 16-bit header (5379 bytes)', () => {
        // The real frame 17 has 5379 bytes of payload — we only have the
        // 4-byte header, so the decoder should reject it (payload exceeds
        // remaining bytes). Verify it returns null rather than crashing.
        expect(decodeWebSocketFromBytes(REAL_EXT16_HEADER)).toBeNull();
    });

    test('decodes concatenated frames (text + ping)', () => {
        const decoded = decodeWebSocketFromBytes(CONCAT_TEXT_PING);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'WebSocket' }));
        // First frame (no prefix)
        expect(getFieldValue(decoded, 'Opcode')).toContain('Text');
        expect(getFieldValue(decoded, 'Payload Preview')).toBe('Hello');
        // Second frame (prefixed with "Frame 2 ")
        expect(findFieldValue(decoded, 'Frame 2 Opcode')).toContain('Ping');
        // Ping payload is rendered as hex preview.
        expect(findFieldValue(decoded, 'Frame 2 Payload Preview')).toContain('70696e67');
    });

    test('returns null for garbage bytes', () => {
        expect(decodeWebSocketFromBytes(GARBAGE)).toBeNull();
    });

    test('returns null for empty input', () => {
        expect(decodeWebSocketFromBytes(new Uint8Array(0))).toBeNull();
    });

    test('returns null for single byte', () => {
        expect(decodeWebSocketFromBytes(new Uint8Array([0x82]))).toBeNull();
    });

    test('rejects frame with unknown opcode (0x0f)', () => {
        const badOpcode = hexToBytes('8f05048656c6c6f');
        expect(decodeWebSocketFromBytes(badOpcode)).toBeNull();
    });

    test('rejects frame with payload length exceeding remaining bytes', () => {
        // Claims 126 extended = 300 bytes but only has 4 bytes of header.
        const truncated = hexToBytes('827e012c68686868');
        expect(decodeWebSocketFromBytes(truncated)).toBeNull();
    });
});

describe('WebSocket Conv decoder — auto-detect', () => {
    test('auto-detects unmasked text frame as websocket', () => {
        const autoDetect = loadAutoDetectWithWebSocket();
        expect(autoDetect(TEXT_FRAME)).toBe('websocket');
    });

    test('auto-detects masked binary frame as websocket', () => {
        const autoDetect = loadAutoDetectWithWebSocket();
        expect(autoDetect(REAL_MASKED_BINARY)).toBe('websocket');
    });

    test('auto-detects extended 16-bit length frame as websocket', () => {
        const autoDetect = loadAutoDetectWithWebSocket();
        expect(autoDetect(EXT16_FRAME_200)).toBe('websocket');
    });

    test('auto-detects close frame as websocket', () => {
        const autoDetect = loadAutoDetectWithWebSocket();
        expect(autoDetect(CLOSE_FRAME)).toBe('websocket');
    });

    test('auto-detects concatenated frames as websocket', () => {
        const autoDetect = loadAutoDetectWithWebSocket();
        expect(autoDetect(CONCAT_TEXT_PING)).toBe('websocket');
    });

    test('does not detect garbage as websocket', () => {
        const autoDetect = loadAutoDetectWithWebSocket();
        expect(autoDetect(GARBAGE)).not.toBe('websocket');
    });
});

describe('WebSocket Conv decoder — wiring', () => {
    const projectRoot = path.resolve(__dirname, '..');

    test('Conv protocol dropdown includes WebSocket option', () => {
        const indexHtml = fs.readFileSync(
            path.join(projectRoot, 'src/index.html'),
            'utf8',
        );
        expect(indexHtml).toContain('<option value="websocket">WebSocket');
    });

    test('decodeWebSocketFromBytes is exported from conv barrel', () => {
        expect(typeof convDecoders.decodeWebSocketFromBytes).toBe('function');
    });

    test('websocket is in SUPPORTED_DECODER_PROTOS', () => {
        expect(convDecoders.SUPPORTED_DECODER_PROTOS.has('websocket')).toBe(true);
    });

    test('protocol hints include websocket variants', () => {
        expect(convDecoders.PROTOCOL_DECODER_HINTS.get('websocket')).toBe('websocket');
        expect(convDecoders.PROTOCOL_DECODER_HINTS.get('ws')).toBe('websocket');
        expect(convDecoders.PROTOCOL_DECODER_HINTS.get('web-socket')).toBe('websocket');
    });

    test('data-tools-panel switch includes websocket case', () => {
        const panelSource = fs.readFileSync(
            path.join(projectRoot, 'src/ui/panels/data-tools-panel.js'),
            'utf8',
        );
        expect(panelSource).toContain('case "websocket"');
        expect(panelSource).toContain('decodeWebSocketFromBytes');
    });

    test('protocol-decoding switch includes websocket case', () => {
        const pdSource = fs.readFileSync(
            path.join(projectRoot, 'src/ui/main-frontend/protocol-decoding.js'),
            'utf8',
        );
        expect(pdSource).toContain('case "websocket"');
        expect(pdSource).toContain('decodeWebSocketFromBytes');
    });
});