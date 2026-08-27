const fs = require('fs');
const path = require('path');
const vm = require('vm');

function extractFunctionSource(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    const bodyStart = sourceText.indexOf('{', startIndex);
    if (bodyStart === -1) {
        throw new Error(`Could not find the body for ${functionName}`);
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
                cursor += 1;
                continue;
            }
        }

        if (char === '{') depth += 1;
        if (char === '}') {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
        cursor += 1;
    }
    throw new Error(`Could not parse function ${functionName}`);
}

function loadDecoderFunctions(filePath) {
    const sourceText = fs.readFileSync(filePath, 'utf8');
    const convDecoders = require(
        path.join(path.resolve(__dirname, '..'), 'src/ui/decoders/conv'),
    );
    let extractedSource = '';
    if (sourceText.includes('function autoDetectProtoFromBytes')) {
        extractedSource = extractFunctionSource(sourceText, 'autoDetectProtoFromBytes');
    } else {
        const autoDetectSource = fs.readFileSync(
            path.join(path.resolve(__dirname, '..'), 'src/ui/decoders/conv/auto-detect.js'),
            'utf8',
        );
        extractedSource = extractFunctionSource(autoDetectSource, 'autoDetectProtoFromBytes');
    }

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
        bytesToHexLower: convDecoders.bytesToHexLower,
        decodeIso8583FromBytes: convDecoders.decodeIso8583FromBytes,
        autoDetectProtoFromBytes: convDecoders.autoDetectProtoFromBytes,
    };
    vm.createContext(context);
    vm.runInContext(extractedSource, context);
    return {
        decodeIso8583FromBytes: context.decodeIso8583FromBytes || convDecoders.decodeIso8583FromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// Build an ASCII-encoded ISO 8583 authorization request (MTI 0100) with
// fields 2 (PAN, LLVAR), 3 (Processing Code, fixed 6), 4 (Amount, fixed 12),
// 7 (Transmission Date, fixed 10), 11 (STAN, fixed 6).
function buildAsciiIso8583Message() {
    // MTI
    const mti = Buffer.from('0100', 'ascii');
    // Primary bitmap (ASCII hex): field 2,3,4,7,11 set
    // bits: 2,3,4,7,11 -> byte0: 0x20|0x10|0x08 = 0x38? No.
    // field N -> bit (N-1) in bitmap. byte = (N-1)/8, bit = 7-((N-1)%8)
    // f2: bit1, f3: bit2, f4: bit3, f7: bit6, f11: bit10
    // byte0 (fields 1-8): bit1=0x40,bit2=0x20,bit3=0x10,bit6=0x02 -> 0x72
    // Wait: field N -> bit (N-1). bit0=MSB(0x80). field1->bit0->0x80.
    // field2->bit1->0x40, field3->bit2->0x20, field4->bit3->0x10,
    // field7->bit6->0x02, field11->bit10-> byte1 bit2->0x20
    const primaryBitmap = Buffer.from('7220000000000000', 'ascii');
    // Field 2: LLVAR length "16" + PAN
    const f2len = Buffer.from('16', 'ascii');
    const f2pan = Buffer.from('4111111111111111', 'ascii');
    // Field 3: Processing Code "123456"
    const f3 = Buffer.from('123456', 'ascii');
    // Field 4: Amount "000000001000"
    const f4 = Buffer.from('000000001000', 'ascii');
    // Field 7: Transmission Date "0131203030" (MMDDhhmmss)
    const f7 = Buffer.from('0131203030', 'ascii');
    // Field 11: STAN "000001"
    const f11 = Buffer.from('000001', 'ascii');
    return new Uint8Array(Buffer.concat([
        mti, primaryBitmap, f2len, f2pan, f3, f4, f7, f11,
    ]));
}

describe('ISO 8583 Conv decoder wiring', () => {
    const projectRoot = path.resolve(__dirname, '..');
    const decoderFiles = [
        path.join(projectRoot, 'src/ui/panels/data-tools-panel.js'),
        path.join(projectRoot, 'src/ui/main-frontend.js'),
    ];

    test.each(decoderFiles)('auto-detects and decodes ISO 8583 from %s', (filePath) => {
        const { decodeIso8583FromBytes, autoDetectProtoFromBytes } = loadDecoderFunctions(filePath);
        const payload = buildAsciiIso8583Message();

        expect(autoDetectProtoFromBytes(payload)).toBe('iso8583');
        const decoded = decodeIso8583FromBytes(payload);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'ISO 8583' }));
        expect(getFieldValue(decoded, 'MTI')).toBe('0100');
        expect(getFieldValue(decoded, 'Message Type')).toBe('Authorization Request');
        expect(getFieldValue(decoded, 'Field 2 (Primary Account Number (PAN))')).toBe('4111111111111111');
        expect(getFieldValue(decoded, 'Field 3 (Processing Code)')).toBe('123456');
        expect(getFieldValue(decoded, 'Field 4 (Amount, Transaction)')).toBe('000000001000');
        expect(getFieldValue(decoded, 'Field 7 (Transmission Date & Time)')).toBe('0131203030');
        expect(getFieldValue(decoded, 'Field 11 (System Trace Audit Number (STAN))')).toBe('000001');
    });

    test('returns null for non-ISO 8583 bytes', () => {
        const { decodeIso8583FromBytes } = loadDecoderFunctions(
            path.join(projectRoot, 'src/ui/panels/data-tools-panel.js'),
        );
        const notIso = new Uint8Array([0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31]);
        expect(decodeIso8583FromBytes(notIso)).toBeNull();
    });

    test('handles BCD-packed MTI (2 bytes)', () => {
        const { decodeIso8583FromBytes } = loadDecoderFunctions(
            path.join(projectRoot, 'src/ui/panels/data-tools-panel.js'),
        );
        // MTI 0800 as BCD: 0x08 0x00
        // bitmap: field 11 only -> bit10 -> byte1 bit2 -> 0x20
        const bcdMti = Buffer.from([0x08, 0x00]);
        const bitmap = Buffer.from([0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        const stan = Buffer.from('000123', 'ascii');
        const payload = new Uint8Array(Buffer.concat([bcdMti, bitmap, stan]));
        const decoded = decodeIso8583FromBytes(payload);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'ISO 8583' }));
        expect(getFieldValue(decoded, 'MTI')).toBe('0800');
        expect(getFieldValue(decoded, 'Message Type')).toBe('Network Management Request');
        expect(getFieldValue(decoded, 'Field 11 (System Trace Audit Number (STAN))')).toBe('000123');
    });

    test('marks truncated fields correctly', () => {
        const { decodeIso8583FromBytes } = loadDecoderFunctions(
            path.join(projectRoot, 'src/ui/panels/data-tools-panel.js'),
        );
        const payload = buildAsciiIso8583Message();
        // Truncate after field 4 (remove field 7 and 11)
        const truncated = payload.slice(0, 4 + 16 + 2 + 16 + 6 + 12);
        const decoded = decodeIso8583FromBytes(truncated);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'ISO 8583' }));
        expect(getFieldValue(decoded, 'Field 7 (Transmission Date & Time)')).toBe('(truncated)');
    });

    test('Conv protocol dropdown includes ISO 8583 option', () => {
        const indexHtml = fs.readFileSync(path.join(projectRoot, 'src/index.html'), 'utf8');
        expect(indexHtml).toContain('<option value="iso8583">ISO 8583 (Financial)</option>');
    });

    test('PROTOCOL_DECODER_HINTS includes iso8583', () => {
        const { PROTOCOL_DECODER_HINTS, PORT_DECODER_HINTS } = require(
            path.join(projectRoot, 'src/ui/decoders/conv/protocol-hints'),
        );
        expect(PROTOCOL_DECODER_HINTS.get('iso8583')).toBe('iso8583');
        expect(PROTOCOL_DECODER_HINTS.get('iso-8583')).toBe('iso8583');
        expect(PORT_DECODER_HINTS.get(8583)).toBe('iso8583');
        expect(PORT_DECODER_HINTS.get(5000)).toBe('iso8583');
    });

    test('SUPPORTED_DECODER_PROTOS includes iso8583 and barrel re-exports the function', () => {
        const conv = require(path.join(projectRoot, 'src/ui/decoders/conv'));
        const { SUPPORTED_DECODER_PROTOS } = require(
            path.join(projectRoot, 'src/ui/decoders/conv/mime-maps'),
        );
        expect(SUPPORTED_DECODER_PROTOS.has('iso8583')).toBe(true);
        expect(typeof conv.decodeIso8583FromBytes).toBe('function');
    });
});