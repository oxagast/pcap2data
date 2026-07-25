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

function loadSipDecoderFunctions(filePath) {
    const sourceText = fs.readFileSync(filePath, 'utf8');
    // decodeSipFromBytes now lives under src/ui/decoders/conv/ (refactor:
    // moved out of data-tools-panel.js). The same is true for the pure
    // orchestrator helper autoDetectProtoFromBytes — it now lives under
    // src/ui/decoders/conv/auto-detect.js, which is what the panel aliases.
    const convDecoders = require(path.join(path.resolve(__dirname, '..'), 'src/ui/decoders/conv'));
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
        decodeSipFromBytes: convDecoders.decodeSipFromBytes,
        autoDetectProtoFromBytes: convDecoders.autoDetectProtoFromBytes,
    };
    vm.createContext(context);
    vm.runInContext(extractedSource, context);
    return {
        decodeSipFromBytes: context.decodeSipFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

describe('SIP Conv decoder wiring', () => {
    const projectRoot = path.resolve(__dirname, '..');
    const decoderFiles = [
        path.join(projectRoot, 'src/ui/panels/data-tools-panel.js'),
        path.join(projectRoot, 'src/ui/main-frontend.js'),
    ];

    test.each(decoderFiles)('auto-detects and decodes SIP request with compact/folded headers from %s', (filePath) => {
        const { decodeSipFromBytes, autoDetectProtoFromBytes } = loadSipDecoderFunctions(filePath);
        const sipRequest = [
            'INVITE sip:bob@example.com SIP/2.0',
            'v: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-a',
            'f: "Alice" <sip:alice@example.com>;tag=111',
            't: <sip:bob@example.com>',
            'i: abc123@example.com',
            'CSeq: 42 INVITE',
            'Authorization: Digest username="alice",',
            ' realm="example.com", nonce="xyz"',
            'c: application/sdp',
            'l: 3',
            '',
            'v=0',
        ].join('\r\n');
        const payload = new TextEncoder().encode(sipRequest);

        expect(autoDetectProtoFromBytes(payload)).toBe('sip');
        const decoded = decodeSipFromBytes(payload);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'SIP' }));
        expect(getFieldValue(decoded, 'Type')).toBe('Request');
        expect(getFieldValue(decoded, 'Method')).toBe('INVITE');
        expect(getFieldValue(decoded, 'Call-ID')).toBe('abc123@example.com');
        expect(getFieldValue(decoded, 'Authorization')).toContain('realm="example.com"');
        expect(getFieldValue(decoded, 'Body Preview')).toContain('v=0');
    });

    test.each(decoderFiles)('decodes SIP response reason phrase from %s', (filePath) => {
        const { decodeSipFromBytes, autoDetectProtoFromBytes } = loadSipDecoderFunctions(filePath);
        const sipResponse = [
            'SIP/2.0 401 Unauthorized Challenge',
            'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-r',
            'Call-ID: resp-123',
            'CSeq: 7 REGISTER',
            'Content-Length: 0',
            '',
        ].join('\r\n');
        const payload = new TextEncoder().encode(sipResponse);

        expect(autoDetectProtoFromBytes(payload)).toBe('sip');
        const decoded = decodeSipFromBytes(payload);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'SIP' }));
        expect(getFieldValue(decoded, 'Type')).toBe('Response');
        expect(getFieldValue(decoded, 'Status Code')).toBe('401');
        expect(getFieldValue(decoded, 'Reason Phrase')).toBe('Unauthorized Challenge');
    });

    test('Conv protocol dropdown includes SIP and Plain text options', () => {
        const indexHtml = fs.readFileSync(path.join(projectRoot, 'src/index.html'), 'utf8');
        expect(indexHtml).toContain('<option value="sip">SIP</option>');
        expect(indexHtml).toContain('<option value="plaintext">Plain text</option>');
    });
});
