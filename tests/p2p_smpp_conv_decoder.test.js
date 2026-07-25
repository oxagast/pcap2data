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

function loadDecoderFunctions(filePath) {
    const sourceText = fs.readFileSync(filePath, 'utf8');
<<<<<<< HEAD
    // decodeSmppFromBytes / decodeSoulseekFromBytes / decodeBittorrentFromBytes
    // and the SMB helpers now live under src/ui/decoders/conv/ (refactor:
    // moved out of data-tools-panel.js). The same is true for the pure
    // orchestrator helpers getPacketProtocolDecoderHint and
    // autoDetectProtoFromBytes — those now live under
    // src/ui/decoders/conv/auto-detect.js, which is what the panel aliases.
    //
    // To test the auto-detect in its real shape (not the alias), we extract
    // its `function` declaration from auto-detect.js (the new home) when
    // working with data-tools-panel.js, and from main-frontend.js (the
    // parallel copy that still has inline definitions) otherwise.
    const convDecoders = require(path.join(path.resolve(__dirname, '..'), 'src/ui/decoders/conv'));
    let extractedSource = '';
    if (sourceText.includes('function autoDetectProtoFromBytes')) {
        // Inline definition (e.g. main-frontend.js).
        extractedSource = extractFunctionSource(sourceText, 'autoDetectProtoFromBytes');
    } else {
        // Alias (e.g. data-tools-panel.js). Pull the function body from the
        // auto-detect module so we can stub out dependencies via the vm
        // context the same way we do for the inline case.
        const autoDetectSource = fs.readFileSync(
            path.join(path.resolve(__dirname, '..'), 'src/ui/decoders/conv/auto-detect.js'),
            'utf8',
        );
        extractedSource = extractFunctionSource(autoDetectSource, 'autoDetectProtoFromBytes');
    }
=======
    const functionNames = [
        'normalizeSmbDecoderBytes',
        'bytesToHexLower',
        'decodeSmppFromBytes',
        'decodeSoulseekFromBytes',
        'decodeBittorrentFromBytes',
        'autoDetectProtoFromBytes',
    ];
    const extractedSource = functionNames
        .map((functionName) => extractFunctionSource(sourceText, functionName))
        .join('\n\n');
>>>>>>> 5862f29a91399490b9ba99449b672af01a186670

    const alwaysNull = () => null;
    const context = {
        Uint8Array,
        DataView,
        TextDecoder,
        getImageTypeFromExifReader: alwaysNull,
        decodeJsonFromBytes: alwaysNull,
        decodeXmlFromBytes: alwaysNull,
<<<<<<< HEAD
        decodeHtmlFromBytes: alwaysNull,
=======
>>>>>>> 5862f29a91399490b9ba99449b672af01a186670
        decodeBsonFromBytes: alwaysNull,
        decodeMessagePackFromBytes: alwaysNull,
        decodeProtobufFromBytes: alwaysNull,
        decodeBerFromBytes: alwaysNull,
        decodeDerFromBytes: alwaysNull,
        decodeYamlFromBytes: alwaysNull,
        decodeLdapFromBytes: alwaysNull,
<<<<<<< HEAD
        normalizeSmbDecoderBytes: convDecoders.normalizeSmbDecoderBytes,
        bytesToHexLower: convDecoders.bytesToHexLower,
        decodeSmppFromBytes: convDecoders.decodeSmppFromBytes,
        decodeSoulseekFromBytes: convDecoders.decodeSoulseekFromBytes,
        decodeBittorrentFromBytes: convDecoders.decodeBittorrentFromBytes,
        autoDetectProtoFromBytes: convDecoders.autoDetectProtoFromBytes,
=======
>>>>>>> 5862f29a91399490b9ba99449b672af01a186670
    };
    vm.createContext(context);
    vm.runInContext(extractedSource, context);
    return {
        decodeSmppFromBytes: context.decodeSmppFromBytes,
        decodeSoulseekFromBytes: context.decodeSoulseekFromBytes,
        decodeBittorrentFromBytes: context.decodeBittorrentFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

describe('SMPP/Soulseek/BitTorrent Conv decoder wiring', () => {
    const projectRoot = path.resolve(__dirname, '..');
    const decoderFiles = [
        path.join(projectRoot, 'src/ui/panels/data-tools-panel.js'),
        path.join(projectRoot, 'src/ui/main-frontend.js'),
    ];

    test.each(decoderFiles)('auto-detects and decodes SMPP from %s', (filePath) => {
        const { decodeSmppFromBytes, autoDetectProtoFromBytes } = loadDecoderFunctions(filePath);
        const payload = new Uint8Array([
            0x00, 0x00, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x07,
        ]);

        expect(autoDetectProtoFromBytes(payload)).toBe('smpp');
        const decoded = decodeSmppFromBytes(payload);
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'SMPP' }));
        expect(getFieldValue(decoded, 'Command')).toBe('bind_transmitter');
        expect(getFieldValue(decoded, 'Sequence Number')).toBe('7');
    });

    test.each(decoderFiles)('auto-detects and decodes Soulseek envelope from %s', (filePath) => {
        const { decodeSoulseekFromBytes, autoDetectProtoFromBytes } = loadDecoderFunctions(filePath);
        const body = Buffer.from('alice', 'utf8');
        const payload = Buffer.concat([
            Buffer.from([0x09, 0x00, 0x00, 0x00]),
            Buffer.from([0x01, 0x00, 0x00, 0x00]),
            body,
        ]);

        expect(autoDetectProtoFromBytes(new Uint8Array(payload))).toBe('soulseek');
        const decoded = decodeSoulseekFromBytes(new Uint8Array(payload));
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'Soulseek' }));
        expect(getFieldValue(decoded, 'Message Code')).toBe('1');
        expect(getFieldValue(decoded, 'Payload Preview')).toContain('alice');
    });

    test.each(decoderFiles)('auto-detects and decodes BitTorrent handshake from %s', (filePath) => {
        const { decodeBittorrentFromBytes, autoDetectProtoFromBytes } = loadDecoderFunctions(filePath);
        const payload = Buffer.concat([
            Buffer.from([19]),
            Buffer.from('BitTorrent protocol', 'ascii'),
            Buffer.alloc(8, 0),
            Buffer.alloc(20, 0xaa),
            Buffer.from('-UT1000-abcdefghijkl', 'ascii').subarray(0, 20),
        ]);

        expect(autoDetectProtoFromBytes(new Uint8Array(payload))).toBe('bittorrent');
        const decoded = decodeBittorrentFromBytes(new Uint8Array(payload));
        expect(decoded).toEqual(expect.objectContaining({ protocol: 'BitTorrent' }));
        expect(getFieldValue(decoded, 'Type')).toBe('Handshake');
        expect(getFieldValue(decoded, 'Protocol')).toBe('BitTorrent protocol');
    });

    test('Conv protocol dropdown includes SMPP, Soulseek, BitTorrent, and Plain text options', () => {
        const indexHtml = fs.readFileSync(path.join(projectRoot, 'src/index.html'), 'utf8');
        expect(indexHtml).toContain('<option value="smpp">SMPP</option>');
        expect(indexHtml).toContain('<option value="soulseek">Soulseek</option>');
        expect(indexHtml).toContain('<option value="bittorrent">BitTorrent</option>');
        expect(indexHtml).toContain('<option value="plaintext">Plain text</option>');
    });
});
