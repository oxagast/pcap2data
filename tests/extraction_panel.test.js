const fs = require('fs');
const path = require('path');
const vm = require('vm');

function extractFunctionSource(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    let startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    // Use the last occurrence if duplicate definitions exist, matching normal file flow.
    const lastIndex = sourceText.lastIndexOf(startToken);
    if (lastIndex !== -1 && lastIndex !== startIndex) {
        startIndex = lastIndex;
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
    let inRegexCharClass = false;
    let escaped = false;

    function isRegexStart(idx) {
        // Walk backwards skipping whitespace to find a token that can precede a regex literal.
        let j = idx - 1;
        while (j >= 0 && /\s/.test(sourceText[j])) j -= 1;
        if (j < 0) return true;
        const prev = sourceText[j];
        // After an opening paren, bracket, operator, comma, colon, semicolon, question mark,
        // or assignment keyword is a common regex context.
        if (/[=(,:\[{};?!|&]|^$/.test(prev)) return true;
        // Keywords return/break/continue/with/if/else/case/while/do/for/switch/throw/catch/await/yield/new
        const back = sourceText.slice(Math.max(0, j - 30), j + 1);
        const match = back.match(/\b(return|break|continue|with|if|else|case|while|do|for|switch|throw|catch|await|yield|new|typeof|instanceof|delete|void)$/);
        if (match) return true;
        return false;
    }

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

        if (inRegex) {
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
            if (char === '[' && !inRegexCharClass) inRegexCharClass = true;
            if (char === ']' && inRegexCharClass) inRegexCharClass = false;
            if (char === '/' && !inRegexCharClass) {
                // Skip regex flags
                inRegex = false;
                cursor += 1;
                while (cursor < sourceText.length && /[dgimsuvy]/i.test(sourceText[cursor])) cursor += 1;
                continue;
            }
            cursor += 1;
            continue;
        }

        if (inSingleQuote || inDoubleQuote || inTemplate) {
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
            // Template literals can contain `${` which we ignore inside the string.
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
            if (isRegexStart(cursor)) {
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
    throw new Error(`Could not parse function ${functionName} (reached EOF at depth ${depth})`);
}

function loadExtractionFunctions(filePath) {
    const sourceText = fs.readFileSync(filePath, 'utf8');
    const functionNames = [
        'inferExtractionFormatName',
        'uint8ArrayToBase64',
        'base64ToUint8Array',
        'parseDataToolsInput',
        'bytesToHexString',
        'sanitizeCarveFilename',
    ];
    const extractedSource = functionNames
        .map((functionName) => extractFunctionSource(sourceText, functionName))
        .join('\n\n');

    const context = {
        Uint8Array,
        DataView,
        TextDecoder,
        TextEncoder,
        Buffer,
        atob: (s) => Buffer.from(s, 'base64').toString('binary'),
        btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
        window: {
            atob: (s) => Buffer.from(s, 'base64').toString('binary'),
            btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
        },
    };
    vm.createContext(context);
    vm.runInContext(extractedSource, context);
    return context;
}
describe('Conv Extraction helpers', () => {
    const projectRoot = path.resolve(__dirname, '..');
    const targetFile = path.join(projectRoot, 'src/ui/main-frontend.js');

    let ctx;
    beforeAll(() => {
        ctx = loadExtractionFunctions(targetFile);
    });

    test('detects gzip magic', () => {
        const gzip = new Uint8Array([0x1f, 0x8b, 0x08, 0x00]);
        expect(ctx.inferExtractionFormatName(gzip)).toBe('gzip');
    });

    test('detects bz2 magic', () => {
        const bz2 = new Uint8Array([0x42, 0x5a, 0x68, 0x39]);
        expect(ctx.inferExtractionFormatName(bz2)).toBe('bz2');
    });

    test('detects lzma magic', () => {
        const lzma = new Uint8Array([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]);
        expect(ctx.inferExtractionFormatName(lzma)).toBe('lzma');
    });

    test('detects lzo magic', () => {
        const lzo = new Uint8Array([0x4c, 0x5a, 0x4f, 0x00]);
        expect(ctx.inferExtractionFormatName(lzo)).toBe('lzo');
    });

    test('detects zip magic', () => {
        const zip = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]);
        expect(ctx.inferExtractionFormatName(zip)).toBe('zip');
    });

    test('detects brotli magic', () => {
        const brotli = new Uint8Array([0x28, 0xb5, 0x2f, 0xfd]);
        expect(ctx.inferExtractionFormatName(brotli)).toBe('brotli');
    });

    test('returns null for random bytes', () => {
        const random = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        expect(ctx.inferExtractionFormatName(random)).toBeNull();
    });

    test('round-trips Uint8Array through base64', () => {
        const original = new Uint8Array([0x00, 0x7f, 0x80, 0xff]);
        const b64 = ctx.uint8ArrayToBase64(original);
        const decoded = ctx.base64ToUint8Array(b64);
        expect(Buffer.from(decoded).toString('hex')).toBe('007f80ff');
    });

    test('parseDataToolsInput decodes plain hex', () => {
        const bytes = ctx.parseDataToolsInput('hex', '1f8b0800');
        expect(bytes).toEqual(new Uint8Array([0x1f, 0x8b, 0x08, 0x00]));
    });

    test('bytesToHexString encodes hex', () => {
        const bytes = new Uint8Array([0x1f, 0x8b, 0x08, 0x00]);
        expect(ctx.bytesToHexString(bytes)).toBe('1f8b0800');
    });

    test('sanitizeCarveFilename strips directories and bad chars', () => {
        expect(ctx.sanitizeCarveFilename('../../../etc/passwd')).toBe('passwd');
        expect(ctx.sanitizeCarveFilename('file<name>.txt')).toBe('file_name_.txt');
    });

    test('index.html has extraction subtab button and panel', () => {
        const indexHtml = fs.readFileSync(path.join(projectRoot, 'src/index.html'), 'utf8');
        expect(indexHtml).toContain('conv-subtab-extraction');
        expect(indexHtml).toContain('conv-extraction-panel');
        expect(indexHtml).toContain('data-tools-extraction-decompress-btn');
        expect(indexHtml).toContain('data-tools-extraction-list-archive-btn');
    });

    test('data-tools-panel includes extraction in valid subtabs', () => {
        const panelSource = fs.readFileSync(path.join(projectRoot, 'src/ui/panels/data-tools-panel.js'), 'utf8');
        expect(panelSource).toContain('CONV_EXTRACTION_SUBTAB');
        expect(panelSource).toContain('"extraction"');
    });
});
