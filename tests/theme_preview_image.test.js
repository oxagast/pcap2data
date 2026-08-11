// Tests that the theme preview image round-trips correctly through both
// the main-process normalizer (main.js) and the renderer's
// buildThemesPreviewDataUri (main-frontend.js).
//
// The catalog now stores previews as a raw "data:image/png;base64,..."
// string. The legacy frontend expected an object of the shape
// {format, base64}. We need both layers to handle the new string form.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const MAIN_JS = path.join(PROJECT_ROOT, 'src', 'main.js');
const FRONTEND_JS = path.join(PROJECT_ROOT, 'src', 'ui', 'main-frontend.js');
// Theme / catalog helpers were extracted to
// ``src/ui/main-frontend/themes-catalog.js``. ``extractFunctionSource``
// falls back to this path so the existing tests can keep sourcing
// their slices without having to chase the new module boundary.
const THEMES_CATALOG_JS = path.join(
    PROJECT_ROOT,
    'src',
    'ui',
    'main-frontend',
    'themes-catalog.js',
);

// ---- helpers (subset of the extraction harness) -----------------------

function extractFunctionSource(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    let startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        // Fall back to the themes-catalog factory module when the
        // function was extracted as part of the Step A slice.
        const themesCatalogSource = fs.readFileSync(THEMES_CATALOG_JS, 'utf8');
        if (themesCatalogSource.indexOf(startToken) !== -1) {
            return extractFunctionSource(themesCatalogSource, functionName);
        }
        throw new Error(`Could not find function ${functionName}`);
    }
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
        const j = (() => {
            let k = idx - 1;
            while (k >= 0 && /\s/.test(sourceText[k])) k -= 1;
            return k;
        })();
        if (j < 0) return true;
        const prev = sourceText[j];
        if (/[=(,:\[{};?!|&]|^$/.test(prev)) return true;
        const back = sourceText.slice(Math.max(0, j - 30), j + 1);
        const match = back.match(
            /\b(return|break|continue|with|if|else|case|while|do|for|switch|throw|catch|await|yield|new|typeof|instanceof|delete|void)$/
        );
        return Boolean(match);
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
            if (escaped) { escaped = false; cursor += 1; continue; }
            if (char === '\\') { escaped = true; cursor += 1; continue; }
            if (char === '[' && !inRegexCharClass) inRegexCharClass = true;
            if (char === ']' && inRegexCharClass) inRegexCharClass = false;
            if (char === '/' && !inRegexCharClass) {
                inRegex = false;
                cursor += 1;
                while (
                    cursor < sourceText.length
                    && /[dgimsuvy]/i.test(sourceText[cursor])
                ) cursor += 1;
                continue;
            }
            cursor += 1;
            continue;
        }
        if (inSingleQuote || inDoubleQuote || inTemplate) {
            if (escaped) { escaped = false; cursor += 1; continue; }
            if (char === '\\') { escaped = true; cursor += 1; continue; }
            if (inSingleQuote && char === "'") inSingleQuote = false;
            else if (inDoubleQuote && char === '"') inDoubleQuote = false;
            else if (inTemplate && char === '`') inTemplate = false;
            cursor += 1;
            continue;
        }
        if (char === '/' && next === '/') { inLineComment = true; cursor += 2; continue; }
        if (char === '/' && next === '*') { inBlockComment = true; cursor += 2; continue; }
        if (char === "'") { inSingleQuote = true; cursor += 1; continue; }
        if (char === '"') { inDoubleQuote = true; cursor += 1; continue; }
        if (char === '`') { inTemplate = true; cursor += 1; continue; }
        if (char === '/') {
            if (isRegexStart(cursor)) { inRegex = true; cursor += 1; continue; }
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

function loadMainNormalizer() {
    const sourceText = fs.readFileSync(MAIN_JS, 'utf8');
    const fnSrc = extractFunctionSource(sourceText, 'normalizeThemeEmbeddedImage');
    const context = {
        console,
    };
    vm.createContext(context);
    vm.runInContext(fnSrc, context);
    return context.normalizeThemeEmbeddedImage;
}

function loadFrontendBuilder() {
    const sourceText = fs.readFileSync(FRONTEND_JS, 'utf8');
    const fnSrc = extractFunctionSource(sourceText, 'buildThemesPreviewDataUri');
    const context = {
        console,
        Buffer,
    };
    vm.createContext(context);
    vm.runInContext(fnSrc, context);
    return context.buildThemesPreviewDataUri;
}

// ---- tests ------------------------------------------------------------

describe('theme preview image normalization', () => {
    const PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9ZptK6gAAAAASUVORK5CYII=';
    const PNG_DATA_URI = `data:image/png;base64,${PNG_B64}`;

    test('main: data URL string is parsed into {format, base64}', () => {
        const normalize = loadMainNormalizer();
        const out = normalize(PNG_DATA_URI);
        expect(out).toEqual({ format: 'png', base64: PNG_B64 });
    });

    test('main: jpeg data URL is normalized to jpg', () => {
        const normalize = loadMainNormalizer();
        const out = normalize('data:image/jpeg;base64,abc');
        expect(out).toEqual({ format: 'jpg', base64: 'abc' });
    });

    test('main: malformed data URL returns null', () => {
        const normalize = loadMainNormalizer();
        expect(normalize('data:image/png;base64,!!!not-base64!!!')).toBeNull();
        expect(normalize('not a data url')).toBeNull();
        expect(normalize('')).toBeNull();
        expect(normalize(null)).toBeNull();
        expect(normalize(undefined)).toBeNull();
    });

    test('main: legacy {format, base64} object still works', () => {
        const normalize = loadMainNormalizer();
        const out = normalize({ format: 'png', base64: PNG_B64 });
        expect(out).toEqual({ format: 'png', base64: PNG_B64 });
    });

    test('main: legacy {format, data} object still works', () => {
        const normalize = loadMainNormalizer();
        const out = normalize({ format: 'jpeg', data: 'abc' });
        expect(out).toEqual({ format: 'jpg', base64: 'abc' });
    });

    test('frontend: accepts a raw data URL string', () => {
        const build = loadFrontendBuilder();
        expect(build(PNG_DATA_URI)).toBe(PNG_DATA_URI);
    });

    test('frontend: accepts the normalized {format, base64} object', () => {
        const build = loadFrontendBuilder();
        const out = build({ format: 'png', base64: PNG_B64 });
        expect(out).toBe(PNG_DATA_URI);
    });

    test('frontend: rejects an empty payload', () => {
        const build = loadFrontendBuilder();
        expect(build(null)).toBeNull();
        expect(build(undefined)).toBeNull();
        expect(build('')).toBeNull();
    });
});
