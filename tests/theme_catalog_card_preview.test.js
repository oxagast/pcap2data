// Tests for the catalog card "Preview" button click handler in
// src/ui/main-frontend.js. The card's Preview button (around the
// `renderCard` function inside `renderThemesCatalog`) should prefer
// the embedded data URI in `entry.previewImage` when present,
// fall back to `entry.previewUrl` when no embedded image exists,
// and gracefully fall back to a "No preview available" message
// when neither is present.
//
// These tests are run on the extracted source of the click handler
// so they don't need a real DOM. We use the same `vm`-based
// extraction approach as `tests/theme_preview_image.test.js` and
// `tests/themes_subtab.test.js`.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const RENDERER_JS = path.join(
    PROJECT_ROOT,
    'src',
    'ui',
    'main-frontend.js',
);

// ---- helpers (subset of the extraction harness) ----------------------

function extractArrowFunction(sourceText, functionName) {
    // The catalog card click handler is an inline arrow function
    // we wired up in `renderCard`:
    //
    //   previewBtn.addEventListener("click", async () => { ... });
    //
    // To unit-test the priority order without spinning up a full
    // DOM, we extract the *body* of that handler and rewrap it as
    // a regular `async` function we can call directly. We anchor
    // on a unique string that only appears in the new code path
    // ("Priority matches the theme-picker path in") so we don't
    // accidentally match a future, similar block.
    const sentinel =
        '// Priority matches the theme-picker path in';
    const startIdx = sourceText.indexOf(sentinel);
    if (startIdx === -1) {
        throw new Error(
            'Could not find catalog card preview click handler',
        );
    }
    // The body sits between the outer `async () => {` and the
    // matching `});` that closes the addEventListener call. The
    // sentinel text lives *inside* the comment block at the top
    // of the body, so we need to find the opening `{` of the
    // arrow function (which appears just before the sentinel)
    // and walk braces from there.
    //
    // Search backwards from the sentinel for the opening `{` of
    // the arrow function (the first `{` we see after walking
    // past the `async () =>` paren group). The substring between
    // the sentinel and the opening brace is `// Priority ...
    // \n` — a comment that contains no braces.
    const openBrace = sourceText.lastIndexOf('=> {', startIdx);
    if (openBrace === -1) {
        throw new Error('Could not find arrow body opening brace');
    }
    // The body opens at the character right after `=> {`. We
    // start the brace counter at 1 (we are already inside one
    // brace when we begin).
    const bodyStart = openBrace + '=> {'.length;
    let depth = 1;
    let cursor = bodyStart;
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inTemplate = false;
    let escaped = false;
    for (; cursor < sourceText.length; cursor += 1) {
        const char = sourceText[cursor];
        if (inSingleQuote) {
            if (escaped) { escaped = false; continue; }
            if (char === '\\') { escaped = true; continue; }
            if (char === "'") inSingleQuote = false;
            continue;
        }
        if (inDoubleQuote) {
            if (escaped) { escaped = false; continue; }
            if (char === '\\') { escaped = true; continue; }
            if (char === '"') inDoubleQuote = false;
            continue;
        }
        if (inTemplate) {
            if (escaped) { escaped = false; continue; }
            if (char === '\\') { escaped = true; continue; }
            if (char === '`') inTemplate = false;
            continue;
        }
        if (char === "'") { inSingleQuote = true; continue; }
        if (char === '"') { inDoubleQuote = true; continue; }
        if (char === '`') { inTemplate = true; continue; }
        if (char === '{') depth += 1;
        else if (char === '}') {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(bodyStart, cursor);
            }
        }
    }
    throw new Error('Could not find handler closing brace');
}

function loadCatalogCardPreviewHandler() {
    const sourceText = fs.readFileSync(RENDERER_JS, 'utf8');
    const body = extractArrowFunction(sourceText, 'renderCard');
    // Rewrap the body as an async function. The handler body in
    // main-frontend.js declares `embeddedDataUri` as a local
    // ``const`` inside the arrow function; we mirror that
    // declaration here so the extracted body runs verbatim.
    const fnSrc = `async function runCatalogCardPreview(entry) {\n${body}\n}`;
    return fnSrc;
}

// We stub out the four render-side helpers the handler calls:
//   - getThemeEmbeddedPreviewDataUri(theme) — returns a data URI
//     string or null
//   - showThemesPreviewFromDataUri(uri, message?) — records calls
//   - showThemesPreviewFromUrl(url)            — records calls
// Each stub records its invocations into a shared `calls` object
// so the assertions can read back the priority order.
function makeHandlerHarness() {
    const calls = { dataUri: [], url: [] };
    const ctx = {
        console,
        // Fallback (catalog card should *never* call this now
        // with the new priority order; kept for completeness).
        showThemesPreviewFromDataUri: (uri, msg) => {
            calls.dataUri.push({ uri, msg });
        },
        showThemesPreviewFromUrl: (url) => {
            calls.url.push(url);
        },
        getThemeEmbeddedPreviewDataUri: (entry) => {
            if (!entry || !entry.previewImage) return null;
            // Mimic the real builder: only return something when
            // the entry has a usable embedded image. Mirrors the
            // shape the renderer reads from `entry.previewImage`
            // (a normalized {format, base64} object, or a raw
            // data-URI string).
            const raw = entry.previewImage;
            if (typeof raw === 'string'
                && raw.startsWith('data:image/')) {
                return raw;
            }
            if (raw && typeof raw === 'object' && raw.format && raw.base64) {
                const mime = raw.format === 'jpg' ? 'jpeg' : raw.format;
                return `data:image/${mime};base64,${raw.base64}`;
            }
            return null;
        },
    };
    vm.createContext(ctx);
    return { ctx, calls };
}

// ---- tests ------------------------------------------------------------

describe('catalog card "Preview" button', () => {
    const PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9ZptK6gAAAAASUVORK5CYII=';
    const PNG_DATA_URI = `data:image/png;base64,${PNG_B64}`;
    const JPG_B64 = '/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/2wBDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD9/KKKK//Z';
    const JPG_DATA_URI = `data:image/jpeg;base64,${JPG_B64}`;

    test('uses the embedded data URI when present (preferred over previewUrl)', async () => {
        const { ctx, calls } = makeHandlerHarness();
        const fnSrc = loadCatalogCardPreviewHandler();
        vm.runInContext(fnSrc, ctx);
        const entry = {
            id: 'matrix',
            previewImage: { format: 'jpg', base64: JPG_B64 },
            previewUrl: 'https://example.com/matrix.jpg',
        };
        await ctx.runCatalogCardPreview(entry);
        expect(calls.dataUri).toEqual([{ uri: JPG_DATA_URI, msg: undefined }]);
        expect(calls.url).toEqual([]);
    });

    test('uses the embedded raw data-URI string when present', async () => {
        const { ctx, calls } = makeHandlerHarness();
        const fnSrc = loadCatalogCardPreviewHandler();
        vm.runInContext(fnSrc, ctx);
        const entry = {
            id: 'brushed',
            previewImage: PNG_DATA_URI,
            previewUrl: 'https://example.com/brushed.png',
        };
        await ctx.runCatalogCardPreview(entry);
        expect(calls.dataUri).toEqual([{ uri: PNG_DATA_URI, msg: undefined }]);
        expect(calls.url).toEqual([]);
    });

    test('falls back to previewUrl when no embedded previewImage', async () => {
        const { ctx, calls } = makeHandlerHarness();
        const fnSrc = loadCatalogCardPreviewHandler();
        vm.runInContext(fnSrc, ctx);
        const entry = {
            id: 'sub7',
            previewImage: null,
            previewUrl: 'https://example.com/sub7.jpg',
        };
        await ctx.runCatalogCardPreview(entry);
        expect(calls.dataUri).toEqual([]);
        expect(calls.url).toEqual(['https://example.com/sub7.jpg']);
    });

    test('falls back to a graceful "no preview" message when both are absent', async () => {
        const { ctx, calls } = makeHandlerHarness();
        const fnSrc = loadCatalogCardPreviewHandler();
        vm.runInContext(fnSrc, ctx);
        const entry = {
            id: 'forrest',
            previewImage: null,
            previewUrl: '',
        };
        await ctx.runCatalogCardPreview(entry);
        expect(calls.dataUri).toEqual([
            { uri: null, msg: 'No preview available for this theme' },
        ]);
        expect(calls.url).toEqual([]);
    });

    test('ignores an empty embedded image and falls back to previewUrl', async () => {
        // The catalog server may emit previewImage: "" instead of
        // null. Treat the empty string the same as null/missing.
        const { ctx, calls } = makeHandlerHarness();
        const fnSrc = loadCatalogCardPreviewHandler();
        vm.runInContext(fnSrc, ctx);
        const entry = {
            id: 'snitchbitch',
            previewImage: '',
            previewUrl: 'https://example.com/snitchbitch.png',
        };
        await ctx.runCatalogCardPreview(entry);
        expect(calls.dataUri).toEqual([]);
        expect(calls.url).toEqual(['https://example.com/snitchbitch.png']);
    });
});
