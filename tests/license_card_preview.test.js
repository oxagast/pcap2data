// Tests for the catalog card "Preview" button click handler in
// src/ui/main-frontend.js — specifically the **license** branch
// of `renderCard` inside `renderThemesCatalog`.
//
// Earlier this branch hard-coded a "No preview for license types"
// fallback because the operator-managed ``themes_dir/<id>.json``
// files only existed for cosmetic themes. The catalog server,
// however, already populates ``previewImage`` (and ``previewUrl``)
// on every entry it returns, including license SKUs, so a license
// that ships with a marketing screenshot (e.g. a pro/enterprise
// feature comparison) should render the same way a theme preview
// does. The behavior under test:
//
//   1. ``entry.previewImage`` populated → render the embedded data
//      URI through ``showThemesPreviewFromDataUri``.
//   2. Otherwise, ``entry.previewUrl`` populated → render via
//      ``showThemesPreviewFromUrl``.
//   3. Neither present → call
//      ``showThemesPreviewFromDataUri(null, "No preview available
//      for this license")`` so the empty-state placeholder is
//      shown (and the message text matches the theme branch's
//      "No preview available for this theme" sibling so the UI is
//      consistent).
//
// The extraction approach mirrors the theme-branch test in
// `tests/theme_catalog_card_preview.test.js` so the two test
// files stay structurally similar and the extraction is easy to
// maintain. The sentinel we anchor on is unique to the license
// branch (the comment block starts with "Licenses use the same
// preview-resolution path as themes"), so a future edit that
// reorders the two branches can't accidentally extract the
// wrong body.

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

// The license branch click handler is:
//
//   previewBtn.addEventListener("click", () => { ... });
//
// (note: synchronous — no ``async`` keyword — because the body
// has no ``await``). To unit-test it without a DOM, we extract
// the body of that handler and rewrap it as a regular function
// we can call directly. We anchor on the unique sentinel that
// appears in the license branch's comment block, walk braces
// from the opening ``{`` of the arrow (which lives just before
// the sentinel), and stop at the matching closing ``}``.
//
// Walking from the sentinel backwards to find ``{`` is the
// part that historically broke when both branches lived in
// source order: ``lastIndexOf('{', sentinel)`` would land on
// the wrong arrow body. We avoid that by walking *backwards
// from the sentinel* past *every* ``=> {`` candidate and
// picking the *first* one whose preceding ~40 chars match
// ``() => {`` (i.e. the synchronous arrow form, since the
// license branch is the only synchronous addEventListener in
// this region of the file). That keeps the extraction
// robust to sibling branches that open with ``() => {``
// earlier in source order.
function extractLicenseHandlerBody(sourceText) {
    const sentinel =
        '// License preview resolution: same priority as the theme';
    const startIdx = sourceText.indexOf(sentinel);
    if (startIdx === -1) {
        throw new Error(
            'Could not find license branch preview click handler '
            + '(missing sentinel)',
        );
    }

    // Walk back to the most recent ``=> {`` that is part of a
    // synchronous ``() => {`` arrow (no ``async`` keyword in
    // the immediately-preceding source). The license branch is
    // the only synchronous addEventListener callback in this
    // region; the theme branch uses ``async () => {`` so the
    // ``\basync\b`` lookback will skip it.
    let openBrace = -1;
    let searchCursor = startIdx;
    while (true) {
        const next = sourceText.lastIndexOf('=> {', searchCursor);
        if (next === -1) break;
        const lookback = sourceText.slice(Math.max(0, next - 40), next);
        // We want the synchronous form: ``() => {`` preceded by
        // a closing paren — i.e. no ``async`` keyword in the
        // lookback. If the lookback contains ``async``, keep
        // searching.
        if (!/\basync\b/.test(lookback)) {
            openBrace = next;
            break;
        }
        searchCursor = next - 1;
    }
    if (openBrace === -1) {
        throw new Error(
            'Could not find synchronous arrow body opening brace for license handler',
        );
    }
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
    throw new Error('Could not find license handler closing brace');
}

function loadLicenseCardPreviewHandler() {
    const sourceText = fs.readFileSync(RENDERER_JS, 'utf8');
    const body = extractLicenseHandlerBody(sourceText);
    // Rewrap the body as a regular (non-async) function. The
    // original handler is a synchronous arrow, and the body
    // declares ``embeddedDataUri`` as a local ``const`` that
    // we mirror in the wrapped function so the extracted body
    // runs verbatim.
    const fnSrc = `function runLicenseCardPreview(entry) {\n${body}\n}`;
    return fnSrc;
}

// Stub harness. Mirrors the theme-branch stub but for the
// license branch. The license branch only ever calls
// ``showThemesPreviewFromDataUri`` or ``showThemesPreviewFromUrl``
// (no third "reset" call from the handler itself — the empty
// state is rendered through
// ``showThemesPreviewFromDataUri(null, msg)``).
function makeHandlerHarness() {
    const calls = { dataUri: [], url: [] };
    const ctx = {
        console,
        showThemesPreviewFromDataUri: (uri, msg) => {
            calls.dataUri.push({ uri, msg });
        },
        showThemesPreviewFromUrl: (url) => {
            calls.url.push(url);
        },
        // The license branch reuses the same
        // ``getThemeEmbeddedPreviewDataUri`` helper as the
        // theme branch — accept the same shapes (raw data-URI
        // string, or a normalized {format, base64} object).
        getThemeEmbeddedPreviewDataUri: (entry) => {
            if (!entry || !entry.previewImage) return null;
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

describe('license card "Preview" button', () => {
    const PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9ZptK6gAAAAASUVORK5CYII=';
    const PNG_DATA_URI = `data:image/png;base64,${PNG_B64}`;
    const JPG_B64 = '/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/2wBDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD9/KKKK//Z';
    const JPG_DATA_URI = `data:image/jpeg;base64,${JPG_B64}`;

    test('uses the embedded data URI when present (preferred over previewUrl)', () => {
        const { ctx, calls } = makeHandlerHarness();
        const fnSrc = loadLicenseCardPreviewHandler();
        vm.runInContext(fnSrc, ctx);
        const entry = {
            id: 'pro-license',
            type: 'license',
            previewImage: { format: 'jpg', base64: JPG_B64 },
            previewUrl: 'https://example.com/pro.jpg',
        };
        ctx.runLicenseCardPreview(entry);
        expect(calls.dataUri).toEqual([{ uri: JPG_DATA_URI, msg: undefined }]);
        expect(calls.url).toEqual([]);
    });

    test('uses the embedded raw data-URI string when present', () => {
        const { ctx, calls } = makeHandlerHarness();
        const fnSrc = loadLicenseCardPreviewHandler();
        vm.runInContext(fnSrc, ctx);
        const entry = {
            id: 'enterprise-license',
            type: 'license',
            previewImage: PNG_DATA_URI,
            previewUrl: 'https://example.com/enterprise.png',
        };
        ctx.runLicenseCardPreview(entry);
        expect(calls.dataUri).toEqual([{ uri: PNG_DATA_URI, msg: undefined }]);
        expect(calls.url).toEqual([]);
    });

    test('falls back to previewUrl when no embedded previewImage', () => {
        const { ctx, calls } = makeHandlerHarness();
        const fnSrc = loadLicenseCardPreviewHandler();
        vm.runInContext(fnSrc, ctx);
        const entry = {
            id: 'pro-license',
            type: 'license',
            previewImage: null,
            previewUrl: 'https://example.com/pro.jpg',
        };
        ctx.runLicenseCardPreview(entry);
        expect(calls.dataUri).toEqual([]);
        expect(calls.url).toEqual(['https://example.com/pro.jpg']);
    });

    test('falls back to a graceful "no preview" message when both are absent', () => {
        const { ctx, calls } = makeHandlerHarness();
        const fnSrc = loadLicenseCardPreviewHandler();
        vm.runInContext(fnSrc, ctx);
        const entry = {
            id: 'developer-license',
            type: 'license',
            previewImage: null,
            previewUrl: '',
        };
        ctx.runLicenseCardPreview(entry);
        expect(calls.dataUri).toEqual([
            { uri: null, msg: 'No preview available for this license' },
        ]);
        expect(calls.url).toEqual([]);
    });

    test('ignores an empty embedded image and falls back to previewUrl', () => {
        // The catalog server may emit previewImage: "" instead of
        // null. Treat the empty string the same as null/missing.
        const { ctx, calls } = makeHandlerHarness();
        const fnSrc = loadLicenseCardPreviewHandler();
        vm.runInContext(fnSrc, ctx);
        const entry = {
            id: 'pro-license',
            type: 'license',
            previewImage: '',
            previewUrl: 'https://example.com/pro.png',
        };
        ctx.runLicenseCardPreview(entry);
        expect(calls.dataUri).toEqual([]);
        expect(calls.url).toEqual(['https://example.com/pro.png']);
    });
});
