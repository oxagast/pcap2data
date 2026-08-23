// Tests for the Settings → Themes subtab, the 400x250 preview box, the
// theme catalog, and the local theme cache (userData/theme-cache) that
// makes purchased themes available offline.
//
// The renderer functions live in a giant CommonJS file
// (src/ui/main-frontend.js) and the main-process helpers live in
// src/main.js. We extract the relevant pure helpers with `vm` and
// stub out `document`/`window`/`fetch`/`fs`/`electron` so the helpers
// can run in plain Node without a full Electron app context.

const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');

const PROJECT_ROOT = path.join(__dirname, '..');
const RENDERER_PATH = path.join(PROJECT_ROOT, 'src', 'ui', 'main-frontend.js');
const MAIN_PATH = path.join(PROJECT_ROOT, 'src', 'main.js');

function extractFunctionSource(sourceText, functionName, { isAsync = false } = {}) {
    const startToken = isAsync
        ? `async function ${functionName}`
        : `function ${functionName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        // Fall back to the plain `function` token so callers that did
        // not pass isAsync still work, but only when no `async function`
        // matches. The `async function` check first prevents accidentally
        // matching the bare `function` token at the start of an async fn.
        if (isAsync) {
            return extractFunctionSource(sourceText, functionName, { isAsync: false });
        }
        throw new Error(`Could not find function ${functionName}`);
    }
    let cursor = startIndex + startToken.length;
    let parenDepth = 0;
    let seenOpenParen = false;
    for (; cursor < sourceText.length; cursor += 1) {
        const char = sourceText[cursor];
        if (char === "(") {
            parenDepth += 1;
            seenOpenParen = true;
            continue;
        }
        if (char === ")") {
            parenDepth -= 1;
            if (seenOpenParen && parenDepth === 0) {
                cursor += 1;
                break;
            }
        }
    }
    let depth = 0;
    for (; cursor < sourceText.length; cursor += 1) {
        const char = sourceText[cursor];
        if (char === '{') depth += 1;
        if (char === '}') {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
    }
    throw new Error(`Could not parse function ${functionName}`);
}

function loadConstant(sourceText, constantName) {
    const startToken = `const ${constantName} = `;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find constant ${constantName}`);
    }
    let inSingle = false;
    let inDouble = false;
    let inBack = false;
    for (let cursor = startIndex + startToken.length; cursor < sourceText.length; cursor += 1) {
        const char = sourceText[cursor];
        if (char === "'" && !inDouble && !inBack) inSingle = !inSingle;
        else if (char === '"' && !inSingle && !inBack) inDouble = !inDouble;
        else if (char === '`' && !inSingle && !inDouble) inBack = !inBack;
        else if (char === ';' && !inSingle && !inDouble && !inBack) {
            return sourceText.slice(startIndex, cursor + 1);
        }
    }
    throw new Error(`Could not parse constant ${constantName}`);
}

function loadRendererConstants(constantNames) {
    const sourceText = fs.readFileSync(RENDERER_PATH, 'utf8');
    return constantNames
        .map((name) => loadConstant(sourceText, name))
        .join('\n');
}

function loadRendererFunctions(functionNames) {
    const sourceText = fs.readFileSync(RENDERER_PATH, 'utf8');
    return functionNames
        .map((name) => extractFunctionSource(sourceText, name))
        .join('\n\n');
}

function loadMainFunction(functionName, { isAsync = false } = {}) {
    const sourceText = fs.readFileSync(MAIN_PATH, 'utf8');
    return extractFunctionSource(sourceText, functionName, { isAsync });
}

function makePreviewVm() {
    const context = {
        URL: { revokeObjectURL: () => { } },
        console,
        window: {},
        document: { getElementById: () => null },
    };
    vm.createContext(context);
    return context;
}

describe('Settings → Themes subtab plumbing', () => {
    test('renderer defines SETTINGS_SUBTAB_THEMES and SETTINGS_SUBTAB_PLUGINS', () => {
        const sourceText = fs.readFileSync(RENDERER_PATH, 'utf8');
        const consts = loadRendererConstants(['SETTINGS_SUBTAB_THEMES', 'SETTINGS_SUBTAB_PLUGINS']);
        const context = { console };
        vm.createContext(context);
        vm.runInContext(consts, context);
        // `const` declarations live in script scope; access them via
        // another runInContext rather than the context object directly.
        expect(
            vm.runInContext('SETTINGS_SUBTAB_THEMES', context),
        ).toBe('themes');
        expect(
            vm.runInContext('SETTINGS_SUBTAB_PLUGINS', context),
        ).toBe('plugins');
    });

    test('renderer setSettingsSubtab branch chain includes the themes tab', () => {
        const source = fs.readFileSync(RENDERER_PATH, 'utf8');
        expect(source).toMatch(/tabName === SETTINGS_SUBTAB_THEMES\s*\?\s*SETTINGS_SUBTAB_THEMES/);
        expect(source).toMatch(/settings-themes-panel/);
    });

    test('startup bootstrap chain does NOT block on refreshThemesCatalog', () => {
        // The catalog hits a remote HTTPS endpoint and must never sit in
        // the preload-hide critical path; only bindThemesSubtabEvents and
        // a status hint are wired at startup.
        const source = fs.readFileSync(RENDERER_PATH, 'utf8');
        const bootstrapMatch = source.match(
            /void loadAvailableThemes\(\)[\s\S]+?startupSettingsInitialized = true;[\s\S]+?maybeHideStartupPreload\(\);/,
        );
        expect(bootstrapMatch).not.toBeNull();
        const bootstrap = bootstrapMatch[0];
        expect(bootstrap).toMatch(/bindThemesSubtabEvents\(\)/);
        expect(bootstrap).toMatch(/Click Refresh Catalog/);
        // refreshThemesCatalog must NOT be awaited before the startup
        // preload is hidden.
        expect(bootstrap).not.toMatch(/return refreshThemesCatalog\(/);
    });

    test('setSettingsSubtab auto-fetches catalog when Themes tab is opened', () => {
        const source = fs.readFileSync(RENDERER_PATH, 'utf8');
        // The Themes-panel branch should call refreshThemesPreviewForSelected
        // and a guarded refreshThemesCatalog on first open.
        const themesBranch = source.match(
            /if \(themesPanel\) \{[\s\S]+?\n  \}\n/,
        );
        expect(themesBranch).not.toBeNull();
        expect(themesBranch[0]).toMatch(/refreshThemesPreviewForSelected/);
        expect(themesBranch[0]).toMatch(/refreshThemesCatalog\(\{ force: false \}\)/);
    });
});

describe('renderer preview helpers', () => {
    let context;
    beforeAll(() => {
        context = makePreviewVm();
        const source = loadRendererFunctions([
            'buildThemesPreviewDataUri',
            'showThemesPreviewFromDataUri',
            'resetThemesPreview',
        ]);
        vm.runInContext(source, context);
    });

    test('buildThemesPreviewDataUri accepts a valid jpg payload', () => {
        const base64 = Buffer.from('hello world').toString('base64');
        const dataUri = context.buildThemesPreviewDataUri({
            format: 'jpg',
            base64,
        });
        expect(dataUri).toBe(`data:image/jpeg;base64,${base64}`);
    });

    test('buildThemesPreviewDataUri accepts a valid png payload', () => {
        const base64 = Buffer.from([0x89, 0x50, 0x4e, 0x47]).toString('base64');
        const dataUri = context.buildThemesPreviewDataUri({
            format: 'png',
            base64,
        });
        expect(dataUri).toBe(`data:image/png;base64,${base64}`);
    });

    test('buildThemesPreviewDataUri strips an existing data URI prefix', () => {
        const base64 = Buffer.from('xyz').toString('base64');
        const dataUri = context.buildThemesPreviewDataUri({
            format: 'png',
            base64: `data:image/png;base64,${base64}`,
        });
        expect(dataUri).toBe(`data:image/png;base64,${base64}`);
    });

    test('buildThemesPreviewDataUri rejects an unsupported format', () => {
        expect(
            context.buildThemesPreviewDataUri({ format: 'gif', base64: 'abc' }),
        ).toBeNull();
    });

    test('buildThemesPreviewDataUri rejects invalid base64', () => {
        expect(
            context.buildThemesPreviewDataUri({ format: 'jpg', base64: 'not base64 !' }),
        ).toBeNull();
    });

    test('buildThemesPreviewDataUri returns null for empty input', () => {
        expect(context.buildThemesPreviewDataUri(null)).toBeNull();
        expect(context.buildThemesPreviewDataUri({})).toBeNull();
    });
});

describe('Themes catalog sandbox banner', () => {
    // Drives the sandbox signal through the real renderer helpers so we
    // verify the banner state matches what the catalog IPC returns.
    function makeSandboxVm() {
        const bannerEl = {
            hidden: true,
            textContent: '',
        };
        const statusEl = {
            textContent: '',
            style: {},
        };
        const listEl = {};
        const context = {
            URL: { revokeObjectURL: () => { } },
            console,
            document: {
                getElementById: (id) => {
                    if (id === 'settings-themes-catalog-sandbox-banner') return bannerEl;
                    if (id === 'settings-themes-catalog-status') return statusEl;
                    if (id === 'settings-themes-catalog-list') return listEl;
                    return null;
                },
            },
            // Module-level renderer state the helper updates.
            themesCatalogIsSandbox: false,
            themesCatalogPaddleEnv: null,
        };
        vm.createContext(context);
        // Bring in the module-level state the helper mutates so the
        // vm's globals line up with main-frontend.js.
        vm.runInContext('var themesCatalogEntries = [];', context);
        // Load the helper so it can run inside the vm.
        const source = loadRendererFunctions([
            'getThemesCatalogSandboxBannerElement',
            'setThemesCatalogStatus',
            'setThemesCatalogSandboxBanner',
        ]);
        vm.runInContext(source, context);
        return { context, bannerEl, statusEl };
    }

    test('hides the banner when neither paddleEnv nor sandbox is set', () => {
        const { context, bannerEl } = makeSandboxVm();
        context.setThemesCatalogSandboxBanner({});
        expect(bannerEl.hidden).toBe(true);
        expect(bannerEl.textContent).toBe('');
        expect(context.themesCatalogIsSandbox).toBe(false);
        expect(context.themesCatalogPaddleEnv).toBe(null);
    });

    test('hides the banner when paddleEnv is production', () => {
        const { context, bannerEl } = makeSandboxVm();
        context.setThemesCatalogSandboxBanner({ paddleEnv: 'production', sandbox: false });
        expect(bannerEl.hidden).toBe(true);
        expect(context.themesCatalogIsSandbox).toBe(false);
        expect(context.themesCatalogPaddleEnv).toBe('production');
    });

    test('shows the banner when sandbox is true (legacy boolean signal)', () => {
        const { context, bannerEl } = makeSandboxVm();
        context.setThemesCatalogSandboxBanner({ sandbox: true });
        expect(bannerEl.hidden).toBe(false);
        expect(bannerEl.textContent).toMatch(/sandbox/i);
        expect(context.themesCatalogIsSandbox).toBe(true);
        expect(context.themesCatalogPaddleEnv).toBe('sandbox');
    });

    test('shows the banner when paddleEnv === "sandbox" (preferred signal)', () => {
        const { context, bannerEl } = makeSandboxVm();
        context.setThemesCatalogSandboxBanner({ paddleEnv: 'sandbox' });
        expect(bannerEl.hidden).toBe(false);
        expect(bannerEl.textContent).toMatch(/sandbox/i);
        expect(context.themesCatalogIsSandbox).toBe(true);
    });

    test('shows the banner when both signals are present', () => {
        const { context, bannerEl } = makeSandboxVm();
        context.setThemesCatalogSandboxBanner({ paddleEnv: 'sandbox', sandbox: true });
        expect(bannerEl.hidden).toBe(false);
        expect(context.themesCatalogIsSandbox).toBe(true);
    });

    test('hides the banner if production is signaled after sandbox', () => {
        const { context, bannerEl } = makeSandboxVm();
        context.setThemesCatalogSandboxBanner({ paddleEnv: 'sandbox' });
        expect(bannerEl.hidden).toBe(false);
        context.setThemesCatalogSandboxBanner({ paddleEnv: 'production', sandbox: false });
        expect(bannerEl.hidden).toBe(true);
        expect(context.themesCatalogIsSandbox).toBe(false);
    });

    test('themes-catalog handler emits sandbox + paddleEnv in success payload', () => {
        // Spot-check the main-process return shape: the handler must
        // forward both fields so the renderer can decide. The handler
        // is registered as `ipcMain.handle("themes-catalog", async …)`,
        // so we grep the source text rather than extracting by name.
        const source = fs.readFileSync(MAIN_PATH, 'utf8');
        const handlerStart = source.indexOf('ipcMain.handle("themes-catalog"');
        expect(handlerStart).toBeGreaterThan(-1);
        const handlerEnd = source.indexOf('\nipcMain.handle(', handlerStart + 1);
        const handlerBody = handlerEnd === -1
            ? source.slice(handlerStart)
            : source.slice(handlerStart, handlerEnd);
        expect(handlerBody).toMatch(/paddleEnv:\s*isSandboxCatalog/);
        expect(handlerBody).toMatch(/sandbox:\s*isSandboxCatalog/);
    });

    test('reconcileThemeLicenses captures the server paddleEnv', () => {
        const source = fs.readFileSync(MAIN_PATH, 'utf8');
        const reconcileFn = extractFunctionSource(
            source,
            'reconcileThemeLicenses',
        );
        expect(reconcileFn).toMatch(/cachedThemeServerPaddleEnv/);
        expect(reconcileFn).toMatch(/paddleEnv:\s*cachedThemeServerPaddleEnv/);
        expect(reconcileFn).toMatch(/sandbox:\s*cachedThemeServerPaddleEnv === "sandbox"/);
    });
});

describe('main.js fetch timeout', () => {
    test('fetchWithTimeout aborts after the requested timeout', async () => {
        // We can't easily run an `await` in vm.runInContext because
        // scripts are not treated as modules. So instead we lift the
        // helper body verbatim and call it from real async context.
        // The helper clamps the timeout to a 1000ms floor, so the
        // fastest we can probe here is ~1000ms.
        const helperSource = loadMainFunction('fetchWithTimeout', { isAsync: true });
        // Fetch stub that respects the AbortSignal so the await actually
        // rejects when fetchWithTimeout's setTimeout fires abort().
        const fetchStub = (url, init) => new Promise((resolve, reject) => {
            const signal = init && init.signal;
            if (signal) {
                if (signal.aborted) {
                    reject(new DOMException('Aborted', 'AbortError'));
                    return;
                }
                signal.addEventListener('abort', () => {
                    reject(new DOMException('Aborted', 'AbortError'));
                }, { once: true });
            }
            // Never resolves; the abort handler above is the only path.
        });
        const context = {
            console,
            DOMException,
            fetch: fetchStub,
            AbortController,
            setTimeout,
            clearTimeout,
        };
        vm.createContext(context);
        vm.runInContext(helperSource, context);
        const start = Date.now();
        let caught = null;
        try {
            // Request 50ms; helper clamps to 1000ms minimum.
            await context.fetchWithTimeout('https://example.invalid/', {}, 50);
        } catch (error) {
            caught = error;
        }
        const elapsed = Date.now() - start;
        expect(caught).not.toBeNull();
        expect(caught.name).toBe('AbortError');
        expect(elapsed).toBeGreaterThanOrEqual(900);
        expect(elapsed).toBeLessThan(3000);
    }, 10000);

    test('fetchThemeServerJson and fetchThemeServerBuffer use fetchWithTimeout', () => {
        const sourceText = fs.readFileSync(MAIN_PATH, 'utf8');
        expect(sourceText).toMatch(/const THEME_SERVER_HTTP_TIMEOUT_MS = 5000/);
        expect(sourceText).toMatch(/function fetchWithTimeout\(/);
        const fetchJsonMatch = sourceText.match(
            /async function fetchThemeServerJson[\s\S]+?^\}/m,
        );
        expect(fetchJsonMatch).not.toBeNull();
        expect(fetchJsonMatch[0]).toMatch(/fetchWithTimeout\(/);
        const fetchBufferMatch = sourceText.match(
            /async function fetchThemeServerBuffer[\s\S]+?^\}/m,
        );
        expect(fetchBufferMatch).not.toBeNull();
        expect(fetchBufferMatch[0]).toMatch(/fetchWithTimeout\(/);
    });

    test('fetchThemeServerJson and fetchThemeServerBuffer send the PacketSnitch User-Agent', () => {
        const sourceText = fs.readFileSync(MAIN_PATH, 'utf8');
        const fetchJsonMatch = sourceText.match(
            /async function fetchThemeServerJson[\s\S]+?^\}/m,
        );
        expect(fetchJsonMatch).not.toBeNull();
        expect(fetchJsonMatch[0]).toMatch(/"User-Agent":\s*userAgent/);
        const fetchBufferMatch = sourceText.match(
            /async function fetchThemeServerBuffer[\s\S]+?^\}/m,
        );
        expect(fetchBufferMatch).not.toBeNull();
        expect(fetchBufferMatch[0]).toMatch(/"User-Agent":\s*userAgent/);
    });
});

describe('main.js theme helpers', () => {
    test('normalizeThemeDefinition preserves previewImage and previewUrl', () => {
        const sourceText = fs.readFileSync(MAIN_PATH, 'utf8');
        const helperSource = [
            loadMainFunction('sanitizeThemeId'),
            loadMainFunction('normalizeThemeEmbeddedImage'),
            loadMainFunction('normalizeThemeDefinition'),
        ].join('\n\n');
        // normalizeThemeDefinition references `metadata.sourcePath` only,
        // so the rest of the file is not required.
        const context = {
            console,
        };
        vm.createContext(context);
        vm.runInContext(helperSource, context);
        const result = context.normalizeThemeDefinition(
            {
                id: 'neon',
                name: 'Neon',
                description: 'A neon theme',
                variables: { '--app-bg': '#000000' },
                previewImage: { format: 'jpg', base64: 'aGVsbG8=' },
                previewUrl: 'https://example.com/neon.png',
            },
            'neon',
            { sourcePath: '/tmp/neon.json', sourceKind: 'cache', sourceMtimeMs: 1 },
        );
        expect(result).not.toBeNull();
        expect(result.previewImage).toEqual({ format: 'jpg', base64: 'aGVsbG8=' });
        expect(result.previewUrl).toBe('https://example.com/neon.png');
    });

    test('listThemeDefinitions merges cached themes via listCachedThemes stub', async () => {
        // We don't run the full main.js (it would pull in Electron);
        // we only verify the structural pieces by reading the source.
        const sourceText = fs.readFileSync(MAIN_PATH, 'utf8');
        expect(sourceText).toMatch(/async function listCachedThemes/);
        expect(sourceText).toMatch(/function getThemeCacheDir/);
        expect(sourceText).toMatch(/const THEME_CACHE_DIR_NAME = "theme-cache"/);
        // The new IPC handlers should all be registered.
        for (const channel of [
            'themes-catalog',
            'themes-fetch-preview',
            'themes-start-checkout',
            'themes-refresh-licenses',
            'themes-download',
        ]) {
            expect(sourceText).toContain(`ipcMain.handle("${channel}"`);
        }
        // listThemeDefinitions should include the cache directory in its merge.
        const mergeStart = sourceText.indexOf('async function listThemeDefinitions');
        const mergeEnd = sourceText.indexOf('function getThemeById', mergeStart);
        const mergeBody = sourceText.slice(mergeStart, mergeEnd);
        expect(mergeBody).toMatch(/listCachedThemes\(\)/);
        expect(mergeBody).toMatch(/\[\.\.\.userThemes, \.\.\.cachedThemes, \.\.\.bundledThemes\]/);
    });

    test('installThemeRecacheTimer uses unref() and runs a startup license probe', () => {
        const sourceText = fs.readFileSync(MAIN_PATH, 'utf8');
        expect(sourceText).toMatch(/async function installThemeRecacheTimer/);
        expect(sourceText).toMatch(/themeRecacheTimer\.unref\(\)/);
        expect(sourceText).toMatch(/reconcileThemeLicenses\(\{ force: false \}\)/);
    });

    test('preload exposes the new themeapi methods', () => {
        const preload = fs.readFileSync(
            path.join(PROJECT_ROOT, 'src', 'preload.js'),
            'utf8',
        );
        expect(preload).toMatch(/listCatalog: \(payload\) => ipcRenderer\.invoke\('themes-catalog'/);
        expect(preload).toMatch(/fetchPreview: \(payload\) => ipcRenderer\.invoke\('themes-fetch-preview'/);
        expect(preload).toMatch(/startCheckout: \(payload\) => ipcRenderer\.invoke\('themes-start-checkout'/);
        expect(preload).toMatch(/refreshLicenses: \(payload\) => ipcRenderer\.invoke\('themes-refresh-licenses'/);
        expect(preload).toMatch(/download: \(payload\) => ipcRenderer\.invoke\('themes-download'/);
    });

    test('normalizeThemeCachePayload unwraps the catalog server themeJson envelope', () => {
        // Lift the helper into a vm. It only depends on JSON, so a
        // bare context is sufficient.
        const helperSource = loadMainFunction('normalizeThemeCachePayload');
        const context = { console };
        vm.createContext(context);
        vm.runInContext(helperSource, context);
        const inner = {
            id: 'weebo',
            name: 'Weebo',
            description: 'test',
            variables: { '--app-bg': '#000000' },
        };
        const envelope = JSON.stringify({
            id: 'weebo',
            name: 'Weebo',
            priceCents: 299,
            priceLabel: '$2.99',
            paddle: { productId: 'pro_x', priceId: 'pri_y' },
            previewImage: '',
            themeJson: inner,
        });
        const out = context.normalizeThemeCachePayload(envelope);
        expect(out.unwrapped).toBe(true);
        // The cache file should be the inner object, not the envelope.
        const reparsed = JSON.parse(out.text);
        expect(reparsed).toEqual(inner);
        expect(reparsed).not.toHaveProperty('priceCents');
        expect(reparsed).not.toHaveProperty('paddle');
    });

    test('normalizeThemeCachePayload unwraps a string-encoded inner JSON', () => {
        const helperSource = loadMainFunction('normalizeThemeCachePayload');
        const context = { console };
        vm.createContext(context);
        vm.runInContext(helperSource, context);
        const inner = { id: 'weebo', name: 'Weebo', variables: { '--app-bg': '#000' } };
        const envelope = JSON.stringify({
            id: 'weebo',
            priceCents: 299,
            themeJson: JSON.stringify(inner),
        });
        const out = context.normalizeThemeCachePayload(envelope);
        expect(out.unwrapped).toBe(true);
        const reparsed = JSON.parse(out.text);
        expect(reparsed).toEqual(inner);
    });

    test('normalizeThemeCachePayload leaves a metadata-only body unchanged', () => {
        // Legacy catalogs that never received the themeJson field will
        // still serve the metadata envelope. The cache file then fails
        // validation downstream and is silently skipped — same as
        // before the envelope existed. We assert the helper doesn't
        // try to invent an inner object.
        const helperSource = loadMainFunction('normalizeThemeCachePayload');
        const context = { console };
        vm.createContext(context);
        vm.runInContext(helperSource, context);
        const legacy = JSON.stringify({
            id: 'weebo',
            name: 'Weebo',
            priceCents: 299,
            priceLabel: '$2.99',
            paddle: { productId: 'pro_x', priceId: 'pri_y' },
        });
        const out = context.normalizeThemeCachePayload(legacy);
        expect(out.unwrapped).toBe(false);
        expect(out.text).toBe(legacy);
    });

    test('normalizeThemeCachePayload tolerates non-JSON bodies', () => {
        const helperSource = loadMainFunction('normalizeThemeCachePayload');
        const context = { console };
        vm.createContext(context);
        vm.runInContext(helperSource, context);
        const out = context.normalizeThemeCachePayload('not json at all');
        expect(out.unwrapped).toBe(false);
        expect(out.text).toBe('not json at all');
    });

    test('normalizeThemeCachePayload passes the upstream inner-JSON contract through', () => {
        // Upstream PacketSnitch-Pro (schema v3) serves the
        // PacketSnitch theme JSON directly from the ``theme_json``
        // DB column, with no envelope wrapper. The desktop client's
        // ``normalizeThemeCachePayload`` must accept that body as-is
        // so the cache file is exactly the inner JSON
        // ``listCachedThemes`` expects to parse. We pin the contract
        // here so a future "helpful" transformation can't start
        // double-unwrapping or strip fields the renderer needs.
        const helperSource = loadMainFunction('normalizeThemeCachePayload');
        const context = { console };
        vm.createContext(context);
        vm.runInContext(helperSource, context);
        const inner = {
            id: 'matrix-theme',
            name: 'Matrix',
            description: 'Green-phosphor hacker vibe',
            variables: {
                '--app-bg': '#000000',
                '--accent': '#00ff66',
            },
            previewImage: { format: 'png', base64: 'iVBORw0KGgo=' },
        };
        const body = JSON.stringify(inner);
        const out = context.normalizeThemeCachePayload(body);
        expect(out.unwrapped).toBe(false);
        // Cache file equals the request body byte-for-byte (after
        // JSON.parse round-trip), so downstream parsers see the
        // exact shape the catalog server produced.
        expect(JSON.parse(out.text)).toEqual(inner);
        // Guard against an accidental second-wrap that would put the
        // JSON inside a new ``themeJson`` envelope.
        const reparsed = JSON.parse(out.text);
        expect(reparsed).not.toHaveProperty('themeJson');
        expect(reparsed).toHaveProperty('variables');
    });

    test('writeThemeToCache calls normalizeThemeCachePayload', () => {
        // The cache write must go through the unwrap helper so the
        // catalog's ``themeJson`` envelope is transparent to the rest
        // of the renderer. We grep rather than executing because
        // writeThemeToCache depends on Node fs + Electron paths.
        const sourceText = fs.readFileSync(MAIN_PATH, 'utf8');
        const writeFn = extractFunctionSource(sourceText, 'writeThemeToCache');
        expect(writeFn).toMatch(/normalizeThemeCachePayload\(/);
        expect(writeFn).toMatch(/unwrapped/);
    });

    test('ps-catalog.py stores the PacketSnitch theme definition in a theme_json column', () => {
        // Upstream PacketSnitch-Pro stores the actual PacketSnitch
        // theme JSON in a ``theme_json`` DB column (schema v3) and
        // serves it from ``/themes/<id>/download``. The desktop
        // client must tolerate BOTH:
        //
        //   1. The new contract: download body == inner PacketSnitch
        //      theme JSON ({id, name, variables, ...}).
        //   2. The legacy envelope: download body == admin metadata
        //      with a top-level ``themeJson`` key whose value is the
        //      inner JSON.
        //
        // This test pins the upstream contract so a future catalog
        // refactor doesn't quietly break the unwrap path on the
        // client.
        const pySource = fs.readFileSync(
            path.join(PROJECT_ROOT, 'src', 'PacketSnitch-Pro', 'Servers', 'Catalog', 'ps-catalog.py'),
            'utf8',
        );
        // Schema v3 introduces a theme_json column on the themes table.
        expect(pySource).toMatch(/SCHEMA_VERSION\s*=\s*3/);
        expect(pySource).toMatch(/theme_json TEXT NOT NULL DEFAULT ''/);
        // The download endpoint must prefer the DB column over the
        // on-disk file. This is the contract the desktop client's
        // ``normalizeThemeCachePayload`` is built around.
        const downloadHandler = pySource.match(
            /def _handle_theme_download[\s\S]+?cache_control="private, max-age=60"/,
        );
        expect(downloadHandler).not.toBeNull();
        expect(downloadHandler[0]).toMatch(/if theme\["theme_json"\]/);
        expect(downloadHandler[0]).toMatch(/body = theme\["theme_json"\]\.encode\("utf-8"\)/);
        // The admin upsert handler must accept a top-level
        // ``themeJson`` field and persist it to the DB column. The
        // CLI path is independent of the admin API and shares the
        // same ``db.upsert_theme(..., theme_json=...)`` call.
        const adminHandler = pySource.match(
            /def _handle_admin_themes_upsert_post[\s\S]+?return self\._write_envelope_json\(200, \{"ok": True, "themeId": theme_id\}\)/,
        );
        expect(adminHandler).not.toBeNull();
        expect(adminHandler[0]).toMatch(/payload\.get\("themeJson"\)/);
        expect(adminHandler[0]).toMatch(/theme_json=theme_json/);
        // The CLI ``cmd_add_theme`` must also persist the field.
        const cliAddTheme = pySource.match(
            /def cmd_add_theme[\s\S]+?^def cmd_remove_theme/m,
        );
        expect(cliAddTheme).not.toBeNull();
        expect(cliAddTheme[0]).toMatch(/raw\.get\("themeJson"\)/);
        expect(cliAddTheme[0]).toMatch(/theme_json=theme_json/);
    });
});

describe('settings.js schema additions', () => {
    test('DEFAULT_SETTINGS.general hardcodes the catalog server + recache', () => {
        const settings = fs.readFileSync(
            path.join(PROJECT_ROOT, 'src', 'settings.js'),
            'utf8',
        );
        // Catalog server URL is locked to the production endpoint.
        expect(settings).toMatch(
            /themeServerBaseUrl:\s*"https:\/\/catalog\.packetsnitch\.com:9021\/"/
        );
        // Recache interval is locked to 3 days (72h).
        expect(settings).toMatch(/themeRefreshIntervalHours:\s*72/);
        // Self-signed certs are always allowed.
        expect(settings).toMatch(/allowInsecureTlsEndpoints:\s*true/);
    });

    test('settings.js normalizer ignores user-supplied values for locked keys', () => {
        const settings = fs.readFileSync(
            path.join(PROJECT_ROOT, 'src', 'settings.js'),
            'utf8',
        );
        // The normalizer should emit the hard-coded defaults, never
        // any user-supplied override of these three keys.
        expect(settings).toMatch(
            /themeServerBaseUrl:\s*generalDefaults\.themeServerBaseUrl/
        );
        expect(settings).toMatch(
            /themeRefreshIntervalHours:\s*generalDefaults\.themeRefreshIntervalHours/
        );
        expect(settings).toMatch(
            /allowInsecureTlsEndpoints:\s*generalDefaults\.allowInsecureTlsEndpoints/
        );
    });
});
