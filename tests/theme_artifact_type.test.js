// Tests for the artifact type tagging and theme validation that
// prevents the theme engine from pulling in non-theme artifacts
// (licenses, plugins) from the catalog server.
//
// The main-process helpers live in src/main.js and are extracted with
// `vm` so they can run in plain Node without a full Electron app.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PROJECT_ROOT = path.join(__dirname, '..');
const MAIN_PATH = path.join(PROJECT_ROOT, 'src', 'main.js');
const RENDERER_PATH = path.join(PROJECT_ROOT, 'src', 'ui', 'main-frontend.js');

function extractFunctionSource(sourceText, functionName, { isAsync = false } = {}) {
    const startToken = isAsync
        ? `async function ${functionName}`
        : `function ${functionName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
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
        if (char === '(') {
            parenDepth += 1;
            seenOpenParen = true;
            continue;
        }
        if (char === ')') {
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

function loadMainFunction(functionName, { isAsync = false } = {}) {
    const sourceText = fs.readFileSync(MAIN_PATH, 'utf8');
    return extractFunctionSource(sourceText, functionName, { isAsync });
}

function loadMainConst(sourceText, constName) {
    const startToken = `const ${constName} = `;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find constant ${constName}`);
    }
    // Handle Set() literals — find the matching closing ");"
    let cursor = startIndex + startToken.length;
    let depth = 0;
    let inSingle = false;
    let inDouble = false;
    let inBack = false;
    for (; cursor < sourceText.length; cursor += 1) {
        const char = sourceText[cursor];
        if (char === "'" && !inDouble && !inBack) inSingle = !inSingle;
        else if (char === '"' && !inSingle && !inBack) inDouble = !inDouble;
        else if (char === '`' && !inSingle && !inDouble) inBack = !inBack;
        else if (char === '(' && !inSingle && !inDouble && !inBack) depth += 1;
        else if (char === ')' && !inSingle && !inDouble && !inBack) {
            depth -= 1;
            if (depth === 0) {
                cursor += 1;
                break;
            }
        } else if (char === ';' && !inSingle && !inDouble && !inBack && depth === 0) {
            return sourceText.slice(startIndex, cursor + 1);
        }
    }
    // Look for the trailing semicolon
    for (; cursor < sourceText.length; cursor += 1) {
        if (sourceText[cursor] === ';') {
            return sourceText.slice(startIndex, cursor + 1);
        }
    }
    return sourceText.slice(startIndex, cursor);
}

function makeValidationVm() {
    const sourceText = fs.readFileSync(MAIN_PATH, 'utf8');
    const helpers = [
        loadMainFunction('sanitizeThemeId'),
        loadMainFunction('getArtifactType'),
        loadMainFunction('isNonThemeArtifact'),
        loadMainFunction('validateThemeDefinition'),
        loadMainFunction('normalizeThemeDefinition'),
        loadMainFunction('normalizeThemeEmbeddedImage'),
        loadMainConst(sourceText, 'THEME_ARTIFACT_TYPE_THEME'),
        loadMainConst(sourceText, 'THEME_ARTIFACT_TYPE_LICENSE'),
        loadMainConst(sourceText, 'THEME_ARTIFACT_TYPE_PLUGIN'),
        loadMainConst(sourceText, 'KNOWN_ARTIFACT_TYPES'),
    ].join('\n\n');
    const context = { console };
    vm.createContext(context);
    vm.runInContext(helpers, context);
    return context;
}

describe('Artifact type constants', () => {
    test('THEME_ARTIFACT_TYPE_* constants are defined with expected values', () => {
        const sourceText = fs.readFileSync(MAIN_PATH, 'utf8');
        expect(sourceText).toMatch(/THEME_ARTIFACT_TYPE_THEME\s*=\s*"theme"/);
        expect(sourceText).toMatch(/THEME_ARTIFACT_TYPE_LICENSE\s*=\s*"license"/);
        expect(sourceText).toMatch(/THEME_ARTIFACT_TYPE_PLUGIN\s*=\s*"plugin"/);
    });

    test('KNOWN_ARTIFACT_TYPES Set contains all three types', () => {
        const context = makeValidationVm();
        // const declarations live in script scope, so access via
        // runInContext rather than the context object.
        expect(vm.runInContext('THEME_ARTIFACT_TYPE_THEME', context)).toBe('theme');
        expect(vm.runInContext('THEME_ARTIFACT_TYPE_LICENSE', context)).toBe('license');
        expect(vm.runInContext('THEME_ARTIFACT_TYPE_PLUGIN', context)).toBe('plugin');
        expect(vm.runInContext('KNOWN_ARTIFACT_TYPES.has("theme")', context)).toBe(true);
        expect(vm.runInContext('KNOWN_ARTIFACT_TYPES.has("license")', context)).toBe(true);
        expect(vm.runInContext('KNOWN_ARTIFACT_TYPES.has("plugin")', context)).toBe(true);
    });
});

describe('getArtifactType', () => {
    test('returns "theme" for objects without a type field', () => {
        const context = makeValidationVm();
        expect(context.getArtifactType({ id: 'neon' })).toBe('theme');
    });

    test('returns "theme" for null/undefined input', () => {
        const context = makeValidationVm();
        expect(context.getArtifactType(null)).toBe('theme');
        expect(context.getArtifactType(undefined)).toBe('theme');
    });

    test('returns the lowercased type when present', () => {
        const context = makeValidationVm();
        expect(context.getArtifactType({ type: 'License' })).toBe('license');
        expect(context.getArtifactType({ type: 'PLUGIN' })).toBe('plugin');
        expect(context.getArtifactType({ type: 'theme' })).toBe('theme');
    });

    test('falls back to "theme" for empty/whitespace type', () => {
        const context = makeValidationVm();
        expect(context.getArtifactType({ type: '' })).toBe('theme');
        expect(context.getArtifactType({ type: '  ' })).toBe('theme');
    });
});

describe('isNonThemeArtifact', () => {
    test('returns true for license type', () => {
        const context = makeValidationVm();
        expect(context.isNonThemeArtifact({ type: 'license' })).toBe(true);
    });

    test('returns true for plugin type', () => {
        const context = makeValidationVm();
        expect(context.isNonThemeArtifact({ type: 'plugin' })).toBe(true);
    });

    test('returns false for theme type', () => {
        const context = makeValidationVm();
        expect(context.isNonThemeArtifact({ type: 'theme' })).toBe(false);
    });

    test('returns false for missing type (backwards compat)', () => {
        const context = makeValidationVm();
        expect(context.isNonThemeArtifact({ id: 'neon' })).toBe(false);
    });
});

describe('validateThemeDefinition', () => {
    test('accepts a valid theme with CSS variables', () => {
        const context = makeValidationVm();
        const result = context.validateThemeDefinition({
            id: 'neon',
            name: 'Neon',
            variables: { '--app-bg': '#000000', '--accent': '#00ff66' },
        });
        expect(result.valid).toBe(true);
        expect(result.reason).toBe('');
    });

    test('rejects null input', () => {
        const context = makeValidationVm();
        const result = context.validateThemeDefinition(null);
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/not an object/);
    });

    test('rejects non-object input', () => {
        const context = makeValidationVm();
        const result = context.validateThemeDefinition('hello');
        expect(result.valid).toBe(false);
    });

    test('rejects a theme with missing id', () => {
        const context = makeValidationVm();
        const result = context.validateThemeDefinition({
            name: 'No ID',
            variables: { '--app-bg': '#000000' },
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/id is missing/);
    });

    test('rejects a theme with empty id', () => {
        const context = makeValidationVm();
        const result = context.validateThemeDefinition({
            id: '  ',
            variables: { '--app-bg': '#000000' },
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/id is missing/);
    });

    test('rejects a theme with no variables object', () => {
        const context = makeValidationVm();
        const result = context.validateThemeDefinition({
            id: 'neon',
            name: 'Neon',
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/variables/);
    });

    test('rejects a theme with empty variables', () => {
        const context = makeValidationVm();
        const result = context.validateThemeDefinition({
            id: 'neon',
            variables: {},
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/no valid CSS/);
    });

    test('rejects a theme where variables only has non--- keys', () => {
        const context = makeValidationVm();
        const result = context.validateThemeDefinition({
            id: 'neon',
            variables: { color: '#000', bg: '#fff' },
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/no valid CSS/);
    });

    test('rejects a theme tagged as license', () => {
        const context = makeValidationVm();
        const result = context.validateThemeDefinition({
            id: 'pro-license',
            type: 'license',
            variables: { '--app-bg': '#000000' },
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/license/);
    });

    test('rejects a theme tagged as plugin', () => {
        const context = makeValidationVm();
        const result = context.validateThemeDefinition({
            id: 'my-plugin',
            type: 'plugin',
            variables: { '--app-bg': '#000000' },
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/plugin/);
    });
});

describe('normalizeThemeDefinition rejects non-theme artifacts', () => {
    test('returns null for a license-tagged payload', () => {
        const context = makeValidationVm();
        const result = context.normalizeThemeDefinition(
            { id: 'pro', type: 'license', name: 'Pro License', variables: { '--app-bg': '#000' } },
            'pro',
        );
        expect(result).toBeNull();
    });

    test('returns null for a plugin-tagged payload', () => {
        const context = makeValidationVm();
        const result = context.normalizeThemeDefinition(
            { id: 'my-plugin', type: 'plugin', name: 'My Plugin', variables: { '--app-bg': '#000' } },
            'my-plugin',
        );
        expect(result).toBeNull();
    });

    test('still normalizes a theme-tagged payload', () => {
        const context = makeValidationVm();
        const result = context.normalizeThemeDefinition(
            { id: 'neon', type: 'theme', name: 'Neon', variables: { '--app-bg': '#000' } },
            'neon',
        );
        expect(result).not.toBeNull();
        expect(result.id).toBe('neon');
    });

    test('still normalizes a payload without a type field (backwards compat)', () => {
        const context = makeValidationVm();
        const result = context.normalizeThemeDefinition(
            { id: 'neon', name: 'Neon', variables: { '--app-bg': '#000' } },
            'neon',
        );
        expect(result).not.toBeNull();
        expect(result.id).toBe('neon');
    });
});

describe('Catalog IPC preserves type field', () => {
    test('themes-catalog handler maps entry.type into the result', () => {
        const source = fs.readFileSync(MAIN_PATH, 'utf8');
        const handlerStart = source.indexOf('ipcMain.handle("themes-catalog"');
        expect(handlerStart).toBeGreaterThan(-1);
        const handlerEnd = source.indexOf('\nipcMain.handle(', handlerStart + 1);
        const handlerBody = handlerEnd === -1
            ? source.slice(handlerStart)
            : source.slice(handlerStart, handlerEnd);
        // The handler should call getArtifactType and include it in the
        // mapped entry.
        expect(handlerBody).toMatch(/getArtifactType/);
        expect(handlerBody).toMatch(/type:\s*artifactType/);
    });

    test('fetchAndCacheTheme validates the downloaded payload before caching', () => {
        const source = fs.readFileSync(MAIN_PATH, 'utf8');
        const fnBody = extractFunctionSource(source, 'fetchAndCacheTheme');
        expect(fnBody).toMatch(/validateThemeDefinition/);
        // Should return null when validation fails
        expect(fnBody).toMatch(/return null/);
    });

    test('reconcileThemeLicenses skips non-theme owned IDs', () => {
        const source = fs.readFileSync(MAIN_PATH, 'utf8');
        const fnBody = extractFunctionSource(source, 'reconcileThemeLicenses', { isAsync: true });
        expect(fnBody).toMatch(/findCatalogEntryTypeById/);
        expect(fnBody).toMatch(/isNonThemeArtifact/);
    });

    test('cachedCatalogEntryTypes is populated by the catalog IPC', () => {
        const source = fs.readFileSync(MAIN_PATH, 'utf8');
        const handlerStart = source.indexOf('ipcMain.handle("themes-catalog"');
        const handlerEnd = source.indexOf('\nipcMain.handle(', handlerStart + 1);
        const handlerBody = handlerEnd === -1
            ? source.slice(handlerStart)
            : source.slice(handlerStart, handlerEnd);
        expect(handlerBody).toMatch(/cachedCatalogEntryTypes/);
    });
});

describe('Renderer uses type field for catalog classification', () => {
    test('renderThemesCatalog classifies by entry.type', () => {
        const source = fs.readFileSync(RENDERER_PATH, 'utf8');
        const fnBody = extractFunctionSource(source, 'renderThemesCatalog');
        // Should check entry.type === "license"
        expect(fnBody).toMatch(/entryType === "license"/);
        // Should check entry.type === "plugin"
        expect(fnBody).toMatch(/entryType === "plugin"/);
        // Plugins should be skipped, not rendered as themes
        expect(fnBody).toMatch(/Plugins are not themes/);
    });

    test('backfillMissingOwnedThemes filters by type === "theme"', () => {
        const source = fs.readFileSync(RENDERER_PATH, 'utf8');
        const fnBody = extractFunctionSource(source, 'backfillMissingOwnedThemes', { isAsync: true });
        expect(fnBody).toMatch(/entry\.type/);
        expect(fnBody).toMatch(/entryType !== "theme"/);
    });
});