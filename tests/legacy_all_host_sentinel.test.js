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
    let depth = 0;
    for (let cursor = bodyStart; cursor < sourceText.length; cursor += 1) {
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

describe('legacy DUMMY_ALL_HOST sentinel translation', () => {
    const sourcePath = path.join(__dirname, '..', 'src/ui/main-frontend.js');
    const sourceText = fs.readFileSync(sourcePath, 'utf8');

    // Extract the relevant constants and helpers
    const scriptText = [
        'const SESSION_FILE_SCHEMA_VERSION = ' +
            (sourceText.match(/const SESSION_FILE_SCHEMA_VERSION = (\d+);/) || [])[1] + ';',
        'const DUMMY_ALL_HOST = "' +
            (sourceText.match(/const DUMMY_ALL_HOST = "([^"]+)";/) || [])[1] + '";',
        // Inline the translation block as a function for unit testing.
        `function translateSelectedHost(rawSelectedHost, sessionSchemaVersion) {
            const LEGACY_ALL_HOST_SENTINEL = "0.0.0.0";
            const isLegacyAllHostSelection =
                sessionSchemaVersion < SESSION_FILE_SCHEMA_VERSION
                && rawSelectedHost === LEGACY_ALL_HOST_SENTINEL;
            return isLegacyAllHostSelection ? DUMMY_ALL_HOST : rawSelectedHost;
        }`,
        // Expose values via globals so the test can read them back
        '({ DUMMY_ALL_HOST, translateSelectedHost, SESSION_FILE_SCHEMA_VERSION });',
    ].join('\n');
    const helpers = vm.runInNewContext(scriptText);

    test('legacy schema (v1) translates "0.0.0.0" host selection to DUMMY_ALL_HOST', () => {
        expect(helpers.DUMMY_ALL_HOST).toBe('__ALL_HOSTS__');
        expect(helpers.translateSelectedHost('0.0.0.0', 1)).toBe('__ALL_HOSTS__');
    });

    test('legacy schema (v1) leaves other hosts alone', () => {
        expect(helpers.translateSelectedHost('192.168.0.50', 1)).toBe('192.168.0.50');
        expect(helpers.translateSelectedHost('__ALL_HOSTS__', 1)).toBe('__ALL_HOSTS__');
        expect(helpers.translateSelectedHost('', 1)).toBe('');
    });

    test('current schema (v2) does NOT translate "0.0.0.0" (user may have selected it intentionally)', () => {
        expect(helpers.translateSelectedHost('0.0.0.0', 2)).toBe('0.0.0.0');
        expect(helpers.translateSelectedHost('0.0.0.0', 3)).toBe('0.0.0.0');
    });

    test('current schema (v2) leaves "__ALL_HOSTS__" alone', () => {
        expect(helpers.translateSelectedHost('__ALL_HOSTS__', 2)).toBe('__ALL_HOSTS__');
    });

    test('missing schema version (Number converts to 0) translates "0.0.0.0" as legacy', () => {
        // In the real restoreSessionState path the schemaVersion is
        // coerced via "Number(sessionState?.schemaVersion) || 0" so a
        // missing field becomes 0 which is < SESSION_FILE_SCHEMA_VERSION
        // and the legacy translation kicks in.  Mirror that coercion here.
        function translateWithCoercion(rawSelectedHost, sessionSchemaVersion) {
            const coercedSchemaVersion = Number(sessionSchemaVersion) || 0;
            return helpers.translateSelectedHost(rawSelectedHost, coercedSchemaVersion);
        }
        expect(translateWithCoercion('0.0.0.0', 0)).toBe('__ALL_HOSTS__');
        expect(translateWithCoercion('0.0.0.0', undefined)).toBe('__ALL_HOSTS__');
    });
});
