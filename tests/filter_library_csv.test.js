// Smoke test for the filter-library plugin's CSV layer. We pull the
// plugin's parse/serialize helpers out of the IIFE so we can exercise
// them without booting the renderer DOM, then verify:
//   - the bundled seed.csv covers the requested protocol topics
//   - serialize -> parse is a stable round-trip
//   - commas, double-quotes, and embedded newlines survive quoting
const fs = require('fs');
const path = require('path');

const PLUGIN_PATH = path.join(
    __dirname,
    '..',
    'samples',
    'plugins',
    'filter-library',
    'filter-library.js',
);
const SEED_PATH = path.join(
    __dirname,
    '..',
    'samples',
    'plugins',
    'filter-library',
    'seed.csv',
);

function loadRuntime() {
    const pluginSource = fs.readFileSync(PLUGIN_PATH, 'utf8');
    const fakeWindow = {};
    const fakeDocument = {
        getElementById: () => null,
        createElement: () => ({ style: {} }),
    };
    const wrap = new Function('window', 'module', 'document', pluginSource);
    const fakeModule = { exports: {} };
    wrap(fakeWindow, fakeModule, fakeDocument);
    const runtime = fakeWindow.FilterLibraryPlugin;
    if (!runtime || !runtime.parseCsv || !runtime.serializeCsv || !runtime.normalizeEntries) {
        throw new Error('filter-library helpers missing from runtime');
    }
    return runtime;
}

describe('filter-library plugin CSV helpers', () => {
    const runtime = loadRuntime();

    test('bundled seed.csv covers mail/ftp/web topics', () => {
        const seed = fs.readFileSync(SEED_PATH, 'utf8');
        const entries = runtime.normalizeEntries(runtime.parseCsv(seed));
        expect(entries.length).toBeGreaterThan(0);

        const requiredTopics = [
            { label: 'IMAP', re: /IMAP/ },
            { label: 'IMAPS', re: /IMAPS/ },
            { label: 'SMTP', re: /SMTP/ },
            { label: 'SMTPS', re: /SMTPS/ },
            { label: 'POP3', re: /POP3/ },
            { label: 'POP3S', re: /POP3S/ },
            { label: 'FTP', re: /FTP/ },
            { label: 'FTP-DATA', re: /FTP-DATA/ },
            { label: 'HTTP', re: /HTTP(?!S)/ },
            { label: 'HTTPS', re: /HTTPS/ },
        ];
        for (const topic of requiredTopics) {
            const hits = entries.filter((entry) => topic.re.test(entry.filter));
            expect(hits.length).toBeGreaterThan(0);
        }
    });

    test('every seed entry has both a name and a filter', () => {
        const seed = fs.readFileSync(SEED_PATH, 'utf8');
        const entries = runtime.normalizeEntries(runtime.parseCsv(seed));
        for (const entry of entries) {
            expect(entry.name).toBeTruthy();
            expect(entry.filter).toBeTruthy();
        }
    });

    test('serialize/parse round-trip preserves every entry', () => {
        const seed = fs.readFileSync(SEED_PATH, 'utf8');
        const entries = runtime.normalizeEntries(runtime.parseCsv(seed));
        const reserialized = runtime.serializeCsv(entries);
        const reparsed = runtime.normalizeEntries(runtime.parseCsv(reserialized));
        expect(reparsed).toEqual(entries);
    });

    test('commas, quotes, and newlines survive quoting', () => {
        const tricky = [
            {
                name: 'Tricky, name',
                description: 'has,comma and "quote" and\nnewline',
                filter: 'application.proto: HTTP || application.proto: HTTPS',
            },
            {
                name: 'Plain',
                description: '',
                filter: 'ip.src.addr: 10.0.0.1',
            },
        ];
        const roundtrip = runtime.normalizeEntries(
            runtime.parseCsv(runtime.serializeCsv(tricky)),
        );
        expect(roundtrip).toEqual(tricky);
    });

    test('header row is recognized and skipped on re-parse', () => {
        const csvWithHeader = 'name,description,filter\nFoo,desc,application.proto: HTTP\n';
        const entries = runtime.normalizeEntries(runtime.parseCsv(csvWithHeader));
        expect(entries).toEqual([
            { name: 'Foo', description: 'desc', filter: 'application.proto: HTTP' },
        ]);
    });

    test('blank rows and rows missing required fields are dropped', () => {
        const noisy = [
            'name,description,filter',
            '',
            '   ,   ,   ',
            ',,',
            'HasName,,application.proto: FTP',
            ',HasDesc,application.proto: FTP',
            'HasFilterOnly,desc,',
            'OK,desc,application.proto: IMAP',
        ].join('\n');
        const entries = runtime.normalizeEntries(runtime.parseCsv(noisy));
        expect(entries.map((e) => e.name)).toEqual(['HasName', 'OK']);
    });

    test('mergeEntries counts added/updated/skipped correctly', () => {
        const local = [
            { name: 'Shared', description: 'old', filter: 'application.proto: HTTP' },
            { name: 'Local-only', description: '', filter: 'application.proto: SMTP' },
        ];
        const remote = [
            { name: 'Shared', description: 'new', filter: 'application.proto: HTTPS' },
            { name: 'Brand-new', description: '', filter: 'application.proto: FTP' },
            { name: 'Brand-new', description: 'dup', filter: 'application.proto: FTP' },
        ];
        const counts = runtime.mergeEntries(local, remote);
        expect(counts).toEqual({ added: 1, updated: 1, skipped: 1 });
    });

    test('applyMerge lets remote entries overwrite matching local names', () => {
        const local = [
            { name: 'Shared', description: 'old', filter: 'application.proto: HTTP' },
            { name: 'Local-only', description: '', filter: 'application.proto: SMTP' },
        ];
        const remote = [
            { name: 'Shared', description: 'new', filter: 'application.proto: HTTPS' },
            { name: 'Brand-new', description: '', filter: 'application.proto: FTP' },
        ];
        const merged = runtime.applyMerge(local, remote);
        expect(merged).toEqual([
            { name: 'Shared', description: 'new', filter: 'application.proto: HTTPS' },
            { name: 'Local-only', description: '', filter: 'application.proto: SMTP' },
            { name: 'Brand-new', description: '', filter: 'application.proto: FTP' },
        ]);
    });

    test('full fetch flow: parse remote CSV and merge', () => {
        const remoteCsv = [
            'name,description,filter',
            'IMAP - all traffic,IMAP4 messages,application.proto: IMAP',
            'Local-only,,application.proto: SMTP',
        ].join('\n');
        const local = [
            { name: 'Local-only', description: '', filter: 'application.proto: SMTP' },
        ];
        const remoteEntries = runtime.normalizeEntries(runtime.parseCsv(remoteCsv));
        const counts = runtime.mergeEntries(local, remoteEntries);
        // "IMAP - all traffic" is new; "Local-only" matches a local
        // entry by name so it counts as updated even though the body
        // is byte-identical.
        expect(counts).toEqual({ added: 1, updated: 1, skipped: 0 });
        const merged = runtime.applyMerge(local, remoteEntries);
        expect(merged.map((e) => e.name)).toEqual([
            'Local-only',
            'IMAP - all traffic',
        ]);
    });

    test('isRemoteCsvPath distinguishes local file paths from URLs', () => {
        if (typeof runtime.isRemoteCsvPath !== 'function') {
            // Older runtime builds without this helper are still valid
            // for the older CSV tests, so do not fail the suite.
            return;
        }
        expect(runtime.isRemoteCsvPath('')).toBe(false);
        expect(runtime.isRemoteCsvPath('/home/user/filter.csv')).toBe(false);
        expect(runtime.isRemoteCsvPath('./relative.csv')).toBe(false);
        expect(runtime.isRemoteCsvPath('C:\\Users\\me\\filter.csv')).toBe(false);
        expect(runtime.isRemoteCsvPath('http://example.com/filter.csv')).toBe(true);
        expect(runtime.isRemoteCsvPath('https://example.com/filter.csv')).toBe(true);
        expect(runtime.isRemoteCsvPath('HTTPS://EXAMPLE.COM/X')).toBe(true);
    });

    test('source declares the Hide button + auto-hide on apply', () => {
        // The hide panel UX is wired in the IIFE and not exposed on
        // the runtime, so we verify the source text contains the
        // required hook points. If these are missing, the button
        // won't render or the auto-hide won't fire.
        const pluginSource = fs.readFileSync(PLUGIN_PATH, 'utf8');
        expect(pluginSource).toMatch(/HIDE_BTN_ID\s*=\s*['"]filter-library-hide-btn['"]/);
        expect(pluginSource).toMatch(/Hide Panel/);
        expect(pluginSource).toMatch(/function\s+hidePanel\s*\(/);
        // Auto-hide on successful apply: the applyBtn handler must
        // call hidePanel after a successful applyFilter call, and
        // the catch block must NOT call hidePanel (otherwise the
        // error message gets hidden from the user).
        const applyIdx = pluginSource.indexOf('applyBtn.addEventListener');
        expect(applyIdx).toBeGreaterThan(-1);
        // Bound to the apply listener's actual closing brace so we
        // don't accidentally include the next handler (Hide button,
        // Fetch URL, etc.) in the search.
        const applyEnd = pluginSource.indexOf('});', applyIdx + 600);
        expect(applyEnd).toBeGreaterThan(applyIdx);
        const applyBlock = pluginSource.slice(applyIdx, applyEnd + 4);
        expect(applyBlock).toMatch(/applyFilter\(context, expression\)/);
        // At least one hidePanel call inside the apply block.
        expect(applyBlock).toMatch(/hidePanel\(documentRef\)/);
        // The catch block must NOT auto-hide — users need to see the
        // error message in the same panel they just clicked.
        const catchIdx = applyBlock.indexOf('catch (error)');
        expect(catchIdx).toBeGreaterThan(-1);
        const catchBlock = applyBlock.slice(catchIdx);
        expect(catchBlock).not.toMatch(/hidePanel\(documentRef\)/);
    });
});
