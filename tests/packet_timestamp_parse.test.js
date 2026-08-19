// Coverage for the timestamp parse that backs the renderer's packet sort.
// The backend emits "YYYY-MM-DD HH:MM:SS.ffffff"; Date.parse truncates the
// microsecond tail to milliseconds, which used to make the renderer's
// comparator disagree with the backend's sort. These tests pin down the
// intended semantics: microsecond precision preserved as a fractional
// millisecond, same local-time convention as Date.parse, and a fast
// already-sorted short-circuit for sortPacketsByOwnStreamOrder.

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

function extractConstDeclaration(sourceText, constName) {
    const startToken = `const ${constName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find const ${constName}`);
    }
    // Include everything up to and including the terminating semicolon.
    const endIndex = sourceText.indexOf(';', startIndex);
    if (endIndex === -1) {
        throw new Error(`Could not find terminating semicolon for ${constName}`);
    }
    return sourceText.slice(startIndex, endIndex + 1);
}

describe('renderer packet timestamp parse', () => {
    const sourcePath = path.join(__dirname, '..', 'src', 'ui', 'main-frontend.js');
    const sourceText = fs.readFileSync(sourcePath, 'utf8');

    // The cache lives at module scope as `const packetTimestampMsCache = new WeakMap();`
    const cacheDecl = extractConstDeclaration(sourceText, 'packetTimestampMsCache');
    const timestampRegexDecl = extractConstDeclaration(sourceText, 'BACKEND_TIMESTAMP_RE');
    const helperFns = [
        cacheDecl,
        timestampRegexDecl,
        extractFunctionSource(sourceText, 'parseBackendTimestampMs'),
        extractFunctionSource(sourceText, 'parsePacketTimestampMs'),
        extractFunctionSource(sourceText, 'parsePacketProcessedNumber'),
        extractFunctionSource(sourceText, 'parsePacketIndexNumber'),
        extractFunctionSource(sourceText, 'comparePacketsChronologically'),
        extractFunctionSource(sourceText, 'isPacketListInStreamOrder'),
        extractFunctionSource(sourceText, 'sortPacketsByOwnStreamOrder'),
    ].join('\n\n');

    function makeContext() {
        const ctx = {
            Date,
            Number,
            WeakMap,
            Array,
            Math,
            Number,
            Boolean,
            String,
        };
        vm.createContext(ctx);
        vm.runInContext(helperFns, ctx);
        return ctx;
    }

    test('parses canonical backend "%Y-%m-%d %H:%M:%S.%f" with microsecond precision', () => {
        const ctx = makeContext();
        const a = { 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.123456' } };
        const b = { 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.123999' } };
        const ta = ctx.parsePacketTimestampMs(a);
        const tb = ctx.parsePacketTimestampMs(b);
        expect(Number.isFinite(ta)).toBe(true);
        expect(Number.isFinite(tb)).toBe(true);
        // The two packets are ~543µs apart. Date.parse would have returned the
        // same millisecond for both; the fast parser must keep them distinct.
        expect(tb).toBeGreaterThan(ta);
        expect(tb - ta).toBeGreaterThan(0);
        expect(tb - ta).toBeLessThan(1);
    });

    test('matches Date.parse absolute ms for whole-millisecond inputs (local time)', () => {
        const ctx = makeContext();
        const raw = '2024-01-15 12:34:56.123';
        const parsed = ctx.parsePacketTimestampMs({ 'packet.info': { 'packet.timestamp': raw } });
        expect(parsed).toBe(Date.parse(raw));
    });

    test('returns null for empty and missing timestamps', () => {
        const ctx = makeContext();
        expect(ctx.parsePacketTimestampMs({ 'packet.info': { 'packet.timestamp': '' } })).toBeNull();
        expect(ctx.parsePacketTimestampMs({ 'packet.info': { 'packet.timestamp': '   ' } })).toBeNull();
        expect(ctx.parsePacketTimestampMs({ 'packet.info': {} })).toBeNull();
        expect(ctx.parsePacketTimestampMs(null)).toBeNull();
    });

    test('memoizes parse results across calls for the same packet object', () => {
        const ctx = makeContext();
        const packet = { 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.999000' } };
        const first = ctx.parsePacketTimestampMs(packet);
        const second = ctx.parsePacketTimestampMs(packet);
        expect(first).toBe(second);
        // Even if the underlying string changes after first call, the memoized
        // value is what subsequent readers see. This is deliberate: timestamps
        // are set once by the backend and never mutate.
        packet['packet.info']['packet.timestamp'] = '2024-01-15 12:34:57.000000';
        expect(ctx.parsePacketTimestampMs(packet)).toBe(first);
    });

    test('isPacketListInStreamOrder recognizes backend-sorted input', () => {
        const ctx = makeContext();
        const sorted = [
            { 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.000001' } },
            { 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.000002' } },
            { 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.000003' } },
        ];
        expect(ctx.isPacketListInStreamOrder(sorted)).toBe(true);
        const unsorted = [sorted[2], sorted[0], sorted[1]];
        expect(ctx.isPacketListInStreamOrder(unsorted)).toBe(false);
    });

    test('sortPacketsByOwnStreamOrder returns the same reference when input is sorted', () => {
        const ctx = makeContext();
        const sorted = [
            { 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.000001', index: 1 } },
            { 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.000002', index: 2 } },
            { 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.000003', index: 3 } },
        ];
        const result = ctx.sortPacketsByOwnStreamOrder(sorted);
        expect(result).toBe(sorted); // reference equality — no copy made
    });

    test('sortPacketsByOwnStreamOrder orders unsorted input and preserves stable tie-breaks', () => {
        const ctx = makeContext();
        const a = { tag: 'a', 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.000002', index: 1 } };
        const b = { tag: 'b', 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.000001', index: 2 } };
        const c = { tag: 'c', 'packet.info': { 'packet.timestamp': '2024-01-15 12:34:56.000002', index: 3 } };
        const result = ctx.sortPacketsByOwnStreamOrder([a, b, c]);
        expect(result.map((p) => p.tag)).toEqual(['b', 'a', 'c']);
        // `a` and `c` tie on timestamp; their relative order must be preserved.
    });
});
