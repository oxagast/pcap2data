// Tests for the Stats tab data being woven into the exported summary.
//
// These tests exercise the new `buildStatsMarkdownSection` helper and the
// modified `getSummaryMarkdownForExport` so that the same Stats tab
// information is included in all three export formats (Markdown, Text, HTML).

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

function loadFunction(functionName) {
    const sourcePath = path.join(__dirname, '..', 'src/ui/main-frontend.js');
    const sourceText = fs.readFileSync(sourcePath, 'utf8');
    return extractFunctionSource(sourceText, functionName);
}

// Build a minimal but realistic capturedPackets payload.
function makeCapturedPacketsStub() {
    return {
        host: {
            '10.0.0.1': [
                { 'packet.info': { index: 1 } },
                { 'packet.info': { index: 2 } },
            ],
        },
    };
}

function makeStatsStub(overrides = {}) {
    return Object.assign(
        {
            protocols: ['eth', 'ip', 'tcp'],
            networkProtocols: ['ip'],
            linkProtocols: ['eth'],
            transportProtocols: ['tcp'],
            decodedProtocols: ['http'],
            arpOperations: [],
            igmpMessageTypes: [],
            hosts: ['10.0.0.1', '10.0.0.2'],
            ports: [80, 443],
            macVendors: ['Cisco', 'Apple'],
            mimeTypes: ['text/html', 'application/json'],
            locations: [['San Francisco, US', 5], ['Berlin, DE', 3]],
            heatmapPoints: [],
            heatmapPacketHits: 12,
            internetHostCount: 4,
            hostnames: ['example.com'],
            dataTypes: ['web'],
            topTalkers: [
                { ip: '10.0.0.1', count: 100 },
                { ip: '10.0.0.2', count: 50 },
            ],
            encryptedCount: 0,
            unencryptedCount: 10,
            undecodableCount: 0,
            totalPackets: 10,
            totalStreams: 1,
            maxStreamLength: 10,
            minStreamLength: 10,
            avgStreamLength: '10.00',
            creds: [],
            uniqueCredentialCount: 0,
            uniqueCredentials: [],
            totalTraffic: 2048,
            retransmissionCount: 0,
            outOfOrderCount: 0,
            bookmarkCount: 0,
        },
        overrides,
    );
}

const helperSource = [
    loadFunction('formatStatsByteCount'),
    loadFunction('joinStatsListValues'),
    loadFunction('truncateStatsList'),
    loadFunction('buildStatsMarkdownTable'),
    loadFunction('buildStatsMarkdownSection'),
    loadFunction('getSummaryMarkdownForExport'),
].join('\n\n');

function runInFreshContext({ capturedPackets, stats, bookmarkList = [], extraContext = {} } = {}) {
    const buildCaptureStats = jest.fn(() => stats);
    const context = Object.assign(
        {
            capturedPackets:
                capturedPackets === undefined ? makeCapturedPacketsStub() : capturedPackets,
            bookmarkList: Array.isArray(bookmarkList) ? bookmarkList : [],
            buildCaptureStats,
            writeLogEntry: () => { },
        },
        extraContext,
    );
    vm.createContext(context);
    vm.runInContext(helperSource, context);
    return { context, buildCaptureStats };
}

describe('summary stats weaving', () => {
    describe('buildStatsMarkdownSection', () => {
        test('returns empty string when no capture is loaded', () => {
            const { context } = runInFreshContext({
                capturedPackets: null,
                stats: makeStatsStub(),
            });
            const result = context.buildStatsMarkdownSection();
            expect(result).toBe('');
        });

        test('returns empty string when host bucket is missing', () => {
            const { context } = runInFreshContext({
                capturedPackets: { other: 1 },
                stats: makeStatsStub(),
            });
            const result = context.buildStatsMarkdownSection();
            expect(result).toBe('');
        });

        test('produces a complete Capture Statistics section', () => {
            const stats = makeStatsStub();
            const { context, buildCaptureStats } = runInFreshContext({ stats });
            const result = context.buildStatsMarkdownSection();

            expect(typeof result).toBe('string');
            expect(result.length).toBeGreaterThan(0);
            // Verify section heading and required subsections.
            expect(result).toContain('## Capture Statistics');
            expect(result).toContain('### Protocols');
            expect(result).toContain('### Hosts, Ports, and Vendors');
            expect(result).toContain('### Top Talkers');
            expect(result).toContain('### Geographic Footprint');
            expect(result).toContain('### MIME Types');
            expect(result).toContain('### Heatmap');
            // Verify overview table values appear.
            expect(result).toContain('Total packets');
            expect(result).toContain('10');
            expect(result).toContain('Internet hosts');
            // Verify formatting helpers.
            expect(result).toContain('2.00 KB'); // totalTraffic formatting
            expect(result).toContain('http'); // decoded protocol
            // Verify buildCaptureStats is called with bookmark count.
            expect(buildCaptureStats).toHaveBeenCalled();
            const callArgs = buildCaptureStats.mock.calls[0];
            expect(callArgs[1]).toBe(0);
        });

        test('formats bytes correctly across unit boundaries', () => {
            const { context } = runInFreshContext({ stats: makeStatsStub() });
            expect(context.formatStatsByteCount(0)).toBe('0 B');
            expect(context.formatStatsByteCount(-1)).toBe('0 B');
            expect(context.formatStatsByteCount(512)).toBe('512 B');
            expect(context.formatStatsByteCount(1024)).toBe('1.00 KB');
            expect(context.formatStatsByteCount(1536)).toBe('1.50 KB');
            expect(context.formatStatsByteCount(1024 * 1024)).toBe('1.00 MB');
            expect(context.formatStatsByteCount(1024 * 1024 * 1024)).toBe(
                '1.00 GB',
            );
        });

        test('truncates long lists with a "more" indicator', () => {
            const longList = Array.from({ length: 30 }, (_, i) => `item-${i}`);
            const { context } = runInFreshContext({ stats: makeStatsStub() });
            const short = context.truncateStatsList(longList, 50);
            expect(short.values).toEqual(longList);
            expect(short.truncated).toBe(0);
            const truncated = context.truncateStatsList(longList, 5);
            expect(truncated.values).toHaveLength(5);
            expect(truncated.truncated).toBe(25);
        });

        test('joins list values and handles empty input', () => {
            const { context } = runInFreshContext({ stats: makeStatsStub() });
            expect(context.joinStatsListValues([])).toBe('None');
            expect(context.joinStatsListValues(null)).toBe('None');
            expect(context.joinStatsListValues(['a', 'b', 'c'])).toBe('a, b, c');
            expect(context.joinStatsListValues([null, '', 'x'])).toBe('x');
        });

        test('builds a markdown table with proper escaping', () => {
            const { context } = runInFreshContext({ stats: makeStatsStub() });
            const table = context.buildStatsMarkdownTable(
                ['A', 'B'],
                [
                    ['value1', 'value|with|pipes'],
                    ['line1\nline2', 'plain'],
                ],
            );
            expect(table).toContain('| A | B |');
            expect(table).toContain('| --- | --- |');
            expect(table).toContain('value\\|with\\|pipes');
            expect(table).toContain('line1 line2');
        });

        test('includes credentials subsection when unique credentials exist', () => {
            const stats = makeStatsStub({
                uniqueCredentials: ['ab****yz', 'cd****wx'],
                uniqueCredentialCount: 2,
            });
            const { context } = runInFreshContext({ stats });
            const result = context.buildStatsMarkdownSection();
            expect(result).toContain('### Credentials');
            expect(result).toContain('Unique credentials (2)');
            expect(result).toContain('ab****yz');
        });

        test('includes stream length / TCP anomaly rows when multiple streams present', () => {
            const stats = makeStatsStub({
                totalStreams: 3,
                maxStreamLength: 25,
                minStreamLength: 5,
                avgStreamLength: '12.00',
                retransmissionCount: 4,
                outOfOrderCount: 2,
            });
            const { context } = runInFreshContext({ stats });
            const result = context.buildStatsMarkdownSection();
            expect(result).toContain('Stream length (avg / min / max)');
            expect(result).toContain('12.00 / 5 / 25 packets');
            expect(result).toContain('TCP retransmissions');
            expect(result).toContain('Out-of-order segments');
        });

        test('passes bookmark count to buildCaptureStats', () => {
            const stats = makeStatsStub({ bookmarkCount: 7 });
            const { context, buildCaptureStats } = runInFreshContext({
                stats,
                bookmarkList: new Array(7),
            });
            context.buildStatsMarkdownSection();
            expect(buildCaptureStats.mock.calls[0][1]).toBe(7);
        });
    });

    describe('getSummaryMarkdownForExport', () => {
        test('appends the stats section after the LLM summary', () => {
            const stats = makeStatsStub();
            const { context, buildCaptureStats } = runInFreshContext({
                stats,
                extraContext: {
                    getCurrentCompactedAnalysisSummary: () =>
                        '## Compaction Result\n\nThe LLM saw a small HTTP transfer.',
                    normalizeSummaryMarkdownHeadings: (input) =>
                        `# PacketSnitch's Summary\n\n${input}`,
                },
            });
            const result = context.getSummaryMarkdownForExport();
            expect(result).toContain("PacketSnitch's Summary");
            expect(result).toContain('## Compaction Result');
            expect(result).toContain('## Capture Statistics');
            // The stats section must come after the LLM summary.
            const llmIndex = result.indexOf('## Compaction Result');
            const statsIndex = result.indexOf('## Capture Statistics');
            expect(llmIndex).toBeGreaterThanOrEqual(0);
            expect(statsIndex).toBeGreaterThan(llmIndex);
            // buildCaptureStats is called via the helper.
            expect(buildCaptureStats).toHaveBeenCalled();
        });

        test('returns the LLM summary untouched when no capture is loaded', () => {
            const { context } = runInFreshContext({
                capturedPackets: null,
                stats: makeStatsStub(),
                extraContext: {
                    getCurrentCompactedAnalysisSummary: () =>
                        '## Compaction Result\n\nLLM analysis content.',
                    normalizeSummaryMarkdownHeadings: (input) =>
                        `# PacketSnitch's Summary\n\n${input}`,
                },
            });
            const result = context.getSummaryMarkdownForExport();
            expect(result).toBe(
                "# PacketSnitch's Summary\n\n## Compaction Result\n\nLLM analysis content.",
            );
            expect(result).not.toContain('## Capture Statistics');
        });
    });

    describe('LLM prompt context', () => {
        // Verifies the source code of writeSummaryFromLLM and
        // runAnalysisCompaction references buildStatsMarkdownSection so the
        // Stats tab data is woven into the LLM's view of the pcap, not just
        // appended at export time.
        const sourcePath = path.join(__dirname, '..', 'src/ui/main-frontend.js');
        const sourceText = fs.readFileSync(sourcePath, 'utf8');

        function extractFunctionBody(name) {
            const startToken = `function ${name}`;
            const startIndex = sourceText.indexOf(startToken);
            if (startIndex === -1) {
                throw new Error(`Could not find function ${name}`);
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
            throw new Error(`Could not parse function ${name}`);
        }

        test('writeSummaryFromLLM includes the stats context in its prompt', () => {
            const body = extractFunctionBody('writeSummaryFromLLM');
            expect(body).toContain('buildStatsMarkdownSection');
            // The prompt template should reference the stats context.
            expect(body).toMatch(/statsContext[A-Za-z]*\}/);
            // The prompt should explicitly tell the LLM to weave the stats
            // into its answer so the analyst has a complete pcap view.
            expect(body.toLowerCase()).toContain('weave');
        });

        test('runAnalysisCompaction includes the stats context in its prompt', () => {
            const body = extractFunctionBody('runAnalysisCompaction');
            expect(body).toContain('buildStatsMarkdownSection');
            // The prompt template should reference the stats context.
            expect(body).toMatch(/statsContext[A-Za-z]*\}/);
            // The compaction prompt should tell the LLM to weave the stats
            // into the compacted summary so the analyst has a complete view.
            expect(body.toLowerCase()).toContain('weave');
        });
    });
});
