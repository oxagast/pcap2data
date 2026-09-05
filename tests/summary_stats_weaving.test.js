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

// Same as loadFunction, but preserves the `async` keyword on the
// declaration. `loadFunction` searches for `function <name>` which
// strips the `async` prefix; this helper searches for
// `async function <name>` first and keeps the `async` keyword in
// the extracted source so the function remains awaitable in the
// test sandbox. Falls back to loadFunction's behaviour if the
// function is not declared async.
function loadAsyncFunction(functionName) {
    const sourcePath = path.join(__dirname, '..', 'src/ui/main-frontend.js');
    const sourceText = fs.readFileSync(sourcePath, 'utf8');
    const asyncStartToken = `async function ${functionName}`;
    const plainStartToken = `function ${functionName}`;
    let startIndex = sourceText.indexOf(asyncStartToken);
    let isAsync = startIndex !== -1;
    if (!isAsync) {
        startIndex = sourceText.indexOf(plainStartToken);
    }
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
                // Slice from the `async` token (or `function` token for
                // non-async helpers) so the extracted source already
                // carries the keyword. Do NOT re-prepend `async`.
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
    }
    throw new Error(`Could not parse function ${functionName}`);
}

function loadConstant(constantName) {
    const sourcePath = path.join(__dirname, '..', 'src/ui/main-frontend.js');
    const sourceText = fs.readFileSync(sourcePath, 'utf8');
    const startToken = `const ${constantName} = `;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find constant ${constantName}`);
    }
    // Walk forward to find the end of the value (terminating semicolon
    // outside of any string literal).
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
    loadConstant('SUMMARY_HEADING'),
    loadFunction('prependSummaryHeading'),
    loadFunction('formatStatsByteCount'),
    loadFunction('joinStatsListValues'),
    loadFunction('truncateStatsList'),
    loadFunction('buildStatsMarkdownTable'),
    loadFunction('buildStatsMarkdownSection'),
    loadFunction('buildMultiCaptureSummaryNotice'),
    loadFunction('getNotesSummarySection'),
    loadFunction('isNoteConcrete'),
    loadFunction('getCurrentSummaryReportMarkdown'),
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
            getCaptureSources: () => [],
            writeLogEntry: () => { },
            // The Notes <-> Summary integration reads `notesList` directly
            // out of the VM context. Older tests in this file don't
            // exercise Notes, but they still call
            // `getCurrentSummaryReportMarkdown` (transitively via
            // `getSummaryMarkdownForExport`), so we provide an empty
            // default to keep them working.
            notesList: [],
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

    describe('buildMultiCaptureSummaryNotice', () => {
        test('returns no notice for a single capture', () => {
            const { context } = runInFreshContext({
                extraContext: {
                    getCaptureSources: () => [{ sourceId: 'one', sourceName: 'one.pcap' }],
                },
            });
            expect(context.buildMultiCaptureSummaryNotice()).toBe('');
        });

        test('describes multiple capture sources before analysis', () => {
            const { context } = runInFreshContext({
                extraContext: {
                    getCaptureSources: () => [
                        { sourceId: 'one', sourceName: 'one.pcap' },
                        { sourceId: 'two', sourceName: 'two.pcap' },
                    ],
                },
            });
            const notice = context.buildMultiCaptureSummaryNotice();
            expect(notice).toContain('2 separate capture sources');
            expect(notice).toContain('one.pcap');
            expect(notice).toContain('two.pcap');
            expect(notice.toLowerCase()).toContain('distinct captures');
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
                        `## Compaction Result\n\nThe LLM saw a small HTTP transfer.`,
                    prependSummaryHeading: (input) =>
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
                        `## Compaction Result\n\nLLM analysis content.`,
                    prependSummaryHeading: (input) =>
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
            // The prompt template should reference the capture-overview
            // variable (the new name after the initial-weave refactor).
            expect(body).toMatch(/captureOverview[A-Za-z]*/);
            // The prompt must mark the Stats data as primary context.
            expect(body).toContain('Capture Statistics (from the Stats panel)');
            // The prompt should explicitly tell the LLM to weave the stats
            // into its answer so the analyst has a complete pcap view.
            expect(body.toLowerCase()).toContain('weave');
            // The keystore summary should also be wired in.
            expect(body).toContain('getLatestKeystoreSummary');
            expect(body).toContain('prependMultiCaptureSummaryNotice');
        });

        test('runAnalysisCompaction includes the stats context in its prompt', () => {
            const body = extractFunctionBody('runAnalysisCompaction');
            expect(body).toContain('buildStatsMarkdownSection');
            // The prompt template should reference the capture-overview
            // variable (the new name after the initial-weave refactor).
            expect(body).toMatch(/captureOverview[A-Za-z]*/);
            // The prompt must mark the Stats data as primary context.
            expect(body).toContain('Capture Statistics (from the Stats panel)');
            // The compaction prompt should tell the LLM to weave the stats
            // into the compacted summary so the analyst has a complete view.
            expect(body.toLowerCase()).toContain('weave');
            // The keystore summary should also be wired in.
            expect(body).toContain('getLatestKeystoreSummary');
            expect(body).toContain('prependMultiCaptureSummaryNotice');
        });

        test('runAnalysisCompaction places the capture overview before the blurbs', () => {
            // The capture overview must appear earlier in the prompt than
            // the chronological blurbs, so it survives any LLM truncation
            // and acts as primary input. We verify this by inspecting the
            // template literal that builds the prompt: `captureOverview`
            // must be interpolated before `${chronologicalBlurbs}`.
            const body = extractFunctionBody('runAnalysisCompaction');
            // Locate the combinedInput template literal.
            const combinedInputMatch = body.match(
                /const combinedInput = `([^`]*?)`;/,
            );
            expect(combinedInputMatch).not.toBeNull();
            const combinedInputTemplate = combinedInputMatch[1];
            // The capture overview must come before the chronological
            // blurbs interpolation in the template.
            const captureOverviewPosition = combinedInputTemplate.indexOf(
                '${captureOverview}',
            );
            const chronologicalBlurbsPosition = combinedInputTemplate.indexOf(
                '${chronologicalBlurbs}',
            );
            expect(captureOverviewPosition).toBeGreaterThanOrEqual(0);
            expect(chronologicalBlurbsPosition).toBeGreaterThanOrEqual(0);
            expect(captureOverviewPosition).toBeLessThan(
                chronologicalBlurbsPosition,
            );
        });
    });

    describe('export-time distillation', () => {
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

        test('distillSummaryMarkdownWithLLM exists and is exported as a function', () => {
            // The distiller must be a top-level function in the file so the
            // export flow can call it. Look for the actual declaration line
            // rather than the first mention (which may be in a comment
            // describing the function's contract or return values).
            const headerLine = sourceText.split('\n').find((line) =>
                /^(async\s+)?function\s+distillSummaryMarkdownWithLLM\b/.test(line),
            );
            expect(headerLine).toBeDefined();
            expect(headerLine).toMatch(
                /^(async\s+)?function distillSummaryMarkdownWithLLM/,
            );
        });

        test('buildSummaryDistillPrompt includes all required instructions', () => {
            const body = extractFunctionBody('buildSummaryDistillPrompt');
            // Dedupe.
            expect(body.toLowerCase()).toContain('deduplicat');
            // Chronological sort.
            expect(body.toLowerCase()).toContain('chronological');
            // Section highlights / importance ranking.
            expect(body.toLowerCase()).toMatch(/stand out|importance|highlight/);
            // Preserve concrete data points.
            expect(body.toLowerCase()).toContain('preserve');
            // Valid Markdown output.
            expect(body.toLowerCase()).toContain('markdown');
        });

        test('saveSummaryFromContextMenu awaits the distiller before saving', () => {
            // The saveSummaryFromContextMenu function must:
            // 1. Call distillSummaryMarkdownWithLLM.
            // 2. Await the result (no fire-and-forget).
            // 3. Use the awaited result as the markdown for the export.
            // 4. Only call window.saveapi.saveText after the await resolves.
            const body = extractFunctionBody('saveSummaryFromContextMenu');
            expect(body).toContain('distillSummaryMarkdownWithLLM');
            // Must use `await` on the distiller call. The await result is
            // assigned to the `distillOutcome` variable, then read via
            // `distillOutcome.text`.
            const distillAwaitMatch = body.match(
                /distillOutcome\s*=\s*await\s+distillSummaryMarkdownWithLLM\(/,
            );
            expect(distillAwaitMatch).not.toBeNull();
            // The distiller call must come BEFORE the saveText invocation
            // (so the user is shown the distilled content in the dialog).
            const distillIndex = body.indexOf('distillSummaryMarkdownWithLLM');
            const saveTextIndex = body.indexOf('.saveText');
            expect(distillIndex).toBeGreaterThanOrEqual(0);
            expect(saveTextIndex).toBeGreaterThan(distillIndex);
            // The save dialog must be reached only after the await — verify
            // the function awaits the LLM and then saves (no fire-and-
            // forget saveText inside a non-awaited branch).
            expect(body).toMatch(/await\s+distillSummaryMarkdownWithLLM/);
        });

        test('saveSummaryFromContextMenu handles distiller failures gracefully', () => {
            // If the distiller throws, the export must still proceed with
            // the original (un-distilled) report so the user is not
            // blocked from saving.
            const body = extractFunctionBody('saveSummaryFromContextMenu');
            // Must have a try/catch around the distiller call.
            expect(body).toMatch(/try\s*\{[\s\S]*?await\s+distillSummaryMarkdownWithLLM[\s\S]*?\}\s*catch/);
            // The catch must restore the outcome to a sensible fallback so
            // summaryMarkdown can be derived from it.
            expect(body).toMatch(/distillOutcome\s*=\s*\{/);
            expect(body).toMatch(/text:\s*rawSummaryMarkdown/);
        });

        test('distillSummaryMarkdownWithLLM short-circuits when the LLM is disabled', () => {
            // The distiller must check the LLM runtime flag and return the
            // input unchanged if the LLM is not available. This guarantees
            // that users without an LLM still get an export.
            const body = extractFunctionBody('distillSummaryMarkdownWithLLM');
            expect(body).toContain('isLlmRuntimeEnabled');
            expect(body).toContain('isLlmEnabledInSettings');
            // Must check both flags before calling the LLM. After a
            // short-circuit the function returns a result object with
            // status + text, not the raw string.
            expect(body).toMatch(
                /isLlmRuntimeEnabled[\s\S]{0,200}return reportResult/,
            );
            expect(body).toMatch(
                /isLlmEnabledInSettings[\s\S]{0,200}return reportResult/,
            );
        });

        test('distillSummaryMarkdownWithLLM short-circuits for short reports', () => {
            // Reports below the minimum length should pass through
            // unchanged so the LLM isn't called unnecessarily.
            const body = extractFunctionBody('distillSummaryMarkdownWithLLM');
            expect(body).toContain('SUMMARY_DISTILL_MIN_LENGTH');
            expect(body).toMatch(
                /SUMMARY_DISTILL_MIN_LENGTH[\s\S]{0,200}return reportResult/,
            );
        });

        test('distillSummaryMarkdownWithLLM falls back on LLM errors', () => {
            // If the LLM throws or returns empty, the distiller must
            // return the original markdown so the user is not blocked.
            const body = extractFunctionBody('distillSummaryMarkdownWithLLM');
            expect(body).toContain('callLargeLanguageModelWithRetry');
            // Must have a try/catch around the LLM call.
            expect(body).toMatch(
                /try\s*\{[\s\S]*?callLargeLanguageModelWithRetry[\s\S]*?\}\s*catch/,
            );
            // The catch must return a result object with the original text.
            expect(body).toMatch(
                /catch[\s\S]{0,300}return reportResult\(\s*summaryMarkdown,\s*SUMMARY_DISTILL_ERROR/,
            );
        });

        test('distillSummaryMarkdownWithLLM caps input and output sizes', () => {
            // The distiller must truncate the input prompt and the output
            // response to keep the export pipeline bounded.
            const body = extractFunctionBody('distillSummaryMarkdownWithLLM');
            expect(body).toContain('SUMMARY_DISTILL_INPUT_MAX_CHARS');
            expect(body).toContain('SUMMARY_DISTILL_OUTPUT_MAX_CHARS');
            expect(body).toContain('LLM_MAX_CONTENT_LENGTH');
        });

        test('saveSummaryFromContextMenu surfaces a status message about distillation', () => {
            // The user must get a visible status update that tells them
            // whether the export was actually distilled by the LLM or
            // whether the original report was saved as-is.
            const body = extractFunctionBody('saveSummaryFromContextMenu');
            expect(body).toContain('statusUpdate');
            expect(body).toMatch(/Status:\s*Distilling export report via LLM/);
            // A success / skip / error message must follow the await.
            expect(body).toMatch(
                /Status:\s*LLM distilled report/,
            );
            expect(body).toMatch(
                /Status:\s*Export not distilled/,
            );
        });

        test('distillSummaryMarkdownWithLLM returns a status-tagged result', () => {
            // The distiller must return an object with `text` and `status`
            // so the caller can decide what status message to surface.
            // The function body should always go through `reportResult(...)`
            // to construct its return values.
            const body = extractFunctionBody('distillSummaryMarkdownWithLLM');
            // The helper that builds the result must be defined.
            expect(body).toContain('const reportResult =');
            // Every return path must go through reportResult. We check
            // the function has at least three return statements using
            // reportResult.
            const reportResultUses = (body.match(/return reportResult\(/g) || []).length;
            expect(reportResultUses).toBeGreaterThanOrEqual(4);
        });

        test('saveSummaryFromContextMenu uses distillOutcome.text for the export', () => {
            // The save function must use the distilled text from the
            // result object — not the raw input — so the user sees the
            // distilled content in the save dialog.
            const body = extractFunctionBody('saveSummaryFromContextMenu');
            expect(body).toMatch(/summaryMarkdown\s*=\s*distillOutcome\.text/);
        });

        test('pushDistilledSummaryIntoSummaryTab is defined and updates the summary state', () => {
            // The Summary tab updater must exist as a top-level function
            // so the export flow can call it after a successful distill.
            const headerLine = sourceText.split('\n').find((line) =>
                line.includes('pushDistilledSummaryIntoSummaryTab'),
            );
            expect(headerLine).toBeDefined();
            expect(headerLine).toMatch(
                /^(async\s+)?function pushDistilledSummaryIntoSummaryTab/,
            );
            // The function must mutate the summary state. The exact name
            // of the variable in the source is "compactedAnalysisSummaries"
            // so we look for that assignment.
            const body = extractFunctionBody(
                'pushDistilledSummaryIntoSummaryTab',
            );
            expect(body).toContain('compactedAnalysisSummaries');
            // It should re-render the Summary tab so the user sees the
            // distilled content immediately.
            expect(body).toContain('renderCombinedAnalysisSummary');
        });

        test('saveSummaryFromContextMenu pushes the distilled result into the Summary tab', () => {
            // The export flow must call pushDistilledSummaryIntoSummaryTab
            // when the LLM successfully distills the report, and it must
            // re-pull the export markdown from the Summary tab afterwards
            // so the save dialog matches the on-screen view.
            const body = extractFunctionBody('saveSummaryFromContextMenu');
            expect(body).toContain('pushDistilledSummaryIntoSummaryTab');
            // The push must happen before the save dialog opens.
            const pushIndex = body.indexOf(
                'pushDistilledSummaryIntoSummaryTab',
            );
            const saveTextIndex = body.indexOf('.saveText');
            expect(pushIndex).toBeGreaterThanOrEqual(0);
            expect(saveTextIndex).toBeGreaterThan(pushIndex);
            // The re-pull must happen between the push and the save so
            // the dialog uses the freshly-pushed distilled content.
            expect(body).toMatch(
                /pushDistilledSummaryIntoSummaryTab[\s\S]{0,200}getSummaryMarkdownForExport/,
            );
        });

        test('pushDistilledSummaryIntoSummaryTab replaces prior distilled entries', () => {
            // Repeated exports should not keep stacking distilled
            // versions on top of each other — the function must filter
            // out any prior distilled entry before pushing the new one.
            const body = extractFunctionBody(
                'pushDistilledSummaryIntoSummaryTab',
            );
            expect(body).toContain('SUMMARY_DISTILL_ENTRY_SIGNATURE');
            // Must filter out prior distilled entries.
            expect(body).toMatch(/filter[\s\S]{0,300}SUMMARY_DISTILL_ENTRY_SIGNATURE/);
        });

        describe('export-time distillation cache', () => {
            // The export-time distiller caches the LLM result keyed on a
            // fingerprint of the *analyst-visible* content. A re-save with
            // no new context must skip the LLM pass and return the cached
            // distilled text under SUMMARY_DISTILL_SKIP_ALREADY_DISTILLED.
            // The cache must be invalidated when notes change so the
            // analyst always sees a fresh distillation on the next save
            // after they add context.
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

            function bootDistillCacheContext(overrides = {}) {
                const llmCalls = [];
                const context = Object.assign(
                    {
                        // Single-entry cache state, mirroring the module-
                        // level declaration in main-frontend.js.
                        summaryDistillCache: {
                            inputHash: '',
                            inputLength: 0,
                            distilledText: '',
                            distilledAt: 0,
                        },
                        // Mimic the prior `__distilled__` push: a list of
                        // summary entries that may or may not include one.
                        compactedAnalysisSummaries: [],
                        notesList: [],
                        // A safe no-op log writer.
                        writeLogEntry: () => { },
                        // The fingerprint builder reads these. The
                        // overrides let tests control notes / stats.
                        buildStatsMarkdownSection: () => 'STATS',
                        isNoteConcrete: () => false,
                        // The LLM mock records calls and returns canned
                        // responses so we can verify cache hits short-
                        // circuit the call.
                        callLargeLanguageModelWithRetry: async (prompt) => {
                            llmCalls.push(prompt);
                            return { response: `DISTILLED(${prompt.length})` };
                        },
                        isLlmRuntimeEnabled: () => true,
                        isLlmEnabledInSettings: () => true,
                        LLM_MAX_CONTENT_LENGTH: 200000,
                        SUMMARY_DISTILL_MIN_LENGTH: 400,
                        SUMMARY_DISTILL_INPUT_MAX_CHARS: 60000,
                        SUMMARY_DISTILL_OUTPUT_MAX_CHARS: 60000,
                        // The distiller also calls these for status.
                        statusUpdate: () => { },
                    },
                    overrides,
                );
                // Wrap the source in an async IIFE so the distiller's
                // `await` is valid. Function declarations inside an
                // async IIFE are scoped to that IIFE — expose them onto
                // the surrounding context so tests can call them
                // directly via `context.distillSummaryMarkdownWithLLM`.
                const source = `
                    (async () => {
                        ${[
                        loadConstant('SUMMARY_DISTILL_ENTRY_SIGNATURE'),
                        loadConstant('SUMMARY_DISTILL_SKIP_ALREADY_DISTILLED'),
                        loadConstant('SUMMARY_DISTILL_OK'),
                        loadConstant('SUMMARY_DISTILL_ERROR'),
                        loadConstant('SUMMARY_DISTILL_SKIP_EMPTY'),
                        loadConstant('SUMMARY_DISTILL_SKIP_TOO_SHORT'),
                        loadConstant('SUMMARY_DISTILL_SKIP_RUNTIME_DISABLED'),
                        loadConstant('SUMMARY_DISTILL_SKIP_SETTINGS_DISABLED'),
                        loadConstant('SUMMARY_DISTILL_SKIP_PROMPT_TOO_LONG'),
                        loadConstant('SUMMARY_DISTILL_SKIP_LLM_EMPTY'),
                        loadFunction('hashSummaryInputForDistillCache'),
                        loadFunction('resetSummaryDistillCache'),
                        loadFunction('buildSummaryDistillCacheFingerprint'),
                        loadFunction('buildSummaryDistillPrompt'),
                        loadFunction('stripLlmThinkingText'),
                        loadAsyncFunction('distillSummaryMarkdownWithLLM'),
                    ].join('\n\n')}
                        globalThis.hashSummaryInputForDistillCache = hashSummaryInputForDistillCache;
                        globalThis.resetSummaryDistillCache = resetSummaryDistillCache;
                        globalThis.buildSummaryDistillCacheFingerprint = buildSummaryDistillCacheFingerprint;
                        globalThis.distillSummaryMarkdownWithLLM = distillSummaryMarkdownWithLLM;
                        globalThis.__booted = true;
                    })();
                `;
                vm.createContext(context);
                vm.runInContext(source, context);
                // Wait for the async IIFE to finish binding the
                // functions to globalThis before returning. The IIFE
                // only does synchronous work after the await in the
                // distiller, so by the time vm.runInContext returns the
                // microtask queue has the IIFE pending. A short polling
                // loop yields until globalThis.__booted is set.
                const waitForBoot = () => new Promise((resolve) => {
                    const check = () => {
                        if (context.__booted) {
                            resolve();
                        } else {
                            setImmediate(check);
                        }
                    };
                    check();
                });
                return waitForBoot().then(() => ({ context, llmCalls }));
            }

            function longEnough(text) {
                // Pad the input so it clears SUMMARY_DISTILL_MIN_LENGTH.
                return `${text}\n\n${'x'.repeat(500)}`;
            }

            test('buildSummaryDistillCacheFingerprint excludes the distilled entry', () => {
                // The fingerprint must not include the distilled entry's
                // summary text. If it did, every re-save would have a
                // different fingerprint and the cache would never hit.
                const baseline = longEnough('baseline content');
                const bootPromise = bootDistillCacheContext();
                return bootPromise.then(({ context }) => {
                    // First save: no distilled entry.
                    context.compactedAnalysisSummaries = [
                        { signature: 'ctx:1', summary: 'Context one' },
                        { signature: 'ctx:2', summary: 'Context two' },
                    ];
                    const fpWithoutDistilled =
                        context.buildSummaryDistillCacheFingerprint();
                    // Simulate the prior save pushing a `__distilled__` entry.
                    context.compactedAnalysisSummaries = [
                        { signature: '__distilled__', summary: 'LLM distilled blob' },
                        { signature: 'ctx:1', summary: 'Context one' },
                        { signature: 'ctx:2', summary: 'Context two' },
                    ];
                    const fpWithDistilled =
                        context.buildSummaryDistillCacheFingerprint();
                    // The distilled entry is the ONLY thing that changed
                    // and the fingerprints must match.
                    expect(fpWithDistilled).toBe(fpWithoutDistilled);
                    // Sanity check: the baseline is not blank.
                    expect(fpWithoutDistilled.length).toBeGreaterThan(0);
                    void baseline;
                });
            });

            test('fingerprint diverges when a new note is added', () => {
                // Notes are part of the cache key so an added note forces
                // a fresh distillation on the next save.
                return bootDistillCacheContext().then(({ context }) => {
                    context.notesList = [];
                    const fpEmpty = context.buildSummaryDistillCacheFingerprint();
                    context.notesList = [
                        { text: 'analyst observation', concrete: false, updatedAt: 1 },
                    ];
                    const fpWithNote =
                        context.buildSummaryDistillCacheFingerprint();
                    expect(fpWithNote).not.toBe(fpEmpty);
                });
            });

            test('fingerprint diverges when a context entry is added', () => {
                // New analysis context (a new compaction pass entry)
                // must also force re-distillation.
                return bootDistillCacheContext().then(({ context }) => {
                    context.compactedAnalysisSummaries = [
                        { signature: 'ctx:1', summary: 'A' },
                    ];
                    const fpOne = context.buildSummaryDistillCacheFingerprint();
                    context.compactedAnalysisSummaries = [
                        { signature: 'ctx:1', summary: 'A' },
                        { signature: 'ctx:2', summary: 'B' },
                    ];
                    const fpTwo = context.buildSummaryDistillCacheFingerprint();
                    expect(fpTwo).not.toBe(fpOne);
                });
            });

            test('re-save with no new context short-circuits the LLM call', async () => {
                // The full end-to-end check: two consecutive saves with
                // the same analyst-visible state must invoke the LLM
                // exactly once. The second call must return
                // SUMMARY_DISTILL_SKIP_ALREADY_DISTILLED with the cached
                // distilled text and must NOT call the LLM again.
                const { context, llmCalls } = await bootDistillCacheContext();
                context.compactedAnalysisSummaries = [
                    { signature: 'ctx:1', summary: 'Some analysis' },
                ];
                context.notesList = [
                    { text: 'note one', concrete: false, updatedAt: 1 },
                ];
                const input1 = longEnough('# Summary\n\nfirst save body');
                const input2 = longEnough('# Summary\n\nfirst save body');
                // First save: cache empty, LLM is called.
                const result1 = await context.distillSummaryMarkdownWithLLM(input1);
                expect(result1.status).toBe('ok');
                expect(result1.text).toMatch(/^DISTILLED\(/);
                expect(llmCalls.length).toBe(1);
                // Second save: same analyst-visible state, but the input
                // *appears* different because we simulate the post-save
                // state where the `__distilled__` entry has been pushed.
                // The distiller must ignore the distilled entry and
                // short-circuit on the fingerprint.
                context.compactedAnalysisSummaries = [
                    { signature: '__distilled__', summary: result1.text },
                    { signature: 'ctx:1', summary: 'Some analysis' },
                ];
                const result2 = await context.distillSummaryMarkdownWithLLM(input2);
                expect(result2.status).toBe('already_distilled');
                expect(result2.text).toBe(result1.text);
                expect(llmCalls.length).toBe(1); // still only one LLM call
            });

            test('resetSummaryDistillCache forces a fresh distillation', async () => {
                // After the cache is reset (e.g. note edit), the next
                // save must call the LLM again even with the same input.
                const { context, llmCalls } = await bootDistillCacheContext();
                context.compactedAnalysisSummaries = [
                    { signature: 'ctx:1', summary: 'Some analysis' },
                ];
                const input = longEnough('# Summary\n\ncontent');
                await context.distillSummaryMarkdownWithLLM(input);
                expect(llmCalls.length).toBe(1);
                // Simulate the prior save pushing the distilled entry.
                context.compactedAnalysisSummaries = [
                    { signature: '__distilled__', summary: 'cached' },
                    { signature: 'ctx:1', summary: 'Some analysis' },
                ];
                context.resetSummaryDistillCache();
                const result = await context.distillSummaryMarkdownWithLLM(input);
                expect(result.status).toBe('ok');
                expect(llmCalls.length).toBe(2);
            });

            test('refreshSummaryForNotes invalidates the cache', () => {
                // The Notes <-> Summary integration helper must clear
                // the cache so the next save after a note edit
                // re-distills. Verified by source-text inspection so we
                // do not have to boot the entire Notes integration.
                const body = extractFunctionBody('refreshSummaryForNotes');
                expect(body).toContain('resetSummaryDistillCache');
            });

            test('cache is shared across all save paths (text, html, markdown, pdf)', async () => {
                // The four save flows — text, html, markdown via the
                // context menu, and pdf via the header button — must
                // share the same module-scoped distillation cache so a
                // re-save in any format after a successful distillation
                // short-circuits the LLM pass. This is the property the
                // user expects: once the report has been distilled, no
                // subsequent export in any format should re-invoke the
                // LLM unless new context has been added.
                //
                // We exercise the cache directly by simulating the
                // distiller invocation that each save path makes. If
                // the cache were path-local, four consecutive calls
                // would each invoke the LLM; with a shared cache the
                // first call populates the entry and the next three
                // hit it.
                const { context, llmCalls } = await bootDistillCacheContext();
                context.compactedAnalysisSummaries = [
                    { signature: 'ctx:1', summary: 'Some analysis' },
                ];
                context.notesList = [
                    { text: 'note one', concrete: false, updatedAt: 1 },
                ];
                const input = longEnough('# Summary\n\ncontent for save');
                // First save (any format): LLM is called.
                const r1 = await context.distillSummaryMarkdownWithLLM(input);
                expect(r1.status).toBe('ok');
                expect(llmCalls.length).toBe(1);
                // Simulate the post-save state where the distilled
                // entry has been pushed into compactedAnalysisSummaries.
                context.compactedAnalysisSummaries = [
                    { signature: '__distilled__', summary: r1.text },
                    { signature: 'ctx:1', summary: 'Some analysis' },
                ];
                // The next three saves — emulating text / html /
                // markdown / pdf — must all hit the cache. We re-use
                // the same input string for the call (the export-time
                // builder is responsible for formatting; the cache
                // decision is made before that step).
                const r2 = await context.distillSummaryMarkdownWithLLM(input);
                const r3 = await context.distillSummaryMarkdownWithLLM(input);
                const r4 = await context.distillSummaryMarkdownWithLLM(input);
                expect(r2.status).toBe('already_distilled');
                expect(r3.status).toBe('already_distilled');
                expect(r4.status).toBe('already_distilled');
                expect(llmCalls.length).toBe(1); // still only one LLM call
                // Every cache hit returns the same distilled text so
                // the analyst's exported file content is consistent
                // across formats.
                expect(r2.text).toBe(r1.text);
                expect(r3.text).toBe(r1.text);
                expect(r4.text).toBe(r1.text);
            });

            test('every save path routes through the cached distiller', () => {
                // Static check: both `saveSummaryFromContextMenu` (used
                // by text / html / markdown) and `saveSummaryAsPdf`
                // (used by the PDF header button) must await the same
                // `distillSummaryMarkdownWithLLM` function so the cache
                // state is shared across all four export formats.
                const contextMenuBody = extractFunctionBody(
                    'saveSummaryFromContextMenu',
                );
                const pdfBody = extractFunctionBody('saveSummaryAsPdf');
                expect(contextMenuBody).toContain('distillSummaryMarkdownWithLLM');
                expect(contextMenuBody).toMatch(
                    /await\s+distillSummaryMarkdownWithLLM\(/,
                );
                expect(pdfBody).toContain('distillSummaryMarkdownWithLLM');
                expect(pdfBody).toMatch(
                    /await\s+distillSummaryMarkdownWithLLM\(/,
                );
                // Both paths must surface the cache-hit status so the
                // analyst sees a positive "LLM not re-invoked" message
                // instead of a generic "export not distilled" warning.
                expect(contextMenuBody).toContain(
                    'SUMMARY_DISTILL_SKIP_ALREADY_DISTILLED',
                );
                expect(pdfBody).toContain(
                    'SUMMARY_DISTILL_SKIP_ALREADY_DISTILLED',
                );
            });
        });
    });

    describe('summary heading single-printing', () => {
        // The "PacketSnitch's Summary" heading must be printed EXACTLY
        // once at the top of the consolidated report — not once per
        // context-scoped entry, not once per export pass. The previous
        // behaviour embedded the heading inside
        // `normalizeSummaryMarkdownHeadings`, which was called per
        // entry, so multi-entry reports printed the heading repeatedly.
        const sourcePath = path.join(__dirname, '..', 'src/ui/main-frontend.js');
        const sourceText = fs.readFileSync(sourcePath, 'utf8');

        function extractFunctionBody(name) {
            const startToken = `function ${name}`;
            const startIndex = sourceText.indexOf(startToken);
            if (startIndex === -1) {
                return null;
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
            return null;
        }

        test('normalizeSummaryMarkdownHeadings no longer prepends the heading', () => {
            // The header must have been promoted to a helper that is
            // called only once at the top of the combined report.
            const body = extractFunctionBody('normalizeSummaryMarkdownHeadings');
            expect(body).toBeDefined();
            // The literal "PacketSnitch's Summary" must NOT appear inside
            // the body of normalizeSummaryMarkdownHeadings anymore.
            expect(body).not.toContain("PacketSnitch's Summary");
        });

        test('a prependSummaryHeading helper exists and adds the heading once', () => {
            const headerLine = sourceText.split('\n').find((line) =>
                line.includes('prependSummaryHeading'),
            );
            expect(headerLine).toBeDefined();
            expect(headerLine).toMatch(
                /^(async\s+)?function prependSummaryHeading/,
            );
            const body = extractFunctionBody('prependSummaryHeading');
            // The helper references the SUMMARY_HEADING constant and
            // guards against double-prepending when the body already
            // starts with the heading.
            expect(body).toContain('SUMMARY_HEADING');
            expect(body).toMatch(/startsWith/);
        });

        test('getSummaryMarkdownForExport prepends the heading exactly once', () => {
            const body = extractFunctionBody('getSummaryMarkdownForExport');
            expect(body).toContain('prependSummaryHeading');
            // Should call it exactly once.
            const calls = body.match(/prependSummaryHeading\(/g) || [];
            expect(calls.length).toBe(1);
        });

        test('renderSummaryMarkdownPreview prepends the heading exactly once', () => {
            const body = extractFunctionBody('renderSummaryMarkdownPreview');
            expect(body).toContain('prependSummaryHeading');
            const calls = body.match(/prependSummaryHeading\(/g) || [];
            expect(calls.length).toBe(1);
        });

        test('buildSummaryBodyHtmlForHtmlExport does not re-add the heading per entry', () => {
            // The HTML export renders each compacted entry individually.
            // We used to call normalizeSummaryMarkdownHeadings per entry
            // which would have re-added the heading per section. Verify
            // the current source does not embed the heading literal
            // inside the per-entry normalization path.
            const body = extractFunctionBody('buildSummaryBodyHtmlForHtmlExport');
            expect(body).toBeDefined();
            // The heading must not live inside the function body.
            expect(body).not.toContain("PacketSnitch's Summary");
        });
    });

    describe('no-op data squelch in LLM prompts', () => {
        // The LLM should be told to omit failed/empty decoders, parsers,
        // and lookups from the final report. Verify the four summary
        // prompts each carry the squelch instruction.
        const sourcePath = path.join(__dirname, '..', 'src/ui/main-frontend.js');
        const sourceText = fs.readFileSync(sourcePath, 'utf8');
        const summarizerPath = path.join(__dirname, '..', 'src/ui/panels/data-tools-llm-summarizer.js');
        const summarizerText = fs.readFileSync(summarizerPath, 'utf8');

        function extractFunctionBody(name, source = sourceText) {
            const startToken = `function ${name}`;
            const startIndex = source.indexOf(startToken);
            if (startIndex === -1) return null;
            const bodyStart = source.indexOf('{', startIndex);
            let depth = 0;
            for (let cursor = bodyStart; cursor < source.length; cursor += 1) {
                const char = source[cursor];
                if (char === '{') depth += 1;
                if (char === '}') {
                    depth -= 1;
                    if (depth === 0) {
                        return source.slice(startIndex, cursor + 1);
                    }
                }
            }
            return null;
        }

        test('distill prompt tells the LLM to squelch no-op data', () => {
            const body = extractFunctionBody('buildSummaryDistillPrompt');
            expect(body).toBeDefined();
            expect(body.toLowerCase()).toContain('squelch');
            expect(body.toLowerCase()).toContain('no-op');
        });

        test('compaction prompt tells the LLM to squelch no-op data', () => {
            // The compaction prompt lives inside runAnalysisCompaction
            // — we look at the full function body for the squelch phrase.
            const body = extractFunctionBody('runAnalysisCompaction');
            expect(body).toBeDefined();
            expect(body.toLowerCase()).toContain('squelch');
            expect(body.toLowerCase()).toContain('no-op');
        });

        test('writeSummaryFromLLM tells the LLM to squelch no-op data', () => {
            const body = extractFunctionBody('writeSummaryFromLLM');
            expect(body).toBeDefined();
            expect(body.toLowerCase()).toContain('squelch');
            expect(body.toLowerCase()).toContain('no-op');
        });

        test('data-tools LLM summarizer tells the LLM to squelch no-op data', () => {
            const body = extractFunctionBody('_buildDataToolsSummaryPrompt', summarizerText);
            expect(body).toBeDefined();
            expect(body.toLowerCase()).toContain('squelch');
            expect(body.toLowerCase()).toContain('no-op');
        });
    });

    describe('aggressive dedupe in summary LLM prompts', () => {
        // The distillation prompt (export-time dedupe + chronological sort)
        // and the compaction prompt (every analysis-compaction run) must
        // each explicitly tell the LLM to collapse duplicate facts so the
        // analyst never reads the same observation reworded over and over.
        // These tests pin down that wording so future tweaks can't
        // silently weaken the dedupe contract.
        const sourcePath = path.join(__dirname, '..', 'src/ui/main-frontend.js');
        const sourceText = fs.readFileSync(sourcePath, 'utf8');

        function extractFunctionBody(name, source = sourceText) {
            const startToken = `function ${name}`;
            const startIndex = source.indexOf(startToken);
            if (startIndex === -1) return null;
            const bodyStart = source.indexOf('{', startIndex);
            let depth = 0;
            for (let cursor = bodyStart; cursor < source.length; cursor += 1) {
                const char = source[cursor];
                if (char === '{') depth += 1;
                if (char === '}') {
                    depth -= 1;
                    if (depth === 0) {
                        return source.slice(startIndex, cursor + 1);
                    }
                }
            }
            return null;
        }

        test('distill prompt labels dedupe as the most important rule', () => {
            // The dedupe rule must be promoted to the #1 / most-important
            // rule in the distillation prompt so the LLM prioritises it
            // over chronological sort, section highlights, length, etc.
            const body = extractFunctionBody('buildSummaryDistillPrompt');
            expect(body).toBeDefined();
            // The literal "AGGRESSIVE DEDUPE" header must appear in the
            // prompt so the LLM knows to treat it as a top-level
            // distillation rule.
            expect(body).toContain('AGGRESSIVE DEDUPE');
            // The phrase "most important" must appear in the same rule
            // (next to AGGRESSIVE DEDUPE) so the LLM sees the priority.
            const dedupeRuleMatch = body.match(
                /\d+\.\s+AGGRESSIVE DEDUPE[\s\S]{0,500}?most important/i,
            );
            expect(dedupeRuleMatch).not.toBeNull();
        });

        test('distill prompt forbids reworded restatements of the same fact', () => {
            // The dedupe rule must explicitly tell the LLM that a
            // reworded duplicate is still a duplicate and must be
            // deleted, not kept as a "different wording".
            const body = extractFunctionBody('buildSummaryDistillPrompt');
            expect(body).toBeDefined();
            const lower = body.toLowerCase();
            // Must mention rewording / rephrasing and forbid it.
            expect(lower).toContain('reword');
            // Must instruct the LLM to drop the redundant restatement.
            expect(lower).toMatch(/drop the (rest|redundant|restatement)/);
            // Must forbid keeping both copies of a duplicated fact.
            expect(lower).toContain('keep it once');
        });

        test('distill prompt resolves Capture Statistics vs LLM-blurb overlap', () => {
            // When the same fact is summarised at a high level in the
            // Capture Statistics section AND described in an LLM blurb,
            // the prompt must tell the LLM which copy to drop.
            const body = extractFunctionBody('buildSummaryDistillPrompt');
            expect(body).toBeDefined();
            const lower = body.toLowerCase();
            // Must mention the Capture Statistics section by name.
            expect(lower).toContain('capture statistics');
            // Must tell the LLM the per-stream / blurb version is the
            // more detailed one to keep.
            expect(lower).toContain('more detailed');
            // Must tell the LLM the Capture Statistics section should
            // only carry facts that don't appear elsewhere.
            expect(lower).toMatch(
                /capture statistics[\s\S]{0,500}?do not appear elsewhere/,
            );
        });

        test('compaction prompt carries an explicit DEDUPLICATE rule', () => {
            // Every compaction run must remind the LLM to dedupe
            // (a) within the previously compacted summary and
            // (b) across the new blurbs, so repeated facts don't
            // accumulate as more blurbs are folded in.
            const body = extractFunctionBody('runAnalysisCompaction');
            expect(body).toBeDefined();
            const lower = body.toLowerCase();
            // The literal "DEDUPLICATE" rule label must be present.
            expect(lower).toContain('deduplicate');
            // Must explicitly cover both the previously compacted
            // summary and the new blurbs.
            expect(lower).toMatch(
                /deduplicate[\s\S]{0,500}?(previously compacted|new blurbs)/,
            );
            // Must forbid the LLM from rewording a fact that is
            // already present in the running summary.
            expect(lower).toContain('reword');
        });

        test('per-stream LLM prompt (writeSummaryFromLLM) carries a DEDUPLICATE rule', () => {
            // The first blub-generation prompt must also tell the LLM
            // not to reword the same fact twice within a single blurb
            // (so the blurbs that feed compaction are already deduped
            // before they ever reach runAnalysisCompaction).
            const body = extractFunctionBody('writeSummaryFromLLM');
            expect(body).toBeDefined();
            const lower = body.toLowerCase();
            expect(lower).toContain('deduplicate');
            expect(lower).toContain('reword');
            // The prompt's "have already described" clause must also
            // forbid rephrasing a fact the LLM already described in
            // a previous turn.
            expect(lower).toMatch(
                /have already described[\s\S]{0,300}?do not reword/,
            );
            // The closing sentence must explicitly forbid rephrasing a
            // fact that is already in the running summary.
            expect(lower).toContain('never rephrase');
        });
    });
});
