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
            // export flow can call it.
            const headerLine = sourceText.split('\n').find((line) =>
                line.includes('distillSummaryMarkdownWithLLM'),
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
    });
});
