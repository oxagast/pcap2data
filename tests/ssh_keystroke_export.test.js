// Tests for the OpenSSH keystroke-timing export helpers in
// src/ui/decoders/ssh-keystrokes/export/index.js. The export is a pure
// function so these tests don't touch the DOM, the IPC bridge, or
// Electron — they only assert on the rendered text.

const {
    buildSshKeystrokeExport,
    buildSshTimingAnalysisBrief,
    computeShapeSignature,
    renderShapeSignature,
    summarizeS2cOutput,
    buildShellCommandPriors,
    renderShellPriors,
    hexToUint8Array,
    extractPacketBytes,
    computeShellOutputCharDistribution,
    renderShellOutputCharDistribution,
    buildSessionTurnPairs,
    renderSessionTurnPairs,
    detectReturnKeys,
    renderReturnKeys,
    renderReturnKeySummary,
    computeRawVsPeeledIidStats,
    renderRawVsPeeledIid,
    computeFlowPacketProfile,
    renderFlowPacketProfile,
    applyDeobfuscatorMode,
    REDACTION_AAA_LENGTH_TOLERANCE,
    BRIEF_MIN_SAMPLES,
    S2C_MIN_PACKETS,
    computeDelayStats,
    formatNumber,
    wrapText,
    directionLabel,
} = require("../src/ui/decoders/ssh-keystrokes/export");

const FIXED_NOW = new Date("2026-08-13T16:45:00.000Z");

function makeFlow(overrides) {
    return Object.assign(
        {
            srcIp: "10.0.2.3",
            srcPort: 60950,
            dstIp: "10.0.2.20",
            dstPort: 22,
            host: "10.0.2.20",
            packets: [{ ts: 1 }, { ts: 2 }, { ts: 3 }, { ts: 4 }],
            firstTimestamp: 1700000000000,
            lastTimestamp: 1700000030000, // 30 s span
            c2sPacketCount: 0,
            s2cPacketCount: 0,
        },
        overrides,
    );
}

describe("SSH keystroke export — pure helpers", () => {
    describe("directionLabel", () => {
        test("c2s renders the client → server arrow", () => {
            expect(directionLabel("c2s")).toBe("client \u2192 server");
        });
        test("s2c renders the server → client arrow", () => {
            expect(directionLabel("s2c")).toBe("server \u2192 client");
        });
        test("both renders the bidirectional arrow", () => {
            expect(directionLabel("both")).toBe("client \u2194 server (both directions)");
        });
        test("unknown values default to the bidirectional arrow", () => {
            expect(directionLabel(undefined)).toBe("client \u2194 server (both directions)");
            expect(directionLabel("nonsense")).toBe("client \u2194 server (both directions)");
        });
    });

    describe("formatNumber", () => {
        test("renders non-finite as em-dash", () => {
            expect(formatNumber(NaN)).toBe("\u2014");
            expect(formatNumber(Infinity)).toBe("\u2014");
            expect(formatNumber(undefined)).toBe("\u2014");
        });
        test("uses 3 decimals for small magnitudes", () => {
            expect(formatNumber(0.123)).toBe("0.123");
            expect(formatNumber(7.89)).toBe("7.890");
        });
        test("uses 2 decimals for mid magnitudes", () => {
            expect(formatNumber(84.5)).toBe("84.50");
            expect(formatNumber(123)).toBe("123.00");
        });
        test("uses 1 decimal for large magnitudes", () => {
            expect(formatNumber(1234.5)).toBe("1234.5");
            expect(formatNumber(-5000.4)).toBe("-5000.4");
        });
    });

    describe("computeDelayStats", () => {
        test("empty input returns NaN/zero stats", () => {
            expect(computeDelayStats([])).toEqual({
                min: NaN, max: NaN, mean: NaN, median: NaN, stddev: NaN,
                p90: NaN, p99: NaN, burstCount: 0, pauseCount: 0,
            });
        });
        test("basic aggregate stats match expected values", () => {
            const stats = computeDelayStats([10, 20, 30, 40, 50]);
            expect(stats.min).toBe(10);
            expect(stats.max).toBe(50);
            expect(stats.mean).toBeCloseTo(30, 5);
            expect(stats.median).toBe(30);
            expect(stats.stddev).toBeCloseTo(Math.sqrt(200), 5);
            // floor(0.9 * 4) = 3 → sorted[3] = 40
            expect(stats.p90).toBe(40);
            // floor(0.99 * 4) = 3 → sorted[3] = 40
            expect(stats.p99).toBe(40);
        });
        test("bursts/pauses use the 30ms/500ms thresholds", () => {
            const stats = computeDelayStats([5, 25, 29, 100, 501, 750, 1200]);
            expect(stats.burstCount).toBe(3); // 5, 25, 29
            expect(stats.pauseCount).toBe(3); // 501, 750, 1200
        });
        test("ignores non-finite samples", () => {
            const stats = computeDelayStats([10, NaN, 30, Infinity, 50]);
            expect(stats.min).toBe(10);
            expect(stats.max).toBe(50);
            expect(stats.mean).toBeCloseTo(30, 5);
        });
        test("does not mutate the input array", () => {
            const input = [50, 10, 30, 20, 40];
            const snapshot = input.slice();
            computeDelayStats(input);
            expect(input).toEqual(snapshot);
        });
    });

    describe("wrapText", () => {
        test("returns empty string for empty input", () => {
            expect(wrapText("", 80)).toBe("");
            expect(wrapText(null, 80)).toBe("");
        });
        test("wraps a long single-paragraph string", () => {
            const long = "word ".repeat(50).trim();
            const out = wrapText(long, 30);
            const lines = out.split("\n");
            for (const line of lines) {
                expect(line.length).toBeLessThanOrEqual(30);
            }
            // No trailing blank line beyond the body's final '\n'.
            expect(out.endsWith("\n")).toBe(false);
        });
        test("preserves paragraph breaks", () => {
            const out = wrapText("First paragraph here.\n\nSecond paragraph follows.", 80);
            expect(out).toContain("First paragraph here.\n");
            expect(out).toContain("\nSecond paragraph follows.");
        });
    });

    describe("applyDeobfuscatorMode", () => {
        function makePaddingResult(overrides) {
            return Object.assign(
                {
                    detected: false,
                    periodMs: null,
                    coverage: 0,
                    residualStdMs: NaN,
                    dominantResidueMs: NaN,
                    snappedDelaysMs: null,
                    keystrokeDelaysMs: null,
                    paddedIntervals: null,
                    candidateScores: [],
                },
                overrides || {},
            );
        }
        test('"off" mode forces detected=false and clears peel artefacts', () => {
            const r = makePaddingResult({
                detected: true,
                periodMs: 20,
                coverage: 0.8,
                keystrokeDelaysMs: [100, 120, 110],
                snappedDelaysMs: [3, -2, 7],
                paddedIntervals: [1, 4],
            });
            const out = applyDeobfuscatorMode(r, [], { enabled: true, mode: "off" });
            expect(out.detected).toBe(false);
            expect(out.keystrokeDelaysMs).toBeNull();
            expect(out.snappedDelaysMs).toBeNull();
        });
        test("enabled=false behaves like off", () => {
            const r = makePaddingResult({
                detected: true,
                periodMs: 20,
                coverage: 0.7,
                keystrokeDelaysMs: [50],
                snappedDelaysMs: [2],
            });
            const out = applyDeobfuscatorMode(r, [], { enabled: false, mode: "auto" });
            expect(out.detected).toBe(false);
            expect(out.keystrokeDelaysMs).toBeNull();
        });
        test('"auto" with a confident detection leaves the result untouched', () => {
            const r = makePaddingResult({
                detected: true,
                periodMs: 20,
                coverage: 0.9,
                keystrokeDelaysMs: [101, 102, 103],
                snappedDelaysMs: [1, 2, 3],
                paddedIntervals: [0, 1],
            });
            const out = applyDeobfuscatorMode(r, [20, 21, 101, 102, 103], {
                enabled: true,
                mode: "auto",
            });
            expect(out.detected).toBe(true);
            expect(out.periodMs).toBe(20);
            expect(out.keystrokeDelaysMs).toEqual([101, 102, 103]);
            expect(out.snappedDelaysMs).toEqual([1, 2, 3]);
        });
        test('"force" with no detection snaps using the best candidate', () => {
            // Build a delay array dominated by 20ms intervals (with some
            // noise) plus a few non-cadence real keystroke intervals.
            const filler = [21, 19, 20, 22, 19, 20, 18, 21, 19, 20];
            const real = [180, 145, 200, 165];
            const delays = filler.concat(real);
            const r = makePaddingResult({
                candidateScores: [
                    {
                        periodMs: 20,
                        coverage: 0.6,
                        residualStdMs: 1.4,
                    },
                ],
            });
            const out = applyDeobfuscatorMode(r, delays, {
                enabled: true,
                mode: "force",
            });
            expect(out.detected).toBe(true);
            expect(out.periodMs).toBe(20);
            expect(out.forcedFromCandidate).toBe(true);
            // snappedDelaysMs preserves interval count; all ~20ms inputs
            // should become near-zero residues.
            expect(out.snappedDelaysMs.length).toBe(delays.length);
            for (let i = 0; i < filler.length; i += 1) {
                expect(Math.abs(out.snappedDelaysMs[i])).toBeLessThanOrEqual(2);
            }
            // keystrokeDelaysMs drops the filler intervals.
            expect(out.keystrokeDelaysMs.length).toBe(real.length);
            for (const v of out.keystrokeDelaysMs) {
                expect(Math.abs(v - filler[0])).toBeGreaterThan(10);
            }
            // paddedIntervals matches the dropped count.
            expect(out.paddedIntervals.length).toBe(filler.length);
        });
        test('"force" with no candidates leaves the result undetected', () => {
            const r = makePaddingResult({ candidateScores: [] });
            const out = applyDeobfuscatorMode(r, [100, 200, 300], {
                enabled: true,
                mode: "force",
            });
            expect(out.detected).toBe(false);
            expect(out.keystrokeDelaysMs).toBeNull();
        });
        test("passes through when settings is undefined", () => {
            const r = makePaddingResult({ detected: true, periodMs: 20, coverage: 0.5 });
            const out = applyDeobfuscatorMode(r, [], undefined);
            // Default mode is "auto", confident detection is honoured.
            expect(out.detected).toBe(true);
        });
        test("tolerates null paddingResult", () => {
            const out = applyDeobfuscatorMode(null, [1, 2, 3], {
                enabled: true,
                mode: "off",
            });
            expect(out.detected).toBe(false);
            expect(Array.isArray(out.candidateScores)).toBe(true);
        });
    });
});

describe("SSH keystroke export — buildSshKeystrokeExport", () => {
    const baseState = () => ({
        flow: makeFlow(),
        model: { layout: "qwerty" },
        direction: "c2s",
        delays: [80, 110, 95, 25, 600, 88, 92],
        delaysWithIdx: [
            { delay: 80, index: 2, packetLength: 48 },
            { delay: 110, index: 3, packetLength: 32 },
            { delay: 95, index: 4, packetLength: 32 },
            { delay: 25, index: 5, packetLength: 32 },
            { delay: 600, index: 6, packetLength: 32 },
            { delay: 88, index: 7, packetLength: 32 },
            { delay: 92, index: 8, packetLength: 32 },
        ],
        candidates: [
            { text: "cat /etc/passwd", logProb: -128.4, combinedScore: 0.62 },
            { text: "vim /etc/hosts", logProb: -134.0, combinedScore: 0.21, llmIsCommand: true },
        ],
        primary: {
            text: "cat /etc/passwd",
            confidence: 0.62,
            kind: "command",
            isCommand: true,
            rationale: "Matches the decoder's top hypothesis under shell priors.",
        },
        insight: {
            text: "Strong match for a defensive read of the local passwd file. Verify the actor before sharing.",
            source: "decoder + LLM",
        },
        estimatedCommandLength: 17,
        backspaceHints: [3, 4],
    });

    test("includes the canonical header lines", () => {
        const text = buildSshKeystrokeExport(baseState(), { now: () => FIXED_NOW });
        expect(text).toContain("# OpenSSH keystroke-timing trace");
        expect(text).toContain("# Generated by PacketSnitch at 2026-08-13T16:45:00.000Z");
        expect(text).toContain("# Flow: 10.0.2.3:60950 \u2192 10.0.2.20:22 (client \u2192 server)");
        expect(text).toContain("# Packets: 4  \u2022  Inter-key delays: 7  \u2022  Direction: c2s");
        expect(text).toContain("# Flow span: 30.000 s");
    });

    test("CSV section has the expected header + every delay row", () => {
        const text = buildSshKeystrokeExport(baseState(), { now: () => FIXED_NOW });
        expect(text).toContain("keystroke_index,delay_ms,packet_index,packet_length");
        expect(text).toContain("1,80.00,2,48");
        expect(text).toContain("5,600.00,6,32");
        expect(text).toContain("(7 rows)");
    });

    test("summary block lists aggregate stats", () => {
        const text = buildSshKeystrokeExport(baseState(), { now: () => FIXED_NOW });
        expect(text).toContain("## Summary");
        expect(text).toContain("- Total delays: 7");
        expect(text).toContain("- Bursts (<30 ms): 1");
        expect(text).toContain("- Thinking pauses (>500 ms): 1");
        expect(text).toContain("- Estimated command length (chars): 17");
        expect(text).toContain("- Backspace hints (count): 2");
    });

    test("candidates block quotes each candidate with logP/combinedScore", () => {
        const text = buildSshKeystrokeExport(baseState(), { now: () => FIXED_NOW });
        expect(text).toContain("## Top decoded candidates");
        expect(text).toContain('1. "cat /etc/passwd"  (logP=-128.40, combined=0.620)');
        expect(text).toContain('2. "vim /etc/hosts"  (logP=-134.00, combined=0.210) [cmd?]');
    });

    test("LLM primary block reports the best guess", () => {
        const text = buildSshKeystrokeExport(baseState(), { now: () => FIXED_NOW });
        expect(text).toContain("## LLM best guess");
        expect(text).toContain('Text: "cat /etc/passwd"');
        expect(text).toContain("Confidence: 62.0%");
        expect(text).toContain("Kind: command");
        expect(text).toContain("Looks like a shell command: yes");
        expect(text).toContain("Rationale: Matches the decoder's top hypothesis under shell priors.");
    });

    test("LLM analyst insight is word-wrapped to ~80 columns", () => {
        const insightState = baseState();
        insightState.insight = {
            text: "Long insight " + "word ".repeat(40) + "tail.",
        };
        const text = buildSshKeystrokeExport(insightState, { now: () => FIXED_NOW });
        // Pull the insight block by looking at lines after the insight
        // header and stopping at the next '## ' section header (the
        // section is followed by padding/raw-vs-peeled/etc. now, so
        // we can't use a fixed terminator like '## Notes').
        const after = text.split("## LLM analyst insight")[1] || "";
        const block = after.split(/\n## /)[0] || "";
        for (const line of block.split("\n")) {
            if (line.length === 0) continue;
            expect(line.length).toBeLessThanOrEqual(80);
        }
    });

    test("omits the LLM primary block when no primary is provided", () => {
        const state = baseState();
        state.primary = null;
        const text = buildSshKeystrokeExport(state, { now: () => FIXED_NOW });
        expect(text).not.toContain("## LLM best guess");
    });

    test("omits the insight block when no insight is provided", () => {
        const state = baseState();
        state.insight = null;
        const text = buildSshKeystrokeExport(state, { now: () => FIXED_NOW });
        expect(text).not.toContain("## LLM analyst insight");
    });

    test("falls back to plain delays when delaysWithIdx is missing", () => {
        const state = baseState();
        state.delaysWithIdx = [];
        const text = buildSshKeystrokeExport(state, { now: () => FIXED_NOW });
        expect(text).toContain("keystroke_index,delay_ms,packet_index,packet_length");
        expect(text).toContain("1,80.00,0,");
        expect(text).toContain("(7 rows)");
    });

    test("missing flow produces a sensible 'unknown' header without crashing", () => {
        const state = baseState();
        state.flow = null;
        const text = buildSshKeystrokeExport(state, { now: () => FIXED_NOW });
        expect(text).toContain("# Flow: unknown");
        expect(text).toContain("keystroke_index,delay_ms,packet_index,packet_length");
        expect(text).toContain("(7 rows)");
    });

    test("ends with a single trailing newline", () => {
        const text = buildSshKeystrokeExport(baseState(), { now: () => FIXED_NOW });
        expect(text.endsWith("\n")).toBe(true);
        expect(text.endsWith("\n\n")).toBe(false);
    });

    test("includes keyboard layout in the notes section when model provides it", () => {
        const text = buildSshKeystrokeExport(baseState(), { now: () => FIXED_NOW });
        expect(text).toContain("Keyboard layout used: qwerty");
    });

    test("renders a Padding detection section when the cadence is detected", () => {
        const state = baseState();
        state.paddingDetection = {
            detected: true,
            periodMs: 20,
            coverage: 0.85,
            residualStdMs: 1.4,
            dominantResidueMs: 1,
            candidateScores: [
                { periodMs: 20, coverage: 0.85, residualStdMs: 1.4 },
                { periodMs: 40, coverage: 0.42, residualStdMs: 5.2 },
            ],
        };
        const text = buildSshKeystrokeExport(state, { now: () => FIXED_NOW });
        expect(text).toContain("## Padding detection");
        expect(text).toContain("20 ms cadence");
        expect(text).toContain("coverage 85.0%");
        expect(text).toContain("Candidate periods:");
        expect(text).toContain("20 ms: coverage 85.0%");
    });

    test("renders a no-detection Padding section when scores were provided but detection was off", () => {
        const state = baseState();
        state.paddingDetection = {
            detected: false,
            periodMs: null,
            coverage: 0.32,
            residualStdMs: 4.4,
            candidateScores: [
                { periodMs: 20, coverage: 0.32, residualStdMs: 4.4 },
                { periodMs: 40, coverage: 0.18, residualStdMs: 6.1 },
            ],
        };
        const text = buildSshKeystrokeExport(state, { now: () => FIXED_NOW });
        expect(text).toContain("## Padding detection");
        expect(text).toContain("No fixed-cadence padding detected");
        expect(text).toContain("20 ms: coverage 32.0%");
    });

    test("omits the Padding detection section when no padding data is provided", () => {
        const text = buildSshKeystrokeExport(baseState(), { now: () => FIXED_NOW });
        expect(text).not.toContain("## Padding detection");
    });
});

// Helper: synthesise a realistic-looking delay series that's comfortably
// above the brief's minimum sample count. Includes a mix of within-word
// bursts, ordinary typing, and a few thinking pauses so the burst/pause
// sections of the brief are populated.
function makeBriefDelays(count) {
    const out = [];
    let i = 0;
    while (out.length < count) {
        // A short word's worth of bursts.
        for (let j = 0; j < 6 && out.length < count; j += 1) {
            out.push(40 + ((i + j) % 10));
        }
        // A couple of normal cadence samples.
        if (out.length < count) out.push(120 + ((i * 7) % 30));
        if (out.length < count) out.push(160 + ((i * 11) % 25));
        // Occasional long pause (command boundary).
        if (i % 4 === 0 && out.length < count) out.push(620 + ((i * 13) % 80));
        i += 1;
    }
    return out;
}

function makeBriefState(overrides) {
    const state = {
        flow: makeFlow(),
        model: { layout: "qwerty", alphabet: "abc " },
        direction: "c2s",
        delays: makeBriefDelays(BRIEF_MIN_SAMPLES),
        candidates: [
            { text: "git status", logProb: -42.5, combinedScore: 0.81, llmIsCommand: true },
            { text: "ls -la", logProb: -55.0, combinedScore: 0.62, llmIsCommand: true },
        ],
        paddingDetection: { detected: false, periodMs: null, coverage: 0 },
    };
    return Object.assign(state, overrides || {});
}

describe("buildSshTimingAnalysisBrief", () => {
    test("returns ok=false with reason='too_few_samples' when below the minimum", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState({ delays: [100, 110, 90] }));
        expect(brief.ok).toBe(false);
        expect(brief.reason).toBe("too_few_samples");
        expect(brief.sampleCount).toBe(3);
        expect(brief.minSamples).toBe(BRIEF_MIN_SAMPLES);
        expect(brief.text).toBeUndefined();
    });

    test("respects a custom minSamples override", () => {
        const delays = [80, 120, 140, 160, 180]; // 5 samples
        const brief = buildSshTimingAnalysisBrief(makeBriefState({ delays }), { minSamples: 5 });
        expect(brief.ok).toBe(true);
        const tooSmall = buildSshTimingAnalysisBrief(makeBriefState({ delays }), { minSamples: 6 });
        expect(tooSmall.ok).toBe(false);
        expect(tooSmall.reason).toBe("too_few_samples");
    });

    test("returns a populated brief when the sample is large enough", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        expect(brief.ok).toBe(true);
        expect(typeof brief.text).toBe("string");
        expect(brief.text.length).toBeGreaterThan(200);
        expect(brief.sampleCount).toBeGreaterThanOrEqual(BRIEF_MIN_SAMPLES);
        expect(brief.truncated).toBe(false);
    });

    test("includes aggregate timing statistics", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        expect(brief.text).toContain("## Aggregate timing statistics");
        expect(brief.text).toContain("Samples:");
        expect(brief.text).toContain("Median inter-key delay:");
        expect(brief.text).toContain("Std-dev:");
        expect(brief.text).toContain("90th percentile:");
        expect(brief.text).toContain("Bursts (<30 ms):");
        expect(brief.text).toContain("Thinking pauses (>500 ms):");
    });

    test("includes burst and pause sections grounded in the delays", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        // Sections always render, even when the underlying lists are
        // empty (in which case the body is the literal "- none").
        expect(brief.text).toContain("## Most prominent bursts (<30 ms) — within-word typing");
        expect(brief.text).toContain("## Most prominent pauses (>500 ms) — likely command boundaries");
        // Our synth seeds >=620ms pauses, so the pauses section must
        // contain at least one real number rather than the "- none"
        // fallback.
        const pausesSection = brief.text.split(
            "## Most prominent pauses (>500 ms) — likely command boundaries",
        )[1].split("## ")[0];
        expect(pausesSection).not.toContain("- none");
    });

    test("lists a sampled head and tail of the delays", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        expect(brief.text).toMatch(/## Sampled inter-key delays/);
        expect(brief.text).toMatch(/- head: \d+/);
        expect(brief.text).toMatch(/- tail: \d+/);
    });

    test("includes the decoder's top candidates in the brief", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        expect(brief.text).toContain("## Local Viterbi decoder candidates");
        expect(brief.text).toContain('"git status"');
        expect(brief.text).toContain('"ls -la"');
        expect(brief.text).toContain("logP=");
    });

    test("omits padding-detection notes when paddingDetection.detected is false", () => {
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({ paddingDetection: { detected: false, periodMs: null, coverage: 0 } }),
            { maxSamples: 200 },
        );
        expect(brief.text).not.toContain("## Padding detection");
        expect(brief.text).not.toContain("Detected 20 ms cadence");
    });

    test("includes a padding summary when paddingDetection.detected is true", () => {
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({
                paddingDetection: { detected: true, periodMs: 20, coverage: 0.7, residualStdMs: 2.5 },
            }),
            { maxSamples: 200 },
        );
        expect(brief.text).toContain("## Padding detection");
        expect(brief.text).toContain("20 ms cadence");
        expect(brief.text).toContain("70%");
        // The brief must explicitly tell the model that the delays
        // shown above are post-peeling residuals, not raw — this is
        // critical for the LLM to avoid misinterpreting residual
        // jitter as a sub-cadence clock or burst structure.
        expect(brief.text).toContain("ALREADY been peeled by the local detector");
        expect(brief.text).toContain("Treat any residual sub-cadence jitter as noise");
    });

    test("includes the previous LLM primary guess when round-tripping", () => {
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({
                primary: {
                    text: "git status",
                    confidence: 0.72,
                    kind: "command",
                    rationale: "matches Viterbi top hit",
                },
            }),
            { maxSamples: 200 },
        );
        expect(brief.text).toContain("## Previous LLM best guess");
        expect(brief.text).toContain('"git status"');
        expect(brief.text).toContain("72.0%");
    });

    test("truncates the per-delay lists when maxSamples is exceeded", () => {
        const big = makeBriefDelays(150);
        const brief = buildSshTimingAnalysisBrief(makeBriefState({ delays: big }), { maxSamples: 50 });
        expect(brief.ok).toBe(true);
        expect(brief.truncated).toBe(true);
        expect(brief.truncatedDropped).toBe(100);
        expect(brief.text).toContain("truncated to 50");
        expect(brief.text).toContain("100 dropped");
    });

    test("handles delays containing non-finite or non-positive entries", () => {
        // Mix of valid + non-finite values; pad with enough valid samples
        // so the brief still produces a summary. The non-finite entries
        // must be filtered before the threshold check.
        const delays = [60, 70, 0, -1, NaN, Infinity, 80, 90, 100, 110, 120, 130];
        while (delays.length < BRIEF_MIN_SAMPLES + 5) delays.push(75 + (delays.length % 5));
        const brief = buildSshTimingAnalysisBrief(makeBriefState({ delays }), { maxSamples: 200 });
        expect(brief.ok).toBe(true);
        // Median should be based only on the positive finite subset.
        expect(brief.text).toMatch(/Median inter-key delay: \d+\.\d+ ms/);
    });

    test("counts only positive finite delays toward the threshold", () => {
        const delays = [60, 70, 0, -1, NaN, Infinity];
        while (delays.length < BRIEF_MIN_SAMPLES) delays.push(75);
        const brief = buildSshTimingAnalysisBrief(makeBriefState({ delays }), { maxSamples: 200 });
        // After filtering, only the padded 75ms entries remain (24 of
        // them), below BRIEF_MIN_SAMPLES — the brief must refuse.
        expect(brief.ok).toBe(false);
        expect(brief.reason).toBe("too_few_samples");
    });

    test("renders direction and layout from the state", () => {
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({ direction: "s2c", model: { layout: "dvorak", alphabet: "abc" } }),
            { maxSamples: 200 },
        );
        expect(brief.text).toContain("Keyboard layout: dvorak");
        expect(brief.text).toContain("Decoder alphabet (3 chars): abc");
        expect(brief.text).toMatch(/Direction: s2c/);
    });

    test("decoder alphabet line is absent when no alphabet is provided", () => {
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({ model: { layout: "qwerty" } }),
            { maxSamples: 200 },
        );
        expect(brief.text).toContain("Keyboard layout: qwerty");
        // The data line says "Decoder alphabet (N chars): ...". When no
        // alphabet was provided to the brief, that data line is
        // omitted (the LEGEND entry still mentions "Decoder alphabet"
        // by name).
        expect(brief.text).not.toMatch(/^# Decoder alphabet \(\d+ chars\)/m);
    });

    test("LEGEND block describes the decoder alphabet field", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        expect(brief.ok).toBe(true);
        const legendIdx = brief.text.indexOf("# LEGEND");
        expect(legendIdx).toBeGreaterThan(0);
        const tail = brief.text.slice(legendIdx);
        expect(tail).toMatch(/Decoder alphabet|alphabet/);
    });

    test("returns a string with a single trailing newline", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        expect(brief.text.endsWith("\n")).toBe(true);
        expect(brief.text.endsWith("\n\n")).toBe(false);
    });

    test("declares BRIEF_MIN_SAMPLES as 30 by default", () => {
        expect(BRIEF_MIN_SAMPLES).toBe(30);
    });

    test("includes a Server output section when state.s2cSummary is provided (ok)", () => {
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({
                s2cSummary: {
                    ok: true,
                    summaryText: "# Server output (s2c) summary\n# 42 s2c packets, 2 chunk(s)\n## Output chunks\n- chunk 1: 1100 B in 22.00 s — rate 50.00 char/s — kind: paged-file-content",
                },
            }),
            { maxSamples: 200 },
        );
        expect(brief.text).toContain("## Server output (s2c) summary");
        expect(brief.text).toContain("chunk 1: 1100 B");
        expect(brief.text).toContain("paged-file-content");
    });

    test("renders the s2c 'not available' reason when no s2c packets exist", () => {
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({
                s2cSummary: { ok: false, reason: "no_s2c_packets" },
            }),
            { maxSamples: 200 },
        );
        expect(brief.text).toContain("## Server output (s2c) summary");
        expect(brief.text).toContain("- not available: no_s2c_packets");
        expect(brief.text).toContain("only the typed-side timing is available");
    });

    test("renders the s2c too-few-packets reason with counts", () => {
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({
                s2cSummary: { ok: false, reason: "too_few_s2c_packets", sampleCount: 2, minSamples: 4 },
            }),
            { maxSamples: 200 },
        );
        expect(brief.text).toContain("not available: too_few_s2c_packets");
        expect(brief.text).toContain("only 2 s2c packet(s) available (need 4)");
    });

    test("omits the s2c section entirely when no s2cSummary is provided", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        expect(brief.text).not.toContain("## Server output (s2c) summary");
    });

    test("includes the LEGEND block as the very first content", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        // The legend must appear BEFORE any data sections so the LLM
        // reads the metric definitions first.
        const legendIdx = brief.text.indexOf("LEGEND");
        const headerIdx = brief.text.indexOf("SSH Session: Keystroke Timing Analysis Brief");
        const statsIdx = brief.text.indexOf("## Aggregate timing statistics");
        expect(legendIdx).toBeGreaterThan(-1);
        expect(headerIdx).toBeGreaterThan(legendIdx);
        expect(statsIdx).toBeGreaterThan(legendIdx);
    });

    test("legend defines every pause-bucket boundary the brief uses", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        // The legend must define the same thresholds the pause classifier
        // uses internally (Bursts<30, Within<200, Short-thinking<500,
        // Command-bound<2000, Idle>=2000). If these drift in the future
        // the test will catch the mismatch.
        expect(brief.text).toContain("< 30 ms");
        expect(brief.text).toContain("30-200 ms");
        expect(brief.text).toContain("200-500 ms");
        expect(brief.text).toContain("500-2000 ms");
        expect(brief.text).toContain("> 2000 ms");
    });

    test("legend defines CV (coefficient of variation) and typing-mode labels", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        expect(brief.text).toContain("Coefficient of variation");
        expect(brief.text).toContain("paste-or-script");
        expect(brief.text).toContain("natural-typing");
    });

    test("legend defines s2c chunk-kind classifications", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        expect(brief.text).toContain("paged-file-content");
        expect(brief.text).toContain("large-file-dump");
        expect(brief.text).toContain("short-status-output");
        expect(brief.text).toContain("dynamic-output");
        expect(brief.text).toContain("prompt-or-echo");
    });

    test("legend explains the Viterbi logP/combined/[cmd?] candidate columns", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        expect(brief.text).toContain("logP");
        expect(brief.text).toContain("combined");
        expect(brief.text).toContain("[cmd?]");
    });

    test("legend warns that c2s delays are post-peeling residuals when obfuscation is active", () => {
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({
                paddingDetection: { detected: true, periodMs: 20, coverage: 0.7, residualStdMs: 2.5 },
            }),
            { maxSamples: 200 },
        );
        // The legend's padding section must be present regardless of
        // whether padding was detected (it's a general explanation).
        expect(brief.text).toContain("Padding detection (SSH server-side timing obfuscation)");
        expect(brief.text).toContain("ALREADY been peeled");
    });
});

// ── summarizeS2cOutput tests ─────────────────────────────────────────
//
// We synthesise minimal `flow.packets`-shaped objects: each packet has
// direction, timestamp, and a nested packet["packet.info"]["packet.length"]
// (mirroring the renderer's getPacketInfo helper). Tests exercise the
// chunking, rate computation, and the rejection paths.

function s2cPacket(ts, bytes, opts) {
    const o = opts || {};
    const direction = o.direction || "s2c";
    const pkt = {
        direction,
        timestamp: ts,
        packet: {
            "packet.info": bytes > 0 ? { "packet.length": bytes } : {},
        },
    };
    return pkt;
}

describe("summarizeS2cOutput", () => {
    test("returns ok=false with reason='no_packets' on empty input", () => {
        const out = summarizeS2cOutput([]);
        expect(out.ok).toBe(false);
        expect(out.reason).toBe("no_packets");
    });

    test("returns ok=false with reason='no_s2c_packets' when only c2s packets exist", () => {
        const pkts = [
            s2cPacket(1000, 32, { direction: "c2s" }),
            s2cPacket(1100, 36, { direction: "c2s" }),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.ok).toBe(false);
        expect(out.reason).toBe("no_s2c_packets");
    });

    test("returns ok=false with reason='too_few_s2c_packets' below the minimum", () => {
        const pkts = [
            s2cPacket(1000, 200),
            s2cPacket(1050, 200),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.ok).toBe(false);
        expect(out.reason).toBe("too_few_s2c_packets");
        expect(out.sampleCount).toBe(2);
        expect(out.minSamples).toBe(S2C_MIN_PACKETS);
    });

    test("groups adjacent packets into a single chunk", () => {
        // 4 packets, all <50 ms apart → 1 chunk.
        const pkts = [
            s2cPacket(1000, 500),
            s2cPacket(1020, 500),
            s2cPacket(1040, 500),
            s2cPacket(1060, 500),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.ok).toBe(true);
        expect(out.totalChunks).toBe(1);
        expect(out.totalBytes).toBe(2000);
        expect(out.totalS2cPackets).toBe(4);
        expect(out.chunks[0].packetCount).toBe(4);
    });

    test("splits packets into chunks when inter-arrival gap exceeds threshold", () => {
        // Default chunkGapMs is 8000 ms. Force a split with a 10 s gap.
        const pkts = [
            s2cPacket(1000, 500),
            s2cPacket(1020, 500),
            s2cPacket(12000, 500), // 10980 ms gap from prev → new chunk
            s2cPacket(12020, 500),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.ok).toBe(true);
        expect(out.totalChunks).toBe(2);
        expect(out.chunks[0].packetCount).toBe(2);
        expect(out.chunks[1].packetCount).toBe(2);
    });

    test("classifies a flat slow stream as paged-file-content", () => {
        // 1055 bytes spread over ~21 s, 5 packets evenly spaced → flat ~50 char/s.
        const pkts = [
            s2cPacket(1000, 211),
            s2cPacket(5000, 211),
            s2cPacket(11000, 211),
            s2cPacket(17000, 211),
            s2cPacket(22000, 211),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.ok).toBe(true);
        expect(out.chunks[0].kind).toBe("paged-file-content");
        // Rate should be ~50 char/s.
        expect(out.chunks[0].rateCharPerSec).toBeGreaterThan(45);
        expect(out.chunks[0].rateCharPerSec).toBeLessThan(55);
    });

    test("classifies a fast dump as large-file-dump", () => {
        // 6 kB in 200 ms → 30 kB/s
        const pkts = [
            s2cPacket(1000, 1200),
            s2cPacket(1050, 1200),
            s2cPacket(1100, 1200),
            s2cPacket(1150, 1200),
            s2cPacket(1200, 1200),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.ok).toBe(true);
        expect(out.chunks[0].kind).toBe("large-file-dump");
    });

    test("classifies tiny output as prompt-or-echo", () => {
        const pkts = [
            s2cPacket(1000, 20),
            s2cPacket(1010, 20),
            s2cPacket(1020, 20),
            s2cPacket(1030, 20),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.ok).toBe(true);
        expect(out.chunks[0].kind).toBe("prompt-or-echo");
    });

    test("classifies a short fast burst as short-status-output", () => {
        // 1500 B in 4 s ≈ 375 char/s — fast enough to skip paged
        // classification (>200 char/s) but slow enough to skip
        // large-file-dump (>5000 char/s). DurationMs=4000 also keeps
        // it out of the short-status bucket? No — bucket requires
        // durationMs < 1500, so bump it: use 1200 ms total.
        const pkts = [
            s2cPacket(1000, 375),
            s2cPacket(1300, 375),
            s2cPacket(1600, 375),
            s2cPacket(1900, 375),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.ok).toBe(true);
        expect(out.chunks[0].kind).toBe("short-status-output");
    });

    test("rateFlatness is near 1 for evenly spaced packets", () => {
        const pkts = [
            s2cPacket(1000, 100),
            s2cPacket(1100, 100),
            s2cPacket(1200, 100),
            s2cPacket(1300, 100),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.chunks[0].rateFlatness).toBeGreaterThan(0.7);
    });

    test("rateFlatness is lower for bursty packets", () => {
        const pkts = [
            s2cPacket(1000, 100),
            s2cPacket(1010, 100), // burst
            s2cPacket(1020, 100),
            s2cPacket(1500, 100), // gap
            s2cPacket(2000, 100), // gap
        ];
        // Default chunkGapMs (100) splits this into multiple chunks —
        // use a wider gap so the burstiness is measured within a single
        // chunk.
        const out = summarizeS2cOutput(pkts, { chunkGapMs: 2000 });
        expect(out.ok).toBe(true);
        expect(out.totalChunks).toBe(1);
        expect(out.chunks[0].rateFlatness).toBeLessThan(0.7);
    });

    test("summary text mentions chunk count and total bytes", () => {
        const pkts = [
            s2cPacket(1000, 500),
            s2cPacket(1100, 500),
            s2cPacket(1200, 500),
            s2cPacket(1300, 500),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.summaryText).toContain("# Server output (s2c) summary");
        expect(out.summaryText).toContain("chunk(s)");
        expect(out.summaryText).toContain("Output chunks (sized, timed, classified)");
        expect(out.summaryText).toContain("Chunk-kind interpretation guide");
    });

    test("respects custom chunkGapMs", () => {
        const pkts = [
            s2cPacket(1000, 100),
            s2cPacket(1050, 100), // 50 ms
            s2cPacket(1500, 100), // 450 ms gap
            s2cPacket(1550, 100),
            s2cPacket(2000, 100), // 450 ms gap
            s2cPacket(2050, 100),
        ];
        // Default chunkGapMs (8000) → 1 chunk (all gaps < 8000).
        const def = summarizeS2cOutput(pkts);
        expect(def.totalChunks).toBe(1);
        // Custom gap = 200 → 3 chunks (split at each 450 ms gap).
        const narrow = summarizeS2cOutput(pkts, { chunkGapMs: 200 });
        expect(narrow.totalChunks).toBe(3);
        // Custom gap = 10000 → still 1 chunk.
        const wide = summarizeS2cOutput(pkts, { chunkGapMs: 10000 });
        expect(wide.totalChunks).toBe(1);
    });

    test("ignores packets with non-finite timestamps", () => {
        const pkts = [
            s2cPacket(1000, 200),
            { direction: "s2c", timestamp: null, packet: { "packet.info": { "packet.length": 200 } } },
            s2cPacket(1100, 200),
            s2cPacket(1200, 200),
            // Pad to satisfy minPackets=4 with valid timestamps.
            s2cPacket(1300, 200),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.ok).toBe(true);
        // 4 valid-timestamp packets (the null-timestamp one is filtered).
        expect(out.totalS2cPackets).toBe(4);
        // totalBytes comes only from valid-timestamp packets (the
        // null-timestamp one is dropped before chunking).
        expect(out.totalBytes).toBe(800);
    });

    test("treats missing/zero packet length as zero bytes", () => {
        const pkts = [
            { direction: "s2c", timestamp: 1000, packet: {} },
            { direction: "s2c", timestamp: 1050, packet: { "packet.info": {} } },
            { direction: "s2c", timestamp: 1100, packet: { "packet.info": { "packet.length": 0 } } },
            { direction: "s2c", timestamp: 1150, packet: { "packet.info": { "packet.length": 200 } } },
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.ok).toBe(true);
        expect(out.totalBytes).toBe(200);
    });

    test("sorts unsorted packets by timestamp before chunking", () => {
        const pkts = [
            s2cPacket(1200, 200),
            s2cPacket(1000, 200),
            s2cPacket(1100, 200),
            s2cPacket(1050, 200),
        ];
        const out = summarizeS2cOutput(pkts);
        expect(out.ok).toBe(true);
        // All <100ms apart after sort → 1 chunk.
        expect(out.totalChunks).toBe(1);
        expect(out.chunks[0].startTs).toBe(1000);
        expect(out.chunks[0].endTs).toBe(1200);
    });

    test("declares S2C_MIN_PACKETS as 4 by default", () => {
        expect(S2C_MIN_PACKETS).toBe(4);
    });
});

// ── computeShapeSignature tests ─────────────────────────────────────
//
// Synthesize delay streams that exercise specific shape signatures
// and assert the digests are useful for command-class reasoning.
// We don't need to know the *exact* typed text — we just need the
// signature to reflect cadence / burst structure / pauses / backspaces
// / s2c response in a way the LLM can act on.

function synthWordDelays(count, wordLen, intraBurstMs, betweenWordMs) {
    // Produces `count` words, each `wordLen` characters long, separated
    // by `betweenWordMs` pauses.
    const out = [];
    for (let i = 0; i < count; i += 1) {
        for (let j = 0; j < wordLen; j += 1) {
            out.push(intraBurstMs);
        }
        if (i < count - 1) out.push(betweenWordMs);
    }
    return out;
}

describe("computeShapeSignature", () => {
    test("returns null on empty input", () => {
        expect(computeShapeSignature({ delays: [] })).toBeNull();
        expect(computeShapeSignature({})).toBeNull();
    });

    test("exposes cadence summary derived from the delays", () => {
        // 10 keystrokes at 50ms cadence.
        const delays = new Array(10).fill(50);
        const shape = computeShapeSignature({ delays });
        expect(shape.ok).toBe(true);
        expect(shape.sampleCount).toBe(10);
        expect(shape.cadence.medianMs).toBeCloseTo(50, 1);
        expect(shape.cadence.keysPerSec).toBe(20);
    });

    test("burst structure counts consecutive sub-30ms runs as word lengths", () => {
        // Two words of 5 chars each (within-word delays <30ms),
        // separated by a 600ms command-boundary pause.
        const delays = [
            10, 10, 10, 10, 10, // "word1"
            600,
            10, 10, 10, 10, 10, // "word2"
        ];
        const shape = computeShapeSignature({ delays });
        expect(shape.burstStructure.burstCount).toBe(2);
        expect(shape.burstStructure.medianLength).toBe(5);
        expect(shape.burstStructure.meanLength).toBe(5);
        expect(shape.burstStructure.maxLength).toBe(5);
    });

    test("classifies pauses into within/short/command/idle buckets", () => {
        const delays = [
            150,  // within-command (30-200ms)
            350,  // short-thinking (200-500ms)
            1000, // command-boundary (500-2000ms)
            3000, // idle (>2000ms)
            // Pad with valid delays to keep the test focused on pauses.
            100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
            100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
            100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
        ];
        const shape = computeShapeSignature({ delays });
        expect(shape.pauses.withinCommand).toBeGreaterThanOrEqual(1);
        expect(shape.pauses.shortThinking).toBeGreaterThanOrEqual(1);
        expect(shape.pauses.commandBoundary).toBeGreaterThanOrEqual(1);
        expect(shape.pauses.idle).toBeGreaterThanOrEqual(1);
    });

    test("backspace distribution by stream location (leading/mid/trailing)", () => {
        const totalLen = 100;
        const delays = new Array(totalLen).fill(50);
        const backspaceHints = {
            indices: [5, 6, 7, 50, 90, 91, 92],
            count: 7,
        };
        const shape = computeShapeSignature({ delays, backspaceHints });
        expect(shape.backspaces.count).toBe(7);
        // 5/6/7 fall in the leading 25% (0..25).
        expect(shape.backspaces.leadingPct).toBeGreaterThan(0);
        // 50 is in the middle 50%.
        expect(shape.backspaces.midPct).toBeGreaterThan(0);
        // 90/91/92 fall in the trailing 25% (75..100).
        expect(shape.backspaces.trailingPct).toBeGreaterThan(0);
        // Longest run = 3 (either 5-6-7 or 90-91-92).
        expect(shape.backspaces.longestRun).toBe(3);
    });

    test("typingMode heuristic detects paste-or-script for fast uniform cadence", () => {
        // 200 keys at 5ms each, no pauses, no backspaces — fast & uniform.
        const delays = new Array(200).fill(5);
        const shape = computeShapeSignature({ delays });
        expect(shape.typingMode).toBe("paste-or-script");
    });

    test("typingMode heuristic detects fast-typing when most keys are bursts", () => {
        // 80% of delays <30ms, 20% between 80-200ms.
        const delays = [];
        for (let i = 0; i < 80; i += 1) delays.push(15); // bursts
        for (let i = 0; i < 20; i += 1) delays.push(120); // word boundaries
        delays.sort((a, b) => a - b); // ensure burst structure
        const shape = computeShapeSignature({ delays });
        expect(["fast-typing", "natural-typing", "mixed"]).toContain(shape.typingMode);
    });

    test("typingMode heuristic detects natural-typing for variable cadence with pauses", () => {
        // 50 keys, mix of 50-150ms, with 5 command-boundary pauses.
        const delays = [];
        for (let i = 0; i < 50; i += 1) delays.push(80 + (i % 7) * 10);
        for (let i = 0; i < 5; i += 1) delays.push(800);
        const shape = computeShapeSignature({ delays });
        expect(["natural-typing", "mixed", "scripted"]).toContain(shape.typingMode);
    });

    test("s2cDigest is exposed when s2cSummary is provided", () => {
        const s2cSummary = {
            ok: true,
            totalChunks: 3,
            totalBytes: 4096,
            totalDurationMs: 5000,
            chunks: [
                { idx: 1, totalBytes: 1024, durationMs: 1500, rateCharPerSec: 683, kind: "paged-file-content" },
                { idx: 2, totalBytes: 1024, durationMs: 1500, rateCharPerSec: 683, kind: "paged-file-content" },
                { idx: 3, totalBytes: 2048, durationMs: 2000, rateCharPerSec: 1024, kind: "short-status-output" },
            ],
        };
        const shape = computeShapeSignature({
            delays: new Array(40).fill(50),
            s2cSummary,
        });
        expect(shape.s2c).not.toBeNull();
        expect(shape.s2c.totalChunks).toBe(3);
        expect(shape.s2c.totalBytes).toBe(4096);
        expect(shape.s2c.kinds.length).toBe(3);
        expect(shape.s2c.kinds[0].kind).toBe("paged-file-content");
    });

    test("handles missing backspaceHints and s2cSummary gracefully", () => {
        const shape = computeShapeSignature({
            delays: new Array(20).fill(60),
        });
        expect(shape.backspaces.count).toBe(0);
        expect(shape.s2c).toBeNull();
    });

    test("CV (coefficient of variation) reflects typing variability", () => {
        // Very uniform → CV near 0.
        const uniform = new Array(50).fill(50);
        // Highly variable → CV much larger.
        const variable = [];
        for (let i = 0; i < 25; i += 1) variable.push(20);
        for (let i = 0; i < 25; i += 1) variable.push(180);
        const u = computeShapeSignature({ delays: uniform });
        const v = computeShapeSignature({ delays: variable });
        expect(u.cadence.cv).toBeLessThan(v.cadence.cv);
    });
});

describe("renderShapeSignature", () => {
    test("returns empty string when shape is null", () => {
        expect(renderShapeSignature(null)).toBe("");
        expect(renderShapeSignature({ ok: false })).toBe("");
    });

    test("renders a Shape signature section with cadence + typing mode", () => {
        const shape = computeShapeSignature({ delays: new Array(30).fill(80) });
        const text = renderShapeSignature(shape);
        expect(text).toContain("## Shape signature");
        expect(text).toContain("Cadence:");
        expect(text).toContain("Typing mode:");
        expect(text).toContain("Pause distribution:");
        expect(text).toContain("Burst structure:");
        expect(text).toContain("Backspaces");
    });

    test("renders backspace cluster location when present", () => {
        const shape = computeShapeSignature({
            delays: new Array(100).fill(50),
            backspaceHints: { indices: [5, 6, 7, 8], count: 4 },
        });
        const text = renderShapeSignature(shape);
        expect(text).toContain("leading");
        expect(text).toContain("4 event(s)");
        expect(text).toContain("longest run 4");
    });

    test("renders s2c chunk digest when provided", () => {
        const s2cSummary = {
            ok: true,
            totalChunks: 2,
            totalBytes: 2048,
            totalDurationMs: 3000,
            chunks: [
                { idx: 1, totalBytes: 1024, durationMs: 1500, rateCharPerSec: 683, kind: "paged-file-content" },
                { idx: 2, totalBytes: 1024, durationMs: 1500, rateCharPerSec: 683, kind: "paged-file-content" },
            ],
        };
        const shape = computeShapeSignature({
            delays: new Array(50).fill(60),
            s2cSummary,
        });
        const text = renderShapeSignature(shape);
        expect(text).toContain("Server response (s2c)");
        expect(text).toContain("2 chunk(s)");
        expect(text).toContain("paged-file-content");
    });
});

describe("buildSshTimingAnalysisBrief shape signature section", () => {
    test("includes the Shape signature section in the rendered brief", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState(), { maxSamples: 200 });
        expect(brief.text).toContain("## Shape signature");
        expect(brief.text).toContain("Typing mode:");
        expect(brief.text).toContain("Cadence:");
    });

    test("includes backspace cluster digest when backspaceHints are present", () => {
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({
                backspaceHints: { indices: [10, 11, 12], count: 3 },
            }),
            { maxSamples: 200 },
        );
        expect(brief.text).toContain("3 event(s)");
        expect(brief.text).toContain("longest run 3");
    });

    test("shape signature classifies paste correctly for dense typing", () => {
        // 200 keys at 5ms = paste. Brief should label this.
        const delays = new Array(200).fill(5);
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({ delays }),
            { maxSamples: 200 },
        );
        expect(brief.text).toContain("Typing mode: paste-or-script");
    });
});

describe("buildShellCommandPriors", () => {
    test("returns ok=false with reason='empty_corpus' on empty input", () => {
        expect(buildShellCommandPriors("")).toEqual({
            ok: false,
            reason: "empty_corpus",
            totalLines: 0,
            totalCommands: 0,
            uniqueCommands: 0,
            verbs: {},
            topVerbs: [],
        });
        expect(buildShellCommandPriors(null)).toMatchObject({ ok: false });
    });

    test("ignores blank lines and JSON-fragment lines", () => {
        const corpus = [
            "{",
            "],",
            "}",
            '"command":',
            "",
            "cat /etc/passwd",
            "ls -la",
            "",
            "cat /etc/passwd",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        expect(priors.ok).toBe(true);
        expect(priors.totalCommands).toBe(3);
        expect(priors.uniqueCommands).toBe(2);
        expect(priors.verbs.cat.count).toBe(2);
        expect(priors.verbs.ls.count).toBe(1);
    });

    test("strips a leading shell prompt from each line", () => {
        const corpus = [
            "[user@host ~]$ cat /etc/hosts",
            "% ls /tmp",
            "❯ pwd",
            "user@host:/var$ sudo systemctl restart nginx",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        expect(priors.ok).toBe(true);
        expect(priors.totalCommands).toBe(4);
        expect(priors.verbs.cat.count).toBe(1);
        expect(priors.verbs.ls.count).toBe(1);
        expect(priors.verbs.pwd.count).toBe(1);
        expect(priors.verbs["sudo systemctl"].count).toBe(1);
    });

    test("buckets multi-verb commands by first+second token when second is not a flag", () => {
        const corpus = [
            "git push origin main",
            "git pull",
            "git push",
            "git -C repo status",
            "systemctl restart nginx",
            "systemctl status nginx",
            "systemctl restart mysql",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        expect(priors.verbs["git push"].count).toBe(2);
        expect(priors.verbs["git pull"].count).toBe(1);
        // Flag-second collapses to the verb alone so "git -C repo status"
        // doesn't create a noisy bucket.
        expect(priors.verbs.git.count).toBe(1);
        expect(priors.verbs["systemctl restart"].count).toBe(2);
        expect(priors.verbs["systemctl status"].count).toBe(1);
    });

    test("preserves distinct example commands per verb up to the cap", () => {
        const corpus = [
            "cat /etc/hosts",
            "cat /etc/passwd",
            "cat /etc/hostname",
            "cat /etc/resolv.conf",
            "cat /etc/fstab",
            "cat /etc/hosts",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus, { maxExamplesPerVerb: 3 });
        expect(priors.verbs.cat.count).toBe(6);
        expect(priors.verbs.cat.examples.length).toBe(3);
        // Should keep the first three distinct ones, not the duplicate.
        expect(priors.verbs.cat.examples).toEqual([
            "cat /etc/hosts",
            "cat /etc/passwd",
            "cat /etc/hostname",
        ]);
    });

    test("strips inline comments and trailing semicolons", () => {
        const corpus = [
            "ls -la # list all files",
            "echo hello world;",
            "cd /tmp # change dir",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        expect(priors.verbs.ls.examples[0]).toBe("ls -la");
        expect(priors.verbs.echo.examples[0]).toBe("echo hello world");
        expect(priors.verbs.cd.examples[0]).toBe("cd /tmp");
    });

    test("sorts topVerbs by frequency descending", () => {
        const corpus = [
            "ls",
            "ls",
            "ls",
            "ls",
            "cat /etc/passwd",
            "cat /etc/hosts",
            "pwd",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        expect(priors.topVerbs.map((e) => e.verb)).toEqual(["ls", "cat", "pwd"]);
        expect(priors.topVerbs.map((e) => e.count)).toEqual([4, 2, 1]);
    });

    test("strips a leading path prefix from the verb (e.g. /usr/bin/cat)", () => {
        const corpus = [
            "/usr/bin/cat /etc/passwd",
            "/bin/ls -la",
            "cat /etc/hosts",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        expect(priors.verbs.cat.count).toBe(2);
        expect(priors.verbs.ls.count).toBe(1);
    });

    test("handles a realistic shell-history dump (parses the actual src/data/shell_corpus.txt)", () => {
        const fs = require("fs");
        const path = require("path");
        const filePath = path.join(__dirname, "..", "src", "data", "shell_corpus.txt");
        if (!fs.existsSync(filePath)) {
            // Skip gracefully if the corpus file isn't shipped (CI may
            // not include it). Tests above still cover the parser.
            return;
        }
        const corpus = fs.readFileSync(filePath, "utf8");
        const priors = buildShellCommandPriors(corpus);
        expect(priors.ok).toBe(true);
        expect(priors.totalCommands).toBeGreaterThan(100);
        expect(priors.uniqueCommands).toBeGreaterThan(50);
        // topVerbs should be sorted descending.
        const counts = priors.topVerbs.map((e) => e.count);
        for (let i = 1; i < counts.length; i += 1) {
            expect(counts[i]).toBeLessThanOrEqual(counts[i - 1]);
        }
        // Each verb bucket has at least one example.
        for (const entry of priors.topVerbs.slice(0, 5)) {
            expect(priors.verbs[entry.verb].examples.length).toBeGreaterThan(0);
        }
    });
});

describe("renderShellPriors", () => {
    test("returns empty string when priors is null or not ok", () => {
        expect(renderShellPriors(null)).toBe("");
        expect(renderShellPriors({ ok: false })).toBe("");
        expect(renderShellPriors({ ok: true, totalCommands: 0 })).toBe("");
    });

    test("renders the priors section with verb buckets + counts + examples", () => {
        const corpus = [
            "git push origin main",
            "git push",
            "git push",
            "systemctl restart nginx",
            "systemctl status nginx",
            "cat /etc/passwd",
            "cat /etc/hosts",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        const text = renderShellPriors(priors);
        expect(text).toMatch(/Shell command priors/);
        expect(text).toMatch(/git push\s+\(3×/);
        expect(text).toMatch(/systemctl restart\s+\(1×/);
        expect(text).toMatch(/cat\s+\(2×/);
        expect(text).toContain("git push origin main");
        expect(text).toContain("systemctl restart nginx");
        expect(text).toContain("cat /etc/passwd");
    });

    test("respects maxVerbs and maxExamplesPerVerb options", () => {
        const corpus = [
            "ls",
            "ls",
            "ls",
            "cat /etc/hosts",
            "cat /etc/passwd",
            "cat /etc/hostname",
            "pwd",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        const text = renderShellPriors(priors, {
            maxVerbs: 1,
            maxExamplesPerVerb: 1,
        });
        // Only the top verb (`ls`) should appear as a verb bucket.
        expect(text).toMatch(/^\s*- ls\b/m);
        expect(text).not.toMatch(/^\s*- cat\b/m);
        expect(text).not.toMatch(/^\s*- pwd\b/m);
        // Exactly one top-level verb bullet + one indented example.
        const verbLines = (text.match(/^[^-].*\n|^-\s/gm) || []);
        // Verb bucket line(s) start with "- " at column 0 (no indent).
        const topLevelBullets = (text.match(/^- /gm) || []);
        expect(topLevelBullets.length).toBe(1);
        // One example line (indented 4 spaces, then "- ").
        const exampleBullets = (text.match(/^ {4}- /gm) || []);
        expect(exampleBullets.length).toBe(1);
    });
});

describe("buildSshTimingAnalysisBrief — shell priors integration", () => {
    test("omits the priors section when state.shellPriors is missing", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState());
        expect(brief.text).not.toMatch(/Shell command priors/);
    });

    test("includes the priors section when state.shellPriors is provided", () => {
        const corpus = [
            "git push origin main",
            "git push",
            "systemctl restart nginx",
            "cat /etc/passwd",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({ shellPriors: priors }),
        );
        expect(brief.text).toMatch(/Shell command priors \(from your shell history\)/);
        expect(brief.text).toMatch(/git push\s+\(2×/);
        expect(brief.text).toMatch(/systemctl restart\s+\(1×/);
    });

    test("omits the priors section when shellPriors.totalCommands is zero", () => {
        const priors = buildShellCommandPriors(""); // empty
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({ shellPriors: priors }),
        );
        expect(brief.text).not.toMatch(/Shell command priors/);
    });

    test("priors section appears AFTER the LEGEND, header, aggregate stats, and shape signature", () => {
        const corpus = "git push\n".repeat(20);
        const priors = buildShellCommandPriors(corpus);
        const brief = buildSshTimingAnalysisBrief(
            makeBriefState({ shellPriors: priors }),
        );
        // Use exact heading anchors that appear only once in the brief.
        // The LEGEND uses "- Aggregate timing statistics" (dash) while
        // the actual section uses "## Aggregate timing statistics".
        const legendIdx = brief.text.indexOf("# LEGEND");
        const headerIdx = brief.text.indexOf("# SSH Session:");
        const aggregateIdx = brief.text.indexOf("## Aggregate timing statistics");
        const shapeIdx = brief.text.indexOf("## Shape signature");
        const priorsIdx = brief.text.indexOf("## Shell command priors");
        expect(legendIdx).toBeGreaterThanOrEqual(0);
        expect(headerIdx).toBeGreaterThan(legendIdx);
        expect(aggregateIdx).toBeGreaterThan(headerIdx);
        expect(shapeIdx).toBeGreaterThan(aggregateIdx);
        expect(priorsIdx).toBeGreaterThan(shapeIdx);
    });
});

describe("buildShellCommandPriors — redaction handling", () => {
    test("accepts lines containing AAAA redaction placeholders", () => {
        const corpus = [
            "cat AAAAAAAAAA/.config/packetsnitch/activity-log.txt",
            "cat AAAAAAAAAA/.config/packetsnitch/activity-log.txt",
            "git push ssh://AAAAAAAAAAAAA@diffraction.lan.oxasploits.com:/repo",
            "git push ssh://AAAAAAAAAAAAA@diffraction.lan.oxasploits.com:/repo",
            "ls -la /tmp",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        expect(priors.ok).toBe(true);
        expect(priors.totalCommands).toBe(5);
        expect(priors.verbs["cat"].count).toBe(2);
        expect(priors.verbs["git push"].count).toBe(2);
        expect(priors.verbs.ls.count).toBe(1);
        // Examples must preserve the redaction tokens verbatim so the
        // LLM can see the shape of the original command.
        expect(priors.verbs["cat"].examples[0]).toContain("AAAAAAAAAA");
        expect(priors.verbs["git push"].examples[0]).toContain("AAAAAAAAAAAAA@diffraction");
    });

    test("treats a pure-A command as a single-token redaction verb (still parseable)", () => {
        // Pure-A tokens are unusual but should not crash — they're
        // bucketed as a literal "AAAA..." verb for diagnostic purposes.
        // The renderer will surface the redaction hint next to them.
        const corpus = "AAAAAAAAAAAAA\n".repeat(3);
        const priors = buildShellCommandPriors(corpus);
        expect(priors.ok).toBe(true);
        expect(priors.totalCommands).toBe(3);
        expect(priors.topVerbs.length).toBeGreaterThan(0);
    });

    test("rejects short A-runs of <4 chars (likely real AAAA-shaped words, not redactions)", () => {
        // "AAA" alone is rare; we don't auto-reject it because the
        // parser's job is to count verb shapes, not to decide what is
        // and isn't PII. Just verify it doesn't crash.
        const corpus = "AAA\naaa\n";
        const priors = buildShellCommandPriors(corpus);
        expect(priors.ok).toBe(true);
        // "AAA" (uppercase) is bucketed; "aaa" (lowercase) is too.
        expect(priors.totalCommands).toBeGreaterThanOrEqual(1);
    });

    test("parser handles the actual scrubbed src/data/shell_corpus.txt corpus", () => {
        const fs = require("fs");
        const path = require("path");
        const filePath = path.join(__dirname, "..", "src", "data", "shell_corpus.txt");
        if (!fs.existsSync(filePath)) return;
        const corpus = fs.readFileSync(filePath, "utf8");
        const priors = buildShellCommandPriors(corpus);
        expect(priors.ok).toBe(true);
        // Every verb bucket should preserve redaction tokens verbatim
        // (we strip nothing inside the command body).
        let foundRedaction = false;
        for (const entry of priors.topVerbs) {
            for (const ex of priors.verbs[entry.verb].examples) {
                if (/A{4,}/.test(ex)) {
                    foundRedaction = true;
                    break;
                }
            }
            if (foundRedaction) break;
        }
        expect(foundRedaction).toBe(true);
    });

    test("shell_corpus corpus flows end-to-end into the analysis brief as Shell command priors", () => {
        // Confirms the full pipeline: shell_corpus → buildShellCommandPriors
        // → brief.shellPriors → brief.text contains "## Shell command
        // priors". This is the same path the renderer takes via the
        // ssh-shell-corpus IPC handler + assembleLlmPrimaryResult.
        const fs = require("fs");
        const path = require("path");
        const filePath = path.join(__dirname, "..", "src", "data", "shell_corpus.txt");
        if (!fs.existsSync(filePath)) return;
        const corpus = fs.readFileSync(filePath, "utf8");
        const shellPriors = buildShellCommandPriors(corpus);
        expect(shellPriors.ok).toBe(true);
        const brief = buildSshTimingAnalysisBrief(makeBriefState({ shellPriors }));
        expect(brief.ok).toBe(true);
        expect(brief.text).toMatch(/## Shell command priors/);
        // At least one prior verb should be referenced in the brief.
        const verbFound = shellPriors.topVerbs.some((entry) =>
            brief.text.includes(`- ${entry.verb}`));
        expect(verbFound).toBe(true);
    });
});

describe("renderShellPriors — redaction hint", () => {
    test("includes a redaction placeholder hint when examples contain AAAA runs", () => {
        const corpus = [
            "git push ssh://AAAAAAAAAAAAA@diffraction.lan.oxasploits.com:/repo",
            "cat AAAAAAAAAA/.config/packetsnitch/activity-log.txt",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        const text = renderShellPriors(priors);
        expect(text).toMatch(/REDACTION PLACEHOLDER/i);
        expect(text).toMatch(/4\+|run of 4\+/i);
        // New wording: ± 4 chars (placeholder-length ± 4).
        expect(text).toMatch(/±\s*4/);
    });

    test("always includes the redaction hint (even when no example contains AAAA runs)", () => {
        // The redaction convention must be told to the LLM every time
        // the priors section is emitted, because the LLM needs the
        // rule in its context regardless of whether THIS particular
        // brief happens to contain redacted tokens.
        const corpus = "ls -la\npwd\ncat /etc/hosts\n".repeat(5);
        const priors = buildShellCommandPriors(corpus);
        const text = renderShellPriors(priors);
        expect(text).toMatch(/REDACTION PLACEHOLDER/i);
        expect(text).toMatch(/±\s*4/);
    });

    test("redaction hint appears BEFORE the verb list so the LLM reads it first", () => {
        const corpus = [
            "git push ssh://AAAAAAAAAAAAA@host:/repo",
            "git push ssh://AAAAAAAAAAAAA@host:/repo",
            "ls -la",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        const text = renderShellPriors(priors);
        const hintIdx = text.indexOf("REDACTION PLACEHOLDER");
        const firstVerbIdx = text.search(/^- [a-z]/m);
        expect(hintIdx).toBeGreaterThan(0);
        expect(firstVerbIdx).toBeGreaterThan(0);
        expect(hintIdx).toBeLessThan(firstVerbIdx);
    });
});

describe("hexToUint8Array", () => {
    test("decodes a clean hex string into bytes", () => {
        const u = hexToUint8Array("48656c6c6f21");
        expect(u).toBeInstanceOf(Uint8Array);
        expect(u.length).toBe(6);
        expect(u[0]).toBe(0x48); // H
        expect(u[5]).toBe(0x21); // !
        expect(String.fromCharCode(...u)).toBe("Hello!");
    });

    test("strips a leading '0x' prefix", () => {
        const u = hexToUint8Array("0xDEADBEEF");
        expect(Array.from(u)).toEqual([0xde, 0xad, 0xbe, 0xef]);
    });

    test("tolerates whitespace between hex pairs", () => {
        const u = hexToUint8Array("48 65 6c 6c 6f");
        expect(String.fromCharCode(...u)).toBe("Hello");
    });

    test("returns null for empty / non-hex input", () => {
        expect(hexToUint8Array("")).toBeNull();
        expect(hexToUint8Array(null)).toBeNull();
        expect(hexToUint8Array(undefined)).toBeNull();
    });

    test("truncates a trailing odd nibble", () => {
        const u = hexToUint8Array("abc");
        expect(u.length).toBe(1);
        expect(u[0]).toBe(0xab);
    });

    test("returns null when the input is not valid hex", () => {
        // Non-hex characters cause parseInt to fail.
        expect(hexToUint8Array("zz")).toBeNull();
    });
});

describe("extractPacketBytes", () => {
    function packetWithRawHex(hex) {
        // The actual shape: packet.packet["packet.info"]["Raw data"]["Payload"]["payload.hex"]
        return {
            packet: {
                "packet.info": {
                    "Raw data": {
                        "Payload": {
                            "payload.hex": hex,
                        },
                    },
                },
            },
        };
    }

    test("returns the bytes via packet.packet['packet.info']", () => {
        const pkt = packetWithRawHex("48656c6c6f");
        const u = extractPacketBytes(pkt);
        expect(u).toBeInstanceOf(Uint8Array);
        expect(String.fromCharCode(...u)).toBe("Hello");
    });

    test("falls back to the capitalised 'Packet Info' alias", () => {
        const pkt = {
            packet: {
                "Packet Info": {
                    "Raw data": {
                        "Payload": {
                            "payload.hex": "48656c6c6f",
                        },
                    },
                },
            },
        };
        const u = extractPacketBytes(pkt);
        expect(String.fromCharCode(...u)).toBe("Hello");
    });

    test("returns null when no recognized hex field is present", () => {
        expect(extractPacketBytes({ packet: { something: "else" } })).toBeNull();
        expect(extractPacketBytes({ packet: { "packet.info": {} } })).toBeNull();
    });

    test("returns null for null / undefined / non-object", () => {
        expect(extractPacketBytes(null)).toBeNull();
        expect(extractPacketBytes(undefined)).toBeNull();
        expect(extractPacketBytes("not-an-object")).toBeNull();
    });
});

describe("computeShellOutputCharDistribution + renderShellOutputCharDistribution", () => {
    test("classifies paths dominated by '/' + dot + dash + underscore", () => {
        // A path that's mostly separators and short tokens — the
        // numbers tell the real story: slash+dot+dash+underscore
        // outnumber letters. We deliberately avoid words like "home"
        // / "user" / "ssh" which would dilute the path signal.
        const path = "/a/b/.c/_d-.e/f-g.h_.i";
        const bytes = path.split("").map(c => c.charCodeAt(0));
        const dist = computeShellOutputCharDistribution(bytes);
        // Path bucket is the sum of slash + dot + dash + underscore.
        const paths = dist.slash + dist.dot + dist.dash + dist.underscore;
        expect(paths).toBeGreaterThan(dist.letters);
        const text = renderShellOutputCharDistribution(dist);
        expect(text).toContain("paths");
        expect(text).toContain("/");
    });

    test("classifies prose dominated by lowercase letters + spaces", () => {
        const bytes = "the quick brown fox jumps over the lazy dog".split("").map(c => c.charCodeAt(0));
        const dist = computeShellOutputCharDistribution(bytes);
        expect(dist.lowercase).toBeGreaterThan(dist.digits);
        expect(dist.letters).toBeGreaterThan(dist.digits);
    });

    test("classifies numeric/JSON output dominated by digits + punct", () => {
        // Numeric-heavy output where digits clearly outnumber letters.
        const bytes = "12 34 56 78 90 12 34 56 78 90".split("").map(c => c.charCodeAt(0));
        const dist = computeShellOutputCharDistribution(bytes);
        expect(dist.digits).toBeGreaterThanOrEqual(dist.letters);
        expect(dist.whitespace).toBeGreaterThan(0);
    });

    test("returns zeroed distribution for empty input", () => {
        const dist = computeShellOutputCharDistribution([]);
        expect(dist.total).toBe(0);
        expect(dist.letters).toBe(0);
        expect(dist.digits).toBe(0);
        expect(dist.slash).toBe(0);
        expect(dist.dot).toBe(0);
        expect(dist.dash).toBe(0);
        expect(dist.underscore).toBe(0);
        expect(dist.punct).toBeUndefined();
        expect(dist.punctuation).toBe(0);
    });

    test("render returns '(no payload bytes)' for empty / all-zero distribution", () => {
        expect(renderShellOutputCharDistribution({
            total: 0, letters: 0, digits: 0, whitespace: 0,
            slash: 0, dot: 0, dash: 0, underscore: 0,
            uppercase: 0, lowercase: 0, punctuation: 0,
            control: 0, highBit: 0,
        })).toBe("(no payload bytes)");
    });

    test("render includes both letters up/lo split and paths sub-breakdown", () => {
        const bytes = "/home/AAAA/test.txt".split("").map(c => c.charCodeAt(0));
        const dist = computeShellOutputCharDistribution(bytes);
        const text = renderShellOutputCharDistribution(dist);
        expect(text).toContain("letters");
        // The actual format is "(up 21% / lo 58%)" — look for the
        // "up" / "lo" tokens with a digit immediately after, not for
        // leading whitespace.
        expect(text).toMatch(/up \d/);
        expect(text).toMatch(/lo \d/);
        expect(text).toContain("paths");
        expect(text).toContain("("); // total bytes suffix
    });
});

describe("buildSessionTurnPairs + renderSessionTurnPairs", () => {
    test("returns empty pair arrays when there are no c2s delays and no s2c chunks", () => {
        const result = buildSessionTurnPairs({
            flow: { firstTimestamp: 1000 },
            delays: [],
            s2cSummary: { ok: true, chunks: [] },
        });
        expect(result.turnCount).toBe(0);
        expect(result.chunkPairs).toEqual([]);
        expect(result.turnPairs).toEqual([]);
    });

    test("identifies c2s turns split by pauses and pairs each with the following s2c chunk", () => {
        // 6 fast bursts (one word), 600 ms pause (command boundary), 4 more keys, another 600 ms pause.
        const delays = [50, 50, 50, 50, 50, 50, 600, 80, 80, 80, 80, 600];
        const s2cSummary = {
            ok: true,
            totalChunks: 2,
            totalBytes: 4096,
            totalDurationMs: 5000,
            chunks: [
                {
                    idx: 1, totalBytes: 1024, durationMs: 1500,
                    rateCharPerSec: 683, kind: "paged-file-content",
                    packetCount: 5, startTs: 2000, endTs: 3500,
                },
                {
                    idx: 2, totalBytes: 3072, durationMs: 1500,
                    rateCharPerSec: 2048, kind: "short-status-output",
                    packetCount: 12, startTs: 4200, endTs: 5700,
                },
            ],
        };
        const result = buildSessionTurnPairs({
            flow: { firstTimestamp: 1000 },
            delays,
            s2cSummary,
        });
        expect(result.ok).toBe(true);
        expect(result.turnCount).toBe(2);
        expect(result.c2sTimestampAvailable).toBe(true);
        expect(result.chunkPairs.length).toBe(2);
        expect(result.turnPairs.length).toBe(2);
        // chunk-based: each chunk pairs to the preceding turn.
        expect(result.chunkPairs[0].producedKind).toBe("paged-file-content");
        expect(result.chunkPairs[1].producedKind).toBe("short-status-output");
        // turn-based: each turn pairs to the next chunk.
        expect(result.turnPairs[0].s2cChunkIdx).toBe(1);
        expect(result.turnPairs[1].s2cChunkIdx).toBe(2);
    });

    test("marks turn-pair producedKind=no-matching-chunk when no s2c follows", () => {
        const delays = [50, 50, 50, 600, 50, 50, 600];
        const s2cSummary = {
            ok: true, totalChunks: 0, totalBytes: 0, totalDurationMs: 0,
            chunks: [],
        };
        const result = buildSessionTurnPairs({
            flow: { firstTimestamp: 1000 },
            delays,
            s2cSummary,
        });
        expect(result.turnCount).toBe(2);
        expect(result.turnPairs.every(p => p.producedKind === "no-matching-chunk")).toBe(true);
    });

    test("rendered section is present and references both pairings", () => {
        const delays = [50, 50, 50, 50, 600, 80, 80, 600];
        const s2cSummary = {
            ok: true,
            totalChunks: 1,
            totalBytes: 1024,
            totalDurationMs: 1500,
            chunks: [
                {
                    idx: 1, totalBytes: 1024, durationMs: 1500,
                    rateCharPerSec: 683, kind: "paged-file-content",
                    packetCount: 5, startTs: 2200, endTs: 3700,
                },
            ],
        };
        const result = buildSessionTurnPairs({
            flow: { firstTimestamp: 1000 },
            delays,
            s2cSummary,
        });
        const text = renderSessionTurnPairs(result);
        expect(text).toContain("## Session turn pairs");
        expect(text).toContain("Chunk-based pairs");
        expect(text).toContain("Turn-based pairs");
        expect(text).toContain("paged-file-content");
        expect(text).toContain("typed-duration");
    });

    test("rendered section notes missing timestamps when flow.firstTimestamp is null", () => {
        const result = buildSessionTurnPairs({
            flow: null,
            delays: [50, 50, 50],
            s2cSummary: { ok: true, chunks: [] },
        });
        const text = renderSessionTurnPairs(result);
        expect(text).toContain("flow.firstTimestamp missing");
    });
});

describe("REDACTION_AAA_LENGTH_TOLERANCE", () => {
    test("is exported and equals 4 (per design)", () => {
        expect(typeof REDACTION_AAA_LENGTH_TOLERANCE).toBe("number");
        expect(REDACTION_AAA_LENGTH_TOLERANCE).toBe(4);
    });

    test("renderShellPriors redaction hint advertises the ±4 tolerance", () => {
        const corpus = [
            "# 2026-08-13 14:02\nscp -i /home/AAAA/.ssh/id_rsa AAAA@AAAA:/srv/AAAA ./AAAA\n",
        ].join("\n");
        const priors = buildShellCommandPriors(corpus);
        const text = renderShellPriors(priors);
        expect(text).toContain("REDACTION PLACEHOLDER");
        // The new wording explicitly says "± 4" (Unicode plus-minus, ASCII space, digit).
        expect(text).toMatch(/±\s*4/);
    });
});

describe("buildSshTimingAnalysisBrief — Session turn pairs integration", () => {
    test("includes the Session turn pairs section when s2cSummary is present", () => {
        const s2cSummary = {
            ok: true,
            totalChunks: 1,
            totalBytes: 2048,
            totalDurationMs: 2000,
            chunks: [
                {
                    idx: 1, totalBytes: 2048, durationMs: 2000,
                    rateCharPerSec: 1024, kind: "paged-file-content",
                    packetCount: 10, startTs: 2200, endTs: 4200,
                },
            ],
        };
        const brief = buildSshTimingAnalysisBrief(makeBriefState({
            s2cSummary,
        }));
        expect(brief.ok).toBe(true);
        expect(brief.text).toContain("## Session turn pairs");
        expect(brief.text).toContain("Chunk-based pairs");
        expect(brief.text).toContain("Turn-based pairs");
        expect(brief.text).toContain("paged-file-content");
    });

    test("does NOT include the Session turn pairs section when s2cSummary is missing AND no Returns are detected", () => {
        // When neither s2cSummary nor detected Returns are present, the
        // section is omitted entirely (turnPairs and chunkPairs would
        // both be empty). build a brief state with delays that don't
        // have any >500ms pauses (so no Returns are detected).
        const flatDelays = Array(40).fill(80);
        const brief = buildSshTimingAnalysisBrief(makeBriefState({ delays: flatDelays }));
        expect(brief.ok).toBe(true);
        expect(brief.text).not.toContain("## Session turn pairs");
    });

    test("LEGEND block mentions session turn pairs and redaction tolerance", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState({}));
        expect(brief.ok).toBe(true);
        // LEGEND section is rendered as a comment-style heading at the top of the brief.
        const legendIdx = brief.text.indexOf("LEGEND");
        expect(legendIdx).toBeGreaterThan(0);
        const tail = brief.text;
        // Session-turn-pairs sub-section, plus redaction-tolerance language.
        expect(tail).toContain("Session turn pairs");
        expect(tail).toMatch(/±\s*4/);
    });
});

describe("computeRawVsPeeledIidStats + renderRawVsPeeledIid", () => {
    function syntheticRawStream(periodMs, jitterMs, count) {
        // Generate a synthetic 20ms-cadence-obfuscated stream: each
        // inter-key delay is N * periodMs + jitter, where N is chosen to
        // look like "real typing inflated by the cadence".
        const out = [];
        for (let i = 0; i < count; i += 1) {
            const N = 1 + (i % 6); // 1..6 packets per keystroke
            const j = ((i * 17) % 5) - 2; // -2..+2 ms jitter
            out.push(N * periodMs + j);
        }
        return out;
    }
    function syntheticPeeledStream(rawStream, periodMs) {
        // The peeled stream removes the cadence: each residue (raw - N*P)
        // is preserved, AND N*P filler intervals are dropped. We
        // approximate that here by keeping residues whose absolute
        // value < periodMs/2 (the "real keystroke" residuals).
        const out = [];
        for (const d of rawStream) {
            const k = Math.round(d / periodMs);
            const residue = d - k * periodMs;
            if (Math.abs(residue) < periodMs / 2 && k > 0) {
                out.push(residue);
            }
        }
        return out;
    }

    test("returns null when padding was not detected", () => {
        const comp = computeRawVsPeeledIidStats({ detected: false }, [50, 60, 70]);
        expect(comp).toBeNull();
    });

    test("returns null when rawDelays is missing", () => {
        const comp = computeRawVsPeeledIidStats({
            detected: true,
            keystrokeDelaysMs: [10, 12, 8],
        }, []);
        expect(comp).toBeNull();
    });

    test("computes a comparison object with both raw + peeled stats", () => {
        const period = 20;
        const raw = syntheticRawStream(period, 1, 60);
        const peeled = syntheticPeeledStream(raw, period);
        // Make sure the peeled stream has positive non-tiny values so
        // medianDeltaRatio is finite (residues from a clean 20 ms stream
        // collapse near 0 and would make the ratio NaN).
        const peeledLifted = peeled.map(r => Math.abs(r) + 5);
        const comp = computeRawVsPeeledIidStats({
            detected: true,
            periodMs: period,
            coverage: 0.9,
            residualStdMs: 1.5,
            dominantResidueMs: 0.5,
            rawDelays: raw,
            keystrokeDelaysMs: peeledLifted,
        });
        expect(comp).not.toBeNull();
        expect(comp.period).toBe(20);
        expect(comp.rawCount).toBe(60);
        expect(comp.peeledCount).toBe(peeledLifted.length);
        expect(comp.fillerRemoved).toBe(60 - peeledLifted.length);
        expect(comp.nearCadenceFraction).toBeGreaterThan(0.5);
        // The raw median should be much larger than the peeled median.
        expect(Number.isFinite(comp.medianDeltaRatio)).toBe(true);
        expect(comp.medianDeltaRatio).toBeGreaterThan(1.5);
    });

    test("render produces a markdown table + cadence-fingerprint line", () => {
        const period = 20;
        const raw = syntheticRawStream(period, 1, 40);
        const peeled = syntheticPeeledStream(raw, period);
        const comp = computeRawVsPeeledIidStats({
            detected: true,
            periodMs: period,
            coverage: 0.85,
            residualStdMs: 1.0,
            dominantResidueMs: 0.3,
            rawDelays: raw,
            keystrokeDelaysMs: peeled,
        });
        const text = renderRawVsPeeledIid(comp);
        expect(text).toContain("## Raw IID vs peeled IID");
        expect(text).toContain("20 ms");
        expect(text).toContain("Raw (obfuscated)");
        expect(text).toContain("Peeled (filler removed)");
        expect(text).toContain("Sample count");
        expect(text).toContain("Median IID");
        expect(text).toContain("Std-dev IID");
        expect(text).toContain("Interpretation:");
        // The cadence-fingerprint strength line should mention the period.
        expect(text).toMatch(/integer multiple of 20/);
    });

    test("render returns empty string when comparison object is null", () => {
        expect(renderRawVsPeeledIid(null)).toBe("");
    });

    test("strong-peeling label fires when median ratio > 2x", () => {
        const raw = [80, 100, 60, 90, 120, 70, 110, 95, 75, 105];
        const peeled = [5, 8, 4, 7, 6, 9, 3, 8];
        const comp = computeRawVsPeeledIidStats({
            detected: true,
            periodMs: 20,
            coverage: 0.9,
            residualStdMs: 1.5,
            dominantResidueMs: 0,
            rawDelays: raw,
            keystrokeDelaysMs: peeled,
        });
        const text = renderRawVsPeeledIid(comp);
        expect(text).toMatch(/strong peeling|moderate peeling|weak peeling/);
    });
});

describe("buildSshTimingAnalysisBrief — Raw vs peeled IID integration", () => {
    function makePadding(periodMs, rawDelays, peeledDelays) {
        return {
            detected: true,
            periodMs,
            coverage: 0.9,
            residualStdMs: 1.2,
            dominantResidueMs: 0.3,
            paddedIntervals: rawDelays
                .map((d, i) => ({ d, i }))
                .filter(x => Math.abs(x.d % periodMs) < 2)
                .map(x => x.i),
            rawDelays,
            keystrokeDelaysMs: peeledDelays,
            snappedDelaysMs: peeledDelays,
            pass1Candidate: periodMs,
            pass1PeakRatio: 2.4,
            candidateScores: [],
        };
    }

    test("Raw vs peeled IID section appears in the brief when padding is detected", () => {
        const period = 20;
        const raw = [];
        for (let i = 0; i < 50; i += 1) raw.push(period * (1 + (i % 5)) + ((i * 7) % 3 - 1));
        const peeled = raw.filter((_, i) => i % 4 !== 0).map(d => d % period);
        const brief = buildSshTimingAnalysisBrief(makeBriefState({
            paddingDetection: makePadding(period, raw, peeled),
        }));
        expect(brief.ok).toBe(true);
        expect(brief.text).toContain("## Raw IID vs peeled IID");
        expect(brief.text).toContain("Cadence fingerprint strength");
        expect(brief.text).toContain("Median IID ratio");
    });

    test("Raw vs peeled IID section is absent when padding was not detected", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState({
            paddingDetection: { detected: false },
        }));
        expect(brief.ok).toBe(true);
        expect(brief.text).not.toContain("## Raw IID vs peeled IID");
    });

    test("Raw vs peeled IID section is absent when paddingDetection is missing", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState({}));
        expect(brief.ok).toBe(true);
        expect(brief.text).not.toContain("## Raw IID vs peeled IID");
    });

    test("LEGEND block describes the two-pass padding detection algorithm", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState({}));
        expect(brief.ok).toBe(true);
        const legendIdx = brief.text.indexOf("# LEGEND");
        expect(legendIdx).toBeGreaterThan(0);
        const tail = brief.text.slice(legendIdx);
        // The new LEGEND entry should mention the algorithm by name.
        expect(tail).toMatch(/two-pass|first-difference|pass 1|pass 2/i);
    });
});

describe("computeFlowPacketProfile + renderFlowPacketProfile", () => {
    function makePacket(direction, opts) {
        const o = opts || {};
        const pinfo = {
            "packet.length": o.length != null ? o.length : 100,
        };
        if (o.cipherLen != null) pinfo.TCP = { "tcp.len": o.cipherLen };
        if (o.flags) pinfo.TCP = Object.assign(pinfo.TCP || {}, { "tcp.flags.str": o.flags });
        if (o.seq != null) pinfo.TCP = Object.assign(pinfo.TCP || {}, { "tcp.seq": o.seq });
        if (o.retransmit) pinfo.TCP = Object.assign(pinfo.TCP || {}, {
            "tcp.analysis": { retransmission: true },
        });
        if (o.outOfOrder) pinfo.TCP = Object.assign(pinfo.TCP || {}, {
            "tcp.analysis": { out_of_order: true },
        });
        return {
            direction,
            packet: { "packet.info": pinfo },
        };
    }

    test("returns null when there are no packets", () => {
        expect(computeFlowPacketProfile({ flow: {} })).toBeNull();
        expect(computeFlowPacketProfile({ flow: { packets: [] } })).toBeNull();
        expect(computeFlowPacketProfile({})).toBeNull();
    });

    test("counts packets by direction and tallies direction changes", () => {
        const packets = [
            makePacket("c2s", { length: 80 }),
            makePacket("c2s", { length: 90 }),
            makePacket("s2c", { length: 500, cipherLen: 460 }),
            makePacket("s2c", { length: 500, cipherLen: 460 }),
            makePacket("c2s", { length: 80 }),
        ];
        const profile = computeFlowPacketProfile({ flow: { packets } });
        expect(profile.totalPackets).toBe(5);
        expect(profile.c2sCount).toBe(3);
        expect(profile.s2cCount).toBe(2);
        expect(profile.directionChanges).toBe(2); // c2s→s2c, s2c→c2s
        expect(profile.firstDirection).toBe("c2s");
        expect(profile.lastDirection).toBe("c2s");
    });

    test("tallies large packets (>= 1000 B) per direction", () => {
        const packets = [
            makePacket("s2c", { length: 1500, cipherLen: 1460 }),
            makePacket("s2c", { length: 800, cipherLen: 760 }),
            makePacket("c2s", { length: 100, cipherLen: 60 }),
        ];
        const profile = computeFlowPacketProfile({ flow: { packets } });
        expect(profile.largePacketCount.s2c).toBe(1);
        expect(profile.largePacketCount.c2s).toBe(0);
    });

    test("flags count is parsed from tcp.flags.str", () => {
        const packets = [
            makePacket("c2s", { length: 100, flags: "...A....", seq: 1000 }),
            makePacket("c2s", { length: 100, flags: "...A....", seq: 1060 }),
            makePacket("s2c", { length: 200, flags: "...AP...", seq: 2000 }),
            makePacket("s2c", { length: 80, flags: "...A....", seq: 2160 }),
        ];
        const profile = computeFlowPacketProfile({ flow: { packets } });
        expect(profile.flagCounts.ack).toBe(4);
        expect(profile.flagCounts.psh).toBe(1);
    });

    test("detects retransmits via tcp.analysis and via seq backwards-jump", () => {
        const packets = [
            makePacket("c2s", { length: 100, seq: 1000 }),
            makePacket("c2s", { length: 100, seq: 1060, retransmit: true }),
            // Backwards seq jump (same direction) is also a retransmit.
            makePacket("c2s", { length: 100, seq: 1120 }),
            makePacket("c2s", { length: 100, seq: 1060 }),
        ];
        const profile = computeFlowPacketProfile({ flow: { packets } });
        // First retransmit (explicit analysis), plus one from seq going backwards.
        expect(profile.retransmitCount).toBeGreaterThanOrEqual(1);
    });

    test("captures ciphertext length per direction and max per direction", () => {
        const packets = [
            makePacket("c2s", { length: 80, cipherLen: 24 }),
            makePacket("c2s", { length: 80, cipherLen: 32 }),
            makePacket("s2c", { length: 1500, cipherLen: 1460 }),
            makePacket("s2c", { length: 800, cipherLen: 760 }),
        ];
        const profile = computeFlowPacketProfile({ flow: { packets } });
        expect(profile.maxCiphertextC2s).toBe(32);
        expect(profile.maxCiphertextS2c).toBe(1460);
        expect(profile.maxCiphertextOverall).toBe(1460);
        expect(profile.ciphertextSample.c2s).toEqual([24, 32]);
        expect(profile.ciphertextSample.s2c).toEqual([1460, 760]);
    });

    test("classifies ACK-only frames via the heuristic (small packet, no ciphertext)", () => {
        const packets = [
            makePacket("c2s", { length: 52 }), // no cipherLen, small → ACK-only heuristic
            makePacket("c2s", { length: 52 }),
            makePacket("s2c", { length: 1500, cipherLen: 1460 }), // real data
        ];
        const profile = computeFlowPacketProfile({ flow: { packets } });
        expect(profile.ackOnlyCount.c2s).toBe(2);
        expect(profile.ackOnlyCount.s2c).toBe(0);
    });

    test("handles packets with no TCP layer gracefully", () => {
        const packets = [
            { direction: "c2s", packet: { "packet.info": { "packet.length": 80 } } },
            { direction: "s2c", packet: { "packet.info": { "packet.length": 1500 } } },
        ];
        const profile = computeFlowPacketProfile({ flow: { packets } });
        expect(profile.totalPackets).toBe(2);
        expect(profile.c2sCount).toBe(1);
        expect(profile.s2cCount).toBe(1);
        // No TCP layer → no ciphertext stats, no flag counts.
        expect(profile.ciphertextLengths.c2s).toEqual([]);
        expect(profile.maxCiphertextOverall).toBe(0);
    });

    test("renders a markdown section with key stats", () => {
        const packets = [
            makePacket("c2s", { length: 80, cipherLen: 24 }),
            makePacket("c2s", { length: 80, cipherLen: 32, seq: 1000 }),
            makePacket("s2c", { length: 1500, cipherLen: 1460, seq: 2000 }),
            makePacket("s2c", { length: 800, cipherLen: 760, seq: 3460 }),
        ];
        const profile = computeFlowPacketProfile({ flow: { packets } });
        const text = renderFlowPacketProfile(profile);
        expect(text).toContain("## Wire-level packet profile");
        expect(text).toContain("Packets: 4");
        expect(text).toContain("Direction changes");
        expect(text).toContain("TCP retransmits");
        expect(text).toContain("ACK-only frames");
        expect(text).toContain("Large packets");
        expect(text).toContain("Max ciphertext segment size");
        expect(text).toContain("TCP flag mix");
        expect(text).toContain("Client → server (c2s)");
        expect(text).toContain("Server → client (s2c)");
        expect(text).toContain("Frame lengths (bytes)");
        expect(text).toContain("Ciphertext sample");
        expect(text).toContain("Interpretation:");
    });

    test("render returns empty string for null profile", () => {
        expect(renderFlowPacketProfile(null)).toBe("");
    });
});

describe("buildSshTimingAnalysisBrief — wire-level packet profile integration", () => {
    function makePacket(direction, opts) {
        const o = opts || {};
        const pinfo = { "packet.length": o.length || 80 };
        if (o.cipherLen != null) pinfo.TCP = { "tcp.len": o.cipherLen };
        return { direction, packet: { "packet.info": pinfo } };
    }

    test("packet profile section appears when flow has packets", () => {
        const packets = [
            makePacket("c2s", { length: 80, cipherLen: 24 }),
            makePacket("c2s", { length: 80, cipherLen: 24 }),
            makePacket("s2c", { length: 1500, cipherLen: 1460 }),
            makePacket("s2c", { length: 1500, cipherLen: 1460 }),
        ];
        const brief = buildSshTimingAnalysisBrief(makeBriefState({
            flow: { ...makeBriefState().flow, packets },
        }));
        expect(brief.ok).toBe(true);
        expect(brief.text).toContain("## Wire-level packet profile");
        expect(brief.text).toContain("Direction changes");
        expect(brief.text).toContain("Ciphertext sample");
    });

    test("packet profile section is absent when flow has no packets", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState({
            flow: { ...makeBriefState().flow, packets: [] },
        }));
        expect(brief.ok).toBe(true);
        expect(brief.text).not.toContain("## Wire-level packet profile");
    });

    test("packet profile section appears regardless of padding detection", () => {
        const packets = [
            makePacket("c2s", { length: 80 }),
            makePacket("s2c", { length: 200 }),
        ];
        const brief = buildSshTimingAnalysisBrief(makeBriefState({
            flow: { ...makeBriefState().flow, packets },
            paddingDetection: { detected: false },
        }));
        expect(brief.ok).toBe(true);
        expect(brief.text).toContain("## Wire-level packet profile");
    });

    test("LEGEND block describes the wire-level packet profile section", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState({}));
        expect(brief.ok).toBe(true);
        const legendIdx = brief.text.indexOf("# LEGEND");
        expect(legendIdx).toBeGreaterThan(0);
        const tail = brief.text.slice(legendIdx);
        expect(tail).toMatch(/Wire-level packet profile|packet\.length|tcp\.len/);
    });
});

describe("detectReturnKeys + renderReturnKeySummary + renderReturnKeys", () => {
    // A simple "two-command" synthetic trace:
    //   command 1: 6 fast keystrokes (5 gaps, all < 200 ms)
    //   a small packet carrying the Return key
    //   a 700 ms pause (the user's response time + the shell starting)
    //   command 2: 12 fast keystrokes (11 gaps, all < 200 ms)
    //   a small packet carrying the Return key
    //   a 900 ms pause (longer response)
    function makeTwoCommandDelays() {
        const delays = [];
        // Command 1: 5 keystrokes (including the Return). The Return
        // is just another keystroke — what makes it identifiable is
        // (a) the small c2s packet carrying it and (b) the very large
        // gap AFTER it (the shell is now executing).
        for (let i = 0; i < 4; i += 1) delays.push(80 + (i * 7) % 30);
        delays.push(250); // compose gap before the Return keypress
        delays.push(700); // post-Return pause (shell is executing)
        // Command 2: 11 keystrokes (including the Return).
        for (let i = 0; i < 9; i += 1) delays.push(60 + (i * 11) % 40);
        delays.push(280); // compose gap before the Return keypress
        delays.push(900); // post-Return pause
        return delays;
    }
    function makeTwoCommandDelaysWithIdx() {
        const delays = makeTwoCommandDelays();
        const out = [];
        // The "Return" position is the LAST keystroke of each command.
        // The detector identifies it via the big inter-command pause:
        //   - delays[5]  = 700 → Return = keystroke 6 (1-based), packet index 5
        //   - delays[16] = 900 → Return = keystroke 17 (1-based), packet index 16
        // delaysWithIdx[i].index stores the LATER packet of the gap at
        // delays[i]; we mark those packets small so the detector's
        // "packet-size" signal fires.
        for (let i = 0; i < delays.length; i += 1) {
            const isReturn = (i + 1) === 5 || (i + 1) === 16;
            out.push({
                delay: delays[i],
                index: i + 1,
                packetLength: isReturn ? 70 : 120,
            });
        }
        return out;
    }

    test("returns empty when there are no delays", () => {
        const det = detectReturnKeys({ delays: [], delaysWithIdx: [] });
        expect(det.returns).toEqual([]);
        expect(det.turnBoundaries).toEqual([]);
    });

    test("detects Return keys at every > 500 ms pause boundary", () => {
        const delays = makeTwoCommandDelays();
        const delaysWithIdx = makeTwoCommandDelaysWithIdx();
        const det = detectReturnKeys({ delays, delaysWithIdx }, { minConfidence: 0.4 });
        // Should find 2 Returns at the two pause boundaries.
        //   - delays[5]  = 700 → lastKeyIdx = 6  (the Return for command 1)
        //   - delays[16] = 900 → lastKeyIdx = 17 (the Return for command 2)
        expect(det.returns.length).toBeGreaterThanOrEqual(2);
        const indices = det.returns.map((r) => r.index).sort((a, b) => a - b);
        expect(indices).toContain(6);
        expect(indices).toContain(17);
        const accepted = det.turnBoundaries;
        expect(accepted).toContain(6);
        expect(accepted).toContain(17);
    });

    test("confidence drops when packet size is large (no small-packet signal)", () => {
        const delays = makeTwoCommandDelays();
        // Mark ALL packets as the same large size — Return signal 2 (packet
        // size) won't fire, so confidence should drop.
        const delaysWithIdxLarge = delays.map((d, i) => ({ delay: d, index: i + 1, packetLength: 200 }));
        const det = detectReturnKeys({ delays, delaysWithIdx: delaysWithIdxLarge }, { minConfidence: 0.0 });
        expect(det.returns.length).toBeGreaterThanOrEqual(2);
        // Mark the Return-key packets as small (delaysWithIdx[4].index = 5
        // for the first Return, delaysWithIdx[15].index = 16 for the
        // second). With the small-packet signal firing, confidence
        // should be higher than the all-large case.
        const delaysWithIdxSmall = delays.map((d, i) => ({
            delay: d,
            index: i + 1,
            packetLength: (i + 1) === 5 || (i + 1) === 16 ? 70 : 120,
        }));
        const detSmall = detectReturnKeys({ delays, delaysWithIdx: delaysWithIdxSmall }, { minConfidence: 0.0 });
        const avgLarge = det.returns.reduce((s, r) => s + r.confidence, 0) / det.returns.length;
        const avgSmall = detSmall.returns.reduce((s, r) => s + r.confidence, 0) / detSmall.returns.length;
        expect(avgLarge).toBeLessThan(avgSmall);
    });

    test("returnDetection is attached to buildSessionTurnPairs output", () => {
        const delays = makeTwoCommandDelays();
        const delaysWithIdx = makeTwoCommandDelaysWithIdx();
        const state = makeBriefState({ delays, delaysWithIdx });
        const pairs = buildSessionTurnPairs(state);
        expect(pairs.returnDetection).toBeDefined();
        expect(Array.isArray(pairs.returnDetection.returns)).toBe(true);
        expect(pairs.returnDetection.returns.length).toBeGreaterThanOrEqual(2);
    });

    test("annotated turns carry endsWithReturn + typedLength + commandTextLength", () => {
        const delays = makeTwoCommandDelays();
        const delaysWithIdx = makeTwoCommandDelaysWithIdx();
        const s2cSummary = {
            ok: true,
            totalChunks: 2, totalBytes: 1024, totalDurationMs: 1000,
            chunks: [
                {
                    idx: 1, totalBytes: 512, durationMs: 500, rateCharPerSec: 1024,
                    kind: "paged-file-content", packetCount: 4, startTs: 1000, endTs: 1500
                },
                {
                    idx: 2, totalBytes: 512, durationMs: 500, rateCharPerSec: 1024,
                    kind: "paged-file-content", packetCount: 4, startTs: 3000, endTs: 3500
                },
            ],
        };
        const state = makeBriefState({ delays, delaysWithIdx, s2cSummary });
        const pairs = buildSessionTurnPairs(state);
        // Find a turn whose end+2 (= Return 1-based keystroke position) is in turnBoundaries.
        const accepted = new Set(pairs.returnDetection.turnBoundaries);
        const annotatedTurns = pairs.turnPairs.map((p) => p.turn).filter((t) => t);
        const detectedTurns = annotatedTurns.filter((t) => accepted.has(t.end + 2));
        expect(detectedTurns.length).toBeGreaterThanOrEqual(2);
        for (const t of detectedTurns) {
            expect(t.endsWithReturn).toBe(true);
            expect(Number.isFinite(t.returnConfidence)).toBe(true);
            // typedLength = turn.length + 1 (one keystroke per gap, plus one).
            expect(t.typedLength).toBe(t.length + 1);
            // commandTextLength = typedLength - 1 (excluding the Return).
            expect(t.commandTextLength).toBe(t.typedLength - 1);
        }
    });

    test("renderReturnKeySummary emits a one-line detection summary", () => {
        const delays = makeTwoCommandDelays();
        const delaysWithIdx = makeTwoCommandDelaysWithIdx();
        const det = detectReturnKeys({ delays, delaysWithIdx }, { minConfidence: 0.4 });
        const text = renderReturnKeySummary(det);
        expect(text).toContain("Return keypress(es)");
        expect(text).toMatch(/2\/[2-9]/); // accepted/total
    });

    test("renderReturnKeySummary returns empty string when no returns detected", () => {
        const text = renderReturnKeySummary({ returns: [], turnBoundaries: [] });
        expect(text).toBe("");
        expect(renderReturnKeySummary(null)).toBe("");
    });

    test("renderReturnKeys emits a markdown table with all signal columns", () => {
        const delays = makeTwoCommandDelays();
        const delaysWithIdx = makeTwoCommandDelaysWithIdx();
        const det = detectReturnKeys({ delays, delaysWithIdx }, { minConfidence: 0.4 });
        const text = renderReturnKeys(det);
        expect(text).toContain("## Return-key detection");
        expect(text).toContain("| Pos | Delay idx | Pre-gap (ms) | Post-gap (ms) | Packet (B) | Confidence |");
        expect(text).toContain("RETURN");
        expect(text).toContain("Accepted Returns");
        expect(text).toContain("typed-length per command");
    });

    test("renderReturnKeys returns empty string when no returns", () => {
        expect(renderReturnKeys({ returns: [], turnBoundaries: [] })).toBe("");
        expect(renderReturnKeys(null)).toBe("");
    });
});

describe("buildSshTimingAnalysisBrief — Return-key detection integration", () => {
    // Build enough delays to clear BRIEF_MIN_SAMPLES (= 30). Each
    // "command" is 5 sub-200ms gaps + a small-gap Return key packet +
    // a big post-Return pause. 5 commands = 35 delays.
    function makeReturnDelays() {
        const delays = [];
        for (let c = 0; c < 5; c += 1) {
            for (let i = 0; i < 5; i += 1) delays.push(80 + (i * 7 + c * 13) % 30);
            delays.push(20);
            delays.push(700 + c * 200);
        }
        return delays;
    }
    function makeReturnDelaysWithIdx() {
        return makeReturnDelays().map((d, i) => ({
            delay: d,
            index: i + 1,
            // Each command produces 7 delays:
            //   delays[i*7+0..4] = 5 compose gaps (6 typed chars)
            //   delays[i*7+5]    = 20ms gap before Return
            //   delays[i*7+6]    = 700+ms inter-command pause
            // The Return is the LATER packet of delays[i*7+5], which is
            // delaysWithIdx[i*7+5].index = (i*7+5) + 1 = i*7+6 (0-based
            // packet position = keystroke 7, 1-based).
            packetLength: (i % 7 === 5) ? 70 : 120,
        }));
    }

    test("Return-key section appears in the brief when delaysWithIdx is provided", () => {
        const delays = makeReturnDelays();
        const delaysWithIdx = makeReturnDelaysWithIdx();
        const brief = buildSshTimingAnalysisBrief(makeBriefState({ delays, delaysWithIdx }));
        expect(brief.ok).toBe(true);
        // 5 commands × 1 Return each = 5 detected.
        expect(brief.text).toContain("Detected 5/5 Return keypress(es) at pause boundaries");
        expect(brief.text).toContain("## Return-key detection");
        expect(brief.text).toContain("RETURN");
    });

    test("Return-key DETAIL table is absent when delaysWithIdx is missing", () => {
        const delays = makeReturnDelays();
        const brief = buildSshTimingAnalysisBrief(makeBriefState({ delays }));
        expect(brief.ok).toBe(true);
        // The per-position detail table requires delaysWithIdx (it uses
        // packet lengths to score each candidate). The one-line summary
        // DOES render without delaysWithIdx (it only uses timing signals).
        expect(brief.text).not.toContain("## Return-key detection (turn anchors)");
        expect(brief.text).not.toContain("| Pos | Delay idx | Pre-gap");
    });

    test("LEGEND block explains Return-key detection algorithm", () => {
        const brief = buildSshTimingAnalysisBrief(makeBriefState({}));
        expect(brief.ok).toBe(true);
        const legendIdx = brief.text.indexOf("# LEGEND");
        expect(legendIdx).toBeGreaterThan(0);
        const tail = brief.text.slice(legendIdx);
        expect(tail).toMatch(/Return-key detection|turn terminator/i);
        // All four signals should be mentioned.
        expect(tail).toMatch(/positional|small.*packet|pre-key|post-key/i);
    });

    test("annotated turn pair shows typedLength + commandTextLength", () => {
        const delays = makeReturnDelays();
        const delaysWithIdx = makeReturnDelaysWithIdx();
        // Provide a synthetic s2cSummary so that turnPairs has at
        // least one pairing to render the per-pair annotation lines.
        const s2cSummary = {
            ok: true,
            totalChunks: 5,
            totalBytes: 2048,
            totalDurationMs: 5000,
            chunks: [
                {
                    idx: 1, totalBytes: 1024, durationMs: 1000, rateCharPerSec: 1024,
                    kind: "paged-file-content", packetCount: 8, startTs: 1000, endTs: 2000,
                    charDistribution: {
                        letters: 100, digits: 0, whitespace: 30, slash: 5,
                        dot: 3, dash: 2, underscore: 1, uppercase: 5, lowercase: 95,
                        punctuation: 5, control: 0, highBit: 0
                    },
                    payloadBytesClassified: 200
                },
                {
                    idx: 2, totalBytes: 1024, durationMs: 1000, rateCharPerSec: 1024,
                    kind: "paged-file-content", packetCount: 8, startTs: 3000, endTs: 4000,
                    charDistribution: {
                        letters: 100, digits: 0, whitespace: 30, slash: 5,
                        dot: 3, dash: 2, underscore: 1, uppercase: 5, lowercase: 95,
                        punctuation: 5, control: 0, highBit: 0
                    },
                    payloadBytesClassified: 200
                },
                {
                    idx: 3, totalBytes: 0, durationMs: 0, rateCharPerSec: 0,
                    kind: "prompt-or-echo", packetCount: 1, startTs: 5000, endTs: 5000
                },
                {
                    idx: 4, totalBytes: 0, durationMs: 0, rateCharPerSec: 0,
                    kind: "prompt-or-echo", packetCount: 1, startTs: 7000, endTs: 7000
                },
                {
                    idx: 5, totalBytes: 0, durationMs: 0, rateCharPerSec: 0,
                    kind: "prompt-or-echo", packetCount: 1, startTs: 9000, endTs: 9000
                },
            ],
        };
        const brief = buildSshTimingAnalysisBrief(makeBriefState({
            delays,
            delaysWithIdx,
            flow: { ...makeBriefState().flow, firstTimestamp: 0, lastTimestamp: 15000 },
            s2cSummary,
        }));
        expect(brief.ok).toBe(true);
        // Per-pair annotation lines.
        expect(brief.text).toContain("return-key detected at last keystroke");
        expect(brief.text).toContain("typed-length=");
        expect(brief.text).toContain("command-text-length=");
    });
});
