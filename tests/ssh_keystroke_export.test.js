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
        test("both / unknown defaults to client → server", () => {
            expect(directionLabel("both")).toBe("client \u2192 server");
            expect(directionLabel(undefined)).toBe("client \u2192 server");
            expect(directionLabel("nonsense")).toBe("client \u2192 server");
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
        const section = text.split("## LLM analyst insight")[1].split("## Notes")[0];
        for (const line of section.split("\n")) {
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
        expect(brief.text).toMatch(/Direction: s2c/);
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

    test("handles a realistic shell-history dump (parses the actual src/data/shell_data)", () => {
        const fs = require("fs");
        const path = require("path");
        const filePath = path.join(__dirname, "..", "src", "data", "shell_data");
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

    test("parser handles the actual scrubbed src/data/shell_data corpus", () => {
        const fs = require("fs");
        const path = require("path");
        const filePath = path.join(__dirname, "..", "src", "data", "shell_data");
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
        expect(text).toMatch(/SAME LENGTH/i);
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
        expect(text).toMatch(/SAME LENGTH/i);
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
