// Tests for detect20msPadding in src/ui/decoders/ssh-keystrokes/index.js.
// Real typing never lines up at exact 20ms multiples — when it does, the
// SSH server is almost certainly padding outgoing packets. These tests
// check the detector picks that up and ignores normal keystroke timing.

const { detect20msPadding } = require("../src/ui/decoders/ssh-keystrokes");

// Deterministic seeded RNG so the tests don't flake on Math.random().
function seededRng(seed) {
    let s = seed >>> 0;
    return () => {
        s = (1664525 * s + 1013904223) >>> 0;
        return s / 0x100000000;
    };
}

function jitterSamples(period, base, jitterMs, count, seed) {
    const rng = seededRng(seed);
    const out = [];
    for (let i = 0; i < count; i += 1) {
        const offset = (rng() - 0.5) * 2 * jitterMs;
        out.push(base + i * period + offset);
    }
    return out;
}

describe("detect20msPadding", () => {
    test("returns detected:false on too-few samples", () => {
        const out = detect20msPadding([20, 40, 60, 80, 100, 120, 140]);
        expect(out.detected).toBe(false);
        expect(out.periodMs).toBeNull();
        expect(out.snappedDelaysMs).toBeNull();
    });

    test("returns detected:false on realistic keystroke delays", () => {
        // Mimic real typing: irregular bursts between 60 and 220ms with
        // broad, *non-uniform* spread (some very short, some long). Real
        // typing never lands a majority of samples within ±4ms of an
        // integer multiple of 20.
        const rng = seededRng(42);
        const out = [];
        for (let i = 0; i < 120; i += 1) {
            // Log-normal-ish: most values around 100-180ms, occasional
            // bursts and long pauses. The offsets are intentionally
            // *non-uniform* so they don't line up on any single period.
            const base = Math.exp(4.4 + (rng() - 0.5) * 0.9); // ~80-180ms
            const phase = i * 7.31; // arbitrary phase
            const skew = (Math.sin(phase) + Math.cos(phase * 0.7)) * 12;
            out.push(base + skew);
        }
        const result = detect20msPadding(out);
        expect(result.detected).toBe(false);
    });

    test("detects 20ms-cadence padding with mild jitter", () => {
        // 40 samples spaced at 20ms with ~±1.5ms jitter. These should
        // cluster cleanly on multiples of 20.
        const delays = jitterSamples(20, 80, 1.5, 40, 7);
        const result = detect20msPadding(delays);
        expect(result.detected).toBe(true);
        expect(result.periodMs).toBe(20);
        expect(result.coverage).toBeGreaterThanOrEqual(0.9);
        expect(result.residualStdMs).toBeLessThan(2);
        expect(Array.isArray(result.snappedDelaysMs)).toBe(true);
        // Snapped delays should be ~0 (residuals only).
        const maxAbs = Math.max(...result.snappedDelaysMs.map(Math.abs));
        expect(maxAbs).toBeLessThan(2.5);
    });

    test("detects 20ms padding on mixed periods (typical of interpacket timing)", () => {
        // Realistic inter-key delays that are sums of multiple keystrokes
        // but all quantized to multiples of 20ms with small jitter.
        const rng = seededRng(99);
        const delays = [];
        for (let i = 0; i < 80; i += 1) {
            // Each "keystroke" produces 2–4 packets → multiples of 20ms.
            const numPackets = 1 + Math.floor(rng() * 4);
            const noise = (rng() - 0.5) * 3;
            delays.push(numPackets * 20 + noise);
        }
        const result = detect20msPadding(delays);
        expect(result.detected).toBe(true);
        expect(result.periodMs).toBe(20);
    });

    test("detects 10ms cadence when explicitly tested", () => {
        const delays = jitterSamples(10, 30, 0.6, 30, 11);
        const result = detect20msPadding(delays, { periodCandidates: [10, 20, 40] });
        expect(result.detected).toBe(true);
        expect(result.periodMs).toBe(10);
    });

    test("skips snapping when snap:false", () => {
        const delays = jitterSamples(20, 60, 1.0, 30, 1);
        const result = detect20msPadding(delays, { snap: false });
        expect(result.detected).toBe(true);
        expect(result.snappedDelaysMs).toBeNull();
    });

    test("returns candidateScores sorted by coverage desc", () => {
        const delays = jitterSamples(20, 80, 1.5, 40, 7);
        const result = detect20msPadding(delays);
        const scores = result.candidateScores;
        expect(scores.length).toBeGreaterThan(0);
        for (let i = 1; i < scores.length; i += 1) {
            expect(scores[i - 1].coverage).toBeGreaterThanOrEqual(scores[i].coverage);
        }
    });

    test("honors custom minCoverage / maxResidualStd gates", () => {
        // Very loose jitter (~±30ms) makes residues spread so wide that
        // no candidate period can satisfy both the coverage and
        // residual-std gates, so detection fails.
        const delays = jitterSamples(20, 60, 30.0, 30, 13);
        const result = detect20msPadding(delays, { maxResidualStdMs: 4 });
        expect(result.detected).toBe(false);
    });

    test("ignores empty / non-numeric input gracefully", () => {
        expect(detect20msPadding([]).detected).toBe(false);
        expect(detect20msPadding(null).detected).toBe(false);
        expect(detect20msPadding([NaN, -1, 0, 20, 40]).detected).toBe(false);
    });
});

describe("detect20msPadding — raw input preservation", () => {
    test("rawDelays + rawDelayCount are set on the not-detected path", () => {
        // A short input that fails the minSampleCount gate.
        const input = [20, 40, 60, 80];
        const result = detect20msPadding(input);
        expect(result.detected).toBe(false);
        expect(Array.isArray(result.rawDelays)).toBe(true);
        expect(result.rawDelays).toEqual([20, 40, 60, 80]);
        expect(result.rawDelayCount).toBe(4);
    });

    test("rawDelays + rawDelayCount are set on the detected path", () => {
        // Build a synthetic 20 ms-cadence stream that triggers detection.
        const input = [];
        for (let i = 0; i < 60; i += 1) {
            input.push(20 * (1 + (i % 6)) + ((i * 7) % 3) - 1);
        }
        const result = detect20msPadding(input);
        expect(result.detected).toBe(true);
        expect(result.rawDelays).toEqual(input);
        expect(result.rawDelayCount).toBe(input.length);
    });

    test("rawDelays are filter-stripped copies (no NaN/negative/zero entries)", () => {
        const input = [NaN, -5, 0, 20, 40, 60, 80];
        const result = detect20msPadding(input, { minSampleCount: 4 });
        expect(result.rawDelays).toEqual([20, 40, 60, 80]);
        expect(result.rawDelayCount).toBe(4);
    });
});

// ── New two-pass + first-difference detector behaviour ─────────────────

describe("detect20msPadding — first-difference detector", () => {
    // Build a deterministic padded stream where every N consecutive
    // delays lie on integer multiples of `period`. This is the
    // fingerprint the first-difference scan targets.
    function paddedStream(period, realCount, fillersPerGap, jitterMs, seed) {
        const rng = seededRng(seed);
        const delays = [];
        for (let i = 0; i < realCount; i += 1) {
            // Real keystroke gap = (random integer in [1,3]) * period +
            // small jitter.
            const n = 1 + Math.floor(rng() * 3); // 1..3 multiples
            const baseDelay = n * period;
            // Insert `fillersPerGap` filler packets at delays 1*P,
            // 2*P, ..., n*P (so the decoder sees N delays instead of 1
            // between this keystroke and the next).
            for (let f = 1; f < n; f += 1) {
                const fillerJitter = (rng() - 0.5) * 2 * jitterMs;
                delays.push(f * period + fillerJitter);
            }
            const realJitter = (rng() - 0.5) * 2 * jitterMs;
            delays.push(baseDelay + realJitter);
        }
        return delays;
    }

    test("detects a 20ms cadence with mild jitter and reports filler intervals", () => {
        const delays = paddedStream(20, 40, 1, 0.8, 7);
        const result = detect20msPadding(delays);
        expect(result.detected).toBe(true);
        expect(result.periodMs).toBeCloseTo(20, 0);
        expect(Array.isArray(result.paddedIntervals)).toBe(true);
        expect(result.paddedIntervals.length).toBeGreaterThan(0);
        expect(result.pass1PeakRatio).toBeGreaterThan(1.4);
    });

    test("keystrokeDelaysMs removes filler intervals (one per real keystroke)", () => {
        const delays = paddedStream(20, 40, 1, 0.5, 3);
        const result = detect20msPadding(delays);
        expect(result.detected).toBe(true);
        expect(Array.isArray(result.keystrokeDelaysMs)).toBe(true);
        // keystrokeDelaysMs should have at most `realCount` entries
        // (= 40 in this build), well below the input length.
        expect(result.keystrokeDelaysMs.length).toBeLessThanOrEqual(40);
        // And strictly less than the input length when at least one
        // filler was classified.
        expect(result.keystrokeDelaysMs.length).toBeLessThan(delays.length);
    });

    test("snappedDelaysMs preserves interval count but is near zero", () => {
        const delays = paddedStream(20, 40, 1, 0.5, 11);
        const result = detect20msPadding(delays);
        expect(result.detected).toBe(true);
        expect(Array.isArray(result.snappedDelaysMs)).toBe(true);
        expect(result.snappedDelaysMs.length).toBe(delays.length);
        // After snapping, the per-interval values should be small
        // (residue, |d| < period/2 on average).
        const maxAbs = Math.max.apply(
            null,
            result.snappedDelaysMs.map((v) => Math.abs(v)),
        );
        expect(maxAbs).toBeLessThan(12);
    });

    test("pass-1 candidate matches pass-2 refined period within 1 ms", () => {
        const delays = paddedStream(20, 40, 1, 0.8, 9);
        const result = detect20msPadding(delays);
        expect(result.detected).toBe(true);
        expect(Number.isFinite(result.pass1Candidate)).toBe(true);
        expect(Math.abs(result.pass1Candidate - result.periodMs)).toBeLessThanOrEqual(1);
    });

    test("detects a non-default cadence (15ms) without any hard-coded list", () => {
        const delays = paddedStream(15, 35, 1, 0.6, 23);
        const result = detect20msPadding(delays);
        expect(result.detected).toBe(true);
        expect(result.periodMs).toBeCloseTo(15, 0);
    });

    test("detects a non-default cadence (25ms)", () => {
        const delays = paddedStream(25, 30, 1, 1.0, 5);
        const result = detect20msPadding(delays);
        expect(result.detected).toBe(true);
        expect(result.periodMs).toBeCloseTo(25, 0);
    });

    test("does not false-positive on natural typing with no fixed cadence", () => {
        // Realistic natural typing: median ~120 ms, exponential-ish
        // distribution, no periodic structure.
        const rng = seededRng(101);
        const delays = [];
        for (let i = 0; i < 80; i += 1) {
            // Mixture of fast bursts and slow thinking gaps.
            const r = rng();
            const gap = r < 0.6 ? 60 + rng() * 80 : 200 + rng() * 600;
            delays.push(gap);
        }
        const result = detect20msPadding(delays);
        expect(result.detected).toBe(false);
    });

    test("candidateScores stays sorted by coverage desc", () => {
        const delays = paddedStream(20, 40, 1, 1.0, 33);
        const result = detect20msPadding(delays);
        const scores = result.candidateScores;
        for (let i = 1; i < scores.length; i += 1) {
            expect(scores[i - 1].coverage).toBeGreaterThanOrEqual(scores[i].coverage);
        }
    });

    test("pass-1 first-difference can detect cadence when fillers are clustered per gap", () => {
        // Realistic padded stream: each real keystroke is preceded by
        // a burst of 2-4 filler packets, all at integer multiples of
        // 20 ms. First differences between consecutive delays are
        // typically 20 ms (filler→filler) or ~realGap (filler→real).
        const rng = seededRng(2);
        const delays = [];
        for (let i = 0; i < 40; i += 1) {
            const fillerCount = 2 + Math.floor(rng() * 3); // 2..4
            const realGap = 60 + rng() * 60;
            // Fillers in order: 1*P, 2*P, ..., n*P (relative to the
            // previous real keystroke).
            let prev = i === 0 ? 0 : delays[delays.length - 1] - realGap;
            for (let f = 1; f <= fillerCount; f += 1) {
                delays.push(f * 20 + (rng() - 0.5) * 0.5);
            }
            delays.push(realGap + (rng() - 0.5) * 2);
        }
        const result = detect20msPadding(delays);
        expect(result.detected).toBe(true);
        expect(result.periodMs).toBeCloseTo(20, -1);
    });
});

describe("autoTunePaddingThreshold", () => {
    const { autoTunePaddingThreshold } = require("../src/ui/decoders/ssh-keystrokes");

    test("returns no-detection when input is too small", () => {
        const out = autoTunePaddingThreshold([20, 40, 60]);
        expect(out.detected).toBe(false);
    });

    test("selects a coverage threshold that yields command-shape chunks on a synthetic padded stream", () => {
        // Build a synthetic "typed commands" stream where each
        // 'command' is 8 keystrokes, then a 600ms Return-shaped gap,
        // and *between* each keystroke the server inserts 2 filler
        // packets at multiples of 20ms. The detector should pick a
        // coverage threshold that classifies the filler as filler
        // and leaves us with one chunk per command (8 keystrokes).
        const rng = seededRng(11);
        const NUM_COMMANDS = 12;
        const FILLER_PER_KEYSTROKE = 2;
        const KEY_GAP_BASE = 110; // ms between keystrokes (real)
        const COMMAND_GAP = 600; // ms between commands (Return-shaped)
        const P = 20; // server pad cadence
        const delays = [];
        for (let cmd = 0; cmd < NUM_COMMANDS; cmd += 1) {
            const ks = 8;
            for (let k = 0; k < ks; k += 1) {
                // Each keystroke is preceded by FILLER_PER_KEYSTROKE
                // filler packets at integer multiples of P that look
                // like inter-key delays.
                for (let f = 1; f <= FILLER_PER_KEYSTROKE; f += 1) {
                    delays.push(f * P + (rng() - 0.5) * 0.5);
                }
                delays.push(KEY_GAP_BASE + (rng() - 0.5) * 6);
            }
            delays.push(COMMAND_GAP + (rng() - 0.5) * 8);
        }
        const result = autoTunePaddingThreshold(delays);
        expect(result.detected).toBe(true);
        expect(result.periodMs).toBeGreaterThan(0);
        // The picked coverage should be in the sweep range.
        expect(result.autotuneSelected).toBeGreaterThan(0);
        expect(result.autotuneSelected).toBeLessThanOrEqual(0.95);
        // And the chunk count should be in the right ballpark — we
        // tolerate a 3x range because the score blend is forgiving.
        expect(result.autotuneChunkCount).toBeGreaterThanOrEqual(3);
        expect(result.autotuneChunkCount).toBeLessThanOrEqual(NUM_COMMANDS * 3);
    });

    test("returns no-detection on realistic keystroke delays", () => {
        const rng = seededRng(99);
        const out = [];
        for (let i = 0; i < 120; i += 1) {
            const base = Math.exp(4.4 + (rng() - 0.5) * 0.9);
            const phase = i * 7.31;
            const skew = (Math.sin(phase) + Math.cos(phase * 0.7)) * 12;
            out.push(base + skew);
        }
        const result = autoTunePaddingThreshold(out);
        expect(result.detected).toBe(false);
    });
});
