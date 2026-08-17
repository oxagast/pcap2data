// Tests for the v2 weight-envelope shrinkage helpers.
//
// These are pure-math tests — no model, no decoder, no fs.

const {
    isEnvelope,
    effectiveSampleSize,
    shrinkToPrior,
    clamp01,
} = require("../src/ui/decoders/ssh-keystrokes/score-envelopes");

describe("score-envelopes helpers", () => {
    describe("isEnvelope", () => {
        test("rejects null and primitives", () => {
            expect(isEnvelope(null)).toBe(false);
            expect(isEnvelope(undefined)).toBe(false);
            expect(isEnvelope(42)).toBe(false);
            expect(isEnvelope("published")).toBe(false);
        });

        test("accepts a v2 envelope (flat shape)", () => {
            // Per scripts/WEIGHT_SCHEMA.md §1: `weight`, `count`,
            // `source`, `lastUpdated` are sibling keys of mean/std.
            const env = {
                mean: 110,
                std: 20,
                weight: 0.85,
                count: 1247,
                source: "empirical",
                lastUpdated: "2026-01-14",
            };
            expect(isEnvelope(env)).toBe(true);
        });

        test("rejects an envelope missing required keys", () => {
            expect(isEnvelope({ weight: 0.5 })).toBe(false);
            expect(
                isEnvelope({
                    weight: 0.5,
                    count: 100,
                    source: "calibration",
                    // lastUpdated missing
                }),
            ).toBe(false);
        });

        test("accepts a defensively-nested envelope too", () => {
            // Older migrators wrote `entry.weight = { ... }`. We accept
            // that shape so legacy data still parses.
            const env = {
                weight: {
                    weight: 0.72,
                    count: 290,
                    source: "tldr",
                    lastUpdated: "2024-01-15",
                },
            };
            expect(isEnvelope(env)).toBe(true);
        });
    });

    describe("effectiveSampleSize", () => {
        test("zero for v1 (no envelope)", () => {
            expect(effectiveSampleSize({ mean: 95, std: 25 })).toBe(0);
        });

        test("virtual count = count * weight, floored at 1", () => {
            expect(
                effectiveSampleSize({
                    mean: 110,
                    std: 20,
                    weight: 0.5,
                    count: 100,
                    source: "x",
                    lastUpdated: "now",
                }),
            ).toBe(50);
            expect(
                effectiveSampleSize({
                    mean: 110,
                    std: 20,
                    weight: 0.01,
                    count: 100,
                    source: "x",
                    lastUpdated: "now",
                }),
            ).toBe(1);
        });

        test("clamps weight to [0, 1]", () => {
            expect(
                effectiveSampleSize({
                    mean: 110,
                    std: 20,
                    weight: 2.5,
                    count: 100,
                    source: "x",
                    lastUpdated: "now",
                }),
            ).toBe(100);
            expect(
                effectiveSampleSize({
                    mean: 110,
                    std: 20,
                    weight: -1,
                    count: 100,
                    source: "x",
                    lastUpdated: "now",
                }),
            ).toBe(1);
        });
    });

    describe("shrinkToPrior", () => {
        const env = (weight, count) => ({
            weight,
            count,
            source: "calibration",
            lastUpdated: "now",
        });

        test("passes through when empirical is null", () => {
            const out = shrinkToPrior(
                null,
                { mean: 95, std: 25, ...env(0.92, 450) },
            );
            expect(out).toEqual({ mean: 95, std: 25, effective_n: 0, alpha: 0 });
        });

        test("passes through when prior is null", () => {
            const out = shrinkToPrior(
                { mean: 110, std: 20, ...env(0.85, 200) },
                null,
            );
            expect(out).toEqual({ mean: 110, std: 20, effective_n: 0, alpha: 0 });
        });

        test("returns null when both are null", () => {
            expect(shrinkToPrior(null, null)).toBeNull();
        });

        test("high-weight empirical dominates", () => {
            // empirical weight 1.0, count 450 → n_eff = 450
            // prior     weight 0.92, count 450
            // Posterior mean should be very close to empirical (110).
            const out = shrinkToPrior(
                { mean: 110, std: 10, ...env(1.0, 450) },
                { mean: 100, std: 50, ...env(0.92, 450) },
            );
            expect(Math.abs(out.mean - 110)).toBeLessThan(2);
            // Posterior std should be << prior std because the empirical
            // evidence is tight.
            expect(out.std).toBeLessThan(20);
        });

        test("low-weight empirical regresses to prior", () => {
            const out = shrinkToPrior(
                { mean: 200, std: 10, ...env(0.1, 10) },
                { mean: 100, std: 50, ...env(0.92, 450) },
            );
            expect(Math.abs(out.mean - 100)).toBeLessThan(Math.abs(out.mean - 200));
        });

        test("variance grows when empirical and prior disagree", () => {
            const tightPrior = {
                mean: 100,
                std: 10,
                ...env(0.95, 1000),
            };
            const consistentEmpirical = shrinkToPrior(
                { mean: 102, std: 10, ...env(0.5, 10) },
                tightPrior,
            );
            const conflictingEmpirical = shrinkToPrior(
                { mean: 200, std: 10, ...env(0.5, 10) },
                tightPrior,
            );
            // Conflicting empirical ⇒ higher posterior variance.
            expect(conflictingEmpirical.std).toBeGreaterThan(consistentEmpirical.std);
        });

        test("v1 entries (no envelope) keep v1 behaviour", () => {
            const out = shrinkToPrior(
                { mean: 110, std: 20 }, // v1
                { mean: 95, std: 25, ...env(0.92, 450) },
            );
            expect(out).toEqual({ mean: 110, std: 20, effective_n: 0, alpha: 0 });
        });

        test("alpha option scales the prior weight", () => {
            const low = shrinkToPrior(
                { mean: 200, std: 10, ...env(0.1, 10) },
                { mean: 100, std: 50, ...env(0.92, 450) },
                { alpha: 0.1 },
            );
            const high = shrinkToPrior(
                { mean: 200, std: 10, ...env(0.1, 10) },
                { mean: 100, std: 50, ...env(0.92, 450) },
                { alpha: 5.0 },
            );
            // Higher alpha pulls harder toward the prior.
            expect(Math.abs(high.mean - 100)).toBeLessThan(Math.abs(low.mean - 100));
        });
    });

    describe("clamp01", () => {
        test.each([
            [-0.5, 0],
            [0, 0],
            [0.3, 0.3],
            [1, 1],
            [1.5, 1],
            [NaN, 0],
        ])("clamp01(%p) = %p", (input, expected) => {
            expect(clamp01(input)).toBe(expected);
        });
    });
});