// Tests for the OpenSSH auto-calibrate orchestrator.
// See src/ui/decoders/ssh-keystrokes/auto-calibrate.js.

const {
    autoCalibrate,
    aggregateScores,
    buildSweep,
    scoreTrial,
    applyKnob,
} = require("../src/ui/decoders/ssh-keystrokes/auto-calibrate");

describe("aggregateScores", () => {
    test("zero on empty input", () => {
        const s = aggregateScores([]);
        expect(s).toEqual({
            n: 0, mean: 0, total: 0, min: 0, max: 0, stddev: 0, exactMatchRate: 0,
        });
    });

    test("computes mean, min, max, total, exactMatchRate", () => {
        const s = aggregateScores([
            { score: 1.0 },
            { score: 0.5 },
            { score: 0.0 },
        ]);
        expect(s.n).toBe(3);
        expect(s.total).toBeCloseTo(1.5, 6);
        expect(s.mean).toBeCloseTo(0.5, 6);
        expect(s.min).toBe(0);
        expect(s.max).toBe(1);
        expect(s.exactMatchRate).toBeCloseTo(1 / 3, 6);
    });

    test("ignores non-finite scores", () => {
        const s = aggregateScores([{ score: Infinity }, { score: 0.5 }]);
        expect(s.n).toBe(1);
        expect(s.mean).toBe(0.5);
    });

    test("stddev is well-formed", () => {
        const s = aggregateScores([{ score: 0.0 }, { score: 1.0 }]);
        expect(s.stddev).toBeCloseTo(0.5, 6);
    });
});

describe("buildSweep", () => {
    test("produces a uniform min..max step grid", () => {
        const out = buildSweep({ min: 0, max: 1, step: 0.25 });
        expect(out).toEqual([0, 0.25, 0.5, 0.75, 1]);
    });

    test("returns an empty array when min/max/step are missing", () => {
        expect(buildSweep({})).toEqual([]);
        expect(buildSweep({ min: 0 })).toEqual([]);
    });

    test("returns values when explicit values array is provided", () => {
        expect(buildSweep({ values: ["a", "b", "c"] })).toEqual(["a", "b", "c"]);
    });

    test("returns values when step is non-positive", () => {
        expect(buildSweep({ min: 0, max: 1, step: 0 })).toEqual([]);
    });
});

describe("applyKnob", () => {
    test("returns a new object with the knob set", () => {
        const base = { a: 1, b: 2 };
        const out = applyKnob(base, "a", 99);
        expect(out).toEqual({ a: 99, b: 2 });
        // The original must not be mutated.
        expect(base).toEqual({ a: 1, b: 2 });
    });
});

describe("scoreTrial", () => {
    test("scores each predicted text against the truth list", () => {
        const truth = [
            { command: "ls -la" },
            { command: "cd /tmp" },
        ];
        const trialResult = {
            perCommand: [
                { idx: 0, predicted: "ls -la" },
                { idx: 1, predicted: "cd /tmp" },
            ],
        };
        const out = scoreTrial(trialResult, truth);
        expect(out).toHaveLength(2);
        expect(out[0].score).toBeGreaterThan(0.95);
        expect(out[1].score).toBeGreaterThan(0.95);
    });

    test("uses fallback when no per-index prediction is available", () => {
        const truth = [{ command: "ls -la" }];
        const trialResult = {
            perCommand: [
                { idx: 99, predicted: "ls -la" },
            ],
        };
        const out = scoreTrial(trialResult, truth);
        expect(out[0].score).toBeGreaterThan(0.95);
    });

    test("missing predictions score 0", () => {
        const truth = [{ command: "ls -la" }, { command: "cd /tmp" }];
        const trialResult = { perCommand: [] };
        const out = scoreTrial(trialResult, truth);
        expect(out).toHaveLength(2);
        expect(out[0].score).toBe(0);
        expect(out[1].score).toBe(0);
    });

    test("honours truth[i].chunkIdx when provided", () => {
        // 5 chunks but only 2 transcript commands; the truth rows
        // carry chunkIdx 0 and 3 (out of order). scoreTrial should
        // score each truth row against perCommand[chunkIdx] rather
        // than perCommand[i].
        const truth = [
            { command: "ls -la", chunkIdx: 0 },
            { command: "cd /tmp", chunkIdx: 3 },
        ];
        const trialResult = {
            perCommand: [
                { idx: 0, predicted: "ls -la" },
                { idx: 1, predicted: "totally_wrong_1" },
                { idx: 2, predicted: "totally_wrong_2" },
                { idx: 3, predicted: "cd /tmp" },
                { idx: 4, predicted: "totally_wrong_4" },
            ],
        };
        const out = scoreTrial(trialResult, truth);
        expect(out[0].predicted).toBe("ls -la");
        expect(out[0].score).toBeGreaterThan(0.95);
        expect(out[1].predicted).toBe("cd /tmp");
        expect(out[1].score).toBeGreaterThan(0.95);
        expect(out[0].chunkIdx).toBe(0);
        expect(out[1].chunkIdx).toBe(3);
    });

    test("falls back to index lookup when chunkIdx is null", () => {
        const truth = [
            { command: "ls -la", chunkIdx: null },
            { command: "cd /tmp", chunkIdx: null },
        ];
        const trialResult = {
            perCommand: [
                { idx: 0, predicted: "ls -la" },
                { idx: 1, predicted: "cd /tmp" },
            ],
        };
        const out = scoreTrial(trialResult, truth);
        expect(out[0].score).toBeGreaterThan(0.95);
        expect(out[1].score).toBeGreaterThan(0.95);
        expect(out[0].chunkIdx).toBeNull();
        expect(out[1].chunkIdx).toBeNull();
    });

    test("falls back to index lookup when chunkIdx points to missing prediction", () => {
        // chunkIdx 9 has no perCommand entry; the scorer should
        // try index 0 instead (since the truth row's i === 0).
        const truth = [
            { command: "ls -la", chunkIdx: 9 },
        ];
        const trialResult = {
            perCommand: [
                { idx: 0, predicted: "ls -la" },
            ],
        };
        const out = scoreTrial(trialResult, truth);
        expect(out[0].score).toBeGreaterThan(0.95);
    });
});

describe("autoCalibrate", () => {
    // Build a fake "trial runner" that returns a per-knob prediction
    // string. The score is computed by ``scoreTrial`` so we have to
    // construct strings that produce measurably different ssdeep
    // scores depending on the knob value. The optimum knob value
    // (0.6) returns the exact truth; everything else returns a string
    // that's deliberately non-overlapping with the truth so the
    // ssdeep score bottoms out.
    function makeFakeRunTrial(truth) {
        return async (knobs) => {
            const coverage = Number(knobs.minCoverage);
            const perCommand = [];
            for (let i = 0; i < truth.length; i += 1) {
                const truthText = truth[i].command;
                const distance = Math.abs(coverage - 0.6);
                let predicted = truthText;
                if (distance >= 0.05) {
                    // Use a markedly different string so the chunks
                    // produced by the rolling hash don't overlap
                    // the truth's chunks. ssdeep tolerates real
                    // prefixes, so we have to abandon the prefix.
                    // Reverse + non-alpha suffix gives 0.0 in our
                    // comparison context.
                    predicted = "zzz_" + truthText.split("").reverse().join("");
                }
                perCommand.push({ idx: i, truth: truthText, predicted, score: 0 });
            }
            return { perCommand };
        };
    }

    test("raises on missing inputs", async () => {
        await expect(autoCalibrate()).rejects.toThrow();
        await expect(autoCalibrate({})).rejects.toThrow();
        await expect(autoCalibrate({ knobs: {}, runTrial: () => { }, truth: [] })).rejects.toThrow();
    });

    test("coordinate descent finds the best knob combination", async () => {
        const truth = [
            { command: "ls -la" },
            { command: "cd /tmp" },
            { command: "apt-get update" },
        ];
        const ranges = {
            minCoverage: { min: 0.3, max: 0.9, step: 0.1 },
        };
        const progress = [];
        const result = await autoCalibrate({
            knobs: { minCoverage: 0.3 },
            ranges,
            runTrial: makeFakeRunTrial(truth),
            truth,
        }, (p) => progress.push(p));
        expect(result.best).toBeTruthy();
        expect(result.best.knobs.minCoverage).toBeCloseTo(0.6, 6);
        expect(result.best.stats.mean).toBeGreaterThan(0.95);
        expect(result.report.nTrials).toBeGreaterThanOrEqual(8);
        expect(progress.length).toBeGreaterThan(0);
    });

    test("returns an error result when aborted before baseline", async () => {
        const truth = [{ command: "ls" }];
        const ranges = { minCoverage: { min: 0.3, max: 0.9, step: 0.1 } };
        const controller = new AbortController();
        controller.abort();
        const result = await autoCalibrate({
            knobs: { minCoverage: 0.3 },
            ranges,
            runTrial: makeFakeRunTrial(truth),
            truth,
        }, null, { signal: controller.signal });
        // No baseline could run; the orchestrator surfaces an error result.
        expect(result.best).toBeNull();
        expect(result.report.error).toBeTruthy();
    });

    test("produces a sensitivity probe per knob", async () => {
        const truth = [{ command: "ls" }];
        const ranges = {
            minCoverage: { min: 0.3, max: 0.9, step: 0.1 },
            minLength: { min: 1, max: 5, step: 1 },
        };
        const result = await autoCalibrate({
            knobs: { minCoverage: 0.6, minLength: 3 },
            ranges,
            runTrial: makeFakeRunTrial(truth),
            truth,
        }, null, { sensitivityDepth: 1 });
        expect(result.sensitivity.minCoverage).toBeDefined();
        expect(result.sensitivity.minLength).toBeDefined();
        expect(result.sensitivity.minCoverage.length).toBe(7);
        expect(result.sensitivity.minLength.length).toBe(5);
    });

    test("surfaces an error result when even the baseline fails", async () => {
        const truth = [{ command: "ls" }];
        const result = await autoCalibrate({
            knobs: { minCoverage: 0.5 },
            ranges: { minCoverage: { min: 0.3, max: 0.9, step: 0.1 } },
            runTrial: async () => { throw new Error("decoder down"); },
            truth,
        });
        expect(result.best).toBeNull();
        expect(result.report.error).toMatch(/baseline run failed/);
    });
});
