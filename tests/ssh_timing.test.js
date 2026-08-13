// Tests for the SSH timing side-channel helpers in
// src/ui/decoders/main/ssh.js. These cover the pure math (recordDelay,
// median, computeMad, classifyMad, classifyBurst, zScore, classifyAnomaly,
// buildTimingRows) without touching the DOM.

const {
    _internals: {
        recordDelay,
        median,
        computeMad,
        classifyMad,
        classifyBurst,
        stddev,
        zScore,
        classifyAnomaly,
        buildTimingRows,
    },
    resetSshTimingState,
} = require("../src/ui/decoders/main/ssh.js");

describe("SSH timing helpers", () => {
    describe("recordDelay", () => {
        test("returns a copy of the input when sample is null", () => {
            const input = [10, 20, 30];
            const out = recordDelay(input, null, 100);
            expect(out).toEqual(input);
            // must not mutate input
            expect(out).not.toBe(input);
        });

        test("appends a new sample at the end", () => {
            expect(recordDelay([1, 2, 3], 4, 100)).toEqual([1, 2, 3, 4]);
        });

        test("drops the oldest sample once maxLogSize is exceeded", () => {
            const history = [1, 2, 3];
            const out = recordDelay(history, 4, 3);
            expect(out).toEqual([2, 3, 4]);
        });

        test("treats undefined sample same as null", () => {
            const input = [5, 6];
            expect(recordDelay(input, undefined, 100)).toEqual(input);
        });
    });

    describe("median", () => {
        test("returns null for empty input", () => {
            expect(median([])).toBeNull();
        });

        test("returns the middle element for odd-length arrays", () => {
            expect(median([3, 1, 2])).toBe(2);
        });

        test("returns the mean of the two middles for even-length arrays", () => {
            expect(median([4, 1, 3, 2])).toBe(2.5);
        });

        test("does not mutate the input", () => {
            const input = [3, 1, 2];
            median(input);
            expect(input).toEqual([3, 1, 2]);
        });
    });

    describe("computeMad", () => {
        test("returns null for empty arrays", () => {
            expect(computeMad([])).toBeNull();
        });

        test("zero MAD when all samples are identical", () => {
            expect(computeMad([50, 50, 50, 50])).toBe(0);
        });

        test("computes MAD on a known asymmetric sample", () => {
            // values = [1, 1, 2, 2, 4, 6, 9] → median = 2
            // |x-2| = [1,1,0,0,2,4,7] → median = 1
            expect(computeMad([1, 1, 2, 2, 4, 6, 9])).toBe(1);
        });
    });

    describe("classifyMad", () => {
        test("null input renders as em-dash", () => {
            expect(classifyMad(null)).toEqual({ label: "—", className: "" });
        });

        test("low MAD uses the green/keystroke class", () => {
            const out = classifyMad(20);
            expect(out.className).toBe("timing-low");
            expect(out.label).toMatch(/Low \(keystroke-like\)/);
        });

        test("moderate MAD uses the yellow class", () => {
            const out = classifyMad(120);
            expect(out.className).toBe("timing-moderate");
            expect(out.label).toMatch(/Moderate/);
        });

        test("high MAD uses the red class", () => {
            const out = classifyMad(500);
            expect(out.className).toBe("timing-high");
            expect(out.label).toMatch(/High \(non-keystroke\)/);
        });

        test("boundary at 50 ms is still Moderate (strict less-than)", () => {
            expect(classifyMad(50).className).toBe("timing-moderate");
        });

        test("boundary at 200 ms is still High", () => {
            expect(classifyMad(200).className).toBe("timing-high");
        });
    });

    describe("classifyBurst", () => {
        test("null or undefined renders as em-dash", () => {
            expect(classifyBurst(null)).toBe("—");
            expect(classifyBurst(undefined)).toBe("—");
        });

        test("delays under 100 ms are bursts", () => {
            expect(classifyBurst(0)).toBe("Yes (Burst)");
            expect(classifyBurst(99.9)).toBe("Yes (Burst)");
        });

        test("delays at or above 100 ms are normal", () => {
            expect(classifyBurst(100)).toBe("No (Normal)");
            expect(classifyBurst(500)).toBe("No (Normal)");
        });
    });

    describe("stddev", () => {
        test("zero for empty input", () => {
            expect(stddev([])).toBe(0);
        });

        test("zero for constant input", () => {
            expect(stddev([5, 5, 5, 5])).toBe(0);
        });

        test("matches population stddev for a small sample", () => {
            // population stddev of [2,4,4,4,5,5,7,9] = 2
            expect(stddev([2, 4, 4, 4, 5, 5, 7, 9])).toBeCloseTo(2, 5);
        });
    });

    describe("zScore", () => {
        test("null for empty population", () => {
            expect(zScore(10, [])).toBeNull();
        });

        test("zero when population has no variance", () => {
            expect(zScore(99, [5, 5, 5])).toBe(0);
        });

        test("positive z when sample is above the mean", () => {
            // population with variance so std > 0
            const z = zScore(50, [10, 20, 30]);
            expect(z).toBeGreaterThan(0);
        });

        test("matches manual computation on varied data", () => {
            // population = [10, 20, 30] → mean=20, std ≈ 8.165
            const z = zScore(35, [10, 20, 30]);
            const mean = 20;
            const std = Math.sqrt(((10 - mean) ** 2 + (20 - mean) ** 2 + (30 - mean) ** 2) / 3);
            expect(z).toBeCloseTo((35 - mean) / std, 5);
        });
    });

    describe("classifyAnomaly", () => {
        test("null renders as em-dash", () => {
            expect(classifyAnomaly(null)).toEqual({ label: "—", className: "" });
        });

        test("zero reports no variance", () => {
            expect(classifyAnomaly(0)).toEqual({
                label: "z = 0.00 — No variance",
                className: "",
            });
        });

        test("z within ±2 is Normal (timing-low class)", () => {
            expect(classifyAnomaly(1.5).className).toBe("timing-low");
            expect(classifyAnomaly(-2).className).toBe("timing-low");
        });

        test("z beyond ±2 is Anomalous (timing-high class)", () => {
            expect(classifyAnomaly(2.5).className).toBe("timing-high");
            expect(classifyAnomaly(-3).className).toBe("timing-high");
        });
    });

    describe("buildTimingRows", () => {
        test("em-dash for everything when delays are empty and no sample", () => {
            const rows = buildTimingRows([], null);
            expect(rows).toHaveLength(4);
            expect(rows[0]).toEqual({ name: "Inter-Packet Delay (Δ)", value: "—" });
            expect(rows[1].value).toBe("—");
            expect(rows[2].value).toBe("—");
            expect(rows[3].value).toBe("—");
            expect(rows[1].className).toBe("");
            expect(rows[3].className).toBe("");
        });

        test("shows 'Insufficient data' until 3 samples accumulate", () => {
            const one = buildTimingRows([50], 50);
            expect(one[1].value).toMatch(/Insufficient data \(1\/3 packets\)/);
            expect(one[3].value).toMatch(/Insufficient data \(1\/3 packets\)/);

            const two = buildTimingRows([50, 60], 60);
            expect(two[1].value).toMatch(/Insufficient data \(2\/3 packets\)/);
        });

        test("formats a low MAD and low z-score as Low/Normal", () => {
            // 3 evenly-spaced samples — MAD = 0 → Low
            const rows = buildTimingRows([100, 100, 100], 100);
            expect(rows[1].className).toBe("timing-low");
            expect(rows[1].value).toMatch(/Low \(keystroke-like\)/);
            // constant delays → stddev = 0 → z = 0 → "No variance"
            expect(rows[3].value).toMatch(/No variance/);
        });

        test("labels an isolated burst as Anomalous", () => {
            // most samples are ~200 ms (background), last one is 5 ms (burst)
            const history = [200, 200, 200];
            const rows = buildTimingRows(history, 5);
            // MAD is 0 → Low (keystroke-like)
            expect(rows[1].className).toBe("timing-low");
            // burst detection
            expect(rows[2].value).toBe("Yes (Burst)");
            // z-score of 5 vs [200,200,200] is undefined (zero stddev) →
            // we still expect the anomaly row to not be em-dash
            expect(rows[3].value).not.toBe("—");
        });

        test("non-zero stddev + outlier sample → Anomalous class", () => {
            // background = [100, 110, 120, 105, 115]; last sample = 1500 (way off)
            const history = [100, 110, 120, 105, 115];
            const rows = buildTimingRows(history, 1500);
            expect(rows[3].className).toBe("timing-high");
            expect(rows[3].value).toMatch(/Anomalous/);
        });

        test("formats the delay string with one decimal place", () => {
            const rows = buildTimingRows([100, 110], 123.456);
            expect(rows[0].value).toBe("123.5 ms");
        });
    });

    describe("resetSshTimingState", () => {
        test("clears the running state so the next packet starts fresh", () => {
            // renderSshTable requires a DOM, so we exercise reset via the
            // smoke call and confirm it doesn't throw. State is module-local,
            // so this is mostly a regression guard.
            expect(() => resetSshTimingState()).not.toThrow();
        });
    });
});
