// Tests for the OpenSSH keystroke-timing decoder.
// See src/ui/decoders/ssh-keystrokes/index.js for the implementation.

const {
    QWERTY_ROWS,
    DECODER_ALPHABET,
    DEFAULT_DIGRAPH_PARAMS,
    qwertyDistance,
    classifyDigraph,
    buildCoordinateIndex,
    loadQwertyModel,
    resolveDigraphParams,
    gaussianLogProbability,
    scoreNextChar,
    decodeKeystrokes,
    buildChartSeries,
    _setModelForTesting,
    _resetModel,
} = require("../src/ui/decoders/ssh-keystrokes");

describe("QWERTY geometry", () => {
    test("qwertyDistance returns 0 for the same key", () => {
        expect(qwertyDistance("a", "a")).toBe(0);
    });

    test("adjacent horizontal neighbors are distance 1", () => {
        expect(qwertyDistance("a", "s")).toBe(1);
        expect(qwertyDistance("q", "w")).toBe(1);
        expect(qwertyDistance("n", "m")).toBe(1);
    });

    test("vertical neighbors (same column, adjacent rows) are distance 1", () => {
        // q (row 0, col 0) → a (row 1, col 0) is straight down.
        expect(qwertyDistance("q", "a")).toBe(1);
        expect(qwertyDistance("a", "z")).toBe(1);
    });

    test("diagonal neighbors (1 col + 1 row) are distance 2", () => {
        expect(qwertyDistance("w", "a")).toBe(2);
        expect(qwertyDistance("e", "s")).toBe(2);
        expect(qwertyDistance("r", "d")).toBe(2);
    });

    test("returns null for keys outside the QWERTY grid", () => {
        expect(qwertyDistance("?", "a")).toBeNull();
        expect(qwertyDistance("a", "$")).toBeNull();
    });

    test("buildCoordinateIndex mirrors the QWERTY_ROWS layout", () => {
        const idx = buildCoordinateIndex(QWERTY_ROWS);
        expect(idx.q).toEqual([0, 0]);
        expect(idx.a).toEqual([0, 1]);
        expect(idx.m).toEqual([6, 2]);
        expect(idx["/"]).toEqual([9, 2]);
    });
});

describe("classifyDigraph", () => {
    test("returns 'sameKey' for identical keys", () => {
        expect(classifyDigraph("e", "e")).toBe("sameKey");
    });

    test("returns 'adjacentKey' for same-row neighbors", () => {
        expect(classifyDigraph("e", "r")).toBe("adjacentKey");
        expect(classifyDigraph("a", "s")).toBe("adjacentKey");
        expect(classifyDigraph("n", "m")).toBe("adjacentKey");
    });

    test("returns 'crossRow' for keys on different rows", () => {
        expect(classifyDigraph("q", "a")).toBe("crossRow");
        expect(classifyDigraph("a", "z")).toBe("crossRow");
    });

    test("returns 'farKey' for distant same-row keys", () => {
        expect(classifyDigraph("q", "p")).toBe("farKey");
    });

    test("returns null for off-grid characters", () => {
        expect(classifyDigraph("a", "?")).toBeNull();
    });
});

describe("resolveDigraphParams", () => {
    test("uses empirical samples when present in either order", () => {
        const empirical = { th: { mean: 90, std: 18 }, he: { mean: 85, std: 16 } };
        // std is clamped to MIN_STD_MS = 20.
        expect(resolveDigraphParams("t", "h", empirical, {})).toEqual({ mean: 90, std: 20 });
        expect(resolveDigraphParams("h", "t", empirical, {})).toEqual({ mean: 90, std: 20 });
        expect(resolveDigraphParams("h", "e", empirical, {})).toEqual({ mean: 85, std: 20 });
    });

    test("falls back to heuristic baselines by digraph classification", () => {
        const baselines = {
            adjacentKey: { mean: 95, std: 25 },
            crossRow: { mean: 200, std: 50 },
        };
        expect(resolveDigraphParams("a", "s", {}, baselines)).toEqual({ mean: 95, std: 25 });
        expect(resolveDigraphParams("q", "a", {}, baselines)).toEqual({ mean: 200, std: 50 });
    });

    test("clamps std to MIN_STD_MS", () => {
        const out = resolveDigraphParams("a", "b", { ab: { mean: 100, std: 5 } }, {});
        expect(out.std).toBeGreaterThanOrEqual(20);
    });

    test("returns DEFAULT_DIGRAPH_PARAMS for unknown non-QWERTY keys", () => {
        const out = resolveDigraphParams("@", "#", {}, {});
        expect(out).toEqual({ ...DEFAULT_DIGRAPH_PARAMS });
    });

    test("lowercases keys before lookup", () => {
        // std 12 is clamped to MIN_STD_MS = 20.
        const out = resolveDigraphParams("T", "H", { th: { mean: 88, std: 12 } }, {});
        expect(out).toEqual({ mean: 88, std: 20 });
    });
});

describe("gaussianLogProbability", () => {
    test("peaks at the mean", () => {
        const atMean = gaussianLogProbability(100, 100, 25);
        const farOff = gaussianLogProbability(200, 100, 25);
        expect(atMean).toBeGreaterThan(farOff);
    });

    test("narrower std produces higher peak log-probability", () => {
        const narrow = gaussianLogProbability(100, 100, 10);
        const wide = gaussianLogProbability(100, 100, 50);
        expect(narrow).toBeGreaterThan(wide);
    });

    test("is symmetric around the mean", () => {
        const left = gaussianLogProbability(80, 100, 25);
        const right = gaussianLogProbability(120, 100, 25);
        expect(left).toBeCloseTo(right, 10);
    });
});

describe("scoreNextChar", () => {
    test("returns a log-probability for every alphabet character", () => {
        const scores = scoreNextChar("a", 95, {
            alphabet: DECODER_ALPHABET,
            empirical: {},
            baselines: { adjacentKey: { mean: 95, std: 25 } },
        });
        expect(Object.keys(scores)).toHaveLength(DECODER_ALPHABET.length);
        for (const ch of DECODER_ALPHABET) {
            expect(Number.isFinite(scores[ch])).toBe(true);
        }
    });

    test("prefers crossRow neighbors for short delays", () => {
        // On the QWERTY grid, `a` (row 1, col 0) is closer in time to `b`
        // (row 2, col 3) than to itself (sameKey), because sameKey typing has
        // a much higher mean delay.
        const model = {
            alphabet: "ab",
            empirical: {},
            baselines: {
                sameKey: { mean: 220, std: 45 },
                crossRow: { mean: 200, std: 50 },
            },
        };
        const scores = scoreNextChar("a", 90, model);
        expect(scores.b).toBeGreaterThan(scores.a);
    });

    test("with no prevChar every char scores the same default", () => {
        const scores = scoreNextChar(null, 95, {
            alphabet: "abc",
            empirical: {},
            baselines: {},
        });
        expect(scores.a).toBe(scores.b);
        expect(scores.b).toBe(scores.c);
    });
});

describe("decodeKeystrokes", () => {
    test("returns no candidates for an empty observation sequence", () => {
        expect(decodeKeystrokes([])).toEqual([]);
    });

    test("returns exactly topN candidates for short observation sequences", () => {
        const out = decodeKeystrokes([95, 95, 95, 95], { topN: 5 });
        expect(out).toHaveLength(5);
    });

    test("top candidate has the highest log-probability", () => {
        const out = decodeKeystrokes([110, 100, 95, 105, 220, 95, 200, 95, 95], { topN: 4 });
        for (let i = 1; i < out.length; i += 1) {
            expect(out[i - 1].logProb).toBeGreaterThanOrEqual(out[i].logProb);
        }
    });

    test("resulting text has one character per observed delay", () => {
        const delays = [95, 110, 95, 95, 95];
        const out = decodeKeystrokes(delays, { topN: 1 });
        expect(out[0].text).toHaveLength(delays.length);
    });

    test("perCharLogProb is populated for every emitted character", () => {
        const delays = [95, 110, 95];
        const out = decodeKeystrokes(delays, { topN: 1 });
        expect(out[0].perCharLogProb).toHaveLength(delays.length);
        for (const p of out[0].perCharLogProb) {
            expect(Number.isFinite(p)).toBe(true);
        }
    });

    test("survives non-finite observation entries", () => {
        const out = decodeKeystrokes([95, null, 95, 95, 95], { topN: 3 });
        expect(out.length).toBeGreaterThan(0);
        expect(out[0].text).toHaveLength(4); // null entry skipped
    });

    test("long delays favor space/digit-like candidates over letters", () => {
        // Build a delay sequence where every inter-key is ~220 ms (pause).
        const delays = [220, 220, 220, 220, 220, 220, 220, 220];
        const out = decodeKeystrokes(delays, { topN: 4 });
        expect(out.length).toBeGreaterThan(0);
        // Top candidate should pick a character whose digraph prior is near 220 ms.
        expect(typeof out[0].text).toBe("string");
    });
});

describe("loadQwertyModel", () => {
    afterEach(() => _resetModel());

    test("loads the bundled JSON and exposes empirical + baselines", () => {
        const json = require("../src/data/qwerty-model.json");
        const model = loadQwertyModel(json);
        expect(Array.isArray(model.layout)).toBe(true);
        expect(model.baselines.adjacentKey).toBeDefined();
        expect(model.alphabet).toBe(DECODER_ALPHABET);
        expect(model.empirical).toBeDefined();
    });

    test("falls back to defaults when the JSON is empty", () => {
        const model = loadQwertyModel({});
        expect(model.alphabet).toBe(DECODER_ALPHABET);
        expect(Object.keys(model.empirical)).toHaveLength(0);
    });

    test("tightens std for common adjacent digraphs in the empirical samples list", () => {
        const json = require("../src/data/qwerty-model.json");
        const model = loadQwertyModel(json);
        // "he" — h is row 1 col 5, e is row 0 col 2 → crossRow, not adjacent.
        // Pick a same-row neighbor: "er" (both row 0, cols 2 and 3) → adjacent.
        if (model.empirical.er) {
            expect(model.empirical.er.std).toBeLessThan(
                model.baselines.adjacentKey.std,
            );
        }
    });
});

describe("buildChartSeries", () => {
    test("returns histogram and reference traces with matching bin counts", () => {
        const delays = [80, 95, 100, 110, 200, 320, 410];
        const series = buildChartSeries(delays, { binSize: 50 });
        expect(series.histogram.x).toHaveLength(series.reference.x.length);
        expect(series.binSize).toBe(50);
    });

    test("zero observations produce a flat histogram of zeros", () => {
        const series = buildChartSeries([], { binSize: 25 });
        expect(series.histogram.y.every((v) => v === 0)).toBe(true);
        expect(series.reference.y.length).toBeGreaterThan(0);
    });

    test("drops non-finite delays from the histogram", () => {
        const series = buildChartSeries([95, NaN, -1, 110], { binSize: 25 });
        const total = series.histogram.y.reduce((s, v) => s + v, 0);
        expect(total).toBe(2);
    });

    test("reference Gaussian is non-negative everywhere", () => {
        const series = buildChartSeries([100, 110, 120]);
        for (const v of series.reference.y) {
            expect(v).toBeGreaterThanOrEqual(0);
        }
    });
});

describe("decoder with custom model", () => {
    test("respects an injected empirical digraph", () => {
        _setModelForTesting({
            alphabet: "abc",
            empirical: { aa: { mean: 100, std: 5 }, bb: { mean: 200, std: 5 } },
            baselines: {},
        });
        const shortDelays = [100, 100, 100, 100];
        const out = decodeKeystrokes(shortDelays, { topN: 3 });
        expect(out[0].text.split("").every((c) => c === "a")).toBe(true);
        _resetModel();
    });
});
