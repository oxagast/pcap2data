"use strict";

const {
    computeSessionConfidence,
    computeLineConfidence,
    computeDelayStats,
} = require("../src/ui/decoders/ssh-keystrokes/markov");

describe("computeSessionConfidence", () => {
    test("returns baseline for empty options", () => {
        const c = computeSessionConfidence({});
        expect(c.score).toBeGreaterThan(0);
        expect(c.score).toBeLessThanOrEqual(1);
        expect(c.factors.length).toBeGreaterThan(0);
        expect(c.interpretation).toMatch(/signal quality/i);
    });

    test("high score for clean human typing session", () => {
        const c = computeSessionConfidence({
            chunkCount: 5,
            delayMean: 100,
            delayStd: 80,
            medianDelayMs: 110,
            clearGapCount: 5,
            autotuneChunkCount: 5,
            autotuneScore: 1.2,
            foldingDominantPhaseRatio: 3.5,
            backspaceHintCount: 2,
            packetLengthMean: 110,
        });
        expect(c.score).toBeGreaterThanOrEqual(0.8);
        expect(c.factors.some((f) => f.name === "chunkShape")).toBe(true);
        expect(c.factors.some((f) => f.name === "foldingStrength")).toBe(true);
        expect(c.factors.some((f) => f.name === "backspaceHints")).toBe(true);
        expect(c.factors.some((f) => f.name === "packetLength")).toBe(true);
    });

    test("low score for script-like uniform traffic", () => {
        const c = computeSessionConfidence({
            chunkCount: 1,
            delayMean: 100,
            delayStd: 5,
            medianDelayMs: 15,
            clearGapCount: 0,
            packetLengthMean: 300,
        });
        expect(c.score).toBeLessThan(0.6);
    });

    test("obfuscation reduces confidence", () => {
        const clean = computeSessionConfidence({
            chunkCount: 3,
            delayMean: 100,
            delayStd: 80,
            medianDelayMs: 110,
            clearGapCount: 3,
        });
        const obfuscated = computeSessionConfidence({
            chunkCount: 3,
            delayMean: 100,
            delayStd: 80,
            medianDelayMs: 110,
            clearGapCount: 3,
            obfuscationDetected: true,
            obfuscationCoverage: 0.9,
        });
        expect(obfuscated.score).toBeLessThan(clean.score);
    });

    test("chunk shape factor degrades with poor auto-tune score", () => {
        const good = computeSessionConfidence({
            chunkCount: 3,
            autotuneChunkCount: 3,
            autotuneScore: 1.0,
        });
        const poor = computeSessionConfidence({
            chunkCount: 3,
            autotuneChunkCount: 3,
            autotuneScore: -1.5,
        });
        expect(poor.score).toBeLessThan(good.score);
    });

    test("backspace hints boost confidence up to a point", () => {
        const none = computeSessionConfidence({
            chunkCount: 3,
            backspaceHintCount: 0,
        });
        const some = computeSessionConfidence({
            chunkCount: 3,
            backspaceHintCount: 3,
        });
        const many = computeSessionConfidence({
            chunkCount: 3,
            backspaceHintCount: 20,
        });
        expect(some.score).toBeGreaterThan(none.score);
        expect(many.score).toBeLessThan(some.score);
    });

    test("packet length factor penalizes tiny and giant means", () => {
        const normal = computeSessionConfidence({
            chunkCount: 3,
            packetLengthMean: 110,
        });
        const tiny = computeSessionConfidence({
            chunkCount: 3,
            packetLengthMean: 40,
        });
        const giant = computeSessionConfidence({
            chunkCount: 3,
            packetLengthMean: 300,
        });
        expect(normal.score).toBeGreaterThan(tiny.score);
        expect(normal.score).toBeGreaterThan(giant.score);
    });
});

describe("computeLineConfidence", () => {
    test("returns baseline for unknown command", () => {
        const c = computeLineConfidence("xyz", {});
        expect(c).toBe(0.5);
    });

    test("uses decoder agreement when provided", () => {
        const low = computeLineConfidence("ls -la", {
            estimatedLength: 6,
            keystrokeCount: 20,
            viterbiMarkovAgreement: 0.3,
        });
        const high = computeLineConfidence("ls -la", {
            estimatedLength: 6,
            keystrokeCount: 6,
            viterbiMarkovAgreement: 0.95,
        });
        expect(high).toBeGreaterThan(low);
    });

    test("keystroke count plausibility affects score", () => {
        const empty = computeLineConfidence("ls", { keystrokeCount: 0 });
        const good = computeLineConfidence("ls", { keystrokeCount: 5 });
        const huge = computeLineConfidence("ls", { keystrokeCount: 50 });
        expect(good).toBeGreaterThan(empty);
        expect(good).toBeGreaterThan(huge);
    });

    test("first-token validity boosts known shell commands", () => {
        const known = computeLineConfidence("ls -la", { keystrokeCount: 6 });
        const weird = computeLineConfidence("qqqzzz", { keystrokeCount: 6 });
        expect(known).toBeGreaterThan(weird);
    });

    test("timing match factor is finite when delays provided", () => {
        const c = computeLineConfidence("ls -la", {
            estimatedLength: 6,
            keystrokeCount: 6,
            delaysMs: [80, 90, 100, 85, 95],
        });
        expect(Number.isFinite(c)).toBe(true);
        expect(c).toBeGreaterThan(0);
        expect(c).toBeLessThanOrEqual(1);
    });
});

describe("computeDelayStats", () => {
    test("computes mean/std/median for delay array", () => {
        const s = computeDelayStats([80, 100, 90, 110, 95]);
        expect(s.count).toBe(5);
        expect(s.mean).toBeCloseTo(95, 0);
        expect(s.median).toBe(95);
        expect(s.std).toBeGreaterThan(0);
    });

    test("returns zeros for empty array", () => {
        const s = computeDelayStats([]);
        expect(s.count).toBe(0);
        expect(s.mean).toBe(0);
        expect(s.std).toBe(0);
    });
});
