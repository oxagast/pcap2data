// Tests for the clock-skew detection module.
// See src/ui/decoders/ssh-keystrokes/clock-skew.js.

const {
    extractLargeGaps,
    scoreAlignment,
    detectClockSkew,
    applySkew,
    formatSkewStatus,
    DEFAULT_OFFSET_RANGE_S,
    DEFAULT_OFFSET_STEP_S,
    DEFAULT_MATCH_TOLERANCE_S,
    DEFAULT_MIN_GAP_MS,
} = require("../src/ui/decoders/ssh-keystrokes/clock-skew");

describe("extractLargeGaps", () => {
    test("returns an empty array for < 2 timestamps", () => {
        expect(extractLargeGaps([])).toEqual([]);
        expect(extractLargeGaps([1000])).toEqual([]);
    });

    test("includes gaps at or above the threshold", () => {
        const out = extractLargeGaps([0, 50, 200, 5000, 5100, 5200], 200);
        // Gaps: 50, 150, 4800, 100, 100 → only the 4800 gap qualifies.
        expect(out.length).toBe(1);
        expect(out[0].timeMs).toBe(5000);
        expect(out[0].gapMs).toBe(4800);
    });

    test("respects a custom minGapMs", () => {
        const out = extractLargeGaps([0, 80, 200, 300], 100);
        // Gaps: 80, 120, 100 → only 120 and 100 >= 100.
        expect(out.map((g) => g.gapMs).sort((a, b) => a - b)).toEqual([100, 120]);
    });
});

describe("scoreAlignment", () => {
    const gaps = [
        { timeMs: 5000, gapMs: 1000 },
        { timeMs: 10000, gapMs: 5000 },
    ];
    test("returns 0 for empty transcript", () => {
        expect(scoreAlignment([], gaps, 0)).toBe(0);
    });
    test("returns 0 when no gaps", () => {
        expect(scoreAlignment([1000], [], 0)).toBe(0);
    });
    test("counts commands within tolerance of a gap", () => {
        // transcript at 5000 with offset 0 → matches first gap
        // transcript at 10000 with offset 0 → matches second gap
        const s = scoreAlignment([5000, 10000], gaps, 0, 3);
        expect(s).toBeGreaterThan(1.5);
    });
    test("applies the offset before matching", () => {
        // transcript at 0 with offset +5s → shifted to 5000 → matches
        const s = scoreAlignment([0], gaps, 5, 3);
        expect(s).toBeGreaterThan(0.5);
    });
    test("does not match outside tolerance", () => {
        // transcript at 7001 with offset 0 → 2001ms from first gap
        // (>2s tol), 2999ms from second gap (>2s tol). Neither
        // matches with a 2s tolerance.
        const s = scoreAlignment([7001], gaps, 0, 2);
        expect(s).toBe(0);
    });
});

describe("detectClockSkew", () => {
    test("returns null for empty transcript", () => {
        expect(detectClockSkew({
            transcriptRows: [],
            pcapTimestampsMs: [0, 100, 5000, 5100],
        })).toBeNull();
    });

    test("returns null when transcript has < 2 timestamps", () => {
        expect(detectClockSkew({
            transcriptRows: [{ timestamp: 1000 }, { command: "no time" }],
            pcapTimestampsMs: [0, 100, 5000, 5100],
        })).toBeNull();
    });

    test("returns null when PCAP has no large gaps", () => {
        expect(detectClockSkew({
            transcriptRows: [{ timestamp: 1000 }, { timestamp: 2000 }],
            pcapTimestampsMs: [0, 100, 200, 300, 400],
        })).toBeNull();
    });

    test("detects the correct offset on a clean synthetic session", () => {
        // 5 transcript commands + a 5s gap between each pair. PCAP
        // starts 1000 seconds before the transcript (offset = -1000).
        const transcript = [
            { timestamp: 1000000 },
            { timestamp: 1005000 },
            { timestamp: 1010000 },
            { timestamp: 1015000 },
            { timestamp: 1020000 },
        ];
        // PCAP timestamps in ms, starting 1000s before transcript
        // base. 5 packets at 0ms then a 5s gap, repeated.
        const pcap = [];
        for (let i = 0; i < 5; i += 1) {
            const start = i * 5500;
            for (let j = 0; j < 5; j += 1) pcap.push(start + j * 20);
        }
        const result = detectClockSkew({
            transcriptRows: transcript,
            pcapTimestampsMs: pcap,
            offsetRangeSec: 1500,
            offsetStepSec: 10,
            toleranceSec: 3,
            minGapMs: 500,
        });
        expect(result).not.toBeNull();
        // Transcript base 1000000ms = 1000s. PCAP base 0ms = 0s.
        // offset = pcapTime - transcriptTime = -1000s. Refinement to
        // 0.1s precision means result could land anywhere in
        // [-1000.5, -999.5]. The coarse grid (10s steps) limits
        // resolution to ±10s but the refinement pass brings it
        // closer.
        expect(result.offsetSec).toBeGreaterThanOrEqual(-1010);
        expect(result.offsetSec).toBeLessThanOrEqual(-990);
        expect(result.matches).toBeGreaterThanOrEqual(4); // at least 4 of 5
        expect(result.confidence).toBeGreaterThan(0.7);
    });

    test("reports low confidence for a transcript with too few timestamps to anchor", () => {
        // Edge case: only 1 transcript timestamp — can't compute a
        // meaningful offset. Module returns null.
        const result = detectClockSkew({
            transcriptRows: [{ timestamp: 1000 }],
            pcapTimestampsMs: [0, 100, 200, 5000, 5100],
        });
        expect(result).toBeNull();
    });

    test("prefers the offset that matches the most commands", () => {
        // Transcript has 5 commands; PCAP has 5 large gaps clustered
        // near offset -1.0s. Detection should pick offset ≈ -1s and
        // match all 5.
        const transcript = [
            { timestamp: 1000 },
            { timestamp: 1200 },
            { timestamp: 1400 },
            { timestamp: 1600 },
            { timestamp: 1800 },
        ];
        // 5 gaps: PCAP packets at 0, 10, 200, 210, 400, 410, 600, 610,
        // 800, 810 (gap ends at 200, 400, 600, 800, 1000). Right
        // offset to align with transcript at 1000..1800 is +200
        // (PCAP+200 = 1000, etc.).
        const pcap = [0, 10, 200, 210, 400, 410, 600, 610, 800, 810, 1000, 1010];
        const result = detectClockSkew({
            transcriptRows: transcript,
            pcapTimestampsMs: pcap,
            offsetRangeSec: 5,
            offsetStepSec: 0.5,
            toleranceSec: 0.2,
            minGapMs: 100,
        });
        expect(result).not.toBeNull();
        // Should match at least 4 of 5 commands when aligned.
        expect(result.matches).toBeGreaterThanOrEqual(4);
    });
});

describe("applySkew", () => {
    test("adds correctedTimestamp equal to timestamp when offset is 0", () => {
        const rows = [{ timestamp: 1000 }, { timestamp: 2000 }];
        const out = applySkew(rows, 0);
        expect(out[0].correctedTimestamp).toBe(1000);
        expect(out[1].correctedTimestamp).toBe(2000);
    });

    test("shifts timestamps by offset seconds", () => {
        const rows = [{ timestamp: 1000 }, { timestamp: 2000 }];
        const out = applySkew(rows, 5);
        expect(out[0].correctedTimestamp).toBe(6000);
        expect(out[1].correctedTimestamp).toBe(7000);
    });

    test("handles negative offsets", () => {
        const rows = [{ timestamp: 10000 }];
        const out = applySkew(rows, -2);
        expect(out[0].correctedTimestamp).toBe(8000);
    });

    test("passes through rows with non-finite timestamps", () => {
        const rows = [{ command: "no time" }, { timestamp: 1000 }];
        const out = applySkew(rows, 5);
        expect(out[0].correctedTimestamp).toBeNull();
        expect(out[1].correctedTimestamp).toBe(6000);
    });

    test("does not mutate input", () => {
        const rows = [{ timestamp: 1000 }];
        applySkew(rows, 5);
        expect(rows[0].correctedTimestamp).toBeUndefined();
    });

    test("returns empty array for non-array input", () => {
        expect(applySkew(null, 5)).toEqual([]);
        expect(applySkew(undefined, 5)).toEqual([]);
    });
});

describe("formatSkewStatus", () => {
    test("formats a positive offset", () => {
        const s = formatSkewStatus({
            offsetSec: 182.8,
            matches: 7,
            totalCommands: 9,
            confidence: 7 / 9,
        });
        expect(s).toContain("+182.8s");
        expect(s).toContain("7/9");
        expect(s).toContain("78%");
    });

    test("formats a negative offset", () => {
        const s = formatSkewStatus({
            offsetSec: -42.3,
            matches: 5,
            totalCommands: 10,
            confidence: 0.5,
        });
        expect(s).toContain("-42.3s");
        expect(s).toContain("5/10");
    });

    test("formats null detection as 'unknown'", () => {
        expect(formatSkewStatus(null)).toContain("unknown");
    });
});

describe("module exports", () => {
    test("exports the documented defaults", () => {
        expect(DEFAULT_OFFSET_RANGE_S).toBe(600);
        expect(DEFAULT_OFFSET_STEP_S).toBe(1);
        expect(DEFAULT_MATCH_TOLERANCE_S).toBe(3.0);
        expect(DEFAULT_MIN_GAP_MS).toBe(200);
    });
});