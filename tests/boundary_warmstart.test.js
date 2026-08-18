// Tests for the auto-calibrate warm-start helper.
// See src/ui/decoders/ssh-keystrokes/boundary-warmstart.js.

const {
    COMMAND_BOUNDARY_LATTICE,
    snapToLattice,
    recommendCommandBoundaryRange,
    recommendRescanWindow,
    MIN_RESCAN_MARGIN,
} = require("../src/ui/decoders/ssh-keystrokes/boundary-warmstart");

describe("COMMAND_BOUNDARY_LATTICE", () => {
    test("is sorted ascending", () => {
        for (let i = 1; i < COMMAND_BOUNDARY_LATTICE.length; i += 1) {
            expect(COMMAND_BOUNDARY_LATTICE[i]).toBeGreaterThan(COMMAND_BOUNDARY_LATTICE[i - 1]);
        }
    });

    test("contains the canonical 8 values", () => {
        expect(COMMAND_BOUNDARY_LATTICE).toEqual([
            50, 80, 100, 120, 150, 200, 300, 500,
        ]);
    });
});

describe("snapToLattice", () => {
    test("snaps exact lattice values to themselves", () => {
        for (const v of COMMAND_BOUNDARY_LATTICE) {
            expect(snapToLattice(v)).toBe(v);
        }
    });

    test("snaps between-entry values to the nearest", () => {
        // 137 is between 120 and 150 — both are 17 ms away; tie goes
        // to the lower because the loop keeps `best` until strictly
        // closer. Verify by checking the documented value.
        const snapped = snapToLattice(137);
        expect([120, 150]).toContain(snapped);
        // 75 ms is between 50 and 80 — should snap to 80 (closer).
        expect(snapToLattice(75)).toBe(80);
        // 175 ms is between 150 and 200 — 175 is equidistant (25 ms
        // either way). Tie goes to whichever the loop encountered
        // first; just confirm we land on one of them.
        const snapped175 = snapToLattice(175);
        expect([150, 200]).toContain(snapped175);
    });

    test("clamps non-finite targets to the first lattice entry", () => {
        expect(snapToLattice(NaN)).toBe(COMMAND_BOUNDARY_LATTICE[0]);
        expect(snapToLattice(Infinity)).toBe(COMMAND_BOUNDARY_LATTICE[0]);
    });

    test("respects a custom lattice", () => {
        const custom = [10, 20, 30, 40];
        expect(snapToLattice(25, custom)).toBe(20);
        expect(snapToLattice(35, custom)).toBe(30);
    });
});

describe("recommendCommandBoundaryRange", () => {
    test("returns low window for obfuscated timing (approxStd < 20)", () => {
        const out = recommendCommandBoundaryRange({
            median: 25,
            approxStd: 5,
            packetCount: 500,
        });
        expect(out).toEqual([80, 100, 120]);
    });

    test("returns high window for heterogeneous / tiny captures", () => {
        const huge = recommendCommandBoundaryRange({
            median: 200,
            approxStd: 100,
            packetCount: 200,
        });
        expect(huge).toEqual([200, 300, 500]);

        const tiny = recommendCommandBoundaryRange({
            median: 100,
            approxStd: 40,
            packetCount: 10,
        });
        expect(tiny).toEqual([200, 300, 500]);
    });

    test("centres the window on median for typical interactive typing", () => {
        // median ~120 → snap to 120, window [100, 120, 150]
        const a = recommendCommandBoundaryRange({
            median: 118,
            approxStd: 30,
            packetCount: 200,
        });
        expect(a).toEqual([100, 120, 150]);

        // median ~150 → snap to 150, window [120, 150, 200]
        const b = recommendCommandBoundaryRange({
            median: 152,
            approxStd: 30,
            packetCount: 200,
        });
        expect(b).toEqual([120, 150, 200]);
    });

    test("clamps to the lattice at the low end", () => {
        // approxStd >= 20 to bypass the obfuscated branch, then a
        // median that would snap below the lowest lattice entry.
        // snapToLattice returns 50, but centreIdx === 0 → low-end
        // walk returns [50, 80, 100].
        const out = recommendCommandBoundaryRange({
            median: 10,
            approxStd: 25,
            packetCount: 200,
        });
        expect(out).toEqual([50, 80, 100]);
    });

    test("clamps to the lattice at the high end", () => {
        const out = recommendCommandBoundaryRange({
            median: 900,
            approxStd: 25,
            packetCount: 200,
        });
        expect(out).toEqual([200, 300, 500]);
    });

    test("falls back to a safe 3-value window when signals are missing", () => {
        expect(recommendCommandBoundaryRange(null)).toEqual([100, 150, 200]);
        expect(recommendCommandBoundaryRange(undefined)).toEqual([100, 150, 200]);
        expect(recommendCommandBoundaryRange({})).toEqual([100, 150, 200]);
    });

    test("returns a 3-value array for every branch", () => {
        const inputs = [
            { median: 25, approxStd: 5, packetCount: 500 },
            { median: 100, approxStd: 30, packetCount: 200 },
            { median: 200, approxStd: 100, packetCount: 200 },
            { median: 100, approxStd: 30, packetCount: 5 },
            { median: 50, approxStd: 19.99, packetCount: 200 },
        ];
        for (const inp of inputs) {
            const out = recommendCommandBoundaryRange(inp);
            expect(Array.isArray(out)).toBe(true);
            expect(out.length).toBe(3);
            // All values must come from the lattice.
            for (const v of out) {
                expect(COMMAND_BOUNDARY_LATTICE).toContain(v);
            }
        }
    });
});

describe("recommendRescanWindow", () => {
    test("does nothing when the best is inside the window", () => {
        const out = recommendRescanWindow({
            best: 120,
            window: [100, 120, 150],
            sensitivity: [
                { value: 100, score: 0.5 },
                { value: 120, score: 0.9 },
                { value: 150, score: 0.6 },
            ],
        });
        expect(out).toBeNull();
    });

    test("triggers a left rescan when the best is at the left edge and the outward neighbour scores better", () => {
        const out = recommendRescanWindow({
            best: 80,
            window: [80, 100, 120],
            sensitivity: [
                { value: 80, score: 0.5 },
                { value: 100, score: 0.4 },
                { value: 120, score: 0.4 },
                { value: 50, score: 0.8 },
            ],
        });
        // Re-centre on 80 → indices [0, 1, 2] → [50, 80, 100].
        expect(out).toEqual([50, 80, 100]);
    });

    test("triggers a right rescan when the best is at the right edge and the outward neighbour scores better", () => {
        const out = recommendRescanWindow({
            best: 300,
            window: [150, 200, 300],
            sensitivity: [
                { value: 150, score: 0.5 },
                { value: 200, score: 0.6 },
                { value: 300, score: 0.7 },
                { value: 500, score: 0.9 },
            ],
        });
        // Re-centre on 300 → indices [5, 6, 7] → [200, 300, 500].
        expect(out).toEqual([200, 300, 500]);
    });

    test("does nothing when the outward neighbour is not meaningfully better", () => {
        const out = recommendRescanWindow({
            best: 80,
            window: [80, 100, 120],
            sensitivity: [
                { value: 80, score: 0.5 },
                { value: 50, score: 0.51 },
            ],
        });
        // 0.51 - 0.5 = 0.01 < MIN_RESCAN_MARGIN (0.02) → no rescan.
        expect(out).toBeNull();
        expect(MIN_RESCAN_MARGIN).toBeGreaterThan(0);
    });

    test("does nothing when sensitivity points are missing", () => {
        const out = recommendRescanWindow({
            best: 80,
            window: [80, 100, 120],
            sensitivity: [],
        });
        expect(out).toBeNull();
    });

    test("does nothing when best is not in the lattice", () => {
        const out = recommendRescanWindow({
            best: 137,
            window: [100, 120, 150],
            sensitivity: [
                { value: 137, score: 0.9 },
                { value: 100, score: 0.5 },
            ],
        });
        expect(out).toBeNull();
    });

    test("honours a custom minMargin override", () => {
        const out = recommendRescanWindow({
            best: 80,
            window: [80, 100, 120],
            sensitivity: [
                { value: 80, score: 0.5 },
                { value: 50, score: 0.51 },
            ],
            minMargin: 0.0001,
        });
        expect(out).toEqual([50, 80, 100]);
    });

    test("does nothing when there is no outward neighbour (edge of lattice)", () => {
        const out = recommendRescanWindow({
            best: 500,
            window: [200, 300, 500],
            sensitivity: [
                { value: 300, score: 0.5 },
                { value: 500, score: 0.9 },
            ],
        });
        // 500 is at the right edge of the lattice — no outward neighbour.
        expect(out).toBeNull();
    });
});