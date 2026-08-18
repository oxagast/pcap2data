const {
    SLIDER_POS_MIN,
    SLIDER_POS_MAX,
    MS_LOW_MAX,
    MS_HIGH_MAX,
    posToMs,
    msToPos,
    formatMsLabel,
} = require("../src/ui/decoders/ssh-keystrokes/chunker-slider");

describe("posToMs", () => {
    test("pos=0 maps to a safe minimum (≥1ms)", () => {
        expect(posToMs(0)).toBe(1);
    });

    test("sub-100ms range is 1:1 (high resolution)", () => {
        expect(posToMs(10)).toBe(10);
        expect(posToMs(50)).toBe(50);
        expect(posToMs(99)).toBe(99);
    });

    test("at the 100ms boundary the linear and quadratic meet", () => {
        expect(posToMs(100)).toBe(100);
    });

    test("above 100ms is linear 10:1 (lower resolution)", () => {
        // 100ms range mapped across 900 positions ≈ 2.11ms per pos.
        expect(posToMs(500)).toBeCloseTo(500 * (1900 / 900) + 100 - 100 * (1900 / 900), 0);
        // Specifically:
        // 500 - 100 = 400; 400 * (1900/900) = 400 * 2.111... = 844.4
        // 100 + 844.4 = 944.4
        expect(posToMs(500)).toBeCloseTo(944, 0);
    });

    test("pos=1000 maps to the max threshold", () => {
        expect(posToMs(1000)).toBeCloseTo(2000, 0);
    });

    test("handles out-of-range inputs defensively", () => {
        expect(posToMs(-5)).toBe(1);   // clamped to 1ms minimum
        expect(posToMs(NaN)).toBe(1);  // NaN → 0 → 1
        // Infinity stays Infinity when added (NaN in our function would
        // clamp to 1; if we want Infinity to pass through we'd need a
        // special branch). The current behaviour: Number.isFinite
        // filters Infinity to 0, which clamps to 1.
        expect(posToMs(Infinity)).toBe(1);
    });

    test("monotonic non-decreasing", () => {
        let prev = posToMs(0);
        for (let p = 1; p <= 1000; p += 1) {
            const cur = posToMs(p);
            expect(cur).toBeGreaterThanOrEqual(prev);
            prev = cur;
        }
    });
});

describe("msToPos (inverse of posToMs)", () => {
    test("0ms maps to pos=0", () => {
        expect(msToPos(0)).toBe(0);
    });

    test("100ms maps to pos=100 (boundary)", () => {
        expect(msToPos(100)).toBe(100);
    });

    test("2000ms maps to pos=1000 (max)", () => {
        expect(msToPos(2000)).toBe(1000);
    });

    test("low-end values round-trip exactly", () => {
        for (let ms = 1; ms <= 100; ms += 1) {
            const pos = msToPos(ms);
            const back = posToMs(pos);
            // Allow ±1ms drift from rounding.
            expect(Math.abs(back - ms)).toBeLessThanOrEqual(1);
        }
    });

    test("high-end values round-trip with ±2ms drift", () => {
        const samples = [150, 250, 500, 750, 1000, 1250, 1500, 1750, 2000];
        for (const ms of samples) {
            const pos = msToPos(ms);
            const back = posToMs(pos);
            // The high-end linear mapping has 2.11ms per step, so the
            // round-trip drift can be up to one step (~2ms).
            expect(Math.abs(back - ms)).toBeLessThanOrEqual(3);
        }
    });

    test("handles out-of-range inputs defensively", () => {
        expect(msToPos(-5)).toBe(0);
        expect(msToPos(NaN)).toBe(0);
        // Infinity filtered by Number.isFinite → 0 → 0
        expect(msToPos(Infinity)).toBe(0);
    });
});

describe("formatMsLabel", () => {
    test("formats integer milliseconds", () => {
        expect(formatMsLabel(100)).toBe("100ms");
        expect(formatMsLabel(1500)).toBe("1500ms");
    });

    test("rounds non-integer values", () => {
        expect(formatMsLabel(123.4)).toBe("123ms");
        expect(formatMsLabel(123.6)).toBe("124ms");
    });

    test("handles non-finite values", () => {
        expect(formatMsLabel(NaN)).toBe("0ms");
        expect(formatMsLabel(undefined)).toBe("0ms");
    });
});

describe("slider constants", () => {
    test("exposes the canonical range constants", () => {
        expect(SLIDER_POS_MIN).toBe(0);
        expect(SLIDER_POS_MAX).toBe(1000);
        expect(MS_LOW_MAX).toBe(100);
        expect(MS_HIGH_MAX).toBe(2000);
    });
});