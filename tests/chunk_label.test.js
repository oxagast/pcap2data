const {
    formatHmsUtc,
    formatFallbackLabel,
    resolveChunkStartTimestamp,
    formatChunkStartLabel,
    formatChunkLabelCell,
} = require("../src/ui/decoders/ssh-keystrokes/chunk-label");

describe("formatHmsUtc", () => {
    test("formats a known timestamp in UTC", () => {
        // 2024-01-15T12:34:56.789Z
        const ts = Date.UTC(2024, 0, 15, 12, 34, 56, 789);
        expect(formatHmsUtc(ts)).toBe("12:34:56.789");
    });

    test("zero-pads single-digit fields", () => {
        const ts = Date.UTC(2024, 0, 1, 1, 2, 3, 4);
        expect(formatHmsUtc(ts)).toBe("01:02:03.004");
    });

    test("returns placeholder for non-finite input", () => {
        expect(formatHmsUtc(NaN)).toBe("—");
        expect(formatHmsUtc(Infinity)).toBe("—");
        expect(formatHmsUtc(-Infinity)).toBe("—");
    });

    test("returns placeholder for negative input", () => {
        expect(formatHmsUtc(-1)).toBe("—");
    });

    test("returns placeholder for invalid Date", () => {
        // Construct a number that yields NaN from getTime
        expect(formatHmsUtc(Number.MAX_SAFE_INTEGER)).toBe("—");
    });
});

describe("formatFallbackLabel", () => {
    test("prefers packet position when both are integer", () => {
        expect(formatFallbackLabel(42, 7)).toBe("p#7");
    });

    test("falls back to delay position when packet is missing", () => {
        expect(formatFallbackLabel(42, null)).toBe("d#42");
    });

    test("returns em-dash when both are missing", () => {
        expect(formatFallbackLabel(null, null)).toBe("—");
    });

    test("treats non-integer packetPos as missing", () => {
        expect(formatFallbackLabel(42, 7.5)).toBe("d#42");
    });
});

describe("resolveChunkStartTimestamp", () => {
    const packets = [
        { timestamp: 100 },
        { timestamp: 200 },
        { timestamp: 300 },
        { timestamp: 400 },
    ];
    const delaysWithIdx = [
        { delay: 50, index: 0 },
        { delay: 60, index: 1 },
        { delay: 70, index: 2 },
        { delay: 80, index: 3 },
    ];

    test("resolves ts via delay.index → packet", () => {
        const r = resolveChunkStartTimestamp({
            flowKey: "k",
            startDelayPos: 1,
            delaysWithIdx,
            getFlowPackets: () => packets,
        });
        expect(r).toEqual({ tsMs: 200, delayPos: 1, packetPos: 1 });
    });

    test("returns null when startDelayPos is non-integer", () => {
        expect(resolveChunkStartTimestamp({
            flowKey: "k",
            startDelayPos: null,
            delaysWithIdx,
            getFlowPackets: () => packets,
        })).toBeNull();
    });

    test("returns null when startDelayPos is negative", () => {
        expect(resolveChunkStartTimestamp({
            flowKey: "k",
            startDelayPos: -1,
            delaysWithIdx,
            getFlowPackets: () => packets,
        })).toBeNull();
    });

    test("returns null when startDelayPos is out of range", () => {
        expect(resolveChunkStartTimestamp({
            flowKey: "k",
            startDelayPos: 99,
            delaysWithIdx,
            getFlowPackets: () => packets,
        })).toBeNull();
    });

    test("returns null when delaysWithIdx is not an array", () => {
        expect(resolveChunkStartTimestamp({
            flowKey: "k",
            startDelayPos: 0,
            delaysWithIdx: null,
            getFlowPackets: () => packets,
        })).toBeNull();
    });

    test("returns fallback when getFlowPackets returns null", () => {
        const r = resolveChunkStartTimestamp({
            flowKey: "k",
            startDelayPos: 1,
            delaysWithIdx,
            getFlowPackets: () => null,
        });
        expect(r).toEqual({ tsMs: null, delayPos: 1, packetPos: 1 });
    });

    test("returns fallback when packetPos is missing in delay row", () => {
        const r = resolveChunkStartTimestamp({
            flowKey: "k",
            startDelayPos: 1,
            delaysWithIdx: [
                { delay: 50, index: 0 },
                { delay: 60 /* no index */ },
            ],
            getFlowPackets: () => packets,
        });
        expect(r).toEqual({ tsMs: null, delayPos: 1, packetPos: null });
    });

    test("returns fallback when packet lacks timestamp", () => {
        const r = resolveChunkStartTimestamp({
            flowKey: "k",
            startDelayPos: 1,
            delaysWithIdx: [
                { delay: 50, index: 0 },
                { delay: 60, index: 1 },
            ],
            getFlowPackets: () => [{}, {}],
        });
        expect(r).toEqual({ tsMs: null, delayPos: 1, packetPos: 1 });
    });

    test("returns fallback when packetPos is out of packets range", () => {
        const r = resolveChunkStartTimestamp({
            flowKey: "k",
            startDelayPos: 1,
            delaysWithIdx: [
                { delay: 50, index: 0 },
                { delay: 60, index: 99 },
            ],
            getFlowPackets: () => packets,
        });
        expect(r).toEqual({ tsMs: null, delayPos: 1, packetPos: 99 });
    });
});

describe("formatChunkStartLabel", () => {
    const packets = [
        { timestamp: Date.UTC(2024, 0, 15, 12, 34, 56, 789) },
        { timestamp: Date.UTC(2024, 0, 15, 12, 35, 1, 0) },
    ];
    const delaysWithIdx = [
        { delay: 50, index: 0 },
        { delay: 60, index: 1 },
    ];

    test("returns formatted timestamp when chain is intact", () => {
        expect(formatChunkStartLabel({
            flowKey: "k",
            startDelayPos: 1,
            delaysWithIdx,
            getFlowPackets: () => packets,
        })).toBe("12:35:01.000");
    });

    test("falls back to packet position label when timestamp is missing", () => {
        expect(formatChunkStartLabel({
            flowKey: "k",
            startDelayPos: 1,
            delaysWithIdx: [{ delay: 50, index: 0 }, { delay: 60, index: 1 }],
            getFlowPackets: () => [{}, {}],
        })).toBe("p#1");
    });

    test("falls back to delay position when packet index is missing", () => {
        expect(formatChunkStartLabel({
            flowKey: "k",
            startDelayPos: 1,
            delaysWithIdx: [{ delay: 50, index: 0 }, { delay: 60 }],
            getFlowPackets: () => packets,
        })).toBe("d#1");
    });

    test("returns em-dash when startDelayPos is null", () => {
        expect(formatChunkStartLabel({
            flowKey: "k",
            startDelayPos: null,
            delaysWithIdx,
            getFlowPackets: () => packets,
        })).toBe("—");
    });

    test("treats missing getFlowPackets as no-flow fallback", () => {
        expect(formatChunkStartLabel({
            flowKey: "k",
            startDelayPos: 1,
            delaysWithIdx: [{ delay: 50, index: 0 }, { delay: 60, index: 99 }],
            // No getFlowPackets at all → panel never provides a flow
        })).toBe("—");
    });
});

describe("formatChunkLabelCell", () => {
    test("surfaces cached top text with title attribute", () => {
        const r = formatChunkLabelCell({
            cachedTopText: "ls -la /tmp",
            maxGapMs: 300,
        });
        expect(r.text).toBe("→ ls -la /tmp");
        expect(r.title).toBe("ls -la /tmp");
    });

    test("falls back to gap label when no cached top exists", () => {
        const r = formatChunkLabelCell({
            cachedTopText: null,
            maxGapMs: 412.7,
        });
        expect(r.text).toBe("→ gap 413ms");
        expect(r.title).toBeNull();
    });

    test("treats empty string as missing", () => {
        const r = formatChunkLabelCell({
            cachedTopText: "",
            maxGapMs: 200,
        });
        expect(r.text).toBe("→ gap 200ms");
    });

    test("returns placeholder when nothing is available", () => {
        const r = formatChunkLabelCell({
            cachedTopText: null,
            maxGapMs: null,
        });
        expect(r.text).toBe("→ (no cached top)");
        expect(r.title).toBeNull();
    });
});