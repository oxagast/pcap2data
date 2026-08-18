// Tests for the truth-alignment helper.
// See src/ui/decoders/ssh-keystrokes/truth-align.js.

const {
    alignTruthToChunks,
    chunkStartTimesFromDelays,
} = require("../src/ui/decoders/ssh-keystrokes/truth-align");

describe("alignTruthToChunks", () => {
    test("returns empty array for non-array input", () => {
        expect(alignTruthToChunks(null, [0, 1000])).toEqual([]);
        expect(alignTruthToChunks(undefined, [0, 1000])).toEqual([]);
    });

    test("returns rows with chunkIdx=null when no chunks available", () => {
        const rows = [{ correctedTimestamp: 100 }, { correctedTimestamp: 200 }];
        const out = alignTruthToChunks(rows, []);
        expect(out).toEqual([
            { correctedTimestamp: 100, chunkIdx: null },
            { correctedTimestamp: 200, chunkIdx: null },
        ]);
    });

    test("pins timestamps before the first chunk to chunk 0", () => {
        const rows = [{ correctedTimestamp: -500 }];
        const out = alignTruthToChunks(rows, [0, 1000, 2000]);
        expect(out[0].chunkIdx).toBe(0);
    });

    test("pins timestamps after the last chunk to the last chunk", () => {
        const rows = [{ correctedTimestamp: 5000 }];
        const out = alignTruthToChunks(rows, [0, 1000, 2000]);
        expect(out[0].chunkIdx).toBe(2);
    });

    test("distributes timestamps across chunk windows", () => {
        const rows = [
            { correctedTimestamp: 500 },   // chunk 0 [0..1000)
            { correctedTimestamp: 1500 },  // chunk 1 [1000..2000)
            { correctedTimestamp: 2500 },  // chunk 2 [2000..+inf)
        ];
        const out = alignTruthToChunks(rows, [0, 1000, 2000]);
        expect(out.map((r) => r.chunkIdx)).toEqual([0, 1, 2]);
    });

    test("two truth rows can map to the same chunk", () => {
        const rows = [
            { correctedTimestamp: 100 },
            { correctedTimestamp: 900 },
        ];
        const out = alignTruthToChunks(rows, [0, 1000]);
        expect(out.map((r) => r.chunkIdx)).toEqual([0, 0]);
    });

    test("rows without correctedTimestamp get chunkIdx=null", () => {
        const rows = [
            { command: "no time" },
            { correctedTimestamp: 500 },
        ];
        const out = alignTruthToChunks(rows, [0, 1000]);
        expect(out[0].chunkIdx).toBeNull();
        expect(out[1].chunkIdx).toBe(0);
    });

    test("does not mutate input rows", () => {
        const rows = [{ correctedTimestamp: 500, chunkIdx: 99 }];
        alignTruthToChunks(rows, [0, 1000]);
        expect(rows[0].chunkIdx).toBe(99);
    });

    test("handles unsorted chunk times by sorting internally", () => {
        const rows = [{ correctedTimestamp: 1500 }];
        const out = alignTruthToChunks(rows, [2000, 0, 1000]);
        expect(out[0].chunkIdx).toBe(1);
    });

    test("matches at the chunk boundary (chunkTimes[i] <= t)", () => {
        // t == chunkTimes[1] should pin to chunk 1, not chunk 0.
        const rows = [{ correctedTimestamp: 1000 }];
        const out = alignTruthToChunks(rows, [0, 1000, 2000]);
        expect(out[0].chunkIdx).toBe(1);
    });
});

describe("chunkStartTimesFromDelays", () => {
    test("returns empty array for empty chunks", () => {
        expect(chunkStartTimesFromDelays([], [{ index: 0 }], [1000])).toEqual([]);
    });

    test("maps startIdx → delaysWithIdx → packet timestamp", () => {
        const chunks = [{ startIdx: 0 }, { startIdx: 2 }];
        const delaysWithIdx = [
            { index: 0 },
            { index: 1 },
            { index: 5 },
            { index: 6 },
        ];
        const packetTimes = [100, 200, 300, 400, 500, 600, 700];
        const out = chunkStartTimesFromDelays(chunks, delaysWithIdx, packetTimes);
        expect(out).toEqual([100, 600]);
    });

    test("returns null for chunks with bad startIdx", () => {
        const chunks = [{ startIdx: 99 }, { startIdx: 0 }];
        const delaysWithIdx = [{ index: 0 }];
        const packetTimes = [1000];
        const out = chunkStartTimesFromDelays(chunks, delaysWithIdx, packetTimes);
        expect(out).toEqual([null, 1000]);
    });

    test("returns null for delays with non-integer index", () => {
        const chunks = [{ startIdx: 0 }];
        const delaysWithIdx = [{ index: "not a number" }];
        const packetTimes = [1000];
        const out = chunkStartTimesFromDelays(chunks, delaysWithIdx, packetTimes);
        expect(out).toEqual([null]);
    });

    test("returns null entries when packet timestamps are missing", () => {
        const chunks = [{ startIdx: 0 }];
        const delaysWithIdx = [{ index: 5 }];
        const packetTimes = [100, 200, 300]; // length 3, index 5 is OOB
        const out = chunkStartTimesFromDelays(chunks, delaysWithIdx, packetTimes);
        expect(out).toEqual([null]);
    });
});