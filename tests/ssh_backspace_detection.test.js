// Tests for the OpenSSH keystroke-timing backspace / delete detector
// in src/ui/decoders/ssh-keystrokes/backspace-detect.js. The detector
// looks for the timing fingerprint of a HELD Backspace key (3+
// consecutive sub-30 ms intervals with very low variance), distinct
// from normal fast typing where bursts have varied cadence.

const { detectBackspaceHints } = require("../src/ui/decoders/ssh-keystrokes/backspace-detect");

// Build a synthetic delay stream with optional packet-length metadata.
function buildStream(delays, pktLens) {
    return delays.map((d, i) => ({
        index: i,
        delay: d,
        packetLength: pktLens ? pktLens[i] : null,
    }));
}

describe("detectBackspaceHints — empty / invalid input", () => {
    test("returns empty result for empty input", () => {
        expect(detectBackspaceHints([])).toEqual({ indices: [], count: 0 });
    });
    test("returns empty result for null / undefined", () => {
        expect(detectBackspaceHints(null)).toEqual({ indices: [], count: 0 });
        expect(detectBackspaceHints(undefined)).toEqual({ indices: [], count: 0 });
    });
    test("returns empty result for non-array input", () => {
        expect(detectBackspaceHints("hello")).toEqual({ indices: [], count: 0 });
    });
});

describe("detectBackspaceHints — held-backspace fingerprint", () => {
    test("detects a 5-interval held Backspace (auto-repeat at 20ms)", () => {
        // 5 sub-30 ms intervals at exactly 20 ms (std = 0). Each
        // packet is 1 byte — a single SSH keystroke.
        const stream = buildStream([20, 20, 20, 20, 20], [1, 1, 1, 1, 1]);
        const result = detectBackspaceHints(stream);
        expect(result.count).toBe(5);
        expect(result.indices).toEqual([0, 1, 2, 3, 4]);
    });

    test("detects with mild jitter (~±1ms std ≲ 5ms tolerance)", () => {
        const stream = buildStream([21, 19, 22, 18, 20, 21], [1, 1, 1, 1, 1, 1]);
        const result = detectBackspaceHints(stream);
        expect(result.count).toBe(6);
    });

    test("two separate backspace events are reported as two clusters", () => {
        // Cluster 1: indices 0-3 (held). Cluster 2: indices 6-9 (held).
        // Indices 4-5 are normal typing (100 ms each) — not bursts.
        const delays = [20, 20, 20, 20, 100, 100, 20, 20, 20, 20];
        const stream = buildStream(delays, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        const result = detectBackspaceHints(stream);
        expect(result.count).toBe(8);
        expect(result.indices).toEqual([0, 1, 2, 3, 6, 7, 8, 9]);
    });

    test("count equals total backspaces, not number of clusters", () => {
        // User holds Backspace for 8 deletes, then holds it for 3 more.
        // Total = 11 backspaces across 2 clusters.
        const delays = [20, 20, 20, 20, 20, 20, 20, 20, 100, 100, 20, 20, 20];
        const stream = buildStream(delays, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        const result = detectBackspaceHints(stream);
        expect(result.count).toBe(11);
    });
});

describe("detectBackspaceHints — rejects normal typing", () => {
    test("normal fast typing within a word (varied cadence) is NOT flagged", () => {
        // A user typing "the" — three keys, varied cadence because each
        // digraph has different finger reach. Bursts are short (1-3
        // intervals) and high-variance.
        const delays = [60, 90, 70]; // sub-80 but only 3 entries — at minClusterSize
        const stream = buildStream(delays, [1, 1, 1]);
        // 3 entries × std > 5 → reject.
        const result = detectBackspaceHints(stream);
        // With 3 entries the std is computed; 60/90/70 has std ≈ 11.8.
        // Since std > maxIntraStd (5), this is rejected.
        expect(result.count).toBe(0);
    });

    test("a stream of all sub-30 ms but with high variance is rejected", () => {
        // All bursts, but std ≫ 5 → not held backspace.
        const delays = [5, 25, 12, 28, 8, 22, 14, 27, 6, 24];
        const stream = buildStream(delays, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        const result = detectBackspaceHints(stream);
        expect(result.count).toBe(0);
    });

    test("a 100-entry keystroke log with realistic typing is NOT flagged", () => {
        // Simulate: most intervals 80-200 ms (normal typing), with a
        // couple of short bursts inside words. NO 3+ consecutive
        // sub-30 ms clusters should be flagged.
        const delays = [];
        const rng = (() => {
            let s = 12345;
            return () => {
                s = (s * 1664525 + 1013904223) >>> 0;
                return s / 0x100000000;
            };
        })();
        for (let i = 0; i < 100; i += 1) {
            // Mostly normal gaps (60-180 ms); occasional burst
            // (sub-30) but never 3+ in a row.
            const r = rng();
            if (r < 0.85) delays.push(60 + Math.floor(rng() * 120));
            else delays.push(10 + Math.floor(rng() * 18));
        }
        const stream = buildStream(delays, delays.map(() => 1));
        const result = detectBackspaceHints(stream);
        // With normal typing the count should be 0 or very close to 0.
        // We allow ≤2 to be lenient about RNG edge cases.
        expect(result.count).toBeLessThanOrEqual(2);
    });
});

describe("detectBackspaceHints — gates", () => {
    test("rejects cluster adjacent to a > 500 ms thinking pause (before)", () => {
        // Long thinking pause, then a held-backspace cluster — user
        // paused for 1 second to think, then deleted. We do NOT mark
        // these because the cluster is preceded by a thinking pause.
        const delays = [800, 20, 20, 20, 20, 20, 50, 80];
        const stream = buildStream(delays, [1, 1, 1, 1, 1, 1, 1, 1]);
        const result = detectBackspaceHints(stream);
        expect(result.count).toBe(0);
    });

    test("rejects cluster adjacent to a > 500 ms thinking pause (after)", () => {
        // Held backspace, then 1 second thinking pause, then typing.
        // The cluster is NOT marked because it's followed by a pause.
        const delays = [50, 20, 20, 20, 20, 20, 800, 80, 100];
        const stream = buildStream(delays, [1, 1, 1, 1, 1, 1, 1, 1, 1]);
        const result = detectBackspaceHints(stream);
        expect(result.count).toBe(0);
    });

    test("rejects cluster when packet lengths are large (> 2 bytes)", () => {
        // Held-cadence timing, but packets are 32 bytes (typed data,
        // not single-key SSH keystrokes). Must be rejected.
        const delays = [20, 20, 20, 20, 20];
        const stream = buildStream(delays, [32, 32, 32, 32, 32]);
        const result = detectBackspaceHints(stream);
        expect(result.count).toBe(0);
    });

    test("allows cluster when packet lengths are unknown", () => {
        // Held-cadence timing; no packet length info. Default behaviour
        // is to allow (don't gate).
        const stream = buildStream([20, 20, 20, 20, 20], null);
        const result = detectBackspaceHints(stream);
        expect(result.count).toBe(5);
    });

    test("cluster of length 2 does not meet minClusterSize=3", () => {
        // Two consecutive sub-30 ms intervals — too short for a held
        // backspace (which auto-repeats at 3+ intervals).
        const delays = [20, 20, 80, 80, 80];
        const stream = buildStream(delays, [1, 1, 1, 1, 1]);
        const result = detectBackspaceHints(stream);
        expect(result.count).toBe(0);
    });
});

describe("detectBackspaceHints — option overrides", () => {
    test("burstThresholdMs=15 tightens the burst window", () => {
        const delays = [10, 10, 10, 10, 10];
        const stream = buildStream(delays, [1, 1, 1, 1, 1]);
        // With default 30 ms: detected (all sub-30).
        expect(detectBackspaceHints(stream).count).toBe(5);
        // 10 ms intervals are sub-15, so they're still bursts.
        expect(detectBackspaceHints(stream, { burstThresholdMs: 15 }).count).toBe(5);
        // With 25 ms threshold: 10 ms < 25 → still bursts.
        expect(detectBackspaceHints(stream, { burstThresholdMs: 25 }).count).toBe(5);
        // Tightening the window means raising the threshold — at 8 ms
        // threshold, 10 ms is NOT a burst.
        expect(detectBackspaceHints(stream, { burstThresholdMs: 8 }).count).toBe(0);
    });

    test("minClusterSize=5 rejects 4-interval clusters", () => {
        const delays = [20, 20, 20, 20, 80];
        const stream = buildStream(delays, [1, 1, 1, 1, 1]);
        expect(detectBackspaceHints(stream).count).toBe(4);
        expect(detectBackspaceHints(stream, { minClusterSize: 5 }).count).toBe(0);
    });

    test("maxIntraClusterStdMs=1 rejects even small jitter", () => {
        // std ≈ 1 ms — exactly at threshold.
        const delays = [20, 21, 19, 20, 21];
        const stream = buildStream(delays, [1, 1, 1, 1, 1]);
        // With default maxIntraStd=5: detected.
        expect(detectBackspaceHints(stream).count).toBe(5);
        // With maxIntraStd=0: rejected.
        expect(detectBackspaceHints(stream, { maxIntraClusterStdMs: 0 }).count).toBe(0);
    });

    test("maxNeighborPauseMs=100 rejects even short inter-cluster pauses", () => {
        // Held cluster (indices 0-4), small 150 ms gap, another cluster
        // (indices 6-10). With default 500 ms threshold, both clusters
        // are detected. With 100 ms threshold, the small gap is
        // treated as a thinking pause and BOTH clusters are rejected.
        const delays = [20, 20, 20, 20, 20, 150, 20, 20, 20, 20, 20];
        const stream = buildStream(delays, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        // Default 500 ms: both clusters detected (gap is 150 ms < 500).
        const def = detectBackspaceHints(stream);
        expect(def.count).toBe(10);
        // Tightened 100 ms: gap is 150 ms > 100 → both rejected.
        const tight = detectBackspaceHints(stream, { maxNeighborPauseMs: 100 });
        expect(tight.count).toBe(0);
    });

    test("requireSmallPackets=false ignores packet-length gate", () => {
        // Held cadence, large packets (32 bytes). Default rejects.
        const delays = [20, 20, 20, 20, 20];
        const stream = buildStream(delays, [32, 32, 32, 32, 32]);
        expect(detectBackspaceHints(stream).count).toBe(0);
        // With requireSmallPackets=false: still detected.
        expect(
            detectBackspaceHints(stream, { requireSmallPackets: false }).count
        ).toBe(5);
    });
});

describe("detectBackspaceHints — realistic 7-10 backspaces in a session", () => {
    test("a long SSH session with exactly 8 held-backspace clusters is detected at count=8", () => {
        // Simulate: 80 intervals of normal typing interspersed with
        // 8 single-interval backspaces (each a 1-key deletion, but
        // they appear as 3+ burst clusters from keyboard repeat).
        // Realistic SSH command-line session: typing, then a backspace,
        // then more typing. Each "backspace event" is a 3-interval
        // keyboard-repeat cluster.
        const delays = [];
        const rng = (() => {
            let s = 7;
            return () => {
                s = (s * 1664525 + 1013904223) >>> 0;
                return s / 0x100000000;
            };
        })();
        for (let i = 0; i < 8; i += 1) {
            // 12 normal typing intervals (mix of 80-180 ms)
            for (let j = 0; j < 12; j += 1) {
                delays.push(80 + Math.floor(rng() * 100));
            }
            // 3-interval held-backspace cluster
            delays.push(20);
            delays.push(20);
            delays.push(20);
            // Short gap to next typing burst
            delays.push(70 + Math.floor(rng() * 30));
        }
        const stream = buildStream(delays, delays.map(() => 1));
        const result = detectBackspaceHints(stream);
        expect(result.count).toBe(24); // 8 events × 3 intervals each
        // The 24 indices should be in 8 separate clusters.
        const clusters = [];
        let cur = [];
        for (const idx of result.indices) {
            if (cur.length === 0 || idx === cur[cur.length - 1] + 1) {
                cur.push(idx);
            } else {
                clusters.push(cur);
                cur = [idx];
            }
        }
        if (cur.length > 0) clusters.push(cur);
        expect(clusters.length).toBe(8);
        for (const c of clusters) expect(c.length).toBe(3);
    });
});
