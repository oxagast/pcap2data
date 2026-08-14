// ── Backspace / delete-key detection ────────────────────────────────────
//
// The SSH keystroke-timing analyzer needs to know which keystrokes were
// backspaces (so the LLM can reconstruct deletions when scoring
// candidate texts). We don't have the keystroke characters themselves —
// only inter-key delays and packet lengths — so we look for the timing
// fingerprint of a HELD backspace.
//
// Held-backspace fingerprint:
//   - 3+ consecutive sub-`burstThresholdMs` intervals (default 30 ms)
//   - Very low intra-cluster variance (std ≤ `maxIntraClusterStdMs`,
//     default 5 ms) — the OS sends the same auto-repeat key at a fixed
//     rate, so each interval is nearly identical
//   - All known packet lengths are ≤ 2 bytes (single-key SSH payloads)
//   - Cluster is NOT adjacent to a thinking pause (>500 ms gap on either
//     side) — a user who paused isn't holding Backspace across that gap
//
// Why this rejects normal fast typing:
//   - Bursts of varied keystrokes have moderate variance (different
//     finger reach, different keys) — std ≳ 8 ms
//   - Word boundaries sit inside bursts but the burst edges meet
//     non-burst neighbours, not thinking pauses
//   - Some keystrokes carry > 2-byte payloads (autocomplete suggestions,
//     pasted content)
//
// `detectBackspaceHints(delaysWithIdx, opts)` returns:
//   { indices: number[], count: number }
// where `indices` are the `index` fields of the matching entries and
// `count === indices.length`. A cluster of N held-backspace intervals
// contributes N entries — the count reflects how many backspaces
// happened, not how many "events" the cluster represents.
//
// `opts` (all optional):
//   - burstThresholdMs     (default 30)  — max delay to count as a burst
//   - minClusterSize       (default 3)   — minimum consecutive bursts
//   - maxIntraClusterStdMs (default 5)   — max std within the cluster
//   - maxNeighborPauseMs   (default 500) — neighbour must NOT exceed this
//   - requireSmallPackets  (default true) — gate on packet-length ≤ 2

const DEFAULTS = Object.freeze({
    burstThresholdMs: 30,
    minClusterSize: 3,
    maxIntraClusterStdMs: 5,
    maxNeighborPauseMs: 500,
    requireSmallPackets: true,
});

function detectBackspaceHints(delaysWithIdx, opts) {
    if (!Array.isArray(delaysWithIdx) || delaysWithIdx.length === 0) {
        return { indices: [], count: 0 };
    }
    const o = opts || {};
    const burstThreshold = Number.isFinite(o.burstThresholdMs)
        ? o.burstThresholdMs
        : DEFAULTS.burstThresholdMs;
    const minClusterSize = Number.isFinite(o.minClusterSize)
        ? o.minClusterSize
        : DEFAULTS.minClusterSize;
    const maxIntraStd = Number.isFinite(o.maxIntraClusterStdMs)
        ? o.maxIntraClusterStdMs
        : DEFAULTS.maxIntraClusterStdMs;
    const maxNeighborPause = Number.isFinite(o.maxNeighborPauseMs)
        ? o.maxNeighborPauseMs
        : DEFAULTS.maxNeighborPauseMs;
    const requireSmallPackets = o.requireSmallPackets !== false
        ? DEFAULTS.requireSmallPackets
        : false;

    // Find every maximal run of consecutive sub-`burstThreshold` ms
    // intervals. A run of length ≥ minClusterSize is a candidate
    // backspace cluster.
    let runStart = -1;
    const runs = [];
    for (let i = 0; i < delaysWithIdx.length; i += 1) {
        const cur = delaysWithIdx[i];
        const isBurst = cur && Number.isFinite(cur.delay) && cur.delay < burstThreshold;
        if (isBurst) {
            if (runStart < 0) runStart = i;
        } else if (runStart >= 0) {
            runs.push({ start: runStart, end: i - 1 });
            runStart = -1;
        }
    }
    if (runStart >= 0) runs.push({ start: runStart, end: delaysWithIdx.length - 1 });

    const indices = [];
    for (const run of runs) {
        const len = run.end - run.start + 1;
        if (len < minClusterSize) continue;
        // Intra-cluster variance: a held key has nearly identical
        // intervals (std ≲ 2 ms). Varied typing within a word has
        // std ≳ 8 ms. Reject high-variance clusters.
        let mean = 0;
        for (let i = run.start; i <= run.end; i += 1) mean += delaysWithIdx[i].delay;
        mean /= len;
        let variance = 0;
        for (let i = run.start; i <= run.end; i += 1) {
            const d = delaysWithIdx[i].delay - mean;
            variance += d * d;
        }
        variance /= len;
        const std = Math.sqrt(variance);
        if (std > maxIntraStd) continue;
        // Packet-length gate: when packet lengths are known, each
        // backspace is a single-byte SSH keystroke packet. Larger
        // packets (typed-character data from autocomplete, paste
        // payloads) should not be marked.
        if (requireSmallPackets) {
            let knownLengths = 0;
            let allSmall = true;
            for (let i = run.start; i <= run.end; i += 1) {
                const pktLen = delaysWithIdx[i].packetLength;
                if (Number.isFinite(pktLen)) {
                    knownLengths += 1;
                    if (pktLen > 2) allSmall = false;
                }
            }
            // Require at least one known length AND that all known
            // lengths are small. If no lengths are known at all, allow
            // (don't gate) so we still work on capture formats that
            // don't include packet lengths.
            if (knownLengths > 0 && !allSmall) continue;
        }
        // Neighbour-pause gate: a held backspace isn't adjacent to a
        // thinking pause on either side.
        const beforeIdx = run.start - 1;
        const afterIdx = run.end + 1;
        if (beforeIdx >= 0) {
            const before = delaysWithIdx[beforeIdx];
            if (before && Number.isFinite(before.delay) && before.delay > maxNeighborPause) {
                continue;
            }
        }
        if (afterIdx < delaysWithIdx.length) {
            const after = delaysWithIdx[afterIdx];
            if (after && Number.isFinite(after.delay) && after.delay > maxNeighborPause) {
                continue;
            }
        }
        // Cluster qualifies — emit every index.
        for (let i = run.start; i <= run.end; i += 1) {
            indices.push(delaysWithIdx[i].index);
        }
    }

    indices.sort((a, b) => a - b);
    return { indices, count: indices.length };
}

module.exports = {
    detectBackspaceHints,
    DEFAULTS,
};
