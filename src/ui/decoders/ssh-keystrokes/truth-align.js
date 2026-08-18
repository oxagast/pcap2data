// Truth-alignment helpers: match each typed-transcript command to a
// chunk produced by the chunker, using absolute PCAP timestamps.
//
// The auto-calibrate orchestrator scores per-command predictions
// against the typed truth. When the chunker produces N chunks and
// the transcript has M commands, the orchestrator can't tell which
// truth row goes with which chunk — it falls back to a noise-prone
// prediction-vs-truth similarity fallback. With timestamp alignment,
// each truth row carries a ``chunkIdx`` that pins it to the right
// chunk, so the orchestrator can score accurately even when the
// counts differ (N < M or N > M).
//
// This module is pure CommonJS — no DOM, no Electron — so it can be
// unit-tested without standing up the renderer.

"use strict";

/**
 * Given an ordered list of chunk timestamps (ms) and a list of
 * transcript rows each carrying a ``correctedTimestamp`` (ms),
 * return a new list of truth rows with ``chunkIdx`` populated
 * according to which chunk window each timestamp falls in.
 *
 * Algorithm:
 *
 *   - Chunk windows are half-open: chunk i covers
 *     ``[chunkTimes[i], chunkTimes[i+1])``. The last chunk covers
 *     ``[chunkTimes[N-1], +Infinity)`` — the user's most recent
 *     command may not yet have hit Enter.
 *   - When a truth timestamp falls **before** the first chunk's
 *     start, it's pinned to chunk 0 (the user typed before we
 *     started capturing — best we can do is "first chunk").
 *   - When a truth timestamp falls **after** the last chunk's
 *     start, it's pinned to the last chunk.
 *   - Two truth rows can map to the same chunk (sub-chunk typing
 *     or the chunker under-splitting); one truth row can never
 *     span multiple chunks under this scheme. The caller decides
 *     how to handle over-subscription.
 *
 * @param {Array<{correctedTimestamp?: number}>} rows  Transcript rows.
 * @param {number[]} chunkTimesMs                     Chunk start times (ms).
 *                                                   Must be ascending.
 * @returns {Array} New rows with ``chunkIdx`` set.
 */
function alignTruthToChunks(rows, chunkTimesMs) {
    if (!Array.isArray(rows)) return [];
    if (!Array.isArray(chunkTimesMs) || chunkTimesMs.length === 0) {
        // No chunks — caller is in trouble anyway. Pass rows through
        // with chunkIdx: null so downstream code can fall back to
        // index-based matching.
        return rows.map((row) => Object.assign({}, row, { chunkIdx: null }));
    }
    const sortedChunks = chunkTimesMs.slice().sort((a, b) => a - b);
    return rows.map((row) => {
        const out = Object.assign({}, row);
        if (!Number.isFinite(row.correctedTimestamp)) {
            out.chunkIdx = null;
            return out;
        }
        // Binary search the chunk window containing this timestamp.
        const t = row.correctedTimestamp;
        let lo = 0;
        let hi = sortedChunks.length - 1;
        let pinned = 0;
        if (t < sortedChunks[0]) {
            pinned = 0;
        } else if (t >= sortedChunks[sortedChunks.length - 1]) {
            pinned = sortedChunks.length - 1;
        } else {
            // Find the largest i with chunkTimes[i] <= t.
            while (lo <= hi) {
                const mid = (lo + hi) >>> 1;
                if (sortedChunks[mid] <= t) {
                    pinned = mid;
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
        }
        out.chunkIdx = pinned;
        return out;
    });
}

/**
 * Extract chunk start timestamps (ms) from a chunk list, using
 * ``startIdx`` indices into ``delaysWithIdx`` and a parallel array
 * of packet timestamps for the direction-filtered packet list.
 *
 * @param {Array<{startIdx: number}>} chunks        Chunk list.
 * @param {Array<{index: number}>} delaysWithIdx    Delays w/ packet indices.
 * @param {number[]} packetTimestampsMs             Sorted per-packet
 *                                                  timestamps (filtered).
 * @returns {number[]} Chunk start times (ms), one per chunk.
 */
function chunkStartTimesFromDelays(chunks, delaysWithIdx, packetTimestampsMs) {
    if (!Array.isArray(chunks) || chunks.length === 0) return [];
    if (!Array.isArray(delaysWithIdx) || !Array.isArray(packetTimestampsMs)) {
        return [];
    }
    const out = [];
    for (const chunk of chunks) {
        if (!chunk || !Number.isInteger(chunk.startIdx)) {
            out.push(null);
            continue;
        }
        const d = delaysWithIdx[chunk.startIdx];
        if (!d || !Number.isInteger(d.index)) {
            out.push(null);
            continue;
        }
        // ``d.index`` is the index of the packet that *ended* the
        // previous interval within the filtered packet list. The
        // chunk *starts* at the packet AFTER that interval, which is
        // d.index (the next packet to arrive after the gap).
        // So ``packetTimestampsMs[d.index]`` is the right timestamp.
        const ts = packetTimestampsMs[d.index];
        out.push(Number.isFinite(ts) ? ts : null);
    }
    return out;
}

module.exports = {
    alignTruthToChunks,
    chunkStartTimesFromDelays,
};