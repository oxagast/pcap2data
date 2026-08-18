// Clock-skew detection + correction between a typed-command transcript
// and an SSH packet capture.
//
// The transcript is generated on the SSH server (e.g. by `script` or
// shell history timestamping), while the PCAP is captured on the
// client or a network tap. The two clocks routinely drift by seconds
// to minutes. Without correction, the auto-calibrate orchestrator
// scores transcript commands against entirely the wrong chunk
// boundaries and picks noise as its "best knob vector".
//
// This module is pure CommonJS — no DOM, no Electron — so it can be
// unit-tested without standing up the renderer.

"use strict";

// Default search range: ±10 minutes is enough for any plausible NTP
// drift between two hosts on the same network. We step in 1s
// increments (a few thousand candidates — fast enough).
const DEFAULT_OFFSET_RANGE_S = 600;
const DEFAULT_OFFSET_STEP_S = 1;

// Tolerance when matching a shifted transcript timestamp to a large
// PCAP gap. 3 seconds is generous: the gap to Enter mapping has at
// least one round-trip's worth of jitter.
const DEFAULT_MATCH_TOLERANCE_S = 3.0;

// Minimum gap size (ms) to consider as a candidate command boundary.
// Below this, the gap is indistinguishable from intra-command
// keystroke cadence.
const DEFAULT_MIN_GAP_MS = 200;

/**
 * Build the list of large-gap times from a sequence of per-packet
 * timestamps. Returns absolute milliseconds (matching the `timestamp`
 * field on transcript rows).
 *
 * @param {number[]} pcapTimestampsMs  Sorted per-packet timestamps (ms).
 * @param {number} [minGapMs=200]      Minimum gap to record (ms).
 * @returns {Array<{ timeMs, gapMs }>}
 *   Each entry is the absolute timestamp of the packet that *ended*
 *   the gap (the moment the next packet arrived — which is when the
 *   user's typing resumed, i.e. right after Enter) plus the gap size.
 */
function extractLargeGaps(pcapTimestampsMs, minGapMs) {
    const floor = (Number.isFinite(minGapMs) && minGapMs > 0)
        ? minGapMs
        : DEFAULT_MIN_GAP_MS;
    if (!Array.isArray(pcapTimestampsMs) || pcapTimestampsMs.length < 2) return [];
    const out = [];
    for (let i = 1; i < pcapTimestampsMs.length; i += 1) {
        const gap = pcapTimestampsMs[i] - pcapTimestampsMs[i - 1];
        if (gap >= floor) {
            out.push({ timeMs: pcapTimestampsMs[i], gapMs: gap });
        }
    }
    return out;
}

/**
 * Compute the alignment score for a single candidate offset. The
 * score is the **count** of transcript commands whose shifted
 * timestamp lands within tolerance of any large gap, with a small
 * bonus for matching bigger gaps (so two near-tied candidates pick
 * the one with stronger alignment).
 *
 * @param {number[]} transcriptTimesMs  Command timestamps (ms).
 * @param {Array<{timeMs, gapMs}>} largeGaps  Pre-extracted large gaps.
 * @param {number} offsetSec             Candidate offset in seconds.
 * @param {number} [toleranceSec=3]      Per-gap match tolerance.
 * @returns {number} Score (higher is better).
 */
function scoreAlignment(transcriptTimesMs, largeGaps, offsetSec, toleranceSec) {
    const tol = (Number.isFinite(toleranceSec) && toleranceSec > 0)
        ? toleranceSec
        : DEFAULT_MATCH_TOLERANCE_S;
    if (!Array.isArray(transcriptTimesMs) || transcriptTimesMs.length === 0) return 0;
    if (!Array.isArray(largeGaps) || largeGaps.length === 0) return 0;
    let score = 0;
    const offsetMs = offsetSec * 1000;
    for (const ts of transcriptTimesMs) {
        if (!Number.isFinite(ts)) continue;
        const target = ts + offsetMs;
        let bestDist = Infinity;
        let bestGap = 0;
        for (const g of largeGaps) {
            const d = Math.abs(g.timeMs - target);
            if (d <= tol * 1000 && d < bestDist) {
                bestDist = d;
                bestGap = g.gapMs;
            }
        }
        if (bestDist !== Infinity) {
            // +1 for the match, +log10(gapMs/100) bonus for big gaps
            // so 5s gaps outrank 200ms gaps when ties are close.
            score += 1 + Math.log10(Math.max(1, bestGap / 100));
        }
    }
    return score;
}

/**
 * Detect the clock skew (in seconds) that best aligns a list of
 * transcript command timestamps to a packet capture's gap sequence.
 *
 * Returns `{ offsetSec, score, matches, candidatesScanned }`. When
 * the transcript is empty, has no parsable timestamps, or the PCAP
 * has no large gaps, returns `null` — the caller should treat null as
 * "no skew could be inferred" and not auto-correct.
 *
 * @param {object} args
 * @param {Array<{timestamp?: number}>} args.transcriptRows
 * @param {number[]} args.pcapTimestampsMs Sorted per-packet timestamps (ms).
 * @param {number} [args.offsetRangeSec=600] Search range ±this many seconds.
 * @param {number} [args.offsetStepSec=1] Grid step.
 * @param {number} [args.toleranceSec=3] Per-gap match tolerance.
 * @param {number} [args.minGapMs=200] Minimum gap to count as boundary.
 * @returns {object|null}
 */
function detectClockSkew(args) {
    if (!args || !Array.isArray(args.transcriptRows) || args.transcriptRows.length === 0) {
        return null;
    }
    if (!Array.isArray(args.pcapTimestampsMs) || args.pcapTimestampsMs.length < 2) {
        return null;
    }
    const transcriptTimesMs = args.transcriptRows
        .map((row) => (row && Number.isFinite(row.timestamp) ? row.timestamp : null))
        .filter((v) => v !== null);
    if (transcriptTimesMs.length < 2) return null;
    const largeGaps = extractLargeGaps(args.pcapTimestampsMs, args.minGapMs);
    if (largeGaps.length === 0) return null;
    const range = (Number.isFinite(args.offsetRangeSec) && args.offsetRangeSec > 0)
        ? args.offsetRangeSec
        : DEFAULT_OFFSET_RANGE_S;
    const step = (Number.isFinite(args.offsetStepSec) && args.offsetStepSec > 0)
        ? args.offsetStepSec
        : DEFAULT_OFFSET_STEP_S;

    let bestOffset = 0;
    let bestScore = -Infinity;
    let bestMatches = 0;
    const toleranceSec = (Number.isFinite(args.toleranceSec) && args.toleranceSec > 0)
        ? args.toleranceSec
        : DEFAULT_MATCH_TOLERANCE_S;

    // First pass: coarse grid search over [−range, +range] in `step`
    // increments. Score is matched-count + log-bonus; we keep the
    // offset with the highest score, breaking ties toward the
    // smaller-magnitude offset (most clocks drift by seconds, not
    // minutes, when NTP is up).
    for (let delta = -range; delta <= range; delta += step) {
        const s = scoreAlignment(transcriptTimesMs, largeGaps, delta, toleranceSec);
        if (s > bestScore + 1e-9) {
            bestScore = s;
            bestOffset = delta;
            bestMatches = countMatches(transcriptTimesMs, largeGaps, delta, toleranceSec);
        }
    }

    // Second pass: 1-second refinement around the coarse winner
    // (±step). Cheap (≤3 evaluations).
    for (let delta = bestOffset - step; delta <= bestOffset + step; delta += 0.1) {
        const s = scoreAlignment(transcriptTimesMs, largeGaps, delta, toleranceSec);
        if (s > bestScore + 1e-9) {
            bestScore = s;
            bestOffset = Math.round(delta * 10) / 10; // 0.1s precision
            bestMatches = countMatches(transcriptTimesMs, largeGaps, bestOffset, toleranceSec);
        }
    }

    // Confidence: matched / total transcript commands. Below 0.3 the
    // alignment is weak — caller's UI should warn rather than silently
    // apply.
    const confidence = bestMatches / transcriptTimesMs.length;
    return {
        offsetSec: bestOffset,
        score: bestScore,
        matches: bestMatches,
        totalCommands: transcriptTimesMs.length,
        confidence,
        largeGapCount: largeGaps.length,
        toleranceSec,
    };
}

function countMatches(transcriptTimesMs, largeGaps, offsetSec, toleranceSec) {
    const tol = toleranceSec * 1000;
    const offsetMs = offsetSec * 1000;
    let matches = 0;
    for (const ts of transcriptTimesMs) {
        if (!Number.isFinite(ts)) continue;
        const target = ts + offsetMs;
        for (const g of largeGaps) {
            if (Math.abs(g.timeMs - target) <= tol) {
                matches += 1;
                break;
            }
        }
    }
    return matches;
}

/**
 * Apply a detected skew to a list of transcript rows. Returns a new
 * array; input is not mutated. Each row gains a `correctedTimestamp`
 * field set to `timestamp + offsetSec * 1000`. Rows with non-finite
 * timestamps are passed through unchanged with `correctedTimestamp`
 * set to null.
 *
 * @param {Array<{timestamp?: number}>} rows
 * @param {number} offsetSec
 * @returns {Array}
 */
function applySkew(rows, offsetSec) {
    if (!Array.isArray(rows)) return [];
    if (!Number.isFinite(offsetSec) || offsetSec === 0) {
        // Zero offset — just copy through with correctedTimestamp
        // equal to timestamp so callers can use either field.
        return rows.map((row) => {
            const out = Object.assign({}, row);
            out.correctedTimestamp = Number.isFinite(row.timestamp) ? row.timestamp : null;
            return out;
        });
    }
    const offsetMs = offsetSec * 1000;
    return rows.map((row) => {
        const out = Object.assign({}, row);
        out.correctedTimestamp = Number.isFinite(row.timestamp)
            ? row.timestamp + offsetMs
            : null;
        return out;
    });
}

/**
 * Render a one-line status string describing a skew detection
 * result. The string is suitable for display in the panel's status
 * area below the transcript loader.
 *
 * @param {object|null} detection Result from `detectClockSkew`.
 * @returns {string}
 */
function formatSkewStatus(detection) {
    if (!detection) return "Clock skew: unknown (insufficient data)";
    const sign = detection.offsetSec >= 0 ? "+" : "";
    const matches = `${detection.matches}/${detection.totalCommands}`;
    return `Clock skew: ${sign}${detection.offsetSec.toFixed(1)}s detected (${matches} commands aligned to large gaps, ${(detection.confidence * 100).toFixed(0)}% confidence)`;
}

module.exports = {
    DEFAULT_OFFSET_RANGE_S,
    DEFAULT_OFFSET_STEP_S,
    DEFAULT_MATCH_TOLERANCE_S,
    DEFAULT_MIN_GAP_MS,
    extractLargeGaps,
    scoreAlignment,
    detectClockSkew,
    applySkew,
    formatSkewStatus,
};