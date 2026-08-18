// Auto-calibrate warm-start: pick a narrow search window for the
// ``minCommandBoundary`` knob from cheap flow-level signals so the
// orchestrator doesn't have to brute-force the full lattice.
//
// The knob lattice we are allowed to emit is fixed by the panel's
// ``buildAutoCalibrateRanges``:
//
//     [50, 80, 100, 120, 150, 200, 300, 500]
//
// All windows this module returns are clamped to that lattice so the
// orchestrator never sees a value it doesn't know how to score.
//
// This module is pure CommonJS — no DOM, no Electron — so it can be
// unit-tested without standing up the renderer.

"use strict";

// Knob lattice (must match `buildAutoCalibrateRanges` in
// crypt-panel.js). Kept as a constant here so the warm-start can be
// tested in isolation from the panel closure.
const COMMAND_BOUNDARY_LATTICE = [50, 80, 100, 120, 150, 200, 300, 500];

/**
 * Pick the lattice entry closest to `target` (rounded down or up).
 * Pure helper used by `recommendCommandBoundaryRange` and tests.
 *
 * @param {number} target Desired boundary value.
 * @param {number[]} [lattice=COMMAND_BOUNDARY_LATTICE] Sorted lattice.
 * @returns {number} Closest lattice entry.
 */
function snapToLattice(target, lattice) {
    const lat = (Array.isArray(lattice) && lattice.length > 0)
        ? lattice
        : COMMAND_BOUNDARY_LATTICE;
    if (!Number.isFinite(target)) return lat[0];
    let best = lat[0];
    let bestDist = Math.abs(target - best);
    for (let i = 1; i < lat.length; i += 1) {
        const d = Math.abs(target - lat[i]);
        if (d < bestDist) {
            best = lat[i];
            bestDist = d;
        }
    }
    return best;
}

/**
 * Derive a "general area" for the command-boundary knob from the
 * flow's timing distribution and volume. These are cheap to compute:
 * `findReturnChunks` already runs the same median/MAD math so we
 * reuse the same formula here instead of recomputing per-trial.
 *
 * The returned window is a 3-value sub-lattice centred on the
 * heuristic pick. Calling code (the auto-cal click handler) can
 * widen it later via the rescan path.
 *
 * Heuristic (deterministic, easy to tune against real corpora):
 *
 *   - approxStd < 20 (obfuscated / scripted timing, median ≈ 20 ms):
 *     the dynamic threshold inside findReturnChunks is already
 *     around 170 ms; a low floor preserves real Return gaps. Window
 *     is `[80, 100, 120]`.
 *
 *   - 20 ≤ approxStd < 80 (typical interactive typing, median
 *     50–200 ms): window centred on `median`, snapped to the
 *     nearest lattice entry, span ±1 step. We snap to keep the
 *     emitted values inside the lattice (a median of 137 ms would
 *     otherwise sit between 120 and 150).
 *
 *   - approxStd ≥ 80 OR packetCount < 20 (slow / heterogeneous
 *     typist or tiny capture): heterogeneous timings need a higher
 *     floor so a single short inter-keystroke gap doesn't
 *     over-split a chunk. Window is `[200, 300, 500]`.
 *
 * @param {object} signals Flow signals.
 * @param {number} signals.median Median keystroke delay (ms).
 * @param {number} signals.approxStd Robust stddev (MAD × 1.4826) (ms).
 * @param {number} [signals.packetCount] Number of packets in flow.
 * @returns {number[]} 3-value sub-lattice (always 3 entries).
 */
function recommendCommandBoundaryRange(signals) {
    const lat = COMMAND_BOUNDARY_LATTICE;
    if (!signals || !Number.isFinite(signals.median) || !Number.isFinite(signals.approxStd)) {
        // Without signals we can't narrow — fall back to the canonical
        // middle-of-the-road window. Caller can still pass the full
        // lattice via `buildAutoCalibrateRanges()` if it wants.
        return [100, 150, 200];
    }
    const { median, approxStd } = signals;
    const packetCount = Number.isFinite(signals.packetCount) ? signals.packetCount : Infinity;

    if (approxStd < 20) {
        return [80, 100, 120];
    }
    if (approxStd >= 80 || packetCount < 20) {
        return [200, 300, 500];
    }

    // Typical interactive typing. Centre on `median`, snapped to the
    // lattice, then take ±1 lattice step on each side.
    const centre = snapToLattice(median, lat);
    const centreIdx = lat.indexOf(centre);
    if (centreIdx <= 0) {
        // Median below the lattice (rare — only if approxStd >= 20
        // tricked the branch above). Walk the low end.
        return [lat[0], lat[1], lat[2]];
    }
    if (centreIdx >= lat.length - 1) {
        return [lat[lat.length - 3], lat[lat.length - 2], lat[lat.length - 1]];
    }
    return [lat[centreIdx - 1], lat[centreIdx], lat[centreIdx + 1]];
}

/**
 * Given the best `minCommandBoundary` value found in a warm-start
 * run and the sensitivity gradient from `result.sensitivity`, decide
 * whether the search should rescan with a window re-centred on the
 * best value.
 *
 * Triggers a rescan when **both**:
 *
 *   1. The best value is at the edge of the previous window (so
 *      there's no in-window neighbour to compare against).
 *   2. The outward-pointing neighbour in the full lattice scored
 *      better than the best by a meaningful margin
 *      (≥ MIN_RESCAN_MARGIN), indicating the optimum is *outside*
 *      the current window.
 *
 * @param {object} args
 * @param {number} args.best Best boundary value from the run.
 * @param {number[]} args.window Window used for this run (the
 *   values array passed via `buildAutoCalibrateRanges`).
 * @param {Array<{value: number, score: number}>} [args.sensitivity]
 *   Per-value sensitivity points from the orchestrator.
 * @param {number} [args.minMargin=0.02] Minimum score improvement
 *   that justifies a rescan.
 * @param {number[]} [args.lattice=COMMAND_BOUNDARY_LATTICE]
 *   Full lattice.
 * @returns {number[]|null} Re-centred window, or null if no rescan
 *   is warranted.
 */
const MIN_RESCAN_MARGIN = 0.02;

function recommendRescanWindow(args) {
    if (!args || !Number.isFinite(args.best) || !Array.isArray(args.window)) {
        return null;
    }
    const lat = (Array.isArray(args.lattice) && args.lattice.length > 0)
        ? args.lattice
        : COMMAND_BOUNDARY_LATTICE;
    const minMargin = Number.isFinite(args.minMargin) ? args.minMargin : MIN_RESCAN_MARGIN;
    const window = args.window.slice().sort((a, b) => a - b);
    const sensitivity = Array.isArray(args.sensitivity) ? args.sensitivity : [];
    const idxInLat = lat.indexOf(args.best);
    if (idxInLat < 0) return null;
    const windowIsAtLeftEdge = idxInLat <= lat.indexOf(window[0]);
    const windowIsAtRightEdge = idxInLat >= lat.indexOf(window[window.length - 1]);
    if (!windowIsAtLeftEdge && !windowIsAtRightEdge) return null;

    // Look outward by one lattice step and compare scores.
    const outwardIdx = windowIsAtLeftEdge ? idxInLat - 1 : idxInLat + 1;
    if (outwardIdx < 0 || outwardIdx >= lat.length) return null;
    const outwardValue = lat[outwardIdx];
    const outwardScore = sensitivity.find((p) => p && p.value === outwardValue);
    const bestScore = sensitivity.find((p) => p && p.value === args.best);
    if (!outwardScore || !bestScore) return null;
    if (!Number.isFinite(outwardScore.score) || !Number.isFinite(bestScore.score)) return null;
    if (outwardScore.score - bestScore.score < minMargin) return null;

    // Re-centre on `best` and take ±1 lattice step.
    const reCentre = idxInLat;
    const a = lat[Math.max(0, reCentre - 1)];
    const b = lat[reCentre];
    const c = lat[Math.min(lat.length - 1, reCentre + 1)];
    return [a, b, c];
}

module.exports = {
    COMMAND_BOUNDARY_LATTICE,
    snapToLattice,
    recommendCommandBoundaryRange,
    recommendRescanWindow,
    MIN_RESCAN_MARGIN,
};