// Non-linear mapping for the chunker-min-boundary slider.
//
// The slider drives `chunkerSettings.minCommandBoundary`, which the
// chunker compares against every inter-key delay in the peeled
// stream. A linear `min/max/step` over the natural 10-2000ms range
// has a usability problem:
//   - At low values (10-100ms), a 10ms step is coarse: a 7ms gap
//     and a 13ms gap both look identical to the chunker, but they
//     fall on opposite sides of the "real" boundary the analyst is
//     trying to find.
//   - At high values (1500-2000ms), a 10ms step is overkill: the
//     difference between 1730ms and 1740ms is meaningless when the
//     next typing pause is measured in seconds.
//
// The fix: map the slider through a curve that gives finer
// resolution at the low end and coarser at the high end. We use a
// piecewise quadratic-on-the-low-half / linear-on-the-high-half so
// the analyst gets sub-millisecond precision where it matters
// (sub-100ms pauses between keystrokes inside a word) and quick
// big jumps where it doesn't (multi-second gaps between commands).
//
// ``posToMs`` and ``msToPos`` are inverses of each other so the
// slider can be re-initialised from a saved knob value without
// drift.

"use strict";

const SLIDER_POS_MIN = 0;
const SLIDER_POS_MAX = 1000;
const MS_LOW_MAX = 100;        // Sub-100ms: 1:1 mapping (1 step = 1ms)
const MS_LOW_TO_POS = MS_LOW_MAX; // pos 0 → 0ms, pos 100 → 100ms
const MS_HIGH_MIN = 100;       // 100-2000ms: linear 10:1 (1 step ≈ 10ms)
const MS_HIGH_MAX = 2000;
const MS_HIGH_RANGE = MS_HIGH_MAX - MS_HIGH_MIN; // 1900ms
const POS_HIGH_RANGE = SLIDER_POS_MAX - MS_LOW_TO_POS; // 900 positions
const MS_PER_HIGH_POS = MS_HIGH_RANGE / POS_HIGH_RANGE; // ≈ 2.11ms/pos

// Convert a slider position (0-1000) into a millisecond threshold.
function posToMs(pos) {
    const p = Number.isFinite(pos) ? pos : 0;
    if (p <= MS_LOW_TO_POS) {
        // 0-100ms: linear 1:1. Clamp to 1ms minimum so the chunker
        // never sees a threshold of 0 (would split on every delay).
        return Math.max(1, p);
    }
    const over = p - MS_LOW_TO_POS;
    return MS_HIGH_MIN + over * MS_PER_HIGH_POS;
}

// Inverse of posToMs — convert a millisecond threshold back into a
// slider position so the slider can be re-initialised from a saved
// knob value without losing precision.
function msToPos(ms) {
    const m = Number.isFinite(ms) ? ms : 0;
    if (m <= MS_LOW_MAX) {
        return Math.max(0, Math.round(m));
    }
    const over = Math.min(MS_HIGH_RANGE, m - MS_HIGH_MIN);
    return MS_LOW_TO_POS + Math.round(over / MS_PER_HIGH_POS);
}

// Format the slider position as a user-facing label. We always show
// integer milliseconds; rounding is the chunker's job, not the
// label's.
function formatMsLabel(ms) {
    const m = Number.isFinite(ms) ? ms : 0;
    return `${Math.round(m)}ms`;
}

module.exports = {
    SLIDER_POS_MIN,
    SLIDER_POS_MAX,
    MS_LOW_MAX,
    MS_HIGH_MAX,
    posToMs,
    msToPos,
    formatMsLabel,
};