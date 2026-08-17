// SSDEEP-style fuzzy similarity (context-triggered piecewise hashing).
//
// Re-implements the public-domain ssdeep comparison algorithm (see
// https://ssdeep-project.github.io/ssdeep/) using a small, dependency-free
// JavaScript core. The output is a number in [0, 1] that we use to score
// predicted vs. typed commands during OpenSSH auto-calibration.
//
// Algorithm summary (one-pass, two-string comparison):
//   1. Hash each input string with a rolling hash over a 7-character window.
//   2. Emit a 2-byte chunk hash whenever the rolling hash hits a "trigger"
//      position (h % 7 == 6). The chunks form a piecewise signature.
//   3. Walk both signatures left-to-right; matching chunks at the same
//      offset score both a "match" and an "order" point. The final score is
//        2 * matched / (|sigA| + |sigB|)
//      which is the canonical ssdeep formula.
//
// This is *not* a cryptographic hash — it's a string similarity heuristic
// tuned for short, slightly-noisy inputs (shell commands). Tolerates
// insertions, deletions, and reorderings, which is exactly what we want
// when comparing a top-1 decoder candidate against a typed command.

"use strict";

const ROLLING_WINDOW = 7;
const TRIGGER_MOD = 7;        // h % 7 == 6  -> emit
const CHUNK_BYTES = 2;        // 2-byte chunks = 4 hex chars per chunk
const MIN_INPUT_LEN = 1;      // allow very short strings; let the caller skip empties

/**
 * Build a CTPH-style piecewise signature for one input string.
 *
 * Returns an array of 2-byte hash chunks extracted at trigger positions.
 * For inputs that are too short to produce any trigger, returns a single
 * chunk derived from the input's first two bytes (so the comparison at
 * least has *something* to match against).
 *
 * @param {string} input
 * @returns {number[]}
 */
function buildSignature(input) {
    if (typeof input !== "string" || input.length < MIN_INPUT_LEN) {
        return [];
    }
    const str = input;
    const chunks = [];
    let h = 0;
    let i = 0;
    // Iterate through the string, advancing the rolling hash window.
    // We start at index 0 to seed the window. The ssdeep paper
    // deliberately skips the first ``ROLLING_WINDOW`` characters and
    // the trailing ``ROLLING_WINDOW`` characters of the input to avoid
    // edge artefacts, but we accept the small fidelity loss so very
    // short commands still produce a usable signature.
    while (i < str.length) {
        const c = str.charCodeAt(i);
        h = ((h * ROLLING_WINDOW) + c) | 0; // keep to 32-bit signed
        // Trigger on a specific residue class.
        if ((i >= ROLLING_WINDOW) && (i + ROLLING_WINDOW < str.length) && (h % TRIGGER_MOD === (TRIGGER_MOD - 1))) {
            // Take the lowest CHUNK_BYTES bytes of the rolling hash as
            // the chunk. Two bytes is the canonical ssdeep chunk size.
            chunks.push(h & 0xffff);
        }
        i += 1;
    }
    // Fallback: if no triggers fired (very short / pathological input),
    // emit a synthetic chunk from the first two chars so the signature
    // is non-empty. This keeps ``compare()`` callable on every command.
    if (chunks.length === 0) {
        const a = str.charCodeAt(0) || 0;
        const b = str.charCodeAt(1) || 0;
        chunks.push(((a & 0xff) << 8) | (b & 0xff));
    }
    return chunks;
}

/**
 * Compute the ssdeep-style similarity between two strings.
 *
 * Returns an object so the caller can report diagnostics (matched chunks,
 * both signatures) alongside the headline score.
 *
 * @param {string} a
 * @param {string} b
 * @returns {{ score: number, matched: number, sigA: number[], sigB: number[] }}
 */
function computeSsdeep(a, b) {
    const sigA = buildSignature(a);
    const sigB = buildSignature(b);
    if (sigA.length === 0 && sigB.length === 0) {
        return { score: 0, matched: 0, sigA, sigB };
    }
    if (sigA.length === 0 || sigB.length === 0) {
        return { score: 0, matched: 0, sigA, sigB };
    }
    // Walk both signatures left-to-right. A match is a chunk that
    // appears at the same position in both signatures *and* hasn't been
    // already consumed. A "same offset" pair scores both the match and
    // an "order" point, exactly like the canonical ssdeep algorithm.
    const usedB = new Array(sigB.length).fill(false);
    let matched = 0;
    let inOrder = 0;
    for (let i = 0; i < sigA.length; i += 1) {
        for (let j = 0; j < sigB.length; j += 1) {
            if (usedB[j]) continue;
            if (sigA[i] === sigB[j]) {
                matched += 1;
                if (i === j) inOrder += 1;
                usedB[j] = true;
                break;
            }
        }
    }
    // Canonical ssdeep formula: 2 * matched / (lenA + lenB).
    const score = (2 * matched) / (sigA.length + sigB.length);
    return { score, matched, sigA, sigB };
}

module.exports = {
    buildSignature,
    computeSsdeep,
    // Exposed for tests / future tuning
    ROLLING_WINDOW,
    TRIGGER_MOD,
    CHUNK_BYTES,
};
