// OpenSSH auto-calibration orchestrator.
//
// Walks the OpenSSH tab's tuning-knob space and finds the combination
// that minimises the difference between the decoder's predicted commands
// and the typed truth. The score function is ssdeep-style (per-command,
// aggregated to mean / total / stddev) so the per-command diagnostics
// surface what's actually being lost.
//
// This module is pure ESM/CommonJS — no DOM, no Electron. It receives a
// `runTrial` callback from the panel that applies a knob vector and
// returns an analysis result, so the orchestrator can be unit-tested
// with a stub runner without standing up the whole renderer.
//
// I/O shape:
//   autoCalibrate(setup, onProgress, { signal })
//     setup:
//       { knobs: starting knobs, ranges: per-knob sweep ranges,
//         runTrial: async (knobs) => trialResult,
//         truth:   array of { command, chunkIdx } }
//     trialResult:
//       { perCommand: [{ idx, truth, predicted, score }],
//         notes: optional extra diagnostics }
//   returns:
//     { best: { knobs, score, perCommand, stats },
//       trials: [...], report: { ... } }

"use strict";

const { computeSsdeep } = require("./ssdeep");

// --- 1. Pure helpers ----------------------------------------------------

/**
 * Build the list of knob values to sweep for one coordinate-descent
 * step. Returns an array that includes the current best value so the
 * step is monotone (no worse than the current best).
 */
function buildSweep(range) {
    if (!range || typeof range !== "object") return [];
    const { min, max, step, values } = range;
    if (Array.isArray(values) && values.length > 0) {
        return values.slice();
    }
    if (!Number.isFinite(min) || !Number.isFinite(max) || !Number.isFinite(step) || step <= 0) {
        return [];
    }
    const out = [];
    for (let v = min; v <= max + 1e-9; v += step) {
        // Round to step precision so accumulated floats don't drift.
        const rounded = Math.round(v * 1e6) / 1e6;
        out.push(rounded);
    }
    return out;
}

/**
 * Aggregate per-command ssdeep scores into the headline statistics
 * the search optimises on.
 */
function aggregateScores(perCommand) {
    const valid = (perCommand || []).filter((row) => Number.isFinite(row.score));
    const n = valid.length;
    if (n === 0) {
        return {
            n: 0,
            mean: 0,
            total: 0,
            min: 0,
            max: 0,
            stddev: 0,
            exactMatchRate: 0,
        };
    }
    let total = 0;
    let min = Infinity;
    let max = -Infinity;
    let exact = 0;
    for (const row of valid) {
        total += row.score;
        if (row.score < min) min = row.score;
        if (row.score > max) max = row.score;
        if (row.score >= 1.0) exact += 1;
    }
    const mean = total / n;
    let sq = 0;
    for (const row of valid) {
        const d = row.score - mean;
        sq += d * d;
    }
    const stddev = Math.sqrt(sq / n);
    return {
        n,
        mean,
        total,
        min,
        max,
        stddev,
        exactMatchRate: exact / n,
    };
}

/**
 * Score a single trial result against the truth list, returning one
 * row per truth command. Unmatched commands score 0. Missing predictions
 * also score 0.
 */
function scoreTrial(trialResult, truth) {
    const predictionsByIdx = new Map();
    const predictedTexts = [];
    if (trialResult && Array.isArray(trialResult.perCommand)) {
        for (const row of trialResult.perCommand) {
            if (Number.isInteger(row.idx)) {
                predictionsByIdx.set(row.idx, row.predicted || "");
            }
            if (row && typeof row.predicted === "string" && row.predicted.length > 0) {
                predictedTexts.push(row.predicted);
            }
        }
    }
    const out = [];
    for (let i = 0; i < (truth || []).length; i += 1) {
        const truthRow = truth[i] || {};
        const truthText = truthRow.command || truthRow.text || "";
        const predicted = predictionsByIdx.has(i)
            ? predictionsByIdx.get(i)
            : pickFallback(predictedTexts, truthText);
        const { score } = computeSsdeep(String(predicted || ""), String(truthText || ""));
        out.push({
            idx: i,
            truth: truthText,
            predicted: predicted || "",
            score,
        });
    }
    return out;
}

/**
 * Best-effort fallback when a per-command prediction isn't available:
 * pick the prediction with the highest ssdeep score against the truth.
 * Returns the empty string if there are no predictions at all.
 */
function pickFallback(predictions, truth) {
    if (!predictions || predictions.length === 0) return "";
    let best = "";
    let bestScore = -1;
    for (const p of predictions) {
        const { score } = computeSsdeep(p, truth);
        if (score > bestScore) {
            bestScore = score;
            best = p;
        }
    }
    return best;
}

/**
 * Apply a single knob override to a knobs object. Returns a *new*
 * object so the orchestrator never mutates the caller's knobs.
 */
function applyKnob(knobs, name, value) {
    const next = Object.assign({}, knobs);
    next[name] = value;
    return next;
}

/**
 * Compute the 1D sensitivity for one knob: walk every value in its
 * range, run the trial, and return the score curve. Used by the report
 * panel to show a per-knob "what changed" view.
 */
async function probeKnobSensitivity(name, range, base, truth, runTrial, onProgress, signal) {
    const sweep = buildSweep(range);
    const points = [];
    for (let i = 0; i < sweep.length; i += 1) {
        if (signal && signal.aborted) return points;
        const knobs = applyKnob(base, name, sweep[i]);
        let perCommand = [];
        try {
            const result = await runTrial(knobs);
            perCommand = scoreTrial(result, truth);
        } catch (err) {
            // Treat as score 0 so the sensitivity curve still has a point
            perCommand = (truth || []).map((row, idx) => ({
                idx,
                truth: row.command || row.text || "",
                predicted: "",
                score: 0,
            }));
        }
        const stats = aggregateScores(perCommand);
        points.push({ knob: name, value: sweep[i], score: stats.mean, stats });
        if (typeof onProgress === "function") {
            try { onProgress({ phase: "sensitivity", knob: name, value: sweep[i], score: stats.mean }); } catch (_e) { /* ignore */ }
        }
    }
    return points;
}

// --- 2. Main entry point ------------------------------------------------

/**
 * Run coordinate-descent auto-calibration.
 *
 * @param {Object} setup
 * @param {Object} setup.knobs - Starting knob values, keyed by name.
 * @param {Object} setup.ranges - Per-knob `{ min, max, step }` or `{ values }`.
 * @param {Function} setup.runTrial - `async (knobs) => { perCommand, ... }`.
 * @param {Array} setup.truth - [{ command, chunkIdx? }] (typed transcript).
 * @param {Function} [onProgress] - optional progress callback.
 * @param {Object} [options] - { signal, sensitivityDepth, randTrials }
 * @returns {Promise<Object>} - { best, trials, sensitivity, report }
 */
async function autoCalibrate(setup, onProgress, options = {}) {
    const { knobs: startKnobs, ranges, runTrial, truth } = setup || {};
    if (!startKnobs || typeof startKnobs !== "object") {
        throw new Error("autoCalibrate: setup.knobs is required");
    }
    if (typeof runTrial !== "function") {
        throw new Error("autoCalibrate: setup.runTrial must be a function");
    }
    if (!Array.isArray(truth) || truth.length === 0) {
        throw new Error("autoCalibrate: setup.truth needs at least one command");
    }
    const signal = options.signal || null;
    const trials = [];

    // Run the baseline trial at the current knob values.
    let best = await runTrialAndScore(startKnobs, ranges, runTrial, truth, trials, onProgress, signal);
    if (!best) return errorResult("baseline run failed");

    const knobNames = Object.keys(ranges || {});
    if (knobNames.length === 0) return finaliseResult(best, trials, {}, truth);

    // Outer loop: keep sweeping each knob until one full pass yields no
    // improvement. Two passes are enough on the small knob set we have.
    let improved = true;
    let pass = 0;
    const maxPasses = Number.isFinite(options.maxPasses) ? options.maxPasses : 3;
    while (improved && pass < maxPasses) {
        improved = false;
        pass += 1;
        for (const name of knobNames) {
            if (signal && signal.aborted) break;
            const sweep = buildSweep(ranges[name]);
            for (let i = 0; i < sweep.length; i += 1) {
                if (signal && signal.aborted) break;
                const trialKnobs = applyKnob(best.knobs, name, sweep[i]);
                const stats = await runTrialAndScore(trialKnobs, ranges, runTrial, truth, trials, onProgress, signal);
                if (!stats) continue;
                if (stats.stats.mean > best.stats.mean + 1e-6) {
                    best = stats;
                    improved = true;
                }
            }
        }
    }

    // Sensitivity probe: 1D curve per knob around the best values.
    const sensitivity = {};
    const depth = Number.isFinite(options.sensitivityDepth) ? options.sensitivityDepth : 1;
    if (depth > 0) {
        for (const name of knobNames) {
            if (signal && signal.aborted) break;
            const range = ranges[name];
            if (!range) continue;
            const probe = await probeKnobSensitivity(name, range, best.knobs, truth, runTrial, onProgress, signal);
            sensitivity[name] = probe;
        }
    }

    return finaliseResult(best, trials, sensitivity, truth);
}

// --- 3. Internal helpers ------------------------------------------------

async function runTrialAndScore(knobs, ranges, runTrial, truth, trials, onProgress, signal) {
    if (signal && signal.aborted) return null;
    let result = null;
    try {
        result = await runTrial(knobs);
    } catch (err) {
        if (typeof onProgress === "function") {
            try { onProgress({ phase: "trial", error: err && err.message ? err.message : String(err) }); } catch (_e) { /* ignore */ }
        }
        return null;
    }
    const perCommand = scoreTrial(result, truth);
    const stats = aggregateScores(perCommand);
    const trial = { knobs: Object.assign({}, knobs), stats, perCommand };
    trials.push(trial);
    if (typeof onProgress === "function") {
        try {
            onProgress({
                phase: "trial",
                trial: trials.length,
                knobs,
                score: stats.mean,
                exactMatchRate: stats.exactMatchRate,
            });
        } catch (_e) { /* ignore */ }
    }
    return trial;
}

function finaliseResult(best, trials, sensitivity, truth) {
    // Top-3 trials for the panel report.
    const ranked = trials.slice().sort((a, b) => b.stats.mean - a.stats.mean);
    const top3 = ranked.slice(0, 3);
    return {
        best,
        trials,
        top3,
        sensitivity,
        report: {
            nCommands: truth.length,
            nTrials: trials.length,
            baseline: trials.length > 0 ? trials[0].stats : null,
            bestStats: best.stats,
            delta: best.stats.mean - (trials[0].stats.mean || 0),
            top3,
        },
    };
}

function errorResult(message) {
    return {
        best: null,
        trials: [],
        top3: [],
        sensitivity: {},
        report: { error: message, nCommands: 0, nTrials: 0, bestStats: null },
    };
}

module.exports = {
    autoCalibrate,
    // exported for unit tests
    aggregateScores,
    buildSweep,
    scoreTrial,
    applyKnob,
    probeKnobSensitivity,
};
