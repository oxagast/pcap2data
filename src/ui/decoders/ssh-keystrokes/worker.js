// ── Self-contained OpenSSH decoder worker ─────────────────────────────────
//
// Runs the Viterbi decode entirely off the main thread so the renderer
// never blocks on large SSH sessions. The worker is given a pre-built
// model from the renderer (via the ``model`` field of the message) and
// re-runs the synchronous decoder against the caller-supplied delays.
// The worker is intentionally self-contained: it does not require the
// decoder module from disk, so it works regardless of how webpack
// bundles the rest of the application.
//
// Message protocol:
//   { type: "decode", delays: number[], topN: number, model: object }
//   → { type: "result", success: true, candidates: [...] }
//   → { type: "result", success: false, error: string }

"use strict";

const { parentPort } = require("worker_threads");

if (!parentPort) {
    process.exit(0);
}

// ── Layout (default QWERTY) ─────────────────────────────────────────────
//
// The decoder is keyboard-agnostic. The bundled default is QWERTY, but
// the renderer can supply a different ``layout`` (DVORAK, Colemak,
// etc.) via the model. The worker rebuilds its coordinate index from
// the model so any user-defined layout Just Works.

function buildCoordinateIndex(rows) {
    const index = {};
    for (let r = 0; r < rows.length; r += 1) {
        for (let c = 0; c < rows[r].length; c += 1) {
            index[rows[r][c]] = [c, r];
        }
    }
    return index;
}

const QWERTY_ROWS = [
    ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"],
    ["a", "s", "d", "f", "g", "h", "j", "k", "l", ";"],
    ["z", "x", "c", "v", "b", "n", "m", ",", ".", "/"],
];

const DEFAULT_COORDINATE_INDEX = buildCoordinateIndex(QWERTY_ROWS);

const DEFAULT_DIGRAPH_PARAMS = { mean: 145, std: 40 };
const MIN_STD_MS = 20;
const DEFAULT_LOG_BEAM_THRESHOLD = -18;

function classifyDigraph(a, b, coordinateIndex) {
    if (a === b) return "sameKey";
    const idx = coordinateIndex || DEFAULT_COORDINATE_INDEX;
    const ca = idx[a];
    const cb = idx[b];
    if (!ca || !cb) return null;
    const [ax, ay] = ca;
    const [bx, by] = cb;
    if (ay !== by) return "crossRow";
    const dx = Math.abs(ax - bx);
    if (dx === 1) return "adjacentKey";
    if (dx <= 3) return "nearbyKey";
    return "farKey";
}

function sanitizeParams(mean, std) {
    const cleanMean = Number.isFinite(mean) ? mean : DEFAULT_DIGRAPH_PARAMS.mean;
    const cleanStd = Number.isFinite(std) ? Math.max(std, MIN_STD_MS) : DEFAULT_DIGRAPH_PARAMS.std;
    return { mean: cleanMean, std: cleanStd };
}

function resolveDigraphParams(a, b, empiricalSamples, baselines, coordinateIndex) {
    const lowerA = String(a || "").toLowerCase();
    const lowerB = String(b || "").toLowerCase();
    const empirical = empiricalSamples || {};
    if (empirical[lowerA + lowerB]) {
        const entry = empirical[lowerA + lowerB];
        return sanitizeParams(entry.mean, entry.std);
    }
    if (empirical[lowerB + lowerA]) {
        const entry = empirical[lowerB + lowerA];
        return sanitizeParams(entry.mean, entry.std);
    }
    const cls = classifyDigraph(lowerA, lowerB, coordinateIndex);
    if (cls && baselines && baselines[cls]) {
        return sanitizeParams(baselines[cls].mean, baselines[cls].std);
    }
    return { mean: DEFAULT_DIGRAPH_PARAMS.mean, std: DEFAULT_DIGRAPH_PARAMS.std };
}

function gaussianLogProbability(value, mean, std) {
    const variance = std * std;
    const diff = value - mean;
    return -0.5 * Math.log(2 * Math.PI * variance) - (diff * diff) / (2 * variance);
}

function scoreNextChar(prevChar, observedDelay, model) {
    const out = {};
    const alphabet = model.alphabet;
    const defaultLogP = gaussianLogProbability(
        observedDelay,
        DEFAULT_DIGRAPH_PARAMS.mean,
        DEFAULT_DIGRAPH_PARAMS.std,
    );
    if (!prevChar) {
        for (let i = 0; i < alphabet.length; i += 1) {
            out[alphabet[i]] = defaultLogP;
        }
        return out;
    }
    for (let i = 0; i < alphabet.length; i += 1) {
        const nextChar = alphabet[i];
        const params = resolveDigraphParams(
            prevChar,
            nextChar,
            model.empirical,
            model.baselines,
            model.coordinateIndex,
        );
        out[nextChar] = gaussianLogProbability(observedDelay, params.mean, params.std);
    }
    return out;
}

// ── Viterbi (linked-list paths, bounded survivors) ───────────────────────
function decode(observedDelays, options) {
    const model = options.model;
    const topN = Math.max(1, Math.floor(options.topN || 8));
    const beam = Number.isFinite(options.beam) ? options.beam : DEFAULT_LOG_BEAM_THRESHOLD;
    const alphabet = model.alphabet;
    const alphabetLen = alphabet.length;
    const maxPathsPerStep = Math.max(
        topN * 2,
        Math.min(
            topN * alphabetLen,
            Number.isFinite(options.maxPathsPerStep) ? options.maxPathsPerStep : topN * alphabetLen,
        ),
    );

    if (!Array.isArray(observedDelays) || observedDelays.length === 0) {
        return [];
    }

    const ROOT = { prev: null, char: "", score: 0, lastChar: null, logProb: 0 };
    let paths = [ROOT];

    for (let step = 0; step < observedDelays.length; step += 1) {
        const observed = observedDelays[step];
        if (observed === null || observed === undefined || !Number.isFinite(Number(observed))) {
            continue;
        }
        const numericObserved = Number(observed);

        const nextByState = new Map();
        for (let pi = 0; pi < paths.length; pi += 1) {
            const path = paths[pi];
            const lastChar = path.lastChar;
            const baseLogProb = path.logProb;
            if (lastChar === null) {
                const defaultLogP = gaussianLogProbability(
                    numericObserved,
                    DEFAULT_DIGRAPH_PARAMS.mean,
                    DEFAULT_DIGRAPH_PARAMS.std,
                );
                for (let ci = 0; ci < alphabetLen; ci += 1) {
                    const nextChar = alphabet[ci];
                    const newPath = {
                        prev: path,
                        char: nextChar,
                        score: defaultLogP,
                        lastChar: nextChar,
                        logProb: baseLogProb + defaultLogP,
                    };
                    let bucket = nextByState.get(nextChar);
                    if (!bucket) {
                        bucket = [];
                        nextByState.set(nextChar, bucket);
                    }
                    bucket.push(newPath);
                }
            } else {
                const scores = scoreNextChar(lastChar, numericObserved, model);
                for (let ci = 0; ci < alphabetLen; ci += 1) {
                    const nextChar = alphabet[ci];
                    const score = scores[nextChar];
                    if (!Number.isFinite(score)) continue;
                    const newPath = {
                        prev: path,
                        char: nextChar,
                        score,
                        lastChar: nextChar,
                        logProb: baseLogProb + score,
                    };
                    let bucket = nextByState.get(nextChar);
                    if (!bucket) {
                        bucket = [];
                        nextByState.set(nextChar, bucket);
                    }
                    bucket.push(newPath);
                }
            }
        }

        const pruned = [];
        let bestLogProb = -Infinity;
        nextByState.forEach((bucket) => {
            const keep = Math.min(topN, bucket.length);
            for (let i = 1; i < bucket.length; i += 1) {
                const entry = bucket[i];
                if (i >= keep && entry.logProb <= bucket[keep - 1].logProb) {
                    continue;
                }
                let j = Math.min(i - 1, keep - 1);
                while (j >= 0 && bucket[j].logProb < entry.logProb) {
                    bucket[j + 1] = bucket[j];
                    j -= 1;
                }
                bucket[j + 1] = entry;
            }
            for (let i = 0; i < keep; i += 1) {
                pruned.push(bucket[i]);
                if (bucket[i].logProb > bestLogProb) bestLogProb = bucket[i].logProb;
            }
        });
        const beamCutoff = bestLogProb + beam;
        let survivors = pruned.filter((p) => p.logProb >= beamCutoff);
        if (survivors.length > maxPathsPerStep) {
            survivors.sort((a, b) => b.logProb - a.logProb);
            survivors = survivors.slice(0, maxPathsPerStep);
        }
        paths = survivors;
        if (paths.length === 0) break;
    }

    paths.sort((a, b) => b.logProb - a.logProb);
    const top = paths.slice(0, topN);
    function materialize(node) {
        const chars = [];
        const perChar = [];
        let cur = node;
        while (cur && cur.prev) {
            chars.push(cur.char);
            perChar.push(cur.score);
            cur = cur.prev;
        }
        chars.reverse();
        perChar.reverse();
        return { text: chars.join(""), logProb: node.logProb, perCharLogProb: perChar };
    }
    return top.map(materialize);
}

parentPort.on("message", (msg) => {
    if (!msg || typeof msg !== "object") return;
    if (msg.type !== "decode") return;
    try {
        const delays = Array.isArray(msg.delays) ? msg.delays : [];
        const topN = Math.max(1, Math.floor(Number(msg.topN) || 8));
        const model = msg.model && typeof msg.model === "object" ? msg.model : null;
        if (!model) {
            parentPort.postMessage({ type: "result", success: false, error: "model is required" });
            return;
        }
        if (typeof model.alphabet !== "string" || model.alphabet.length === 0) {
            parentPort.postMessage({ type: "result", success: false, error: "model.alphabet is empty" });
            return;
        }
        const candidates = decode(delays, { topN, model });
        parentPort.postMessage({ type: "result", success: true, candidates });
    } catch (err) {
        parentPort.postMessage({
            type: "result",
            success: false,
            error: err && err.message ? err.message : String(err),
        });
    }
});
