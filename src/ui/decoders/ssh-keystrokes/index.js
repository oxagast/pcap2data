// OpenSSH keystroke-timing decoder for the Crypt → OpenSSH subtab.
//
// Given a sequence of inter-packet delays from a TCP stream on port 22/2222,
// this module:
//   1. Scores each delay against a per-QWERTY-digraph Gaussian model.
//   2. Runs an N-best Viterbi over printable ASCII characters to produce
//      the most likely keystroke strings.
//   3. Provides a histogram-vs-reference helper for the Plotly chart.
//
// The math is pure (no DOM, no Plotly, no fs/path) so it can be exercised
// from Jest and bundled by webpack for the renderer without polyfills.
//
// The QWERTY model JSON lives in `src/data/qwerty-model.json` and is
// loaded by the main process; the renderer pulls it via the
// `opensshapi.loadQwertyModel()` preload bridge and passes the resulting
// object to `loadQwertyModel({...})`. Tests can call `_setModelForTesting`
// to inject a model directly without IPC.
//
// References for the empirical values in qwerty-model.json:
//   - Monrose & Rubin, "Keystroke Dynamics as a Biometric for Authentication"
//     (FGCS, 1997).
//   - Song, Miller, & Stahie, "Keystroke Biometric Identification Studies on
//     Long Text" (2001).
//   - Killourhy & Maxion, "Comparing Anomaly-Detection Algorithms for
//     Keystroke Dynamics" (DSN 2009).

// Characters the decoder will consider. Space (typed as one space char)
// and common shell punctuation get included; upper-case letters are folded
// to lower-case before scoring.
const DECODER_ALPHABET = (() => {
    const letters = "abcdefghijklmnopqrstuvwxyz";
    const digits = "0123456789";
    const symbols = " .,-_/:;=?!@#$%^&*()[]{}<>'\"|\\~`+";
    return letters + digits + symbols;
})();

const DECODER_ALPHABET_SET = new Set(DECODER_ALPHABET);

// Default Gaussian parameters (ms) used when no digraph-specific data is
// available. Tuned for the average QWERTY typist from Killourhy & Maxion.
const DEFAULT_DIGRAPH_PARAMS = {
    mean: 145,
    std: 40,
};

// Minimum stddev to keep the Gaussian numerically stable. Below this the
// prior dominates.
const MIN_STD_MS = 20;

// Maximum log-probability magnitude we keep in the Viterbi forward pass.
// Anything worse than this prunes the beam.
const DEFAULT_LOG_BEAM_THRESHOLD = -18;

// ── Geometry helpers (layout-agnostic) ──────────────────────────────────
//
// The decoder is intentionally keyboard-agnostic. The bundled default
// is QWERTY, but users can define their own layout (DVORAK, Colemak,
// AZERTY, custom splits, etc.) by supplying a `layout` field in the
// model JSON — an array of arrays of single-character key strings. The
// module-level `QWERTY_ROWS` is only the default fallback; at runtime
// every geometric lookup goes through `model.coordinateIndex`, which is
// built from the supplied layout.

const QWERTY_ROWS = [
    ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"],
    ["a", "s", "d", "f", "g", "h", "j", "k", "l", ";"],
    ["z", "x", "c", "v", "b", "n", "m", ",", ".", "/"],
];

const DEFAULT_COORDINATE_INDEX = buildCoordinateIndex(QWERTY_ROWS);

/** Build a lookup from a key character to its (row, col) on a grid. */
function buildCoordinateIndex(rows) {
    const index = {};
    for (let r = 0; r < rows.length; r += 1) {
        for (let c = 0; c < rows[r].length; c += 1) {
            index[rows[r][c]] = [c, r];
        }
    }
    return index;
}

/** Manhattan distance between two keys on the supplied coordinate index. */
function qwertyDistance(a, b, coordinateIndex) {
    const idx = coordinateIndex || DEFAULT_COORDINATE_INDEX;
    const ca = idx[a];
    const cb = idx[b];
    if (!ca || !cb) return null;
    return Math.abs(ca[0] - cb[0]) + Math.abs(ca[1] - cb[1]);
}

/**
 * Classify a digraph by the relationship of the two keys. Used to pick a
 * baseline Gaussian when no empirical data exists.
 *
 * Returns one of: "sameKey", "adjacentKey", "nearbyKey", "farKey",
 * "crossRow", or null if either key isn't on the supplied grid.
 */
function classifyDigraph(a, b, coordinateIndex) {
    const idx = coordinateIndex || DEFAULT_COORDINATE_INDEX;
    if (a === b) return "sameKey";
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

// ── Empirical model loader ──────────────────────────────────────────────

/**
 * Resolve (mean, std) for a digraph. Order matters: empirical samples
 * first, then heuristic baselines keyed by `classifyDigraph`, then a
 * flat default. The result always satisfies std >= MIN_STD_MS.
 */
function resolveDigraphParams(a, b, empiricalSamples, baselines, coordinateIndex) {
    const lowerA = String(a || "").toLowerCase();
    const lowerB = String(b || "").toLowerCase();

    // 1. Empirical samples keyed in either order ("th" or "ht").
    const empirical = empiricalSamples || {};
    if (empirical[`${lowerA}${lowerB}`]) {
        const entry = empirical[`${lowerA}${lowerB}`];
        return sanitizeParams(entry.mean, entry.std);
    }
    if (empirical[`${lowerB}${lowerA}`]) {
        const entry = empirical[`${lowerB}${lowerA}`];
        return sanitizeParams(entry.mean, entry.std);
    }

    // 2. Heuristic baselines by digraph classification.
    const cls = classifyDigraph(lowerA, lowerB, coordinateIndex);
    if (cls && baselines && baselines[cls]) {
        return sanitizeParams(baselines[cls].mean, baselines[cls].std);
    }

    // 3. Fallback default.
    return { ...DEFAULT_DIGRAPH_PARAMS };
}

function sanitizeParams(mean, std) {
    const cleanMean = Number.isFinite(mean) ? mean : DEFAULT_DIGRAPH_PARAMS.mean;
    const cleanStd = Number.isFinite(std) ? Math.max(std, MIN_STD_MS) : DEFAULT_DIGRAPH_PARAMS.std;
    return { mean: cleanMean, std: cleanStd };
}

/**
 * Build the in-memory model from the JSON object returned by the
 * preload bridge. The model JSON lives at `src/data/qwerty-model.json`
 * and follows the schema:
 *
 * {
 *   "version": 1,
 *   "layout": [            // optional — defaults to QWERTY
 *     ["q","w","e","r","t","y","u","i","o","p"],
 *     ["a","s","d","f","g","h","j","k","l",";"],
 *     ["z","x","c","v","b","n","m",",",".","/"]
 *   ],
 *   "baselines": {
 *     "sameKey":      { "mean": 220, "std": 45 },
 *     "adjacentKey":  { "mean":  95, "std": 25 },
 *     "nearbyKey":    { "mean": 130, "std": 30 },
 *     "farKey":       { "mean": 175, "std": 40 },
 *     "crossRow":     { "mean": 200, "std": 50 }
 *   },
 *   "commonDigraphs": ["th", "he", "in", ...],
 *   "samples": ["th", "he", "in", ...]
 * }
 *
 * The decoder is keyboard-agnostic: if the user supplies a `layout`
 * (DVORAK, Colemak, custom, etc.), the coordinate index is rebuilt
 * from that layout and the heuristic baselines follow the same key
 * adjacency rules on whatever grid the user provides.
 */
function loadQwertyModel(parsedJson) {
    const parsed = parsedJson && typeof parsedJson === "object" ? parsedJson : {};
    const baselines = parsed.baselines || {};
    const samples = Array.isArray(parsed.samples) ? parsed.samples : [];
    const commonDigraphs = Array.isArray(parsed.commonDigraphs) ? parsed.commonDigraphs : [];

    // Resolve the keyboard layout. Fall back to the bundled QWERTY rows
    // when the JSON omits a layout.
    let layoutRows = QWERTY_ROWS;
    if (Array.isArray(parsed.layout) && parsed.layout.length > 0) {
        const cleaned = parsed.layout
            .filter((row) => Array.isArray(row))
            .map((row) => row.filter((k) => typeof k === "string" && k.length > 0));
        if (cleaned.length > 0 && cleaned.some((row) => row.length > 0)) {
            layoutRows = cleaned;
        }
    }
    const coordinateIndex = buildCoordinateIndex(layoutRows);

    const commonSet = new Set(commonDigraphs);
    const empirical = {};
    for (const sample of samples) {
        if (typeof sample !== "string" || sample.length !== 2) continue;
        const [a, b] = sample;
        if (!coordinateIndex[a] || !coordinateIndex[b]) continue;
        const cls = classifyDigraph(a, b, coordinateIndex);
        const baseline =
            (cls && baselines[cls]) || baselines.adjacentKey || DEFAULT_DIGRAPH_PARAMS;
        const tightening = commonSet.has(sample) ? 0.85 : 1.0;
        empirical[sample] = {
            mean: baseline.mean,
            std: baseline.std * tightening,
        };
    }

    // Merge explicit empirical entries from the JSON (if any). These take
    // precedence over the sample-derived values. Keys are expected to be
    // two-character strings (e.g. "th", "a ") with numeric mean/std.
    if (parsed.empirical && typeof parsed.empirical === "object") {
        for (const k of Object.keys(parsed.empirical)) {
            if (typeof k !== "string" || k.length !== 2) continue;
            const entry = parsed.empirical[k];
            if (!entry || !Number.isFinite(Number(entry.mean))) continue;
            const sp = sanitizeParams(Number(entry.mean), Number(entry.std));
            empirical[k.toLowerCase()] = { mean: sp.mean, std: sp.std };
        }
    }

    return {
        layout: layoutRows,
        coordinateIndex,
        baselines,
        empirical,
        alphabet: DECODER_ALPHABET,
        alphabetSet: DECODER_ALPHABET_SET,
    };
}

// ── Probability helpers ─────────────────────────────────────────────────

/** Gaussian log-probability (base e). Numerically stable for our use. */
function gaussianLogProbability(value, mean, std) {
    const variance = std * std;
    const diff = value - mean;
    return -0.5 * Math.log(2 * Math.PI * variance) - (diff * diff) / (2 * variance);
}

/**
 * Score a single observed inter-key delay against every character in the
 * alphabet. Returns `{ char: logProb }`.
 *
 * The "previous character" anchors the digraph model. If `prevChar` is
 * null, every alphabet entry gets the same flat log-likelihood (the
 * decoder has no prior for the very first character).
 */
function scoreNextChar(prevChar, observedDelay, model) {
    const out = {};
    const alphabet = model.alphabet;
    const defaultLogP = gaussianLogProbability(
        observedDelay,
        DEFAULT_DIGRAPH_PARAMS.mean,
        DEFAULT_DIGRAPH_PARAMS.std,
    );
    if (!prevChar) {
        // No digraph context — fall back to a uniform default.
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

// ── N-best Viterbi ──────────────────────────────────────────────────────

/**
 * Decode a sequence of observed inter-packet delays into the top-N most
 * likely character sequences.
 *
 * Returns an array of `{ text, logProb, perCharLogProb }` objects sorted
 * by logProb (highest first).
 *
 * Implementation notes:
 *   - Beam width is set by `DEFAULT_LOG_BEAM_THRESHOLD`: at each step we
 *     drop any partial path whose logProb is more than `beam` below the
 *     best path's logProb.
 *   - The state is the last character. We keep the top-N partial paths
 *     ending at each possible last character ("N-best per state").
 *   - For typical SSH bursts (5–30 keystrokes) and an alphabet of ~70,
 *     this runs comfortably under 10 ms.
 */
function decodeKeystrokes(observedDelays, options = {}) {
    const model = options.model || CURRENT_MODEL || fallbackModel();
    const topN = Math.max(1, Math.floor(options.topN || 8));
    const beam = Number.isFinite(options.beam) ? options.beam : DEFAULT_LOG_BEAM_THRESHOLD;
    const alphabet = model.alphabet;
    const alphabetLen = alphabet.length;
    // Hard ceiling on surviving paths per step so the inner loop cannot
    // grow without bound across very long sessions.
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

    // Sentinel path node (the empty prefix). Real paths point back to it.
    const ROOT = {
        prev: null,
        char: "",
        score: 0,
        lastChar: null,
        logProb: 0,
    };

    let paths = [ROOT];

    for (let step = 0; step < observedDelays.length; step += 1) {
        const observed = observedDelays[step];
        if (
            observed === null ||
            observed === undefined ||
            !Number.isFinite(Number(observed))
        ) {
            continue;
        }
        const numericObserved = Number(observed);

        // Per-state top-N container: map<lastChar, topN array of paths>
        const nextByState = new Map();
        for (let pi = 0; pi < paths.length; pi += 1) {
            const path = paths[pi];
            const lastChar = path.lastChar;
            const baseLogProb = path.logProb;
            if (lastChar === null) {
                // First char: every alphabet entry gets the same default log-prob.
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

        // Collapse per-state buckets to top-N using a bounded insertion sort,
        // then apply beam.
        const pruned = [];
        let bestLogProb = -Infinity;
        nextByState.forEach((bucket) => {
            const keep = Math.min(topN, bucket.length);
            // Bounded partial sort: insert each entry into the front
            // `keep` slots, skipping entries that are worse than the
            // current worst survivor.
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

    // Materialize the linked-list paths back into strings / per-char arrays.
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

/**
 * Async, batched variant of `decodeKeystrokes` that yields to the event
 * loop frequently to avoid locking the UI on very long observed
 * sequences. Returns a Promise that resolves to the same value as
 * `decodeKeystrokes`.
 *
 * Implementation notes:
 *  - The path representation is a linked list: each path stores only
 *    `{ prev, char, score, lastChar, logProb }`. Extending a path is an
 *    O(1) allocation, not an O(N) array copy. The string is materialized
 *    only for the top-N survivors at the end.
 *  - The nested inner loop yields every `batchSize` alphabet extensions
 *    (= 100 by default) using a counter, so the renderer paints roughly
 *    every 100 × 100 = ~10k Viterbi operations instead of every 100 ×
 *    paths.length × alphabet.length operations.
 *  - Per-state top-N selection uses a bounded insertion sort so the
 *    bucket is only partially sorted (we only need the top N).
 */
async function decodeKeystrokesBatched(observedDelays, options = {}) {
    const batchSize = Number.isFinite(options.batchSize) ? Math.max(1, options.batchSize) : 100;
    const onProgress = typeof options.onProgress === "function" ? options.onProgress : null;
    const model = options.model || CURRENT_MODEL || fallbackModel();
    const topN = Math.max(1, Math.floor(options.topN || 8));
    const beam = Number.isFinite(options.beam) ? options.beam : DEFAULT_LOG_BEAM_THRESHOLD;
    const alphabet = model.alphabet;
    const alphabetLen = alphabet.length;
    // Hard ceiling on the number of surviving paths per step. This is the
    // `paths.length * alphabet.length` factor that previously made the
    // inner loop grow without bound on long sessions. Even with a very
    // permissive beam the candidate search is bounded by topN × alphabet.
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

    // Sentinel path node (the empty prefix). Real paths point back to it.
    const ROOT = {
        prev: null,
        char: "",
        score: 0,
        lastChar: null,
        logProb: 0,
    };

    let paths = [ROOT];
    let processedExtensions = 0;
    let lastReportedStep = -1;

    function yieldIfNeeded() {
        if (processedExtensions >= batchSize) {
            processedExtensions = 0;
            return new Promise((resolve) => setTimeout(resolve, 0));
        }
        return null;
    }

    for (let step = 0; step < observedDelays.length; step += 1) {
        const observed = observedDelays[step];
        if (
            observed === null ||
            observed === undefined ||
            !Number.isFinite(Number(observed))
        ) {
            continue;
        }
        const numericObserved = Number(observed);

        // Per-state top-N container: map<lastChar, topN array of paths>
        const nextByState = new Map();
        for (let pi = 0; pi < paths.length; pi += 1) {
            const path = paths[pi];
            const lastChar = path.lastChar;
            const baseLogProb = path.logProb;
            if (lastChar === null) {
                // First char: every alphabet entry gets the same default log-prob.
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
                    processedExtensions += 1;
                    const maybe = yieldIfNeeded();
                    if (maybe) { await maybe; } // eslint-disable-line no-await-in-loop
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
                    processedExtensions += 1;
                    const maybe = yieldIfNeeded();
                    if (maybe) { await maybe; } // eslint-disable-line no-await-in-loop
                }
            }
        }

        // Collapse per-state buckets to top-N using a bounded insertion sort,
        // then apply beam. To bound the surviving path count (and therefore
        // the inner loop's growth on the next step), we also enforce
        // `maxPathsPerStep` by taking the top-N candidates across all states
        // once each state has been pruned to topN.
        const pruned = [];
        let bestLogProb = -Infinity;
        nextByState.forEach((bucket) => {
            const keep = Math.min(topN, bucket.length);
            // Bounded insertion sort: insert each entry into the front
            // `keep` slots. After this loop, `bucket[0..keep-1]` holds the
            // top `keep` entries sorted descending by logProb.
            for (let i = 1; i < bucket.length; i += 1) {
                const entry = bucket[i];
                if (i >= keep && entry.logProb <= bucket[keep - 1].logProb) {
                    // entry is worse than every survivor so far — skip.
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
        // Enforce the hard ceiling on survivor count so the inner loop
        // cannot grow without bound across very long sessions.
        if (survivors.length > maxPathsPerStep) {
            survivors.sort((a, b) => b.logProb - a.logProb);
            survivors = survivors.slice(0, maxPathsPerStep);
        }
        paths = survivors;
        if (paths.length === 0) break;
        if (onProgress && step - lastReportedStep >= Math.max(1, Math.floor(observedDelays.length / 50))) {
            lastReportedStep = step;
            try { onProgress({ step, total: observedDelays.length, paths: paths.length }); } catch (_e) { /* ignore */ }
        }
    }

    paths.sort((a, b) => b.logProb - a.logProb);
    const top = paths.slice(0, topN);

    // Materialize the linked-list paths back into strings / per-char arrays.
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

// ── Default model ───────────────────────────────────────────────────────

let CURRENT_MODEL = null;
function fallbackModel() {
    // Heuristic-only model used when no JSON is loaded yet (e.g. tests
    // that haven't injected a model, or when the preload bridge fails).
    return {
        layout: QWERTY_ROWS,
        coordinateIndex: DEFAULT_COORDINATE_INDEX,
        baselines: {
            sameKey: { mean: 220, std: 45 },
            adjacentKey: { mean: 95, std: 25 },
            nearbyKey: { mean: 130, std: 30 },
            farKey: { mean: 175, std: 40 },
            crossRow: { mean: 200, std: 50 },
        },
        empirical: {},
        alphabet: DECODER_ALPHABET,
        alphabetSet: DECODER_ALPHABET_SET,
    };
}

// ── Chart helpers ───────────────────────────────────────────────────────

/**
 * Build a histogram of observed inter-key delays plus a reference
 * Gaussian curve (drawn from the decoder's neutral defaults). The shape
 * matches Plotly's `scatter` + `bar` API so the renderer can plug the
 * result straight into `Plotly.newPlot`.
 */
function buildChartSeries(observedDelays, options = {}) {
    const binSize = Math.max(10, Math.floor(options.binSize || 25));
    const maxDelay = Math.max(
        500,
        ...observedDelays.filter((d) => Number.isFinite(d) && d > 0),
    );
    const bins = [];
    for (let edge = 0; edge <= maxDelay; edge += binSize) {
        bins.push({ x0: edge, x1: edge + binSize, count: 0 });
    }
    for (let i = 0; i < observedDelays.length; i += 1) {
        const d = observedDelays[i];
        if (!Number.isFinite(d) || d < 0) continue;
        const idx = Math.min(bins.length - 1, Math.floor(d / binSize));
        bins[idx].count += 1;
    }
    const histogram = {
        x: bins.map((b) => b.x0 + binSize / 2),
        y: bins.map((b) => b.count),
        type: "bar",
        name: "Observed inter-key delays",
        marker: { color: "rgba(99, 110, 250, 0.55)" },
    };

    // Reference Gaussian (decoder's neutral default).
    const mean = DEFAULT_DIGRAPH_PARAMS.mean;
    const std = DEFAULT_DIGRAPH_PARAMS.std;
    const totalCount = observedDelays.length || 1;
    const refX = [];
    const refY = [];
    for (let edge = 0; edge <= maxDelay; edge += binSize) {
        const center = edge + binSize / 2;
        refX.push(center);
        const density =
            Math.exp(gaussianLogProbability(center, mean, std)) * binSize * totalCount;
        refY.push(density);
    }
    const reference = {
        x: refX,
        y: refY,
        type: "scatter",
        mode: "lines",
        name: `Neutral Gaussian (μ=${mean} ms, σ=${std} ms)`,
        line: { color: "rgba(220, 71, 71, 0.9)", width: 2 },
    };
    return { histogram, reference, binSize };
}

// ── Obfuscation-packet detection ────────────────────────────────────────
//
// Some SSH servers insert filler packets on a fixed cadence (commonly
// every 20 ms, but the actual value varies — 5/6/10/12/15/20/25/30/40 ms
// are all seen in the wild depending on kernel scheduler, Nagle state,
// and the obfuscation library) to flood the timing channel and defeat
// keystroke-side analysis. The pattern is detectable because the
// observed inter-key delays end up sitting near integer multiples of
// the pad period with very low spread — something real typing never
// produces — and because the autocorrelation of the delay sequence
// shows a sharp peak at the pad period.
//
// `detect20msPadding(delaysMs, opts)` runs a TWO-PASS detector:
//
//   Pass 1 — autocorrelation. We slide a window over a wide range of
//   candidate periods (default 5 ms → 80 ms, 1 ms steps) and pick the
//   period whose autocorrelation peak rises highest above the local
//   noise floor. No magic period is hard-coded — the data tells us.
//
//   Pass 2 — refine. We re-run the per-period residue scan around the
//   pass-1 winner (±3 ms, 0.5 ms steps) to find the exact period with
//   the tightest residual std, and to compute coverage / dominant
//   residue / paddedIntervals.
//
// `opts` fields (all optional):
//   - `periodMinMs`       : number  - lower bound of autocorrelation scan
//                                           (default 5)
//   - `periodMaxMs`       : number  - upper bound of autocorrelation scan
//                                           (default 80)
//   - `periodStepMs`      : number  - step size for the scan (default 1)
//   - `refineStepMs`      : number  - step size for the refine pass (default 0.5)
//   - `refineWindowMs`    : number  - half-width of the refine window
//                                           around the pass-1 winner (default 3)
//   - `toleranceMs`       : number  - "near a multiple" width (default
//                                           max(2, period*0.15)). The
//                                           default scales with period so
//                                           short cadences (5 ms) get a
//                                           narrow window and long cadences
//                                           (50 ms) get a wider one.
//   - `minCoverage`       : number  - minimum fraction of delays that
//                                           must fall within tolerance of a
//                                           multiple of the candidate period
//                                           to count as detected (default 0.5)
//   - `maxResidualStdMs`  : number  - hard ceiling on the residue std
//                                           (default null = use the
//                                           period-relative rule below)
//   - `stdTighteningFactor`: number - observed std must be <= factor *
//                                           (P / sqrt(12)) to count as a
//                                           real cadence (default 0.55)
//   - `autocorrPeakThreshold`: number - minimum peak / noise-floor ratio
//                                           to accept a pass-1 candidate
//                                           (default 1.4)
//   - `minSampleCount`    : number  - minimum delays before the detector
//                                           runs (default 25)
//   - `snap`              : boolean - when true, populate
//                                           `snappedDelaysMs` and
//                                           `keystrokeDelaysMs` (default true)
//
// Returns: {
//   detected:            boolean,
//   periodMs:            number|null,
//   coverage:            number,           // fraction of intervals classified as filler
//   residualStdMs:       number,           // std-dev of residues at best period
//   dominantResidueMs:   number,           // most common residue value
//   snappedDelaysMs:     number[]|null,    // delays with integer multiples
//                                           // of period removed (preserves
//                                           // filler-padded interval count)
//   keystrokeDelaysMs:   number[]|null,    // delays with filler intervals
//                                           // removed entirely (one delay
//                                           // per real keystroke)
//   paddedIntervals:     number[]|null,    // indices into the input array
//                                           // that were classified as filler
//   pass1Candidate:      number|null,      // period suggested by pass 1
//                                           // before refine
//   pass1PeakRatio:      number,           // pass-1 first-difference
//                                           // peak / noise floor
//   candidateScores:     [{ periodMs, coverage, residualStdMs }, ...],
// }

// First-difference histogram pass 1. The most direct fingerprint of
// a fixed-cadence obfuscator is that consecutive delays differ by
// integer multiples of the cadence P. We build a histogram of
// `|delays[i+1] - delays[i]|` rounded to the nearest integer ms, and
// the strongest peak in that histogram IS the cadence.
//
// Why this works:
//   - For real typing, consecutive-delay differences follow a roughly
//     smooth distribution (no sharp peaks).
//   - For a padded session where every inter-character gap is N*P for
//     some N, the consecutive-delay difference is either 0 (same N)
//     or ±P (N changed by 1). The histogram has a sharp peak at P.
//   - The peak survives jitter: ±1 ms noise spreads P into [P-1, P+1]
//     but the bin at P still wins.
//
// Returns the candidate period (ms) with the strongest peak relative
// to the median bin, or null if no peak exceeds `peakThreshold`.
function findCadenceViaFirstDifference(delays, opts) {
    const periodMin = Number.isFinite(opts.periodMinMs) ? opts.periodMinMs : 5;
    const periodMax = Number.isFinite(opts.periodMaxMs) ? opts.periodMaxMs : 80;
    const peakThreshold = Number.isFinite(opts.autocorrPeakThreshold)
        ? opts.autocorrPeakThreshold
        : 1.6;

    // Build the histogram of first differences (in ms, rounded).
    const diffs = [];
    for (let i = 1; i < delays.length; i += 1) {
        diffs.push(Math.abs(delays[i] - delays[i - 1]));
    }
    if (diffs.length < 4) return null;

    // Use integer-ms bins up to periodMax*2 — we want enough range to
    // capture the peak even if it lands slightly above periodMax due
    // to jitter accumulation.
    const histogram = new Map();
    for (const d of diffs) {
        const key = Math.round(d);
        histogram.set(key, (histogram.get(key) || 0) + 1);
    }

    // Compute median bin count as a noise floor.
    const counts = Array.from(histogram.values()).sort((a, b) => a - b);
    const medianIdx = Math.floor(counts.length / 2);
    const noiseFloor = counts[medianIdx] || 1;

    let best = null;
    for (const [key, count] of histogram.entries()) {
        if (key < periodMin || key > periodMax) continue;
        const peakRatio = count / Math.max(noiseFloor, 1);
        if (peakRatio < peakThreshold) continue;
        if (!best || peakRatio > best.peakRatio) {
            best = { periodMs: key, peakRatio, count };
        }
    }
    return best;
}

// Autocorrelation helper kept for diagnostics / future use. It scores
// how much the delay sequence correlates with itself shifted by
// `periodMs / stepMs` samples. For padding-amplified sequences this
// returns high values, but the first-difference histogram is more
// reliable for picking the period, so this function is only used to
// surface a secondary peak ratio in the result.
function autocorrelationScore(delays, periodMs, stepMs) {
    const samplesPerPeriod = Math.max(1, Math.round(periodMs / stepMs));
    if (samplesPerPeriod <= 0 || samplesPerPeriod >= delays.length) return 0;
    const n = delays.length;
    const mean = delays.reduce((s, v) => s + v, 0) / n;
    const centered = delays.map((d) => d - mean);
    let autocorr = 0;
    let count = 0;
    for (let i = 0; i + samplesPerPeriod < n; i += 1) {
        autocorr += centered[i] * centered[i + samplesPerPeriod];
        count += 1;
    }
    let variance = 0;
    for (let i = 0; i < n; i += 1) variance += centered[i] * centered[i];
    if (variance <= 0 || count === 0) return 0;
    return (autocorr / count) / (variance / n);
}

// Pass 2 — refine. Given a candidate period, sweep a small window
// around it at sub-millisecond resolution and pick the exact period
// whose residue std is lowest AND whose coverage is highest. Then
// compute paddedIntervals / snappedDelaysMs / keystrokeDelaysMs.
function refineCadenceAtPeriod(delays, candidatePeriodMs, opts) {
    const refineStep = Number.isFinite(opts.refineStepMs) ? opts.refineStepMs : 0.5;
    const refineWindow = Number.isFinite(opts.refineWindowMs) ? opts.refineWindowMs : 3;
    const toleranceBase = Number.isFinite(opts.toleranceMs) ? opts.toleranceMs : null;
    const minCoverage = Number.isFinite(opts.minCoverage) ? opts.minCoverage : 0.5;
    const stdTighteningFactor = Number.isFinite(opts.stdTighteningFactor)
        ? opts.stdTighteningFactor
        : 0.55;
    const maxResidualStd = Number.isFinite(opts.maxResidualStdMs)
        ? opts.maxResidualStdMs
        : null;
    const snap = opts.snap !== false;

    const low = Math.max(1, candidatePeriodMs - refineWindow);
    const high = candidatePeriodMs + refineWindow;
    let best = null;
    const allScores = [];
    for (let p = low; p <= high + 1e-6; p += refineStep) {
        const tolerance = toleranceBase !== null
            ? toleranceBase
            : Math.max(2, p * 0.15);
        let matches = 0;
        const residues = [];
        const paddedIdx = [];
        for (let i = 0; i < delays.length; i += 1) {
            const d = delays[i];
            const rounded = Math.round(d / p);
            const distanceMs = Math.abs(d - rounded * p);
            if (distanceMs <= tolerance) {
                matches += 1;
                paddedIdx.push(i);
            }
            residues.push(d - rounded * p);
        }
        const coverage = matches / delays.length;
        const mean = residues.reduce((s, v) => s + v, 0) / residues.length;
        const variance = residues.reduce((s, v) => s + (v - mean) ** 2, 0) / residues.length;
        const std = Math.sqrt(variance);
        const uniformStd = p / Math.sqrt(12);
        const stdThreshold = maxResidualStd !== null
            ? Math.min(maxResidualStd, uniformStd * stdTighteningFactor)
            : uniformStd * stdTighteningFactor;
        // Mode of residues (rounded to 1 ms) for diagnostic logging.
        const buckets = new Map();
        for (const r of residues) {
            const key = Math.round(r);
            buckets.set(key, (buckets.get(key) || 0) + 1);
        }
        let dominant = 0;
        let dominantCount = -1;
        for (const [k, v] of buckets.entries()) {
            if (v > dominantCount) { dominant = k; dominantCount = v; }
        }
        const score = {
            periodMs: p,
            coverage,
            residualStdMs: std,
            uniformStdMs: uniformStd,
            stdThresholdMs: stdThreshold,
            dominantResidueMs: dominant,
            paddedIndices: paddedIdx,
        };
        allScores.push(score);
        if (!best) {
            best = { ...score };
            continue;
        }
        // Tightest cadence with the most coverage wins.
        if (
            score.coverage > best.coverage ||
            (score.coverage === best.coverage && score.residualStdMs < best.residualStdMs)
        ) {
            best = { ...score };
        }
    }

    const detected = best
        && best.coverage >= minCoverage
        && best.residualStdMs <= best.stdThresholdMs;

    if (!detected) {
        return {
            detected: false,
            periodMs: null,
            coverage: best ? best.coverage : 0,
            residualStdMs: best ? best.residualStdMs : NaN,
            dominantResidueMs: best ? best.dominantResidueMs : NaN,
            snappedDelaysMs: null,
            keystrokeDelaysMs: null,
            paddedIntervals: null,
            pass1Candidate: candidatePeriodMs,
            candidateScores: allScores,
        };
    }

    const periodMs = best.periodMs;
    const paddedIndices = best.paddedIndices;
    let snappedDelaysMs = null;
    let keystrokeDelaysMs = null;
    if (snap) {
        // snappedDelaysMs preserves interval count: each input delay
        // becomes its residue (delay - round(delay/period)*period). The
        // decoder can still consume it, but the values are now small.
        snappedDelaysMs = delays.map((d) => {
            const rounded = Math.round(d / periodMs);
            return d - rounded * periodMs;
        });
        // keystrokeDelaysMs REMOVES padded intervals entirely, so the
        // decoder sees one delay per real keystroke instead of one per
        // packet. Use this when the decoder is sensitive to interval
        // count (e.g. Viterbi beam width assumptions).
        keystrokeDelaysMs = [];
        for (let i = 0; i < delays.length; i += 1) {
            if (paddedIndices.indexOf(i) >= 0) continue;
            keystrokeDelaysMs.push(snappedDelaysMs[i]);
        }
    }

    return {
        detected: true,
        periodMs,
        coverage: best.coverage,
        residualStdMs: best.residualStdMs,
        dominantResidueMs: best.dominantResidueMs,
        snappedDelaysMs,
        keystrokeDelaysMs,
        paddedIntervals: paddedIndices,
        pass1Candidate: candidatePeriodMs,
        candidateScores: allScores,
    };
}

function detect20msPadding(delaysMs, opts) {
    const o = opts || {};
    const minSampleCount = Number.isFinite(o.minSampleCount) ? o.minSampleCount : 25;
    const snap = o.snap !== false; // default true

    const delays = Array.isArray(delaysMs)
        ? delaysMs.filter((d) => Number.isFinite(d) && d > 0)
        : [];
    const notDetected = {
        detected: false,
        periodMs: null,
        coverage: 0,
        residualStdMs: NaN,
        dominantResidueMs: NaN,
        snappedDelaysMs: null,
        keystrokeDelaysMs: null,
        paddedIntervals: null,
        pass1Candidate: null,
        pass1PeakRatio: 0,
        candidateScores: [],
    };
    if (delays.length < minSampleCount) return notDetected;

    // Pass 1 — first-difference histogram scan.
    const pass1 = findCadenceViaFirstDifference(delays, o);
    if (!pass1) {
        return Object.assign({}, notDetected);
    }

    // Pass 2 — refine around the pass-1 winner.
    const refined = refineCadenceAtPeriod(delays, pass1.periodMs, o);
    if (!refined.detected) {
        return Object.assign({}, notDetected, {
            coverage: refined.coverage,
            residualStdMs: refined.residualStdMs,
            dominantResidueMs: refined.dominantResidueMs,
            pass1Candidate: pass1.periodMs,
            pass1PeakRatio: pass1.peakRatio,
            candidateScores: refined.candidateScores.slice().sort((a, b) => {
                if (b.coverage !== a.coverage) return b.coverage - a.coverage;
                return a.residualStdMs - b.residualStdMs;
            }),
        });
    }

    return Object.assign({}, refined, {
        snappedDelaysMs: snap ? refined.snappedDelaysMs : null,
        keystrokeDelaysMs: snap ? refined.keystrokeDelaysMs : null,
        pass1PeakRatio: pass1.peakRatio,
        candidateScores: refined.candidateScores.slice().sort((a, b) => {
            if (b.coverage !== a.coverage) return b.coverage - a.coverage;
            return a.residualStdMs - b.residualStdMs;
        }),
    });
}

// ── Public surface ──────────────────────────────────────────────────────

module.exports = {
    // Constants
    QWERTY_ROWS,
    DECODER_ALPHABET,
    DEFAULT_DIGRAPH_PARAMS,
    DEFAULT_LOG_BEAM_THRESHOLD,
    // Geometry
    qwertyDistance,
    classifyDigraph,
    buildCoordinateIndex,
    // Model
    loadQwertyModel,
    resolveDigraphParams,
    gaussianLogProbability,
    scoreNextChar,
    // Decoder
    decodeKeystrokes,
    decodeKeystrokesBatched,
    // Chart
    buildChartSeries,
    // Obfuscation detection
    detect20msPadding,
    // Testing hooks
    _setModelForTesting(model) {
        CURRENT_MODEL = model;
    },
    _resetModel() {
        CURRENT_MODEL = null;
    },
};
