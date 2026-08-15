"use strict";

// Pure-JS port of scripts/shell_markov.py. Same behavior, same constants:
// n-gram order 4 by default (trigram context -> next char), Laplace alpha 0.05,
// BOS = "\u0002", EOS = "\u0003", QWERTY-distance scoring for the optional timing
// channel, length prior weight 0.35, exact-match bonus 0.25, beam branching
// capped at 24 next-chars per context.

const BOS = "\u0002";
const EOS = "\u0003";

// Mirrors Python _ROWS / SHIFT tables byte-for-byte.
const _ROWS = [
    ["`1234567890-=", 0.0],
    ["qwertyuiop[]\\", 0.25],
    ["asdfghjkl;'", 0.5],
    ["zxcvbnm,./", 0.75],
];
const SHIFT = {
    "~": "`", "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6",
    "&": "7", "*": "8", "(": "9", ")": "0", "_": "-", "+": "=",
    "{": "[", "}": "]", "|": "\\", ":": ";", '"': "'", "<": ",", ">": ".",
    "?": "/",
};
const QPOS = Object.create(null);
for (let y = 0; y < _ROWS.length; y += 1) {
    const row = _ROWS[y][0];
    const off = _ROWS[y][1];
    for (let x = 0; x < row.length; x += 1) {
        const ch = row[x];
        QPOS[ch] = [x + off, y];
        QPOS[ch.toUpperCase()] = [x + off, y];
    }
}
for (const a of Object.keys(SHIFT)) QPOS[a] = QPOS[SHIFT[a]];
QPOS[" "] = [5.0, 4.0];

const PUNCT_EXTRA = new Set("|{}[]()\"'<>?:_+~!@#$%^&*");

function keyDistance(a, b) {
    const pa = QPOS[a];
    const pb = QPOS[b];
    if (!pa || !pb) return 1.5;
    const dx = pa[0] - pb[0];
    const dy = pa[1] - pb[1];
    return Math.sqrt(dx * dx + dy * dy);
}

function cleanLines(text) {
    // Collapse pathological indentation only (mirror of clean_lines()).
    const out = [];
    for (const raw of text.split(/\r?\n/)) {
        if (!raw.trim()) continue;
        out.push(raw.replace(/^\s{2,}/, ""));
    }
    return out;
}

class ShellMarkov {
    constructor(order = 4, alpha = 0.05) {
        this.order = order;
        this.alpha = alpha;
        this.counts = Object.create(null);        // ctx -> { ch: count, ... }
        this.contextTotals = Object.create(null); // ctx -> total count
        this.vocab = Object.create(null);         // ch -> count
        this.lengths = Object.create(null);       // len -> count
        this.firstTokens = Object.create(null);   // tok -> count
        this.commandCounts = Object.create(null); // exact string -> count
        this.nCommands = 0;
    }

    train(commands) {
        const k = this.order - 1;
        for (const cmd of commands) {
            this.nCommands += 1;
            this.commandCounts[cmd] = (this.commandCounts[cmd] || 0) + 1;
            this.lengths[String(cmd.length)] = (this.lengths[String(cmd.length)] || 0) + 1;
            const trimmed = cmd.trim();
            const tok = trimmed ? trimmed.split(/\s+/, 1)[0] : "";
            if (tok) this.firstTokens[tok] = (this.firstTokens[tok] || 0) + 1;
            const seq = BOS.repeat(k) + cmd + EOS;
            for (let i = k; i < seq.length; i += 1) {
                const ctx = seq.slice(i - k, i);
                const ch = seq[i];
                if (!this.counts[ctx]) this.counts[ctx] = Object.create(null);
                this.counts[ctx][ch] = (this.counts[ctx][ch] || 0) + 1;
                this.contextTotals[ctx] = (this.contextTotals[ctx] || 0) + 1;
                this.vocab[ch] = (this.vocab[ch] || 0) + 1;
            }
        }
        return this;
    }

    get alphabet() {
        return Object.keys(this.vocab).sort();
    }

    transLogP(ctx, ch) {
        const c = this.counts[ctx];
        const V = Math.max(1, Object.keys(this.vocab).length);
        const n = c && c[ch] ? c[ch] : 0;
        const total = this.contextTotals[ctx] || 0;
        return Math.log((n + this.alpha) / (total + this.alpha * V));
    }

    commandLogP(cmd, includeLength = true) {
        const k = this.order - 1;
        const seq = BOS.repeat(k) + cmd + EOS;
        let lp = 0;
        let n = 0;
        for (let i = k; i < seq.length; i += 1) {
            lp += this.transLogP(seq.slice(i - k, i), seq[i]);
            n += 1;
        }
        // length-normalised average, like Python
        lp /= Math.max(1, n);
        if (includeLength) {
            let total = 0;
            for (const k2 of Object.keys(this.lengths)) total += this.lengths[k2];
            const lenKey = String(cmd.length);
            lp += 0.35 * Math.log(
                ((this.lengths[lenKey] || 0) + 1) / (total + Object.keys(this.lengths).length),
            );
        }
        if (this.commandCounts[cmd]) {
            lp += 0.25 * Math.log1p(this.commandCounts[cmd]);
        }
        return lp;
    }

    timingScore(cmd, delaysMs) {
        if (!delaysMs || cmd.length < 2) return 0;
        const ds = delaysMs.slice(0, Math.max(0, cmd.length - 1)).map((x) => Number(x));
        if (ds.length < 2) return 0;
        const sorted = ds.slice().sort((a, b) => a - b);
        const med = sorted[Math.floor(sorted.length / 2)];
        const madVals = sorted.map((x) => Math.abs(x - med)).sort((a, b) => a - b);
        const mad = madVals[Math.floor(madVals.length / 2)] || 1.0;
        const z = ds.map((d) => Math.max(-3, Math.min(3, (d - med) / (1.4826 * mad))));
        const moves = [];
        for (let i = 0; i < cmd.length - 1; i += 1) {
            let d = keyDistance(cmd[i], cmd[i + 1]);
            if (SHIFT[cmd[i + 1]] || PUNCT_EXTRA.has(cmd[i + 1])) d += 0.55;
            moves.push(d);
        }
        let zA = z;
        let mA = moves;
        if (moves.length > zA.length) mA = moves.slice(0, zA.length);
        if (zA.length > mA.length) zA = zA.slice(0, mA.length);
        if (mA.length < 2) return 0;
        const mm = mA.reduce((s, x) => s + x, 0) / mA.length;
        const mv = Math.sqrt(
            mA.reduce((s, x) => s + (x - mm) ** 2, 0) / mA.length,
        ) || 1.0;
        const mz = mA.map((x) => (x - mm) / mv);
        let mse = 0;
        for (let i = 0; i < zA.length; i += 1) mse += (mz[i] - zA[i]) ** 2;
        return -mse / zA.length;
    }

    score(cmd, delaysMs, timingWeight = 0.22) {
        let s = this.commandLogP(cmd);
        if (delaysMs) s += timingWeight * this.timingScore(cmd, delaysMs);
        return s;
    }

    rank(candidates, delaysMs, timingWeight = 0.22) {
        const out = [];
        for (const c of candidates) out.push([this.score(c, delaysMs, timingWeight), c]);
        out.sort((a, b) => b[0] - a[0]);
        return out;
    }

    generateBeam(targetLen = null, tolerance = 3, beam = 500, maxLen = 120, topn = 30) {
        const k = this.order - 1;
        const vocabLen = Object.keys(this.vocab).length;
        // initial states
        let states = [[0.0, BOS.repeat(k), ""]];
        const finals = [];
        for (let step = 0; step <= maxLen; step += 1) {
            const next = [];
            for (const [score, ctx, text] of states) {
                // Prevent repeating patterns: if the last 3 chars are the same
                // as the 3 chars before them, skip this state
                if (text.length >= 6 && text.slice(-3) === text.slice(-6, -3)) {
                    // Allow legitimate patterns like "user@server" but block
                    // garbage like "ser@ser@ser@ser"
                    const last6 = text.slice(-6);
                    if (last6.includes("@") && last6.split("@").length > 2) {
                        continue;
                    }
                }
                const cands = this.counts[ctx];
                if (!cands) {
                    // Fallback: if no transition counts for this context,
                    // use the model's vocabulary to continue generation.
                    // This prevents the beam search from exiting early
                    // when encountering unseen context patterns.
                    const fallbackChars = Object.keys(this.vocab).filter(
                        c => c !== BOS && c !== EOS
                    );
                    if (fallbackChars.length > 0) {
                        const rand = fallbackChars[Math.floor(Math.random() * fallbackChars.length)];
                        const nctx = (ctx + rand).slice(-k);
                        const nt = text + rand;
                        next.push([0.0, nctx, nt]);
                    }
                    continue;
                }
                const items = Object.entries(cands).sort((a, b) => b[1] - a[1]).slice(0, 24);
                for (const [ch] of items) {
                    const ns = score + this.transLogP(ctx, ch);
                    if (ch === EOS) {
                        const L = text.length;
                        if (targetLen === null || Math.abs(L - targetLen) <= tolerance) {
                            finals.push([this.commandLogP(text), text]);
                        }
                        continue;
                    }
                    if (targetLen !== null && text.length >= targetLen + tolerance) continue;
                    const nt = text + ch;
                    const nctx = (ctx + ch).slice(-k);
                    next.push([ns, nctx, nt]);
                }
            }
            if (next.length === 0) break;
            // length-normalised score for ranking, like Python's `score/len(text)`
            next.sort((a, b) => (b[0] / Math.max(1, b[2].length)) - (a[0] / Math.max(1, a[2].length)));
            states = next.slice(0, beam);
        }
        // dedupe finals, keep best score per string
        const best = Object.create(null);
        for (const [s, t] of finals) {
            if (!(t in best) || s > best[t]) best[t] = s;
        }
        return Object.entries(best)
            .map(([t, s]) => [s, t])
            .sort((a, b) => b[0] - a[0])
            .slice(0, topn);
    }

    toDict() {
        return {
            model_type: "character_markov_shell_command_prior",
            order: this.order,
            alpha: this.alpha,
            n_commands: this.nCommands,
            vocab: { ...this.vocab },
            lengths: { ...this.lengths },
            first_tokens: { ...this.firstTokens },
            command_counts: { ...this.commandCounts },
            transitions: Object.fromEntries(
                Object.entries(this.counts).map(([k2, v]) => [k2, { ...v }]),
            ),
        };
    }

    static fromDict(d) {
        const m = new ShellMarkov(d.order, d.alpha != null ? d.alpha : 0.05);
        m.nCommands = d.n_commands || 0;
        m.vocab = { ...(d.vocab || {}) };
        const lenKeys = Object.keys(d.lengths || {});
        const lenObj = Object.create(null);
        for (const k2 of lenKeys) lenObj[String(k2)] = d.lengths[k2];
        m.lengths = lenObj;
        m.firstTokens = { ...(d.first_tokens || {}) };
        m.commandCounts = { ...(d.command_counts || {}) };
        for (const [k2, cnt] of Object.entries(d.transitions || {})) {
            m.counts[k2] = { ...cnt };
            m.contextTotals[k2] = Object.values(cnt).reduce((s, x) => s + x, 0);
        }
        return m;
    }
}

function loadDelays(jsonText) {
    const d = JSON.parse(jsonText);
    const out = [];
    for (const x of d.delays || []) {
        if (typeof x.delayMs === "number" && Number.isFinite(x.delayMs)) out.push(x.delayMs);
    }
    return out;
}

// ── Enhanced Confidence Calculation ──────────────────────────────────
//
// These functions provide comprehensive confidence scoring for both
// individual Markov candidates (line confidence) and overall session
// quality (session confidence).

/**
 * Computes a line confidence score for a single Markov candidate command.
 *
 * Factors considered:
 * - Length match: penalty if command length differs from estimated
 * - Timing match: QWERTY distance correlation with observed delays
 * - Obfuscation penalty: if padding was detected, confidence is reduced
 * - Markov probability: the model's inherent score for this command
 * - First token validity: does it look like a valid shell command?
 *
 * Returns a confidence value in [0, 1] range.
 */
function computeLineConfidence(cmd, opts) {
    if (!cmd || typeof cmd !== "string") return 0.0;

    const options = opts || {};
    let confidence = 0.5; // baseline
    let factors = [];

    // 1. Length match factor
    if (Number.isFinite(options.estimatedLength) && options.estimatedLength > 0) {
        const lenDiff = Math.abs(cmd.length - options.estimatedLength);
        // Penalty: 0.1 per character difference beyond tolerance
        const tolerance = options.lengthTolerance || 2;
        const excessDiff = Math.max(0, lenDiff - tolerance);
        const lengthPenalty = excessDiff * 0.1;
        const lengthFactor = Math.max(0.3, 1.0 - lengthPenalty);
        factors.push({ name: "lengthMatch", weight: 0.25, value: lengthFactor });
    }

    // 2. Timing match factor (using QWERTY distance correlation)
    if (Array.isArray(options.delaysMs) && options.delaysMs.length >= 2 && cmd.length >= 2) {
        const ds = options.delaysMs.slice(0, cmd.length - 1).map(Number);
        if (ds.length >= 2) {
            const sorted = ds.slice().sort((a, b) => a - b);
            const med = sorted[Math.floor(sorted.length / 2)];
            const madVals = sorted.map((x) => Math.abs(x - med)).sort((a, b) => a - b);
            const mad = madVals[Math.floor(madVals.length / 2)] || 1.0;
            const z = ds.map((d) => Math.max(-3, Math.min(3, (d - med) / (1.4826 * mad))));

            const moves = [];
            for (let i = 0; i < cmd.length - 1; i += 1) {
                let d = keyDistance(cmd[i], cmd[i + 1]);
                if (SHIFT[cmd[i + 1]] || PUNCT_EXTRA.has(cmd[i + 1])) d += 0.55;
                moves.push(d);
            }

            const zA = z.slice(0, moves.length);
            if (zA.length >= 2) {
                const mm = moves.reduce((s, x) => s + x, 0) / moves.length;
                const mv = Math.sqrt(
                    moves.reduce((s, x) => s + (x - mm) ** 2, 0) / moves.length
                ) || 1.0;
                const mz = moves.map((x) => (x - mm) / mv);

                // Compute negative MSE (higher = better match)
                let mse = 0;
                for (let i = 0; i < zA.length; i += 1) mse += (mz[i] - zA[i]) ** 2;
                const negMse = -mse / zA.length;

                // Convert to [0.3, 1.0] range
                // Typical negMse ranges from -10 (poor) to 0 (perfect)
                const timingFactor = Math.min(1.0, Math.max(0.3, 0.65 + negMse * 0.1));
                factors.push({ name: "timingMatch", weight: 0.30, value: timingFactor });
            }
        }
    }

    // 3. Obfuscation penalty
    if (options.obfuscationDetected) {
        const coverage = Number.isFinite(options.obfuscationCoverage)
            ? options.obfuscationCoverage
            : 0.5;
        // Higher coverage = lower confidence
        const obfuscationFactor = Math.max(0.5, 1.0 - coverage * 0.4);
        factors.push({ name: "obfuscation", weight: 0.15, value: obfuscationFactor });
    }

    // 4. Markov probability factor (if available)
    if (Number.isFinite(options.markovScore)) {
        // Normalize markov score to [0, 1] range
        // Typical scores range from -10 (low prob) to -1 (high prob)
        const normalized = Math.min(1.0, Math.max(0.3, (options.markovScore + 10) / 9));
        factors.push({ name: "markovProb", weight: 0.20, value: normalized });
    }

    // 5. First token validity (shell command heuristic)
    if (cmd.trim()) {
        const firstToken = cmd.trim().split(/\s+/)[0] || "";
        // Check if first token looks like a typical shell command
        const validShellPrefixes = [
            "ls", "cd", "cat", "grep", "find", "git", "sudo", "apt", "yum", "dnf",
            "chmod", "chown", "mkdir", "rm", "cp", "mv", "ssh", "scp", "curl", "wget",
            "python", "python3", "node", "npm", "docker", "kubectl", "vim", "nano",
            "systemctl", "service", "journalctl", "tail", "head", "less", "more",
            "echo", "export", "source", "./", "../", "/", "~/",
        ];
        let tokenScore = 0.5;
        if (firstToken.length >= 2) {
            for (const prefix of validShellPrefixes) {
                if (firstToken.startsWith(prefix)) {
                    tokenScore = 0.85;
                    if (firstToken === prefix) tokenScore = 0.95; // exact match
                    break;
                }
            }
            // Penalize if first token contains weird chars
            if (/[^\w\-\/\.]/.test(firstToken)) {
                tokenScore = Math.max(0.3, tokenScore - 0.2);
            }
        }
        factors.push({ name: "firstToken", weight: 0.10, value: tokenScore });
    }

    // If no factors, return baseline
    if (factors.length === 0) return confidence;

    // Compute weighted average
    let totalWeight = 0;
    let weightedScore = 0;
    for (const f of factors) {
        totalWeight += f.weight;
        weightedScore += f.value * f.weight;
    }

    confidence = totalWeight > 0 ? weightedScore / totalWeight : 0.5;

    // Clamp to [0, 1]
    return Math.min(1.0, Math.max(0.0, confidence));
}

/**
 * Computes a session confidence score for the entire SSH timing analysis.
 *
 * Factors considered:
 * - Number of detected chunks/commands (more = better)
 * - Delay variability (CV - coefficient of variation)
 * - Obfuscation level (percentage of padding detected)
 * - Signal quality (median delay, presence of clear boundaries)
 * - Number of small packets (keystroke indicators)
 *
 * Returns an object with:
 * - score: overall session confidence [0, 1]
 * - factors: breakdown of individual factors
 * - interpretation: human-readable explanation
 */
function computeSessionConfidence(opts) {
    const options = opts || {};
    let factors = [];

    // 1. Chunk count factor (number of detected commands)
    if (Number.isFinite(options.chunkCount) && options.chunkCount >= 0) {
        let chunkFactor;
        if (options.chunkCount === 0) {
            chunkFactor = 0.2; // no chunks detected
        } else if (options.chunkCount === 1) {
            chunkFactor = 0.6; // single command
        } else if (options.chunkCount <= 3) {
            chunkFactor = 0.8; // few commands
        } else {
            chunkFactor = Math.min(1.0, 0.8 + (options.chunkCount - 3) * 0.05);
        }
        factors.push({ name: "chunkCount", weight: 0.20, value: chunkFactor, label: `Detected ${options.chunkCount} command(s)` });
    }

    // 2. Delay variability (CV = std/mean)
    // Human typing has CV ~0.5-1.0; scripts/paste have CV ~0.1
    if (Number.isFinite(options.delayMean) && Number.isFinite(options.delayStd)) {
        const cv = options.delayMean > 0 ? options.delayStd / options.delayMean : 0;
        let cvFactor;
        if (cv < 0.1) {
            cvFactor = 0.3; // too uniform - likely script/paste
        } else if (cv < 0.3) {
            cvFactor = 0.6; // somewhat uniform
        } else if (cv < 0.5) {
            cvFactor = 0.85; // good variability
        } else if (cv < 1.5) {
            cvFactor = 1.0; // excellent - typical human typing
        } else {
            cvFactor = 0.7; // high variability - may be noise
        }
        factors.push({ name: "delayVariability", weight: 0.25, value: cvFactor, label: `CV = ${cv.toFixed(2)}` });
    }

    // 3. Obfuscation level
    if (options.obfuscationDetected) {
        const coverage = Number.isFinite(options.obfuscationCoverage)
            ? options.obfuscationCoverage
            : 0.5;
        let obfusFactor;
        if (coverage < 0.2) {
            obfusFactor = 0.9; // minimal obfuscation
        } else if (coverage < 0.5) {
            obfusFactor = 0.7; // moderate
        } else if (coverage < 0.8) {
            obfusFactor = 0.5; // significant
        } else {
            obfusFactor = 0.3; // heavy obfuscation
        }
        factors.push({ name: "obfuscationLevel", weight: 0.25, value: obfusFactor, label: `${(coverage * 100).toFixed(0)}% padding` });
    } else {
        factors.push({ name: "obfuscationLevel", weight: 0.25, value: 1.0, label: "No padding detected" });
    }

    // 4. Signal quality (median delay and gap detection)
    if (Number.isFinite(options.medianDelayMs)) {
        let medianFactor;
        if (options.medianDelayMs < 30) {
            medianFactor = 0.4; // too fast - likely not human
        } else if (options.medianDelayMs < 60) {
            medianFactor = 0.7; // fast typing
        } else if (options.medianDelayMs < 200) {
            medianFactor = 1.0; // typical human typing
        } else if (options.medianDelayMs < 500) {
            medianFactor = 0.8; // slower, thinking
        } else {
            medianFactor = 0.6; // very slow - maybe noise
        }
        factors.push({ name: "medianDelay", weight: 0.15, value: medianFactor, label: `Median = ${options.medianDelayMs.toFixed(0)}ms` });
    }

    // 5. Clear boundary detection (Return gaps)
    if (Number.isFinite(options.clearGapCount)) {
        let gapFactor;
        if (options.clearGapCount === 0) {
            gapFactor = 0.4; // no clear boundaries
        } else if (options.clearGapCount === 1) {
            gapFactor = 0.7; // one boundary
        } else {
            gapFactor = Math.min(1.0, 0.7 + (options.clearGapCount - 1) * 0.1);
        }
        factors.push({ name: "clearBoundaries", weight: 0.15, value: gapFactor, label: `${options.clearGapCount} clear gap(s)` });
    }

    // Compute overall score
    let totalWeight = 0;
    let weightedScore = 0;
    for (const f of factors) {
        totalWeight += f.weight;
        weightedScore += f.value * f.weight;
    }

    const score = totalWeight > 0 ? weightedScore / totalWeight : 0.5;
    const clampedScore = Math.min(1.0, Math.max(0.0, score));

    // Generate interpretation
    let interpretation;
    if (clampedScore >= 0.8) {
        interpretation = "Excellent signal quality - results are highly reliable";
    } else if (clampedScore >= 0.6) {
        interpretation = "Good signal quality - results are reasonably reliable";
    } else if (clampedScore >= 0.4) {
        interpretation = "Moderate signal quality - results should be treated with caution";
    } else {
        interpretation = "Poor signal quality - results may be unreliable";
    }

    return {
        score: clampedScore,
        factors: factors,
        interpretation: interpretation,
        label: `${(clampedScore * 100).toFixed(0)}%`,
    };
}

/**
 * Helper to compute delay statistics (mean, std, median, MAD) from an array of delays.
 */
function computeDelayStats(delaysMs) {
    if (!Array.isArray(delaysMs) || delaysMs.length === 0) {
        return { mean: 0, std: 0, median: 0, mad: 0, count: 0 };
    }

    const valid = delaysMs.filter((d) => Number.isFinite(d) && d > 0);
    if (valid.length === 0) {
        return { mean: 0, std: 0, median: 0, mad: 0, count: 0 };
    }

    const mean = valid.reduce((s, x) => s + x, 0) / valid.length;
    const variance = valid.reduce((s, x) => s + (x - mean) ** 2, 0) / valid.length;
    const std = Math.sqrt(variance);

    const sorted = valid.slice().sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    const median = sorted.length % 2 === 1
        ? sorted[mid]
        : (sorted[mid - 1] + sorted[mid]) / 2;

    const absDevs = sorted.map((x) => Math.abs(x - median)).sort((a, b) => a - b);
    const mad = absDevs[Math.floor(absDevs.length / 2)] || 0;

    return {
        mean: mean,
        std: std,
        median: median,
        mad: mad,
        count: valid.length,
        cv: mean > 0 ? std / mean : 0,
    };
}

module.exports = {
    ShellMarkov,
    cleanLines,
    loadDelays,
    keyDistance,
    BOS,
    EOS,
    computeLineConfidence,
    computeSessionConfidence,
    computeDelayStats,
};
