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

module.exports = {
    ShellMarkov,
    cleanLines,
    loadDelays,
    keyDistance,
    BOS,
    EOS,
};
