"use strict";

// Pure-JS port of scripts/shell_markov.py. Same behavior, same constants:
// n-gram order 4 by default (trigram context -> next char), Laplace alpha 0.05,
// BOS = "\u0002", EOS = "\u0003", QWERTY-distance scoring for the optional timing
// channel, length prior weight 0.35, exact-match bonus 0.25, beam branching
// capped at 24 next-chars per context.

const BOS = "\u0002";
const EOS = "\u0003";

// Slot marker: used to identify variable-length argument positions in templates.
// When a command template has a slot, arguments matching that position can
// be 1-64 chars without incurring a strict total-length mismatch penalty.
const SLOT_MARKER = "\u25c6";  // ◆ - diamond marker for slots

// Slot patterns: these define common placeholder patterns in the corpus.
// During scoring, if a candidate matches the "skeleton" of a corpus command
// but has different content in a slot position, it doesn't get penalized
// for total-length mismatch (only the character transitions matter).
const SLOT_PATTERNS = [
    // Filename-like placeholders
    { pattern: /\bfile\.(txt|log|conf|py|js|json|md|sh|bak)\b/gi, type: "filename" },
    { pattern: /\b(file|filename|target|link|backup)\b/gi, type: "filename", wordOnly: true },
    // Directory placeholders  
    { pattern: /\b(directory|dir|src|build|logs|tmp)\b/gi, type: "directory", wordOnly: true },
    // User@host placeholders
    { pattern: /\b(user|root)@(server|host)\b/gi, type: "user_at_host" },
    { pattern: /\b(user|root)@[\d\.]+/gi, type: "user_at_host" },  // user@192.168.1.1
    // Hostname/IP placeholders
    { pattern: /\b(server|host|localhost)\b/gi, type: "hostname", wordOnly: true },
    { pattern: /\bexample\.com\b/gi, type: "hostname" },
    // Path placeholders
    { pattern: /~\/\.ssh\/[^ \t]+/gi, type: "path" },  // ~/.ssh/id_rsa
    { pattern: /\/(var|tmp|etc|usr|opt|root|home)\//gi, type: "path" },
    // URL placeholders
    { pattern: /https?:\/\/[^\s]+/gi, type: "url" },
    // Bucket/resource placeholders (AWS/S3)
    { pattern: /\bbucket\b/gi, type: "bucket", wordOnly: true },
    { pattern: /s3:\/\/[^\s]+/gi, type: "s3path" },
];

// Fixed structure tokens: these are part of the command "skeleton" that should match.
// If these differ between corpus template and candidate, it's a different command.
const FIXED_STRUCTURE_TOKENS = new Set([
    // Commands
    "ls", "cd", "cat", "grep", "find", "tail", "head", "less", "more",
    "ssh", "scp", "rsync", "wget", "curl",
    "git", "npm", "node", "python", "python3", "pip",
    "sudo", "systemctl", "service", "journalctl",
    "chmod", "chown", "ln", "mkdir", "rm", "cp", "mv", "touch",
    "ps", "top", "htop", "df", "du", "free", "uname",
    "which", "whoami", "id", "hostname", "echo", "history",
    // Common subcommands/flags that are structural
    "status", "start", "stop", "restart", "enable", "disable",
    "clone", "push", "pull", "add", "commit", "checkout", "branch", "switch",
    "diff", "log", "fetch", "stash", "remote",
    "install", "run", "build", "test", "dev",
    "-r", "-R", "-rf", "-f", "-v", "-h", "-n", "-m", "-i", "-a", "-av", "-avz",
    "-p", "-P", "-L", "-R", "-D", "-X", "-d",
    "--recursive", "--force", "--verbose", "--help",
    // Special shell syntax
    "|", ">", ">>", "<", "<<", "&&", "||", ";",
    ".", "..", "~", "/", "./", "../",
    // Quotes (content inside varies, but quotes are structure)
    "'", "\"", "`",
    // Common path roots
    "/tmp", "/var", "/etc", "/usr", "/home", "/root", "/opt",
]);

// Extract a command template from a corpus command by replacing slot patterns
// with the slot marker. This helps match variable arguments during scoring.
function extractCommandTemplate(cmd) {
    let template = cmd;
    // Apply slot patterns - replace matches with slot marker
    for (const sp of SLOT_PATTERNS) {
        if (sp.wordOnly) {
            // Word-boundary only replacement
            template = template.replace(sp.pattern, SLOT_MARKER);
        } else {
            template = template.replace(sp.pattern, SLOT_MARKER);
        }
    }
    // Collapse multiple adjacent slot markers
    template = template.replace(new RegExp(`${SLOT_MARKER}+`, "g"), SLOT_MARKER);
    return template;
}

// Check if a candidate command matches the "skeleton" of a template command.
// The skeleton is the fixed structure (commands, flags, operators) - slots
// can contain variable content.
function matchesSkeleton(candidate, templateCmd) {
    // Quick check: tokenize and compare non-slot tokens
    const candTokens = tokenizeCommand(candidate);
    const tmplTokens = tokenizeCommand(templateCmd);

    // If they have wildly different token counts, it's not a match
    if (Math.abs(candTokens.length - tmplTokens.length) > 3) {
        return false;
    }

    // Check if the command (first non-flag token) matches
    const candCmd = candTokens.find(t => !t.startsWith("-") && t.length > 0);
    const tmplCmd = tmplTokens.find(t => !t.startsWith("-") && t.length > 0 && t !== SLOT_MARKER);

    if (tmplCmd && candCmd !== tmplCmd) {
        return false;
    }

    return true;
}

// Simple command tokenizer that respects quotes
function tokenizeCommand(cmd) {
    const tokens = [];
    let current = "";
    let inQuote = null;  // null, "'", or '"'

    for (let i = 0; i < cmd.length; i += 1) {
        const ch = cmd[i];

        if (inQuote) {
            if (ch === inQuote) {
                inQuote = null;
            }
            current += ch;
        } else if (ch === "'" || ch === '"') {
            inQuote = ch;
            current += ch;
        } else if (/\s/.test(ch)) {
            if (current.length > 0) {
                tokens.push(current);
                current = "";
            }
        } else if (/[|&;<>()]/.test(ch)) {
            if (current.length > 0) {
                tokens.push(current);
                current = "";
            }
            // Check for 2-char operators like &&, ||, >>, <<
            if (i + 1 < cmd.length && /[|&<>]/.test(ch) && cmd[i + 1] === ch) {
                tokens.push(ch + ch);
                i += 1;
            } else {
                tokens.push(ch);
            }
        } else {
            current += ch;
        }
    }

    if (current.length > 0) {
        tokens.push(current);
    }

    return tokens;
}

// Calculate a "structure match score" between candidate and a corpus command.
// Returns:
//   - matchScore: 0-1, how well the structure matches
//   - fixedLength: length of non-slot characters in template
//   - hasSlots: whether the template has variable slots
function compareToTemplate(candidate, corpusCmd) {
    const candLen = candidate.length;
    const corpusLen = corpusCmd.length;

    // Check structure match
    const skeletonMatch = matchesSkeleton(candidate, corpusCmd);

    // Check for slot patterns in both
    let hasSlots = false;
    for (const sp of SLOT_PATTERNS) {
        if (sp.pattern.test(corpusCmd)) {
            hasSlots = true;
            sp.pattern.lastIndex = 0;  // reset
            break;
        }
    }

    // Calculate expected fixed length (rough estimate)
    let fixedLength = corpusLen;
    if (hasSlots) {
        // Subtract estimated slot lengths from corpus command
        for (const sp of SLOT_PATTERNS) {
            const matches = corpusCmd.match(sp.pattern);
            if (matches) {
                for (const m of matches) {
                    fixedLength -= m.length;
                }
            }
            sp.pattern.lastIndex = 0;
        }
        // Add back minimum slot content
        fixedLength += 1;  // at least 1 char per slot
    }

    return {
        skeletonMatch,
        fixedLength,
        hasSlots,
        corpusLength: corpusLen,
        candidateLength: candLen,
    };
}

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

    // Find the best matching corpus template for a candidate command.
    // Returns { template, matchScore, fixedLength } or null if no good match.
    _findBestMatchingTemplate(cmd) {
        // If we have no commandCounts or it's empty, skip template matching
        const corpusCommands = Object.keys(this.commandCounts);
        if (!corpusCommands || corpusCommands.length === 0) {
            return null;
        }

        const candTokens = tokenizeCommand(cmd);
        const candCmdToken = candTokens.find(t => !t.startsWith("-") && t.length > 0);

        if (!candCmdToken) return null;

        let bestMatch = null;
        let bestScore = -Infinity;

        // Search through corpus commands for structure matches
        for (const corpusCmd of corpusCommands) {
            const tmplTokens = tokenizeCommand(corpusCmd);
            const tmplCmdToken = tmplTokens.find(t => !t.startsWith("-") && t.length > 0);

            // Must have same base command
            if (!tmplCmdToken || tmplCmdToken !== candCmdToken) {
                continue;
            }

            // Compare structure
            const comparison = compareToTemplate(cmd, corpusCmd);

            if (comparison.skeletonMatch) {
                // Score based on:
                // 1. Has slots (prefer templates with slots for variable args)
                // 2. Token count similarity
                const tokenDiff = Math.abs(candTokens.length - tmplTokens.length);
                let score = 0;

                if (comparison.hasSlots) {
                    score += 10;  // Slots are good for variable matching
                }
                score -= tokenDiff * 2;  // Penalize token count differences

                // If exact match (no length difference), boost
                if (cmd === corpusCmd) {
                    score += 100;
                }

                if (score > bestScore) {
                    bestScore = score;
                    bestMatch = {
                        template: corpusCmd,
                        hasSlots: comparison.hasSlots,
                        fixedLength: comparison.fixedLength,
                        corpusLength: comparison.corpusLength,
                        tokenMatchScore: score,
                    };
                }
            }
        }

        return bestMatch;
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

            // Check for slot-aware length matching
            let lenKey = String(cmd.length);
            let useSlotAware = false;
            let slotLengthBonus = 0;

            const bestTemplate = this._findBestMatchingTemplate(cmd);

            if (bestTemplate && bestTemplate.hasSlots) {
                // This candidate matches a template that has slots.
                // Use a more flexible length calculation:
                // - The FIXED structure must match roughly
                // - Slot content can vary (1-64 chars per slot)

                const candLen = cmd.length;
                const fixedLen = bestTemplate.fixedLength;
                const corpusLen = bestTemplate.corpusLength;

                // How much "extra" length does the candidate have beyond fixed?
                // This is assumed to be slot content
                const slotContentLen = Math.max(0, candLen - fixedLen);

                // Slot content should be reasonable (1-64 chars per typical slot)
                // We'll allow generous variation: 0-128 chars of slot content
                if (slotContentLen <= 128 && slotContentLen >= 0) {
                    useSlotAware = true;

                    // For slot-aware matching:
                    // 1. Use the corpus command's length as a baseline
                    // 2. But add a bonus based on slot content reasonableness

                    // Try both the actual length AND the corpus length, take the better one
                    const corpusLenKey = String(corpusLen);
                    const actualLenProb = Math.log(
                        ((this.lengths[lenKey] || 0) + 1) / (total + Object.keys(this.lengths).length),
                    );
                    const corpusLenProb = Math.log(
                        ((this.lengths[corpusLenKey] || 0) + 1) / (total + Object.keys(this.lengths).length),
                    );

                    // Use whichever length gives a better probability
                    // Also add a small bonus for slot-aware matching being used
                    slotLengthBonus = Math.max(actualLenProb, corpusLenProb) + 0.1;
                }
            }

            if (useSlotAware) {
                lp += 0.35 * slotLengthBonus;
            } else {
                // Original strict length matching
                lp += 0.35 * Math.log(
                    ((this.lengths[lenKey] || 0) + 1) / (total + Object.keys(this.lengths).length),
                );
            }
        }

        // Exact match bonus (still valuable even with slots)
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

        // Calculate a typical bad transition log-prob for fallback scoring
        // With alpha=0.05, unseen transitions get ~log(0.05 / (total + 0.05*V))
        // We want fallback to be significantly WORSE than any real transition
        const FALLBACK_LOG_P = Math.log(this.alpha / (1000 + this.alpha * vocabLen));  // ~-15 or worse

        // initial states: [score, ctx, text, visitedContextsSet]
        // visitedContextsSet tracks which (context + position_in_text) we've seen
        // to prevent cycles: Markov order=4 means context is 3 chars, which is easy to cycle
        let states = [[0.0, BOS.repeat(k), "", new Set()]];
        const finals = [];
        // Helper: detect pathological repeating patterns in generated text
        function _isRepeatingGarbage(text) {
            const len = text.length;
            if (len < 10) return false;

            // ========== APPROACH ==========
            // Instead of just checking aligned repetition at the END, we need to:
            // 1. Check for ANY repeating unit in the suffix (not just end-aligned)
            // 2. Check units up to 48 chars (for patterns like "file.command . -type ")
            // 3. Use entropy/density metrics to detect pathological behavior
            // 4. Look for suspicious repetition counts of common placeholder words

            // --- Check 1: End-aligned repetition with extended unit lengths ---
            // Check units from 2 to 48 characters at the very end
            for (let unitLen = 2; unitLen <= 48; unitLen += 1) {
                const minReps = unitLen <= 8 ? 3 : 2;  // More reps needed for shorter units
                if (len < unitLen * minReps) continue;

                const lastUnit = text.slice(-unitLen);

                // Check if this unit repeats backwards from the end
                let consecutiveReps = 1;
                for (let i = 1; i < minReps + 1; i += 1) {
                    const startPos = len - unitLen * (i + 1);
                    if (startPos < 0) break;
                    const checkUnit = text.slice(startPos, startPos + unitLen);
                    if (checkUnit === lastUnit) {
                        consecutiveReps += 1;
                    } else {
                        break;
                    }
                }

                if (consecutiveReps >= minReps) {
                    // This is definitely pathological - 2+ full repetitions at the end
                    // For very short units, require more reps to avoid false positives

                    // Extra check: allow legit repetition like "==========" (visual separators)
                    const allSameInUnit = lastUnit.split("").every(c => c === lastUnit[0]);

                    // But if it's 2+ different chars repeating, it's garbage
                    if (!allSameInUnit || consecutiveReps >= 5) {
                        return true;
                    }
                }
            }

            // --- Check 2: Find ANY repeating substring in the last 200 chars ---
            // Patterns like "file.command . -type file.command . -type" may not align
            // perfectly to the end if there's a partial tail

            const suffixLen = Math.min(len, 200);
            const suffix = text.slice(-suffixLen);

            // Look for common pathological substrings that appear in your examples:
            const pathologicalPatterns = [
                /file\.command /g,
                /file\.command \. -type /g,
                /python3 -m /g,
                /\.command \. -type /g,
                /systemctl /g,  // if repeated 2x
            ];

            for (const pattern of pathologicalPatterns) {
                const matches = suffix.match(pattern);
                if (matches && matches.length >= 3) {
                    // 3+ occurrences of the same pathological substring = garbage
                    return true;
                }
            }

            // --- Check 3: @ symbol density (original bug pattern) ---
            const atCount = (suffix.match(/@/g) || []).length;
            if (atCount >= 4 && suffixLen >= 20) {
                // High @ density = repeating @ser pattern
                return true;
            }

            // --- Check 4: Suspicious placeholder words repetition ---
            const placeholders = ["file", "directory", "path", "target", "user", "server", "python3"];
            let totalPlaceholderCount = 0;
            for (const ph of placeholders) {
                const phRegex = new RegExp(`\\b${ph}\\b`, "g");
                const phCount = (suffix.match(phRegex) || []).length;
                totalPlaceholderCount += phCount;
            }
            if (totalPlaceholderCount >= 8 && suffixLen >= 50) {
                // 8+ placeholder words in short space = pathological beam loop
                return true;
            }

            // --- Check 5: Repetition density heuristic ---
            // Count how many times 6-gram substrings repeat in the suffix
            // Normal text has low repetition; beam loops have very high repetition
            const gramCounts = new Map();
            const gramLen = 6;
            if (suffixLen >= gramLen * 3) {
                for (let i = 0; i <= suffixLen - gramLen; i += 1) {
                    const gram = suffix.slice(i, i + gramLen);
                    gramCounts.set(gram, (gramCounts.get(gram) || 0) + 1);
                }

                // Count grams that appear 4+ times
                let highFreqGrams = 0;
                for (const count of gramCounts.values()) {
                    if (count >= 4) highFreqGrams += 1;
                }

                // If many grams repeat frequently, it's a loop
                const uniqueGrams = gramCounts.size;
                if (highFreqGrams >= 5 && uniqueGrams > 0) {
                    const highFreqRatio = highFreqGrams / uniqueGrams;
                    if (highFreqRatio > 0.15) {  // >15% of grams are high-freq
                        return true;
                    }
                }
            }

            return false;
        }

        for (let step = 0; step <= maxLen; step += 1) {
            const next = [];
            for (const [score, ctx, text, visited] of states) {
                // Block pathological repeating patterns: "@ser@ser@ser", "aaaaa", etc.
                if (_isRepeatingGarbage(text)) {
                    continue;
                }

                const cands = this.counts[ctx];
                if (!cands) {
                    // Fallback: if no transition counts for this context,
                    // we use a random character BUT WITH A VERY NEGATIVE SCORE.
                    //
                    // ROOT CAUSE FIX #1: Previously this pushed [0.0, nctx, nt], but
                    // transLogP() returns NEGATIVE values (log probs are always <= 0).
                    // So 0.0 was actually BETTER than any real transition, causing
                    // the beam to prefer fallback garbage over legitimate commands!

                    // Use only a small number of fallbacks to avoid polluting the beam
                    const fallbackChars = Object.keys(this.vocab).filter(
                        c => c !== BOS && c !== EOS
                    );
                    if (fallbackChars.length > 0 && text.length < 30) {
                        // Pick at most 1 random char per step, with very bad score
                        const rand = fallbackChars[Math.floor(Math.random() * fallbackChars.length)];
                        const nctx = (ctx + rand).slice(-k);
                        const nt = text + rand;

                        // Create new visited set for this branch
                        const newVisited = new Set(visited);
                        newVisited.add(nctx + "|" + nt.length);

                        // VERY NEGATIVE score for fallback - much worse than any real transition
                        next.push([score + FALLBACK_LOG_P, nctx, nt, newVisited]);
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

                    // ROOT CAUSE FIX #2: Prevent Markov cycles by tracking visited contexts.
                    // Since the Markov model is order=4, the context is only 3 characters.
                    // This makes it EASY to form cycles: ABC -> D, CDA -> B, etc.
                    //
                    // We track "context + text_length" to catch cycles where the same
                    // context reappears at the same "position" in the generation.
                    //
                    // Example cycle that would be caught:
                    //   "file " -> "." (ctx="le " -> "."), text now "file ."
                    //   "." -> "-" (ctx="e ." -> "-"), text now "file .-"
                    //   ... eventually cycles back to "le " -> "." at same relative position

                    const visitKey = nctx + "|" + nt.length;

                    if (visited.has(visitKey)) {
                        // CYCLE DETECTED - we've been in this exact context at this length before
                        // Skip this continuation - it would lead to infinite repetition
                        continue;
                    }

                    // Create new visited set for this branch (copy parent's visited)
                    const newVisited = new Set(visited);
                    newVisited.add(visitKey);

                    next.push([ns, nctx, nt, newVisited]);
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

    // Return the N most frequent corpus lines, optionally filtered by target length.
    // This is the PREFERRED method over generateBeam() because:
    // 1. It returns actual known commands, not generated garbage
    // 2. The corpus is already sorted by frequency (most common first)
    // 3. You can then re-rank with timingScore() for rhythm matching
    //
    // Returns [[logPriorScore, command], ...] sorted by score descending
    rankCorpus(targetLen = null, tolerance = 3, topn = 30) {
        const entries = Object.entries(this.commandCounts);  // [command, count]

        if (entries.length === 0) {
            return [];
        }

        const scored = [];
        for (const [cmd, count] of entries) {
            const len = cmd.length;

            // Length filter (if targetLen provided)
            if (targetLen !== null) {
                if (Math.abs(len - targetLen) > tolerance + 5) {
                    // Allow more tolerance for slot-aware matching
                    // Use the template matching to see if it's a slot-based match
                    const template = this._findBestMatchingTemplate(cmd);
                    if (!template || !template.hasSlots) {
                        continue;  // No slots and wrong length = skip
                    }
                    // With slots, allow much wider variation
                    if (len < 3 || len > 120) {
                        continue;
                    }
                }
            }

            // Score = frequency bonus + commandLogP + length bonus (if applicable)
            let score = this.commandLogP(cmd);

            // Add length-based bonus if targetLen is provided
            if (targetLen !== null) {
                const lenDiff = Math.abs(len - targetLen);
                if (lenDiff <= tolerance) {
                    // Small bonus for exact-ish length match
                    score += 0.5;
                }

                // Also check slot-aware matching
                const template = this._findBestMatchingTemplate(cmd);
                if (template && template.hasSlots) {
                    // Command has slots - it's a template that can fit variable args
                    // Give it a bonus since it's more flexible
                    score += 1.0;
                }
            }

            scored.push([score, cmd]);
        }

        // Sort by score descending
        scored.sort((a, b) => b[0] - a[0]);

        return scored.slice(0, topn);
    }

    // N-gram similarity between two strings (for partial matching)
    // Returns a score 0-1 where 1 = exact match
    ngramSimilarity(a, b, n = 3) {
        if (a === b) return 1.0;
        if (a.length < n || b.length < n) return 0.0;

        const gramsA = new Map();
        const gramsB = new Map();

        for (let i = 0; i <= a.length - n; i += 1) {
            const g = a.slice(i, i + n);
            gramsA.set(g, (gramsA.get(g) || 0) + 1);
        }
        for (let i = 0; i <= b.length - n; i += 1) {
            const g = b.slice(i, i + n);
            gramsB.set(g, (gramsB.get(g) || 0) + 1);
        }

        // Compute intersection
        let intersection = 0;
        let union = 0;

        const allGrams = new Set([...gramsA.keys(), ...gramsB.keys()]);
        for (const gram of allGrams) {
            const countA = gramsA.get(gram) || 0;
            const countB = gramsB.get(gram) || 0;
            intersection += Math.min(countA, countB);
            union += Math.max(countA, countB);
        }

        return union === 0 ? 0.0 : intersection / union;
    }

    // Re-rank candidates using both timing and optionally a partial text hint
    // hintText is optional partial keystroke data for ssdeep-like matching
    rankWithTiming(candidates, delaysMs, timingWeight = 0.22, hintText = null) {
        const out = [];
        for (const [baseScore, cmd] of candidates) {
            let score = baseScore;
            if (delaysMs && delaysMs.length > 0) {
                score += timingWeight * this.timingScore(cmd, delaysMs);
            }
            if (hintText && hintText.length > 0) {
                // N-gram similarity bonus for partial text matching
                // (simple alternative to ssdeep)
                const sim = this.ngramSimilarity(cmd, hintText, 3);
                score += sim * 2.0;  // Up to +2.0 for good match
            }
            out.push([score, cmd]);
        }
        out.sort((a, b) => b[0] - a[0]);
        return out;
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
    SLOT_MARKER,
    SLOT_PATTERNS,
    tokenizeCommand,
    compareToTemplate,
    matchesSkeleton,
    extractCommandTemplate,
    computeLineConfidence,
    computeSessionConfidence,
    computeDelayStats,
};
