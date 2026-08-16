"use strict";

// Pure-JS port of scripts/shell_markov.py. Same behavior, same constants:
// n-gram order 4 by default (trigram context -> next char), Laplace alpha 0.05,
// BOS = "\u0002", EOS = "\u0003", QWERTY-distance scoring for the optional timing
// channel, length prior weight 0.35, exact-match bonus 0.25, beam branching
// capped at 24 next-chars per context.

// Runtime-configurable settings for keystroke analysis.
// These can be set via the exported `setMarkovConfig()` function.
const _markovConfig = {
    // Conciseness bonus multiplier for short slotless commands.
    // Short commands (ls, pwd, cd, etc.) don't have slots, so they get
    // a bonus to compete with slot-containing templates like "cat file.txt".
    // At 1.0 (default), very short commands (1-5 chars) get +1.2 bonus.
    // At 2.0, they'd get +2.4 bonus.
    // Tuned default: 1.7 (favors short commands moderately)
    concisenessBonusMultiplier: 1.7,

    // Length bonus multiplier for target-length proximity matching.
    // Applied to:
    // - The +0.5 bonus for being within tolerance of targetLen
    // - The +1.0 bonus for slot-containing templates (flexible length)
    // Default 1.0 means bonuses are applied as-is.
    // At 2.0, the bonuses are doubled, making length-matching more important.
    // Tuned default: 2.6 (strongly favors commands that match the target length)
    lengthBonusMultiplier: 2.6,
};

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
    // More specific patterns first to avoid overlapping issues
    // URL placeholders
    { pattern: /https?:\/\/[^\s]+/gi, type: "url" },
    // S3 path placeholders
    { pattern: /s3:\/\/[^\s]+/gi, type: "s3path" },
    // SSH config path placeholders
    { pattern: /~\/\.ssh\/[^ \t]+/gi, type: "path" },  // ~/.ssh/id_rsa
    // User@host placeholders (more specific first)
    { pattern: /\b(user|root)@[\d\.]+/gi, type: "user_at_host" },  // user@192.168.1.1
    { pattern: /\b(user|root)@(server|host)\b/gi, type: "user_at_host" },
    // Full filename placeholders with extensions (specific first)
    { pattern: /\b(file|filename|target|link|backup)\.(txt|log|conf|config|py|js|json|md|sh|bak|yaml|yml|xml|html|css|csv|tsv|doc|docx|xls|xlsx|pdf|zip|tar|gz|bz2|7z|rar)\b/gi, type: "filename" },
    // Arbitrary filename-like patterns (any word followed by common extension)
    { pattern: /\b[a-zA-Z0-9_-]+\.(txt|log|conf|config|py|js|json|md|sh|bak|yaml|yml|xml|html|css|csv|tsv|doc|docx|xls|xlsx|pdf|zip|tar|gz|bz2|7z|rar)\b/gi, type: "filename" },
    // Path placeholders with directory prefixes
    { pattern: /\/(var|tmp|etc|usr|opt|root|home|srv|mnt|media|proc|sys|dev)\/[^ \t]*/gi, type: "path" },
    // Hostname/IP placeholders
    { pattern: /\bexample\.com\b/gi, type: "hostname" },
    { pattern: /\b(server|host|localhost|hostname)\b/gi, type: "hostname", wordOnly: true },
    // Directory placeholders (word only)
    { pattern: /\b(directory|dir|src|build|logs|tmp|test|dist|node_modules|__pycache__|cache|config|data|lib|bin|include)\b/gi, type: "directory", wordOnly: true },
    // Bucket/resource placeholders (AWS/S3)
    { pattern: /\bbucket\b/gi, type: "bucket", wordOnly: true },
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

    // First, detect all slots in corpusCmd without overlaps
    // (using the same logic as detectSlotsInCommand)
    const allMatches = [];
    for (const sp of SLOT_PATTERNS) {
        const pattern = sp.pattern;
        pattern.lastIndex = 0; // reset before each use

        let match;
        while ((match = pattern.exec(corpusCmd)) !== null) {
            allMatches.push({
                type: sp.type,
                start: match.index,
                end: match.index + match[0].length,
                match: match[0],
                length: match[0].length,
            });
        }
    }

    // Sort by start position, then by length descending
    allMatches.sort((a, b) => {
        if (a.start !== b.start) return a.start - b.start;
        return b.length - a.length;
    });

    // Remove overlapping matches
    const nonOverlappingSlots = [];
    let lastEnd = -1;
    for (const m of allMatches) {
        if (m.start >= lastEnd) {
            nonOverlappingSlots.push(m);
            lastEnd = m.end;
        }
    }

    const hasSlots = nonOverlappingSlots.length > 0;

    // Calculate fixed length by subtracting only non-overlapping slot lengths
    let fixedLength = corpusLen;
    let numSlots = 0;
    for (const slot of nonOverlappingSlots) {
        fixedLength -= slot.length;
        numSlots += 1;
    }
    // Add back minimum slot content (1 char per slot)
    fixedLength += numSlots;

    return {
        skeletonMatch,
        fixedLength,
        hasSlots,
        corpusLength: corpusLen,
        candidateLength: candLen,
        slotCount: numSlots,
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
                    // Applied with lengthBonusMultiplier
                    const lenMult = _markovConfig.lengthBonusMultiplier || 1.0;
                    score += 0.5 * lenMult;
                }

                // Also check slot-aware matching
                const template = this._findBestMatchingTemplate(cmd);
                if (template && template.hasSlots) {
                    // Command has slots - it's a template that can fit variable args
                    // Give it a bonus since it's more flexible
                    // Applied with lengthBonusMultiplier
                    const lenMult = _markovConfig.lengthBonusMultiplier || 1.0;
                    score += 1.0 * lenMult;
                } else {
                    // Command has NO slots - these are typically short "atomic" commands
                    // like `ls`, `pwd`, `cd ..`, `git status`, etc. that DON'T have
                    // variable placeholders. Give them a "conciseness bonus" to
                    // compete with slot-containing commands which get a +1.0 slot bonus.
                    // Short commands are often MORE frequent in real shell history.
                    //
                    // The multiplier is configurable via setMarkovConfig().
                    // At default 1.0: ls=+1.2, cd ..=+0.6, git status=+0.3
                    // At 2.0: ls=+2.4, cd ..=+1.2, git status=+0.6
                    const mult = _markovConfig.concisenessBonusMultiplier || 1.0;
                    const len = cmd.length;
                    if (len <= 5) {
                        // Very short commands (1-5 chars): full bonus
                        score += 1.2 * mult;
                    } else if (len <= 10) {
                        // Medium-short commands (6-10 chars): partial bonus
                        score += 0.6 * mult;
                    } else if (len <= 15) {
                        // Moderate length (11-15 chars): small bonus
                        score += 0.3 * mult;
                    }
                    // Longer commands without slots get no conciseness bonus
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

// ============================================================================
// Slot Detection and Filling
// ============================================================================
//
// Functions to detect slot patterns in corpus commands and fill them
// with actual artifacts from the capture.

/**
 * Detects slots in a corpus command and returns their positions and types.
 * 
 * Returns an array of: { 
 *   type: "filename" | "user_at_host" | "hostname" | "path" | "url" | ...,
 *   start: number,  // index in original string
 *   end: number,    // index after last char
 *   match: string,  // the actual matched text
 * }
 */
function detectSlotsInCommand(cmd) {
    const slots = [];
    if (!cmd || typeof cmd !== "string") return slots;

    // We need to find all slot matches without overlapping
    // Sort patterns by match length (longer first) to prefer more specific matches
    const allMatches = [];

    for (const sp of SLOT_PATTERNS) {
        const pattern = sp.pattern;
        pattern.lastIndex = 0;

        let match;
        while ((match = pattern.exec(cmd)) !== null) {
            allMatches.push({
                type: sp.type,
                start: match.index,
                end: match.index + match[0].length,
                match: match[0],
                length: match[0].length,
            });
        }
    }

    // Sort by start position, then by length descending
    allMatches.sort((a, b) => {
        if (a.start !== b.start) return a.start - b.start;
        return b.length - a.length;
    });

    // Remove overlaps
    let lastEnd = -1;
    for (const m of allMatches) {
        if (m.start >= lastEnd) {
            slots.push(m);
            lastEnd = m.end;
        }
    }

    return slots;
}

/**
 * Given a corpus command (like "scp file.txt user@server:/path") and
 * a SessionArtifactStore, generates filled variants by replacing slot
 * patterns with actual artifacts from the capture.
 * 
 * Returns an array of { filledCommand, score, slotsUsed } where score
 * is based on how well the artifacts match the slot requirements.
 */
function fillCommandSlots(cmd, artifactStore, options = {}) {
    const results = [];
    if (!artifactStore) return results;

    const slots = detectSlotsInCommand(cmd);
    if (slots.length === 0) {
        // No slots to fill - return original with perfect score
        results.push({
            filledCommand: cmd,
            score: 1.0,
            slotsUsed: [],
            originalCommand: cmd,
        });
        return results;
    }

    // Map slot type to artifact type and findBestSlotFill slotType
    const slotTypeMap = {
        filename: { artifactType: "filename", slotType: "filename" },
        directory: { artifactType: "filename", slotType: "path" },
        user_at_host: { artifactType: null, slotType: "user_at_host" },
        hostname: { artifactType: "hostname", slotType: "hostname" },
        path: { artifactType: "filename", slotType: "path" },
        url: { artifactType: "http_url", slotType: "url" },
        bucket: { artifactType: null, slotType: "url" },
        s3path: { artifactType: null, slotType: "url" },
    };

    // Collect potential fills for each slot
    const slotFills = [];

    for (const slot of slots) {
        const mapping = slotTypeMap[slot.type] || slotTypeMap.filename;
        const fillsForSlot = [];

        if (slot.type === "user_at_host") {
            // Special: user@host combines username + hostname/IP
            // Try to find best user_at_host slot fill
            const userHostFill = artifactStore.findBestSlotFill("user_at_host", {
                targetLength: slot.length,
            });

            if (userHostFill) {
                fillsForSlot.push({
                    slot,
                    artifact: userHostFill.artifact,
                    fillText: userHostFill.value,
                    score: userHostFill.score,
                });
            }

            // Also try to construct from separate username + hostname/IP
            const usernames = artifactStore.getArtifactsByType("username");
            const hosts = [
                ...artifactStore.getArtifactsByType("hostname"),
                ...artifactStore.getArtifactsByType("ip_address"),
            ];

            for (const u of usernames.slice(0, 3)) {
                for (const h of hosts.slice(0, 5)) {
                    const combined = `${u.value}@${h.value}`;
                    const combinedScore = (u.confidence + h.confidence) / 2;
                    fillsForSlot.push({
                        slot,
                        artifact: { from: [u, h] },
                        fillText: combined,
                        score: combinedScore,
                    });
                }
            }

            // If no username, try just IP/hostname as fallback
            for (const h of hosts.slice(0, 5)) {
                fillsForSlot.push({
                    slot,
                    artifact: h,
                    fillText: `root@${h.value}`,
                    score: h.confidence * 0.8,
                });
            }
        } else {
            // Regular slot type - use findBestSlotFill
            const bestFill = artifactStore.findBestSlotFill(mapping.slotType, {
                targetLength: slot.length,
            });

            if (bestFill) {
                fillsForSlot.push({
                    slot,
                    artifact: bestFill.artifact,
                    fillText: bestFill.value,
                    score: bestFill.score,
                });
            }

            // Also check similar artifacts
            const similars = artifactStore.findSimilar(
                slot.match,
                mapping.artifactType,
                0.2
            );

            for (const sim of similars.slice(0, 5)) {
                fillsForSlot.push({
                    slot,
                    artifact: sim.artifact,
                    fillText: sim.artifact.value,
                    score: sim.score,
                });
            }
        }

        // When no artifacts available, use [unintelligible-N] where N is character count
        // Lower score than original fallback so it only shows when no artifacts match
        fillsForSlot.push({
            slot,
            artifact: null,
            fillText: `[unintelligible-${slot.match.length}]`,
            score: 0.05,
        });

        // Deduplicate by fillText
        const seen = new Set();
        const uniqueFills = [];
        for (const f of fillsForSlot) {
            const key = `${f.slot.start}:${f.fillText}`;
            if (!seen.has(key)) {
                seen.add(key);
                uniqueFills.push(f);
            }
        }
        uniqueFills.sort((a, b) => b.score - a.score);

        slotFills.push({
            slot,
            fills: uniqueFills.slice(0, 5),
        });
    }

    // Generate combinations - simple case: use top fill for each slot
    const topFills = [];
    const slotsUsed = [];
    let combinedScore = 1.0;

    for (const sf of slotFills) {
        if (sf.fills.length > 0) {
            const topFill = sf.fills[0];
            topFills.push(topFill);
            slotsUsed.push({
                slotType: sf.slot.type,
                originalMatch: sf.slot.match,
                fillText: topFill.fillText,
                score: topFill.score,
            });
            combinedScore *= topFill.score;
        } else {
            // No fill - use original
            topFills.push({
                slot: sf.slot,
                fillText: sf.slot.match,
                score: 0.1,
            });
        }
    }

    // Build the filled command by replacing slots in reverse order
    let filled = cmd;
    const sortedFills = [...topFills].sort((a, b) => b.slot.end - a.slot.end);

    for (const fill of sortedFills) {
        filled = filled.slice(0, fill.slot.start) + fill.fillText + filled.slice(fill.slot.end);
    }

    results.push({
        filledCommand: filled,
        score: combinedScore,
        slotsUsed,
        originalCommand: cmd,
        slotCount: slots.length,
    });

    return results;
}

/**
 * Enhanced rankCorpus variant that also generates slot-filled variants.
 * Uses artifacts from the session to fill template slots (file.txt → actual_filenames.log, etc.)
 * 
 * Returns [[score, command, originalTemplate, slotFillInfo], ...]
 */
function rankCorpusWithSlotFilling(model, artifactStore, targetLen = null, tolerance = 3, topn = 30) {
    if (!model || typeof model.rankCorpus !== "function") {
        return [];
    }

    // Get base ranking
    const baseRanked = model.rankCorpus(targetLen, tolerance, topn * 2);
    if (baseRanked.length === 0) {
        return [];
    }

    const results = [];

    for (const [baseScore, cmd] of baseRanked) {
        // Add original command
        results.push({
            score: baseScore,
            command: cmd,
            originalTemplate: cmd,
            isSlotFilled: false,
            slotFillInfo: null,
        });

        // Try to fill slots if we have an artifact store
        if (artifactStore) {
            const filledVariants = fillCommandSlots(cmd, artifactStore);

            for (const fv of filledVariants) {
                if (fv.slotsUsed && fv.slotsUsed.length > 0) {
                    // Score = base score + slot fill bonus
                    const fillBonus = fv.score * 2.0;

                    results.push({
                        score: baseScore + fillBonus,
                        command: fv.filledCommand,
                        originalTemplate: cmd,
                        isSlotFilled: true,
                        slotFillInfo: fv,
                    });
                }
            }
        }
    }

    // Sort by combined score
    results.sort((a, b) => b.score - a.score);

    // Return in the same format as rankCorpus for compatibility
    return results.slice(0, topn).map((r) => [
        r.score,
        r.command,
        r.originalTemplate,
        { isSlotFilled: r.isSlotFilled, slotFillInfo: r.slotFillInfo },
    ]);
}

// ============================================================================
// SessionArtifactStore: fuzzy matching for IPs, hosts, filenames, domains
// ============================================================================
//
// ssdeep-style Context Triggered Piecewise Hashing (CTPH) for artifact matching.
// Combines:
//   1. Traditional CTPH for file/artifact similarity
//   2. Keyboard distance (QWERTY) for typed-string similarity
//   3. IP/network-aware matching for CIDR and neighbor IPs
//
// Artifact types stored:
//   - ip_address: IPv4, IPv6
//   - mac_address: Ethernet addresses
//   - hostname: From DNS, SSL CN, SSH key comment
//   - domain: eTLD+1 (example.com, example.co.uk)
//   - filename: Carved from TCP streams, FTP data
//   - username: From auth, SSH key comment
//   - command: Partial/full keystroke reconstructions
//   - port_artifact: Port number with service metadata
//   - http_url: URL path/query
//   - dns_qname: DNS query name
//   - ssl_cn: SSL certificate common name
//   - keystroke_fragment: Partial keystream from timing analysis
// ============================================================================
//

// Roll hash constants for CTPH (ssdeep-like)
const ROLL_HASH_WINDOW = 7;
const ROLL_HASH_MOD = 1 << 16;  // 65536
const SPAMSUM_LENGTH = 64;
const SPAMSUM_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Roll hash (FNV-1a variant for CTPH)
function _rollHashUpdate(h, c) {
    return ((h << 5) - h + c) % ROLL_HASH_MOD;
}

// CTPH - compute fuzzy hash of arbitrary data/string
// Returns { chunkHash: string, blockSize: number }
// where chunkHash is "blockSize:hash1:hash2" like ssdeep
function computeCtphHash(str, minBlockSize = 3) {
    if (!str || str.length === 0) {
        return { chunkHash: "0::", blockSize: 0, rawBytes: 0 };
    }

    // Convert string to bytes
    const bytes = [];
    for (let i = 0; i < str.length; i += 1) {
        bytes.push(str.charCodeAt(i) & 0xFF);
    }

    // Choose block size based on length (like ssdeep)
    // blockSize is a power of 2
    let blockSize = minBlockSize;
    while (blockSize * SPAMSUM_LENGTH < bytes.length) {
        blockSize *= 2;
    }

    function _spamsumWithBlockSize(bs) {
        let hash1 = "";  // blockSize
        let hash2 = "";  // blockSize*2
        let rh = 0;  // roll hash
        let i = 0;

        // Roll hash window
        const window = [];

        for (let bi = 0; bi < bytes.length; bi += 1) {
            const b = bytes[bi];
            window.push(b);
            if (window.length > ROLL_HASH_WINDOW) window.shift();

            rh = _rollHashUpdate(rh, b);

            // Trigger point for blockSize
            if (rh % bs === (bs - 1) && hash1.length < SPAMSUM_LENGTH) {
                const ch = SPAMSUM_B64[rh & 63];
                hash1 += ch;
            }

            // Trigger point for 2*blockSize
            if (rh % (bs * 2) === (bs * 2 - 1) && hash2.length < SPAMSUM_LENGTH) {
                const ch = SPAMSUM_B64[rh & 63];
                hash2 += ch;
            }
        }

        // Finalize: always add last partial block
        if (hash1.length === 0 || bytes.length > 0) {
            hash1 += SPAMSUM_B64[rh & 63];
        }
        if (hash2.length === 0 || bytes.length > 0) {
            hash2 += SPAMSUM_B64[(rh * 2) & 63];
        }

        return `${bs}:${hash1}:${hash2}`;
    }

    return {
        chunkHash: _spamsumWithBlockSize(blockSize),
        blockSize,
        rawBytes: bytes.length,
        rawString: str,
    };
}

// Compare two ssdeep-like hashes
// Returns score 0.0 - 1.0 where 1.0 = identical
function compareCtphHashes(hashA, hashB) {
    if (!hashA || !hashB) return 0.0;

    // Parse "blockSize:hash1:hash2"
    function parse(h) {
        if (typeof h === "string") {
            const parts = h.split(":");
            if (parts.length >= 3) {
                return {
                    blockSize: parseInt(parts[0], 10) || 0,
                    h1: parts[1],
                    h2: parts[2],
                };
            }
        } else if (h && h.chunkHash) {
            return parse(h.chunkHash);
        }
        return null;
    }

    const a = parse(hashA);
    const b = parse(hashB);

    if (!a || !b || !a.h1 || !b.h1) return 0.0;

    // Block sizes must be within factor of 2
    if (a.blockSize !== b.blockSize && a.blockSize !== b.blockSize * 2 && b.blockSize !== a.blockSize * 2) {
        return 0.0;
    }

    // Simple edit-distance based scoring for the hash strings
    function scoreEditDistance(s1, s2) {
        if (s1 === s2) return 1.0;
        if (!s1 || !s2) return 0.0;

        const len1 = s1.length;
        const len2 = s2.length;
        const maxLen = Math.max(len1, len2);

        // Count common substrings of length 4
        let matches = 0;
        const windowLen = 4;

        const s2Windows = new Map();
        for (let i = 0; i <= len2 - windowLen; i += 1) {
            const w = s2.slice(i, i + windowLen);
            s2Windows.set(w, (s2Windows.get(w) || 0) + 1);
        }

        for (let i = 0; i <= len1 - windowLen; i += 1) {
            const w = s1.slice(i, i + windowLen);
            const cnt = s2Windows.get(w);
            if (cnt && cnt > 0) {
                matches += 1;
                s2Windows.set(w, cnt - 1);
            }
        }

        const maxPossible = Math.max(1, maxLen - windowLen + 1);
        return Math.min(1.0, matches / maxPossible);
    }

    // Try all relevant combinations
    let bestScore = 0.0;
    bestScore = Math.max(bestScore, scoreEditDistance(a.h1, b.h1));
    bestScore = Math.max(bestScore, scoreEditDistance(a.h1, b.h2));
    bestScore = Math.max(bestScore, scoreEditDistance(a.h2, b.h1));
    bestScore = Math.max(bestScore, scoreEditDistance(a.h2, b.h2));

    return bestScore;
}

// IP address utilities
function _parseIp(ipStr) {
    // IPv4: 192.168.1.1
    if (ipStr.includes(".")) {
        const parts = ipStr.split(".").map(Number);
        if (parts.length === 4 && parts.every(n => n >= 0 && n <= 255)) {
            const numeric = parts[0] * (256 ** 3) + parts[1] * (256 ** 2) + parts[2] * 256 + parts[3];
            return { type: "ipv4", numeric, parts, raw: ipStr };
        }
    }
    // IPv6: simplified (we just do string comparison for now)
    if (ipStr.includes(":")) {
        return { type: "ipv6", raw: ipStr, numeric: 0 };
    }
    return null;
}

// Score similarity between two IP addresses
// Returns 0.0-1.0, where 1.0 = same IP
function scoreIpSimilarity(ipA, ipB) {
    if (ipA === ipB) return 1.0;

    const a = _parseIp(ipA);
    const b = _parseIp(ipB);

    if (!a || !b || a.type !== b.type) return 0.0;

    if (a.type === "ipv4") {
        const diff = Math.abs(a.numeric - b.numeric);

        // Same /24 subnet
        if ((a.numeric >> 8) === (b.numeric >> 8)) {
            return 0.85;
        }
        // Same /16 subnet
        if ((a.numeric >> 16) === (b.numeric >> 16)) {
            return 0.70;
        }
        // Same /8 subnet
        if ((a.numeric >> 24) === (b.numeric >> 24)) {
            return 0.50;
        }
        // Numerically close (within 255 IPs)
        if (diff <= 255) {
            return 0.40;
        }
        // Same private class
        const isPrivateA = (a.numeric >> 24) === 10 ||  // 10/8
            ((a.numeric >> 16) & 0xFFFF) === 0xC0A8 ||  // 192.168/16
            ((a.numeric >> 20) & 0xFFF) === 0xAC1;     // 172.16/12
        const isPrivateB = (b.numeric >> 24) === 10 ||
            ((b.numeric >> 16) & 0xFFFF) === 0xC0A8 ||
            ((b.numeric >> 20) & 0xFFF) === 0xAC1;
        if (isPrivateA === isPrivateB) {
            return 0.20;
        }
    }

    return 0.10;
}

// Score similarity between two domains/hostnames using:
// 1. String similarity (CTPH)
// 2. Domain hierarchy match
// 3. Keyboard distance (for typos/adjacent-key misobservations)
function scoreDomainSimilarity(domA, domB) {
    if (domA === domB) return 1.0;
    if (!domA || !domB) return 0.0;

    const a = domA.toLowerCase();
    const b = domB.toLowerCase();

    // Same eTLD+1 (example.com matches sub.example.com)
    const aParts = a.split(".");
    const bParts = b.split(".");

    // Check for suffix match
    if (a.endsWith("." + b) || b.endsWith("." + a)) {
        return 0.80;
    }

    // Compute CTPH similarity
    const hashA = computeCtphHash(a);
    const hashB = computeCtphHash(b);
    const ctphScore = compareCtphHashes(hashA, hashB);

    // Compute keyboard-based QWERTY similarity
    let keyboardScore = 0.0;
    if (a.length === b.length) {
        // Same length - compute per-char keyboard distance
        let totalDist = 0;
        let validPairs = 0;
        for (let i = 0; i < a.length; i += 1) {
            const d = keyDistance(a[i], b[i]);
            if (d < 5) {  // Only count reasonable distances
                totalDist += d;
                validPairs += 1;
            }
        }
        if (validPairs === a.length) {
            const avgDist = totalDist / a.length;
            keyboardScore = Math.max(0, 1.0 - avgDist * 0.15);
        }
    }

    // Combined score
    return Math.max(ctphScore * 0.8, keyboardScore * 0.9);
}

// Score similarity between two filenames/paths
function scoreFilenameSimilarity(fnA, fnB) {
    if (fnA === fnB) return 1.0;
    if (!fnA || !fnB) return 0.0;

    // Same basename
    const aName = fnA.split(/[/\\]/).pop();
    const bName = fnB.split(/[/\\]/).pop();

    if (aName === bName) {
        return 0.90;
    }

    // Same extension
    const aExt = aName.includes(".") ? aName.slice(aName.lastIndexOf(".")) : "";
    const bExt = bName.includes(".") ? bName.slice(bName.lastIndexOf(".")) : "";
    let extBonus = 0.0;
    if (aExt && bExt && aExt === bExt) {
        extBonus = 0.20;
    }

    // CTPH for overall similarity
    const hashA = computeCtphHash(fnA);
    const hashB = computeCtphHash(fnB);
    const ctphScore = compareCtphHashes(hashA, hashB);

    return Math.min(1.0, ctphScore * 0.85 + extBonus);
}

// ============================================================================
// SessionArtifactStore: Central registry for all artifacts seen in a capture
// ============================================================================
//

class SessionArtifactStore {
    constructor() {
        // By type: Map<artifactKey, artifactInfo>
        this.artifacts = new Map();
        // By flowKey: Map<flowKey, artifactKey[]>
        this.artifactsByFlow = new Map();
        // Counter for unique IDs
        this._nextId = 1;
    }

    // Artifact types:
    //   ip_address, mac_address, hostname, domain, filename, username,
    //   command, port_artifact, http_url, dns_qname, ssl_cn,
    //   keystroke_fragment, slot_candidate

    addArtifact(type, value, options = {}) {
        const {
            flowKey = null,
            source = "unknown",  // "capture", "dns", "ssl", "keystroke", "inference"
            confidence = 0.5,    // 0-1, how confident we are this is real
            category = null,     // subtype: "private_ip", "public_ip", "txt_record", etc.
            timestampMs = null,
            metadata = {},
        } = options;

        // Create artifact key
        const key = `${type}:${value}`;

        let artifact = this.artifacts.get(key);

        if (!artifact) {
            artifact = {
                id: this._nextId++,
                type,
                value,
                category,
                source,
                firstSeenMs: timestampMs || Date.now(),
                lastSeenMs: timestampMs || Date.now(),
                confidence,
                flowKeys: new Set(),
                references: 1,
                ctphHash: null,  // computed on-demand
                metadata: { ...metadata },
            };
            this.artifacts.set(key, artifact);
        } else {
            artifact.lastSeenMs = timestampMs || Date.now();
            artifact.references += 1;
            artifact.confidence = Math.max(artifact.confidence, confidence);
            if (source !== "unknown") {
                artifact.metadata.sources = artifact.metadata.sources || [];
                if (!artifact.metadata.sources.includes(source)) {
                    artifact.metadata.sources.push(source);
                }
            }
        }

        if (flowKey) {
            artifact.flowKeys.add(flowKey);
            if (!this.artifactsByFlow.has(flowKey)) {
                this.artifactsByFlow.set(flowKey, []);
            }
            const flowArtifacts = this.artifactsByFlow.get(flowKey);
            if (!flowArtifacts.includes(key)) {
                flowArtifacts.push(key);
            }
        }

        return artifact;
    }

    // Convenience methods
    addIpAddress(ip, options = {}) {
        const parsed = _parseIp(ip);
        const category = parsed ? (
            parsed.type === "ipv4" ? (
                ((parsed.numeric >> 24) === 10 ||
                    ((parsed.numeric >> 16) & 0xFFFF) === 0xC0A8 ||
                    ((parsed.numeric >> 20) & 0xFFF) === 0xAC1)
                    ? "private_ipv4"
                    : "public_ipv4"
            ) : parsed.type
        ) : null;

        return this.addArtifact("ip_address", ip, { category, ...options });
    }

    addMacAddress(mac, options = {}) {
        return this.addArtifact("mac_address", mac.toLowerCase(), options);
    }

    addHostname(hostname, options = {}) {
        return this.addArtifact("hostname", hostname.toLowerCase(), options);
    }

    addDomain(domain, options = {}) {
        return this.addArtifact("domain", domain.toLowerCase(), options);
    }

    addFilename(filename, options = {}) {
        return this.addArtifact("filename", filename, options);
    }

    addUsername(username, options = {}) {
        return this.addArtifact("username", username, options);
    }

    addCommand(command, options = {}) {
        return this.addArtifact("command", command, options);
    }

    addKeystrokeFragment(fragment, options = {}) {
        return this.addArtifact("keystroke_fragment", fragment, {
            source: "keystroke",
            ...options,
        });
    }

    addSlotCandidate(candidateText, slotType, options = {}) {
        // Slot candidates are potential fills for Markov template slots
        return this.addArtifact("slot_candidate", candidateText, {
            category: slotType,  // "filename", "user_at_host", "hostname", "path", etc.
            source: "inference",
            ...options,
        });
    }

    // Query methods
    getArtifactsByType(type) {
        return Array.from(this.artifacts.values()).filter(a => a.type === type);
    }

    getArtifactsByFlow(flowKey) {
        const keys = this.artifactsByFlow.get(flowKey) || [];
        return keys.map(k => this.artifacts.get(k)).filter(Boolean);
    }

    getAllArtifacts() {
        return Array.from(this.artifacts.values());
    }

    // Lazy CTPH computation
    _getOrComputeHash(artifact) {
        if (artifact.ctphHash) return artifact.ctphHash;
        artifact.ctphHash = computeCtphHash(artifact.value);
        return artifact.ctphHash;
    }

    // Find similar artifacts
    findSimilar(value, type = null, minScore = 0.3) {
        const results = [];

        for (const artifact of this.artifacts.values()) {
            if (type && artifact.type !== type) continue;

            let score = 0.0;

            // Exact match
            if (artifact.value === value) {
                score = 1.0;
            }
            // Type-specific scoring
            else if (artifact.type === "ip_address" && type === "ip_address") {
                score = scoreIpSimilarity(artifact.value, value);
            }
            else if (artifact.type === "hostname" || artifact.type === "domain") {
                score = scoreDomainSimilarity(artifact.value, value);
            }
            else if (artifact.type === "filename" || type === "filename") {
                score = scoreFilenameSimilarity(artifact.value, value);
            }
            else {
                // Generic CTPH for everything else
                const hashA = computeCtphHash(value);
                const hashB = this._getOrComputeHash(artifact);
                score = compareCtphHashes(hashA, hashB);
            }

            if (score >= minScore) {
                results.push({
                    artifact,
                    score,
                    matchedValue: value,
                });
            }
        }

        results.sort((a, b) => b.score - a.score);
        return results;
    }

    // Find best slot fill for a Markov template slot
    // slotType: "filename", "user_at_host", "hostname", "path", "ip", "url"
    // constraints: { targetLength: number, prefixHint: string, suffixHint: string }
    findBestSlotFill(slotType, constraints = {}) {
        const {
            targetLength = null,
            prefixHint = null,
            suffixHint = null,
            maxLengthVariance = 2,  // ±2 chars tolerance by default
        } = constraints;

        // Map slotType to artifact types
        const typeMap = {
            filename: ["filename", "slot_candidate"],
            user_at_host: ["username", "hostname", "ip_address", "slot_candidate"],
            hostname: ["hostname", "domain", "ip_address", "slot_candidate"],
            path: ["filename", "slot_candidate"],
            ip: ["ip_address", "slot_candidate"],
            url: ["http_url", "domain", "hostname", "slot_candidate"],
        };
        const artifactTypes = typeMap[slotType] || ["slot_candidate", "hostname", "ip_address"];

        const candidates = [];

        for (const artifact of this.artifacts.values()) {
            if (!artifactTypes.includes(artifact.type)) continue;
            if (artifact.type === "slot_candidate" && artifact.category !== slotType) continue;

            // HARD CONSTRAINT: Length must be within tolerance (default ±2 chars)
            if (targetLength != null && maxLengthVariance != null) {
                const lenDiff = Math.abs(artifact.value.length - targetLength);
                if (lenDiff > maxLengthVariance) continue;  // Skip - too far from slot length
            }

            let baseScore = artifact.confidence * 0.5;  // Base score from confidence

            // Length match bonus (within tolerance, closer = better)
            if (targetLength != null) {
                const lenDiff = Math.abs(artifact.value.length - targetLength);
                const maxVar = maxLengthVariance ?? 2;
                baseScore += Math.max(0, 1.0 - (lenDiff / (maxVar + 1))) * 0.3;
            }

            // Prefix/suffix hints (from keystroke analysis)
            if (prefixHint && artifact.value.startsWith(prefixHint)) {
                baseScore += 0.2;
            }
            if (suffixHint && artifact.value.endsWith(suffixHint)) {
                baseScore += 0.15;
            }

            // Keyboard distance to hints if available
            if (prefixHint && prefixHint.length > 2 && artifact.value.length >= prefixHint.length) {
                const p = artifact.value.slice(0, prefixHint.length);
                let d = 0;
                for (let i = 0; i < prefixHint.length; i++) d += keyDistance(prefixHint[i], p[i]);
                if ((d / prefixHint.length) < 2.0) baseScore += 0.15;
            }

            candidates.push({
                artifact,
                score: baseScore,
                value: artifact.value,
                type: artifact.type,
            });
        }

        // If no artifacts found, return empty
        if (candidates.length === 0) {
            return null;
        }

        candidates.sort((a, b) => b.score - a.score);
        return candidates[0];
    }

    // =====================================================================
    // Time-Aware Artifact Matching
    // =====================================================================

    findArtifactsNearTime(targetMs, windowMs = 30000, type = null) {
        const results = [];
        if (!Number.isFinite(targetMs)) return results;

        for (const artifact of this.artifacts.values()) {
            if (type && artifact.type !== type) continue;
            const timeDiffMs = Math.abs(artifact.firstSeenMs - targetMs);

            if (timeDiffMs <= windowMs) {
                let temporalScore = 0.0;
                if (timeDiffMs <= 1000) temporalScore = 1.0;
                else if (timeDiffMs <= 5000) temporalScore = 0.8;
                else if (timeDiffMs <= 15000) temporalScore = 0.5;
                else if (timeDiffMs <= 30000) temporalScore = 0.2;

                results.push({ artifact, timeDiffMs, temporalScore });
            }
        }

        results.sort((a, b) => {
            if (a.temporalScore !== b.temporalScore) return b.temporalScore - a.temporalScore;
            return a.timeDiffMs - b.timeDiffMs;
        });
        return results;
    }

    findBestSlotFillTimeAware(slotType, constraints = {}) {
        const {
            targetLength = null, prefixHint = null, suffixHint = null,
            commandTimeMs = null, slotTimeMs = null, temporalWeight = 0.4,
            maxLengthVariance = 2,
        } = constraints;

        const targetTimeMs = slotTimeMs ?? commandTimeMs;

        const typeMap = {
            filename: ["filename", "slot_candidate"],
            user_at_host: ["username", "hostname", "ip_address", "slot_candidate"],
            hostname: ["hostname", "domain", "ip_address", "slot_candidate"],
            path: ["filename", "slot_candidate"],
            ip: ["ip_address", "slot_candidate"],
            url: ["http_url", "domain", "hostname", "slot_candidate"],
        };
        const artifactTypes = typeMap[slotType] || ["slot_candidate", "hostname", "ip_address"];

        let timeProximate = new Map();
        if (Number.isFinite(targetTimeMs)) {
            const nearTime = this.findArtifactsNearTime(targetTimeMs, 30000, null);
            for (const nt of nearTime) timeProximate.set(nt.artifact.id, nt);
        }

        const candidates = [];
        for (const artifact of this.artifacts.values()) {
            if (!artifactTypes.includes(artifact.type)) continue;
            if (artifact.type === "slot_candidate" && artifact.category !== slotType) continue;

            // HARD CONSTRAINT: Length must be within ±maxLengthVariance chars
            if (targetLength != null && maxLengthVariance != null) {
                const lenDiff = Math.abs(artifact.value.length - targetLength);
                if (lenDiff > maxLengthVariance) continue;
            }

            let baseScore = artifact.confidence * 0.5;

            if (targetLength != null) {
                const lenDiff = Math.abs(artifact.value.length - targetLength);
                const maxVar = maxLengthVariance ?? 2;
                baseScore += Math.max(0, 1.0 - (lenDiff / (maxVar + 1))) * 0.3;
            }

            if (prefixHint && artifact.value.startsWith(prefixHint)) baseScore += 0.2;
            if (suffixHint && artifact.value.endsWith(suffixHint)) baseScore += 0.15;

            if (prefixHint && prefixHint.length > 2 && artifact.value.length >= prefixHint.length) {
                const p = artifact.value.slice(0, prefixHint.length);
                let d = 0;
                for (let i = 0; i < prefixHint.length; i++) d += keyDistance(prefixHint[i], p[i]);
                if ((d / prefixHint.length) < 2.0) baseScore += 0.15;
            }

            let temporalScore = 0.0;
            const ti = timeProximate.get(artifact.id);
            if (ti) temporalScore = ti.temporalScore;

            const finalScore = baseScore * (1.0 - temporalWeight) + temporalScore * temporalWeight;

            candidates.push({
                artifact, baseScore, temporalScore,
                score: finalScore, value: artifact.value, type: artifact.type,
            });
        }

        if (candidates.length === 0) return null;
        candidates.sort((a, b) => b.score - a.score);
        return candidates[0];
    }

    getArtifactsInTimeRange(startTimeMs, endTimeMs, type = null) {
        const results = [];
        for (const a of this.artifacts.values()) {
            if (type && a.type !== type) continue;
            if ((a.firstSeenMs >= startTimeMs && a.firstSeenMs <= endTimeMs) ||
                (a.lastSeenMs >= startTimeMs && a.lastSeenMs <= endTimeMs)) {
                results.push(a);
            }
        }
        results.sort((a, b) => a.firstSeenMs - b.firstSeenMs);
        return results;
    }

    // Export/Import for persistence
    toDict() {
        const artifacts = [];
        for (const [key, a] of this.artifacts) {
            artifacts.push({
                id: a.id,
                type: a.type,
                value: a.value,
                category: a.category,
                source: a.source,
                firstSeenMs: a.firstSeenMs,
                lastSeenMs: a.lastSeenMs,
                confidence: a.confidence,
                references: a.references,
                flowKeys: Array.from(a.flowKeys),
                metadata: a.metadata,
            });
        }
        return {
            nextId: this._nextId,
            artifacts,
            artifactsByFlow: Object.fromEntries(
                Array.from(this.artifactsByFlow.entries()).map(([k, v]) => [k, v])
            ),
        };
    }

    static fromDict(d) {
        const store = new SessionArtifactStore();
        store._nextId = d.nextId || 1;

        if (d.artifacts) {
            for (const a of d.artifacts) {
                const key = `${a.type}:${a.value}`;
                store.artifacts.set(key, {
                    ...a,
                    flowKeys: new Set(a.flowKeys || []),
                    ctphHash: null,
                });
            }
        }

        if (d.artifactsByFlow) {
            for (const [k, v] of Object.entries(d.artifactsByFlow)) {
                store.artifactsByFlow.set(k, v);
            }
        }

        return store;
    }
}

// Global singleton instance for the current capture
let _globalArtifactStore = null;

function getSessionArtifactStore() {
    if (!_globalArtifactStore) {
        _globalArtifactStore = new SessionArtifactStore();
    }
    return _globalArtifactStore;
}

function resetSessionArtifactStore() {
    _globalArtifactStore = new SessionArtifactStore();
    return _globalArtifactStore;
}

// Convenience wrappers using the singleton
function findArtifactsNearTime(targetMs, windowMs = 30000, type = null) {
    return getSessionArtifactStore().findArtifactsNearTime(targetMs, windowMs, type);
}

function findBestSlotFillTimeAware(slotType, constraints = {}) {
    return getSessionArtifactStore().findBestSlotFillTimeAware(slotType, constraints);
}

function getArtifactsInTimeRange(startTimeMs, endTimeMs, type = null) {
    return getSessionArtifactStore().getArtifactsInTimeRange(startTimeMs, endTimeMs, type);
}

// Config getter/setter for runtime adjustment of Markov behavior
function setMarkovConfig(partialConfig) {
    if (partialConfig && typeof partialConfig === "object") {
        if (typeof partialConfig.concisenessBonusMultiplier === "number") {
            _markovConfig.concisenessBonusMultiplier = partialConfig.concisenessBonusMultiplier;
        }
        if (typeof partialConfig.lengthBonusMultiplier === "number") {
            _markovConfig.lengthBonusMultiplier = partialConfig.lengthBonusMultiplier;
        }
    }
    return { ..._markovConfig };
}

function getMarkovConfig() {
    return { ..._markovConfig };
}

// Deprecated/legacy convenience wrappers using singleton
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
    // Runtime config
    setMarkovConfig,
    getMarkovConfig,
    // Session artifact store for fuzzy matching
    SessionArtifactStore,
    getSessionArtifactStore,
    resetSessionArtifactStore,
    // CTPH / ssdeep-like hashing
    computeCtphHash,
    compareCtphHashes,
    // Type-specific similarity scoring
    scoreIpSimilarity,
    scoreDomainSimilarity,
    scoreFilenameSimilarity,
    // Slot detection and filling
    detectSlotsInCommand,
    fillCommandSlots,
    rankCorpusWithSlotFilling,
    // Time-Aware Artifact Matching
    findArtifactsNearTime,
    findBestSlotFillTimeAware,
    getArtifactsInTimeRange,
};
