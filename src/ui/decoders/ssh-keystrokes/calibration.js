// SSH Keystroke Timing Calibration Module
//
// Given a PCAP (or extracted packet delays) and a known transcript of commands,
// this module automatically learns:
//   - Per-digraph Gaussian parameters (mean, std) from observed delays
//   - Per-command timing profiles (rhythm signatures)
//   - Optimal coverage threshold for padding detection
//   - Optimal Markov bonuses (conciseness, length)
//   - Client-specific timing profile
//
// Incorporates methodology from SSHniff (https://crzphil.github.io/posts/sshniff/):
//   - Enter key detection via large latency gaps (>2-3s)
//   - Backspace/delete detection
//   - Command-level rhythm signatures
//   - DTW/Euclidean distance for sequence comparison
//
// The output is a profile JSON that can be saved and selected in the UI.
// This module is pure JS (no Electron, no DOM) so it can run in main process.

"use strict";

const {
    loadQwertyModel,
    detect20msPadding,
    autoTunePaddingThreshold,
    decodeKeystrokes,
    buildCoordinateIndex,
    qwertyDistance,
    classifyDigraph,
    DEFAULT_DIGRAPH_PARAMS,
    DECODER_ALPHABET,
} = require("./index.js");

// v2 weight-envelope helpers
const {
    isEnvelope,
    effectiveSampleSize,
    shrinkToPrior,
    clamp01,
} = require("./score-envelopes.js");

// SSHniff-inspired constants
const ENTER_KEY_THRESHOLD_MS = 2000;  // Large gap indicates Enter/Return
const BACKSPACE_THRESHOLD_MS = 50;    // Very short gap may indicate backspace
const MIN_COMMAND_KEYSTROKES = 2;     // Minimum keystrokes for a command
const MAX_COMMAND_KEYSTROKES = 100;   // Maximum keystrokes for a command

/**
 * Dynamic Time Warping distance between two delay sequences.
 * Allows comparison of sequences of different lengths.
 */
function dtwDistance(seq1, seq2) {
    const n = seq1.length;
    const m = seq2.length;
    if (n === 0 || m === 0) return Infinity;

    const dtw = Array(n + 1).fill(null).map(() => Array(m + 1).fill(Infinity));
    dtw[0][0] = 0;

    for (let i = 1; i <= n; i++) {
        for (let j = 1; j <= m; j++) {
            const cost = Math.abs(seq1[i - 1] - seq2[j - 1]);
            dtw[i][j] = cost + Math.min(
                dtw[i - 1][j],    // insertion
                dtw[i][j - 1],    // deletion
                dtw[i - 1][j - 1] // match
            );
        }
    }

    return dtw[n][m];
}

/**
 * Euclidean distance between two delay sequences (requires same length).
 */
function euclideanDistance(seq1, seq2) {
    if (seq1.length !== seq2.length) return Infinity;
    let sum = 0;
    for (let i = 0; i < seq1.length; i++) {
        const diff = seq1[i] - seq2[i];
        sum += diff * diff;
    }
    return Math.sqrt(sum);
}

/**
 * Normalize a delay sequence to unit length for comparison.
 */
function normalizeSequence(seq) {
    const mean = seq.reduce((a, b) => a + b, 0) / seq.length;
    const std = Math.sqrt(seq.reduce((a, b) => a + (b - mean) ** 2, 0) / seq.length) || 1;
    return seq.map(v => (v - mean) / std);
}

/**
 * Extract command-level timing profiles from aligned data.
 * Returns a map of command -> { delays: [], count: [], rhythm: [] }
 */
function extractCommandProfiles(alignments) {
    const commandProfiles = {};
    let currentCommand = null;
    let currentDelays = [];

    for (const a of alignments) {
        const char = a.expectedChar;
        const delay = a.observedDelay;
        const cmd = a.command;

        // Track command boundaries
        if (cmd !== currentCommand) {
            // Save previous command profile
            if (currentCommand && currentDelays.length >= MIN_COMMAND_KEYSTROKES) {
                if (!commandProfiles[currentCommand]) {
                    commandProfiles[currentCommand] = { delays: [], count: 0, rhythm: [] };
                }
                commandProfiles[currentCommand].delays.push([...currentDelays]);
                commandProfiles[currentCommand].count++;

                // Compute rhythm signature (normalized delay pattern)
                const normalized = normalizeSequence(currentDelays);
                commandProfiles[currentCommand].rhythm.push(normalized);
            }
            currentCommand = cmd;
            currentDelays = [];
        }

        if (char !== "\n" && char !== "\r") {
            currentDelays.push(delay);
        }
    }

    // Save last command
    if (currentCommand && currentDelays.length >= MIN_COMMAND_KEYSTROKES) {
        if (!commandProfiles[currentCommand]) {
            commandProfiles[currentCommand] = { delays: [], count: 0, rhythm: [] };
        }
        commandProfiles[currentCommand].delays.push([...currentDelays]);
        commandProfiles[currentCommand].count++;
        const normalized = normalizeSequence(currentDelays);
        commandProfiles[currentCommand].rhythm.push(normalized);
    }

    return commandProfiles;
}

/**
 * Compute aggregate rhythm signature for a command from multiple samples.
 * Uses median of normalized sequences for robustness.
 */
function computeCommandRhythmSignature(profile) {
    if (!profile.rhythm || profile.rhythm.length === 0) return null;

    // Find median length
    const lengths = profile.rhythm.map(r => r.length).sort((a, b) => a - b);
    const medianLen = lengths[Math.floor(lengths.length / 2)];

    // Pad/truncate all rhythms to median length
    const aligned = profile.rhythm.map(r => {
        if (r.length === medianLen) return r;
        if (r.length < medianLen) {
            return [...r, ...Array(medianLen - r.length).fill(0)];
        }
        return r.slice(0, medianLen);
    });

    // Compute median at each position
    const signature = [];
    for (let i = 0; i < medianLen; i++) {
        const vals = aligned.map(r => r[i]).sort((a, b) => a - b);
        signature.push(vals[Math.floor(vals.length / 2)]);
    }

    return signature;
}

/**
 * Detect Enter key positions from large latency gaps.
 * Returns array of indices in the delay array where Enter likely occurred.
 */
function detectEnterKeys(delays, thresholdMs = ENTER_KEY_THRESHOLD_MS) {
    const enterIndices = [];
    for (let i = 0; i < delays.length; i++) {
        if (delays[i] > thresholdMs) {
            enterIndices.push(i);
        }
    }
    return enterIndices;
}

/**
 * Detect potential backspace/delete keystrokes from very short delays.
 * Returns array of indices.
 */
function detectBackspaces(delays, thresholdMs = BACKSPACE_THRESHOLD_MS) {
    const backspaceIndices = [];
    for (let i = 0; i < delays.length; i++) {
        if (delays[i] > 0 && delays[i] < thresholdMs) {
            backspaceIndices.push(i);
        }
    }
    return backspaceIndices;
}

/**
 * Split delays into command sequences based on Enter key detection.
 */
function splitIntoCommands(delays, enterIndices) {
    const commands = [];
    let start = 0;

    for (const enterIdx of enterIndices) {
        if (enterIdx > start) {
            commands.push(delays.slice(start, enterIdx + 1));
        }
        start = enterIdx + 1;
    }

    // Add remaining as last command
    if (start < delays.length) {
        commands.push(delays.slice(start));
    }

    return commands.filter(cmd => cmd.length >= MIN_COMMAND_KEYSTROKES);
}

/**
 * Match an unknown command delay sequence against known command profiles.
 * Returns best match with distance score.
 */
function matchCommandToProfiles(commandDelays, commandProfiles) {
    let bestMatch = null;
    let bestDistance = Infinity;
    let bestMethod = null;

    const normalizedCmd = normalizeSequence(commandDelays);

    for (const [cmd, profile] of Object.entries(commandProfiles)) {
        const signature = computeCommandRhythmSignature(profile);
        if (!signature) continue;

        // Try DTW (handles different lengths)
        const dtwDist = dtwDistance(normalizedCmd, signature);
        if (dtwDist < bestDistance) {
            bestDistance = dtwDist;
            bestMatch = cmd;
            bestMethod = 'dtw';
        }

        // Try Euclidean (if same length)
        if (normalizedCmd.length === signature.length) {
            const eucDist = euclideanDistance(normalizedCmd, signature);
            if (eucDist < bestDistance) {
                bestDistance = eucDist;
                bestMatch = cmd;
                bestMethod = 'euclidean';
            }
        }
    }

    return { command: bestMatch, distance: bestDistance, method: bestMethod };
}

/**
 * Parse a transcript file into an array of known commands with timestamps.
 * Transcript format (one command per line):
 *   timestamp_ms  command_string
 *   timestamp:command_string   (Unix seconds with colon separator)
 *   OR just:
 *   command_string
 * 
 * If timestamps are provided, they're used to align with packet delays.
 * If not, commands are assumed to be in chronological order.
 */
function parseTranscript(transcriptText) {
    const lines = transcriptText.trim().split(/\r?\n/);
    const commands = [];
    let currentTime = 0;

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;

        let timestamp = null;
        let command = trimmed;

        // Try colon-separated format first: timestamp:command (Unix seconds)
        const colonIdx = trimmed.indexOf(":");
        if (colonIdx > 0) {
            const tsPart = trimmed.substring(0, colonIdx);
            const cmdPart = trimmed.substring(colonIdx + 1);
            const ts = parseFloat(tsPart);
            if (!isNaN(ts) && ts > 1000000000 && ts < 2000000000) {
                // Valid Unix timestamp in seconds - convert to milliseconds
                timestamp = ts * 1000;
                command = cmdPart.trim();
            }
        }

        // Fallback: whitespace-separated timestamp_ms command
        if (timestamp === null) {
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 2 && !isNaN(parseFloat(parts[0]))) {
                const ts = parseFloat(parts[0]);
                // If it looks like seconds (10 digits), convert to ms
                if (ts > 1000000000 && ts < 2000000000) {
                    timestamp = ts * 1000;
                } else {
                    timestamp = ts; // Assume already milliseconds
                }
                command = parts.slice(1).join(" ");
            }
        }

        commands.push({ command, timestamp });
    }

    return commands;
}

/**
 * Extract inter-packet delays from SSH flow packets.
 * Returns array of { delayMs, direction, packetIndex, timestamp }
 */
function extractDelaysFromFlow(flow) {
    const delays = [];
    let prevTs = null;
    let prevDir = null;

    for (let i = 0; i < flow.packets.length; i++) {
        const pkt = flow.packets[i];
        if (pkt.timestamp === null || pkt.timestamp === undefined) continue;

        if (prevTs !== null && pkt.direction === prevDir) {
            const delay = pkt.timestamp - prevTs;
            if (delay > 0 && delay < 60000) { // Sanity check
                delays.push({
                    delayMs: delay,
                    direction: pkt.direction,
                    packetIndex: i,
                    timestamp: pkt.timestamp,
                });
            }
        }
        prevTs = pkt.timestamp;
        prevDir = pkt.direction;
    }

    console.log(`[Calibration] Extracted ${delays.length} delays from flow (c2s: ${delays.filter(d => d.direction === 'c2s').length}, s2c: ${delays.filter(d => d.direction === 's2c').length})`);
    return delays;
}

/**
 * Align known commands to observed delays.
 * This is the core calibration challenge: we know what was typed,
 * we observe delays between packets, we need to map them.
 */
function alignCommandsToDelays(commands, delays, direction = "c2s") {
    // Filter delays for the relevant direction (client-to-server for keystrokes)
    const relevantDelays = delays.filter(d => d.direction === direction);

    // Flatten commands into keystrokes with expected timing
    const expectedKeystrokes = [];
    for (const cmd of commands) {
        const chars = cmd.command.split("");
        for (const ch of chars) {
            expectedKeystrokes.push({
                char: ch.toLowerCase(),
                command: cmd.command,
                expectedTimestamp: cmd.timestamp,
            });
        }
        // Add Return key
        expectedKeystrokes.push({
            char: "\n",
            command: cmd.command,
            expectedTimestamp: cmd.timestamp,
        });
    }

    console.log(`[Calibration] Expected keystrokes: ${expectedKeystrokes.length}, Relevant delays: ${relevantDelays.length}`);

    // Simple alignment: assume each keystroke = one delay
    // In reality, SSH batches keystrokes, so this is approximate
    const alignments = [];
    const maxAlign = Math.min(expectedKeystrokes.length, relevantDelays.length);

    for (let i = 0; i < maxAlign; i++) {
        alignments.push({
            expectedChar: expectedKeystrokes[i].char,
            observedDelay: relevantDelays[i].delayMs,
            command: expectedKeystrokes[i].command,
            delayIndex: i,
        });
    }

    console.log(`[Calibration] Alignments created: ${alignments.length}`);
    return alignments;
}

/**
 * Calculate weight for a digraph based on sample count and consistency.
 * Higher count + lower variance = higher weight.
 */
function calculateDigraphWeight(count, std, baselineStd = DEFAULT_DIGRAPH_PARAMS.std) {
    // Base weight from count: sigmoid curve
    // - count < 5: very low weight
    // - count 5-20: increasing weight
    // - count > 20: high weight
    const countFactor = Math.min(1, count / 30);

    // Variance factor: compare to baseline std
    // - std close to baseline: high weight
    // - std much larger than baseline: lower weight (noisy)
    const stdRatio = Math.min(3, std / Math.max(baselineStd, 20));
    const varianceFactor = Math.max(0.3, 1 - (stdRatio - 1) * 0.3);

    // Combine factors
    const weight = clamp01(countFactor * varianceFactor);
    return weight;
}

/**
 * Learn Gaussian parameters from aligned (char, delay) pairs.
 * Groups by digraph (prevChar -> char) and computes mean/std.
 * 
 * v2 weight envelope integration:
 * - Adds weight, count, source, lastUpdated, variance, tags to each entry
 * - Uses calculateDigraphWeight() to determine confidence based on sample quality
 */
function learnDigraphParameters(alignments, layout = null, options = {}) {
    const coordinateIndex = layout ? buildCoordinateIndex(layout) : null;
    const digraphStats = {}; // "prev|char" -> { delays: [], count: 0 }

    let prevChar = null;

    for (const a of alignments) {
        const char = a.expectedChar;
        const delay = a.observedDelay;

        if (prevChar !== null && char !== "\n") {
            const key = `${prevChar}|${char}`;
            if (!digraphStats[key]) {
                digraphStats[key] = { delays: [], count: 0 };
            }
            digraphStats[key].delays.push(delay);
            digraphStats[key].count++;
        }

        if (char !== "\n") {
            prevChar = char;
        } else {
            prevChar = null; // Reset at command boundary
        }
    }

    console.log(`[Calibration] Digraph stats collected: ${Object.keys(digraphStats).length} unique digraphs`);

    // Compute mean/std for each digraph with v2 weight envelope
    const learnedParams = {};
    const source = options.source || "calibrated";
    const lastUpdated = new Date().toISOString().split('T')[0];

    for (const [key, stats] of Object.entries(digraphStats)) {
        if (stats.count < 3) continue; // Need minimum samples

        const delays = stats.delays;
        const mean = delays.reduce((a, b) => a + b, 0) / delays.length;
        const variance = delays.reduce((a, b) => a + (b - mean) ** 2, 0) / delays.length;
        const std = Math.max(Math.sqrt(variance), 10); // Floor at 10ms

        // Calculate v2 weight envelope fields
        const weight = calculateDigraphWeight(stats.count, std);

        // Build tags based on characteristics
        const tags = ["digraph", "calibrated"];
        if (stats.count >= 20) tags.push("high_count");
        if (stats.count < 10) tags.push("low_count");
        if (std < 30) tags.push("low_variance");
        if (std > 80) tags.push("high_variance");

        learnedParams[key] = {
            mean,
            std,
            // v2 weight envelope fields (flat schema per WEIGHT_SCHEMA.md)
            weight,
            count: stats.count,
            source,
            lastUpdated,
            variance: Number.isFinite(variance) ? variance : null,
            tags,
        };
    }

    console.log(`[Calibration] Digraphs with >=3 samples: ${Object.keys(learnedParams).length}`);
    return learnedParams;
}

/**
 * Learn optimal padding detection threshold by testing coverage values
 * against the known transcript (ground truth).
 */
function learnPaddingThreshold(delays, alignments, direction = "c2s") {
    const relevantDelays = delays.filter(d => d.direction === direction).map(d => d.delayMs);

    // Test coverage thresholds from 0.3 to 0.9
    const thresholds = [];
    for (let cov = 0.3; cov <= 0.9; cov += 0.05) {
        const result = detect20msPadding(relevantDelays, { minCoverage: cov, autoTuneEnabled: false });
        if (result.detected) {
            // Score: how well does the peeled stream match expected keystroke count?
            const expectedKeystrokes = alignments.length;
            const detectedKeystrokes = result.keystrokeDelaysMs ? result.keystrokeDelaysMs.length : 0;
            const accuracy = detectedKeystrokes > 0 ?
                1 - Math.abs(detectedKeystrokes - expectedKeystrokes) / expectedKeystrokes : 0;

            thresholds.push({ coverage: cov, accuracy, result });
        }
    }

    // Return best threshold
    thresholds.sort((a, b) => b.accuracy - a.accuracy);
    return thresholds[0] || { coverage: 0.5, accuracy: 0 };
}

/**
 * Learn optimal Markov bonuses by testing against ground truth.
 */
function learnMarkovBonuses(alignments, commands) {
    // This would require running the full decoder with different bonuses
    // and measuring top-1 accuracy. For now, return defaults.
    // TODO: Implement grid search over bonus values
    return {
        concisenessBonusMultiplier: 1.7,
        lengthBonusMultiplier: 2.6,
    };
}

/**
 * Detect SSH client type from flow characteristics.
 * Looks at packet timing patterns, batching behavior, and other heuristics.
 */
function detectSshClientType(flow, delays, options = {}) {
    const {
        paddingResult = null,
        commandCount = 0,
    } = options;

    // Default to generic
    let clientType = "Generic SSH";
    let clientVersion = "Unknown";
    let confidence = 0.3;

    // Heuristic 1: OpenSSH typically has very regular 20ms padding
    if (paddingResult && paddingResult.detected) {
        const periodMs = paddingResult.periodMs || 0;
        if (Math.abs(periodMs - 20) < 3) {
            // Very close to 20ms - strong OpenSSH indicator
            clientType = "OpenSSH";
            clientVersion = "6.0+";
            confidence = 0.85;
        } else if (Math.abs(periodMs - 10) < 2) {
            // Some older clients use 10ms
            clientType = "OpenSSH (legacy)";
            clientVersion = "5.x";
            confidence = 0.7;
        }
    }

    // Heuristic 2: Look at delay distribution characteristics
    if (delays && delays.length > 20) {
        const meanDelay = delays.reduce((a, b) => a + b, 0) / delays.length;
        const variance = delays.reduce((a, b) => a + (b - meanDelay) ** 2, 0) / delays.length;
        const std = Math.sqrt(variance);

        // PuTTY tends to have more variable delays
        if (std > 100 && meanDelay > 80) {
            if (clientType === "Generic SSH") {
                clientType = "PuTTY";
                confidence = 0.6;
            }
        }

        // Very consistent delays suggest newer OpenSSH
        if (std < 30 && meanDelay > 15 && meanDelay < 30) {
            if (clientType === "OpenSSH") {
                clientVersion = "7.0+";
                confidence = Math.min(0.95, confidence + 0.1);
            }
        }
    }

    // Heuristic 3: Command count and pattern hints
    if (commandCount > 10) {
        // Interactive sessions with many commands are typical of OpenSSH
        if (clientType === "Generic SSH") {
            clientType = "OpenSSH";
            confidence = 0.5;
        }
    }

    return {
        type: clientType,
        version: clientVersion,
        confidence,
        detectedFeatures: {
            has20msPadding: !!(paddingResult && paddingResult.detected && Math.abs((paddingResult.periodMs || 0) - 20) < 5),
            paddingPeriodMs: paddingResult?.periodMs || null,
            commandCount,
        },
    };
}

/**
 * Build a profile from auto-calibration results.
 * Takes the best knobs from autoCalibrate() and merges them with learned digraphs.
 */
function buildProfileFromAutoCalibration(flow, transcriptText, autoCalibrateResult, learnedDigraphs, options = {}) {
    const {
        direction = "c2s",
        clientName = "Unknown",
        profileName = null,
        paddingResult = null,
        commandCount = 0,
        baseModel = null,
    } = options;

    // Use base model or load default
    const model = baseModel || loadQwertyModel({});

    // Detect client type from flow characteristics
    const clientInfo = detectSshClientType(flow, [], {
        paddingResult,
        commandCount,
    });

    // Merge learned digraphs into empirical model
    const empirical = { ...model.empirical };
    for (const [key, params] of Object.entries(learnedDigraphs)) {
        empirical[key] = params;
    }

    // Build profile with metadata
    const bestKnobs = autoCalibrateResult?.best?.knobs || {};
    const profile = {
        version: 4,  // Version 4 includes weight envelopes and client detection
        name: profileName || `${clientInfo.type}_${Date.now()}`.replace(/[^a-zA-Z0-9_-]/g, '_'),
        displayName: profileName || `Auto-calibrated: ${clientInfo.type}`,

        // SSH client information
        clientInfo: {
            type: clientInfo.type,
            version: clientInfo.version,
            detectionConfidence: clientInfo.confidence,
            detectedFeatures: clientInfo.detectedFeatures,
            userLabel: clientName !== "Unknown" ? clientName : null,
        },

        createdAt: new Date().toISOString(),
        schemaVersion: 2,  // v2 weight envelope schema

        source: {
            flowKey: flow?.flowKey || "manual",
            packetCount: flow?.packets?.length || 0,
            commandCount: commandCount || 0,
            calibrationMethod: "auto-calibrate",
            bestScore: autoCalibrateResult?.best?.stats?.mean || 0,
            exactMatchRate: autoCalibrateResult?.best?.stats?.exactMatchRate || 0,
            trialsRun: autoCalibrateResult?.report?.nTrials || 0,
        },

        // Model geometry
        layout: model.layout || "qwerty",
        baselines: model.baselines,
        empirical: empirical,
        coordinateIndex: model.coordinateIndex,
        alphabet: DECODER_ALPHABET,

        // SSHniff-inspired features
        commandRhythms: options.commandRhythms || {},
        enterKeyThresholdMs: ENTER_KEY_THRESHOLD_MS,
        backspaceThresholdMs: BACKSPACE_THRESHOLD_MS,

        // Calibration-specific settings from auto-calibration
        calibration: {
            coverageThreshold: bestKnobs.minCoverage || (paddingResult?.coverage) || 0.5,
            paddingAccuracy: paddingResult?.accuracy || 0,
            digraphsLearned: Object.keys(learnedDigraphs).length,
            totalAlignments: options.alignmentCount || 0,
            markovBonuses: {
                concisenessBonusMultiplier: bestKnobs.concisenessBonusMultiplier || 1.7,
                lengthBonusMultiplier: bestKnobs.lengthBonusMultiplier || 2.6,
            },
            minCommandLength: bestKnobs.minCommandLength || 1,
        },

        // Runtime settings (can be overridden in UI)
        runtime: {
            minCoverage: bestKnobs.minCoverage || (paddingResult?.coverage) || 0.5,
            minCommandLength: bestKnobs.minCommandLength || 1,
            concisenessBonusMultiplier: bestKnobs.concisenessBonusMultiplier || 1.7,
            lengthBonusMultiplier: bestKnobs.lengthBonusMultiplier || 2.6,
        },

        // Per-command results for debugging/review
        perCommandResults: autoCalibrateResult?.best?.perCommand?.slice(0, 50) || [],  // Limit to 50 for size
    };

    return profile;
}

/**
 * Main calibration function.
 * Input: flow (from aggregateSshFlows), transcript text
 * Output: profile object ready to save
 * 
 * v4 updates:
 * - Integrates weight envelope system (v2 schema)
 * - Detects SSH client type automatically
 * - Supports building profiles from auto-calibration results
 */
async function calibrateFromFlowAndTranscript(flow, transcriptText, options = {}) {
    const {
        direction = "c2s",
        clientName = "Unknown",
        profileName = null,
        autoCalibrateResult = null,  // Optional: result from autoCalibrate()
    } = options;

    console.log(`[Calibration] Starting calibration for flow ${flow.flowKey}, direction ${direction}`);

    // Parse transcript
    const commands = parseTranscript(transcriptText);
    if (commands.length === 0) {
        throw new Error("No valid commands found in transcript");
    }
    console.log(`[Calibration] Parsed ${commands.length} commands from transcript`);

    // Extract delays from flow
    const rawDelays = extractDelaysFromFlow(flow);
    if (rawDelays.length === 0) {
        throw new Error("No valid delays extracted from flow");
    }

    // Use the deobfuscation/peeling logic to get per-keystroke delays
    // This attempts to split batched keystrokes by detecting and removing
    // the 20ms padding cadence that SSH uses
    const relevantRawDelays = rawDelays.filter(d => d.direction === direction).map(d => d.delayMs);

    // Run padding detection with auto-tune to find the best coverage threshold
    const paddingResult = autoTunePaddingThreshold(relevantRawDelays, { minCoverage: 0.5 });

    let keystrokeDelays = [];
    if (paddingResult.detected && paddingResult.keystrokeDelaysMs) {
        keystrokeDelays = paddingResult.keystrokeDelaysMs;
        console.log(`[Calibration] Padding detected: period=${paddingResult.periodMs.toFixed(1)}ms, coverage=${paddingResult.coverage.toFixed(2)}, peeled ${keystrokeDelays.length} keystroke delays`);
    } else {
        // Fallback: use raw delays (will be fewer than keystrokes due to batching)
        keystrokeDelays = relevantRawDelays;
        console.log(`[Calibration] No padding detected, using ${keystrokeDelays.length} raw delays`);
    }

    // Convert keystrokeDelays back to alignment format
    const delaysForAlignment = keystrokeDelays.map((delayMs, idx) => ({
        delayMs,
        direction,
        packetIndex: idx,
        timestamp: 0, // Not needed for alignment
    }));

    // Align commands to delays
    const alignments = alignCommandsToDelays(commands, delaysForAlignment, direction);
    if (alignments.length < 10) {
        throw new Error(`Insufficient alignments (${alignments.length}), need at least 10`);
    }

    // Learn digraph parameters with v2 weight envelopes
    const learnedDigraphs = learnDigraphParameters(alignments, null, {
        source: "calibrated",
    });

    // Extract SSHniff-inspired command profiles and rhythm signatures
    const commandProfiles = extractCommandProfiles(alignments);
    const commandRhythms = {};
    for (const [cmd, profile] of Object.entries(commandProfiles)) {
        const signature = computeCommandRhythmSignature(profile);
        if (signature) {
            commandRhythms[cmd] = {
                signature,
                sampleCount: profile.count,
                medianKeystrokes: Math.floor(
                    profile.delays.map(d => d.length).sort((a, b) => a - b)[Math.floor(profile.delays.length / 2)]
                ),
            };
        }
    }
    console.log(`[Calibration] Extracted rhythm signatures for ${Object.keys(commandRhythms).length} commands`);

    // Detect Enter keys and backspaces from delays (SSHniff methodology)
    const enterIndices = detectEnterKeys(keystrokeDelays);
    const backspaceIndices = detectBackspaces(keystrokeDelays);
    console.log(`[Calibration] Detected ${enterIndices.length} Enter keys, ${backspaceIndices.length} potential backspaces`);

    // Split into command sequences for validation
    const commandSequences = splitIntoCommands(keystrokeDelays, enterIndices);
    console.log(`[Calibration] Split into ${commandSequences.length} command sequences`);

    // Learn Markov bonuses (placeholder)
    const markovBonuses = learnMarkovBonuses(alignments, commands);

    // Detect SSH client type
    const clientInfo = detectSshClientType(flow, keystrokeDelays, {
        paddingResult,
        commandCount: commands.length,
    });

    console.log(`[Calibration] Detected SSH client: ${clientInfo.type} (confidence: ${(clientInfo.confidence * 100).toFixed(0)}%)`);
    console.log(`[Calibration] Profile built with ${Object.keys(learnedDigraphs).length} learned digraphs`);

    // If we have auto-calibration results, build enhanced profile
    if (autoCalibrateResult) {
        const baseModel = loadQwertyModel({});
        return buildProfileFromAutoCalibration(flow, transcriptText, autoCalibrateResult, learnedDigraphs, {
            direction,
            clientName: clientName !== "Unknown" ? clientName : clientInfo.type,
            profileName,
            paddingResult,
            commandCount: commands.length,
            alignmentCount: alignments.length,
            baseModel,
            commandRhythms,
        });
    }

    // Legacy profile building (no auto-calibration results)
    const baseModel = loadQwertyModel({});

    // Merge learned digraphs into empirical model
    const empirical = { ...baseModel.empirical };
    for (const [key, params] of Object.entries(learnedDigraphs)) {
        empirical[key] = params;
    }

    const profile = {
        version: 4,  // Version 4 includes weight envelopes and client detection
        name: profileName || `${clientInfo.type}_${Date.now()}`.replace(/[^a-zA-Z0-9_-]/g, '_'),
        displayName: profileName || `Calibrated: ${clientInfo.type}`,

        // SSH client information
        clientInfo: {
            type: clientInfo.type,
            version: clientInfo.version,
            detectionConfidence: clientInfo.confidence,
            detectedFeatures: clientInfo.detectedFeatures,
            userLabel: clientName !== "Unknown" ? clientName : null,
        },

        createdAt: new Date().toISOString(),
        schemaVersion: 2,  // v2 weight envelope schema

        source: {
            flowKey: flow.flowKey,
            packetCount: flow.packets.length,
            commandCount: commands.length,
            alignmentCount: alignments.length,
            calibrationMethod: "manual",
        },

        // Model geometry
        layout: baseModel.layout || "qwerty",
        baselines: baseModel.baselines,
        empirical: empirical,
        coordinateIndex: baseModel.coordinateIndex,
        alphabet: DECODER_ALPHABET,

        // SSHniff-inspired features
        commandRhythms: commandRhythms,
        enterKeyThresholdMs: ENTER_KEY_THRESHOLD_MS,
        backspaceThresholdMs: BACKSPACE_THRESHOLD_MS,
        detectedEnterIndices: enterIndices,
        detectedBackspaceIndices: backspaceIndices,
        commandSequences: commandSequences.map(seq => seq.length),

        // Calibration-specific settings
        calibration: {
            coverageThreshold: paddingResult.coverage,
            paddingAccuracy: paddingResult.accuracy,
            digraphsLearned: Object.keys(learnedDigraphs).length,
            totalAlignments: alignments.length,
            markovBonuses,
        },

        // Runtime settings (can be overridden in UI)
        runtime: {
            minCoverage: paddingResult.coverage,
            minCommandLength: 1,
            concisenessBonusMultiplier: markovBonuses.concisenessBonusMultiplier,
            lengthBonusMultiplier: markovBonuses.lengthBonusMultiplier,
        },
    };

    return profile;
}

// Profile persistence functions are handled by main process IPC handlers
// (ssh-profiles-save, ssh-profiles-load, ssh-profiles-delete)
// to avoid @electron/remote dependency which doesn't work in main process.

module.exports = {
    parseTranscript,
    extractDelaysFromFlow,
    alignCommandsToDelays,
    learnDigraphParameters,
    learnPaddingThreshold,
    learnMarkovBonuses,
    calibrateFromFlowAndTranscript,
    // New v4 functions
    calculateDigraphWeight,
    detectSshClientType,
    buildProfileFromAutoCalibration,
    // SSHniff-inspired functions
    dtwDistance,
    euclideanDistance,
    normalizeSequence,
    extractCommandProfiles,
    computeCommandRhythmSignature,
    detectEnterKeys,
    detectBackspaces,
    splitIntoCommands,
    matchCommandToProfiles,
    ENTER_KEY_THRESHOLD_MS,
    BACKSPACE_THRESHOLD_MS,
    MIN_COMMAND_KEYSTROKES,
    MAX_COMMAND_KEYSTROKES,
};