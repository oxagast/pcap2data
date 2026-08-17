// SSH c2s compression-likelihood heuristic.
//
// We cannot decrypt the SSH stream, so we have to infer whether the
// client-to-server channel is compressed (e.g. `zlib@openssh.com`) from
// observable packet-level signals:
//
//   * Median c2s packet length. Uncompressed ASCII keystrokes typically
//     produce wire packets in the 40-120 byte range (one keystroke +
//     Ethernet/IP/TCP/MAC headers). Heavily compressed streams skew
//     smaller because the plaintext gets reduced.
//
//   * Fraction of "tiny" c2s packets (<= SHORT_PACKET_BYTES). A high
//     fraction of tiny packets on a fast typist is a strong compression
//     signal — without compression each keystroke usually produces at
//     least 60-70 bytes on the wire (Ethernet + IP + TCP + SSH overhead
//     + 1 byte plaintext).
//
//   * Size homogeneity. zlib output is famously blocky: runs of packets
//     within a few bytes of each other is suspicious. We measure this
//     by the 25th-to-75th percentile spread normalized by the median.
//
// The returned score is intentionally a soft probability in [0, 1] —
// the downstream keystroke-count heuristic reads it as a multiplier
// (1.0 = trust the small-packet heuristic as-is, >1 = inflate), so a
// false-positive only inflates a small-packet count by a small amount.
//
// This module is pure JS (no Electron, no DOM) so it is trivially
// testable.

"use strict";

const DEFAULT_SHORT_PACKET_BYTES = 60;
const DEFAULT_MIN_C2S_PACKETS = 10;
const MEDIAN_UNCOMPRESSED_BYTES = 95;     // typical median c2s packet len when uncompressed
const TINY_PACKET_THRESHOLD_BYTES = 60;   // below this is suspicious for uncompressed single-keystroke packets

/**
 * Compute a robust-ish median of an array of numbers. Returns null
 * for empty input.
 */
function median(values) {
    if (!Array.isArray(values) || values.length === 0) return null;
    const sorted = values.slice().sort((a, b) => a - b);
    const n = sorted.length;
    if (n % 2 === 1) return sorted[(n - 1) / 2];
    const lo = sorted[n / 2 - 1];
    const hi = sorted[n / 2];
    return (lo + hi) / 2;
}

/**
 * Linear percentile (0..1) on a numeric array. Returns null for empty input.
 */
function percentile(values, p) {
    if (!Array.isArray(values) || values.length === 0) return null;
    if (p <= 0) return Math.min(...values);
    if (p >= 1) return Math.max(...values);
    const sorted = values.slice().sort((a, b) => a - b);
    const idx = (sorted.length - 1) * p;
    const lo = Math.floor(idx);
    const hi = Math.ceil(idx);
    if (lo === hi) return sorted[lo];
    const frac = idx - lo;
    return sorted[lo] * (1 - frac) + sorted[hi] * frac;
}

/**
 * Extract the wire length for each c2s packet. Pulls the same field
 * the renderer uses (`packet.info["packet.length"]`) so the heuristic
 * runs over the same data the rest of the pipeline sees.
 *
 * Returns an array of positive integers. Packets whose length cannot
 * be resolved are dropped (we cannot reason about compression without
 * a length signal).
 */
function extractC2sPacketLengths(packets, opts) {
    const o = opts || {};
    const minLen = Number.isFinite(o.minLen) ? o.minLen : 1;
    const out = [];
    for (const pkt of packets) {
        if (!pkt || pkt.direction !== "c2s") continue;
        const info = (pkt.packet && (pkt.packet["packet.info"] || pkt.packet["Packet Info"])) || null;
        if (!info || typeof info !== "object") continue;
        const raw = info["packet.length"] ?? info["Packet Length"] ?? info["Length"];
        const n = Number(raw);
        if (Number.isFinite(n) && n >= minLen) {
            out.push(n);
        }
    }
    return out;
}

/**
 * Score a single signal in [0, 1] from an observed value.
 *
 * `signal` is one of:
 *   - "medianLenLow"     : higher score = smaller median (more compression-like)
 *   - "shortFractionHigh" : higher score = more tiny packets
 *   - "homogeneityHigh"  : higher score = more homogeneous sizes
 */
function scoreSignal(signal, observed) {
    switch (signal) {
        case "medianLenLow": {
            // Map median length to score in [0, 1]:
            //   <= MEDIAN_UNCOMPRESSED_BYTES / 2 → 1.0 (very compressed-looking)
            //   >= MEDIAN_UNCOMPRESSED_BYTES * 1.2 → 0.0 (very uncompressed-looking)
            const lo = MEDIAN_UNCOMPRESSED_BYTES * 0.5;
            const hi = MEDIAN_UNCOMPRESSED_BYTES * 1.2;
            if (!Number.isFinite(observed)) return 0;
            if (observed <= lo) return 1;
            if (observed >= hi) return 0;
            return (hi - observed) / (hi - lo);
        }
        case "shortFractionHigh": {
            if (!Number.isFinite(observed)) return 0;
            // 0% tiny → 0; 60%+ tiny → 1 (clipped).
            return Math.max(0, Math.min(1, observed / 0.6));
        }
        case "homogeneityHigh": {
            // homogeneity is already a [0, 1] value (1 - spread/median).
            if (!Number.isFinite(observed)) return 0;
            return Math.max(0, Math.min(1, observed));
        }
        default:
            return 0;
    }
}

/**
 * Analyze a flow's c2s packets and return a soft compression-likelihood
 * score in [0, 1] along with the underlying signal values.
 *
 * opts:
 *   - shortPacketBytes: bytes threshold below which a packet is "tiny"
 *     (default 60).
 *   - minC2sPackets: minimum number of c2s packets required to attempt
 *     a score (default 10). Below this the score returns 0 (insufficient
 *     evidence).
 *   - weights: optional { medianLen, shortFraction, homogeneity }
 *     weight overrides (default 0.4 / 0.4 / 0.2).
 *
 * Returns:
 *   {
 *     likelihood: number,        // 0..1
 *     signals: {
 *       c2sPacketCount: number,
 *       medianLen: number|null,
 *       shortFraction: number,    // 0..1
 *       homogeneity: number,      // 0..1
 *     },
 *   }
 *
 * Pure: no side effects, no I/O.
 */
function analyzeCompressionLikelihood(packets, opts) {
    const o = opts || {};
    const shortPacketBytes = Number.isFinite(o.shortPacketBytes)
        ? o.shortPacketBytes
        : TINY_PACKET_THRESHOLD_BYTES;
    const minC2sPackets = Number.isFinite(o.minC2sPackets)
        ? o.minC2sPackets
        : DEFAULT_MIN_C2S_PACKETS;
    const weights = o.weights || { medianLen: 0.4, shortFraction: 0.4, homogeneity: 0.2 };

    const empty = {
        likelihood: 0,
        signals: { c2sPacketCount: 0, medianLen: null, shortFraction: 0, homogeneity: 0 },
    };

    if (!Array.isArray(packets) || packets.length === 0) return empty;

    const lens = extractC2sPacketLengths(packets);
    if (lens.length < minC2sPackets) {
        return {
            likelihood: 0,
            signals: { c2sPacketCount: lens.length, medianLen: null, shortFraction: 0, homogeneity: 0 },
        };
    }

    const med = median(lens);
    const p25 = percentile(lens, 0.25);
    const p75 = percentile(lens, 0.75);
    const shortCount = lens.filter((n) => n <= shortPacketBytes).length;
    const shortFraction = shortCount / lens.length;
    const spread = (p75 !== null && p25 !== null && med !== null && med > 0)
        ? (p75 - p25) / med
        : 1;
    const homogeneity = Math.max(0, Math.min(1, 1 - spread));

    const sMedian = scoreSignal("medianLenLow", med);
    const sShort = scoreSignal("shortFractionHigh", shortFraction);
    const sHomog = scoreSignal("homogeneityHigh", homogeneity);

    const wSum = weights.medianLen + weights.shortFraction + weights.homogeneity;
    let likelihood = 0;
    if (wSum > 0) {
        likelihood =
            (sMedian * weights.medianLen + sShort * weights.shortFraction + sHomog * weights.homogeneity)
            / wSum;
    }
    if (!Number.isFinite(likelihood)) likelihood = 0;
    likelihood = Math.max(0, Math.min(1, likelihood));

    return {
        likelihood,
        signals: {
            c2sPacketCount: lens.length,
            medianLen: med,
            shortFraction,
            homogeneity,
        },
    };
}

/**
 * Given a flow-level compression likelihood and an observed c2s
 * packet length, return an inflation factor in [1, INFLATION_MAX] that
 * the small-packet heuristic should multiply its per-packet keystroke
 * count by.
 *
 * The factor scales gently — at likelihood=0.5 we already credit a
 * compressed-looking packet with ~25% extra keystrokes, at likelihood=1
 * we credit up to INFLATION_MAX (default 1.6 = +60%). The intent is
 * "within reason": under-count by a little is preferable to over-count.
 *
 * Length scaling: very small packets (<= 40 bytes) get the full
 * inflation because they're the most under-counted case. Larger
 * packets (>120 bytes) probably hold >1 keystroke even without
 * compression, so we taper the inflation toward 1.
 */
const INFLATION_MAX = 1.6;
const LENGTH_TAPER_BYTES = 120;

function compressionInflationFactor(likelihood, packetLength) {
    const l = Number.isFinite(likelihood) ? Math.max(0, Math.min(1, likelihood)) : 0;
    if (l <= 0) return 1;
    // Linear ramp 0→l gives 1.0→INFLATION_MAX
    const baseFactor = 1 + (INFLATION_MAX - 1) * l;
    // Length taper: full effect at small lengths, taper to 1.0 at large.
    // `taper` here scales the *delta* (baseFactor - 1), so at taper=1
    // we get the full baseFactor and at taper=0 we get exactly 1.0.
    let deltaScale = 1;
    if (Number.isFinite(packetLength) && packetLength > 0) {
        if (packetLength <= 40) {
            deltaScale = 1;
        } else if (packetLength >= LENGTH_TAPER_BYTES) {
            deltaScale = 0;
        } else {
            const t = (packetLength - 40) / (LENGTH_TAPER_BYTES - 40);
            deltaScale = 1 - t;
        }
    }
    const factor = 1 + (baseFactor - 1) * deltaScale;
    if (!Number.isFinite(factor) || factor < 1) return 1;
    return Math.min(INFLATION_MAX + 0.5, factor);
}

module.exports = {
    analyzeCompressionLikelihood,
    compressionInflationFactor,
    // internals exposed for testing
    _internal: {
        median,
        percentile,
        extractC2sPacketLengths,
        scoreSignal,
        DEFAULT_SHORT_PACKET_BYTES,
        DEFAULT_MIN_C2S_PACKETS,
        MEDIAN_UNCOMPRESSED_BYTES,
        TINY_PACKET_THRESHOLD_BYTES,
        INFLATION_MAX,
        LENGTH_TAPER_BYTES,
    },
};