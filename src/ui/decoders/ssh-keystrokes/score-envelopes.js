// src/ui/decoders/ssh-keystrokes/score-envelopes.js
//
// Bayesian helpers for the v2 weight-envelope schema described in
// scripts/WEIGHT_SCHEMA.md.
//
// The envelope is **flat**: the schema specifies `weight`, `count`,
// `source`, `lastUpdated` as sibling keys of `mean`/`std` on each
// entry, not a nested object. This file works directly on the flat
// shape so readers can pass `entry.weight`, `entry.count`, etc.
// directly without unwrapping.
//
// Two responsibilities:
//
//   1. **Effective sample size** — translate the schema's
//      `weight ∈ [0, 1]` into a "virtual observation count" that
//      downstream code can use as a Bayesian weight:
//
//          effective_n = max(1, round(count * weight))
//
//      Confident priors (`weight=1, count=large`) keep their influence;
//      unconfident priors (low weight, low count) contribute very
//      little. We floor at 1 so callers can rely on a non-zero weight
//      for blending math.
//
//   2. **Shrinkage** — when an empirical observation has low count or
//      low weight, blend it toward a strong prior instead of treating
//      it as ground truth:
//
//          posteriorMean = (n_eff * empirical + alpha * prior) / (n_eff + alpha)
//          posteriorVar  = (n_eff * eVar + alpha * pVar) / (n_eff + alpha)
//                          + (n_eff * alpha / (n_eff + alpha)^2) * (eMean - pMean)^2
//
//      The variance formula is standard inverse-variance pooling with
//      an extra term that grows the posterior uncertainty when
//      empirical and prior disagree.
//
// We never touch the v1 surface: legacy entries that omit
// `weight` / `count` continue to work (effective_n defaults to 0 and
// the empirical value passes through unchanged).

"use strict";

const REQUIRED_ENVELOPE_KEYS = ["weight", "count", "source", "lastUpdated"];
const DEFAULT_PRIOR_ALPHA = 5;

/**
 * True if `entry` carries the v2 envelope fields. Accepts both the
 * flat shape (`entry.weight`, `entry.count`, …) and a defensive
 * nested shape (`entry.weight.weight`) so legacy data from an
 * earlier migrator still parses.
 */
function isEnvelope(entry) {
    if (!entry || typeof entry !== "object") return false;
    if (typeof entry.weight === "number" || entry.weight === null) {
        for (const k of REQUIRED_ENVELOPE_KEYS) {
            if (!(k in entry)) return false;
        }
        return true;
    }
    if (entry.weight && typeof entry.weight === "object") {
        // Nested shape — also accepted.
        for (const k of REQUIRED_ENVELOPE_KEYS) {
            if (!(k in entry.weight)) return false;
        }
        return true;
    }
    return false;
}

/**
 * Effective virtual sample size for an entry. Combines the entry's
 * `count` with its `weight ∈ [0, 1]` to give a "virtual observation
 * count" suitable as a Bayesian weight.
 */
function effectiveSampleSize(entry) {
    if (!isEnvelope(entry)) return 0;
    const weight = clamp01(Number(entry.weight));
    const count = Math.max(0, Number(entry.count) || 0);
    return Math.max(1, Math.round(count * weight));
}

/**
 * Shrink an empirical observation toward a prior.
 *
 * Returns `{ mean, std, effective_n, alpha }`. If the empirical
 * entry has no envelope (v1 surface) the function returns the
 * empirical mean/std unchanged with `effective_n = 0`, which is the
 * "trust the empirical exactly" semantic. Legacy callers get the
 * same behaviour they always have.
 */
function shrinkToPrior(empirical, prior, options) {
    if (!empirical || typeof empirical !== "object") {
        return prior && typeof prior === "object"
            ? { mean: Number(prior.mean), std: Number(prior.std), effective_n: 0, alpha: 0 }
            : null;
    }
    if (!prior || typeof prior !== "object") {
        return {
            mean: Number(empirical.mean),
            std: Number(empirical.std),
            effective_n: 0,
            alpha: 0,
        };
    }
    if (!isEnvelope(empirical)) {
        return {
            mean: Number(empirical.mean),
            std: Number(empirical.std),
            effective_n: 0,
            alpha: 0,
        };
    }

    const nEff = effectiveSampleSize(empirical);
    const alpha = clamp01(
        options && options.alpha ? options.alpha : 1.0,
    ) * DEFAULT_PRIOR_ALPHA;

    const eMean = Number(empirical.mean);
    const eVar = Number(empirical.std) * Number(empirical.std);
    const pMean = Number(prior.mean);
    const pVar = Number(prior.std) * Number(prior.std);

    const denom = nEff + alpha;
    const postMean = (nEff * eMean + alpha * pMean) / denom;
    const postVar =
        (nEff * eVar + alpha * pVar) / denom +
        (nEff * alpha * (eMean - pMean) * (eMean - pMean)) /
        (denom * denom);

    return {
        mean: postMean,
        std: Math.sqrt(Math.max(0, postVar)),
        effective_n: nEff,
        alpha,
    };
}

function clamp01(x) {
    if (!Number.isFinite(x)) return 0;
    if (x < 0) return 0;
    if (x > 1) return 1;
    return x;
}

module.exports = {
    DEFAULT_PRIOR_ALPHA,
    isEnvelope,
    effectiveSampleSize,
    shrinkToPrior,
    clamp01,
};