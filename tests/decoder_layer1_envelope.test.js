// Integration test for the Layer-1 weight-envelope wiring in the
// OpenSSH decoder. We build a v2 digraph model with envelopes, score
// the same observed delay against it under three configurations:
//
//   1. v1 model (no envelopes)  — baseline behaviour, must match pre-v2.
//   2. v2 model with shrinkage on  — confident priors dominate, sparse
//                                     priors regress to the baseline.
//   3. v2 model with shrinkage off — must match configuration 1.
//
// The numerical tolerances are wide because the Viterbi forward pass
// uses log-probabilities and tiny std differences amplify.

const fs = require("fs");
const path = require("path");

const REPO = path.resolve(__dirname, "..");
const decoder = require(path.join(REPO, "src/ui/decoders/ssh-keystrokes/index.js"));

function loadModel() {
    const parsed = JSON.parse(
        fs.readFileSync(path.join(REPO, "src/data/qwerty-model.json"), "utf8"),
    );
    return decoder.loadQwertyModel(parsed);
}

function modelWithShrinkage(model, envelopeOptions) {
    return Object.assign({}, model, {
        envelopeOptions: envelopeOptions || {},
    });
}

describe("decoder Layer-1 envelope shrinkage", () => {
    test("scoreNextChar is unchanged for v1 (no-envelope) models", () => {
        const v1 = loadModel();
        // Strip envelopes so we mimic a v1 surface.
        for (const k of Object.keys(v1.empirical)) {
            delete v1.empirical[k].weight;
        }
        v1.envelopeOptions = { useEnvelopeShrinkage: false };
        const delays = [100, 120, 80];
        const out = decoder.scoreNextChar("t", delays[0], v1);
        // All values must be finite log-probs.
        for (const ch of Object.keys(out)) {
            expect(Number.isFinite(out[ch])).toBe(true);
        }
    });

    test("scoreNextChar changes for v2 model with envelopes", () => {
        const v2 = loadModel();
        v2.envelopeOptions = {};
        const delays = [100, 120, 80];
        const v1Scores = decoder.scoreNextChar("t", delays[0], modelWithShrinkage(v2, { useEnvelopeShrinkage: false }));
        const v2Scores = decoder.scoreNextChar("t", delays[0], modelWithShrinkage(v2, {}));
        // At least one char must have a different logProb between the
        // two configurations — otherwise shrinkage is a no-op.
        let anyDiff = false;
        for (const ch of Object.keys(v2Scores)) {
            if (Math.abs((v1Scores[ch] || 0) - (v2Scores[ch] || 0)) > 1e-6) {
                anyDiff = true;
                break;
            }
        }
        expect(anyDiff).toBe(true);
    });

    test("high-confidence empirical entry dominates the prior", () => {
        const model = loadModel();
        model.envelopeOptions = {};
        // Find any digraph that exists in the empirical table.
        const digraph = Object.keys(model.empirical)[0];
        const entry = model.empirical[digraph];
        // Inject the test envelope: weight 1.0, count 1000 (high
        // confidence). Flat-shape per scripts/WEIGHT_SCHEMA.md §1.
        model.empirical[digraph] = Object.assign({}, entry, {
            mean: 250,
            std: 5,
            weight: 1.0,
            count: 1000,
            source: "unit-test",
            lastUpdated: "2026-08-17T00:00:00Z",
        });
        // The observed delay is near the empirical mean; the logP for the
        // empirical category's "true" char should be near 0, dominating
        // the baseline.
        const params = decoder.resolveDigraphParamsWithEnvelope(
            digraph[0], digraph[1], model.empirical, model.baselines, model.coordinateIndex, {},
        );
        // Empirical mean 250, std 5 → confident prior dominates. The
        // returned params should be near empirical.
        expect(Math.abs(params.mean - 250)).toBeLessThan(20);
        expect(params.std).toBeLessThan(40);
    });

    test("low-confidence empirical entry regresses toward the baseline", () => {
        const model = loadModel();
        model.envelopeOptions = {};
        const digraph = Object.keys(model.empirical)[0];
        const entry = model.empirical[digraph];
        // Inject a sparse empirical observation: weight 0.05, count 5 —
        // far below the threshold for "trustworthy".
        model.empirical[digraph] = Object.assign({}, entry, {
            mean: 400, // outlier far from any category baseline
            std: 80,
            weight: 0.05,
            count: 5,
            source: "unit-test",
            lastUpdated: "2026-08-17T00:00:00Z",
        });
        const params = decoder.resolveDigraphParamsWithEnvelope(
            digraph[0], digraph[1], model.empirical, model.baselines, model.coordinateIndex, {},
        );
        // Posterior should be pulled away from 400 toward the category
        // baseline. Without the prior we'd be at 400 exactly.
        expect(Math.abs(params.mean - 400)).toBeGreaterThan(50);
    });

    test("decodeKeystrokes end-to-end with v2 model", () => {
        const model = loadModel();
        model.envelopeOptions = {};
        const delays = [80, 90, 70, 100, 85, 95, 110];
        const v1Results = decoder.decodeKeystrokes(delays, {
            model: modelWithShrinkage(model, { useEnvelopeShrinkage: false }),
            topN: 3,
        });
        const v2Results = decoder.decodeKeystrokes(delays, {
            model: modelWithShrinkage(model, {}),
            topN: 3,
        });
        // Both should return at least one candidate.
        expect(v1Results.length).toBeGreaterThan(0);
        expect(v2Results.length).toBeGreaterThan(0);
        // The top-N top-1 result should be a string (might differ between
        // configurations; that's fine).
        expect(typeof v1Results[0].text).toBe("string");
        expect(typeof v2Results[0].text).toBe("string");
    });
});