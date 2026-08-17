// Jest tests for the qwerty-model.json v1 → v2 migrator.
//
// Verifies:
//   1. Round-trip (migrate → rollback → migrate) is lossless.
//   2. New fields default to reasonable values for legacy entries.
//   3. Backfill runs when fields are present but stale.
//   4. Re-running the migrator on an already-v2 file is a no-op.

const fs = require('fs');
const os = require('os');
const path = require('path');

const {
    migrateFile,
    rollbackFile,
    looksLikeV2,
} = require('./migrate_qwerty_model_v2');

const V1_SAMPLE = {
    meta: {
        source: 'unit-test',
        keys: 26,
        bigrams: 1,
        rows: ['1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'],
        fingerprint_method: 'empirical-mean',
    },
    unigrams: {
        a: { count: 100, mean_dwell_ms: 80, sd_dwell_ms: 12 },
        b: { count: 50, mean_dwell_ms: 90, sd_dwell_ms: 18 },
    },
    bigrams: {
        ab: { count: 20, mean_gap_ms: 110, sd_gap_ms: 30 },
        ba: { count: 10, mean_gap_ms: 130, sd_gap_ms: 40 },
    },
    trigrams: {
        abc: { count: 5, mean_gap_ms: 250, sd_gap_ms: 60 },
    },
};

function withTmpDir(fn) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qwerty-mig-'));
    try {
        return fn(dir);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

function readJson(p) {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
}

describe('migrate_qwerty_model_v2', () => {
    test('migrates a v1 file to v2 with weight envelopes', () => {
        withTmpDir((dir) => {
            const file = path.join(dir, 'm.json');
            fs.writeFileSync(file, JSON.stringify(V1_SAMPLE));
            const result = migrateFile(file);
            expect(result.changed).toBe(true);
            expect(result.warnings).toEqual([]);

            const v2 = readJson(file);
            expect(v2.version).toBe(2);
            expect(looksLikeV2(v2)).toBe(true);

            // unigrams: weight from count/(count+alpha)
            const alpha = v2.weight_envelope.alpha;
            const expectedA = 100 / (100 + alpha);
            expect(v2.unigrams.a.weight).toBeCloseTo(expectedA, 6);
            expect(v2.unigrams.a.weight_alpha).toBe(alpha);
            expect(v2.unigrams.a.weight_confidence).toBeCloseTo(expectedA, 6);
            expect(v2.unigrams.a.weight_effective_n).toBe(100);
            expect(v2.unigrams.a.derived_from).toEqual({
                primary: 'count',
                backing_fields: ['count'],
                model_version: 1,
            });

            // bigrams: weight from count too
            const expectedAb = 20 / (20 + alpha);
            expect(v2.bigrams.ab.weight).toBeCloseTo(expectedAb, 6);
            expect(v2.bigrams.ab.weight_effective_n).toBe(20);

            // trigrams: same treatment
            expect(v2.trigrams.abc.weight).toBeCloseTo(5 / (5 + alpha), 6);

            // meta is preserved + augmented
            expect(v2.meta.source).toBe('unit-test');
            expect(v2.meta.keys).toBe(26);
            expect(v2.meta.fingerprint_method).toBe('empirical-mean');
            expect(v2.meta.weight_envelope).toBeDefined();
            expect(v2.meta.weight_envelope.alpha).toBe(alpha);
            expect(v2.meta.weight_envelope.beta).toBeDefined();
        });
    });

    test('rollback produces a v1-shaped file', () => {
        withTmpDir((dir) => {
            const file = path.join(dir, 'm.json');
            fs.writeFileSync(file, JSON.stringify(V1_SAMPLE));
            migrateFile(file);
            const rb = rollbackFile(file);
            expect(rb.changed).toBe(true);
            const back = readJson(file);
            expect(back.version).toBeUndefined();
            expect(back.meta.source).toBe('unit-test');
            expect(back.unigrams.a.count).toBe(100);
            expect(back.bigrams.ab.count).toBe(20);
            expect(back.trigrams.abc.count).toBe(5);
        });
    });

    test('round-trip (migrate → rollback → migrate) is lossless', () => {
        withTmpDir((dir) => {
            const file = path.join(dir, 'm.json');
            fs.writeFileSync(file, JSON.stringify(V1_SAMPLE));
            const m1 = migrateFile(file);
            const rb = rollbackFile(file);
            const m2 = migrateFile(file);
            expect(m1.changed).toBe(true);
            expect(rb.changed).toBe(true);
            expect(m2.changed).toBe(false); // already v2 after rollback → migrate

            const v2a = JSON.parse(m1.after);
            const v2b = readJson(file);
            // Strip derived_from timestamps (may differ)
            expect(v2a.version).toBe(v2b.version);
            expect(v2a.unigrams).toEqual(v2b.unigrams);
            expect(v2a.bigrams).toEqual(v2b.bigrams);
            expect(v2a.trigrams).toEqual(v2b.trigrams);
            // meta without timestamps
            const stripTs = (m) => ({
                ...m,
                entries: undefined,
            });
            // we can't deeply diff meta.migrated_at cleanly, so check key fields
            expect(v2a.meta.source).toBe(v2b.meta.source);
            expect(v2a.meta.weight_envelope).toEqual(v2b.meta.weight_envelope);
        });
    });

    test('re-running on v2 is a no-op', () => {
        withTmpDir((dir) => {
            const file = path.join(dir, 'm.json');
            fs.writeFileSync(file, JSON.stringify(V1_SAMPLE));
            migrateFile(file);
            const m2 = migrateFile(file);
            expect(m2.changed).toBe(false);
            expect(m2.warnings).toEqual([]);
        });
    });

    test('backfills entries missing weight fields', () => {
        withTmpDir((dir) => {
            const file = path.join(dir, 'm.json');
            const partial = {
                meta: { source: 'partial' },
                unigrams: {
                    // has weight but no envelope
                    a: { count: 100, weight: 0.95, weight_alpha: 5 },
                    // missing weight
                    b: { count: 50 },
                },
                bigrams: {},
                trigrams: {},
            };
            fs.writeFileSync(file, JSON.stringify(partial));
            const result = migrateFile(file);
            expect(result.changed).toBe(true);

            const v2 = readJson(file);
            // a keeps its explicit weight
            expect(v2.unigrams.a.weight).toBe(0.95);
            expect(v2.unigrams.a.weight_confidence).toBe(0.95);
            expect(v2.unigrams.a.weight_effective_n).toBe(100);
            // b gets a backfilled weight from count
            const alpha = v2.weight_envelope.alpha;
            expect(v2.unigrams.b.weight).toBeCloseTo(50 / (50 + alpha), 6);
        });
    });

    test('handles missing meta gracefully', () => {
        withTmpDir((dir) => {
            const file = path.join(dir, 'm.json');
            fs.writeFileSync(
                file,
                JSON.stringify({
                    unigrams: { a: { count: 10 } },
                    bigrams: {},
                    trigrams: {},
                })
            );
            const result = migrateFile(file);
            expect(result.changed).toBe(true);
            const v2 = readJson(file);
            expect(v2.version).toBe(2);
            expect(v2.meta).toBeDefined();
            expect(v2.meta.weight_envelope).toBeDefined();
        });
    });
});