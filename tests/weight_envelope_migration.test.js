// Validates the v2 weight-envelope shape on the three migrated JSON
// artifacts in scripts/. The migrator is idempotent; this test makes
// sure running it again doesn't regress anything.
//
// See scripts/WEIGHT_SCHEMA.md for the field-level schema.

const fs = require('fs');
const path = require('path');

const REPO = path.resolve(__dirname, '..');
const TARGETS = [
    'scripts/ssh_proposed_qwerty_baselines.json',
    'scripts/shell_markov_model.json',
    'scripts/ssh_timing_stats.json',
];

function readJson(rel) {
    const abs = path.join(REPO, rel);
    return JSON.parse(fs.readFileSync(abs, 'utf8'));
}

function isEnvelope(obj) {
    return (
        obj !== null &&
        typeof obj === 'object' &&
        typeof obj.confidence === 'number' &&
        typeof obj.sample_size === 'number' &&
        typeof obj.source === 'string' &&
        typeof obj.last_updated === 'string'
    );
}

describe('weight envelope migration', () => {
    test.each(TARGETS)('%s has a top-level v2 weight envelope', (rel) => {
        const data = readJson(rel);
        expect(data.weight).toBeDefined();
        expect(isEnvelope(data.weight)).toBe(true);
        expect(data.schema_version).toBe(2);
    });

    test('ssh_proposed_qwerty_baselines wraps each category', () => {
        const data = readJson('scripts/ssh_proposed_qwerty_baselines.json');
        const expected = ['sameKey', 'adjacentKey', 'nearbyKey', 'farKey', 'crossRow'];
        for (const name of expected) {
            expect(data.baselines[name]).toBeDefined();
            expect(isEnvelope(data.baselines[name].weight)).toBe(true);
            expect(typeof data.baselines[name].mean).toBe('number');
            expect(typeof data.baselines[name].std).toBe('number');
        }
    });

    test('shell_markov_model preserves transitions', () => {
        const data = readJson('scripts/shell_markov_model.json');
        // 3820 contexts is the size we recorded on first migration; if the
        // migrator was changed to drop transitions, this would fail.
        expect(Object.keys(data.transitions).length).toBe(3820);
        expect(data.weight.sample_size).toBeGreaterThan(0);
    });

    test('ssh_timing_stats preserves per-direction blocks', () => {
        const data = readJson('scripts/ssh_timing_stats.json');
        expect(data.client_to_server).toBeDefined();
        expect(data.server_to_client).toBeDefined();
        expect(data.client_to_server.count).toBeGreaterThan(0);
        expect(data.server_to_client.count).toBeGreaterThan(0);
        // weight envelope summarises both directions
        expect(data.weight.sample_size).toBeGreaterThanOrEqual(
            data.client_to_server.count + data.server_to_client.count
        );
    });
});

describe('weight envelope migrator CLI', () => {
    test('--dry-run does not modify files', () => {
        const { execFileSync } = require('child_process');
        // Snapshot one of the smaller targets.
        const target = path.join(REPO, 'scripts/ssh_proposed_qwerty_baselines.json');
        const before = fs.readFileSync(target, 'utf8');
        execFileSync(
            'python3',
            [path.join(REPO, 'scripts/migrate_weight_envelopes.py'), '--dry-run'],
            { cwd: REPO, stdio: 'pipe' }
        );
        const after = fs.readFileSync(target, 'utf8');
        expect(after).toBe(before);
    });

    test('--apply is idempotent', () => {
        const { execFileSync } = require('child_process');
        execFileSync(
            'python3',
            [path.join(REPO, 'scripts/migrate_weight_envelopes.py'), '--apply'],
            { cwd: REPO, stdio: 'pipe' }
        );
        // Capture mtimes + sizes after first apply.
        const targets = TARGETS.map((rel) => path.join(REPO, rel));
        const snapshot1 = targets.map((p) => ({
            p,
            mtime: fs.statSync(p).mtimeMs,
            size: fs.statSync(p).size,
        }));
        execFileSync(
            'python3',
            [path.join(REPO, 'scripts/migrate_weight_envelopes.py'), '--apply'],
            { cwd: REPO, stdio: 'pipe' }
        );
        const snapshot2 = targets.map((p) => ({
            p,
            mtime: fs.statSync(p).mtimeMs,
            size: fs.statSync(p).size,
        }));
        for (let i = 0; i < targets.length; i++) {
            expect(snapshot2[i].mtime).toBe(snapshot1[i].mtime);
            expect(snapshot2[i].size).toBe(snapshot1[i].size);
        }
    });
});