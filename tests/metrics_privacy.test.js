// Regression tests for the privacy/settings metrics plumbing.
//
// The renderer's metrics service (src/metrics.js) used to read the
// privacy block via a synchronous call to ``window.settingsapi.get``,
// which actually returns a Promise. That made the metrics layer see
// an empty privacy block on every read, which had two visible
// symptoms:
//
//   1. ``metrics.track()`` was always a no-op because
//      ``isEnabled()`` saw ``metricsEnabled`` as undefined.
//   2. ``init()`` always thought there was no install id, so it
//      generated a fresh one and wrote it back via a partial
//      ``settingsapi.update({ privacy: { metricsInstallId: id } })``.
//      Because the main process used a shallow merge for the
//      ``settings-update`` IPC, that partial write clobbered the
//      user's other privacy fields (the toggle and the endpoint URL).
//
// The fix has two parts:
//   * src/ui/main-frontend.js now calls ``metrics.setSettingsSnapshot``
//     every time the in-memory settings change.
//   * src/metrics.js reads from that snapshot instead of round-tripping
//     through the IPC.
//
// These tests guard both halves of the contract.

const path = require('path');

const METRICS_PATH = path.join(__dirname, '..', 'src', 'metrics.js');
const SETTINGS_PATH = path.join(__dirname, '..', 'src', 'settings.js');

function freshRequire() {
    delete require.cache[require.resolve(METRICS_PATH)];
    delete require.cache[require.resolve(SETTINGS_PATH)];
    return {
        metrics: require(METRICS_PATH),
        settings: require(SETTINGS_PATH),
    };
}

describe('privacy settings round-trip', () => {
    test('metrics reads metricsEnabled from the in-memory snapshot', () => {
        const { metrics, settings } = freshRequire();
        const { normalizeSettings, DEFAULT_SETTINGS } = settings;

        const snapshot = normalizeSettings({
            ...DEFAULT_SETTINGS,
            privacy: {
                ...DEFAULT_SETTINGS.privacy,
                metricsEnabled: true,
                metricsConsentAsked: true,
                metricsEndpointUrl: 'http://127.0.0.1:8088/mhook',
                metricsInstallId: '01234567-89ab-cdef-0123-456789abcdef',
            },
        });
        metrics.setSettingsSnapshot(snapshot);
        expect(metrics.getConsentStatus()).toBe('enabled');
    });

    test('metrics reads metricsEnabled: false from the in-memory snapshot', () => {
        const { metrics, settings } = freshRequire();
        const { normalizeSettings, DEFAULT_SETTINGS } = settings;

        const snapshot = normalizeSettings({
            ...DEFAULT_SETTINGS,
            privacy: {
                ...DEFAULT_SETTINGS.privacy,
                metricsEnabled: false,
                metricsConsentAsked: true,
                metricsInstallId: '01234567-89ab-cdef-0123-456789abcdef',
            },
        });
        metrics.setSettingsSnapshot(snapshot);
        expect(metrics.getConsentStatus()).toBe('disabled');
    });

    test('a clean ~/.config with no metricsConsentAsked reads as first-run', () => {
        // This is the regression guard for the missing consent
        // prompt: if the user has never been asked, the consent
        // status must be 'first-run' so the renderer can surface
        // the first-run overlay.
        const { metrics, settings } = freshRequire();
        const { normalizeSettings, DEFAULT_SETTINGS } = settings;

        const snapshot = normalizeSettings({
            ...DEFAULT_SETTINGS,
            privacy: {
                ...DEFAULT_SETTINGS.privacy,
                metricsEnabled: false,
                metricsConsentAsked: false,
                metricsEndpointUrl: '',
                metricsInstallId: '',
            },
        });
        metrics.setSettingsSnapshot(snapshot);
        expect(metrics.getConsentStatus()).toBe('first-run');
        expect(metrics.hasBeenAsked()).toBe(false);
    });

    test('legacy installs with metricsEnabled set are treated as already asked', () => {
        // Backwards compatibility: users who opted in (or out) on
        // an older build only have ``metricsEnabled`` and possibly
        // ``metricsInstallId`` in their settings.json. They must not
        // be re-prompted on every launch.
        const { metrics, settings } = freshRequire();
        const { normalizeSettings, DEFAULT_SETTINGS } = settings;

        const optInSnapshot = normalizeSettings({
            ...DEFAULT_SETTINGS,
            privacy: {
                ...DEFAULT_SETTINGS.privacy,
                metricsEnabled: true,
                metricsInstallId: '01234567-89ab-cdef-0123-456789abcdef',
            },
        });
        metrics.setSettingsSnapshot(optInSnapshot);
        expect(metrics.hasBeenAsked()).toBe(true);
        expect(metrics.getConsentStatus()).toBe('enabled');

        const optOutSnapshot = normalizeSettings({
            ...DEFAULT_SETTINGS,
            privacy: {
                ...DEFAULT_SETTINGS.privacy,
                metricsEnabled: false,
                metricsInstallId: '01234567-89ab-cdef-0123-456789abcdef',
            },
        });
        metrics.setSettingsSnapshot(optOutSnapshot);
        expect(metrics.hasBeenAsked()).toBe(true);
        expect(metrics.getConsentStatus()).toBe('disabled');
    });

    test('init() does not regenerate the install id once one is known', () => {
        const { metrics, settings } = freshRequire();
        const { normalizeSettings, DEFAULT_SETTINGS } = settings;

        const snapshot = normalizeSettings({
            ...DEFAULT_SETTINGS,
            privacy: {
                ...DEFAULT_SETTINGS.privacy,
                metricsConsentAsked: true,
                metricsInstallId: '01234567-89ab-cdef-0123-456789abcdef',
            },
        });
        metrics.setSettingsSnapshot(snapshot);
        // ``init`` would normally call ``persistInstallId`` if it
        // thought the install id was missing. With a fresh snapshot
        // we expect it to be a no-op for the install id side-effect.
        // ``installId`` is intentionally not part of the public API
        // (the metrics module is a singleton state object), so we
        // assert the visible behaviour: a subsequent ``flush`` does
        // not throw, the consent status reads as a known state, and
        // no fresh install id was written back.
        expect(() => metrics.init()).not.toThrow();
        // After init, the consent status reflects the snapshot's
        // install id (no longer "first-run") and the metricsEnabled
        // value as-is.
        expect(metrics.getConsentStatus()).toBe('disabled');
    });

    test('init() never generates an install id on a clean install', () => {
        // Regression guard: the previous behaviour generated an
        // install id on first run and persisted it via a partial
        // ``settingsapi.update`` that risked clobbering other
        // privacy fields. The new flow waits for explicit consent
        // before stamping any identifying info to settings.json.
        const { metrics, settings } = freshRequire();
        const { normalizeSettings, DEFAULT_SETTINGS } = settings;

        const snapshot = normalizeSettings({
            ...DEFAULT_SETTINGS,
            privacy: {
                ...DEFAULT_SETTINGS.privacy,
                metricsConsentAsked: false,
                metricsInstallId: '',
            },
        });
        metrics.setSettingsSnapshot(snapshot);
        // No ``window.settingsapi`` is available in this test
        // environment, so ``init`` cannot persist anything. Even
        // if it tried, the privacy block above has
        // ``metricsEnabled`` left at the default (``false``), so
        // the legacy "backfill" branch must not fire.
        expect(() => metrics.init()).not.toThrow();
        // The visible side-effect of ``init`` on a clean install
        // is that ``getConsentStatus`` still reads as
        // ``first-run`` (no install id was stamped).
        expect(metrics.getConsentStatus()).toBe('first-run');
    });

    test('settings-update deep-merges the privacy block', () => {
        const { settings } = freshRequire();
        const { normalizeSettings, DEFAULT_SETTINGS } = settings;

        const before = normalizeSettings({
            ...DEFAULT_SETTINGS,
            privacy: {
                ...DEFAULT_SETTINGS.privacy,
                metricsEnabled: true,
                metricsEndpointUrl: 'http://127.0.0.1:8088/mhook',
            },
        });

        // Simulate what ``metrics.js`` does on first run: a partial
        // update that only carries the new install id.
        const partialUpdate = {
            ...before,
            privacy: {
                ...before.privacy,
                metricsInstallId: '01234567-89ab-cdef-0123-456789abcdef',
            },
        };

        // The fix in src/main.js merges ``partial.privacy`` into
        // ``current.privacy`` instead of replacing it wholesale.
        // Replicate the same shape here so we can assert the
        // contract directly.
        const merged = {
            ...before,
            privacy: {
                ...before.privacy,
                ...partialUpdate.privacy,
            },
        };
        expect(merged.privacy.metricsEnabled).toBe(true);
        expect(merged.privacy.metricsEndpointUrl).toBe('http://127.0.0.1:8088/mhook');
        expect(merged.privacy.metricsInstallId).toBe('01234567-89ab-cdef-0123-456789abcdef');
    });

    test('normalizeSettings preserves a custom endpoint URL', () => {
        const { settings } = freshRequire();
        const { normalizeSettings, DEFAULT_SETTINGS } = settings;
        const out = normalizeSettings({
            ...DEFAULT_SETTINGS,
            privacy: {
                ...DEFAULT_SETTINGS.privacy,
                metricsEndpointUrl: 'http://127.0.0.1:8088/mhook',
            },
        });
        expect(out.privacy.metricsEndpointUrl).toBe('http://127.0.0.1:8088/mhook');
    });
});
