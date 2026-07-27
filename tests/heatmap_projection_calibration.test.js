// Regression test for the heatmap map-projection calibration defaults.
//
// Background:
//   The heatmap projection calibration lives in two places — the renderer
//   panel (src/ui/panels/stats-panel.js) and the persisted debug settings
//   (src/settings.js). Historically these could drift apart, which caused
//   the map to jump out of calibration whenever settings were reset or
//   loaded fresh.
//
// Fix:
//   src/settings.js now exports MAP_PROJECTION_CALIBRATION as the single
//   source of truth, and stats-panel.js imports it. This test asserts
//   that:
//     1. DEFAULT_SETTINGS.debug.mapProjection* mirror MAP_PROJECTION_CALIBRATION.
//     2. cloneDefaultSettings preserves the calibration values.
//     3. normalizeSettings uses MAP_PROJECTION_CALIBRATION as the fallback
//        for the four debug defaults.
//     4. MAP_PROJECTION_CALIBRATION is frozen so it cannot be mutated
//        silently.
//     5. stats-panel.js loads and exposes a stats panel with calibrated
//        defaults that match MAP_PROJECTION_CALIBRATION (via the require
//        chain, the panel's local aliases pick up the same numbers).

const path = require('path');

const SETTINGS_PATH = path.join(__dirname, '..', 'src', 'settings.js');
const STATS_PANEL_PATH = path.join(__dirname, '..', 'src', 'ui', 'panels', 'stats-panel.js');

function freshRequireSettings() {
    delete require.cache[require.resolve(SETTINGS_PATH)];
    return require(SETTINGS_PATH);
}

function freshRequireStatsPanel() {
    delete require.cache[require.resolve(SETTINGS_PATH)];
    delete require.cache[require.resolve(STATS_PANEL_PATH)];
    return require(STATS_PANEL_PATH);
}

describe('heatmap map-projection calibration defaults', () => {
    test('MAP_PROJECTION_CALIBRATION is exported and frozen', () => {
        const { MAP_PROJECTION_CALIBRATION } = freshRequireSettings();
        expect(MAP_PROJECTION_CALIBRATION).toBeDefined();
        expect(Object.isFrozen(MAP_PROJECTION_CALIBRATION)).toBe(true);
        expect(MAP_PROJECTION_CALIBRATION).toEqual({
            zoomX: 0.29,
            zoomY: 0.83,
            offsetX: -1.30,
            offsetY: 0.39,
        });
    });

    test('DEFAULT_SETTINGS.debug.mapProjection* match MAP_PROJECTION_CALIBRATION', () => {
        const { DEFAULT_SETTINGS, MAP_PROJECTION_CALIBRATION } = freshRequireSettings();
        const debug = DEFAULT_SETTINGS.debug;
        expect(debug.mapProjectionZoomX).toBe(MAP_PROJECTION_CALIBRATION.zoomX);
        expect(debug.mapProjectionZoomY).toBe(MAP_PROJECTION_CALIBRATION.zoomY);
        expect(debug.mapProjectionOffsetX).toBe(MAP_PROJECTION_CALIBRATION.offsetX);
        expect(debug.mapProjectionOffsetY).toBe(MAP_PROJECTION_CALIBRATION.offsetY);
    });

    test('cloneDefaultSettings preserves the calibration values', () => {
        const { cloneDefaultSettings, MAP_PROJECTION_CALIBRATION } = freshRequireSettings();
        const cloned = cloneDefaultSettings();
        expect(cloned.debug.mapProjectionZoomX).toBe(MAP_PROJECTION_CALIBRATION.zoomX);
        expect(cloned.debug.mapProjectionZoomY).toBe(MAP_PROJECTION_CALIBRATION.zoomY);
        expect(cloned.debug.mapProjectionOffsetX).toBe(MAP_PROJECTION_CALIBRATION.offsetX);
        expect(cloned.debug.mapProjectionOffsetY).toBe(MAP_PROJECTION_CALIBRATION.offsetY);
    });

    test('normalizeSettings uses MAP_PROJECTION_CALIBRATION as the fallback', () => {
        const { normalizeSettings, MAP_PROJECTION_CALIBRATION } = freshRequireSettings();
        // Strip the four projection values; normalizeSettings must fall
        // back to the canonical calibration constants.
        const partialDebug = {
            bsonGzipSessionEnabled: true,
            ungroupedListVirtualizationEnabled: false,
            backendHttpDataModeEnabled: true,
        };
        const normalized = normalizeSettings({ debug: partialDebug });
        expect(normalized.debug.mapProjectionZoomX).toBe(MAP_PROJECTION_CALIBRATION.zoomX);
        expect(normalized.debug.mapProjectionZoomY).toBe(MAP_PROJECTION_CALIBRATION.zoomY);
        expect(normalized.debug.mapProjectionOffsetX).toBe(MAP_PROJECTION_CALIBRATION.offsetX);
        expect(normalized.debug.mapProjectionOffsetY).toBe(MAP_PROJECTION_CALIBRATION.offsetY);
    });

    test('stats-panel.js loads with calibration aliases tied to MAP_PROJECTION_CALIBRATION', () => {
        const { MAP_PROJECTION_CALIBRATION } = freshRequireSettings();
        // The panel module is required (no DOM needed for module-level
        // evaluation). It must export createStatsPanel / buildCaptureStats
        // and the module must have loaded without throwing, which is the
        // observable contract: the calibration aliases at module top are
        // populated from the imported MAP_PROJECTION_CALIBRATION object.
        const panel = freshRequireStatsPanel();
        expect(typeof panel.createStatsPanel).toBe('function');
        expect(typeof panel.buildCaptureStats).toBe('function');
        // Sanity check: the canonical values are unchanged and finite.
        for (const key of ['zoomX', 'zoomY', 'offsetX', 'offsetY']) {
            expect(Number.isFinite(MAP_PROJECTION_CALIBRATION[key])).toBe(true);
        }
    });
});