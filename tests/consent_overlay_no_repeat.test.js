// Regression test for the consent overlay being re-shown on every
// launch even after the user has answered it.
//
// Bug history: ``metrics.getConsentStatus()`` returns "first-run"
// whenever the metrics module has not yet received a settings
// snapshot (the in-code ``metrics`` object has its ``settingsSnapshot``
// set to ``null`` until ``loadPersistedSettings`` finishes). The
// install screen used to call ``maybeShowConsentOverlay`` as soon as
// ``installapi.checkFirstRun`` resolved, which happens BEFORE the
// renderer finishes its initial ``loadPersistedSettings()`` and
// pushes the persisted privacy block into the metrics module. As a
// result the overlay was shown on every launch — even when
// ``privacy.metricsConsentAsked`` was already ``true`` on disk.
//
// The fix: ``maybeShowConsentOverlay`` defers the prompt until the
// metrics snapshot is populated. When it is empty it subscribes to
// ``packetsnitch:settings-updated`` once and retries.
//
// We use a hand-rolled DOM stub — JSDOM is overkill for this
// regression test and brings in a large ESM-only dep tree that the
// existing jest config cannot transform.

const path = require("path");

function makeFakeElement() {
    return {
        hidden: true,
        style: {},
    };
}

function makeFakeDocument() {
    const overlay = makeFakeElement();
    overlay.hidden = true;
    return {
        getElementById(id) {
            if (id === "metrics-consent-overlay") return overlay;
            return null;
        },
        __overlay: overlay,
    };
}

function makeFakeWindow() {
    const listeners = new Map();
    return {
        __listeners: listeners,
        addEventListener(type, callback) {
            if (!listeners.has(type)) listeners.set(type, new Set());
            listeners.get(type).add(callback);
            return () => {
                const set = listeners.get(type);
                if (set) set.delete(callback);
            };
        },
        removeEventListener(type, callback) {
            const set = listeners.get(type);
            if (set) set.delete(callback);
        },
        dispatchEvent(event) {
            const set = listeners.get(event.type);
            if (!set) return;
            // Snapshot the listener set so that listeners that remove
            // themselves during dispatch do not affect iteration.
            const snapshot = Array.from(set);
            for (const cb of snapshot) {
                try {
                    cb(event);
                } catch (_error) {
                    // ignore: best-effort
                }
            }
        },
        CustomEvent: function CustomEvent(type, init = {}) {
            this.type = type;
            this.detail = init.detail;
        },
    };
}

describe("metrics consent overlay — does not re-prompt after answered", () => {
    let fakeDocument;
    let fakeWindow;
    let consentOverlay;
    let metrics;

    beforeEach(() => {
        jest.resetModules();
        fakeDocument = makeFakeDocument();
        fakeWindow = makeFakeWindow();
        global.window = fakeWindow;
        global.document = fakeDocument;
        consentOverlay = require(path.resolve("src/ui/panels/consent-overlay"));
        metrics = require(path.resolve("src/metrics"));
    });

    afterEach(() => {
        delete global.window;
        delete global.document;
    });

    test("does not show the overlay before the persisted settings snapshot is pushed", () => {
        metrics.setSettingsSnapshot(null);
        const shown = consentOverlay.maybeShowConsentOverlay({
            documentRef: fakeDocument,
            metrics,
        });
        expect(shown).toBe(false);
        expect(fakeDocument.__overlay.hidden).toBe(true);
    });

    test("shows the overlay on a clean first-run (snapshot populated, no consent yet)", () => {
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: false, metricsEnabled: false, metricsInstallId: "" },
        });
        const shown = consentOverlay.maybeShowConsentOverlay({
            documentRef: fakeDocument,
            metrics,
        });
        expect(shown).toBe(true);
        expect(fakeDocument.__overlay.hidden).toBe(false);
    });

    test("does NOT re-show the overlay when metricsConsentAsked is true on disk", () => {
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: true, metricsEnabled: true, metricsInstallId: "abc-123" },
        });
        const shown = consentOverlay.maybeShowConsentOverlay({
            documentRef: fakeDocument,
            metrics,
        });
        expect(shown).toBe(false);
        expect(fakeDocument.__overlay.hidden).toBe(true);
    });

    test("does NOT re-show the overlay when the user previously opted out", () => {
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: true, metricsEnabled: false, metricsInstallId: "" },
        });
        const shown = consentOverlay.maybeShowConsentOverlay({
            documentRef: fakeDocument,
            metrics,
        });
        expect(shown).toBe(false);
        expect(fakeDocument.__overlay.hidden).toBe(true);
    });

    test("defers until settings snapshot is pushed, then shows on first-run", () => {
        metrics.setSettingsSnapshot(null);
        const shown = consentOverlay.maybeShowConsentOverlay({
            documentRef: fakeDocument,
            metrics,
        });
        expect(shown).toBe(false);
        expect(fakeDocument.__overlay.hidden).toBe(true);

        // Simulate the renderer eventually loading persisted settings and
        // pushing the snapshot into the metrics module. The deferred
        // listener must pick this up and re-evaluate.
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: false, metricsEnabled: false, metricsInstallId: "" },
        });
        fakeWindow.dispatchEvent({ type: "packetsnitch:settings-updated", detail: {} });

        expect(fakeDocument.__overlay.hidden).toBe(false);
    });

    test("defers until settings snapshot is pushed, then stays hidden when already answered", () => {
        metrics.setSettingsSnapshot(null);
        const shown = consentOverlay.maybeShowConsentOverlay({
            documentRef: fakeDocument,
            metrics,
        });
        expect(shown).toBe(false);
        expect(fakeDocument.__overlay.hidden).toBe(true);

        // Persisted settings arrive saying the user already opted in
        // on a previous run. The deferred re-check must respect that.
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: true, metricsEnabled: true, metricsInstallId: "abc" },
        });
        fakeWindow.dispatchEvent({ type: "packetsnitch:settings-updated", detail: {} });

        expect(fakeDocument.__overlay.hidden).toBe(true);
    });
});