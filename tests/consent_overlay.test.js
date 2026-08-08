// Regression test for the consent overlay wiring.
//
// The original implementation of the first-run metrics consent
// overlay had two related bugs:
//
//   1. A CSS specificity bug: `#metrics-consent-overlay` was set to
//      `display: flex`, and the user-agent default `[hidden] {
//      display: none }` was overridden, so toggling the ``hidden``
//      attribute had no visual effect.  The user clicked the
//      buttons, the click handlers fired, but the overlay never
//      went away.
//   2. A state-sync bug: the consent overlay's Yes button updated
//      settings.json on disk but the renderer's in-memory
//      ``appSettings`` and the privacy tab form were not refreshed,
//      so opening Settings → Privacy afterwards showed the toggle
//      still unchecked.
//
// These tests exercise both halves of the fix:
//   1. The CSS layer: ``hidden`` actually hides the overlay.
//   2. The wiring layer: clicking Yes/No records consent AND the
//      overlay visually goes away.
//   3. The state-sync layer: a ``packetsnitch:settings-updated`` event
//      is dispatched on the renderer with the new settings, so the
//      privacy tab can re-sync.
//
// We use a hand-rolled DOM stub — JSDOM is overkill for these
// regression tests and brings in a large ESM-only dep tree that
// the existing jest config cannot transform. (See
// tests/consent_overlay_no_repeat.test.js for the same reasoning.)
//
// The CSS "computed style" checks are replaced with structural
// assertions on the CSS source: we verify that the cascade-fixing
// rule ``#metrics-consent-overlay[hidden] { display: none }`` is
// present in ``src/assets/css/style.css`` alongside the base rule
// ``#metrics-consent-overlay { display: flex }``. Removing either
// rule reproduces one of the original bugs, so the presence check
// is a faithful regression guard.

const path = require("path");
const fs = require("fs");

// ---------------------------------------------------------------------------
// Tiny CSS cascade simulator.
//
// Scope: enough to evaluate the two rules that matter to the consent
// overlay regression — ``#metrics-consent-overlay { display: ... }``
// and ``#metrics-consent-overlay[hidden] { display: ... }``. Specificity
// is computed as ``(#ids, #attrs + #classes, #elements)`` for the simple
// selectors we encounter; the cascade falls back to source order when
// specificity is tied. We deliberately do NOT try to be a general CSS
// engine — the test asserts on exactly two rules, and any other rule
// (e.g. from the ``body`` selector) does not affect the overlay's
// ``display``.
//
// Returns the computed ``display`` for a synthetic element with the
// given ``hidden`` attribute state.
// ---------------------------------------------------------------------------

function parseSimpleSelectorSpecificity(selector) {
    // Trim pseudo-classes / pseudo-elements we don't care about and
    // split on the structural pieces: ``#id``, ``[attr]``, ``.class``,
    // ``tag``.
    const cleaned = selector.replace(/::?[a-zA-Z-]+(\([^)]*\))?/g, "");
    const ids = (cleaned.match(/#/g) || []).length;
    const attrs = (cleaned.match(/\[/g) || []).length;
    const classes = (cleaned.match(/\./g) || []).length;
    const tags = (cleaned.match(/[a-zA-Z]/g) || []).length;
    // ``[hidden]`` counts toward attrs/classes; we treat each as one
    // class-equivalent unit per the W3C selector specificity rules.
    return [ids, attrs + classes, tags];
}

function compareSpecificity(a, b) {
    for (let i = 0; i < a.length; i += 1) {
        if (a[i] !== b[i]) return a[i] - b[i];
    }
    return 0;
}

function selectorMatches(selector, elementState) {
    // Supports ``#id`` and ``#id[attr]`` only — exactly what the consent
    // overlay rules use.
    const idMatch = selector.match(/^#([a-zA-Z0-9_-]+)/);
    if (!idMatch) return false;
    if (idMatch[1] !== elementState.id) return false;
    const attrMatches = selector.match(/\[([a-zA-Z0-9_-]+)\]/g) || [];
    for (const attrSel of attrMatches) {
        const m = attrSel.match(/\[([a-zA-Z0-9_-]+)\]/);
        if (!m) continue;
        const attrName = m[1];
        if (!elementState.attrs[attrName]) return false;
    }
    return true;
}

function extractOverlayRules(cssText) {
    // Naive but adequate: pull every top-level rule whose selector
    // mentions ``#metrics-consent-overlay``. We rely on the fact that
    // the overlay's two rules are written on their own lines and do
    // not span across comment blocks. Strip block comments first so
    // that the long explanatory header above the first rule doesn't
    // leak into the captured selector text.
    const cleaned = cssText.replace(/\/\*[\s\S]*?\*\//g, "");
    const rules = [];
    const ruleRegex = /([^{}]+)\{([^{}]+)\}/g;
    let match;
    while ((match = ruleRegex.exec(cleaned)) !== null) {
        const selectorText = match[1].trim();
        if (!selectorText.includes("#metrics-consent-overlay")) continue;
        const body = match[2];
        const displayMatch = body.match(/display\s*:\s*([^;]+);/);
        if (!displayMatch) continue;
        const displayValue = displayMatch[1].trim();
        // Each selector in the comma list may match independently.
        for (const rawSelector of selectorText.split(",")) {
            const selector = rawSelector.trim();
            rules.push({ selector, display: displayValue });
        }
    }
    return rules;
}

function computeOverlayDisplay(cssText, elementState) {
    const rules = extractOverlayRules(cssText);
    let best = null;
    for (const rule of rules) {
        if (!selectorMatches(rule.selector, elementState)) continue;
        const specificity = parseSimpleSelectorSpecificity(rule.selector);
        if (
            !best ||
            compareSpecificity(specificity, best.specificity) > 0
        ) {
            best = { specificity, display: rule.display };
        }
    }
    // The user-agent default: ``[hidden] { display: none }`` applies
    // when the element has the ``hidden`` attribute and no author
    // rule wins.
    if (!best && elementState.attrs.hidden) return "none";
    return best ? best.display : "";
}

const OVERLAY_CSS_PATH = path.resolve("src/assets/css/style.css");

function loadOverlayCssText() {
    return fs.readFileSync(OVERLAY_CSS_PATH, "utf-8");
}

// ---------------------------------------------------------------------------
// Hand-rolled DOM stub.
//
// Mirrors the subset of the DOM used by
// ``src/ui/panels/consent-overlay.js`` and the test assertions:
// ``getElementById``, ``hidden`` attribute on elements,
// ``addEventListener`` for ``click`` events on buttons and
// ``packetsnitch:settings-updated`` events on the window, and the
// ``window.dispatchEvent`` / ``window.CustomEvent`` machinery the
// renderer uses.
// ---------------------------------------------------------------------------

function makeFakeWindow() {
    const listeners = new Map();
    return {
        __listeners: listeners,
        addEventListener(type, callback) {
            if (!listeners.has(type)) listeners.set(type, new Set());
            listeners.get(type).add(callback);
        },
        removeEventListener(type, callback) {
            const set = listeners.get(type);
            if (set) set.delete(callback);
        },
        dispatchEvent(event) {
            const set = listeners.get(event.type);
            if (!set) return;
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

function makeFakeElement(id) {
    const listeners = new Map();
    return {
        id,
        hidden: true,
        nodeName: "DIV",
        _listeners: listeners,
        addEventListener(type, cb) {
            if (!listeners.has(type)) listeners.set(type, new Set());
            listeners.get(type).add(cb);
        },
        removeEventListener(type, cb) {
            const set = listeners.get(type);
            if (set) set.delete(cb);
        },
        click() {
            const set = listeners.get("click");
            if (!set) return;
            const event = { type: "click", target: this };
            for (const cb of Array.from(set)) {
                try {
                    cb(event);
                } catch (_error) {
                    // ignore
                }
            }
        },
    };
}

function makeFakeDocument(elementsById) {
    return {
        getElementById(id) {
            return elementsById[id] || null;
        },
    };
}

describe("metrics consent overlay", () => {
    let fakeWindow;
    let updateCalls;
    let lastSavedSettings;
    let fakeDocument;
    let elementsById;

    function makeSavedSettings(patch) {
        // Mimic the main process's deep-merge behaviour.  Anything
        // not in the patch falls back to defaults.
        return {
            general: {},
            llm: {},
            plugins: {},
            privacy: {
                metricsConsentAsked: false,
                metricsEnabled: false,
                metricsEndpointUrl: "http://47.37.209.29:8088/mhook",
                metricsFlushIntervalSeconds: 60,
                metricsMaxQueueSize: 500,
                metricsInstallId: "",
                ...(patch && patch.privacy),
            },
        };
    }

    beforeEach(() => {
        jest.resetModules();
        updateCalls = [];
        lastSavedSettings = null;
        elementsById = {
            "metrics-consent-overlay": makeFakeElement("metrics-consent-overlay"),
            "metrics-consent-accept": makeFakeElement("metrics-consent-accept"),
            "metrics-consent-decline": makeFakeElement("metrics-consent-decline"),
        };
        fakeDocument = makeFakeDocument(elementsById);
        fakeWindow = makeFakeWindow();
        fakeWindow.settingsapi = {
            update: jest.fn((patch) => {
                updateCalls.push(patch);
                const saved = makeSavedSettings(patch);
                lastSavedSettings = saved;
                return Promise.resolve(saved);
            }),
            get: jest.fn().mockResolvedValue({ privacy: {} }),
        };
        global.window = fakeWindow;
        global.document = fakeDocument;
    });

    afterEach(() => {
        delete global.window;
        delete global.document;
    });

    test("the [hidden] attribute actually hides the overlay visually", () => {
        // Structural CSS cascade check (replaces JSDOM
        // getComputedStyle): with ``hidden`` set, the more-specific
        // ``#metrics-consent-overlay[hidden]`` rule must win and
        // produce ``display: none``.
        const cssText = loadOverlayCssText();
        expect(
            computeOverlayDisplay(cssText, {
                id: "metrics-consent-overlay",
                attrs: { hidden: true },
            }),
        ).toBe("none");
    });

    test("removing [hidden] paints the overlay as a flex container", () => {
        // Without the ``hidden`` attribute, the cascade falls back to
        // the base rule ``#metrics-consent-overlay { display: flex }``.
        const cssText = loadOverlayCssText();
        expect(
            computeOverlayDisplay(cssText, {
                id: "metrics-consent-overlay",
                attrs: {},
            }),
        ).toBe("flex");
    });

    test("clicking Yes records consent, hides the overlay, and visually un-paints it", async () => {
        const metrics = require(path.resolve("src/metrics"));
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: false, metricsEnabled: false, metricsInstallId: "" },
        });
        fakeWindow.__PACKETSNITCH_METRICS__ = metrics;

        const consentOverlay = require(path.resolve("src/ui/panels/consent-overlay"));
        consentOverlay.initializeConsentOverlay({
            installapi: null,
            documentRef: fakeDocument,
            metrics,
        });

        const overlay = elementsById["metrics-consent-overlay"];
        overlay.hidden = false;
        const cssText = loadOverlayCssText();
        expect(
            computeOverlayDisplay(cssText, {
                id: "metrics-consent-overlay",
                attrs: {},
            }),
        ).toBe("flex");

        elementsById["metrics-consent-accept"].click();
        // Let the broadcast promise chain settle.
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));

        // The persisted snapshot now reflects the user's opt-in.
        expect(updateCalls.length).toBeGreaterThan(0);
        const lastCall = updateCalls[updateCalls.length - 1];
        expect(lastCall.privacy.metricsConsentAsked).toBe(true);
        expect(lastCall.privacy.metricsEnabled).toBe(true);
        expect(lastCall.privacy.metricsInstallId.length).toBeGreaterThan(0);

        // The overlay must be both flagged hidden AND visually gone.
        expect(overlay.hidden).toBe(true);
        expect(
            computeOverlayDisplay(cssText, {
                id: "metrics-consent-overlay",
                attrs: { hidden: true },
            }),
        ).toBe("none");
    });

    test("clicking No records consent, hides the overlay, and visually un-paints it", async () => {
        const metrics = require(path.resolve("src/metrics"));
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: false, metricsEnabled: false, metricsInstallId: "" },
        });
        fakeWindow.__PACKETSNITCH_METRICS__ = metrics;

        const consentOverlay = require(path.resolve("src/ui/panels/consent-overlay"));
        consentOverlay.initializeConsentOverlay({
            installapi: null,
            documentRef: fakeDocument,
            metrics,
        });

        const overlay = elementsById["metrics-consent-overlay"];
        overlay.hidden = false;
        const cssText = loadOverlayCssText();
        expect(
            computeOverlayDisplay(cssText, {
                id: "metrics-consent-overlay",
                attrs: {},
            }),
        ).toBe("flex");

        elementsById["metrics-consent-decline"].click();
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));

        expect(updateCalls.length).toBeGreaterThan(0);
        const lastCall = updateCalls[updateCalls.length - 1];
        expect(lastCall.privacy.metricsConsentAsked).toBe(true);
        expect(lastCall.privacy.metricsEnabled).toBe(false);

        expect(overlay.hidden).toBe(true);
        expect(
            computeOverlayDisplay(cssText, {
                id: "metrics-consent-overlay",
                attrs: { hidden: true },
            }),
        ).toBe("none");
    });

    test("clicking Yes broadcasts the new settings so the privacy tab stays in sync", async () => {
        const metrics = require(path.resolve("src/metrics"));
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: false, metricsEnabled: false, metricsInstallId: "" },
        });
        fakeWindow.__PACKETSNITCH_METRICS__ = metrics;

        // Wire a listener that mirrors what main-frontend.js does: the
        // ``packetsnitch:settings-updated`` event tells the renderer
        // to refresh ``appSettings`` and the visible form. Without
        // this broadcast the privacy tab checkbox would stay
        // unchecked after the user clicked Yes on the overlay.
        const setCurrentSettingsMock = jest.fn();
        const syncSettingsFormFromStateMock = jest.fn();
        fakeWindow.addEventListener("packetsnitch:settings-updated", (event) => {
            setCurrentSettingsMock(event.detail);
            syncSettingsFormFromStateMock();
        });

        const consentOverlay = require(path.resolve("src/ui/panels/consent-overlay"));
        consentOverlay.initializeConsentOverlay({
            installapi: null,
            documentRef: fakeDocument,
            metrics,
        });

        const overlay = elementsById["metrics-consent-overlay"];
        overlay.hidden = false;

        elementsById["metrics-consent-accept"].click();
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));

        // ``setSettingsSnapshot`` may have fired an initial broadcast
        // before this listener was registered — the broadcast is
        // delivered on a microtask, so a listener added synchronously
        // after the snapshot push can still see it. The crucial check
        // is that the broadcast triggered by the user's click carries
        // the new privacy settings, so the privacy tab can re-sync.
        expect(setCurrentSettingsMock.mock.calls.length).toBeGreaterThan(0);
        const passedSettings =
            setCurrentSettingsMock.mock.calls[
            setCurrentSettingsMock.mock.calls.length - 1
            ][0];
        expect(passedSettings.privacy.metricsEnabled).toBe(true);
        expect(passedSettings.privacy.metricsConsentAsked).toBe(true);
        expect(passedSettings.privacy.metricsInstallId.length).toBeGreaterThan(0);
        // The renderer should re-sync the privacy form exactly once per
        // broadcast that the listener received — count of mock calls
        // matches the count of broadcasts the listener saw.
        expect(syncSettingsFormFromStateMock.mock.calls.length).toBe(
            setCurrentSettingsMock.mock.calls.length,
        );
    });

    test("clicking No broadcasts the new settings with metricsEnabled=false", async () => {
        const metrics = require(path.resolve("src/metrics"));
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: false, metricsEnabled: false, metricsInstallId: "" },
        });
        fakeWindow.__PACKETSNITCH_METRICS__ = metrics;

        const setCurrentSettingsMock = jest.fn();
        const syncSettingsFormFromStateMock = jest.fn();
        fakeWindow.addEventListener("packetsnitch:settings-updated", (event) => {
            setCurrentSettingsMock(event.detail);
            syncSettingsFormFromStateMock();
        });

        const consentOverlay = require(path.resolve("src/ui/panels/consent-overlay"));
        consentOverlay.initializeConsentOverlay({
            installapi: null,
            documentRef: fakeDocument,
            metrics,
        });

        const overlay = elementsById["metrics-consent-overlay"];
        overlay.hidden = false;

        elementsById["metrics-consent-decline"].click();
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));

        // See the matching "clicking Yes" test for the rationale
        // around ``mock.calls.length`` versus ``toHaveBeenCalledTimes(1)``.
        expect(setCurrentSettingsMock.mock.calls.length).toBeGreaterThan(0);
        const passedSettings =
            setCurrentSettingsMock.mock.calls[
            setCurrentSettingsMock.mock.calls.length - 1
            ][0];
        expect(passedSettings.privacy.metricsEnabled).toBe(false);
        expect(passedSettings.privacy.metricsConsentAsked).toBe(true);
        expect(syncSettingsFormFromStateMock.mock.calls.length).toBe(
            setCurrentSettingsMock.mock.calls.length,
        );
    });
});
