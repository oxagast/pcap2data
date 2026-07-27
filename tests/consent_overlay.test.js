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

const path = require("path");
const { JSDOM } = require("jsdom");
const fs = require("fs");

function loadOverlayCss() {
    const css = fs.readFileSync(path.resolve("src/assets/css/style.css"), "utf-8");
    // Slice out the metrics-consent-overlay block.
    const start = css.indexOf("/* First-run metrics consent overlay.");
    if (start === -1) return "";
    // Find the end of the metrics-consent block (next blank line
    // followed by a non-metric rule). A coarse cut is fine – the
    // test only computes styles on the overlay, so extra rules
    // cannot mask our intent.
    const end = css.indexOf("\n", css.indexOf(".metrics-consent-btn-secondary:hover", start));
    return end === -1 ? css.slice(start) : css.slice(start, end + 200);
}

function bootDom() {
    return new JSDOM(
        `<!doctype html><html><head>
      <style>${loadOverlayCss()}</style>
    </head><body>
      <div id="install-screen" style="display: none;">
        <div id="install-version"></div>
        <ul id="install-file-list"></ul>
        <div id="install-ollama-status"></div>
        <button id="install-continue-btn">Continue</button>
      </div>
      <div id="metrics-consent-overlay" hidden>
        <div id="metrics-consent-card">
          <div id="metrics-consent-title">Help improve PacketSnitch?</div>
          <div id="metrics-consent-body"></div>
          <div id="metrics-consent-actions">
            <button id="metrics-consent-decline" class="metrics-consent-btn metrics-consent-btn-secondary">No</button>
            <button id="metrics-consent-accept" class="metrics-consent-btn metrics-consent-btn-primary">Yes</button>
          </div>
        </div>
      </div>
    </body></html>`,
        { pretendToBeVisual: true, url: "http://localhost/" },
    );
}

describe("metrics consent overlay", () => {
    let dom;
    let fakeWindow;
    let updateCalls;
    let lastSavedSettings;

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
        dom = bootDom();
        fakeWindow = {
            settingsapi: {
                update: jest.fn((patch) => {
                    updateCalls.push(patch);
                    const saved = makeSavedSettings(patch);
                    lastSavedSettings = saved;
                    return Promise.resolve(saved);
                }),
                get: jest.fn().mockResolvedValue({ privacy: {} }),
            },
            // Match the production preload bridge: CustomEvent exists
            // on the real window, but in JSDOM we expose it explicitly
            // so the metrics module can construct events.
            CustomEvent: dom.window.CustomEvent,
        };
        // Forward dispatchEvent/addEventListener onto the JSDOM
        // window so listeners attached via the renderer's
        // ``window.addEventListener`` actually see the event.
        fakeWindow.dispatchEvent = (event) => dom.window.dispatchEvent(event);
        fakeWindow.addEventListener = (...args) => dom.window.addEventListener(...args);
        global.window = fakeWindow;
        global.document = dom.window.document;
    });

    afterEach(() => {
        delete global.window;
        delete global.document;
    });

    test("the [hidden] attribute actually hides the overlay visually", () => {
        const overlay = dom.window.document.getElementById("metrics-consent-overlay");
        overlay.hidden = true;
        expect(dom.window.getComputedStyle(overlay).display).toBe("none");
    });

    test("removing [hidden] paints the overlay as a flex container", () => {
        const overlay = dom.window.document.getElementById("metrics-consent-overlay");
        overlay.hidden = false;
        expect(dom.window.getComputedStyle(overlay).display).toBe("flex");
    });

    test("clicking Yes records consent, hides the overlay, and visually un-paints it", async () => {
        const metrics = require(path.resolve("src/metrics"));
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: false, metricsEnabled: false, metricsInstallId: "" },
        });
        fakeWindow.__PACKETSNITCH_METRICS__ = metrics;

        const installScreen = require(path.resolve("src/ui/panels/install-screen"));
        installScreen.initializeInstallScreen({
            installapi: null,
            documentRef: dom.window.document,
            metrics,
        });

        const overlay = dom.window.document.getElementById("metrics-consent-overlay");
        overlay.hidden = false;
        expect(dom.window.getComputedStyle(overlay).display).toBe("flex");

        dom.window.document.getElementById("metrics-consent-accept").click();
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
        expect(dom.window.getComputedStyle(overlay).display).toBe("none");
    });

    test("clicking No records consent, hides the overlay, and visually un-paints it", async () => {
        const metrics = require(path.resolve("src/metrics"));
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: false, metricsEnabled: false, metricsInstallId: "" },
        });
        fakeWindow.__PACKETSNITCH_METRICS__ = metrics;

        const installScreen = require(path.resolve("src/ui/panels/install-screen"));
        installScreen.initializeInstallScreen({
            installapi: null,
            documentRef: dom.window.document,
            metrics,
        });

        const overlay = dom.window.document.getElementById("metrics-consent-overlay");
        overlay.hidden = false;
        expect(dom.window.getComputedStyle(overlay).display).toBe("flex");

        dom.window.document.getElementById("metrics-consent-decline").click();
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));

        expect(updateCalls.length).toBeGreaterThan(0);
        const lastCall = updateCalls[updateCalls.length - 1];
        expect(lastCall.privacy.metricsConsentAsked).toBe(true);
        expect(lastCall.privacy.metricsEnabled).toBe(false);

        expect(overlay.hidden).toBe(true);
        expect(dom.window.getComputedStyle(overlay).display).toBe("none");
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
        dom.window.addEventListener("packetsnitch:settings-updated", (event) => {
            setCurrentSettingsMock(event.detail);
            syncSettingsFormFromStateMock();
        });

        const installScreen = require(path.resolve("src/ui/panels/install-screen"));
        installScreen.initializeInstallScreen({
            installapi: null,
            documentRef: dom.window.document,
            metrics,
        });

        const overlay = dom.window.document.getElementById("metrics-consent-overlay");
        overlay.hidden = false;

        dom.window.document.getElementById("metrics-consent-accept").click();
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));

        expect(setCurrentSettingsMock).toHaveBeenCalledTimes(1);
        const passedSettings = setCurrentSettingsMock.mock.calls[0][0];
        expect(passedSettings.privacy.metricsEnabled).toBe(true);
        expect(passedSettings.privacy.metricsConsentAsked).toBe(true);
        expect(passedSettings.privacy.metricsInstallId.length).toBeGreaterThan(0);
        expect(syncSettingsFormFromStateMock).toHaveBeenCalledTimes(1);
    });

    test("clicking No broadcasts the new settings with metricsEnabled=false", async () => {
        const metrics = require(path.resolve("src/metrics"));
        metrics.setSettingsSnapshot({
            privacy: { metricsConsentAsked: false, metricsEnabled: false, metricsInstallId: "" },
        });
        fakeWindow.__PACKETSNITCH_METRICS__ = metrics;

        const setCurrentSettingsMock = jest.fn();
        const syncSettingsFormFromStateMock = jest.fn();
        dom.window.addEventListener("packetsnitch:settings-updated", (event) => {
            setCurrentSettingsMock(event.detail);
            syncSettingsFormFromStateMock();
        });

        const installScreen = require(path.resolve("src/ui/panels/install-screen"));
        installScreen.initializeInstallScreen({
            installapi: null,
            documentRef: dom.window.document,
            metrics,
        });

        const overlay = dom.window.document.getElementById("metrics-consent-overlay");
        overlay.hidden = false;

        dom.window.document.getElementById("metrics-consent-decline").click();
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));

        expect(setCurrentSettingsMock).toHaveBeenCalledTimes(1);
        const passedSettings = setCurrentSettingsMock.mock.calls[0][0];
        expect(passedSettings.privacy.metricsEnabled).toBe(false);
        expect(passedSettings.privacy.metricsConsentAsked).toBe(true);
        expect(syncSettingsFormFromStateMock).toHaveBeenCalledTimes(1);
    });
});
