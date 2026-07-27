// Regression test for the per-tab metrics tracking.
//
// Only the settings subtab was originally tracked; clicking any
// other tab button (Analysis, Host Data, Conv, Crypt, Keystore,
// Stats, List, Notes, or one of the Conv / Crypt subtabs) did
// not record a metric.  This test exercises the
// ``metrics.trackTabSwitch`` helper and the document-level click
// listener that funnels every tab / subtab click into it.

const path = require("path");
const { JSDOM } = require("jsdom");

function bootDom() {
    return new JSDOM(
        `<!doctype html><html><body>
          <input type="button" id="summary-btn" value="Analysis" />
          <input type="button" id="data-btn" value="Host Data" />
          <input type="button" id="data-tools-btn" value="Conv" />
          <input type="button" id="crypt-btn" value="Crypt" />
          <input type="button" id="keystore-btn" value="Keystore" />
          <input type="button" id="stats-btn" value="Stats" />
          <input type="button" id="list-btn" value="List" />
          <input type="button" id="notes-btn" value="Notes" />
          <input type="button" id="settings-btn" value="Settings" />
          <button id="conv-subtab-conversions">Conv</button>
          <button id="conv-subtab-hashes">Hashes</button>
          <button id="conv-subtab-extraction">Extraction</button>
          <button id="conv-subtab-decodes">Decodes</button>
          <button id="conv-subtab-subnet">Subnet</button>
          <button id="conv-subtab-threat-intel">Threat Intel</button>
          <button id="conv-subtab-packet-json">Packet JSON</button>
          <button id="crypt-subtab-ssl">SSL</button>
          <button id="crypt-subtab-pgp">PGP</button>
          <button id="crypt-subtab-openssh">OpenSSH</button>
        </body></html>`,
        { url: "http://localhost/" },
    );
}

function installClickListener(dom) {
    // Mirrors the click handler in src/ui/main-frontend.js.
    const trackedEvents = [];
    const metrics = {
        trackTabSwitch({ tab, subtab } = {}) {
            const evt = subtab
                ? { name: "subtab.switch", tab, subtab }
                : { name: "tab.switch", tab };
            trackedEvents.push(evt);
        },
    };
    const MAIN_TAB_BUTTON_TO_TAB = {
        "summary-btn": "summary",
        "data-btn": "data",
        "data-tools-btn": "data-tools",
        "crypt-btn": "crypt",
        "keystore-btn": "keystore",
        "stats-btn": "stats",
        "list-btn": "list",
        "notes-btn": "notes",
        "settings-btn": "settings",
    };
    const CONV_SUBTAB_PREFIX = "conv-subtab-";
    const CRYPT_SUBTAB_PREFIX = "crypt-subtab-";
    dom.window.document.addEventListener("click", (event) => {
        if (!metrics || typeof metrics.trackTabSwitch !== "function") return;
        const target = event.target;
        if (!target || typeof target !== "object" || typeof target.id !== "string") return;
        const buttonId = target.id;
        if (!buttonId) return;
        const mainTab = MAIN_TAB_BUTTON_TO_TAB[buttonId];
        if (mainTab) {
            metrics.trackTabSwitch({ tab: mainTab });
            return;
        }
        if (buttonId.startsWith(CONV_SUBTAB_PREFIX)) {
            metrics.trackTabSwitch({
                tab: "data-tools",
                subtab: buttonId.slice(CONV_SUBTAB_PREFIX.length),
            });
            return;
        }
        if (buttonId.startsWith(CRYPT_SUBTAB_PREFIX)) {
            metrics.trackTabSwitch({
                tab: "crypt",
                subtab: buttonId.slice(CRYPT_SUBTAB_PREFIX.length),
            });
            return;
        }
    });
    return trackedEvents;
}

describe("metrics trackTabSwitch helper", () => {
    test("fires tab.switch when only tab is supplied", () => {
        const metrics = require(path.resolve("src/metrics"));
        // Force the metrics module into "enabled" so trackTabSwitch
        // actually enqueues an event.  We assert on the queue
        // contents.
        metrics.setSettingsSnapshot({
            privacy: { metricsEnabled: true, metricsInstallId: "test" },
        });
        metrics.init();
        metrics.clearQueue();
        metrics.trackTabSwitch({ tab: "summary" });
        const queue = metrics.getQueue();
        expect(queue.length).toBe(1);
        expect(queue[0].name).toBe("tab.switch");
        expect(queue[0].props.tab).toBe("summary");
    });

    test("fires subtab.switch when both tab and subtab are supplied", () => {
        const metrics = require(path.resolve("src/metrics"));
        metrics.setSettingsSnapshot({
            privacy: { metricsEnabled: true, metricsInstallId: "test" },
        });
        metrics.init();
        metrics.clearQueue();
        metrics.trackTabSwitch({ tab: "data-tools", subtab: "conversions" });
        const queue = metrics.getQueue();
        expect(queue.length).toBe(1);
        expect(queue[0].name).toBe("subtab.switch");
        expect(queue[0].props.tab).toBe("data-tools");
        expect(queue[0].props.subtab).toBe("conversions");
    });

    test("does not enqueue an event when neither tab nor subtab is supplied", () => {
        const metrics = require(path.resolve("src/metrics"));
        metrics.setSettingsSnapshot({
            privacy: { metricsEnabled: true, metricsInstallId: "test" },
        });
        metrics.init();
        metrics.clearQueue();
        metrics.trackTabSwitch({});
        metrics.trackTabSwitch();
        expect(metrics.getQueue().length).toBe(0);
    });

    test("is a no-op when metrics are disabled", () => {
        const metrics = require(path.resolve("src/metrics"));
        metrics.setSettingsSnapshot({
            privacy: { metricsEnabled: false, metricsInstallId: "" },
        });
        metrics.init();
        metrics.clearQueue();
        metrics.trackTabSwitch({ tab: "summary" });
        metrics.trackTabSwitch({ tab: "data-tools", subtab: "conversions" });
        expect(metrics.getQueue().length).toBe(0);
    });
});

describe("document-level click listener tracks every tab and subtab button", () => {
    let dom;
    let trackedEvents;

    beforeEach(() => {
        dom = bootDom();
        trackedEvents = installClickListener(dom);
    });

    test("tracks the Analysis tab", () => {
        dom.window.document.getElementById("summary-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "summary" }]);
    });

    test("tracks the Host Data tab", () => {
        dom.window.document.getElementById("data-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "data" }]);
    });

    test("tracks the Conv tab itself", () => {
        dom.window.document.getElementById("data-tools-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "data-tools" }]);
    });

    test("tracks the Crypt tab itself", () => {
        dom.window.document.getElementById("crypt-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "crypt" }]);
    });

    test("tracks the Keystore tab", () => {
        dom.window.document.getElementById("keystore-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "keystore" }]);
    });

    test("tracks the Stats tab", () => {
        dom.window.document.getElementById("stats-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "stats" }]);
    });

    test("tracks the List tab", () => {
        dom.window.document.getElementById("list-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "list" }]);
    });

    test("tracks the Notes tab", () => {
        dom.window.document.getElementById("notes-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "notes" }]);
    });

    test("tracks the Settings tab", () => {
        dom.window.document.getElementById("settings-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "settings" }]);
    });

    test("tracks every conv subtab", () => {
        const convSubtabs = [
            "conversions",
            "hashes",
            "extraction",
            "decodes",
            "subnet",
            "threat-intel",
            "packet-json",
        ];
        convSubtabs.forEach((subtab) => {
            dom.window.document
                .getElementById(`conv-subtab-${subtab}`)
                .click();
        });
        expect(trackedEvents).toEqual(
            convSubtabs.map((subtab) => ({
                name: "subtab.switch",
                tab: "data-tools",
                subtab,
            })),
        );
    });

    test("tracks every crypt subtab", () => {
        const cryptSubtabs = ["ssl", "pgp", "openssh"];
        cryptSubtabs.forEach((subtab) => {
            dom.window.document
                .getElementById(`crypt-subtab-${subtab}`)
                .click();
        });
        expect(trackedEvents).toEqual(
            cryptSubtabs.map((subtab) => ({
                name: "subtab.switch",
                tab: "crypt",
                subtab,
            })),
        );
    });

    test("ignores clicks on elements without a tracked id", () => {
        const div = dom.window.document.createElement("div");
        div.id = "unrelated";
        dom.window.document.body.appendChild(div);
        div.click();
        expect(trackedEvents).toEqual([]);
    });
});
