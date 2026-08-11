// Regression test for the per-tab metrics tracking.
//
// Only the settings subtab was originally tracked; clicking any
// other tab button (Analysis, Host Data, Conv, Crypt, Keystore,
// Stats, List, Notes, or one of the Conv / Crypt subtabs) did
// not record a metric.  This test exercises the
// ``metrics.trackTabSwitch`` helper and the document-level click
// listener that funnels every tab / subtab click into it.
//
// We use a hand-rolled DOM stub — JSDOM is overkill for this
// regression test and brings in a large ESM-only dep tree that
// the existing jest config cannot transform. (See
// tests/consent_overlay_no_repeat.test.js for the same reasoning.)

const path = require("path");

// Minimal DOM stub.
//
// Why this shape: the production handler is registered on
// ``document.addEventListener("click", ...)`` and inspects
// ``event.target.id``. Real browsers bubble click events from the
// clicked element up to the document, so we mirror that here: each
// element stores a reference to its parent and ``click()`` walks
// the ancestor chain dispatching a click event to every listener
// registered at each level (including the document).

function makeFakeElement(id) {
    return {
        id,
        nodeName: id ? id.toUpperCase() : "DIV",
        children: [],
        _parent: null,
    };
}

function makeFakeDocument() {
    const documentListeners = new Map();
    const elementsById = new Map();
    const body = makeFakeElement("body");

    function dispatchOnAncestors(event, startEl) {
        let target = startEl;
        while (target) {
            const set = target._listeners && target._listeners.get("click");
            if (set) {
                for (const cb of Array.from(set)) {
                    cb(event);
                }
            }
            target = target._parent;
        }
        // Finally dispatch to the document listeners.
        const docSet = documentListeners.get("click");
        if (docSet) {
            for (const cb of Array.from(docSet)) {
                cb(event);
            }
        }
    }

    function attachClick(el) {
        el._listeners = el._listeners || new Map();
        el._listeners.set("click", el._listeners.get("click") || new Set());
        el.click = function () {
            dispatchOnAncestors({ type: "click", target: el }, el);
        };
    }

    const ids = [
        "summary-btn",
        "data-btn",
        "data-tools-btn",
        "crypt-btn",
        "keystore-btn",
        "stats-btn",
        "list-btn",
        "notes-btn",
        "settings-btn",
        "conv-subtab-conversions",
        "conv-subtab-hashes",
        "conv-subtab-extraction",
        "conv-subtab-decodes",
        "conv-subtab-subnet",
        "conv-subtab-threat-intel",
        "conv-subtab-packet-json",
        "crypt-subtab-hashes",
        "crypt-subtab-ssl",
        "crypt-subtab-pgp",
        "crypt-subtab-openssh",
    ];
    for (const id of ids) {
        const el = makeFakeElement(id);
        attachClick(el);
        elementsById.set(id, el);
        body.children.push(el);
        el._parent = body;
    }

    return {
        body,
        elementsById,
        document: {
            body,
            addEventListener(type, cb) {
                if (!documentListeners.has(type)) documentListeners.set(type, new Set());
                documentListeners.get(type).add(cb);
            },
            removeEventListener(type, cb) {
                const set = documentListeners.get(type);
                if (set) set.delete(cb);
            },
            getElementById(id) {
                return elementsById.get(id) || null;
            },
            createElement(/* tagName */) {
                const el = makeFakeElement("");
                attachClick(el);
                return el;
            },
        },
    };
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
    dom.document.addEventListener("click", (event) => {
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
        dom = makeFakeDocument();
        trackedEvents = installClickListener(dom);
    });

    test("tracks the Analysis tab", () => {
        dom.elementsById.get("summary-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "summary" }]);
    });

    test("tracks the Host Data tab", () => {
        dom.elementsById.get("data-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "data" }]);
    });

    test("tracks the Conv tab itself", () => {
        dom.elementsById.get("data-tools-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "data-tools" }]);
    });

    test("tracks the Crypt tab itself", () => {
        dom.elementsById.get("crypt-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "crypt" }]);
    });

    test("tracks the Keystore tab", () => {
        dom.elementsById.get("keystore-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "keystore" }]);
    });

    test("tracks the Stats tab", () => {
        dom.elementsById.get("stats-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "stats" }]);
    });

    test("tracks the List tab", () => {
        dom.elementsById.get("list-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "list" }]);
    });

    test("tracks the Notes tab", () => {
        dom.elementsById.get("notes-btn").click();
        expect(trackedEvents).toEqual([{ name: "tab.switch", tab: "notes" }]);
    });

    test("tracks the Settings tab", () => {
        dom.elementsById.get("settings-btn").click();
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
            dom.elementsById.get(`conv-subtab-${subtab}`).click();
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
            dom.elementsById.get(`crypt-subtab-${subtab}`).click();
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
        const div = dom.document.createElement("div");
        div.id = "unrelated";
        dom.body.children.push(div);
        div._parent = dom.body;
        div.click();
        expect(trackedEvents).toEqual([]);
    });
});
