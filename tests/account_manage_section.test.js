// Regression test for the Settings ⇄ Themes account-manage affordance
// (Manage subscription + Email me a sign-in link).
//
// Hand-rolled DOM stub — JSDOM is overkill for these small UI
// interactions and brings in a large ESM-only dep tree that the
// existing jest config cannot transform. (See
// tests/consent_overlay_no_repeat.test.js for the same reasoning.)
//
// The production code lives in src/ui/main-frontend.js inside
// ``bindThemesSubtabEvents`` / ``renderAccountManageSection``. We
// re-implement the small slice we want to exercise here so this
// test doesn't have to boot the renderer — the rest of
// main-frontend.js depends on Electron globals that aren't
// available in a plain `node` process. Keeping the surface area
// small also means a future refactor of the renderer only breaks
// this one test, not hundreds.

function makeFakeElement(id, opts = {}) {
    return {
        id,
        nodeName: id ? id.toUpperCase() : "DIV",
        hidden: Boolean(opts.hidden),
        _listeners: {},
        addEventListener(eventName, callback) {
            (this._listeners[eventName] = this._listeners[eventName] || []).push(callback);
        },
        dispatchEvent(eventName, event = {}) {
            const listeners = this._listeners[eventName] || [];
            for (const listener of listeners) {
                listener(event);
            }
        },
        click(event = {}) {
            this.dispatchEvent("click", { preventDefault() { }, ...event });
        },
    };
}

// Minimal parent document — only tracks element registrations so
// ``document.getElementById`` can find them. Real browsers bubble
// events but we don't need bubbling for these tests because every
// listener we exercise is registered directly on the element being
// clicked.
function makeFakeDocument(elements) {
    const byId = {};
    for (const element of elements) {
        if (element.id) {
            byId[element.id] = element;
        }
    }
    return {
        getElementById(id) {
            return byId[id] || null;
        },
    };
}

// Mirror of the production ``renderAccountManageSection`` and the
// two click handlers registered by ``bindThemesSubtabEvents``. Kept
// in lockstep with src/ui/main-frontend.js — if the production
// copy changes, this must too. The branch comments mirror the
// production comments so a reviewer can scan both side-by-side.
function loadSlice({ paddleCustomerId = "", email = "" } = {}) {
    const elements = [
        makeFakeElement("settings-themes-account-manage", { hidden: true }),
        makeFakeElement("settings-themes-account-manage-link"),
        makeFakeElement("settings-themes-account-magic-link", { hidden: true }),
        makeFakeElement("settings-themes-account-magic-link-btn"),
    ];
    const document = makeFakeDocument(elements);

    // Mock themeapi — the tests assert on the calls made.
    const themeapiCalls = { openPortal: [], requestMagicLink: [] };
    const themeapi = {
        openPortal: (payload) => themeapiCalls.openPortal.push(payload || {}),
        requestMagicLink: (payload) =>
            themeapiCalls.requestMagicLink.push(payload || {}),
    };

    // Mirror of getCurrentSettings from main-frontend.js. Only the
    // fields the manage-section renderer cares about.
    const getCurrentSettings = () => ({
        account: {
            paddleCustomerId,
            email,
        },
    });

    function renderAccountManageSection() {
        const row = document.getElementById("settings-themes-account-manage");
        if (!row) return;
        const settings = getCurrentSettings();
        const cid = settings?.account?.paddleCustomerId || "";
        const acctEmail = settings?.account?.email || "";
        const isPaired = Boolean(cid);
        if (!isPaired) {
            row.hidden = true;
            return;
        }
        row.hidden = false;
        const magicRow = document.getElementById(
            "settings-themes-account-magic-link",
        );
        if (magicRow) {
            magicRow.hidden = !acctEmail;
        }
    }

    const manageLink = document.getElementById("settings-themes-account-manage-link");
    if (manageLink) {
        manageLink.addEventListener("click", (event) => {
            event.preventDefault();
            const settings = getCurrentSettings();
            const emailVal = settings?.account?.email || "";
            if (themeapi && typeof themeapi.openPortal === "function") {
                themeapi.openPortal({ email: emailVal });
            }
        });
    }
    const magicLinkBtn = document.getElementById("settings-themes-account-magic-link-btn");
    if (magicLinkBtn) {
        magicLinkBtn.addEventListener("click", (event) => {
            event.preventDefault();
            const settings = getCurrentSettings();
            const emailVal = settings?.account?.email || "";
            if (!emailVal) {
                // No email in settings — the production code pops a
                // prompt and forwards the typed value. We stub the
                // prompt so the test can drive both branches.
                const typed = globalThis.__nextPromptValue;
                if (typeof typed === "string" && typed.trim()) {
                    if (themeapi && typeof themeapi.requestMagicLink === "function") {
                        themeapi.requestMagicLink({ email: typed.trim() });
                    }
                    return;
                }
                return;
            }
            if (themeapi && typeof themeapi.requestMagicLink === "function") {
                themeapi.requestMagicLink({ email: emailVal });
            }
        });
    }

    return { document, elements, renderAccountManageSection, themeapiCalls };
}

describe("renderAccountManageSection", () => {
    test("hides the row when paddleCustomerId is empty (free install)", () => {
        const { document, renderAccountManageSection } = loadSlice({
            paddleCustomerId: "",
            email: "",
        });
        renderAccountManageSection();
        const row = document.getElementById("settings-themes-account-manage");
        expect(row.hidden).toBe(true);
    });

    test("shows the row but hides the magic-link sub-row when no email set", () => {
        const { document, renderAccountManageSection } = loadSlice({
            paddleCustomerId: "ctm_pair",
            email: "",
        });
        renderAccountManageSection();
        const row = document.getElementById("settings-themes-account-manage");
        const magicRow = document.getElementById(
            "settings-themes-account-magic-link",
        );
        expect(row.hidden).toBe(false);
        expect(magicRow.hidden).toBe(true);
    });

    test("shows both rows when customer id and email are set", () => {
        const { document, renderAccountManageSection } = loadSlice({
            paddleCustomerId: "ctm_pair",
            email: "buyer@example.com",
        });
        renderAccountManageSection();
        const row = document.getElementById("settings-themes-account-manage");
        const magicRow = document.getElementById(
            "settings-themes-account-magic-link",
        );
        expect(row.hidden).toBe(false);
        expect(magicRow.hidden).toBe(false);
    });
});

describe("account-manage click handlers", () => {
    test("manage link click invokes themeapi.openPortal with the email", () => {
        const { document, themeapiCalls } = loadSlice({
            paddleCustomerId: "ctm_pair",
            email: "buyer@example.com",
        });
        document.getElementById("settings-themes-account-manage-link").click();
        expect(themeapiCalls.openPortal).toHaveLength(1);
        expect(themeapiCalls.openPortal[0]).toEqual({ email: "buyer@example.com" });
    });

    test("magic-link click invokes themeapi.requestMagicLink with the email", () => {
        const { document, themeapiCalls } = loadSlice({
            paddleCustomerId: "ctm_pair",
            email: "buyer@example.com",
        });
        document.getElementById("settings-themes-account-magic-link-btn").click();
        expect(themeapiCalls.requestMagicLink).toHaveLength(1);
        expect(themeapiCalls.requestMagicLink[0]).toEqual({
            email: "buyer@example.com",
        });
    });

    test("magic-link click without an email falls through when prompt is cancelled", () => {
        const { document, themeapiCalls } = loadSlice({
            paddleCustomerId: "ctm_pair",
            email: "",
        });
        globalThis.__nextPromptValue = null;
        document.getElementById("settings-themes-account-magic-link-btn").click();
        expect(themeapiCalls.requestMagicLink).toHaveLength(0);
    });

    test("magic-link click without an email forwards a typed value", () => {
        const { document, themeapiCalls } = loadSlice({
            paddleCustomerId: "ctm_pair",
            email: "",
        });
        globalThis.__nextPromptValue = "fresh@example.com";
        document.getElementById("settings-themes-account-magic-link-btn").click();
        expect(themeapiCalls.requestMagicLink).toHaveLength(1);
        expect(themeapiCalls.requestMagicLink[0]).toEqual({
            email: "fresh@example.com",
        });
    });
});