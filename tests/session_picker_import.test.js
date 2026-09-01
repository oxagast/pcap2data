// Tests for the session picker "Import" button and the import-name prompt
// round-trip between the renderer and the main process.
//
// The session picker panel is initialized with a hand-rolled DOM stub and a
// fake `sessionsapi` so we can assert that clicking the Import button invokes
// `importFromFile()` and that the 'session-import-prompt-name' callback
// drives the existing session-name dialog and reports the result back via
// `sendImportNameResult`.

const path = require("path");

function makeFakeButton(label) {
    return {
        textContent: label || "",
        className: "",
        title: "",
        disabled: false,
        _listeners: new Map(),
        addEventListener(type, cb) {
            if (!this._listeners.has(type)) this._listeners.set(type, new Set());
            this._listeners.get(type).add(cb);
        },
        removeEventListener(type, cb) {
            const set = this._listeners.get(type);
            if (set) set.delete(cb);
        },
        click() {
            const set = this._listeners.get("click");
            if (!set) return;
            for (const cb of Array.from(set)) cb({});
        },
        setAttribute() { },
        getAttribute() {
            return null;
        },
    };
}

function makeFakeInput() {
    return {
        value: "",
        focus() { },
        select() { },
        addEventListener() { },
    };
}

function makeFakeDialog(id) {
    return { hidden: true, addEventListener() { }, focus() { } };
}

function makeFakeDocument(overrides) {
    const ids = Object.assign(
        {
            "session-picker": { style: {}, display: "" },
            "session-picker-list": { innerHTML: "", appendChild() { } },
            "session-picker-status": { textContent: "", className: "" },
            "session-picker-new-btn": makeFakeButton("New Session"),
            "session-picker-import-btn": makeFakeButton("Import"),
            "session-picker-close-btn": makeFakeButton(),
            "session-picker-refresh-btn": makeFakeButton("Refresh"),
            "session-name-dialog": makeFakeDialog("session-name-dialog"),
            "session-name-input": makeFakeInput(),
            "session-name-confirm-btn": makeFakeButton("Save"),
            "session-name-cancel-btn": makeFakeButton("Cancel"),
            "session-name-dialog-title": { textContent: "" },
            "session-name-dialog-status": { textContent: "" },
            "session-delete-dialog": makeFakeDialog("session-delete-dialog"),
            "session-delete-dialog-description": { textContent: "" },
            "session-delete-confirm-btn": makeFakeButton("Delete"),
            "session-delete-cancel-btn": makeFakeButton("Cancel"),
        },
        overrides || {},
    );

    return {
        getElementById(id) {
            return ids[id] || null;
        },
        createElement(tag) {
            return {
                tagName: tag,
                className: "",
                textContent: "",
                title: "",
                appendChild() { },
                addEventListener() { },
            };
        },
    };
}

function makeFakeSessionsapi() {
    const calls = [];
    const importPromptCallbacks = [];
    return {
        calls,
        list: async () => ({ success: true, sessions: [], fromCache: false }),
        load: async () => ({ success: true, data: "{}" }),
        save: async () => ({ success: true }),
        rename: async () => ({ success: true, name: "renamed" }),
        remove: async () => ({ success: true }),
        exportToFile: async () => ({ success: true }),
        importFromFile: async () => {
            calls.push("importFromFile");
            return { success: true, name: "imported-session" };
        },
        onImportPromptName: (cb) => {
            importPromptCallbacks.push(cb);
        },
        sendImportNameResult: (name) => {
            calls.push("sendImportNameResult:" + name);
        },
        onRefreshed: () => { },
        refresh: async () => ({}),
        _importPromptCallbacks: importPromptCallbacks,
    };
}

describe("session picker import button", () => {
    let initializeSessionPicker;

    beforeEach(() => {
        jest.resetModules();
        initializeSessionPicker = require(path.resolve(
            "src/ui/panels/session-picker",
        )).initializeSessionPicker;
    });

    test("Import button is wired and calls sessionsapi.importFromFile on click", async () => {
        const fakeDocument = makeFakeDocument();
        const fakeSessionsapi = makeFakeSessionsapi();

        initializeSessionPicker({
            sessionsapi: fakeSessionsapi,
            documentRef: fakeDocument,
            onSessionSelected: () => { },
            onNewSession: () => { },
            buildSessionFilePayload: async () => "{}",
        });

        const importBtn = fakeDocument.getElementById("session-picker-import-btn");
        expect(importBtn).toBeTruthy();

        // Click should kick off the import flow.
        const before = fakeSessionsapi.calls.length;
        importBtn.click();
        // Allow the async handleImport chain (importFromFile + loadSessions) to
        // settle across microtask boundaries.
        for (let i = 0; i < 10; i++) {
            await new Promise((r) => setImmediate(r));
        }
        expect(fakeSessionsapi.calls.filter((c) => c === "importFromFile").length).toBeGreaterThan(before);

        // A successful import is followed by a list refresh; the status line is
        // cleared by loadSessions(), so just assert no error class is set.
        expect(fakeDocument.getElementById("session-picker-status").className).not.toContain("error");
    });

    test("onImportPromptName drives the session-name dialog and reports the result", async () => {
        const fakeDocument = makeFakeDocument();
        const fakeSessionsapi = makeFakeSessionsapi();

        initializeSessionPicker({
            sessionsapi: fakeSessionsapi,
            documentRef: fakeDocument,
            onSessionSelected: () => { },
            onNewSession: () => { },
            buildSessionFilePayload: async () => "{}",
        });

        expect(fakeSessionsapi._importPromptCallbacks.length).toBe(1);
        const promptCb = fakeSessionsapi._importPromptCallbacks[0];

        // The prompt resolves a promise; clicking confirm with a value resolves it.
        const promptPromise = promptCb({ defaultName: "exported" });
        await new Promise((r) => setImmediate(r));

        // Simulate the user typing a name and clicking Save in the dialog.
        const input = fakeDocument.getElementById("session-name-input");
        const confirmBtn = fakeDocument.getElementById("session-name-confirm-btn");
        input.value = "my-imported-session";
        confirmBtn.click();

        await promptPromise;
        expect(fakeSessionsapi.calls).toContain("sendImportNameResult:my-imported-session");
    });

    test("canceling the import name prompt sends an empty name result", async () => {
        const fakeDocument = makeFakeDocument();
        const fakeSessionsapi = makeFakeSessionsapi();

        initializeSessionPicker({
            sessionsapi: fakeSessionsapi,
            documentRef: fakeDocument,
            onSessionSelected: () => { },
            onNewSession: () => { },
            buildSessionFilePayload: async () => "{}",
        });

        const promptCb = fakeSessionsapi._importPromptCallbacks[0];
        const promptPromise = promptCb({ defaultName: "exported" });
        await new Promise((r) => setImmediate(r));

        // Cancel the dialog.
        const cancelBtn = fakeDocument.getElementById("session-name-cancel-btn");
        cancelBtn.click();

        await promptPromise;
        expect(fakeSessionsapi.calls).toContain("sendImportNameResult:");
    });

    test("handles importFromFile returning canceled without erroring", async () => {
        const fakeDocument = makeFakeDocument();
        const fakeSessionsapi = makeFakeSessionsapi();
        fakeSessionsapi.importFromFile = async () => ({ success: false, canceled: true });

        initializeSessionPicker({
            sessionsapi: fakeSessionsapi,
            documentRef: fakeDocument,
            onSessionSelected: () => { },
            onNewSession: () => { },
            buildSessionFilePayload: async () => "{}",
        });

        const importBtn = fakeDocument.getElementById("session-picker-import-btn");
        importBtn.click();
        await new Promise((r) => setImmediate(r));
        await new Promise((r) => setImmediate(r));
        // On cancel the status is cleared, not shown as an error.
        expect(fakeDocument.getElementById("session-picker-status").textContent).toBe("");
    });

    test("shows an error status when import fails", async () => {
        const fakeDocument = makeFakeDocument();
        const fakeSessionsapi = makeFakeSessionsapi();
        fakeSessionsapi.importFromFile = async () => ({ success: false, error: "boom" });

        initializeSessionPicker({
            sessionsapi: fakeSessionsapi,
            documentRef: fakeDocument,
            onSessionSelected: () => { },
            onNewSession: () => { },
            buildSessionFilePayload: async () => "{}",
        });

        const importBtn = fakeDocument.getElementById("session-picker-import-btn");
        importBtn.click();
        await new Promise((r) => setImmediate(r));
        await new Promise((r) => setImmediate(r));
        expect(fakeDocument.getElementById("session-picker-status").textContent).toContain("Import failed");
        expect(fakeDocument.getElementById("session-picker-status").className).toContain("error");
    });
});