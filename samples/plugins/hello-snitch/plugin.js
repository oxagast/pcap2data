/*
 * hello-snitch tutorial plugin
 *
 * This sample is intentionally comment-heavy. It demonstrates common plugin patterns:
 * 1) Add custom UI (tab + panel)
 * 2) Add an action into the existing right-click context menu
 * 3) Read/write files from plugin code
 * 4) Fetch remote data over HTTP(S)
 * 5) Safely wrap (override) host callbacks and clean them up in dispose()
 */

(function helloSnitchPluginBootstrap() {
    // --- Stable IDs used by this plugin ---------------------------------------------------------
    // Keep these in constants so we can cleanly remove UI in dispose().
    const HELLO_TAB_BTN_ID = "hello-snitch-tab-btn";
    const HELLO_TAB_BOX_ID = "hello-snitch-box";
    const HELLO_TEXT_ID = "hello-snitch-version-text";
    const HELLO_FETCH_BTN_ID = "hello-snitch-fetch-btn";
    const HELLO_FETCH_RESULT_ID = "hello-snitch-fetch-result";
    const HELLO_CONTEXT_MENU_BTN_ID = "ctx-hello-open";

    // PacketSnitch has several main content panes. This mirrors app behavior when switching tabs.
    const MAIN_BOX_IDS = [
        "summary_box",
        "stats_box",
        "data_tools_box",
        "crypt_box",
        "keystore_box",
        "list_box",
        "notes_box",
        "settings_box",
        "packetInfoPane",
        "packetPayloadPane",
    ];

    // Small runtime state holder so init()/dispose() can coordinate cleanup.
    const runtimeState = {
        wrappedStatusUpdateRestore: null,
        lastOutputPath: "",
    };

    // --- Utility: hide default panes and show our panel -----------------------------------------
    function hideDefaultBoxes(documentRef) {
        MAIN_BOX_IDS.forEach((id) => {
            const el = documentRef.getElementById(id);
            if (el) {
                el.style.display = "none";
            }
        });
    }

    function showHelloPanel(documentRef) {
        hideDefaultBoxes(documentRef);
        const helloBox = documentRef.getElementById(HELLO_TAB_BOX_ID);
        if (helloBox) {
            helloBox.style.display = "block";
        }
    }

    // --- UI creation ----------------------------------------------------------------------------
    // Pattern: create elements only once, and make sure IDs are unique.
    function ensureHelloUi(documentRef) {
        const tabBar = documentRef.getElementById("tab-btns");
        const mainPanel = documentRef.getElementById("main");
        if (!tabBar || !mainPanel) {
            throw new Error("HelloSnitch could not find tab bar/main panel in DOM");
        }

        // Add a top-level tab button.
        let helloBtn = documentRef.getElementById(HELLO_TAB_BTN_ID);
        if (!helloBtn) {
            helloBtn = documentRef.createElement("input");
            helloBtn.type = "button";
            helloBtn.id = HELLO_TAB_BTN_ID;
            helloBtn.value = "hello";
            helloBtn.className = "custom-btns";
            tabBar.appendChild(helloBtn);
        }

        // Add our panel into the main container.
        let helloBox = documentRef.getElementById(HELLO_TAB_BOX_ID);
        if (!helloBox) {
            helloBox = documentRef.createElement("div");
            helloBox.id = HELLO_TAB_BOX_ID;
            helloBox.style.display = "none";
            helloBox.innerHTML = `
                <div class="settings-workspace-header">Hello</div>
                <div class="settings-help-text">
                    This panel is created by a plugin. Use it as a starter template for custom views.
                </div>
                <div id="${HELLO_TEXT_ID}" class="settings-help-text"></div>
                <div class="settings-actions-row" style="margin-top: 0.6rem; gap: 0.5rem; display: flex; flex-wrap: wrap;">
                    <button type="button" id="${HELLO_FETCH_BTN_ID}">Fetch Example Data</button>
                </div>
                <pre id="${HELLO_FETCH_RESULT_ID}" class="settings-help-text" style="margin-top: 0.6rem; white-space: pre-wrap;"></pre>
            `;
            mainPanel.appendChild(helloBox);
        }

        helloBtn.onclick = () => showHelloPanel(documentRef);
    }

    // --- Context-menu contribution ---------------------------------------------------------------
    // This app has a global context menu container (#convert-context-menu).
    // We append one extra action that simply opens the Hello panel.
    function ensureContextMenuEntry(documentRef) {
        const contextMenu = documentRef.getElementById("convert-context-menu");
        if (!contextMenu) {
            return;
        }

        let openHelloButton = documentRef.getElementById(HELLO_CONTEXT_MENU_BTN_ID);
        if (!openHelloButton) {
            openHelloButton = documentRef.createElement("button");
            openHelloButton.type = "button";
            openHelloButton.id = HELLO_CONTEXT_MENU_BTN_ID;
            openHelloButton.setAttribute("role", "menuitem");
            openHelloButton.textContent = "Open Hello";
            contextMenu.appendChild(openHelloButton);
        }

        openHelloButton.onclick = () => {
            showHelloPanel(documentRef);
            // Hide context menu after click if visible.
            contextMenu.hidden = true;
        };
    }

    // --- File IO examples -----------------------------------------------------------------------
    // This demonstrates write + read operations from a plugin.
    // NOTE: This requires Node access in the plugin runtime bridge.
    function writeVersionFileExample(message) {
        const path = require("path");
        const os = require("os");
        const fs = require("fs");

        const documentsDir = path.join(os.homedir(), "Documents");
        const outputPath = path.join(documentsDir, "hello-snitch-version.txt");
        fs.mkdirSync(documentsDir, { recursive: true });
        fs.writeFileSync(outputPath, `${message}\n`, "utf8");
        runtimeState.lastOutputPath = outputPath;
        return outputPath;
    }

    function readVersionFileExample() {
        const fs = require("fs");
        if (!runtimeState.lastOutputPath || !fs.existsSync(runtimeState.lastOutputPath)) {
            return "(no output file has been written yet)";
        }
        return fs.readFileSync(runtimeState.lastOutputPath, "utf8").trim();
    }

    // --- Network fetch example ------------------------------------------------------------------
    // Uses browser fetch() so it follows app CSP/connect-src rules.
    async function fetchRemoteExample() {
        const response = await fetch("https://api.github.com/repos/microsoft/vscode", {
            headers: {
                Accept: "application/vnd.github+json",
            },
        });
        if (!response.ok) {
            throw new Error(`Fetch failed with HTTP ${response.status}`);
        }
        const body = await response.json();
        return {
            full_name: body.full_name,
            stargazers_count: body.stargazers_count,
            updated_at: body.updated_at,
        };
    }

    // --- Safe function override (wrapping) example ----------------------------------------------
    // "Overwriting a function" is risky. Prefer wrapping with cleanup:
    // 1) keep original reference
    // 2) replace with wrapper
    // 3) restore original in dispose()
    function installSafeStatusWrapperExample(context = {}) {
        if (runtimeState.wrappedStatusUpdateRestore) {
            return;
        }
        const originalStatusUpdate =
            typeof context.statusUpdate === "function" ? context.statusUpdate : null;
        if (!originalStatusUpdate) {
            return;
        }

        context.statusUpdate = (message) => {
            originalStatusUpdate(`[hello-snitch] ${String(message || "")}`);
        };

        runtimeState.wrappedStatusUpdateRestore = () => {
            context.statusUpdate = originalStatusUpdate;
            runtimeState.wrappedStatusUpdateRestore = null;
        };
    }

    // --- Disposal -------------------------------------------------------------------------------
    function disposeHelloUi(documentRef) {
        const helloBtn = documentRef.getElementById(HELLO_TAB_BTN_ID);
        if (helloBtn && helloBtn.parentNode) {
            helloBtn.parentNode.removeChild(helloBtn);
        }

        const helloBox = documentRef.getElementById(HELLO_TAB_BOX_ID);
        if (helloBox && helloBox.parentNode) {
            helloBox.parentNode.removeChild(helloBox);
        }

        const contextMenuBtn = documentRef.getElementById(HELLO_CONTEXT_MENU_BTN_ID);
        if (contextMenuBtn && contextMenuBtn.parentNode) {
            contextMenuBtn.parentNode.removeChild(contextMenuBtn);
        }
    }

    // --- Runtime entrypoints --------------------------------------------------------------------
    function resolvePacketsnitchVersion(context = {}) {
        let version = String(context?.packetsnitchVersion || "").trim();
        if (version) return version;

        // Backward-compat fallback if runtime bridge does not provide version.
        const installApi = window.installapi;
        if (installApi && typeof installApi.checkFirstRun === "function") {
            return installApi
                .checkFirstRun()
                .then((firstRunInfo) => String(firstRunInfo?.version || "unknown").trim() || "unknown")
                .catch(() => "unknown");
        }
        return "unknown";
    }

    async function runHelloSnitch(context = {}) {
        const documentRef = context?.documentRef || document;
        ensureHelloUi(documentRef);
        ensureContextMenuEntry(documentRef);

        const resolvedVersion = await resolvePacketsnitchVersion(context);
        const version = typeof resolvedVersion === "string" ? resolvedVersion : "unknown";
        const message = `Hello, from PacketSnitch version: ${version}`;

        const outputPath = writeVersionFileExample(message);
        const outputFilePreview = readVersionFileExample();

        const textEl = documentRef.getElementById(HELLO_TEXT_ID);
        if (textEl) {
            textEl.textContent = `${message} (written to ${outputPath}) | File says: ${outputFilePreview}`;
        }

        const fetchBtn = documentRef.getElementById(HELLO_FETCH_BTN_ID);
        const fetchResultEl = documentRef.getElementById(HELLO_FETCH_RESULT_ID);
        if (fetchBtn && fetchResultEl) {
            fetchBtn.onclick = async () => {
                fetchResultEl.textContent = "Fetching...";
                try {
                    const remote = await fetchRemoteExample();
                    fetchResultEl.textContent = JSON.stringify(remote, null, 2);
                } catch (error) {
                    fetchResultEl.textContent = `Fetch error: ${error?.message || error}`;
                }
            };
        }

        showHelloPanel(documentRef);
        return { message, version, outputPath };
    }

    async function initHelloSnitch(context = {}) {
        const result = await runHelloSnitch(context);

        // Uncomment to see safe status wrapping in action. Leave disabled by default.
        // installSafeStatusWrapperExample(context);

        if (typeof context.writeLogEntry === "function") {
            context.writeLogEntry(
                `hello-snitch initialized version=${JSON.stringify(result.version)} output=${JSON.stringify(result.outputPath)}`,
            );
        }
        if (typeof context.statusUpdate === "function") {
            context.statusUpdate(`Status: ${result.message}`);
        }
        return result;
    }

    async function disposeHelloSnitch(context = {}) {
        const documentRef = context?.documentRef || document;
        disposeHelloUi(documentRef);

        if (typeof runtimeState.wrappedStatusUpdateRestore === "function") {
            runtimeState.wrappedStatusUpdateRestore();
        }

        if (typeof context.writeLogEntry === "function") {
            context.writeLogEntry("hello-snitch disposed and UI removed");
        }
        return { disposed: true };
    }

    // Export shape supports both direct function plugins and object plugins.
    const runtime = {
        init: initHelloSnitch,
        run: runHelloSnitch,
        dispose: disposeHelloSnitch,

        // Expose examples so plugin developers can experiment in DevTools if desired.
        examples: {
            fetchRemoteExample,
            writeVersionFileExample,
            readVersionFileExample,
            installSafeStatusWrapperExample,
        },
    };

    window.HelloSnitchPlugin = runtime;
    if (typeof module !== "undefined" && module && module.exports) {
        module.exports = runtime;
    }
})();
