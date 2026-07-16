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
    const HELLO_TAB_BTN_ID = "hello-snitch-tab-btn";
    const HELLO_TAB_BOX_ID = "hello-snitch-box";
    const HELLO_TEXT_ID = "hello-snitch-version-text";
    const HELLO_FETCH_BTN_ID = "hello-snitch-fetch-btn";
    const HELLO_FETCH_RESULT_ID = "hello-snitch-fetch-result";
    const HELLO_DENY_BTN_ID = "hello-snitch-deny-btn";
    const HELLO_CONTEXT_MENU_BTN_ID = "ctx-hello-open";

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

    const runtimeState = {
        outputPath: "",
        restoreWrappedStatus: null,
    };

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

    async function writeVersionFileExample(context, message) {
        const fsApi = context?.api?.fs;
        if (!fsApi) {
            throw new Error("Plugin fs api is unavailable");
        }
        const documentsDir = fsApi.joinPath(fsApi.homeDirectory(), "Documents");
        runtimeState.outputPath = fsApi.joinPath(documentsDir, "hello-snitch-version.txt");
        await fsApi.writeText(runtimeState.outputPath, `${message}\n`, "utf8");
        return runtimeState.outputPath;
    }

    async function readVersionFileExample(context) {
        if (!runtimeState.outputPath) {
            return "(no output file has been written yet)";
        }
        return String(await context.api.fs.readText(runtimeState.outputPath, "utf8")).trim();
    }

    async function fetchRemoteExample(context) {
        const response = await context.api.network.fetch(
            "https://api.github.com/repos/oxasploits/PacketSnitch",
            {
                headers: {
                    Accept: "application/vnd.github+json",
                },
            },
        );
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

    function installSafeStatusWrapperExample(context = {}) {
        if (runtimeState.restoreWrappedStatus) {
            return;
        }
        const overwriteFn = context?.api?.packetsnitch?.overwriteFunction;
        if (typeof overwriteFn !== "function") {
            return;
        }
        runtimeState.restoreWrappedStatus = overwriteFn("statusUpdate", (originalFn) => {
            return (message) => originalFn(`[hello-snitch] ${String(message || "")}`);
        });
    }

    function ensureHelloUi(context = {}) {
        const documentRef = context?.documentRef || document;
        const tabBar = documentRef.getElementById("tab-btns");
        const mainPanel = documentRef.getElementById("main");
        if (!tabBar || !mainPanel) {
            throw new Error("HelloSnitch could not find tab bar/main panel in DOM");
        }

        context.api.ui.tabs.create({ id: HELLO_TAB_BTN_ID, label: "hello" });

        let helloBox = documentRef.getElementById(HELLO_TAB_BOX_ID);
        if (!helloBox) {
            helloBox = documentRef.createElement("div");
            helloBox.id = HELLO_TAB_BOX_ID;
            helloBox.style.display = "none";
            helloBox.innerHTML = `
                <div class="settings-workspace-header">Hello</div>
                <div class="settings-help-text">
                    This panel is created by a plugin using guarded APIs.
                </div>
                <div id="${HELLO_TEXT_ID}" class="settings-help-text"></div>
                <div class="settings-actions-row" style="margin-top: 0.6rem; gap: 0.5rem; display: flex; flex-wrap: wrap;">
                    <button type="button" id="${HELLO_FETCH_BTN_ID}">Fetch Example Data</button>
                    <button type="button" id="${HELLO_DENY_BTN_ID}">Try Unauthorized chmod</button>
                </div>
                <pre id="${HELLO_FETCH_RESULT_ID}" class="settings-help-text" style="margin-top: 0.6rem; white-space: pre-wrap;"></pre>
            `;
            mainPanel.appendChild(helloBox);
        }

        const helloBtn = documentRef.getElementById(HELLO_TAB_BTN_ID);
        if (helloBtn) {
            helloBtn.onclick = () => showHelloPanel(documentRef);
        }
    }

    function ensureContextMenuEntry(context = {}) {
        const documentRef = context?.documentRef || document;
        context.api.ui.contextMenu.create({
            id: HELLO_CONTEXT_MENU_BTN_ID,
            text: "Open Hello",
            onClick: () => {
                showHelloPanel(documentRef);
                const contextMenu = documentRef.getElementById("convert-context-menu");
                if (contextMenu) {
                    contextMenu.hidden = true;
                }
            },
        });
    }

    function disposeHelloUi(documentRef) {
        [HELLO_TAB_BTN_ID, HELLO_TAB_BOX_ID, HELLO_CONTEXT_MENU_BTN_ID].forEach((id) => {
            const el = documentRef.getElementById(id);
            if (el && el.parentNode) {
                el.parentNode.removeChild(el);
            }
        });
    }

    async function runHelloSnitch(context = {}) {
        const documentRef = context?.documentRef || document;
        ensureHelloUi(context);
        ensureContextMenuEntry(context);

        const version = context.api.version.read();
        const message = `Hello, from PacketSnitch version: ${version}`;

        const outputPath = await writeVersionFileExample(context, message);
        const outputFilePreview = await readVersionFileExample(context);

        const textEl = documentRef.getElementById(HELLO_TEXT_ID);
        if (textEl) {
            textEl.textContent = `${message} (written to ${outputPath}) | File says: ${outputFilePreview}`;
        }

        const fetchBtn = documentRef.getElementById(HELLO_FETCH_BTN_ID);
        const denyBtn = documentRef.getElementById(HELLO_DENY_BTN_ID);
        const fetchResultEl = documentRef.getElementById(HELLO_FETCH_RESULT_ID);

        if (fetchBtn && fetchResultEl) {
            fetchBtn.onclick = async () => {
                fetchResultEl.textContent = "Fetching...";
                try {
                    const remote = await fetchRemoteExample(context);
                    fetchResultEl.textContent = JSON.stringify(remote, null, 2);
                } catch (error) {
                    fetchResultEl.textContent = `Fetch error: ${error?.message || error}`;
                }
            };
        }

        if (denyBtn && fetchResultEl) {
            denyBtn.onclick = async () => {
                try {
                    await context.api.fs.chmod(outputPath, 0o600);
                    fetchResultEl.textContent = "chmod succeeded";
                } catch (error) {
                    fetchResultEl.textContent = `Denied as expected: ${error?.message || error}`;
                }
            };
        }

        showHelloPanel(documentRef);
        return { message, version, outputPath };
    }

    async function initHelloSnitch(context = {}) {
        const result = await runHelloSnitch(context);
        if (typeof context.writeLogEntry === "function") {
            await context.writeLogEntry(
                `hello-snitch initialized version=${JSON.stringify(result.version)} output=${JSON.stringify(result.outputPath)}`,
            );
        }
        context.api.ui.statusBar.setText(`Status: ${result.message}`);

        if (context.permissions?.has?.("packetsnitch.functions.overwrite")) {
            installSafeStatusWrapperExample(context);
        }
        return result;
    }

    async function disposeHelloSnitch(context = {}) {
        const documentRef = context?.documentRef || document;
        disposeHelloUi(documentRef);

        if (typeof runtimeState.restoreWrappedStatus === "function") {
            runtimeState.restoreWrappedStatus();
            runtimeState.restoreWrappedStatus = null;
        }

        if (typeof context.writeLogEntry === "function") {
            await context.writeLogEntry("hello-snitch disposed and UI removed");
        }
        return { disposed: true };
    }

    const runtime = {
        init: initHelloSnitch,
        run: runHelloSnitch,
        dispose: disposeHelloSnitch,
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
