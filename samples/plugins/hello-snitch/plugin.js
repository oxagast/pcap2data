// hello-snitch sample plugin
// Adds a "hello" tab with PacketSnitch version details and writes version text to Documents.

(function helloSnitchPluginBootstrap() {
    const HELLO_TAB_BTN_ID = "hello-snitch-tab-btn";
    const HELLO_TAB_BOX_ID = "hello-snitch-box";
    const HELLO_TEXT_ID = "hello-snitch-version-text";
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

    function ensureHelloUi(documentRef) {
        const tabBar = documentRef.getElementById("tab-btns");
        const mainPanel = documentRef.getElementById("main");
        if (!tabBar || !mainPanel) {
            throw new Error("HelloSnitch could not find tab bar/main panel in DOM");
        }

        let helloBtn = documentRef.getElementById(HELLO_TAB_BTN_ID);
        if (!helloBtn) {
            helloBtn = documentRef.createElement("input");
            helloBtn.type = "button";
            helloBtn.id = HELLO_TAB_BTN_ID;
            helloBtn.value = "hello";
            helloBtn.className = "custom-btns";
            tabBar.appendChild(helloBtn);
        }

        let helloBox = documentRef.getElementById(HELLO_TAB_BOX_ID);
        if (!helloBox) {
            helloBox = documentRef.createElement("div");
            helloBox.id = HELLO_TAB_BOX_ID;
            helloBox.style.display = "none";
            helloBox.innerHTML = `
        <div class="settings-workspace-header">Hello</div>
        <div id="${HELLO_TEXT_ID}" class="settings-help-text"></div>
      `;
            mainPanel.appendChild(helloBox);
        }

        helloBtn.onclick = () => showHelloPanel(documentRef);
    }

    function disposeHelloUi(documentRef) {
        const helloBtn = documentRef.getElementById(HELLO_TAB_BTN_ID);
        if (helloBtn && helloBtn.parentNode) {
            helloBtn.parentNode.removeChild(helloBtn);
        }
        const helloBox = documentRef.getElementById(HELLO_TAB_BOX_ID);
        if (helloBox && helloBox.parentNode) {
            helloBox.parentNode.removeChild(helloBox);
        }
    }

    async function runHelloSnitch(context = {}) {
        let version = String(context?.packetsnitchVersion || "").trim();
        if (!version) {
            const installApi = window.installapi;
            if (!installApi || typeof installApi.checkFirstRun !== "function") {
                throw new Error("installapi.checkFirstRun is unavailable");
            }
            const firstRunInfo = await installApi.checkFirstRun();
            version = String(firstRunInfo?.version || "unknown").trim() || "unknown";
        }
        const message = `Hello, from PacketSnitch version: ${version}`;

        const path = require("path");
        const os = require("os");
        const fs = require("fs");
        const documentsDir = path.join(os.homedir(), "Documents");
        const outputPath = path.join(documentsDir, "hello-snitch-version.txt");
        fs.mkdirSync(documentsDir, { recursive: true });
        fs.writeFileSync(outputPath, `${message}\n`, "utf8");

        ensureHelloUi(document);
        const textEl = document.getElementById(HELLO_TEXT_ID);
        if (textEl) {
            textEl.textContent = `${message} (written to ${outputPath})`;
        }

        return { message, version, outputPath };
    }

    async function initHelloSnitch(context = {}) {
        const result = await runHelloSnitch(context);
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
        if (typeof context.writeLogEntry === "function") {
            context.writeLogEntry("hello-snitch disposed and UI removed");
        }
        return { disposed: true };
    }

    const runtime = {
        init: initHelloSnitch,
        run: runHelloSnitch,
        dispose: disposeHelloSnitch,
    };

    window.HelloSnitchPlugin = runtime;
    if (typeof module !== "undefined" && module && module.exports) {
        module.exports = runtime;
    }
})();
