## Themes Reference

This page includes both the PacketSnitch Themes reference and a complete Plugins reference/tutorial.

PacketSnitch uses a file-driven theming engine. A theme is a JSON file that overrides CSS variables and can optionally replace the app logo, apply a backdrop wallpaper, and tune panel transparency.

This guide covers:

- Where theme files live
- Theme JSON schema
- How to set app colors
- How to set a custom logo
- How to set a backdrop wallpaper
- How to control opacity and panel translucency
- How the app validates/falls back when a theme is invalid

---

## Screenshots

<p align="center">
Screenshot of the "Matrix" theme.

<a href="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-matrix-theme.png">
<img alt="The Matrix Theme on PacketSnitch 1.8" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-matrix-theme.png">
</a>

Also a cobalt/black "Sub7" inspired theme.

<a href="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-sub7-theme.png">
<img alt="The Sub7 Theme on PacketSnitch 1.8" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-sub7-theme.png">
</a>

A lighter, airy pastels theme, "Nilla Horizon".

<a href="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-nilla-horizon-theme.png">
<img alt="The Matrix Theme on PacketSnitch 1.8" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-nilla-horizon-theme.png">
</a>
</p>



---

## Theme File Locations

PacketSnitch uses two theme locations:

- Windows the userdir usually resolves to `C:\Users\Username\AppData\Roaming\packetsnitch\themes\*.json`.
- Linux it ususally resolves to `/home/username/.config/packetsnitch/themes/*.json`.


At startup, PacketSnitch ensures default themes exist in `userData/themes`. The Settings tab reads from this runtime directory.

In-app, open **Settings → General** and check the theme-directory hint text to find the exact path on your system.

---

## Theme JSON Schema

A valid theme must have a non-empty `variables` object with CSS custom properties.

```json
{
  "id": "my_custom_theme",
  "name": "My Custom Theme",
  "description": "Optional description shown in docs/source",
  "variables": {
    "--app-bg": "#101418",
    "--surface-0": "#0b0f13",
    "--surface-1": "#151c24",
    "--surface-2": "#111820",
    "--color-1": "#9ad8ff",
    "--color-5": "#d7e9f7",
    "--tab-inactive-opacity": "0.72"
  },
  "logoImage": {
    "format": "png",
    "base64": "iVBORw0KGgoAAAANSUhEUgAA..."
  },
  "backdropImage": {
    "format": "jpg",
    "base64": "/9j/4AAQSkZJRgABAQAAAQABAAD..."
  }
}
```

### Field Rules

- `id`: sanitized to lowercase with only `a-z`, `0-9`, `_`, `-`
- `name`: display label shown in Settings
- `description`: optional text
- `variables`: required, must include at least one valid CSS variable key/value
- `quitButtonCharacter`: optional single-character override for the app quit button label
- `logoImage`: optional
- `backdropImage`: optional

Validation behavior:

- Only variable keys starting with `--` are applied.
- Variable values must be non-empty strings.
- If `variables` is empty/invalid, the theme file is ignored.
- Invalid JSON files are skipped (the app continues running).
- Duplicate theme IDs are de-duplicated.

---

## Setting App Colors

The base color system is driven by CSS custom properties in `src/assets/css/style.css`.

Tip: start from an existing file in `themes/`, then change values incrementally.

## Full Variable Reference

The variables below are currently consumed by PacketSnitch styles and can be set in `theme.variables`.

### Core Surfaces and UI Colors

- `--app-bg`: app/page background.
- `--surface-0`: primary workspace surface.
- `--surface-1`: secondary panel surface.
- `--surface-2`: tertiary surface token (available for themes).
- `--scrollbar-track`: scrollbar track color.
- `--border-strong`: stronger border color used by major frames.
- `--color-1`: primary accent/foreground token.
- `--color-2`: secondary accent/background token.
- `--color-2-hover`: hover state for secondary accents.
- `--color-3`: common border/outline token used widely.
- `--color-4`: muted panel/background token.
- `--color-5`: primary readable foreground text token.
- `--color-6`: secondary readable foreground text token.
- `--color-7`: shared panel background token.

### Header, Sidebar, Inputs, and App Chrome

- `--top-bar-bg`: top title/tagline bar background (center logo/tagline strip).
- `--header-text-color`: heading/title text color.
- `--sidebar-text-color`: sidebar text color.
- `--input-bg-color`: text/select input background.
- `--input-text-color`: text/select input foreground.
- `--quit-btn-color`: quit button color.
- `--quit-btn-hover-color`: quit button hover color.
- `--stats-tag-text-color`: stats tag text color.
- `--notes-link-color`: markdown preview link color in notes.
- `--notes-markdown-bg`: markdown preview background color in notes.
- `--crypt-panel-bg`: crypt workspace panel background.
- `--crypt-panel-text`: crypt workspace text color.

### Data Tools Workspace Variables

- `--data-tools-frame-bg`: data tools frame background.
- `--data-tools-frame-color`: data tools frame text color.
- `--data-tools-frame-border`: data tools frame border color.
- `--data-tools-hex-color`: hex conversion accent/border color.
- `--data-tools-binary-color`: binary conversion accent/border color.
- `--data-tools-decimal-color`: decimal conversion accent/border color.
- `--data-tools-decimal-integer-color`: decimal-integer conversion accent/border color.
- `--data-tools-ascii-color`: ASCII conversion accent/border color.
- `--data-tools-base64-color`: Base64 conversion accent/border color.

### Activity Log Variables

- `--log-bg`: activity log background.
- `--log-text`: activity log text.

### Typography and Layout Variables

- `--body-font-family`: global body font family.
- `--panel-bg-opacity`: panel background opacity mix percentage (`0%`-`100%`). Lower values let the backdrop wallpaper show through panel surfaces.
- `--tab-inactive-opacity`: inactive tab opacity (string value from `0` to `1`).
- `--sidebar-width`: sidebar width token used in layout sizing.

### Internal Utility Tokens (Usually Leave Alone)

These are internal sizing helpers used by the filter input/clear button layout.

- `--filter-clear-button-width`
- `--filter-clear-padding`
- `--filter-clear-right-offset`

You can override them, but values that are too small/large may cause overlap or clipping in the filter controls.

---

## Custom Logo

You can set a per-theme logo with `logoImage`.

Supported formats:

- `png`
- `jpg` (or `jpeg`, normalized to `jpg`)

Supported payload fields:

- `logoImage.base64`
- `logoImage.data`

If a data URI prefix is included (for example `data:image/png;base64,...`), PacketSnitch strips it automatically.

Example:

```json
"logoImage": {
  "format": "jpg",
  "base64": "/9j/4AAQSkZJRgABAQAAAQABAAD..."
}
```

If `logoImage` is missing or invalid, PacketSnitch falls back to the default app logo.

---

## Optional Backdrop Wallpaper

You can set a full-app backdrop wallpaper with `backdropImage`.

This image is rendered in the dedicated backdrop layer behind the full UI stack.

Hint: Animated .png images (APNG format) *are* supported by the theme engine, however, I just personally think they are too distracting to be practical in this use case.

Supported formats:

- `png`
- `jpg` (or `jpeg`, normalized to `jpg`)

Supported payload fields:

- `backdropImage.base64`
- `backdropImage.data`

Example:

```json
"backdropImage": {
  "format": "jpg",
  "base64": "/9j/4AAQSkZJRgABAQAAAQABAAD..."
}
```

If `backdropImage` is missing or invalid, PacketSnitch shows no wallpaper and uses standard theme backgrounds only.

---

## Opacity Controls

Theme opacity is controlled with CSS variable values where supported.

Most useful controls:

- `--tab-inactive-opacity`: inactive tab button opacity (`0` to `1`)
- `--panel-bg-opacity`: major panel/chrome background mix percentage (`0%` to `100%`) used to let backdrop wallpaper show through

Example:

```json
"variables": {
  "--tab-inactive-opacity": "0.60",
  "--panel-bg-opacity": "84%"
}
```

Recommended starting points:

- `--panel-bg-opacity: "80%"` to `"92%"` for subtle translucency
- `--tab-inactive-opacity: "0.55"` to `"0.75"` for readable but dimmed inactive tabs

---

## Build and Test Workflow

1. Copy an existing theme JSON in `packetsnitch/themes`.
2. Rename file and update `id`/`name`.
3. Modify `variables` (and optional `logoImage` / `backdropImage`).
4. Open **Settings → General** and select your theme.
5. Save settings.
6. If needed, reopen Settings or restart the app to refresh newly added files.

---

## Troubleshooting

Theme does not appear in Settings:

- Confirm file extension is `.json`.
- Confirm JSON is valid.
- Confirm `variables` exists and has at least one `--variable` string value.
- Confirm the file is in `~/.config/PacketSnitch/themes` or `C:\Users\Username\AppData\Roaming\packetsnitch\themes`.
- Make sure the variables are in the correct *places in the json*, check all *commas* are where they should be, and make sure variables are *not duplicated*.

Theme appears but styles do not change:

- Confirm variable names exactly match CSS variable names used by the app.
- Confirm values are valid CSS strings (`#hex`, `rgb(...)`, numeric string for opacity).

Logo does not render:

- Confirm `format` is `png`, `jpg`, or `jpeg`.
- Confirm base64 payload is valid and non-empty.
- Remove line breaks/whitespace from base64 if needed.
- A good way to get a valid base64 for an image is: `cat image.png | base64 -w0 | wl-copy`

Backdrop wallpaper does not render:

- Confirm `backdropImage.format` is `png`, `jpg`, or `jpeg`.
- Confirm `backdropImage.base64` is valid base64.
- If using custom runtime themes, ensure you edited the active file in `userData/themes` and restart the app if needed.

Wallpaper renders but is hard to notice:

- Lower `--panel-bg-opacity` (for example from `100%` to `70%`).
- Ensure your panel surfaces are not fully opaque overrides in the selected theme.

---

## Plugins Reference

PacketSnitch includes a built-in plugin engine with install, inspect, enable/disable, runtime loading, failure tracking, and uninstall workflows.

This section covers:

- Where plugin files are stored at runtime
- Plugin package/manifest requirements
- Runtime lifecycle (`init`/`dispose`) and host context
- Safe plugin loading behavior and compatibility checks
- A complete `hello-snitch` plugin tutorial with full sample code

---

## Plugin Runtime Locations

PacketSnitch stores plugin runtime files under the app `userData` directory:

- Plugin registry: `userData/config/plugins.json`
- Installed zip packages: `userData/plugins/packages/`
- Extracted plugin code: `userData/plugins/installed/`

Registry entries persist enabled state, priority, failure counts, compatibility metadata, and install paths.

---

## Plugin Package Format

Plugins are installed from a `.zip` file via **Settings → Plugins → Install Plugin Zip**.

A plugin zip must contain a `plugin.json` manifest and a runtime entry file (defaults to `plugin.js` unless `entry` is set in the manifest).

Archive safety and validation behavior:

- Unsafe archive paths are rejected (`..`, absolute paths, invalid extraction paths).
- `plugin.json` must parse as a JSON object.
- Required fields:
  - `pluginName` (or `name` fallback)
  - `pluginVersion` (or `version` fallback)
  - `capabilities` (non-empty array)
  - `compatiblePacketsnitchVersions` (non-empty array)
- Optional metadata:
  - `author`, `authorHomepage`, `updateUrl`, `priority`, `entry`
- Version compatibility is checked before install; incompatible plugins are rejected.
- Declared capabilities are shown to the user during install review before confirmation.
- Capability tokens are normalized to lowercase and de-duplicated at runtime.

---

## Plugin Lifecycle and Runtime Contract

When a plugin is enabled, the frontend loads it through `window.pluginapi.loadRuntime(...)`.

Accepted runtime export styles:

- Export an object with `init(context)`
- Export a function (called as the initializer)

When disabling/unloading, PacketSnitch calls (if present):

- `dispose(context)`
- else `deinit(context)`
- else `shutdown(context)`

The runtime context includes:

- `plugin`: normalized plugin registry entry
- `packetsnitchVersion`: current app version
- `permissions`: permission helpers (`list`, `has`, `assert`, `catalog`)
- `api`: capability-gated helper namespaces (`version`, `ui`, `fs`, `network`, `packetsnitch`, `backend`, `capture`, `stats`, `keystore`, `filter`)
- `documentRef`: guarded DOM handle (writes require `ui.dom.write`)
- `windowRef`: guarded window handle (writes require `ui.dom.write`)
- `statusUpdate(message)`: status bridge (requires `ui.statusbar.modify`)
- `writeLogEntry(message)`: app activity log bridge (requires `plugin.log.write`)

### Capability Catalog (Dot Notation)

Canonical source file: `src/preload.js` (`PLUGIN_CAPABILITY_CATALOG`)

- `version.read`
- `ui.dialog.add`
- `ui.dom.write`
- `ui.tabs.create`
- `ui.tabs.modify`
- `ui.contextmenu.create`
- `ui.contextmenu.modify`
- `ui.statusbar.modify`
- `fs.read`
- `fs.write`
- `fs.execute`
- `fs.chmod`
- `network.fetch.http`
- `network.socket.listen`
- `network.socket.connect`
- `packetsnitch.functions.use`
- `packetsnitch.functions.overwrite`
- `backend.talk`
- `packet.metadata.read`
- `session.pcap.read`
- `stats.json.read`
- `keystore.read`
- `keystore.write`
- `filter.query`
- `plugin.log.write`

### New Data Access and Filter APIs

The following APIs were added for plugin data access and querying:

- `context.api.capture.getCurrentPacketKey()` (requires `packet.metadata.read`)
- `context.api.capture.getCurrentPacketMetadata()` (requires `packet.metadata.read`)
- `context.api.capture.getCurrentStreamTuple()` (requires `packet.metadata.read`)
- `context.api.capture.getSessionPcapSource()` (requires `session.pcap.read`)
- `context.api.stats.getJson()` (requires `stats.json.read`)
- `context.api.keystore.getSessionEntries()` (requires `keystore.read`)
- `context.api.keystore.addSessionEntry(entry)` (requires `keystore.write`)
- `context.api.keystore.addSessionEntries(entries)` (requires `keystore.write`)
- `context.api.filter.query(expression, options)` (requires `filter.query`)

`context.api.filter.query(...)` supports two modes:

- Background mode (`{ mode: "background" }`): executes filter matching via capture-store without applying the filter in the visible UI.
- UI mode (`{ mode: "ui", trackHistory?: boolean }`): applies the filter through the renderer UI path and returns matched packet keys.

Example:

```js
const packetMeta = context.api.capture.getCurrentPacketMetadata();
const statsJson = context.api.stats.getJson();
const writeResult = context.api.keystore.addSessionEntry({
  type: "secret",
  label: "Plugin Generated Token",
  content: "example-token",
  source: "plugin-manual",
});
const keysBg = await context.api.filter.query("ip.src.addr: 10.0.0.1", {
  mode: "background",
});
const keysUi = await context.api.filter.query("tcp.dst.port: 443", {
  mode: "ui",
  trackHistory: true,
});
```

Runtime policy behavior:

- Capabilities are enforced for guarded host bridges (`context.api.*`, `context.permissions.*`, guarded `documentRef`/`windowRef`, `context.fetch`, `statusUpdate`, `writeLogEntry`).
- Sensitive operations on guarded APIs are denied unless the required capability is declared.
- Denied operations are logged to Activity Log with plugin ID and reason.
- Exact tokens, `*`, and namespace wildcards (for example `network.*`) are supported by capability matching.
- This is not an OS/container sandbox; plugins should use guarded APIs to remain compatible with policy enforcement.

Legacy alias normalization:

- `ui.message` -> `ui.statusbar.modify`
- `ui.tab` -> `ui.tabs.create`
- `ui.contextmenu` -> `ui.contextmenu.create`
- `filesystem.read` -> `fs.read`
- `filesystem.write` -> `fs.write`
- `documents.write` -> `ui.dom.write`
- `network.fetch` -> `network.fetch.http`
- `status.wrap` -> `packetsnitch.functions.overwrite`

Failure handling and safety:

- Runtime errors are shown in the Settings Plugins error panel.
- Critical failures increment per-plugin failure count.
- Plugins auto-disable when failure count reaches threshold.
- Threshold can be global or per-plugin override.

---

## hello-snitch Complete Tutorial

The sample plugin is in `samples/plugins/hello-snitch`.

It demonstrates:

1. Creating a custom tab + panel in the PacketSnitch UI.
2. Adding an action into the global context menu.
3. Reading/writing a local file (`~/Documents/hello-snitch-version.txt`).
4. Fetching remote data over HTTPS.
5. Wrapping host callbacks safely and restoring on dispose.

### Step 1: Create plugin directory

```bash
mkdir -p my-plugin
cd my-plugin
```

### Step 2: Create manifest (`plugin.json`)

Use this complete sample manifest:

```json
{
  "pluginName": "hello-snitch",
  "version": "1.0.0",
  "pluginVersion": "1.0.0",
  "author": "oxagast",
  "authorHomepage": "https://packetsnitch.com",
  "updateUrl": "https://packetsnitch.com/plugins/hello-snitch",
  "capabilities": [
    "version.read",
    "ui.dialog.add",
    "ui.dom.write",
    "ui.tabs.create",
    "ui.tabs.modify",
    "ui.contextmenu.create",
    "ui.contextmenu.modify",
    "ui.statusbar.modify",
    "fs.read",
    "fs.write",
    "network.fetch.http",
    "packetsnitch.functions.use",
    "packet.metadata.read",
    "session.pcap.read",
    "stats.json.read",
    "keystore.read",
    "keystore.write",
    "filter.query",
    "plugin.log.write"
  ],
  "compatiblePacketsnitchVersions": [
    ">=2.0.0"
  ],
  "priority": 100,
  "entry": "hello.js",
  "description": "Comment-heavy tutorial plugin showing UI tab creation, context menu action wiring, file IO, remote fetch, and safe callback wrapping patterns."
}
```

### Step 3: Create runtime (`hello.js`)

Use this complete `hello-snitch` runtime script:

```js
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
    const response = await fetch("https://api.github.com/repos/oxasploits/PacketSnitch", {
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
```

### Step 4: Zip the plugin

Create a zip where `plugin.json` is included in the archive content (root or subdirectory).

Example from inside your plugin folder:

```bash
zip -r hello-snitch.zip plugin.json hello.js
```

### Step 5: Install and run in PacketSnitch

1. Open **Settings → Plugins**.
2. Click **Install Plugin Zip**.
3. Select your zip.
4. Review declared capabilities in the install confirmation prompt.
5. Confirm installation.
6. Ensure the plugin is enabled in the plugin manager list.

After install, PacketSnitch loads enabled plugins and calls `init(context)`.

### Step 6: Verify behavior

- A new `hello` tab button appears.
- The plugin panel shows PacketSnitch version text.
- A context-menu action `Open Hello` appears.
- A file is written to `~/Documents/hello-snitch-version.txt`.
- Clicking **Fetch Example Data** requests repository metadata from GitHub.
- Clicking **Try Unauthorized chmod** demonstrates capability denial unless `fs.chmod` is granted.

---

## Plugin Authoring Checklist

- Keep IDs/selectors unique to avoid host UI collisions.
- Clean up all DOM/event handlers in `dispose()`.
- Guard all host-bridge calls with capability checks (`typeof ... === "function"`).
- Handle network and file errors gracefully.
- Treat `capabilities` as explicit user-visible permission intent.
- Keep compatibility constraints current in `compatiblePacketsnitchVersions`.

---

## Plugin Troubleshooting

Plugin zip will not install:

- Confirm the archive contains `plugin.json`.
- Confirm required manifest fields are present and non-empty.
- Confirm `compatiblePacketsnitchVersions` matches your installed app version.
- Confirm the plugin zip path is a real file and not a folder.

Plugin installs but does not run:

- Confirm plugin is enabled in **Settings → Plugins**.
- Check **Plugin Errors** in Settings for runtime failures.
- Confirm your runtime exports an `init(context)` function or a callable function export.

Plugin loads but unload leaves UI artifacts:

- Implement `dispose(context)` and remove all injected UI elements/listeners.
- Restore any wrapped callbacks or overwritten references during dispose.
