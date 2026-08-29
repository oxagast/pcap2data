---
applyTo: "**"
---

# AGENTS.md — PacketSnitch

> Concise, actionable guidance for AI coding agents working in this
> repository. **Link, don't embed** — every section below points at
> the canonical source so the file stays short and the codebase stays
> authoritative.

---

## 1. Project shape

PacketSnitch is a desktop **Electron + Python** packet-capture analyzer
shipped via electron-forge makers (Squirrel/DEB/RPM/ZIP). The renderer
talks to the Python backend (`snitch`/`snitch-extract`, PyInstaller-bundled)
over TCP or HTTP; the backend talks to a separate **catalog server** for
themes, licenses, and metrics.

| Layer | Where | Role |
| --- | --- | --- |
| Main process | [`src/main.js`](src/main.js) | IPC, settings, Ollama/Cloud, plugins, themes, archive extraction, metrics transport |
| Preload | [`src/preload.js`](src/preload.js) | `contextBridge` — `modelsapi`, `captureapi`, `validkeysapi`, etc. |
| Renderer | [`src/ui/main-frontend.js`](src/ui/main-frontend.js) (and `src/ui/main-frontend/*`) | UI orchestrator + sub-factories |
| Backend | [`src/backend/`](src/backend/) | Python analyzer (TShark/Scapy, PCAP parsing) |
| Build | [`forge.config.js`](forge.config.js), [`webpack.*.config.js`](webpack.main.config.js) | electron-forge + webpack 5 |
| Catalog server | external `https://catalog.packetsnitch.com:9021/` | Themes, licenses, Paddle checkout |

> Renderer modules in `src/ui/main-frontend/*` are wired into
> `main-frontend.js` via factory helpers (`createThemesCatalogHelpers`,
> `createSettingsFormHelpers`, `createPacketDetailViewHelpers`, …) — see
> the [main-frontend refactor note](memories/repo/main_frontend_refactor.md)
> for the split history.

---

## 2. Build, test, run

Use the npm scripts (workspace tasks at the top of the editor mirror
these). Run from the repo root.

| Task | Command | Notes |
| --- | --- | --- |
| Install (JS) | `npm install` | |
| Install (Python deps) | `pip3 install -r src/backend/requirements.txt --break-system-packages` | see [pep668 note](memories/repo/pep668_externally_managed.md) |
| Build backend | `npm run build:backend` | Produces `src/backend/snitch` (+ `snitch-extract`) via PyInstaller; rebuild after editing `src/backend/**/*.py` |
| Run dev | `npm start` (electron-forge) | Renderer is hot-reloaded; backend is invoked via `src/backend/snitch.py` |
| Run backend tests | `npm run test:backend` | `pytest tests/test_backend_compile.py tests/test_backend_json.py tests/test_backend_server.py --maxfail=1` through `scripts/with-libs-path.js` |
| Run frontend tests | `npm run test:frontend` | `jest --runInBand` over `tests/**/*.test.js` |
| All tests | `npm run tests` | |
| Package installer | `npm run make` | `build:deps` + `patch` + `build:backend` + `build:extractor` + electron-forge make |

After touching `src/backend/**/*.py`, **always rebuild the backend**
(`npm run build:backend`) before running dev — Python sources are not
hot-reloaded.

> If `npm run start` or `make` fails on a fresh clone, re-run
> `npm install` (the `node_modules` tree must match `package-lock.json`).
> See the [build cache note](memories/repo/build_cache.md) for the
> per-platform binary outputs.

---

## 3. Architecture decisions that surprise newcomers

These are the load-bearing choices the codebase makes. Re-check the
linked code before "fixing" what looks like a bug.

- **Ollama is optional.** The `ollama` npm package is loaded in a
  guarded `try/require` ([`src/main.js`](src/main.js) ~line 26). If
  it's missing, LLM features silently disable rather than crashing
  the GUI. New code must preserve this property — wrap any new Ollama
  client surface in `isOllamaClientModuleAvailable()`.
- **Locked settings.** The catalog server URL, refresh interval,
  `allowInsecureTlsEndpoints`, and metrics endpoint are hard-coded
  constants in `src/main.js` and `src/settings.js`. Don't try to
  expose them in the Settings UI — see the comments above
  `DEFAULT_THEME_SERVER_BASE_URL` in [`src/main.js`](src/main.js) for
  the rationale.
- **CSP is intentionally permissive.** `default-src '*'` is set
  globally so plugin `network.fetch.http` calls work; the per-host
  plugin capability is the gate that matters. See the
  [plugin CSP diagnosis note](memories/repo/plugin_csp_diagnosis.md).
- **`extraResource` layout.** Backend binaries live directly under
  `process.resourcesPath` (no subdir). `getModelsLibraryFilePath`
  and friends assume this — do not introduce a `bin/` subdir.
- **Squirrel elevation gate.** Install hooks run PowerShell + `net
  session` to detect elevation. The handler short-circuits on
  non-Windows. See the [Windows installer elevation guard
  note](memories/repo/windows_installer_elevation_guard.md).

---

## 4. LLM / Ollama model subsystem (the **models** area)

> This section is the authoritative entry point for any change to
> the model catalog, Ollama integration, or LLM settings. Read it
> before touching `config/models.json`, the `modelsapi` bridge, or
> anything in [`src/ui/main-frontend/themes-catalog.js`](src/ui/main-frontend/themes-catalog.js).

### 4.1 Data flow at a glance

```
config/models.json (bundled)
        │
        │ read at startup via getBundledModelsLibraryFilePath()
        ▼
getBundledOllamaModels()  ──►  ollamaModelsCache  ──►  IPC: get-ollama-models
        │                                                       │
        │  also seeded into <userData>/config/models.json        │
        │                                                       ▼
        ▼                                          preload → window.modelsapi
ensureModelsLibraryFileExists()                          .getOllamaModels()
                                                                │
                                                                ▼
                                       createThemesCatalogHelpers.loadAvailableOllamaModels()
                                                                │
                                                                ▼
                                          <select id="settings-llm-model"> in Settings tab
```

`ipcMain.handle('llm:generate', ...)` (in [`src/main.js`](src/main.js))
is a separate surface that **consumes** `settings.llm.provider` and
dispatches to the active provider's registered handler in
[`src/llm.js`](src/llm.js) (Ollama for `provider === "ollama"`,
OpenRouter for `provider === "openrouter"`). It does **not** read from
the models catalog — the catalog only feeds the dropdown. A backward-
compat alias `'ollama:generate'` is also registered; new code should
call the canonical `'llm:generate'` channel.

### 4.2 Files involved

| Concern | File | Notes |
| --- | --- | --- |
| Bundled catalog (seed) | [`config/models.json`](config/models.json) | Single-entry shape: `{ "models": [{ "name", "label" }] }`. Add new defaults here. |
| Bundled read + normalization | `getBundledOllamaModels` in [`src/main.js`](src/main.js) (~line 5089) | Reads `config/models.json`, runs `normalizeOllamaModelsLibrary` |
| User-file write | `ensureModelsLibraryFileExists` in [`src/main.js`](src/main.js) (~line 5098) | On first run, seeds `<userData>/config/models.json` from the bundled catalog |
| User-file read | `loadOllamaModelsFromDisk` in [`src/main.js`](src/main.js) (~line 5128) | Falls back to bundled defaults if the user file is empty/missing |
| IPC handlers | `get-ollama-models`, `invalidate-ollama-models-cache` (~line 6150, ~line 6155) | Cached in `ollamaModelsCache`; cleared on `saveSettingsToDisk` |
| Preload bridge | [`src/preload.js`](src/preload.js) (`modelsapi` block, ~line 1589) | Exposes `getOllamaModels` + `invalidateOllamaModelsCache` |
| Renderer wiring | [`src/ui/main-frontend/themes-catalog.js`](src/ui/main-frontend/themes-catalog.js) (`createThemesCatalogHelpers`, `loadAvailableOllamaModels`, `renderLlmModelOptions`, `normalizeOllamaModelEntry`) | State stored in `state.availableOllamaModels`; dropdown re-renders on each `loadAvailableOllamaModels()` |
| Settings form | [`src/ui/main-frontend/settings-form.js`](src/ui/main-frontend/settings-form.js) | Reads `settings.llm.ollamaModel` and `settings.apiKeys.ollamaApiKey`; calls `renderLlmModelOptions` |
| Generate call | `ipcMain.handle('llm:generate', ...)` + backward-compat `ipcMain.handle('ollama:generate', ...)` (~line 2313) | Reads `settings.llm.provider` and dispatches via `generateLlm` in [`src/llm.js`](src/llm.js) (Ollama for `provider === "ollama"`, OpenRouter for `provider === "openrouter"`). |
| Cloud ping | `checkOllamaCloudApi` + `refreshOllamaCloudApiDiagnostics` | Hits `https://ollama.com/api/generate` with `gpt-oss:120b` for reachability |
| Local list | `fetchLocalOllamaModels` (~line 148) | `new Ollama().list()` — only consulted via the bundled `ollama` package |

### 4.3 LLM settings shape

From [`src/settings.js`](src/settings.js) `DEFAULT_SETTINGS.llm`:

```js
llm: {
  ollamaModel: "minimax-m3:cloud",          // selected model
  activeByDefault: false,
  backgroundSummaryGenerationEnabled: true,
  triggerDelaySeconds: 5,
  maxSummaryTokens: 1024,
  ollamaRequestTimeoutSeconds: 300,
  retryCount: 2,
  analysisCompactionThresholdBlubs: 6,
},
apiKeys: { ollamaApiKey: "" }               // used for cloud (ollama.com) calls
```

The `models.json` schema is **loose** — entries may be either a string
or `{ name?, model?, value?, label }`. `normalizeOllamaModelEntry` in
`src/main.js` handles both. Comments are introduced with `#` (lines
that start with `#` are filtered out by `normalizeOllamaModelName`).

### 4.4 When you add a new model to the bundled catalog

1. Edit [`config/models.json`](config/models.json).
2. Use `{ "name": "<model-id>", "label": "<human label>" }` for new
   entries. Strings are also accepted for backwards compatibility.
3. Do not remove the existing `minimax-m3:cloud` entry — it is the
   shipped default in `DEFAULT_SETTINGS.llm.ollamaModel`.
4. No code changes required: `getBundledOllamaModels` reads the file
   at startup and `ensureModelsLibraryFileExists` seeds the user file
   on first run. New users will see the new option; existing users
   keep their overrides until they reset.
5. After editing, run `npm run test:frontend` to catch any Jest
   snapshots that lock the dropdown order.

### 4.5 When you change the Ollama client surface

- The `ollama` package is loaded via guarded `try/require`. Any new
  function you call on the imported `Ollama` constructor must be
  gated by `isOllamaClientModuleAvailable()`.
- `ollamaFetch` wraps `undici` with a per-timeout dispatcher cache.
  New fetch paths that need a different timeout should reuse
  `getOllamaFetch(timeoutMs)` instead of re-rolling their own.
- The `llm:generate` IPC handler (and its `ollama:generate` alias)
  is currently the **only** path that issues a generate call. If
  you add a streaming variant, model it on the existing handler
  (try/catch around `setLlmDiagnostics`, `appendActivityLogLine`)
  so diagnostics stay consistent.

### 4.6 Testing the models subsystem

There is currently **no Jest coverage** for the model catalog. If
you add tests, place them in `tests/` (the existing
`themes-catalog`-style tests live there). Test seams to cover:

- `normalizeOllamaModelEntry` (string vs object shapes, comment
  filtering, dedup by `value`)
- `loadOllamaModelsFromDisk` (missing/empty/garbage file falls back
  to bundled)
- `getBundledOllamaModels` (integration with `config/models.json`)

Backend tests (`pytest`) do not exercise the models surface —
keep new Python-side tests in `tests/test_backend_*.py`.

---

## 5. Conventions the agent should follow

- **Settings go through `normalizeSettings`.** Never write raw fields
  to `settings.json`; use the helpers in `src/settings.js` so legacy
  fields survive a round-trip.
- **IPC is one-way by default**; return values are wrapped in
  `{ success, error? }` or `{ ok, error? }`. Match the convention of
  the handler you're adding next to.
- **Activity log lines** are written via `appendActivityLogLine(line)`
  with a `[<iso>][<scope>][<origin>]` prefix. See
  `logLlmDiagnostics` for the LLM-specific template.
- **Renderer state is module-level `let`.** When extracting helpers
  into `src/ui/main-frontend/*`, follow the factory pattern: define
  inside-block state in the factory closure, accept `state`/`getter`
  for the outside-owned bits. See
  [main-frontend refactor note](memories/repo/main_frontend_refactor.md).
- **Diagnostic pill state is cached in the main process.**
  `cachedOllamaInstalled`, `cachedOllamaServerListening`,
  `cachedOllamaCloudApiReachable`, etc. are the source of truth; the
  renderer only ever reads via `ipcMain.handle('get-llm-diagnostics')`.

---

## 6. Pitfalls and foot-guns

- **`ollama` is not bundled in the renderer.** Don't import it from
  `src/ui/**` — it lives in the main process only.
- **Don't rename `models.json` in `config/`.** `forge.config.js`
  references `config/models.json` (line ~154) so the file ships in
  the asar; the read path uses `getBundledModelsLibraryFilePath()`.
- **`window.modelsapi` may be undefined** in tests that don't preload
  the bridge. Always guard:
  `if (window.modelsapi?.getOllamaModels) { ... }`.
- **`ollamaModelsCache`** lives in the main process and is reset on
  every `saveSettingsToDisk`. Don't add parallel caches in the
  renderer.
- **Cloud model names** end in `:cloud` (`isOllamaCloudModel`
  helper). The current `minimax-m3:cloud` is a cloud model — local
  Ollama daemon calls with that name will fail. Don't suggest users
  run it via a local `ollama pull`.
- **Renderer-driven `loadAvailableOllamaModels`** swallows errors and
  falls back to the default. If you add stricter error surfacing,
  keep the fallback so a broken IPC bridge doesn't lock the user out
  of changing models.
- **Settings form save path** (`persistSettingsFromForm`) clears
  `ollamaModelsCache` indirectly via `saveSettingsToDisk` — the next
  `get-ollama-models` IPC will re-read. If you add a new "model
  catalog revalidate" UI button, call
  `window.modelsapi.invalidateOllamaModelsCache()` first, then
  `loadAvailableOllamaModels()`.

---

## 7. Where to look first

| If you're changing… | Start at |
| --- | --- |
| Bundled model list | [`config/models.json`](config/models.json) |
| Model dropdown UI | [`src/ui/main-frontend/themes-catalog.js`](src/ui/main-frontend/themes-catalog.js) |
| LLM settings form fields | [`src/ui/main-frontend/settings-form.js`](src/ui/main-frontend/settings-form.js) |
| IPC + cache + `llm:generate` (alias `ollama:generate`) | [`src/main.js`](src/main.js) — search `ollamaModelsCache`, `llm:generate` |
| Ollama cloud API key | `settings.apiKeys.ollamaApiKey` + `checkOllamaCloudApi` |
| LLM-related tests | `tests/**/*.test.js` (none currently); consider `tests/test_ollama_catalog.test.js` |
| Theme catalog (sibling subsystem) | [`src/ui/main-frontend/themes-catalog.js`](src/ui/main-frontend/themes-catalog.js) — the models helpers live in the same factory |
