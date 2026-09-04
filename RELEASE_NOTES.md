# Release Notes

## v2.8.0 - 2026-09-03

**Type:** minor

> ⚠️ **Versioning scheme switch.** This release moves from the prior
> `MAJOR.MINOR.<build-counter>` scheme (e.g. `2.7.1735`) back to a
> classic `MAJOR.MINOR.PATCH` triple. The build-counter third part
> was getting out of order because of a build-tracking bug that
> could bump the counter on stale or aborted builds, which then
> caused release candidates to publish with version numbers that
> didn't reflect their actual chronological order. Starting with
> v2.8.0 we ship a clean `MAJOR.MINOR.PATCH` number per release;
> bump the patch for fix-only releases, the minor for new features,
> and the major when we cross a boundary.
>
> WebSocket transport, eight new protocol decoders (MNDP, Modbus,
> S7comm, DNP3, CDP, HSRP, LACP, OSPF, STP), the Artifacts store
> overhaul, Conv UX polish, a Stats → Conv jump-to-stream shortcut,
> Host Data alignment fixes, and the removed deprecated LLM checkbox.

### ✨ Features

- **WebSocket support + improved OCPF decoder walking** — the backend
  now speaks WebSocket in addition to HTTP for renderer ↔ backend
  communication, enabling bidirectional streaming without the
  polling/chunked-workaround pattern. The OCPF (Open Collaboration
  Protocol Format) decoder's byte-walking logic was also improved for
  better field extraction and boundary handling.
- **MNDP (MikroTik Neighbor Discovery Protocol) decoder** — new Conv
  → Decodes + sidebar renderer for MNDP, the MikroTik Layer 2/3
  neighbour-discovery protocol carried over UDP/5678 (broadcast).
  The decoder walks all known TLV types — MAC Address, Identity,
  Version, Platform, Uptime (centiseconds), Software ID, Board,
  Unpack, IPv6/IPv4 Address, and Interface Name — and auto-detects
  via the same CDP-style byte-heuristic cascade (gated on the
  mandatory first TLV being type 1 / MAC Address, length 6, per
  Wireshark's dissector). Registered in `SUPPORTED_DECODER_PROTOS`,
  `PROTOCOL_DECODER_HINTS` (`mndp`, `mikrotik-neighbor-discovery`),
  and `PORT_DECODER_HINTS` (5678).
- **Industrial protocol decoders — Modbus, S7comm, DNP3 (Conv →
  Decodes)** — three new Conv stream decoders handle SCADA/ICS
  traffic: **Modbus** (function codes 1–23, coils/discretes/registers,
  exception responses), **S7comm** (Siemens S7 communication,
  setup, read/write, cyclic, PLC-stop, and diagnostics), and
  **DNP3** (Distributed Network Protocol, data objects, binary/analog
  inputs/outputs, control/cooking). All three are registered in
  `SUPPORTED_DECODER_PROTOS` and auto-detected via
  `PROTOCOL_DECODER_HINTS` / `PORT_DECODER_HINTS` for ports 502
  (Modbus), 102 (S7comm), and 20000 (DNP3).
- **Network-control / discovery protocol decoders — CDP, HSRP, LACP,
  OSPF, STP (Conv → Decodes + sidebar)** — five more Conv decoders
  round out the LAN/network-control coverage: **CDP** (Cisco
  Discovery Protocol), **HSRP** (Hot Standby Router Protocol),
  **LACP** (Link Aggregation Control Protocol), **OSPF** (Open
  Shortest Path First), and **STP** (Spanning Tree Protocol). All
  ship in both `src/backend/decoders/` and `src/ui/decoders/conv/`
  with matching sidebar renderers in `src/ui/decoders/main/`, are
  registered in `SUPPORTED_DECODER_PROTOS`, and auto-detect via
  the standard `PROTOCOL_DECODER_HINTS` / `PORT_DECODER_HINTS`
  machinery. Coverage: `tests/test_backend_ospf_decoder.py` and
  `tests/test_backend_stp_decoder.py`.
- **Artifacts store overhaul (replaces Keystore)** — the former
  **Keystore** panel was rebuilt into a broader **Artifacts** store
  that now handles arbitrary file artifacts alongside keys and
  credentials. Artifacts are typed (`wifi-wep`, `wifi-wpa-psk`,
  `wifi-pmk`, `generic-secret`, `file`, etc.), each carries a
  name/description/timestamp, and the panel was reorganised with
  better grouping, search, and bulk-operations support.
- **Conv UX improvements — image no-op / partial data handling,
  decoder dropdown selection, protocol autodetection fix** — the Conv
  output renderer now correctly handles image streams with no-op
  transforms and partial data without cutting off renders. The
  Decodes dropdown selection UX was improved for faster protocol
  switching. Protocol autodetection was tightened to reduce false
  positives on non-protocol traffic that happened to look like
  valid protocol headers.
- **Stats → Conv "jump to protocol decoder" context menu** — right-
  clicking an artifact on the Stats tab now offers a context-menu
  entry that jumps directly to Conv's Protocol Decoder view on the
  stream that produced the artifact, removing the manual
  "find the stream, open Conv, pick the decoder" workflow.
- **Host Data view alignment overhaul** — the Host Data panel's
  long-standing alignment issues were fixed end-to-end: column
  borders, header rows, and per-row field renderers now line up
  consistently across resizes and across the panel's collapsible
  groups.
- **Removed deprecated "Use LLM" checkbox** — the legacy
  `settings.capture.useLlm` field and its associated UI control were
  removed. LLM integration is now always available when an LLM
  provider is configured; the checkbox was redundant with the
  provider/model selection controls.
- **Summarization pipeline improvements** — internal refinements
  to the LLM summarization pipeline in the data tools panel
  (`src/ui/panels/data-tools-llm-summarizer.js`,
  `src/ui/panels/data-tools-panel.js`) for better chunking and
  output assembly.
- **PCAP import cleanup hardening** — while zeroing capture state in
  preparation for a new PCAP import, log output is now suppressed
  and external function calls to non-localhost sites are blocked, so
  a partially-zeroed state can't leak data or fan out telemetry to
  remote endpoints mid-transition.

### 🐛 Fixes

- **Duplicate data in the artifacts store** — fixed a bug where
  re-running a capture could double-count artifact entries in the
  store; the store now correctly reuses existing entries by key
  instead of creating duplicates.
- **Conv search/replace alignment** — the search-and-replace bar in
  Conv is now visually and functionally aligned with its manual carve
  counterpart, with consistent state tracking across both paths.
- **Autoselectable decoder restrictions tightened in Conv** — the
  heuristic that lets Conv auto-pick a decoder was further
  restricted so plain-text and other non-protocol streams are no
  longer misrouted to a specialised decoder when the bytes happen to
  match a header shape.
- **Dropdown transparency bug** — fixed a regression where the
  LLM/Settings dropdowns rendered with a transparent background
  against certain themes; they now use the standard theme surface
  fill.

## v2.7.1736 - 2026-09-01

**Type:** minor

> Session library import — bring exported sessions back into the
> picker without hunting for the sessions directory.

### ✨ Features

- **Session picker → Import** — the saved-sessions picker now has an
  **Import** button next to **New Session**. Clicking it opens a file
  dialog, validates the selected file against the expected
  PacketSnitch session structure, prompts for a destination name, and
  writes the session into the library so it shows up in the list and
  can be opened like any other saved session. This replaces the
  manual "find the sessions directory and copy the file in" workflow.
  The canonical import format is the gzipped-BSON `.psb` produced by
  the existing **Export** action; legacy `.pss` / `.pss.gz` / `.json`
  exports are still accepted for backward compatibility but surface a
  deprecation notice prompting the user to re-export as `.psb`. The
  validation lives in a new dependency-free module
  ([src/session-format.js](src/session-format.js)) that both the
  main-process import handler
  ([src/main.js](src/main.js) `session-import` IPC) and the renderer's
  session-name prompt round-trip consume, so an invalid file is
  rejected with a precise error (missing `host` map, empty host map,
  non-array host entry, non-object packet, etc.) before anything is
  written to disk. The preload bridge exposes
  `window.sessionsapi.importFromFile()`,
  `onImportPromptName(callback)`, and `sendImportNameResult(name)`,
  and the picker panel
  ([src/ui/panels/session-picker.js](src/ui/panels/session-picker.js))
  reuses the existing session-name dialog for the destination prompt.

## v2.7.1735 - 2026-08-31

**Type:** minor

> Theme engine overhaul, OpenRouter LLM provider, Conv data
> transformations, ISO 8583 decoder, and a VirusTotal results panel
> that remembers every lookup — plus the usual round of polish.

### ✨ Features

- **OpenRouter LLM provider (Settings → LLM)** — PacketSnitch now ships a
  first-class OpenRouter.com integration alongside the existing Ollama
  surface. The Settings → LLM sub-tab exposes a **Provider** dropdown
  (Ollama / OpenRouter) that drives the rest of the UI: choose a
  provider, then pick a model from that provider's bundled catalog.
  OpenRouter ships with five defaults (`openai/gpt-4o-mini`,
  `openai/gpt-4o`, `anthropic/claude-3.5-sonnet`,
  `google/gemini-pro-1.5`, `meta-llama/llama-3.1-405b-instruct`) in
  `config/models.json` under a new `openrouter.defaultModels` block,
  the main process seeds `<userData>/config/models.json` on first run
  via the new `ensureModelsLibraryFileExists` openrouter branch, and
  the renderer reads it through the new `openrouter-api` preload
  bridge (`listModels` / `getModel` / `getStatus` + a 30s
  `cachedOpenRouterLastLookup` diagnostic probe so the zero-cost
  reachability check never gets conflated with a real generation).
  Generation routes through a dedicated `generateOpenRouter` handler
  in [src/llm.js](src/llm.js) that talks to
  `https://openrouter.ai/api/v1/chat/completions`, normalises the
  OpenAI-compatible response back into the Ollama shape the rest of
  the renderer already speaks, and reuses `getFetchForProvider` so
  the per-timeout dispatcher cache (`openrouterDispatcherCache` in
  [src/main.js](src/main.js)) lines up with the existing Ollama
  surface. The API key lives in `settings.apiKeys.openrouterApiKey`,
  the selected model in `settings.llm.openrouterModel`, the timeout
  in `settings.llm.openrouterRequestTimeoutSeconds`, and the
  per-call `{ maxTokens, temperature, think }` overrides from the
  2.6 cycle flow through the same provider-agnostic channel.
- **Theme engine overhaul (Settings → Themes + storefront)** — the
  theme engine was rebuilt around a new shared `src/ui/common-frontend.js`
  helpers module plus a unified theming surface in
  [src/main.js](src/main.js). The catalog now renders license tiers
  (developer / standard / pro) inline with badges and supports
  in-storefront previews sourced from per-theme `theme.json` previews
  with a fixed 400×250 aspect ratio (`themes/smokeshow.json` and the
  other theme JSONs were updated to drop the legacy `preview`
  workaround). A new `themeapi.getLicenseTier` preload bridge ships
  on top of the existing `themes-catalog` IPC, the keystore panel
  surfaces the new tier badge, and the developer tier is wired end
  to end so a developer-licensed theme unlocks correctly on first
  launch. Themes now group consistently in the storefront (by
  license, not by raw `theme.json` key), the Sandbox-mode banner
  reads `paddleEnv` with the legacy `sandbox` flag fallback, and the
  400×250 preview fetch retries once on a transient undici failure
  with a "preview unavailable" fallback. Tests:
  `tests/themes_subtab.test.js`, `tests/test_catalog_portal.py`,
  `tests/test_catalog_admin_api.py`, `tests/test_catalog_list_themes.py`,
  `tests/test_catalog_paddle_poller.py`. The new
  `tests/test_catalog_listable_gate.py` lock-in prevents a theme
  that the catalog hasn't marked as listable from appearing in the
  storefront at all.
- **ISO 8583 financial protocol decoder (Conv → Decodes)** — a new ISO
  8583 decoder ships in both the backend
  (`src/backend/decoders/iso8583.py`) and the Conv decoder
  (`src/ui/decoders/conv/iso8583.js`). It decodes the standard ISO
  8583 message structure: MTI (4 ASCII digits or 2 BCD bytes),
  primary/secondary bitmap (ASCII-hex or binary), and data elements
  per the ISO 8583:1987/1993 field definitions. Supports
  LLVAR/LLLVAR length prefixes in both ASCII and binary modes,
  transparently strips 2- or 4-byte TPDU/message-length framing
  prefixes common in ISO 8583 over TCP, and rejects false positives
  (e.g. HTTP text that happens to start with 4 ASCII digits) by
  validating the BCD MTI against the known MTI table and requiring
  the first data field to parse. Auto-detect routes matching traffic
  (ports 8583, 5000, 5001, 14401) to the new decoder, and the
  Decodes dropdown now offers "ISO 8583 (Financial)". Field values
  that are BCD-packed or otherwise non-printable render as hex in
  the conv decoder table via the new `readAsciiOrHex` helper and
  the `data-tools-proto-hex` CSS class in `renderProtoDecoderOutput`.
  Two sample captures ship for quick smoke-testing:
  `samples/pcaps/iso8583_ascii_sample.pcapng` (port 14401, ASCII-hex
  bitmap) and `samples/pcaps/iso8583_bin_sample.pcapng` (port 14401,
  binary bitmap). Coverage: `tests/iso8583_conv_decoder.test.js` (8
  tests) and `tests/test_backend_iso8583_decoder.py` (6 tests).
- **Data transformations in Conv (`Invert / Endian / Bit-order /
  Transpose`)** — the Conv output panel now exposes a dedicated
  **Data Transformations** block (`#data-tools-transform-row` in
  [src/index.html](src/index.html), wired through
  [src/ui/data-transformations.js](src/ui/data-transformations.js)
  - new `applyDataToolsTransformsToOutput` /
  `resetDataToolsTransforms` handlers in
  [src/ui/main-frontend.js](src/ui/main-frontend.js)). Four
  composable transformations are supported, applied in order:
  **Invert data** (full byte-sequence reversal), **Endianness swap**
  (16-bit or 32-bit word reversal — chosen via a Word radio), **Bit
  order** (reversal of every bit within every byte), and **Transpose**
  (read the bytes row-major into a matrix with the user-specified
  column count and emit them column-major). A **Reset Output**
  button restores the untransformed Conv input bytes; **Apply to
  Output** re-renders the panel and writes a
  `Conv output transforms applied transforms=…` line to the activity
  log. The transformations are pure functions, exported and tested
  in `tests/data_transformations.test.js` (covers reverse, swap,
  bit-order, transpose, error paths, and the composed
  `applyDataToolsTransforms` runner). The Conv input itself is
  never modified — only the displayed output.
- **Threat Intel → VirusTotal results panel (history + multi-result
  cards)** — the Threat Intel sub-tab in
  [src/ui/panels/subnet-calculator-panel.js](src/ui/panels/subnet-calculator-panel.js)
  now keeps every VirusTotal lookup across the session and renders
  them as stacked result cards instead of overwriting a single
  card. The new `virustotalResults[]` array is plumbed through the
  session save/load round-trip (new
  `virustotalResults` key on the threat-intel snapshot), seeded
  from a single historical `threatIntelState.virustotal` value when
  a legacy session is restored, and the IPSum / Tor cards are now
  hidden by default (`#subnet-ti-ipsum-card` / `#subnet-ti-tor-card`
  with `setOptionalThreatIntelCardVisibility`) so the panel only
  shows reputation sources the analyst actually consulted. The
  VirusTotal response object also now exposes the full attribute
  surface (`size`, `type_description`, `type_extension`,
  `type_tag`, `magic`, `tags`, `type_tags`, `magika`, `filecondis`,
  `times_submitted`, `first_submission_date`, `last_submission_date`,
  `last_modification_date`, `last_analysis_results`,
  `sigma_analysis_results`, `sigma_analysis_stats`) plus the
  `raw` payload so the renderer never has to guess. The stats block
  also surfaces `confirmed_timeout` and `failure` / `type_unsupported`
  counters that older builds dropped, and `attributes.names` is
  truncated to a 3-entry sample so legacy renderers don't explode
  the card with hundreds of aliases. The new
  `analysis` lookup type routes `GET /analyses/{id}` and
  `GUI: /file-analysis/{id}` so analysts can walk the full analysis
  chain after uploading a sample. Coverage: the extended
  `tests/threat_intel_virustotal_ui.test.js` plus the new
  analysis-id branch in `tests/test_backend_compile.py` /
  `tests/test_backend_json.py`.
- **Provider-agnostic `llm:generate` IPC channel** — the LLM
  generation IPC handler is now exposed under the canonical
  `llm:generate` channel name, with the legacy `ollama:generate`
  channel kept as a backward-compat alias. The handler reads
  `settings.llm.provider` and dispatches to the active provider's
  registered handler in [src/llm.js](src/llm.js) (Ollama for
  `provider === "ollama"`, OpenRouter for `provider === "openrouter"`),
  so the channel name no longer falsely implies an Ollama-only path
  when OpenRouter is selected. The `llmapi.generate` preload bridge
  in [src/preload.js](src/preload.js) now calls `llm:generate`; the
  handler in [src/main.js](src/main.js) is a shared
  `handleLlmGenerateRequest` function registered under both channel
  names.

### 🐛 Fixes

- **Threat Intel → shorter labels fit smaller windows** — the
  Threat Intel sub-tab's IPSum / Tor / VirusTotal card titles were
  shortened so the three reputation cards no longer overflow on
  default window widths. Wired through
  [src/ui/panels/subnet-calculator-panel.js](src/ui/panels/subnet-calculator-panel.js)
  and [src/index.html](src/index.html).
- **Theme-engine UX plumbing** — the theme engine now controls the
  storefront UX more directly: per-theme `theme.json` previews are
  loaded with a fixed aspect-ratio container (no more stretched
  thumbnails), the license-tier badge in Settings is consistent
  with the storefront rendering, and the developer-license path
  works end-to-end on first launch.
- **Host Data info-pane grouping** — the `current-stream-packet`,
  `current-filtered-packet`, and `timestamp` readouts moved out of
  the top toolbar / `welcome` pane and now live under a dedicated
  **General Information** block (`#general-info-head` +
  `#packet-readouts.packet-readouts` in [src/index.html](src/index.html))
  inside the active-recon scroll, so the analyst no longer loses
  the timestamp when the toolbar overflows. CSS in
  [src/assets/css/style.css](src/assets/css/style.css) (`#packet-readouts.packet-readouts`)
  styles the new block consistently with the existing
  `#protocols` / `#compression` groups.

## v2.6.1629 - 2026-08-20

**Type:** minor

### ✨ Features

- **OpenSSH keystroke-timing decoder (Crypt → OpenSSH sub-tab)** — a full keystroke-reconstruction engine now lives under `src/ui/decoders/ssh-keystrokes/` (`index.js` + `markov.js`, `calibration.js`, `auto-calibrate.js`, `boundary-warmstart.js`, `chunk-label.js`, `chunker-slider.js`, `clock-skew.js`, `backspace-detect.js`, `compression-heuristic.js`, `padding-detection.js`, `session-confidence.js`, `ssdeep.js`, `truth-align.js`, `score-envelopes.js`, `markov-loader.js`, `worker.js`, plus an `export/` barrel). Given a sequence of inter-packet delays from a TCP stream on port 22/2222 the decoder scores each delay against a per-QWERTY-digraph Gaussian model (`src/data/qwerty-model.json`, sourced from Monrose & Rubin / Song, Miller & Stahie / Killourhy & Maxion), runs an N-best Viterbi over printable ASCII to produce the most likely keystroke strings, and renders a Plotly delay histogram. The pipeline is pure (no DOM, no Plotly, no fs/path) so it exercises from Jest and bundles cleanly through webpack. The bundled `shell_corpus_sorted.txt` (a sorted, de-identified shell command corpus) is loaded by the main process at startup via `worker_threads` and pre-cached into `userData`; the renderer pulls it through the new `markovapi` preload bridge (`getUserDataDir` / `getStatus` / `getModel` / `train` / `getCachedShellMarkov`) and the corpus path is resolved across source, dev-bundle, and packaged-install layouts in `resolveMarkovCorpusPath` (`src/main.js`). The new `opensshapi` preload bridge exposes `loadQwertyModel` + `decode`, and `llmapi.generate` lets the renderer ask the main process to forward prompts to the configured Ollama backend with per-call `{ maxTokens, temperature, think }` overrides. The OpenSSH sub-tab ships a full settings surface (`#crypt-openssh-*` controls in `src/index.html`) wired through the new `keystroke` settings block (`markovMinCommandLength`, `concisenessBonusMultiplier`) and the `llm` block (`language`, `llmWeightPercent`, `preset`, `autotuneEnabled`), so the analyst can tune the Markov ranking floor, the short-command bonus, and the LLM re-ranking weight without a restart. Covered by `tests/openssh_keystrokes.test.js`, `tests/{auto_calibrate,boundary_warmstart,chunk_label,chunker_max_packet_wiring,chunker_slider,clock_skew,score_envelopes,ssh_backspace_detection,ssh_keystroke_markov,ssh_keystrokes_compression_heuristic,ssh_padding_detection,ssh_session_confidence,ssh_timing,truth_align,weight_envelope_migration}.test.js`.
- **hashes.com reverse-lookup integration (Conv → Hashes)** — the Hashes sub-tab now has a dedicated **Hash Reverse** section (`#data-tools-hash-reverse-*` in `src/index.html`): paste an MD5/SHA-1/SHA-256/… hash and click **Reverse Hash** to POST it to hashes.com `/en/api/search` and render any plaintext matches, or click **Identify Hash Types** to GET the `/en/api/identifier` endpoint and list candidate algorithms. The main process exposes three new IPC handlers — `hashes-com:search`, `hashes-com:identify`, `hashes-com:diagnostics` — coalescing concurrent callers and caching a recent successful probe for 30s (mirroring the VirusTotal diagnostics path), and the preload bridge exposes `extractapi.hashesComSearch` / `hashesComIdentify` / `hashesComDiagnostics`. The Settings tab renders four pills for the endpoint: reachability, key validity, last cost, and last lookup result, with a `cachedHashesComLastLookup` tracker so the diagnostic probe (zero-credit) never gets conflated with a real reverse. The API key lives in `settings.apiKeys.hashesComApiKey`. Covered by `tests/hash_reverse_helpers.test.js`, `tests/hashes_com_diagnostics.test.js`, and `tests/hashes_com_identifier.test.js`.
- **Crypt → Hashes sub-tab** — the Crypt workspace now opens on a dedicated **Hashes** sub-tab (`#crypt-hashes-panel`, `CRYPT_HASHES_SUBTAB` in `src/ui/main-frontend.js`) that mirrors the Conv → Hashes panel: it reads the current value of `#data-tools-hash-input-reading` and renders all nine digests (MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 + SHA3-256 / SHA3-512, RIPEMD-160, Whirlpool) via the new `renderCryptHashesFromConvInput` helper, so analysts can inspect digests without flipping workspaces. Hashes is now the default Crypt sub-tab on a fresh install. The reverse-lookup UI also gained a **Cross Reference Hash** button alongside the existing one.
- **Lazy packet hydration + backend reuse at startup** — the renderer no longer materialises the full capture into memory up front. `capture-store.js` was refactored to build an in-memory store (`storeId` now `mem-<ts>-<rand>`, no disk write of the `.packets.ndjson` file), and a new `backendEarlyYieldPacketThreshold` setting (~5000 packets) tells the renderer to load the first backend snapshot and then defer until the backend completes, at which point it does a clean full swap — no expensive incremental merge. On GUI startup the bridge now **reuses** an already-running backend on the configured HTTP port instead of spawning a new one (tracked by `reusedExistingBackendAtStartup` in `src/back-comm.js`), eliminating the port-conflict respawn loop that previously churned on large captures. The `backendPacketChunkSize` default dropped 2000 → 500 for smoother progressive pushes. Covered by `tests/listentries_fast_path.test.js`, `tests/test_network_metadata.test.js`, and `tests/wifi_keys_rerun_session_following.test.js`.
- **Per-call LLM overrides + thinking-mode bypass** — `ipcMain.handle('llm:generate', ...)` (with a backward-compat alias `ipcMain.handle('ollama:generate', ...)`) now accepts a second `options` argument (`{ maxTokens, temperature, think }`) that overrides the user's `maxSummaryTokens` / temperature defaults per call. The renderer can pass `think: false` to disable the model's internal-reasoning channel — Ollama cloud models like `minimax-m3:cloud` use thinking mode by default and can consume the entire response budget in reasoning with nothing emitted as `response`; disabling thinking is the most reliable way to get a structured answer back. The new `llmapi.generate(prompt, options)` preload bridge exposes this to the renderer. The OpenSSH decoder uses the override path for its multi-field JSON interpretation.
- **Website moved to its own submodule** — the docs site is now a git submodule at `docs/PacketSnitch-Website` (added to `.gitignore` so the submodule pointer doesn't pollute the tree), the app homepage in `forge.config.js` and `package.json` points at `https://packetsnitch.com/`, and the bundled `shell_corpus.txt` extraResource in `forge.config.js` now references the sorted corpus (`src/data/shell_corpus_sorted.txt`).

### 🐛 Fixes

- **Theme preview loading** — the theme catalog's 400×250 preview fetch now retries once on a transient undici failure and surfaces a "preview unavailable" state instead of leaving a broken image card; the sandbox-banner logic correctly reads `paddleEnv` (with the legacy `sandbox` flag fallback) so test purchases can never be mistaken for real ones.
- **Heatmap convergence animation + backend reuse** — the heatmap's convergence leader lines now animate, and the backend is reused across animation passes instead of being continuously respawned (which never took). The Plotly vendored under `src/assets/vendor/plotly-2.35.2.min.js` is loaded only on the OpenSSH sub-tab so it doesn't slow the main render path.
- **Backend reclaim no longer drops data on re-runs** — the startup reclaim path now stops any current jobs and reuses the running service rather than spawning a conflicting backend; previously the port was held by a stale process and the new backend silently failed to bind.
- **Session-bound state survives wifi-keys reruns** — a `pendingSessionRerunSnapshot` (current session name, filter query, selected host) is taken at the start of a wifi-keys rerun and re-applied when the rerun completes, so the user's session identity and view state survive the silent background re-run. A `sessionExplicitlyClosed` flag distinguishes a user-initiated "new capture" from a background rerun so the Save-Session flow prompts for a fresh name only when the user actually closed the session. Covered by `tests/wifi_keys_rerun_session_following.test.js`.

### 🧪 Tests

- `tests/openssh_keystrokes.test.js` — end-to-end wiring of the OpenSSH sub-tab, `loadQwertyModel`, `decode`, and the `openssh-decode` IPC payload shape.
- `tests/{auto_calibrate,boundary_warmstart,chunk_label,chunker_max_packet_wiring,chunker_slider,clock_skew,score_envelopes,ssh_backspace_detection,ssh_keystroke_markov,ssh_keystrokes_compression_heuristic,ssh_padding_detection,ssh_session_confidence,ssh_timing,truth_align,weight_envelope_migration}.test.js` — per-module coverage of the ssh-keystrokes engine.
- `tests/hash_reverse_helpers.test.js`, `tests/hashes_com_diagnostics.test.js`, `tests/hashes_com_identifier.test.js` — hashes.com search / identify / diagnostics wiring, pill rendering, and the zero-credit diagnostic-vs-real-lookup distinction.
- `tests/listentries_fast_path.test.js`, `tests/test_network_metadata.test.js` — lazy packet hydration + in-memory capture-store refactor.
- `tests/wifi_keys_rerun_session_following.test.js` — session-bound state survives a wifi-keys background rerun.
- `tests/test_regex_issue.test.js`, `tests/packet_timestamp_parse.test.js`, `tests/decoder_layer1_envelope.test.js`, `tests/metrics_tab_tracking.test.js` (extension), `tests/ssdeep.test.js`, `tests/hash_reverse_helpers.test.js` — assorted regressions.

### 🔧 Improvements

- `src/settings.js` now carries the `keystroke` block (`markovMinCommandLength`, `concisenessBonusMultiplier`), the extended `llm` block (`language`, `llmWeightPercent`, `preset`, `autotuneEnabled`), `backend.httpProgressLogMinIntervalMs`, `debug.backendEarlyYieldPacketThreshold`, `backend.backendPacketChunkSize` (2000 → 500), and `apiKeys.hashesComApiKey` — all normalised through `normalizeSettings` so legacy/corrupt values round-trip safely.
- `src/back-comm.js` honours `backend.httpProgressLogMinIntervalMs` to throttle `[Bridge] HTTP progress ...` activity-log lines without affecting renderer data flow, and reuses an existing backend at startup instead of spawning a conflicting one.
- `src/main.js` resolves the bundled Markov corpus across source, dev-bundle, and packaged-install layouts; precomputes the shell-Markov model at startup in a `worker_threads` worker; and exposes the `markov:*`, `hashes-com:*`, and `openssh-*` IPC surfaces.
- `src/preload.js` adds the `markovapi`, `llmapi`, and `opensshapi` bridges, extends `extractapi` with `hashesComSearch` / `hashesComIdentify` / `hashesComDiagnostics`, and extends `themeapi` with `getLicenseTier`.

---

## v2.5.2304 - 2026-08-09

**Type:** minor

### ✨ Features

- **Configurable post-load landing tab (Settings → General)** — a new "Open after capture load" preference lets the user pick which workspace opens after a capture finishes loading. Three options are exposed in the **General** sub-tab as a `<select>` (with help text describing each): **Host Data** (drills into the first packet's hex/ASCII + protocol tree), **Stats** (the at-a-glance Capture Statistics / Map / Anomalies overview), and **List** (the sortable, pcap-ordered packet list). The default is **Stats**, so a fresh install lands on the overview without forcing the user to click a tab — but every choice is one click away on the General settings panel. Stored as `general.defaultTab` in the persisted settings (see `src/settings.js`), normalized against a new `VALID_DEFAULT_TABS` whitelist so a corrupt or stale value can never strand the user on a blank workspace, and read by the new `resolveDefaultLandingTab()` / `openDefaultLandingTab()` helpers in `src/ui/main-frontend.js`. The existing session-state restoration path now also falls back to this preference instead of the hard-coded tab, so a session saved before the default was changed still honors the saved choice while a brand-new capture honors the new preference. The new setting is reflected back into the `<select>` on every `syncSettingsFormFromState()` pass, logs a `Settings updated defaultTab=…` line to the activity log on change (matching the other General settings), and goes through the existing `persistSettingsFromForm()` pipeline so the VirusTotal diagnostics cache invalidation, capture-worker resync, theme re-apply, and metrics-save instrumentation all keep working unchanged.
- **In-app theme catalog (Settings → Themes)** — a full storefront experience now lives inside PacketSnitch. The Themes sub-tab auto-fetches a live catalog from the catalog server (default `https://oxasploits.com:9021/`) on first open, renders a responsive card grid (name, description, price, 400×250 preview), and exposes a "Buy" button that opens the Paddle-hosted checkout in the user's default browser via `shell.openExternal`. Successful purchases deep-link back into PacketSnitch through a new `packetsnitch://checkout-success` deeplink (handler in `src/main.js`), where the main process calls `reconcileThemeLicenses({ force: true })` to pull the newly-licensed theme(s), pre-caches them under `userData/theme-cache/<id>/theme.json` so they work offline, and broadcasts `deeplink:checkout-success` to the renderer with the unlocked theme ids. A 72-hour background recache timer keeps owned-but-not-yet-installed themes warm. The "Sandbox mode" banner above the catalog grid lights up automatically when the server returns `paddleEnv: "sandbox"` (or the legacy `sandbox: true` flag) so test purchases can never be mistaken for real ones.
- **Catalog & purchase hardening** — the catalog server URL, recache interval, and `allowInsecureTlsEndpoints` flag are now hard-coded constants in `src/main.js` (mirrored in `src/settings.js`) so the purchase path can't be redirected or neutralized via settings edits. HTTPS calls to the catalog server (and the metrics endpoint, which shares the same self-signed cert) attach an undici dispatcher with `rejectUnauthorized: false` via a cached `getInsecureThemeServerDispatcher` helper. The `themes-catalog` IPC handler now translates undici's generic `fetch failed` into an actionable hint — plain-`http://` URLs pointing at an HTTPS-only server get a "change the URL to https://" hint, self-signed cert failures with the insecure-TLS flag off get a "enable 'Allow self-signed certificates for the theme server' in Settings → Themes" hint, and unreachable hosts get a "verify the URL and your network" hint. `fetchWithTimeout` now logs `begin / ok / fail` lines (with elapsed-ms, abort status, and a sanitized cause message) to the activity log so transient catalog outages are diagnosable from `activity-log.txt`. The settings-endpoint URL is built with `buildThemeServerUrl(..., { force: "1" })` so a "Refresh Catalog" click bypasses the 60-second license-check cache.
- The top toolbar **Help** button opens the PacketSnitch documentation hub at <https://packetsnitch.com/docu/> in PacketSnitch's own in-app browser window — the same child `BrowserWindow` that the previous behaviour used. The main-process `did-create-window` handler in `src/main.js` locks the child window to whitelisted docs hosts (packetsnitch.com, github.com/oxasploits/PacketSnitch, buymeacoffee.com, virustotal.com), resizes it to 1200×900, strips the menu bar, and tags it with the desktop user-agent. Help is the only in-app link that opens inside PacketSnitch; every other external link (release notes, donate, theme catalog, VirusTotal card, etc.) still routes to the user's default system browser via `shell.openExternal` so the user keeps their existing browser session.
- New Kerberos 5 (`krb5`) Conv decoder (`src/ui/decoders/conv/kerberos.js`): the Decodes sub-tab now exposes a "Kerberos (krb5)" entry that disassembles AS-REQ/AS-REP/TGS-REQ/TGS-REP/AP-REQ/AP-REP/KRB-ERROR/KRB-PRIV/KRB-CRED messages and surfaces pvno, msg-type, realm, cname/sname, KDC options (with the RFC 4120 bit-numbered flags), till, nonce, etype list, ticket (tkt-vno/realm), and an EncryptedData etype + cipher preview. Auto-detect and protocol/port hints (`krb5`, `kerberos`, ports 88/464/750) route matching traffic to the new decoder, and the inline decoder switch in `src/ui/main-frontend.js` + `src/ui/main-frontend-test.cjs` is updated to match.
- **New Conv Decodes dropdown entries + stream decoders for DNS, SNMP, DHCP, and DHCPv6** — the Decodes protocol selector (`#data-tools-proto-select` in [src/index.html](src/index.html)) now offers `DNS`, `SNMP`, `DHCP`, and `DHCPv6` alongside the existing `Kerberos (krb5)` / SIP / SMB entries, and each one is backed by a real Conv stream decoder instead of just a sidebar table. The new files live in `src/ui/decoders/conv/{dns,snmp,dhcp,dhcpv6}.js`, are re-exported from the `src/ui/decoders/conv/index.js` barrel, are routed in the `decodeWithSelectedProtocol` switch in [src/ui/panels/data-tools-panel.js](src/ui/panels/data-tools-panel.js), and are registered with `SUPPORTED_DECODER_PROTOS` in [src/ui/decoders/conv/mime-maps.js](src/ui/decoders/conv/mime-maps.js) so the auto-detect path can pick them. Behaviour summary:
  - **`dns` (port 53)** — splits TCP-framed DNS into 2-byte length-prefixed messages, walks each message's header (id, QR/Opcode/AA/TC/RD/RA/AD/CD, rcode), and parses question + answer/authority/additional sections: label-sequence decoding (RFC 1035 §4.1.4 with compression-pointer dereferencing across message boundaries), QTYPE/QCLASS lookup for A/AAAA/CNAME/MX/NS/TXT/SOA/PTR/SRV/HINFO, and a per-RR resource-record tree showing name/type/class/TTL/rdlength plus the typed rdata preview (A → IPv4, AAAA → IPv6, CNAME → target, MX → preference+exchange, NS → nsdname, TXT → character-string list, SOA → mname/rname/serial/refresh/retry/expire/minimum, SRV → priority/weight/port/target). IPv4/IPv6 A/AAAA rdata is rendered with the existing dotted/colon formatting helpers.
  - **`snmp` (ports 161/162)** — consumes BER-encoded SNMPv1/v2c/v3 PDUs (using the shared `parseAsn1Length` + `decodeBerFromBytes` in [src/ui/decoders/conv/asn1.js](src/ui/decoders/conv/asn1.js) / [ber.js](src/ui/decoders/conv/ber.js)), walks the SEQUENCE-wrapped message, and surfaces the version (`SNMPv1` / `SNMPv2c` / `SNMPv3`), community string, request-id, error-status (`noError` / `tooBig` / `noSuchName` / `badValue` / `readOnly` / `genErr` / `noAccess` / `wrongType` / `wrongLength` / `wrongEncoding` / `wrongValue` / `noCreation` / `noSuchObject` / `noSuchInstance` / `endOfMibView` / `inconsistentValue` / `resourceUnavailable` / `commitFailed` / `undoFailed` / `authorizationError` / `notWritable` / `inconsistentName`), error-index, and a flattened VarBind tree with OID, named-MIB lookup (`1.3.6.1.2.1.1.1.0` → `sysDescr.0`, etc.), and a hex-or-textual value preview.
  - **`dhcp` (ports 67/68)** — walks the RFC 2131 BOOTP/DHCP header (op, htype/hlen, hops, xid, secs, flags `BROADCAST`, ciaddr/yiaddr/siaddr/giaddr, chaddr, sname, file, magic cookie) and then streams the DHCP option list in declaration order, decoding every option from the registry (subnet-mask, router, time-servers, name-server, log-server, cookie/server, lpr-server, impress-server, rlp-server, host-name, boot-file-size, merit-dump-file, domain-name, swap-server, root-path, extensions-path, ip-forwarding, non-local-source-routing, policy-filter, max-datagram-reassembly-size, default-ip-ttl, interface-mtu, all-subnets-local, broadcast-address, router-discovery, router-solicitation, static-routes, trailer-encapsulation, arp-cache-timeout, ethernet-encapsulation, tcp-default-ttl, tcp-keepalive-interval, tcp-keepalive-garbage, nis-domain, nis-servers, ntp-servers, vendor-specific, netbios-name-servers, netbios-dd-server, netbios-node-type, netbios-scope, x-window-fs, x-window-dm, requested-ip, lease-time, option-overload, message-type → `DHCPDISCOVER`/`DHCPOFFER`/`DHCPREQUEST`/`DHCPDECLINE`/`DHCPACK`/`DHCPNAK`/`DHCPRELEASE`/`DHCPINFORM`, server-id, parameter-request-list, message, max-message-size, renewal-time, rebinding-time, vendor-class-id, client-id, rapid-commit, plus any vendor-specific / unknown option as raw hex), surfacing the parsed fields as a tree.
  - **`dhcpv6` (ports 546/547)** — RFC 8415/3315 relay + server/client message decoder: parses the 1-byte msg-type (`SOLICIT`/`ADVERTISE`/`REQUEST`/`CONFIRM`/`RENEW`/`REBIND`/`REPLY`/`RELEASE`/`DECLINE`/`RECONFIGURE`/`INFORMATION-REQUEST`/`RELAY-FORW`/`RELAY-REPL`) + 3-byte transaction-id header, then walks the TLV option stream (client-id, server-id, IA-NA, IA-TA, IAADDR, ORO, preference, rapid-commit, unicast, status-code, vendor-class, vendor-opts, interface-id, reconf-msg, reconf-accept, dns-servers, domain-search-list, sntp-servers, fqdn, leasequery, + recursive nested IAs and relay message options) with proper 16-bit option-length handling. Status-code sub-options are decoded into `Success`/`UnspecFail`/`NoAddrsAvail`/`NoBinding`/`NotOnLink`/`UseMulticast`/`NoPrefixAvail`/etc.
  - `PROTOCOL_DECODER_HINTS` and `PORT_DECODER_HINTS` in [src/ui/decoders/conv/protocol-hints.js](src/ui/decoders/conv/protocol-hints.js) are extended so the inline decoder switch in `src/ui/main-frontend.js` + `src/ui/main-frontend-test.cjs`, auto-detect (`autoDetectProtoFromBytes`), and the `data-tools-proto-select` `<select>` populate the right protocol the first time a user opens Decodes on a DHCP/SNMP/DNS stream. The new tests live in `tests/{dns,snmp,dhcp,dhcpv6}_conv_decoder.test.js` and follow the same pattern as `tests/kerberos_conv_decoder.test.js` (wiring + registry + hints + round-trip fixtures).
- Notes tab is now wired into the Summary tab: every note created on the Notes tab is automatically reflected on the Analysis/Summary tab under a clear "Inferred Data (from Notes)" heading, so the analyst never has to copy/paste observations between the two tabs. Each note carries a new "Mark as verified data (concrete)" checkbox in the Notes editor; toggling it moves the note to a separate "Verified Notes (from Notes)" heading on the Summary tab so concrete analyst-confirmed facts are visually distinct from inferred observations. The flag persists across session save/load.
- Better decodes stream following in Conv (`src/ui/decoders/conv/{index,smb,smb-helpers}.js` + `src/ui/panels/data-tools-panel.js`): the Conv **Decodes** subtab now has a dedicated SMB follow-stream path that walks SMB2 read/write transactions, presents a per-message tree of headers, file content, and offsets, and reuses the unified stream-stack assembly used by other decoders. The new SMB helpers are extracted into `smb-helpers.js` so the inline decoder code stays small and testable.
- **Wifi / 802.11 decryption in the Crypt tab** — the Crypt workspace now has a dedicated **Wifi** subtab (`crypt-wifi-panel` in [src/index.html](src/index.html)) backed by a brand-new 802.11 backend decoder ([src/backend/decoders/wireless_80211.py](src/backend/decoders/wireless_80211.py) + [src/backend/decoders/wpa2_ptk.py](src/backend/decoders/wpa2_ptk.py)). The decoder auto-detects Dot11 / RadioTap frames, walks management/data/control sub-types, and surfaces SSID, BSSID, channel, frame type/subtype, cipher, and crypto metadata. When a WPA2 4-way handshake is present in the capture, the backend derives the per-session PTK (PBKDF2-HMAC-SHA1 PMK → PRF-384 PTK per IEEE 802.11i §8.5.1) and uses the TK portion to decrypt CCMP data frames; WEP and pre-computed PMK keys are also supported. New sample captures `samples/pcaps/wifi-Coherer-Induction.pcap` and `samples/pcaps/wifi-Coherer-Induction-dec.pcap` ship with the release for quick smoke-testing. Wifi keys are managed directly from the Crypt tab (`#crypt-wifi-keystore-list`) with WPA-PSK / WEP / PMK key-type selector, sent to the backend via a new `setBackendWifiKeys` IPC, and the backend is auto-rerun in the background so decrypted frames flow into the rest of the workspace without a manual reload. A "decryptable with my keys" filter and SSID/BSSID substring filters help analysts cut straight to decryptable traffic, and the session keystore is the source of truth — keystore entries of type `wifi-wep` / `wifi-wpa-psk` / `wifi-pmk` are auto-collected and shown in the keystore sub-list.
- **Conv Decodes dropdown entries for EPMAP, LLMNR, NBNS, NBDGM (NetBIOS Datagram), plus upgraded LDAP** — the Decodes protocol selector now offers `EPMAP` (DCE/RPC endpoint mapper), `LLMNR` (link-local multicast name resolution), `NBNS` (NetBIOS name service), and `NBDGM` (NetBIOS datagram service) alongside the existing entries. The LDAP decoder has been substantially upgraded to handle more message types, response parsing, and tree rendering. All four new decoders live in their own files under [src/ui/decoders/conv/](src/ui/decoders/conv/) (`epmap.js`, `llmnr.js`, `nbns.js`, `nbdgm.js`) and are re-exported from the `index.js` barrel; auto-detect and protocol/port hints route the right traffic automatically. Behaviour summary:
  - **`epmap`** — walks the DCE/RPC endpoint mapper (EPM) request/response shape and surfaces the tower/UUID/vers/rhs/flags fields plus the inquiry/insert/delete/replace lookup types.
  - **`llmnr`** — disassembles LLMNR (RFC 4795) queries and responses, including the QR/Opcode/C/TC/T/Z/RCODE bits, question/answer/authority/additional sections with typed rdata preview (A/AAAA/PTR/CNAME/HINFO).
  - **`nbns`** — parses NetBIOS name-encoding (32-byte half-ASCII label) and the RR-type fields (NB, NBSTAT, GENERAL-NAME-SERVICE, etc.), surfacing each entry as a flat list with name/type/class.
  - **`nbdgm`** — NetBIOS datagram service (RFC 1002 §6) decoder: walks the 8-byte header (msg-type, datagram-id, datagram-length, packet-offset, source-name, destination-name) and surfaces both broadcast and unicast datagram types.
  - **`ldap`** (upgraded) — improved search/filters/entries/attribute rendering; entry attributes now surface as a typed tree (DN/objectClass/cn/sn/etc.) with raw bytes for opaque values.
- **Stats → Anomalies sub-tab** — the Stats tab now has a third sub-tab alongside **Statistics** and **Map** called **Anomalies** ([src/ui/panels/stats-panel.js](src/ui/panels/stats-panel.js)). It surfaces four structured anomaly detectors running over the loaded capture:
  - **Portscans** (`detectStatsAnomaliesPortscan`) — flags a single source sweeping many destination ports in a short window (configurable per-source threshold) and renders each finding with source IP, count, and the targeted port list.
  - **Brute-force login bursts** (`detectStatsAnomaliesBruteForce`) — detects repeated failed authentication attempts to a single host on ports 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 110 (POP3), 143 (IMAP), 3389 (RDP), 5900 (VNC), and 389/636 (LDAP) with a per-destination, per-service rolling window.
  - **Baseline packet-length / per-minute outliers** (`detectStatsAnomaliesBaselineOutliers`) — computes rolling per-minute packet-count and average length baselines and flags minutes that drift more than a configurable standard deviation from the mean.
  - **High-entropy cleartext payloads** (`detectStatsAnomaliesEmbeddedContent`) — flags outbound payloads that are both unencrypted and above an entropy threshold (potential covert channels).
  - Findings render as click-to-filter cards in `renderStatsAnomaliesPanel` (clicking a card applies the matching filter expression) and the implementation shares the same `detectProtocolAnomalies` engine with the Threat Intel sub-tab so the two views never disagree.
- **Session Threat Score (Threat Intel sub-tab)** — the Threat Intel sub-tab now leads with a Session Threat Score card (`#subnet-ti-score-card` in [src/index.html](src/index.html), logic in the new [src/ui/panels/threat-intel-scorer.js](src/ui/panels/threat-intel-scorer.js) module). The card shows a 0-100 score with banded pill (`Clean` / `Low` / `Medium` / `High` / `Critical`), a color-graded weight breakdown of every contributing indicator (IPSum hits, Tor exit nodes, VirusTotal malicious / suspicious verdicts, high-entropy cleartext, portscan / brute-force / baseline outliers from the Stats Anomalies tab, public-IP / domain / URL / hash counts, and the current Conv input entropy), and a "Capture Footprint" summary with public IPs / unique domains / URLs / registered hashes / reputation lookups / protocol anomalies. Three actions live on the card: **Recompute** (re-derive the deterministic score), **Get LLM Assessment** (asks the active LLM to summarize the breakdown into a short analyst narrative plus up to 5 concrete next actions), and **Send to Notes** (appends the breakdown to the active Notes tab as a structured note). Every per-target lookup in the Threat Intel sub-tab feeds the next recompute, so the score evolves as the analyst does more lookups. A `globalThis.__THREAT_INTEL_DEBUG__` toggle is exposed for in-renderer debugging.
- **Save Report... submenu on the packet context menu** — saving the analysis summary moved out of the toolbar and into the right-click context menu under a new `Reports...` branch (`#ctx-reports-submenu` / `#ctx-reports-branch` in [src/index.html](src/index.html), wired in [src/ui/fragments/convert-context-menu.js](src/ui/fragments/convert-context-menu.js)). The submenu exposes four formats — **Save Report (Markdown)**, **Save Report (Text)**, **Save Report (HTML)**, and **Save Report (PDF)** — backed by the new `saveSummaryFromContextMenu(format)` handler and the dedicated `saveSummaryAsPdf()` PDF path in [src/ui/main-frontend.js](src/ui/main-frontend.js). When the LLM is enabled, a final distillation pass over the assembled Markdown (dedupe + chronological sort + importance re-rank) runs before the save dialog opens so the file the analyst sees in the dialog is the cleaned-up version. If the LLM is disabled, fails, or the report is too short to warrant a pass, the distiller transparently falls back to the un-distilled report. A new `SUMMARY_DISTILL_SKIP_EMPTY` / `SUMMARY_DISTILL_ERROR` status surface keeps the activity log honest about which path was used. The PDF path reuses the same self-contained HTML the HTML exporter builds and hands it to Electron's built-in `webContents.printToPDF` via the new `save-pdf-report` IPC in [src/main.js](src/main.js), so no third-party PDF dependency is required and the PDF + standalone HTML are visually identical. The Summary workspace header also gets a dedicated **Save as PDF** button (`#summary-save-pdf-btn` in [src/index.html](src/index.html), wired in [src/ui/panels/summary-panel.js](src/ui/panels/summary-panel.js)).
- **WEP (Wired Equivalent Privacy) decryption in the Crypt → Wifi sub-tab** — the 802.11 decoder in [src/backend/decoders/wireless_80211.py](src/backend/decoders/wireless_80211.py) now recognizes `Dot11WEP` frames (in addition to CCMP / TKIP) and decrypts them with the matching `wifi-wep` keystore entry. The new `_wepDecrypt` / `_wepPlaintextLooksValid` helpers take the proper WEP body (3-byte IV + 1-byte KeyID + ciphertext + 4-byte ICV), RC4-decrypt it via `cryptography.hazmat.decrepit.ciphers.algorithms.ARC4` (with a legacy `cryptography.hazmat.primitives.ciphers.algorithms.ARC4` fallback for older installs), verify the standard CRC-32 ICV leniently (real WEP pcaps in the wild often have a corrupt or zeroed ICV), and gate the "ok" verdict on a structural LLC/SNAP + valid-EtherType sanity check so the wrong key never produces a false positive. Supported key sizes: WEP-40 (5 bytes), WEP-104 (13 bytes), WEP-128 (16 bytes) — `_resolveWepKey` accepts all three via the same `wepKeyHex` field. A new `samples/pcaps/wep-A4-81-53-B4-CF.pcap` sample ships with the release (BSSID `c0:4a:00:80:76:e4`, WEP-40 key `A4:81:53:B4:CF`) so analysts can smoke-test the WEP path end-to-end. Coverage: `tests/test_backend_wireless_80211_wep.py` (RC4 parity, sanity-check rejects wrong key, decryptWifiPayload WEP returns the same `{ok, plaintextHex, algorithm, bssid}` shape as the CCMP path) and `tests/test_backend_json.py::test_backend_decrypts_wep_capture_with_hex_key` (end-to-end bridge → backend → decrypted 802.11 frames on the matching BSSID).
- **Wifi keys round-trip through sessions** — saved sessions now carry the 802.11 wifi keys alongside the rest of the keystore, and on session restore the bridge re-sends them to the backend so re-opening a wifi capture still decrypts 802.11 frames without manual re-entry. The renderer-side state machine (`wifiKeysRerunInFlight` flag in [src/ui/main-frontend.js](src/ui/main-frontend.js)) plus the bridge-side `--wifi-keys-file` placement fix in [src/back-comm.js](src/back-comm.js) ensure the silent re-rerun after a successful `setBackendWifiKeys` actually triggers a fresh backend pass and that pass actually produces decrypted output. Covered end-to-end by the new `tests/wifi_keys_rerun_path_mode.test.js` and `tests/wifi_keys_legacy_spawn_placement.test.js`.

### 🐛 Fixes

- **"Restore defaults" button is now confirmable, not destructive** — clicking the **Restore defaults** button in Settings no longer immediately wipes every setting. It opens a new in-app confirmation dialog (`#settings-reset-confirm-dialog` in `src/index.html`) styled like the other confirm overlays ("Restore Defaults" title + descriptive copy: *"This will reset all settings to their default values. Any unsaved changes will be lost. Continue?"*) with explicit `Restore` / `Cancel` buttons, focus auto-moved to `Restore` on open, and full keyboard support (Enter = continue, Escape = cancel) via the new `requestSettingsResetConfirm` / `resolveSettingsResetConfirm` helpers in `src/ui/main-frontend.js`. If the DOM nodes are missing (e.g. very old markup) the helper transparently falls back to `window.confirm` so the destructive action can never silently fail to confirm. The status line now reads `Restore defaults canceled.` when the user backs out, and `Defaults restored.` (plus an activity-log entry `Settings restored defaults`) on success; both branches go through the existing `persistSettingsFromForm({ resetToDefaults })` path that invalidates the VirusTotal diagnostics cache when the saved key changes, re-syncs capture workers, re-applies the theme, and persists the cloned `DEFAULT_SETTINGS` snapshot. A new `resetToDefaults: true|false` metric field is included on every settings-save event so analytics can distinguish a real save from a defaults restore. CSS for the dialog lives alongside the other confirm overlays in `src/assets/css/style.css` (`#settings-reset-confirm-dialog` / `#settings-reset-confirm-description`).
- Fixed decoders bug for single block decodes: when a stream contains exactly one reassembly block, Conv **Decodes** now correctly feeds that block through the decoder pipeline instead of bailing out. Covered by `tests/conv_decodes_stream_stack.test.js`.
- Inline decoder wiring (`src/ui/main-frontend.js`) now matches the dropdown entries — picking a protocol from the inline switch honours the same detection and hints path as the Conv Decodes subtab.
- **Wifi rerun no longer drops decryption on the second run** — the legacy spawn path in `src/back-comm.js` previously staged the per-job `wifi-keys.json` file *inside* `jobOutputDir` and then wiped `jobOutputDir` immediately before launching the backend, so the backend always saw a missing `--wifi-keys-file` and silently skipped 802.11 (AES-CCMP) decryption. The keys file is now staged in `testcaseOutputDir` (a sibling of `jobOutputDir`) so the wipe can't touch it, gets a unique per-job filename (`wifi-keys-<jobId>.json`), and the bridge cleans it up after the backend process closes. The renderer-side rerun fix in `processBackendJsonPathPayload` (honouring `wifiKeysRerunInFlight`) is now actually effective because the backend actually produces decrypted data again. Regression coverage in `tests/wifi_keys_legacy_spawn_placement.test.js`.
- **All-Hosts sentinel survives across snapshot refreshes** — picking the `0.0.0.0` "All Hosts" virtual option in the Host Data target-host dropdown no longer collapses to a single host after a backend progressive snapshot or rerun. The sentinel value is now preserved by `legacyAllHostSentinel` plumbing in the renderer so navigation stays bound to the full packet set even when the snapshot pipeline rewrites the host list. Regression coverage in `tests/legacy_all_host_sentinel.test.js`.
- **Decrypted 802.11 frames no longer masquerade as "WIFI" in the List → App Protocol column** — TCP/UDP/ICMP packets recovered from a decrypted Wi-Fi frame used to be relabelled `WIFI` in the List panel's **App Protocol** column because the backend prepended `"WIFI"` to `packet.decoded_protocols` and the renderer added every decoded name (link-layer included) to its app-protocol candidate set. Two coordinated changes fix this: (1) the backend in [src/backend/snitch.py](src/backend/snitch.py) no longer prepends `"WIFI"` — link-layer identity is already conveyed via `link.proto = "IEEE 802.11"`, and leaving the transport/app-layer values alone keeps the renderer honest about what was actually decoded inside the stripped 802.11 payload; (2) the renderer in [src/ui/panels/list-panel.js](src/ui/panels/list-panel.js) now defensively filters link-layer protocol names (`WIFI`, `IEEE 802.11`, `ETHERNET`, `LINUX COOKED`, `LINUX COOKED V1/V2`, `FRAME`, `LINK`, `RAW`, `LOOPBACK`, `NULL`, `TUN`, `TAP`) out of `collectDecodedProtocolNames` so a legacy `decoded_protocols` payload (e.g. an older hosts.json) can't trick the column into re-labelling decrypted TCP/UDP frames. Decrypted HTTP, SSH, DNS, … flows now surface the real application protocol. Regression coverage in `tests/list_panel_app_protocol.test.js`.
- **Aggressive dedupe in the Summary distillation + compaction LLM prompts** — the export-time distillation pass (`buildSummaryDistillPrompt` in [src/ui/main-frontend.js](src/ui/main-frontend.js)) and every analysis-compaction run (`runAnalysisCompaction`) used to ask the LLM to "deduplicate" in a single short sentence, which the LLM interpreted as "remove exact duplicates" — so the same fact restated in slightly different words (e.g. "the host at 10.0.0.1 reached out to example.com" vs. "10.0.0.1 talked to example.com") survived into the running summary and the saved report, and the same observation accumulated rewrites every time a new blurb was folded into the compacted summary. The fix promotes dedupe to the **most important** rule in the distillation prompt (`AGGRESSIVE DEDUPE`) and adds explicit sub-bullets: collapse every duplicate into a single canonical statement, delete the rest of the copies entirely (don't rephrase them), and — when a fact is summarised at a high level in the Capture Statistics section AND described in an LLM blurb — keep the more detailed version in the LLM-blurb / per-stream section and remove the high-level restatement from the Capture Statistics section. The compaction prompt now carries its own `DEDUPLICATE` rule that covers both (a) within the previously compacted summary and (b) across the new blurbs, and the per-stream `writeSummaryFromLLM` prompt carries a closing "Never rephrase a fact that is already in the running summary" instruction so the blurbs that feed compaction are already deduped before they ever reach `runAnalysisCompaction`. A reader should never feel that the same observation is being repeated in the consolidated Summary tab or in the exported report. Locked in by five new test cases in [tests/summary_stats_weaving.test.js](tests/summary_stats_weaving.test.js) under the new `aggressive dedupe in summary LLM prompts` `describe` block.

### 🧪 Tests

- New `tests/themes_subtab.test.js` exercises the renderer-side theme catalog surface: the `settings-themes-catalog-{list,status,sandbox-banner}` DOM wiring, `themesCatalogIsSandbox` / `themesCatalogPaddleEnv` state, the `setThemesCatalogSandboxBanner` reducer (legacy `sandbox` flag → new `paddleEnv` field), the `themes-catalog` IPC handler shape (returns `sandbox` + `paddleEnv` on success), `reconcileThemeLicenses`'s paddleEnv capture, `fetchWithTimeout` abort semantics, `fetchThemeServerJson` / `fetchThemeServerBuffer` routing through `fetchWithTimeout`, and the preload bridge exposing `listCatalog` over `themes-catalog`.
- Extended `tests/test_catalog_server.py` now drives the full end-to-end purchase round-trip (catalog fetch → Paddle redirect → `checkout-success?transaction_id=…` → `packetsnitch://checkout-success?installUuid=…&themeId=…` deeplink → license reconcile → theme cache write) plus the production vs. sandbox paddleEnv assertion on every catalog response.
- New `tests/kerberos_conv_decoder.test.js` exercises wiring, registry, hints, and AS-REQ/AS-REP round-trips through both the data-tools panel and main-frontend inline paths using hand-built ASN.1 fixtures.
- New `tests/dns_conv_decoder.test.js`, `tests/snmp_conv_decoder.test.js`, `tests/dhcp_conv_decoder.test.js`, and `tests/dhcpv6_conv_decoder.test.js` follow the same pattern as `tests/kerberos_conv_decoder.test.js`: each one imports the new `decode{Dns,Snmp,Dhcp,Dhcpv6}FromBytes` + `normalizeSmbDecoderBytes` + `bytesToHexLower` + `autoDetectProtoFromBytes` + `getPacketProtocolDecoderHint` exports, asserts the dropdown wiring (`SUPPORTED_DECODER_PROTOS.has('dns' | 'snmp' | 'dhcp' | 'dhcpv6')`, `decodeWithSelectedProtocol` switch case coverage), exercises the new `PROTOCOL_DECODER_HINTS` / `PORT_DECODER_HINTS` entries (ports 53 / 161 / 162 / 67 / 68 / 546 / 547 and protocol names `dns`/`snmp`/`dhcp`/`dhcpv6`), and round-trips hand-built fixtures through the decoder — DNS label-sequence + compression-pointer + RR-type decoding, SNMP BER VarBind walks, DHCP option-stream decode (incl. RFC 2132 vendor-encapsulated options), and DHCPv6 msg-type + TLV option stream + nested IA + status-code sub-options.
- New `tests/notes_summary_integration.test.js` covers the inferred/verified routing (`isNoteConcrete`, `createNoteEntry` default + opt-in, `getNotesSummarySection` heading selection, mixed buckets, legacy fallback), `getCurrentSummaryReportMarkdown` ordering, and session save/load round-tripping the `concrete` flag.
- New `tests/conv_decodes_stream_stack.test.js` covers the new SMB follow-stream wiring, the stream-stack assembly pipeline, and the single-block decode regression.
- New `tests/smb_conv_decoder.test.js` exercises the dedicated SMB Conv decoder including header parsing and tree rendering.
- New `tests/summary_stats_weaving.test.js` extensions lock down the new "Inferred Data (from Notes)" / "Verified Notes (from Notes)" summary headings.
- New `tests/summary_stats_weaving.test.js` `aggressive dedupe in summary LLM prompts` describe block adds five regression cases that pin down the stronger dedupe wording in the three LLM prompts that produce the consolidated Summary tab and the exported report: (1) the distillation prompt labels dedupe as the most important rule and carries the `AGGRESSIVE DEDUPE` header; (2) it explicitly forbids reworded restatements of the same fact and instructs the LLM to drop them; (3) it resolves the Capture Statistics / LLM-blurb overlap by keeping the more detailed version in the blurb section and removing the high-level restatement from the Capture Statistics section; (4) the compaction prompt carries its own `DEDUPLICATE` rule that covers both the previously compacted summary and the new blurbs; and (5) the per-stream `writeSummaryFromLLM` prompt carries the closing "Never rephrase a fact that is already in the running summary" instruction so the blurbs that feed compaction are already deduped before they ever reach `runAnalysisCompaction`.
- New `tests/wifi_keys_legacy_spawn_placement.test.js` is a structural regression test that locks in the fix above: it asserts the wifi-keys file is staged in `testcaseOutputDir` (not inside `jobOutputDir`), is not written at the old buggy location, is cleaned up after the backend closes, and the `--wifi-keys-file` flag is still wired into the legacy spawn argv.
- New `tests/wifi_keys_rerun_path_mode.test.js` locks down the renderer-side `wifiKeysRerunInFlight` flag, the auto-rerun path after `setBackendWifiKeys` succeeds, the `wifi-keys-<jobId>.json` filename pattern, and the keystore round-trip (session save → restore → re-send keys → backend decrypts).
- New `tests/epmap_conv_decoder.test.js`, `tests/llmnr_conv_decoder.test.js`, `tests/nbns_conv_decoder.test.js`, `tests/nbdgm_conv_decoder.test.js`, and `tests/ldap_conv_decoder.test.js` follow the same pattern as `tests/kerberos_conv_decoder.test.js`: each one imports the new `decode{Epmap,Llmnr,Nbns,Nbdgm,Ldap}FromBytes` exports, asserts the dropdown wiring (`SUPPORTED_DECODER_PROTOS.has(...)`, `decodeWithSelectedProtocol` switch case coverage), exercises the new `PROTOCOL_DECODER_HINTS` / `PORT_DECODER_HINTS` entries (ports 135 / 5355 / 137 / 138 / 389 / 636 and protocol names `epmap`/`llmnr`/`nbns`/`nbdgm`/`ldap`), and round-trips hand-built fixtures through the decoder — EPM tower decoding, LLMNR RR walks, NBNS 32-byte NetBIOS name decoding, NBDGM header walks, and LDAP filter + attribute tree rendering.
- New `tests/stats_anomalies.test.js` exercises every detector in the new **Stats → Anomalies** sub-tab: `detectStatsAnomaliesPortscan` (per-source port sweep detection), `detectStatsAnomaliesBruteForce` (per-service / per-destination brute-force windows over FTP/SSH/Telnet/SMTP/POP3/IMAP/RDP/VNC/LDAP), `detectStatsAnomaliesBaselineOutliers` (per-minute packet-count / length baseline drift), `detectStatsAnomaliesEmbeddedContent` (high-entropy cleartext payloads), the `collectStatsAnomalies` aggregator, and the `renderStatsAnomaliesPanel` rendering pipeline (click-to-filter cards). Includes fixtures derived from the new `samples/pcaps/portscan.pcap` and `samples/pcaps/ftp-crack.pcap`.
- New `tests/threat_intel_scorer.test.js` exercises every public helper in [src/ui/panels/threat-intel-scorer.js](src/ui/panels/threat-intel-scorer.js): `collectIpIndicators` / `collectDomainIndicators` / `collectHashIndicators` / `collectReputationIndicators`, `calculateShannonEntropy`, `detectProtocolAnomalies`, `clampScore`, `computeSessionThreatScore` (incl. band classification, weight breakdown ordering, capture footprint rollup), `buildSessionThreatScoreBreakdown` (Markdown + JSON shapes), and `buildSessionThreatLlmPrompt` (the prompt sent to the active LLM for assessment). Fixtures include malicious hash hits, Tor exit-node indicators, high-entropy cleartext payloads, and intentionally-empty captures.
- New `tests/threat_intel_stats_anomalies.test.js` covers the cross-tab wiring: the same indicators surfaced in the Stats → Anomalies sub-tab also lift the Session Threat Score, and recompute-after-lookup keeps the score in sync as the analyst adds threat-intel lookups.
- New `tests/legacy_all_host_sentinel.test.js` asserts the `legacyAllHostSentinel` value survives progressive snapshot / rerun rewrites of the host list so the `0.0.0.0` "All Hosts" target keeps binding to the full packet set.
- New `tests/test_backend_wireless_80211_wep.py` exercises the WEP decryption path end-to-end: `getWirelessLayers` recognises `Dot11WEP` as the encrypted layer, `_wepDecrypt` round-trips the `wep-A4-81-53-B4-CF.pcap` sample (WEP-40 key `A4:81:53:B4:CF`, BSSID `c0:4a:00:80:76:e4`) into bytes that pass the LLC/SNAP + valid-EtherType sanity check, `_wepPlaintextLooksValid` rejects a wrong key (no false positives) and arbitrary garbage, and `decryptWifiPayload` returns the same `{ok, plaintextHex, algorithm, bssid}` shape for WEP that the AES-CCMP path already returned for WPA2. Also covers `_resolveWepKey` accepting WEP-40 / WEP-104 / WEP-128 hex keys and rejecting malformed lengths.
- New `tests/list_panel_app_protocol.test.js` is a structural regression for the `WIFI`-relabelling bug: it loads the real `src/ui/panels/list-panel.js` source via `vm.runInContext`, extracts `collectDecodedProtocolNames` (and the helpers `isLinkLayerProtocolName` / `LINK_LAYER_PROTOCOL_NAMES`), and pins down both halves of the fix — a decrypted TCP frame whose `decoded_protocols` still contains a legacy `WIFI` token must not be surfaced as `WIFI` in the App Protocol column, and a fresh backend payload whose `decoded_protocols` is `{WIFI, TCP, HTTP}` must report `TCP` / `HTTP` (and never `WIFI`) as the application-layer label.

### ✨ Features

- **Extraction panel now handles archives & compressed bundles** — the extractor (`src/backend/extractor.py` + the new helpers under `src/ui/panels/extraction-panel.js`) now natively unpacks `cab`, `7zip`, `zip`, `tar`, `gz`, `bzip2`, and `zstd` archives and compression, so an analyst can drop a captured package bundle onto the panel and the contents surface under their own sub-entries instead of being dumped as a single opaque blob. Archive / compression detection runs on file magic first and falls back to extension matching, and the panel keeps the per-entry carve context menu (load into Extraction / Decoders, send to VirusTotal) consistent across nested entries.
- **Image, executable, and hash extraction complete the framework** — the extraction panel now covers the rest of the practical artifact classes: PNG / JPEG / GIF / WEBP image bytes are auto-classified via `inferMimeType` in [src/ui/main-frontend.js](src/ui/main-frontend.js), generic PE / ELF executables are detected via the same magic-byte pipeline, and the SMB / NFS / FTP file-carve context menu (`carveCurrentStreamToFileFromContextMenu`) plus the manual-carve row in the Data Tools panel surface those bytes for save. Loading any extracted artifact — archive entry, carved file, or manual carve — into the Conv input auto-populates the full hash grid in the Hashes sub-tab via `computeDataToolsHashes`: MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 + SHA3-256 / SHA3-512, RIPEMD-160, and Whirlpool, with the `buildConvHashesMarkdownTable` helper available for report export. PDFs already detected; Office documents, scripts, and the unified "extract all" bulk-export workflow remain TODO.
- **Statically linked backend for hostile / unknown environments** — the snitch Python backend is now repackaged through `staticx` so the shipped binary no longer needs a co-located Python or system libraries to launch. The post-pyinstaller pipeline (`scripts/build-backend.js` + the new `scripts/with-libs-path.js` env wrapper) runs the `snitch` binary with the host's dynamic loader path so the in-test backend boots cleanly on Kali, fresh containers, and minimal CI images, and the standalone `snitch-extract` binary gets the same treatment via `src/backend/requirements-extract.txt`. The `tests/test_backend_{compile,json,server}.py` suites now run through the staticx-wrapped binary by default and `conftest.py` is the single source of truth for staging the build.
- **"Load full packet (with headers) into Conv" via right-click context menu** — every packet now has a new `Load full packet (with headers) into Conv` action on the right-click context menu. The selected packet (link-layer headers and all) is handed to the Conv tab as the analysis input so the analyst can immediately walk the L2/L3/L4 structure in the data-tools panel without a separate "open in Wireshark" hop.
- **Backend build cache + Windows installer hardening** — `scripts/build-cache.js` wraps the PyInstaller + staticx + snitch-extract pipeline in a content-hashed cache so unchanged rebuilds skip the slow steps (PyInstaller already only re-runs when the source fingerprint changes), and the same wrapper produces a single canonical `snitch` + `snitch-extract` pair for packaging. The Windows installer scripts (`src/main.js` Squirrel hooks + `tests/windows_elevation_check.test.js`) now create both the Start-menu shortcut (location corrected to land under `Programs\PacketSnitch` consistently) and the desktop icon from the same PowerShell helper, so per-machine vs. per-user installs can no longer disagree on where the shortcut lands. The Start-menu and desktop icon flow is fully test-covered and idempotent — a re-install no longer produces duplicate shortcuts.
- **Self-hostable backend env on stripped-down hosts** — `scripts/with-libs-path.js` is the single env wrapper that augments `LD_LIBRARY_PATH` / `PATH` (and the Windows equivalents) before launching the snitch binary, and `src/back-comm.js` calls into it for the new `testcaseOutputDir`-based keys-file staging. The result: a freshly built snitch binary boots on a vanilla container where the only Python on disk is whatever the staticx build embedded.
- **Metrics install UUID is now minted exactly once** — the install-UUID minting path that powers `metricsInstallId` no longer regenerates the UUID on every settings-save or consent decision, so the install identity stays stable across upgrades, settings changes, and a "restore defaults" pass. The fix is wired into `src/metrics.js` and pinned by the new `tests/metrics_privacy.test.js` extension that asserts the UUID survives a clean save → load → save round-trip.
- **Default Ollama model updated to `minimax-m3:cloud`** — the bundled default model name in the LLM dropdown now matches the current model line, so a clean install no longer requests a model the user doesn't have and silently falls back to no-LLM.

- New `tests/windows_elevation_check.test.js` extension covers the Start-menu and desktop-icon creation helpers (idempotent across re-installs, correct location, correct per-machine vs. per-user branch).
- New `tests/test_backend_{compile,json,server}.py` extensions drive the staticx-wrapped `snitch` binary end-to-end so the build-cache wrapper and the `with-libs-path.js` env shim are exercised on every CI run.

---

## v2.4.2169 - 2026-07-27

**Type:** minor

### ✨ Features

- Halfed exe/rpm/deb installer sizes
- Anonymous, opt-in usage metrics: new `src/metrics.js` module + `metricsapi` IPC bridge ship tab/subtab usage, action timing, and error reports to a user-configurable HTTP endpoint (default `http://64.227.4.43:8088/mhook`)
- First-run consent overlay: clean installs now show a dedicated Yes/No dialog before any metrics can be collected; decision is recorded via `settings.privacy.metricsConsentAsked` and can be changed any time in Settings → Privacy
- New `Privacy` subtab under Settings: enable/disable metrics, set the endpoint URL, tune flush interval and in-memory queue size, and view the auto-generated install UUID
- Self-hostable metrics endpoint (`src/metrics/server.py`) with NDJSON-on-disk sink for log aggregators (ElasticSearch/Graylog/Loki/Splunk/Vector) plus a `/healthz` liveness probe
- "Analyze IP..." submenu in the context menu: route the right-clicked IP straight into the Subnet Calculator or the Threat Intel lookup
- Carved-file context-menu entries in Stats: "Load carved file into Extraction", "Load carved file into Decoders" (with auto-extension hinting: `.jpg`→`jpeg`, `.json`→`json`, `.xml`→`xml`, `.html`→`html`, `.yaml`/`.yml`→`yaml`, etc.) and "Send carved file to VirusTotal" for entries in the new Carvable Files list
- `runThreatIntelIpLookup` / `setAnalysisInput` exposed on the Subnet Calculator panel for cross-panel IP drill-down
- Backend port reclaim: on GUI startup we look for a stale snitch HTTP backend on the configured port and shut it down gracefully (with OS-level kill fallback) before launching our own

### 🐛 Fixes

- Heatmap map projection calibration is now sourced from a single `MAP_PROJECTION_CALIBRATION` constant in `src/settings.js`; the previously hard-coded values in `stats-panel.js` (and persisted debug settings defaults) now agree
- VirusTotal startup diagnostic is coalesced: eager + persisted-settings + backend-ready callers share a single in-flight probe with a 30s "last successful fetch" dedupe window, and a new `invalidateVirusTotalDiagnosticsCache()` hook refreshes immediately when the API key changes
- Privacy block in `settings-update` IPC is now deep-merged so a partial write (e.g. the metrics service writing back a fresh install UUID) can no longer wipe the user's `metricsEnabled` toggle or custom endpoint URL
- Metrics flush loop now actually fires: `mainWindow.webContents.send("metrics:flush-request", ...)` is paired with a renderer `metricsapi.onFlushRequest` listener and a `beforeunload` final-flush, so events ship instead of piling up in the queue
- `install-screen` only auto-shows the consent overlay on a clean install (not on every launch where the install screen is suppressed) and records the choice before un-hiding
- Resolved a stale `<<<<<<< HEAD` merge marker in the Conv Decodes protocol dropdown (`src/index.html`)
- Context menu layout: "Open in Heatmap" and the new carvable/extraction entries are no longer orphaned by misplaced `<hr>` dividers

### 🗑️ Removed

- Duplicated `0.55 / 0.95 / -0.53 / 0` heatmap calibration constants in `src/settings.js` and `src/ui/panels/stats-panel.js` (consolidated into `MAP_PROJECTION_CALIBRATION`)

### 🔧 Improvements

- New `tests/consent_overlay.test.js`, `tests/metrics_privacy.test.js`, `tests/metrics_tab_tracking.test.js`, and `tests/test_metrics_server.py` cover the new consent overlay, privacy settings, tab-tracking path, and the Python metrics server end-to-end
- New `tests/heatmap_projection_calibration.test.js` locks the shared calibration constants so future tweaks do not silently regress the heatmap alignment
- Settings schema expanded with a normalized `privacy` block (`metricsEnabled`, `metricsConsentAsked`, `metricsEndpointUrl`, `metricsFlushIntervalSeconds`, `metricsMaxQueueSize`, `metricsInstallId`)
- `src/ui/main-frontend.js` now listens for the `packetsnitch:settings-updated` CustomEvent so out-of-band writes (consent overlay, metrics install-id generation) re-sync the in-memory settings and the Privacy tab form
- All metrics tracking respects a strict `SAFE_PROP_KEYS` allowlist and per-key length caps — no PCAP paths, IPs, prompts, or other user content ever leave the renderer
- Docs (`docs/context-menu.md`) updated to describe the new Analyze IP submenu and the carvable-file context actions
- Default Ollama model updated to `minimax-m3:cloud` to match the current model line
- Metrics endpoint URL is user-configurable; the bundled `src/metrics/server.py` is documented and ready to deploy behind any reverse proxy for self-hosted setups

---

## v2.4.2115 - 2026-07-26

**Type:** minor

### ✨ Features

- Threat Intel sub-tab under Conv (VirusTotal lookup, hash cross-reference button, auto-select in VirusTotal)
- Subnet calculator panel in Conv (queries backend HTTP server for GeoIP and IP reputation data)
- Nmap scan support and IP/Subnet analyzer rearrangements
- Shodan support in IP information
- High-resolution raster worldmap image for Heatmap view
- More sample pcaps
- Better plugin capabilities enforcement
- Sample plugin `hello-snitch.zip`
- Backend ico of the snitch
- Distiller for the summary report generator
- Bugfixer added to website
- More info for LLM

### 🐛 Fixes

- File importing no longer errors on successful load, now also shows in Stats panel
- Stats tab Total Traffic indicator
- Path validation fix in `snitch.py` (security fix for path traversal)
- HTML/content layout shift on docs site
- Conv tab hex input scrolling
- Filter bleed bug
- Filter autocomplete

### 🗑️ Removed

- Lots of old dead code removed during major code cleanup

### 🔧 Improvements

- Major code cleanup; lots of old dead code removed, function organization improved
- Streamlined the frontend with stream payload caches
- Frontend processing optimizations
- Fixed HTTP body and file carving
- Subnet Calc subtab UI cleanups
- Heatmap zoom support
- Backend scheduler optimizations
- Better stream hydration/dehydration logic
- Code organization: parted out backend's individual protocol decoders to their own files
- Code organization: moved sidebar protocol renderers to `src/ui/decoders/main/`
- More backend test coverage
- Better font shipping/fallbacks for docs site
- Markdown supported in Summary tab
- Better filter bar logic with saving/labeling filters
- Search and replace in Conv tab
- File Carving section added to Stats tab
- Better Conv to Notes
- Conv tab "load more" button for large data
- Setting to disable Summary auto-generation

---

## v2.3.1694 - 2026-07-23

**Type:** patch

### 🗑️ Removed

- `patchall` from `make` (under Windows)

### 🐛 Fixes

- Removed `patchall` from `make` for Windows so it completes under Windows
- Quieted noisy backend HTTP error on stop

### 🔧 Improvements

- Took out `--icon` from PyInstaller and added to `.spec` for backend icon
- Backend ICO of the snitch

---

## v2.2.1638 - 2026-07-18

**Type:** minor

### ✨ Features

- IPv6 support improvements (brackets on port usage, fixed delimiter issues)
- Threat Intel sub-tab under Conv (VirusTotal)
- Backend HTTP server (refined)
- More sample pcaps
- Table of contents in docs
- Better stream hydration/dehydration logic
- Filter autocomplete

### 🐛 Fixes

- List panel blank bug
- Big-endian nanosecond resolution pcap support
- `ports.json` removal from samples (no longer needed)

### 🗑️ Removed

- `ports.json` from samples (no longer needed)
- Screenshots from frontend docs

### 🔧 Improvements

- Removed screenshots from frontend docs
- Backend pushes packets in chunks for more responsive frontend
- Lazyload packets; call everything from drive instead of loading entire capture into memory
- More decoders added
- Keystore autoadd objects added
- Backend existence check before run
- Filter query status updates
- Explicit logging of filter clear
- Stream statistics in Host Data view and Stats tab
- Conv tab data saved with session data
- Context menu reference in docs
- Differentiation between `tcp.proto` and `udp.proto`, new `app.proto` catchall
- Locations listing queryable on click via `loc.src.city || loc.dst.city`
- Globbing-style regex support in filter (now supports `?` and `*`)
- Brotli detection
- Help button + new window to docs

---

## v2.1.1606 - 2026-07-16

**Type:** minor

### ✨ Features

- Soulseek, Bittorrent, and SMPP support
- Better PPP, PPPoE, and LLDP support
- Improved plugin capabilities with new internal interaction APIs
- Better crypt support for ambiguous data
- Improved XML, JSON, YAML support
- Generic decoders renamed
- Updated build config
- Backend now fails on unknown filetype magic
- GitHub workflow fixes (repo stats)

### 🐛 Fixes

- List panel blank bug
- Big-endian nanosecond resolution pcaps

### 🗑️ Removed

- Non-clickable password badge from UI

### 🔧 Improvements

- Plugin enforcement tests
- Widened settings panels
- Improved plugin UI handler
- Some plugin support groundwork
- Parted out backend protocol decoders to their own files for better organization
- Widened sidebars for both OSs
- Backend chunk size now arbitrary
- Streamlined frontend with stream payload caches
- Fixed creds uniqing bug in Stats panel
- Fixed HTTP body and file carving
- Cleaned up UI, removed non-clickable password badge, fixed subnet calc title

---

## v2.0.1573 - 2026-07-15

**Type:** major

### ⚠️ Breaking Changes

- Version 2.0 represents a major version bump with substantial architecture changes
- New session save file format (gzipped BSON) replaces the previous format; old session saves are not compatible

### ✨ Features

- `.psb` is on by default in debug mode
- New session save file format based on gzipped BSON (binary JSON)
- Multi-job processing on backend and frontend with job IDs
- Backend's common/ library fixed
- Conv tab retooled for better use of screen real estate
- List tab columns hidden by default
- LDAP decoder support improved
- Updated Samba code
- Markdown compatibility for LLM and send-to-Notes data shapes
- Startup splash screen
- `/status` endpoint on backend's API
- Major serialization bug fix on backend
- Streamlined packet ingestion on the frontend
- List tab support for zero-length payloads
- Frontend logging tunables to reduce UI main thread load
- New defaults for UI main thread logging backlog
- List tab column rearranging support
- Settings tab improvements
- Backend version line in packetsnitch exe gen
- Themes bundled
- Updated Python spec file for snitch.py

### 🐛 Fixes

- SIP handling under Conv tab decoders
- Better pagination for large streams loaded into Conv
- Better formatting in Conv tab
- Filter bleed bug
- Word wrapping touchups
- Settings overlap bug
- List tab scrolling bug on virtualized lists
- Host Data view content hidden bug
- List tab zero payload length bug
- Dropdown colors now follow themes
- Backend bug finding common/

### 🗑️ Removed

- Unnecessary testcases dir creation in HTTP mode

### 🔧 Improvements

- Version bump
- Updated python spec file for snitch.py
- Increased fade out sec
- Longer startup time
- One-shot override for the decodes subtab on Conv
- Session picker updates
- Better LDAP decoder support
- Updated Samba code
- Removed unnecessary testcases dir creation in HTTP mode
- Updated User-Agent string globally
- Updated Help tab to allow new domain
- Updated settings tab
- New Release check
- Download new release button
- SnitchBitch theme updated
- Fav icon added
- More backend test coverage
- Better plugin capabilities enforcement

---

## v2.0.1566 - 2026-07-14

**Type:** minor

### ✨ Features

- `.psb` is on by default in debug mode
- Backend's `common/` library bug fix
- Multi-job processing on backend and frontend with job IDs
- New session save file format (gzipped bson)
- Major serialization bug fix on backend
- SIP handling improvements in Conv tab
- LDAP decoder improvements
- Updated Samba code

---

## v1.9.1518 - 2026-07-11

**Type:** minor

### 🗑️ Removed

- References to `models.txt` from code
- Test automatic run (left tests manual)
- Map crosshair

### 🐛 Fixes

- Removed references to `models.txt` in code, left `modes.json` support
- MAC address pulling IP into field bug on backend
- Backend kickoff improvements
- Map updated, crosshair removed
- Map animations smoother

### 🔧 Improvements

- Updated map animations for smoother zoom
- Streamlined the frontend
- Stream payload caches
- Frontend processing optimizations
- Fixed creds uniqing in Stats panel
- Backend chunk size now arbitrary
- Widened sidebars for both OSs
- Removed test automatic run, left tests manual
- Updated SnitchBitch theme
- Favicon added
- Updated Sponsorship stuff
- Thanks to IRC network admins where dev chan is hosted
- New Release check added
- Download new release button added
- Pulling data from runtime main process
- Updated download link generation handler
- Now detect Windows/RedHat/Debian flavors
- Better Nmap scan support
- Shodan support in IP/Subnet analyzer
- Threat Intelligence under IP information in Subnet Calc subtab
- Better documentation

---

## v1.9.1442 - 2026-07-05

**Type:** minor

### ✨ Features

- Worldmap
- Backend HTTP server
- PGP workspace in the Crypt tab
- Settings tab
- LLM now in frontend
- Heatmap with Wikipedia images
- Layer fix; statusbar brought forward
- Better default zoom/offset options on map calibration
- Heatmap zoom support
- Heatmap, "Worldmap" view
- Subtab for Threat Intelligence under IP info
- Credential count and creds readout in Stats tab
- Rudimentary protocol support for SIGTRAN packets for SS7 network captures
- Anime theme (animated background, demo purposes)
- New light soft pastels theme
- Better theme engine (backdrop images support)
- PGP tab (basic implementation; decrypt and verify messages)
- Backend API over JSON HTTP
- Better Filter history (filter history saves/labeled)
- Better filter bar logic

### 🐛 Fixes

- Removed duplicates in the backend JSON
- Preprocessor's legacy keys cleaned up; removed all non dot-notation keys
- This can be a breaking change on session saves; you may need to remove old saves or use them with the previous version of PacketSnitch
- Conv tab hex input scrolling
- Filter validation strips `!`, `(`, `)`
- Initial check on Group by Stream in List tab
- Some small aesthetic changes
- Removed need for `threads` var in backend config
- Backend now pulls the number of available CPU cores dynamically

### ⚠️ Breaking Changes

- Saved sessions need to be discarded and rebuilt from their pcap
- Old session saves may not work due to legacy key removal

### 🗑️ Removed

- All non dot-notation (legacy) keys from the preprocessor output
- Need for `threads` var in backend config (now pulled dynamically from available CPU cores)
- Duplicates in the backend JSON

### 🔧 Improvements

- New themes: pastels and Sub7
- Tweaked the light theme
- New ico location
- Encodings as a hidden import for the python backend .deb builds
- Forge config converted to conditional builds based on building OS
- Windows installer icons fixed
- Added things to make deb build correctly under Kali
- Template for .desktop so the icon works properly under Linux
- UPX packing option (not default)
- Installer splash
- Backend scheduling optimizations
- Resize and show/hide columns in List tab
- Backend version string; version can be queried via /version
- Version check for the packetsnitch backend api
- PGP autoloads its secrets into the keystore
- Heatmap scales better
- Backend now has a proper version string
- Hardened FRAME and unknown behavior fallback
- Normalized key format
- Added src/dst port aliases
- Retooled the map zoom algorithm
- Map calibration edits
- Backend scheduler optimizations
- Repositioned Prev/Next
- LLM diagnostics in activity log
- Backend now works correctly with the server

---

## v1.8.1384 - 2026-07-01

**Type:** patch

### 🗑️ Removed

- Unneeded reqs in `requirements.txt`
- Ollama dep from backend (LLM moved to frontend)
- LLM references and calls from backend
- `_dirname` and `_filename` patches (replaced with DefinePlugin and fallback)

### 🐛 Fixes

- Removed unneeded reqs in `requirements.txt`; let pip handle that
- Windows cPyInstaller should be able to use Linux forward slashes in spec file for snitch.py
- Pushing startup hardening to the backend loader
- Pushed `_dirname` and `_filename` patches
- DefinePlugin and a fallback for dirname
- Tried to fix Windows no style/js runtime bug
- Tried to fix ollama compile issue

### 🔧 Improvements

- Ver bump and removed ollama dep in backend
- Does a check to see if LLM Ollama backend is running before exposing it in UI
- Updated LLM with a longer default timeout for slow models
- LLM calls are now handled on a per-stream basis in the frontend
- LLM references and calls removed from backend for performance and stability
- PacketSnitch now scales better for larger capture files
- Notes markdown dep "marked" added so tables are properly generated
- Markdown and note edit mode now works properly
- Setting for the stream size warning threshold
- New Settings tab
- Theme engine: select quit button icon and color
- Two new themes: pastels and Sub7
- Theme engine: light theme tweaks
- Fixed pretty JSON screen in Conv
- Updated `snitch.py` to take a chunk size var from frontend's user config
- Credentials counter in Stats section
- Some context-aware LLM stuff
- More stream/packet targeted ollama support on frontend
- Improved filter grepping to include label/content/type hint of keystore entries
- Fixed keystore filtering; only visible when session keychain is in use
- User can filter keystore list if many entries
- Touchups to logging code
- Theme engine: old theme carryover fixed; resets all themable colors on new theme selection
- Updated docs and themes guide
- Theme engine: support for logo replacement
- Some logging and status updates on settings changes
- Settings logging to activity log on changes
- Theme selection decision matrix

---

## v1.8.1332 - 2026-06-28

**Type:** minor

### 🐛 Fixes

- Try checking the type and returning if not an arr
- Fixed for zero packets warning
- Correction so it doesn't return before clearing the old packet data
- Added check to see if a key is valid if zero packets are returned by the filter
- Added link to license

### 🔧 Improvements

- Initial test of LLM in frontend
- Per-packet/key filtering and grouping
- Stats tab Total Traffic indicator fixed
- Began adding heatmap functionality

---

## v1.7.969 - 2026-06-24

**Type:** minor

### ✨ Features

- Globbing-style regex support in filter (now supports `?` and `*`)
- Brotli detection
- Help button tied to new window that loads the documentation from the internet
- Access controls to help page browser
- Extensive features list section in documentation
- Two more sample captures
- New compression sample
- New filter keys added to docs

### 🐛 Fixes

- Backend clobbering bug when a new session was loaded before the backend was done
- Some corrections in backend to what layer a proto returns as
- Sets user agent to PacketSnitch and version for web reqs
- Made demo gif a link to YouTube vid of better resolution
- Some more guards on the URL the Help center can browse to
- Some guards on hideAllData() so hex grid no longer has lingering null
- Now hides data types list on BGP packets too by default
- Repositioned the Overview in the Stats tab form one to three columns

### 🔧 Improvements

- Added `link.proto` context menu filter options
- Relabeled transport and application filters in context menu
- Added some proper protocol keys to backend for more descriptive filtering (e.g., `transport.proto: tcp`, or `link.proto: ethernet`)
- Added some new examples for globbing feature

---

## v1.7.935 - 2026-06-21

**Type:** minor

### ✨ Features

- Decoders: SIP and FTP (with keychain credential autopopulation)
- New filter keys: `tcp.retransmission`, retransmission/out-of-order packet keys
- Statistics to Stats tab for retransmission
- Data type guesses for network endpoints and MAC addresses
- Date and time format type identifiers
- Single byte data type guessing
- Save Raw Conv tab data via context menu
- Streamlined protocol matching logic
- HTTP following: whole body gets copied to Conv tab and exported to files (not just initial packet)
- Decompression-aware context menu items for handling HTTP data
- Some specific sample data for demos
- Preliminary IGMP backend support
- Properly handles non-TCP formed packets (ARP, FRAME, etc.)
- Some lower-level protocol identifiers for the Stats tab
- Improved protocols used readout in Host Data view
- Some protocol auth extractors
- Filter for bookmarked hosts
- Warning if the stream they try to load is large
- Keystore autoadd to work with packet lazyload on metadata
- Table coloring

### 🐛 Fixes

- Data types frame auto hides if it doesn't make sense to have it there
- Renamed exploit pcap

### 🔧 Improvements

- Better and more targeted context menu
- Uppercased application layer protocols in Stats tab for congruence

---

## v1.7.848 - 2026-06-17

**Type:** minor

### ✨ Features

- Backend now pushes packets into frontend in chunks for more responsive frontend
- Code can lazyload packets and call everything from drive instead of loading entire capture into memory
- Increased the number of seconds status update stays on to 10
- JSON/pcap/pcapng constraint on session picker's new session dialog
- Added support for some more decoders
- Some keystore autoadd objects
- Added check to see if the selected file is a session or pcap; code paths for each
- Backend existence check before trying to run
- Filter query status updates
- Explicit logging of filter clear
- Updated some stream stats on the left hand side for each packet
- Stream statistics in Host Data view and Stats tab
- Conv tab data saved with session data
- Context menu reference in docs
- Differentiation between `tcp.proto` and `udp.proto`, new `app.proto` catchall
- Locations listing queryable on click via `loc.src.city || loc.dst.city`
- Removed stray IP addresses from `dns.qname` in Stats page

### 🗑️ Removed

- Stray IP addresses from `dns.qname` in Stats page
- Divider above Exports submenu

### 🐛 Fixes

- Backend handles packet array sync up properly with guards
- Now only runs autosave if a real session is opened, discards a dummy session (<5000 bytes)
- Autosave function triggers on exit and on log write
- Added check to see if a session is even open before asking to save it on quit
- New session button properly clears out the old session before reloading
- Now from Stats tab, if a Ports Seen port is clicked, it searches for both TCP and UDP ports
- `back-comm.js` loader handles loading new compressed format session files
- Now while data is being pushed from backend incrementally, the tab doesn't keep jumping back to Host Data view
- The same message about switching to List view doesn't come up in the log repeatedly on startup
- [Snitch] entries in log no longer have unary space near beginning

### 🔧 Improvements

- Moved save button to the very bottom
- Removed divider above Exports submenu
- Edited some context menu items to shorten them
- Some changes to the way protocols from application and transport layer protos are added to the filter
- Added gif demo of packetsnitch
- Added a static width to the gif
- Renamed workflow and schedule daily runs
- Added repo stats GitHub action
- Quits without removing the darkening from session picker, for aesthetics
- Recall the `persistSessionToDisk` function with null session name if autosave session is being manually saved
- Fixed autosave behavior
- Exit button on session picker screen just exits picker, not packetsnitch
- Some guards so user can't save/export the session or reprocess the pcap while being preprocessed
- Fixed session restoring not reloading packet payload data
- Log now notes which Renderer thread a log update is coming from
- Error message corrected for reprocess button
- Catch if reprocess button is hit too soon
- Added some screenshots to the documentation on the frontend
- Made correction to docs
- Stream order and filter context in Host Data tab
- Auto host targeted filtering from the Stats tab
- Session manager now saves the pcap itself to the session file, allows for reprocessing from session file

---

## v1.6.807 - 2026-06-14

**Type:** minor

### ✨ Features

- Autosave function that triggers on exit and on log write
- New session file format (compressed)

### 🗑️ Removed

- Dependency on manually saving session on exit (now handled by autosave)

### 🐛 Fixes

- Now only runs autosave if a real session is opened
- Discards a dummy session (any session less than 5000 bytes)
- Added check to see if a session is even open before asking to save it on quit
- Fixed new session button so it now properly clears out the old session before reloading
- Loading screen dims PS behind it while active
- Undims when processing is complete
- Added blank hosts list on list panel if only packet is by host 0.0.0.0
- Packet array now syncs up properly with guards

---

## v1.5.731 - 2026-06-07

**Type:** minor

### ✨ Features

- Encodings as a hidden import for the python backend .deb builds
- Swapped snitch binary location due to earlier breaking change in forge config
- Conditional forge config builds based on building OS
- .desktop template so icon works properly under Linux
- UPX packing option (not default)
- Installer splash

### 🐛 Fixes

- Windows installer icons fixed
- Stripped some unnecessary stuff out of backend package
- Added things to make deb build correctly under Kali
- Redid way data is imported into .desktop metadata file, dynamically generated
- Updated that compression block with a notice

### 🔧 Improvements

- Updated metadata for the builds
- Updated description and uninstaller ico
- Added installer loop gif with installer written on it
- Updated some docs
- New ico location
- Added documentation ai redo
- Some keywords and the terminal explicit false to the .desktop metadata

### 🗑️ Removed

- Unnecessary stuff from backend package

---

## v1.5.705 - 2026-06-03

**Type:** minor

### ✨ Features

- New width/height config so it better fits smaller screens
- Removed need for `threads` var in backend config
- Now pulls the number of available CPU cores dynamically
- Adjusted colors in the Conv color coding for better visibility
- Conv input history UI
- Conv output visibility mapping made explicit
- Hide redundant conv output pane
- Clamp conversion panel overflow
- Constrain conversion panel columns
- Fix Conv output expansion toggle and align output color coding
- Fixed background color in color coded conv boxes
- Prevent drag-and-drop text editing in Conv tab input only
- Prevent drag-and-drop text editing in filter/host inputs
- Fix Conv hex output mouse-drag behavior and dark blue frame backgrounds
- Refine Conv highlight map fallbacks
- Harden Conv selection sync handling
- Add Conv hex color coding and cross-frame selection sync
- Guard conv output expand handlers against duplicate binding
- Add conv output expand and collapse interaction
- Conv text type heuristics
- Refine Conv guess scan behavior and context-menu derive flow
- Add chunked Conv guess scanning and context derive action
- Sanitize host target filter query terms
- Refactor guessDataType: extract UUID/JWT regex constants, name base64 score constants
- Sync target host selection with filter bar
- Fix guessDataType: tighten JWT regex
- Add data type guessing (hashes, base64, PGP, JWT, UUID) below MIME type in Conv tab
- Restrict keystore reset action to unlock mode
- Guard nested keystore reset action
- Polish keystore dialog wipe button
- Refine keystore dialog reset flow
- Add keychain wipe action to unlock dialog
- Log renderer console.error to activity log
- Tidy keystore password confirm check
- Fix keystore reset function scope
- Centralize keystore reset warning text
- Centralize keystore minimum password length constant
- Add keystore password reset with wipe warning
- Keep loading screen visible until packets render
- Modified Python requirements.txt setup slightly so it doesn't bork on linux

### 🗑️ Removed

- Need for `threads` var in backend config (now pulled from available CPU cores dynamically)

### 🔧 Improvements

- Normalizing and removing some duplicated things
- Got most of the logging stuff congruent
- Add build from source instructions to README
- Added proper patching for the node_modules rpm builder bug
- Updated some logging code
- Added the frontend to the installed screen
- Fixed path for installed files locator
- Removed compiled backend dir, added tagline logo
- Updated ps views gif
- Fixed paths for installer screen checks
- Removed the patchup build from regular npm run make so it completes under Windows
- Updated version

---

## v1.5.618 - 2026-05-30

**Type:** patch

### ✨ Features

- Added the frontend to the installed screen
- Fixed path for installed files locator

---

## v1.5.610 - 2026-05-29

**Type:** minor

### 🗑️ Removed

- Compiled backend dir
- Patchup build from regular `npm run make` (so it completes under Windows)

### 🔧 Improvements

- Updated `ps_views.gif`
- Removed compiled backend dir, added tagline logo
- Added tagline purple
- Fixed paths for installer screen checks
- Removed the patchup build from regular `npm run make` so it completes under Windows
- Updated README

---

## v1.4.508 - 2026-05-26

**Type:** minor

### ✨ Features

- Stream filter to when selecting packet from List or Stats screens
- Hash algorithm outputs (MD5, SHA-1, SHA-256/384/512, SHA3-256/512, RIPEMD-160, Whirlpool) to Conv tab
- `@noble/hashes` and `whirlpool-js` for Conv tab hash outputs
- Refactor: switch Conv hash functions to pure JS crypto implementations
- Reorganize context menu copy and export cookie actions
- Improved auto cookie entry labels and naming clarity
- HTTP File context menu branch for dumping HTTP uploads/downloads
- Auto-add HTTP cookie jar entries to session keystore
- Cookie jar context menu branch
- Add to Keystore context menu for highlighted text
- Context-menu action to load raw payload into Conv tab
- Context-menu action to load the full raw packet (entire frame) into Conv tab
- Multi-level submenu viewport positioning via ancestor panel revelation
- Extract cookies and generic POST body credentials into session keystore
- Auto-detect credentials in HTTP, SMTP, POP3, IMAP, Telnet and add to session keystore
- Session key bookmarking to persistent keychain
- Password-gated keychain manager with session/persistent modes
- First-time keychain password setup flow
- Persist keystore in IndexedDB with encrypted entry payloads
- Split keystore panel and harden keystore/filter handling
- Move keystore UI to standalone panel and add Keystore menu tab
- Tighten Telnet auto-detection to require IAC + valid command byte
- Add HTTP, Telnet, SSH, POP3, IMAP, SMTP decoders to Conv tab
- Implement Crypt tab with SSL workspace and persistent local keystore
- Filter syntax validation and error reporting
- Context-menu actions for explicit filter parentheses
- Avoid double wrapping negated context filter clauses
- Add unary `!` filter inversion and context-menu is-not actions
- Add explicit `&&` and `||` filter-append context options
- Add Clear and... submenu under Add to filter context menu
- Remove double `[Console]` label on renderer console.log entries
- Label all backend process logs as `[Console][Backend]` in activity log
- Label backend errors as `[Console][Backend]` in activity log
- Prefix all UI log entries with `[GUI][UI]`
- Log console output to activity log
- Adjust tab bar width and Prev/Next placement
- Move Prev/Next buttons to far right of tab bar
- Swap Stats/Data tab positions and rename Data tab to Conv
- Tighten context menu active cursor guards
- Normalize context menu active packet cursor handling
- Sync active packet cursor for context menu helpers
- Use active packet accessor in context menu export
- Flip context submenus inside viewport
- Restructure context menu into convert/filter/export branches
- TLSv1.2 context to satisfy backend security scan
- Allow TLS protocol negotiation with min TLS1.2
- Improve TLS probe reliability with SNI fallback
- Use explicit TLSv1.2 context for banner SSL probe
- Refine HTTPS service checks and SNI hostname selection
- Harden TLS context and tidy HTTPS service detection
- Fix TLS encryption details for HTTPS-like services
- Replace filter history popup with standard select dropdown
- Add tooltip to Conv tab button
- Hex-view copy actions to right-click context menu
- Unify right-click context menus and conditional copy visibility
- Right-click context menu with copy, paste, and save JSON
- Blank right panel when list or stats tab is active
- Darken selected packet row on hover in list tab
- Use Unknown fallback for stream grouping when protocol is missing
- Sortable packet-list columns via clickable headers
- Enhance list tab with hover highlight, bookmark column, and stream grouping
- Add List tab between Stats and Log for packet browsing by host
- Filter aliases and text matching for `wire.proto`, `eth.src.vendor`, `mime.type`, `dns.qname`
- Capture stats page with protocols, hosts, locations, and more
- Polish query-highlight loop and dropdown event guards
- Refine query-history empty-state styling and toggle handling
- Improve query syntax UI accessibility and keyboard behavior
- Allow empty query-history dropdown to open with empty-state message
- Add syntax highlighting for filter query input and history dropdown
- Packet query history dropdown for reruns
- Use cached host value in packet display logging
- Normalize error log helpers and host iteration
- Log all remaining frontend error paths
- Harden activity timeframe parsing and normalize log entry format
- Fix IPC placement and harden activity log capture entries
- Add activity log UI and persistence plumbing
- Filter to stream when selecting packet from List or Stats screens
- Refactor: simplify packetsForHost fallback in stream filter path
- Preserve active filter and packet on Host Data reopen

### 🐛 Fixes

- Fixed Prev Next positioning to something sane
- Some UI tweaks with more error messages
- Fixed tabs opacity
- Resized data tools input box (taller)
- Fixed port and Network Class context menu filter detection
- Adjust port handling in context filter parser
- Tighten context filter query sanitization
- Harden context filter value handling
- Append context-menu filters to existing query
- Fix context filter parsing edge cases
- Tighten editable target checks for context-menu paste
- Avoid deprecated execCommand in context-menu paste flow
- Fix context-menu paste targeting and reorder save option
- Harden save-json handling and rename action visibility flag
- Add success status feedback for context menu copy
- Apply review nit in unified context menu rendering
- Clean up catch blocks and byteIndex naming
- Rename hex grid iterator variable for clarity
- Fix context menu closing and startup hidden state
- Address review nits for catches and docs labels
- Refine context conversion validation and comments
- Fixed some box sizing stuff
- Fixed log search box positioning
- Enforce fixed column widths in packet list table
- Normalize and sanitize stats entries on Stats page
- Simplify hex grid cell wrapping rule
- Keep hex payload grid cells square at all zoom levels

### 🔧 Improvements

- Edit author line
- Removed eslint backup
- Added chardet to backend's requirements.txt
- Some minor changes to themes
- Updated documentation for new codebase changes
- Added screenshot of the list screen

---

## v1.3.353 - 2026-05-24

**Type:** minor

### ✨ Features

- Updated some electron forge stuff
- Updated python requirements.txt
- Fixed log search box positioning
- List tab between Stats and Log for packet browsing by host
- Enforce fixed column widths in packet list table
- Remove unused `.packet-list-host-header` CSS class
- Add screenshot of the stats tab
- Normalize and sanitize stats entries on Stats page
- Filter aliases and text matching for `wire.proto`, `eth.src.vendor`, `mime.type`, `dns.qname`
- Capture stats page with protocols, hosts, locations, and more
- Polish query-highlight loop and dropdown event guards
- Refine query-history empty-state styling and toggle handling
- Improve query syntax UI accessibility and keyboard behavior
- Allow empty query-history dropdown to open with empty-state message
- Add syntax highlighting for filter query input and history dropdown
- Packet query history dropdown for reruns
- Use cached host value in packet display logging
- Normalize error log helpers and host iteration
- Log all remaining frontend error paths
- Harden activity timeframe parsing and normalize log entry format
- Fix IPC placement and harden activity log capture entries
- Add activity log UI and persistence plumbing
- Simplify hex grid cell wrapping rule
- Keep hex payload grid cells square at all zoom levels
- Added chardet to backend's requirements.txt

### 🔧 Improvements

- Removed eslint backup
- Some minor changes to themes
- Update screenshot in README for main view
- Added screenshot 24

### 🗑️ Removed

- `eslint` backup

---

## v1.2.310 - 2026-04-23

**Type:** minor

### ✨ Features

- Fix frontend to safely read MAC fields when Ethernet Frame may be N/A
- Show MAC address info when one IP is private and other is internet
- Save JSON from in-memory data instead of copying backend temp file
- Update image source in README.md
- Fix off-by-one so first packet in each host list is reachable and bookmarkable
- Sync bookmark dropdown when target host changes
- Extract `syncBookmarkDropdown` helper to remove duplication
- Sync bookmark dropdown with current packet navigation
- Add eslint fixes
- Resolve all JavaScript errors in src/ files
- Updated linting config
- Remove `.progress-ps.html` page
- Load hosts.json directly after backend finishes with 1s delay
- Clarify RADIUS TCP support is per RFC 6614
- Wire new protocol decoders into frontend render pipeline
- Add decoders for FTP, SMTP, POP3, IMAP, Telnet, IRC, MTP, LDAP, MySQL, PostgreSQL, XMPP, SMB, MQTT, RTSP, TFTP, BGP, HTTP/2, NNTP, RADIUS
- Extract protocol decoders into decoders.js
- Wire CopyPlugin to copy `src/assets` into webpack output so images load
- Replace inline base64 PNG images with file references in index.html
- Backend changed to onedir instead of onefile (shaves 4 seconds off backend time, no package unpack)
- Status shows PS version number
- Add `SOFTWARE_VERSION` const to frontend scripts.js
- Add installation complete screen shown on first run after new version install
- Rewrite README.md to focus on frontend and full tool overview

### 🔧 Improvements

- Hide menu bar
- Fix images so they load from files
- Update reference to Filters documentation
- Update Filters.md with new protocol filter keys

---

## v1.2.254 - 2026-04-16

**Type:** minor

### ✨ Features

- Add Filters.md link to main README
- Add comprehensive Filters.md documentation page
- Update README with donation options and installation steps
- Update donation section with QR codes
- Organize docs section
- Update Frontend.md with installation instructions
- Set `numWorkerThreads` to twice the available CPU cores
- Make top bar draggable; exclude close button from drag region
- Add aria-label to close button and enable top bar window dragging
- Removed frame
- Revise README with new version and documentation links
- Backed zoom out a bit
- Made error go away automatically on correct filter
- Update README.md
- Reorganize into Backend.md and Frontend.md with all new searchable attributes and output frames
- Add HTTP protocol decoder to backend and frontend
- Changed `packet.protocol` to `packet.proto` for uniformity
- Add SNMP, ICMP, SIP, DHCP, and NTP protocol support
- Add UDP and DNS packet support on backend and frontend
- Default save dialog to user's Documents folder cross-platform
- Fix pointer to the filesave worker
- Copy temp `hosts.json` to dest instead of passing data through IPC
- Add threaded save-JSON function
- Remove save functions
- Backend exits silently when output dir exists (remove `input()` prompt, clean dir before each run)
- Reset state on subsequent file loads after saving
- Rename all snake_case function names to camelCase in snitch.py and scripts.js
- Fix code review issues: JSON key literals, string comparisons, comment typos, and filename
- Rename variables to camelCase with descriptive names across frontend and backend
- Now filter with target host selection keeps in track with filter readout
- Add Save JSON button with save-as functionality
- Reloading with optimized backend
- Removed .exe
- Removed useless icons
- Fixed nollm call
- Add LLM enable/disable checkbox to frontend; add `--no-llm` backend flag
- Added dev install instructions
- Improve README with images and usage sections
- Updated version
- Fixed part of bookmark code that isn't available if host pointer is incorrect
- Fixed off by one in bookmark code
- Fixed bookmark code
- Fixed horizontal scroll on packet payload pane (disabled)
- Fix note to remove `dns.hostnames` (non-leaf) reference
- Add Searchable Attributes section with all dot-notation leaf nodes
- Update README with new version and screenshot
- Added new screenshot
- Updated version
- Fixed timestamp and recon positioning
- Fix payloadascii tooltip not showing on hexg mouseover
- Removed a few old unworking samples
- Added some new properly formatted search parameters
- Added a timer for how long it took to load the file read
- Fixed a few things, added a packet size and filter ret size readout
- Added some new functionality with counting packets on the sidebar
- Fixed some positioning and zindex stuff
- Fixed zoom bug
- Bringing up ver
- Fixed some initial display bugs
- Now properly handles when no packets are returned from filter
- New screenshot, a couple updates to comparison
- Added better filtering mechanism
- Now index should work right (it was adding twice to the array)
- Filter works better now
- Added some filter code
- Filter code is mostly working
- Filtered is almost working right
- Starting to build filter functions
- Better compression logic
- Better DNS host logic, also added catchall error handling
- Better error handling, loading dots blink now
- Made some small changes to the summary box
- Fixed bug if encryption stuff is undefined
- Added an error message function
- Updated some stuff for squirrel install
- Added some failsafes
- Updated screenshot
- Version update
- Fixed a bug in the data box, added a few more data points
- Added a new pane for more extra infos
- Added a nice loading screen
- Cleaned up code a bit, now makes sure backend is dead on quit
- Added icons for the installers and exe
- Building first working bins
- Windows version builds and works!
- Updated for os detection
- Adjustments for build
- Should work better calling the backend now when installed
- Initial commit

### 🐛 Fixes

- Make all boxes resize relative to window size using flexbox and CSS variables
- Add parenthesis grouping support to packet filter query parser
- Use Unix-style path for non-Windows platforms in back-comm.js
- Resolve all JavaScript errors in src/ files
- Fix payloadascii tooltip not showing on hexg mouseover
- Updated linting config
- Fix some things with eslint

### 🗑️ Removed

- Window frame (frameless window)
- A few old unworking samples

### 🔧 Improvements

- Various UI improvements
- Updated version number
- Updated screenshot
- Removed .exe
- Removed useless icons
- Fixed bookmark code

---

## v1.2.227 - 2026-04-15

**Type:** minor

### ✨ Features

- Add HTTP protocol decoder to backend and frontend
- Changed `packet.protocol` to `packet.proto` for uniformity
- Add SNMP, ICMP, SIP, DHCP, and NTP protocol support
- Add UDP and DNS packet support on backend and frontend
- Default save dialog to user's Documents folder cross-platform
- Fix pointer to the filesave worker
- Copy temp `hosts.json` to dest instead of passing data through IPC
- Add threaded save-JSON function
- Rename all snake_case function names to camelCase in snitch.py and scripts.js
- Reset state on subsequent file loads after saving
- Add Save JSON button with save-as functionality
- Add LLM enable/disable checkbox to frontend; add `--no-llm` backend flag
- Improve README with images and usage sections
- Updated version
- Fixed part of bookmark code that isn't available if host pointer is incorrect
- Fixed off by one in bookmark code
- Fixed bookmark code
- Fixed horizontal scroll on packet payload pane (disabled)
- Removed a few old unworking samples
- Added some new properly formatted search parameters
- Added a timer for how long it took to load the file read
- Fixed a few things, added a packet size and filter ret size readout
- Added some new functionality with counting packets on the sidebar
- Fixed some positioning and zindex stuff
- Fixed zoom bug
- Better compression logic
- Better DNS host logic, also added catchall error handling
- Better error handling, loading dots blink now
- Made some small changes to the summary box
- Fixed bug if encryption stuff is undefined
- Added an error message function
- Updated some stuff for squirrel install
- Added some failsafes
- Fixed a bug in the data box, added a few more data points
- Added a new pane for more extra infos
- Added a nice loading screen
- Cleaned up code a bit, now makes sure backend is dead on quit
- Added icons for the installers and exe
- Building first working bins
- Windows version builds and works!
- Updated for os detection
- Adjustments for build
- Should work better calling the backend now when installed
- Initial commit

### 🐛 Fixes

- Make all boxes resize relative to window size using flexbox and CSS variables
- Add parenthesis grouping support to packet filter query parser
- Various UI fixes

### 🗑️ Removed

- Window frame (frameless window)
- A few old unworking samples

---

## v1.1.195 - 2026-04-13

**Type:** minor

### 🗑️ Removed

- Useless icons

### ✨ Features

- Removed useless icons
- Added new ver
- Add LLM enable/disable checkbox to frontend; add `--no-llm` backend flag
- Fixed nollm call
- Added dev install instructions
- Improve README with images and usage sections
- Fixed part of bookmark code that isn't available if host pointer is incorrect
- Fixed off by one in bookmark code
- Fixed bookmark code
- Fixed horizontal scroll on packet payload pane (disabled)

### 🔧 Improvements

- Optimized snitch.py backend - O(1) lookups, GeoIP cache, thread safety, fix bugs
- Backed off threads again

---

## v1.1.184 - 2026-04-12

**Type:** minor

### ✨ Features

- Updated version
- Fixed part of bookmark code that isn't available if host pointer is incorrect
- Fixed off by one in bookmark code
- Fixed bookmark code
- Fixed horizontal scroll on packet payload pane (disabled)
- Add Searchable Attributes section with all dot-notation leaf nodes
- Update README with new version and screenshot
- Added new screenshot
- Updated version #
- Fixed timestamp and recon positioning
- Fix payloadascii tooltip not showing on hexg mouseover
- Removed a few old unworking samples
- Added some new properly formatted search parameters
- Added a timer for how long it took to load the file read
- Fixed a few things, added a packet size and filter ret size readout
- Added some new functionality with counting packets on the sidebar
- Fixed some positioning and zindex stuff
- Fixed zoom bug
- Bringing up ver
- Fixed some initial display bugs
- Now properly handles when no packets are returned from filter
- Added better filtering mechanism
- Better compression logic
- Better DNS host logic
- Better error handling
- Added a nice loading screen
- Cleaned up code a bit
- Initial commit

### 🗑️ Removed

- A few old unworking samples

### 🔧 Improvements

- Made all boxes resize relative to window size using flexbox and CSS variables
- Add parenthesis grouping support to packet filter query parser
- Various UI improvements

---

## v1.0.175 - 2026-04-13

**Type:** patch

### 🗑️ Removed

- Useless icons

### 🔧 Improvements

- Removed useless icons
- Version bump
- Updated version

---

## v1.0.158 - 2026-04-01

**Type:** major

### 🗑️ Removed

- Window frame (frameless window)

### ✨ Features

- First stable 1.0 release
- Initial application framework
- Backend Python service integration
- Frontend Electron UI
- Filter system
- Bookmark system
- Hex grid payload viewer
- Info panel and packet details
- Data box with packet information
- Loading screen
- Window frame removed
- Cross-platform installers (Windows, Linux, macOS)
- Auto-update functionality
- Statistics tab
- Stream statistics
- Compression and encoding detection
- Network class detection
- GeoIP location data
- Hostname resolution
- LLM integration in backend

### 🐛 Fixes

- Fixed many initial display bugs
- Filter improvements
- Bookmark logic improvements
- Backend process management on quit
- Various UI bugs

---

## v0.9.130alpha - 2026-03-24

**Type:** major (alpha)

### ✨ Features

- Alpha release
- Initial working binaries (Windows, Linux, macOS)
- Application framework
- Backend Python service (snitch.py)
- Frontend Electron UI
- Filter system
- Bookmark system
- Hex grid payload viewer
- Info panel
- Statistics
- GeoIP integration
- Hostname resolution
- Squirrel installer integration
- OS detection
- Icons and branding
- Build configuration

---

## Initial Development - 2026-02-17 to 2026-03-24

**Type:** pre-alpha

### ✨ Features

- Initial project commit
- Project scaffolding
- Basic Electron + Python backend architecture
- Working on bookmark dropdown and its relative functions
- Now full packet data works in JSON and Prev/Next works properly
- Added next/prev buttons to walk through packets
- Some logo stuff for the real logo (not the placeholder)
- Fixed some things and changed color scheme
- Worked on getting divs and fonts right on frontend
- Consolidated some ideas and mockups to one folder
- Add screenshot section to README
- Added a screenshot for the docs page
- Add image to README for PacketSnitch
- Created a grid for the hex payload, and timestamp in info panel
- Updated screenshot
- Updated screenshot
- Added two pane system, now pulling the Hex encoded payload works
- Trying out new layout scheme
- Added an info pane and payload pane, ontop of each other
- Bookmarks work now
- Bookmark function needs rewrite, but layout should be right
- Now we have a dedicated right pane
- Working on bookmark dropdown and its relative functions
- Now full packet data works in json and Prev/Next works properly
- Added next/prev buttons to walk through packets
- Added some logo stuff for the real logo (not the placeholder
- Fixed some things and changed color scheme
- worked on getting divs and fonts right on frontend
- Updated logo stuff
- updated screenshot in docs
- Populated some of the panels, needs some work on spacing and stuff
- Got next page thing working without doubling up
- Added a checksum table, and table creation routine
- Fixex box repeating itself
- Trying to make things congruent
- GNU GPLv3 reference in readme
- Rename LICENSE to LICENSE.md
- Updated readme for new ss
- Uploaded screenshot 14 (windows)
- Matched up some alignment stuff better in the CSS
- updated docs for some deps
- updated screenshot
- Now grid highlights and dehighlights properly
- Now a hover box with offset and ascii text representation of the hexgrid fades into view on mouseover
- Updating screenshot and readme
- Added better location logic, now can run the backend from frontend on packet capture load
- Trying to get backend hook working
- Polling now works right
- Got the IPC from renderer to call the bridge handler on preload.js which accepts our json packet[4~ data pulled in main.js
- Fixed some things like the incorrect network class, and added a default config from a stash
- Lining it up
- Entropy box works now
- Got tables the right width
- Added some things to sidebar (location)
- Small tweaks to alignment
- now doesn't barf if you click data without selecting a host, also has sort of help menu
- Some tuning to the interface
- Trying to add binary to run
- Some documentation/comments on the scripts
- Added logo on readme
- Added image to README for PacketSnitch
- Trying out new layout scheme
- Add image to README for PacketSnitch
- Change logo image link in README.md
- Update image links in README.md
- Added the xcf of hte byline
- Updated screenshot
- Modified colorscheme, added transparent byline and logo
- Fixed bookmark logic so it doesn't get stuck on undefined host. Changed some icons
- Update funding usernames in FUNDING.yml
