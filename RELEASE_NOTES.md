# Release Notes

## v2.3.1694 - 2026-07-25
**Type:** minor

### ✨ Features
- **Manual file carving in Conv** — pick arbitrary hex/ASCII byte ranges from any decoded payload and export them as a file. Clickable offsets jump directly to the chosen bytes. Manually carved files are now also surfaced in the **Stats → Carvable Files** list so they can be reloaded later.
- **Manual cursor + Manual Carve merged into a single panel** in Conv — the byte cursor, click-to-seek offset picker, and manual-carve export share one UI surface.
- **Stream / file extraction from archives and compressed data** in Conv — extract embedded files from ZIP, gzip, zlib, tar, and similar payloads, and add them to the carved files list.
- **HTTP carving is more reliable** with webkit form boundary embedded files (multipart/form-data uploads + downloads are picked up cleanly).
- **SMB (Samba) file carving fixed** — multi-file transfers, signing-protected sessions, and large responses now export cleanly.
- **Threat Intel sub-tab in Conv** (replaces the inline reputation card) — dedicated workspace for IP / URL / hash lookups via the **VirusTotal** card (auto-select, detection ratio, last analysis, community score) and the **IPSum** / **Tor** reputation cards. Requires a VirusTotal API key in **Settings → Backend**.
- **Cross Reference Hash** — one button on the **Hashes** sub-tab sends the focused / selected hash (defaulting to SHA-256) straight into Threat Intel as a hash query.
- **Filter autocomplete** in the filter bar — keys and recent values are suggested as you type. Filter bar no longer relies on the legacy textbox.
- **Better IPv6 support** — endpoint strings are bracketed automatically when a port is present (e.g. `2001:db8::1` vs `2001:db8::1]:443`), and the filter tokenizer splits only on the first `:` so raw IPv6 literals work in queries.
- **Better stream hydration/dehydration logic** — only one stream is fully hydrated at a time, and switching streams releases the previous stream's hydrated packets to keep memory bounded.
- **Big-endian nanosecond-resolution pcap support** — captures recorded with high-resolution nanosecond timestamps (big-endian) now decode correctly instead of producing an empty list.
- **List panel blank bug fixed** — captures with a single host now render their first table on initial load (no empty table until the user changes the search/group toggle).
- **Backend now fails fast on unknown filetype magic** — invalid or truncated payloads surface a clear error instead of silently producing empty guesses.
- **Better XML / JSON / YAML decoders** in Conv — generic structured-data decoders were renamed and now share auto-detect logic; JSON auto-detects from trimmed `{`/`[` input.
- **Analyze Subnet (Conv)** — IPv4/IPv6 subnet math, WHOIS, GeoIP, Shodan, IPSum, and Tor lookups via the new backend HTTP service (`/geoip`, `/whois`, `/ipsum`, `/tor`, `/shodan`).
- **Optional Nmap `-sV` service enumeration** in Analyze Subnet, gated by `general.nmapServiceScanEnabled` (default off). Results cache per-IP for the active session.
- **Stats → Carvable Files** — discovered carve candidates across HTTP/FTP/NFS/SMB streams (plus manually carved files) appear as clickable tags that load the carved bytes directly into Conv with a **Filename Guess**.
- **Backend HTTP service mode** — long-lived HTTP/JSON service replacing per-run spawn. Endpoints: `GET /ping`, `GET /version`, `GET /status` (also `/`), `POST /process` (NDJSON progress + snapshots), `POST /control` (`set-runtime-config`, `stop-processing`, `shutdown`), plus `/geoip` / `/whois` / `/ipsum` / `/tor` / `/shodan` lookups.
- **Worldmap / Internet heatmap** in Stats — GeoIP basemap with zoom, intensity, point size, tightness, and blur controls. Aggregate by **Entire Capture** vs **Filtered Packets**, intensity by **Packets** vs **Bytes**. Click a location dot to zoom, click again to filter by host traffic.
- **PGP workspace in the Crypt tab** — scan packet payloads for ASCII-armored OpenPGP blocks, analyze structure, convert armor↔binary, decrypt/verify with optional armored private/public keys plus packet-derived passphrase candidates, and promote validated private keys / passphrases to the session keystore.
- **Plugin engine with dot-notation capabilities** — sandboxed VM runtime with restricted `context.api.*` APIs, guarded DOM proxies, capability-gated FS / network / backend access, denied-attempt activity logging, and a capability catalog exposed to the renderer.
- **Settings workspace** — General, Backend, LLM, Debug, and About sub-tabs. Persistent in `userData/config/settings.json`, exposed to the renderer via `settingsapi`. Includes per-backend tuning (TCP host/port, worker threads, chunk size, force-legacy spawn), LLM runtime controls (model, API key, timeout, retries, activeByDefault, backgroundSummaryGenerationEnabled), and Debug controls (progressive-load throttles, frontend ingest threading, worldmap projection calibration, ungrouped list virtualization, backend HTTP data mode).
- **Theme engine** — file-driven, runtime-discoverable. Built-in defaults bundled in `themes/*.json`, user-editable themes mirrored to `userData/themes`, persisted via `general.themeId`. Theme switching clears prior inline custom properties to avoid mixed color schemes.
- **LLM moved to the frontend** — Ollama calls now flow through `window.llmapi` (`ipcMain('ollama:generate')`) and are gated by both `llm.activeByDefault` and the startup Ollama daemon check. Diagnostics (install / online / cloud API / last call result) are mirrored to the LLM settings panel.
- **Stream-context follow-up summaries** — while navigating packets, the frontend summarizes the active conversation stream after a short idle delay and appends new findings to the Summary pane. Conv subtab tracking prevents redundant summary calls. **Export Summary as HTML** in the context menu now includes inline data URIs for any carved images so summaries can be archived/ported as self-contained HTML.
- **Keystore auto-build expanded** — extracts HTTP Basic / form / cookie entries, HTTP request target URLs, FTP USER/PASS (port 21), SMTP AUTH (25/465/587), IMAP LOGIN (143/993), RDP user:/pass: (3389), SIP Digest + Basic + email (5060/5061), plus hostnames, IPv4s, emails, and URLs from packet text. Auto-population runs in the background via `requestIdleCallback`; stub packets are hydrated on demand via `captureapi.getPacket`.
- **Saved-filter library** — right-click save of the current filter query into a centralized `config/filters.json` (via `savedfiltersapi`); the top filter dropdown merges labeled saved filters with session-local `filterHistory` entries. Uses an in-app centered modal dialog (no native `window.prompt` dependency).
- **Filter bar bookmark expressions** — `bookmark:true` / `bookmark:false` with `!=`, `!`, `&&`, `||`, and parentheses; **Bookmarked** virtual option in Target Host.
- **Lazy / progressive capture loading** — packet stubs are built immediately, full payloads hydrate on demand (`window.captureapi`), NDJSON snapshots stream from the backend, and a left-panel partial-data warning appears until the final `hosts.json` arrives. Session save/export is blocked until backend preprocessing completes.
- **Saved sessions** — autosave every 5 minutes, compressed on disk (LZMA via `lzma-native` with gzip fallback, or `.psb` BSON+gzip when `debug.bsonGzipSessionEnabled` is on).
- **Notes workspace with Markdown preview** — `marked` renders GFM tables/headings/lists/blockquotes/code/links into a sanitized preview pane; LLM actions explicitly state Markdown support in both query and response. LLM-generated notes are added collapsed by default.
- **Activity log noise reduction** — duplicate renderer console entries suppressed for 5 s, `[Worker] Processing packet` lines dropped, and repeated Host Data navigation messages cached.
- **Host Data layered protocol panel** — deduped Link/Network/Transport/Application/Encryption/Decoded entries; Data Type List hidden by default for ARP/RARP/IGMP with an inline reveal control.
- **Stats panel additions** — Total Traffic (bytes), Credentials Found (keychain), ARP/RARP Operations, IGMP Message Types, Carvable Files.

### 🐛 Fixes
- Removed duplicates in the backend JSON output (per-stream app protocol labels are normalized to the first/last decodable packet's label).
- Sidebar sizing no longer relies on an undefined `--sidebar-width`; left/right sidebars use a pinned flex basis so they do not shrink unexpectedly on Windows.
- List tab initial render now triggers when at least one host exists (was `> 1`), so single-host captures no longer start with an empty table.
- `processBackendJsonDataPayload` skips the O(N) `countCaptureDataPackets` recount after the first chunk load.
- `totalPacketCount()` is now cached and versioned by capture id to avoid repeated O(N) recounts during data-tab updates.
- Conv panes now clear on a new session open (previously retained stale state).
- HTTP carving no longer misses webkit form boundary embedded files.
- SMB file carving now correctly handles signing-protected and large multi-file transfers.
- Crypt tab certificate/PGP flows no longer report empty entries when `Encryption Data` is present; TLS decrypt now prefers `entry.decryptPayloadHex` so leading stream/header bytes are skipped.
- Backend now returns a proper 500 (not silent) on `cryptography` import failures so the install screen surfaces a useful remediation message.
- Manual Conv file imports respect `general.manualConvImportMaxBytes` and warn above 512 KiB.
- Frontend CSP injection is now scoped to local app documents (so the docs/Help site CSP is not overridden).
- Installer first-run probe now checks multiple backend candidates so dev/installer layouts don't falsely report a missing backend.
- Image auto-decodes (JPEG/PNG/GIF/WebP) now show the scaled image and EXIF table in the **Decodes** sub-tab of Conv.
- Filter alias `application-proto` prefers `Traits.Network Data` labels so stale explicit app-proto values don't bleed packets into the wrong Host Data protocol filter.
- IPv6 endpoint strings are normalized (compressed form, brackets, port) before IP validation/lookup across context menu, Crypt filter queries, and Nmap targets.
- LLM startup diagnostics correctly require both `ollama --version` and `ollama list` (backend reachable) before setting `ollamaInstalled=true`.
- Saved filter label input uses the in-app centered modal dialog on all platforms (works around missing native `window.prompt` in some Electron contexts).
- New session restore: legacy `Host` (capital H) key is now mapped to `host` to avoid a false "Invalid JSON file" error.
- Filter bar in Electron no longer relies on `window.prompt` for save/label flows.

### ⚠️ Breaking Changes
- Saved sessions need to be discarded and rebuilt from their pcap (legacy `json.xz` sessions produced before the BSON/gzip pipeline shipped may not round-trip cleanly).
- Backend service mode is the default. If you run multiple PacketSnitch instances against the same userData, set distinct `backend.tcpHost` / `backend.tcpPort` per instance in **Settings → Backend**.
- Analyzer subtab rename: the previous **IP Reputation / Threat Intel** card in Analyze Subnet has been moved to its own **Threat Intel** sub-tab in Conv.

### 🔧 Notes for Upgraders
- Packetsnitch 2.0+ is an Electron-Forge / Webpack application. Source builds need `npm install` followed by `npm run make` (which builds the bundled `snitch` Python backend via PyInstaller then the Electron app). Developers using Fedora should also run `npm run patch-rpm-build`.
- The bundled Python backend now includes GeoIP, WHOIS, Shodan, IPSum, Tor, and VirusTotal lookup endpoints. Backend runtime configuration lives in **Settings → Backend**.
- LLM is optional and runs locally via Ollama. Configure the model + API key in **Settings → LLM**.

---

## v2.2.1638 - 2026-07-18
**Type:** minor

### ✨ Features
- **Plugin support expanded** — runtime guards and per-plugin failure tracking foundations.
- **Backend ico** for the bundled `snitch` executable on Windows.
- `--icon` removed from the PyInstaller invocation in favor of the spec file (cleaner Linux/macOS builds).

### 🐛 Fixes
- N/A

### ⚠️ Breaking Changes
- N/A

---

## v2.1.1606 - 2026-07-16
**Type:** minor

### ✨ Features
- Initial **plugin engine** scaffolding with capability checks.
- **Updated build config** and description metadata for the Electron-Forge pipeline.

### 🐛 Fixes
- N/A

### ⚠️ Breaking Changes
- N/A

---

## v2.0.1573 - 2026-07-15
**Type:** major

> The **2.0 release** introduces the new long-lived **Backend HTTP service** (replacing per-run spawn), the **Settings workspace**, the **Plugin engine**, the **Crypt PGP workspace**, the **Worldmap / Internet Heatmap**, the **Backend HTTP server**, the **Threat Intel** workspace (replacing inline IP reputation), the **Analyze Subnet** panel in Conv, the **Notes Markdown preview** (`marked`), and the **first version of the LLM running in the frontend**. The 2.0 cycle also lands the new **`.psb` BSON+gzip session format**, **streamed NDJSON snapshots**, **multi-job backend processing** with job IDs, and the foundation for **progressive / lazy capture loading**. Saved sessions produced before 2.0 should be discarded (legacy `json.xz` saves may not round-trip cleanly under the new pipeline).

### ✨ Features
- **Backend HTTP server / long-lived service** — `/ping`, `/version`, `/status` (and `/`), `/process` (NDJSON `application/x-ndjson` for progress + incremental snapshots), `/control` (`set-runtime-config`, `stop-processing`, `shutdown`), plus `/geoip`, `/whois`, `/ipsum`, `/tor`, `/shodan` lookup endpoints used by the new Analyze Subnet panel.
- **Worldmap / Internet Heatmap** (Stats) — themed SVG basemap with zoom, intensity, point size, tightness, blur, and **Aggregate By** (Entire Capture / Filtered) + **Intensity By** (Packets / Bytes) toggles. Click a location dot to zoom, click again to filter by host traffic.
- **PGP workspace in the Crypt tab** — scan packet payloads for ASCII-armored OpenPGP blocks, analyze structure, convert armor↔binary, decrypt/verify with optional armored private/public keys plus packet-derived passphrase candidates.
- **Settings workspace** — General, Backend, LLM, Debug, Plugins, and About sub-tabs. Persisted to `userData/config/settings.json` and exposed to the renderer via `settingsapi`.
- **LLM now in the frontend** — Ollama calls flow through `window.llmapi -> ipcMain('ollama:generate')`; startup diagnostics (install / online / cloud API / last call result) are mirrored to the LLM settings panel.
- **Threat Intelligence** under IP information in the Subnet Calc subtab of Conv — IPSum blocklist and Tor exit-node reputation lookups via the new backend HTTP endpoints.
- **Subnet calculator panel** in Conv — queries the backend HTTP service for GeoIP, IPSum, Tor exit-node, and Shodan enrichment data under the calc.
- **Notes Markdown preview** — `marked` renders GFM tables/headings/lists/blockquotes/code/links into a sanitized preview pane.
- **Streamed NDJSON backend output** — captures stream as `application/x-ndjson` (progress events + incremental `hosts-*.json` snapshots) instead of waiting on disk files.
- **Multi-job backend processing** with explicit job IDs across the backend and the frontend.
- **New `.psb` BSON+gzip session format** (default in `debug`) — removes the xz/lzma dependency for session save/load.
- **Pagination for large streams** loaded into Conv plus threading for faster loading.
- **One-shot override for the decodes subtab in Conv** so any Conv data can be sent there.
- **Improved SIP handling** under the Conv tab decoders.
- **Better LDAP decoder** support.
- **Updated Samba decoder** (foundation for the later 2.3 SMB carving fixes).
- **List tab column rearrange support** and a virtualization fix for the scrollable list.
- **Frontend logging tunables** to reduce main-thread load; **better word wrapping**; **new UI main-thread logging backlog defaults**.
- **New release check + Download new release button** in the About panel.
- **Initial oneshot override for the decodes subtab on Conv** so any Conv data can be sent there.
- **Better backend kickoff** and detection of Windows / RedHat / Debian packaging flavors.
- **Detection of Windows / RedHat / Debian packaging flavors** for installer first-run probes.
- **Initial Subnet calculator** in Conv with GeoIP, IPSum, Tor, and Shodan enrichment.
- **Nmap scan support** scaffolding inside the Subnet Calc subtab of Conv.
- **Streamlined frontend with stream payload caches** and fixed credentials uniqing in the Stats panel.
- **Packet ingestion streamlining** on the frontend.
- **Updated User-Agent string** globally.
- **Tuned LLM and Send to Notes data shapes** for Markdown compatibility.
- **IP/Subnet analyzer** with Shodan support and **Threat Intelligence** under IP information.
- **Streamlined packet ingestion** on the frontend.
- **Major backend serialization bugfix** alongside the new NDJSON pipeline.
- **Startup splash** during backend boot.
- **Bundle themes** in the installer.

### 🐛 Fixes
- Removed duplicates in the backend JSON output.
- Sidebar sizing no longer relies on an undefined `--sidebar-width`; left/right sidebars use a pinned flex basis.
- List tab initial render now triggers when at least one host exists (was `> 1`).
- HTTP body and file carving cleanup.
- Stats panel no longer shows non-clickable password badges or junk data.
- Settings tab overlap bug.
- Filter bleed bug.
- Backend can now find `common/` in installer/portable layouts.
- MAC address pulling IP into field bug on the backend.
- `HOST` / `host` key normalization in legacy session files.
- Cross-platform backend install probing so dev/installer layouts no longer falsely report a missing backend.

### ⚠️ Breaking Changes
- Saved sessions need to be discarded and rebuilt from their pcap (legacy `json.xz` sessions produced before the BSON/gzip pipeline shipped may not round-trip cleanly).
- Backend service mode is the default; multi-instance setups must set distinct `backend.tcpHost` / `backend.tcpPort` per instance.
- Preprocessor legacy keys were removed — any non dot-notation session saves from before 2.0 are no longer compatible.

### 🔧 Notes for Upgraders
- 2.0 is an Electron-Forge / Webpack application. Source builds need `npm install` followed by `npm run make` (which builds the bundled `snitch` Python backend via PyInstaller then the Electron app). Developers using Fedora should also run `npm run patch-rpm-build`.
- The bundled Python backend now includes GeoIP, WHOIS, Shodan, IPSum, Tor, and (in later 2.x) VirusTotal lookup endpoints. Backend runtime configuration lives in **Settings → Backend**.
- LLM is optional and runs locally via Ollama. Configure the model + API key in **Settings → LLM**.
- New session saves default to `.psb` BSON+gzip when `debug.bsonGzipSessionEnabled` is on (default in 2.0). To keep reading legacy `json.xz` saves, leave the flag off until you've re-saved.

---

## v1.9.1565 - 2026-07-14
**Type:** minor

> Bridge release between 1.8 and 2.0 that lands the **new `.psb` BSON+gzip session format**, the **streamed NDJSON backend output**, the **multi-job backend pipeline**, the **Pagination for large streams** in Conv, the **List tab column rearrange support**, and **frontend logging tunables**. Most of these features are absorbed into the 2.0 release notes; 1.9 is kept here as the transitional minor so existing 1.x users have a clean upgrade path.

### ✨ Features
- **New `.psb` BSON+gzip session format** (default in `debug`).
- **Pagination for large streams** in Conv plus threading for faster loading.
- **NDJSON streamed output** (`application/x-ndjson`) from the backend.
- **List tab column rearrange** and virtualization fix for the scrollable list.
- **Frontend logging tunables** to reduce UI main-thread load.
- **New UI main-thread logging backlog defaults**.
- **One-shot override for the decodes subtab on Conv** so any Conv data can be sent there.
- **Improved SIP handling** under Conv tab decoders.
- **Better LDAP decoder** support.
- **Updated Samba decoder**.
- **Tuned LLM and Send to Notes data shapes** for Markdown compatibility.

### 🐛 Fixes
- Removed duplicates in the backend JSON output.
- Filter bleed bug.
- Settings tab overlap bug.
- Fixed list tab scrolling bug on virtualized lists.
- Major backend serialization bug fix.
- `HOST` / `host` key normalization in legacy session files.

### ⚠️ Breaking Changes
- Saved sessions need to be discarded and rebuilt from their pcap.

---

## v1.9.1529 - 2026-07-11
**Type:** minor

### ✨ Features
- **Subnet calculator panel** in Conv with GeoIP, IPSum, Tor, and Shodan enrichment lookups.
- **Threat Intelligence** under IP information in the Subnet Calc subtab of Conv.
- **Nmap scan support** scaffolding inside the Subnet Calc subtab.
- **IP/Subnet analyzer** with Shodan support and Threat Intelligence under IP information.
- **Streamlined frontend with stream payload caches** and fixed credentials uniqing in Stats.
- **Packet ingestion streamlining** on the frontend.
- **Multi-job backend processing** with explicit job IDs.
- **Major backend serialization bugfix** alongside the NDJSON pipeline.
- **Startup splash** during backend boot.
- **New release check** and download button in the About panel.
- **Detection of Windows / RedHat / Debian packaging flavors** for installer first-run probes.
- **Bundle themes** in the installer.
- **Initial oneshot override for the decodes subtab on Conv** so any Conv data can be sent there.

### 🐛 Fixes
- Sidebar sizing no longer relies on an undefined `--sidebar-width`.
- HTTP body and file carving cleanup.
- Stats panel no longer shows non-clickable password badges or junk data.
- Backend can now find `common/` in installer/portable layouts.
- MAC address pulling IP into field bug on the backend.

### ⚠️ Breaking Changes
- Saved sessions need to be discarded and rebuilt from their pcap.

---

## v1.9.1442 - 2026-07-07
**Type:** minor

### ✨ Features
- **Tests scaffolded** under `tests/` with a backend JSON validity test, a backend HTTP service test, and a backend SMB decoder test.
- `npm run tests` now runs both backend (`pytest`) and frontend (`jest`) test suites.
- Backend test harness with pretty output.

### 🐛 Fixes
- Removed duplicates in the backend JSON output.

### ⚠️ Breaking Changes
- N/A

---

## v1.8.1442 - 2026-07-05
**Type:** minor

### ✨ Features
- Worldmap
- Backend HTTP server
- PGP workspace in the Crypt tab
- Settings tab
- LLM now in frontend

### 🐛 Fixes
- Removed duplicates in the backend json

### ⚠️ Breaking Changes
- Saved sessions need to be discarded and rebuilt from their pcap.

