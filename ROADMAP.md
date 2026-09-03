# PacketSnitch Roadmap & Implementation Tracker

> **A rolling, living document.** This file merges the historical `ideas.txt`
> backlog with the `RELEASE_NOTES.md` history. Each item has a status, a
> current-state description, and an estimate of remaining work. Update this
> file as features are added, scoped down, or retired so the next person
> (or future us) can pick up where the last one left off.

---

## Release velocity (how fast this project actually ships)

The day-counts in this file are **calibrated to PacketSnitch's actual
release cadence**, not generic estimates. From v0.9.130alpha on
2026-03-24 through v2.4.2169 on 2026-07-27 (29 tagged releases in 125
days):

- **Average:** 1 release every **~4.3 days** (rolling 30-day average
  during active development is closer to **1 every 1–3 days**).
- **Largest gap:** ~10 days, only when crossing a major version
  boundary (1.0 → 1.5 was the longest at 58 days; 1.5 → 2.0 was 13).
- **Per-release footprint:** most releases bundle 5–25 bullet-level
  changes, often spanning frontend, backend, tests, docs, and
  installers in a single cut.

**Calibration rule** (used to scale the original backlog estimates):

| Original complexity | Original est. | This project's reality |
| --- | --- | --- |
| Low | 1–4 days | **0.5–1 day** (frequently ship in a single release) |
| Medium | 3–8 days | **1–2 days** (1–2 releases) |
| High | 6–12 days | **2–4 days** (1–2 weeks, 2–4 releases) |
| Very High | 18–40 days | **1–2 weeks** (5–10 releases) |

In other words: if `ideas.txt` said "10 days", on this project it's
realistically closer to **3–4 days**, often broken into a couple of
shippable slices. The "Est. remaining" numbers in this file already
apply that calibration — when you pick up an item, expect to land it
in days, not weeks.

---

## Status legend

| Symbol | Meaning |
| --- | --- |
| ✅ | Shipped (in a tagged release) |
| 🟡 | Partially implemented (some sub-bullets shipped, others still TODO) |
| 🚧 | In progress (work started in `Unreleased` / current branch) |
| 📋 | Planned (not yet started) |
| 🗄️ | Deferred / parked (decided not to do, or punted to a much later release) |
| ❌ | Withdrawn (no longer relevant) |

> **Priority scale** (P0 highest, P3 lowest) and **Complexity** (Low / Medium /
> High / Very High) are kept from the original backlog so we don't lose the
> signal.

---

## Table of contents

- [High priority features](#high-priority-features)
- [Release 0.9.0 — Quick wins](#release-090--quick-wins)
- [Release 0.10.0 — Analyst depth](#release-0100--analyst-depth)
- [Release 0.11.0 — Advanced forensics](#release-0110--advanced-forensics)
- [Detection & analysis](#detection--analysis)
- [Visualization & investigation](#visualization--investigation)
- [Protocol support](#protocol-support)
  - [ICS / SCADA protocol decoders](#ics--scada-protocol-decoders)
  - [Routing / network-control protocol decoders](#routing--network-control-protocol-decoders)
  - [Service-discovery / LAN protocol decoders](#service-discovery--lan-protocol-decoders)
  - [Crypto / secure-channel metadata parsers](#crypto--secure-channel-metadata-parsers)
- [AI features](#ai-features)
- [Long-term (1.0+)](#long-term-10)
- [Future / advanced ideas](#future--advanced-ideas)
- [Suggested execution order](#suggested-execution-order)
- [Backend optimizations](#backend-optimizations)
- [Recently shipped (release history mirror)](#recently-shipped-release-history-mirror)

---

## High priority features

### Session / Conversation Reconstruction

> **Status:** 🟡 Partial — TCP/UDP stream reassembly, HTTP follow, FTP/SIP
> decoders, SMB follow-stream, and an in-app follow-stream UI exist. SMTP
> session view, FTP transfer reconstruction, and the unified HTTP *session*
> view (vs. one-shot body extraction) still need work.

- [🟡] Reassemble complete TCP/UDP conversations — **shipped** via the
  backend HTTP service and the Conv tab's stream stack.
- [🟡] Display client/server request-response chains — basic chain view
  exists in the List/Stats tabs; a dedicated "Request → Response" tree per
  conversation is still TODO.
- [🟡] HTTP session view — body extraction ships; full session log (one
  row per request) is partial.
- [📋] SMTP session view
- [📋] FTP transfer reconstruction (control channel parsing ships in
  decoder, but no "rebuild the file" view yet)
- [🟡] SMB file activity tracking — SMB Conv decoder + follow-stream
  ships in 2.4.2169 (per-message tree, file content, offsets, dedicated
  `src/ui/decoders/conv/smb-helpers.js`). Activity timeline across the
  capture still TODO.
- [🟡] Load full packet into Conv — new `Load full packet (with
  headers) into Conv` action on the right-click context menu hands
  the selected packet (link-layer headers and all) to the Conv tab
  as the analysis input.

### IOC / Threat Detection Engine

> **Status:** 🟡 Partial — VirusTotal lookup ships under Conv → Threat
> Intel. Bulk threat intel feeds, custom rules, and malware behavior
> detection are still TODO.

- [🟡] Detect known malicious IPs — VirusTotal IP lookup ships.
- [🟡] Detect known malicious domains — VirusTotal domain lookup ships.
- [📋] Detect suspicious user agents
- [📋] Detect common malware behaviors
- [📋] Custom IOC rule support
- [📋] Import threat intelligence feeds (MISP, STIX, custom CSV)

### PCAP Diff Mode

> **Status:** 📋 Planned — nothing shipped.

- [ ] Compare two captures
- [ ] New hosts detected
- [ ] Missing hosts
- [ ] New protocols
- [ ] New ports
- [ ] Traffic volume changes
- [ ] Timeline comparison

### Artifact Extraction Framework

> **Status:** 🟡 Partial — HTTP object extraction, file carving,
> carvable-files context menu, archive / compression unpacking
> (`cab`, `7zip`, `zip`, `tar`, `gz`, `bzip2`, `zstd`), executable /
> image / ZIP extraction, and artifact hashing (MD5 / SHA-1 / SHA-256 /
> 384 / 512 + SHA3, RIPEMD-160, Whirlpool) all ship (see 2.4.2115 /
> 2.4.2169 / Unreleased). Office documents, scripts, an explicit
> PDF extraction pass, and the unified "extract all" workflow are still
> TODO.

- [✅] Extract executables — generic PE / ELF carving ships via the
  extraction panel's MIME detection (`inferMimeType` covers
  `application/x-elf` plus Windows PE magic), and the SMB / NFS / FTP
  file-carve context menu ships for streaming protocols (see
  `carveCurrentStreamToFileFromContextMenu` and
  `registerExtractionResultForStats` in
  [src/ui/main-frontend.js](src/ui/main-frontend.js)).
- [🟡] Extract PDFs — carving detects PDF magic; explicit extraction pass
  still TODO.
- [📋] Extract Office documents
- [✅] Extract ZIP archives — `cab` / `7zip` / `zip` / `tar` / `gz` /
  `bzip2` / `zstd` all unpack via the extraction panel (magic-first
  detection via `inferExtractionFormatName`, extension fallback). See
  [src/ui/main-frontend.js](src/ui/main-frontend.js) (around the
  extraction panel implementation).
- [✅] Extract images — PNG / JPEG / GIF / WEBP plus XML / JSON / YAML /
  HTML / SVG / CSS / JS auto-classification ships via `inferMimeType`,
  and the carvable-files context menu / Conv Extraction panel can
  surface those bytes for save (see `inferMimeType` and
  `registerExtractionResultForStats` in
  [src/ui/main-frontend.js](src/ui/main-frontend.js)).
- [📋] Extract scripts
- [✅] Hash all extracted artifacts — MD5 / SHA-1 / SHA-256 / SHA-384 /
  SHA-512 + SHA3-256 / SHA3-512, RIPEMD-160, and Whirlpool hash outputs
  ship in the Conv tab; loading any extracted artifact into the Conv
  input auto-populates all nine hashes (see `computeDataToolsHashes`
  and `buildConvHashesMarkdownTable` in
  [src/ui/main-frontend.js](src/ui/main-frontend.js)).
- [📋] Export artifacts to disk (bulk)

### Network Graph Visualization

> **Status:** 🟡 Partial — Heatmap view (with the worldmap) and an in-app
  map projection ship. The *graph* view (host nodes, edge weights) is
  still TODO.

- [📋] Host-to-host relationship graph
- [📋] Protocol-based graph coloring
- [📋] Traffic volume weighting
- [📋] Interactive exploration
- [📋] Community clustering
- [📋] Attack path visualization

---

## Release 0.9.0 — Quick wins

### Saved Filter Library

> **Status:** 🟡 Partial — filter history dropdown, label persistence, and
> named filters ship (see 1.9.1442 + 2.4.2115). Categories/tags and
> export/import of filter sets are still TODO.

- [✅] Named filters
- [🟡] Filter categories/tags — labels persist; free-form tag taxonomy
  still TODO.
- [🟡] Quick filter selection — history dropdown ships.
- [📋] Share/export filter sets
- **Priority:** P0 · **Complexity:** Low · **Est. remaining:** 0.5–1 day

### Rule-Based Highlights

> **Status:** 📋 Planned — nothing shipped yet.

- [ ] Color rows based on filter matches
- [ ] Highlight hosts
- [ ] Highlight packets
- [ ] Highlight conversations
- [ ] Severity coloring
- **Priority:** P0 · **Complexity:** Low · **Est. dev time:** 0.5–1 day

### Packet Pinboard

> **Status:** 🟡 Partial — bookmark column on packet list, host bookmarks,
> session-level keychain, and packet-side bookmarking ship. A dedicated
> "pinboard" workspace UI is still TODO.

- [📋] Collect suspicious packets
- [📋] Investigation workspace
- [🟡] Bookmark packet evidence — packet-level bookmarks ship.
- [🟡] Quick navigation — Prev/Next, host-targeted filter, and bookmark
  dropdown ship.
- **Priority:** P1 · **Complexity:** Low · **Est. remaining:** 0.5 day

### IOC Extraction Panel

> **Status:** 🟡 Partial — Stats panel lists IPs, domains, ports, hosts,
> and credentials. A dedicated "IOCs" panel with deduplication and copy
> actions is still TODO.

- [🟡] Extract IP addresses — listed in Stats.
- [🟡] Extract domains — DNS qname aggregation ships in Stats.
- [🟡] Extract URLs — HTTP decoder harvests URLs.
- [🟡] Extract hashes — Conv tab hash outputs cover MD5/SHA family, etc.
- [🟡] Extract email addresses — partial (SMTP decoder captures them; no
  dedicated list yet).
- [📋] IOC deduplication
- **Priority:** P0 · **Complexity:** Medium · **Est. remaining:** 1–2 days

### One-Click IOC Export

> **Status:** 🟡 Partial — "Save session JSON" ships; dedicated IOC
> export (CSV/JSON) is still TODO.

- [🟡] CSV export — covered indirectly via "Save JSON" + manual
  conversion.
- [🟡] JSON export — "Save JSON" ships.
- [📋] Selective export (per IOC type / per host)
- **Priority:** P0 · **Complexity:** Low · **Est. remaining:** 0.5 day

### Report Templates

> **Status:** 🟡 Partial — Summary/Analysis tab with LLM distillation,
> markdown export, a **Reports...** submenu in the right-click context
> menu (Markdown / Text / HTML), a dedicated **Save as PDF** button on
> the Summary workspace header, and a context-menu **Save Report
> (PDF)** entry ship. Named report templates are still TODO.

- [📋] Incident response summary template
- [📋] Triage report template
- [🟡] Executive report — Summary tab with markdown export ships.
- [✅] Exportable templates — Markdown / Text / HTML ship via the
  Reports... context menu submenu; HTML is light-styled.
- [✅] Export to PDF — the Summary header "Save as PDF" button and the
  context-menu "Save Report (PDF)" entry both render the same
  self-contained HTML the HTML exporter uses, then hand it to Electron's
  `webContents.printToPDF` (no third-party PDF dependency).
- **Priority:** P1 · **Complexity:** Low · **Est. remaining:** 0.5 day (templates)

---

## Release 0.10.0 — Analyst depth

### Diff Two Packets

> **Status:** 📋 Planned.

- [ ] Field-by-field comparison
- [ ] Highlight changed values
- [ ] Side-by-side view
- **Priority:** P0 · **Complexity:** Medium · **Est. dev time:** 1–2 days

### Filter Builder UI

> **Status:** 🟡 Partial — filter syntax validation, syntax highlighting,
> history dropdown, and parens/`!`/`&&`/`||` support ship. A true visual
> builder is still TODO.

- [🟡] Visual query builder — covered by syntax highlighting + history.
- [🟡] Boolean groups — `&&` / `||` / parens ship.
- [🟡] Nested conditions — covered by parens grouping.
- [🟡] Live query preview — filter status updates and result count ship.
- [📋] Drag-and-drop condition chips
- **Priority:** P1 · **Complexity:** Medium · **Est. remaining:** 1–2 days

### DNS Threat Lens

> **Status:** 🟡 Partial — DNS decoder + Stats panel aggregation ship.
> DGA / entropy / rare-TLD heuristics are still TODO.

- [📋] Entropy outliers
- [📋] Rare TLD detection
- [📋] NXDOMAIN spikes
- [📋] Suspicious DNS activity summary view
- **Priority:** P0 · **Complexity:** Medium · **Est. dev time:** 1–2 days

### Protocol Anomaly Heuristics

> **Status:** 🟡 Partial — TCP retransmission / out-of-order detection
> ships. Generic anomaly scoring does not. The **Anomalies sub-tab**
> under Stats ships: protocol-content anomalies, portscans
> (`detectStatsAnomaliesPortscan`), brute-force login bursts
> (`detectStatsAnomaliesBruteForce` — FTP/SSH/Telnet/SMTP/POP3/IMAP/
> RDP/VNC/LDAP), baseline packet-length / per-minute outliers
> (`detectStatsAnomaliesBaselineOutliers`), and high-entropy cleartext
> payloads (`detectStatsAnomaliesEmbeddedContent`). The findings render
> as click-to-filter cards in `renderStatsAnomaliesPanel` and the
> detector engine is shared with the Threat Intel sub-tab's
> **Session Threat Score** so the two views never disagree. Future
> work ties per-packet suspicion into the score and adds ranked
> anomaly dashboards.

- [📋] Session suspicion scoring
- [📋] Packet suspicion scoring
- [📋] Protocol misuse detection
- [📋] Behavioral anomalies
- **Priority:** P0 · **Complexity:** Medium · **Est. dev time:** 2–3 days

### Batch Analysis

> **Status:** 📋 Planned.

- [ ] Multi-PCAP ingest
- [ ] Consolidated summaries
- [ ] Cross-capture analysis
- [ ] Batch reporting
- **Priority:** P1 · **Complexity:** Medium · **Est. dev time:** 1–2 days

### Case Workspace

> **Status:** 🟡 Partial — Notes tab + Session save/load + Notes →
> Summary integration (with the "Inferred Data (from Notes)" vs.
> "Verified Notes (from Notes)" split) ship. A unified "Case" entity
> that ties packets, IOCs, sessions, and reports is still TODO.

- [🟡] Notes linked to packets — Notes tab ships; packet-anchored
  references still TODO.
- [🟡] Notes linked to IOCs — manual via copy/paste; structured link
  still TODO.
- [🟡] Investigation organization — session save/load covers most of it.
- [✅] Session persistence — `.psb` (gzipped BSON) is the default session
  format.
- [🟡] Notes auto-feed Summary — every note now appears on the Summary
  tab under "Inferred Data (from Notes)", and the per-note "Mark as
  verified" toggle moves the note to "Verified Notes (from Notes)".
  The flag persists across session save/load.
- **Priority:** P1 · **Complexity:** Medium · **Est. remaining:** 1–2 days

---

## Release 0.11.0 — Advanced forensics

### Expert Events Feed

> **Status:** 📋 Planned.

- [ ] Anomaly event stream
- [ ] Severity ratings
- [ ] Event categorization
- [ ] Timeline integration
- **Priority:** P0 · **Complexity:** High · **Est. dev time:** 2–4 days

### TLS Fingerprinting

> **Status:** 🟡 Partial — TLS handshake decoding ships (HTTPS service
> detection + SNI). JA3 / JA4 fingerprint generation is still TODO.

- [🟡] JA3 fingerprints — handshake info is decoded; JA3 hash still TODO.
- [🟡] JA4 fingerprints — same.
- [🟡] Client identification — covered by User-Agent + SNI heuristics.
- [📋] TLS anomaly detection
- **Priority:** P1 · **Complexity:** Medium · **Est. remaining:** 1 day

### Stream Reassembly

> **Status:** 🟡 Partial — TCP stream stack + Conv follow-stream ship
> (see 2.4.2169). Missing-packet handling and ordered stream view are
> still partial.

- [🟡] TCP payload reconstruction — ships via the stream stack.
- [🟡] Ordered stream view — pagination + "load more" ship.
- [🟡] Missing packet handling — out-of-order / retransmission keys ship

> (see 1.7.935); explicit "show gaps" UI is still TODO.

- [✅] Protocol reconstruction foundation — used by HTTP, FTP, SIP, SMB

> decoders.

- **Priority:** P0 · **Complexity:** High · **Est. remaining:** 2–4 days

### HTTP Object Extraction

> **Status:** 🟡 Partial — body extraction + decompression-aware context
> menu ship. A unified "objects" view is still TODO.

- [🟡] Extract downloaded files — body copy + carve + file context menu
  ship.
- [🟡] Extract HTTP responses — same.
- [🟡] File carving — carvable-files list ships (2.4.2115).
- [🟡] Metadata extraction — MIME + chardet + data type guessing ship.
- [📋] "All HTTP objects" panel
- **Priority:** P0 · **Complexity:** High · **Est. remaining:** 2–4 days

### Timeline View

> **Status:** 📋 Planned — there is a heatmap/worldmap but not a packet
> timeline view.

- [ ] Zoomable timeline
- [ ] Host activity timeline
- [ ] Event overlays
- [ ] Protocol filtering
- **Priority:** P1 · **Complexity:** High · **Est. dev time:** 2–4 days

### Conversation Graph

> **Status:** 📋 Planned.

- [ ] Interactive host graph
- [ ] Service relationships
- [ ] Communication mapping
- [ ] Traffic weighting
- **Priority:** P2 · **Complexity:** High · **Est. dev time:** 2–4 days

### Conv Data Transformations

> **Status:** ✅ Shipped (v2.7.1657). The Conv output panel now
> exposes a dedicated **Data Transformations** block
> (`#data-tools-transform-row` in
> [src/index.html](src/index.html)) with four composable
> transformations, applied in this order: **Invert data** (full
> byte-sequence reversal), **Endianness swap** (16-bit or 32-bit
> word reversal — chosen via a Word radio), **Bit order** (reversal
> of every bit within every byte), and **Transpose** (read bytes
> row-major into a matrix with the user-specified column count,
> then emit column-major). A **Reset Output** button restores the
> untransformed Conv input bytes; **Apply to Output** re-renders
> the panel and writes a
> `Conv output transforms applied transforms=…` line to the
> activity log. The transformations are pure functions in
> [src/ui/data-transformations.js](src/ui/data-transformations.js)
> (`reverseBytes`, `reverseBitOrder`, `swapEndianness`,
> `transposeBytes`, plus the composed `applyDataToolsTransforms`
> runner), exposed to the renderer via `applyDataToolsTransformsToOutput`
> / `resetDataToolsTransforms` in
> [src/ui/main-frontend.js](src/ui/main-frontend.js). The Conv
> input itself is never modified — only the displayed output.
> Covered by `tests/data_transformations.test.js` (reverse,
> swap, bit-order, transpose, error guards, composed runner).

- [✅] Invert (byte reversal) — ships.
- [✅] Endianness swap (16-bit / 32-bit) — ships.
- [✅] Bit-order reversal — ships.
- [✅] Transpose (row-major → column-major) — ships.
- [✅] Non-destructive reset — ships; **Reset Output** restores
  the untransformed Conv input bytes.
- [📋] Drag-to-reorder transformation list (so analysts can pick
  the order without the current fixed inversion → endianness →
  bit-order → transposition pipeline).
- **Priority:** P2 · **Complexity:** Low · **Est. remaining:**
  0.5 day

---

## Detection & analysis

### Beacon Detection

> **Status:** 📋 Planned.

- [ ] Periodic communication detection
- [ ] Low-and-slow beacon identification
- [ ] Jitter analysis
- [ ] C2 behavior scoring

### Suspicious Entropy Dashboard

> **Status:** 🟡 Partial — entropy readout in the data tools/Conv tab
> ships. A ranked dashboard is still TODO.

- [📋] Highest entropy hosts
- [📋] Highest entropy conversations
- [🟡] Encrypted payload detection — entropy box ships in info panel.
- [📋] Potential covert channels

### Credential Exposure Report

> **Status:** 🟡 Partial — auto-detection for HTTP, SMTP, POP3, IMAP,
> Telnet, FTP, SSH ships (see 1.4.508 + 1.7.935). A consolidated
> "Credential Exposure Report" is still TODO.

- [🟡] Basic auth detection — keystore autoadd ships.
- [🟡] FTP credential detection — keystore autoadd ships.
- [🟡] Telnet credential detection — keystore autoadd ships.
- [🟡] SMTP authentication detection — keystore autoadd ships.
- [📋] Password reuse identification
- [📋] Consolidated report

### DNS Intelligence

> **Status:** 🟡 Partial — DNS decoder, qname aggregation, NXDOMAIN
> signals all reachable. DGA / fast-flux / NRD / tunneling detectors
> are still TODO.

- [📋] DGA detection
- [📋] Newly registered domains
- [🟡] NXDOMAIN analysis — visible in Stats; no spike detection.
- [📋] Fast-flux detection
- [📋] DNS tunneling detection

### Secret Detection

> **Status:** 🟡 Partial — keystore autoadd harvests HTTP/SMTP/IMAP/POP3/
> Telnet/SSH/FTP creds. Generic regex-based secret scanners are still
> TODO.

- [🟡] HTTP basic auth + cookies — covered.
- [�] AWS keys — regex detection in token worker + file rescan
- [🚧] Azure keys — regex detection in token worker + file rescan
- [🚧] GCP credentials — Google API keys (AIza), OAuth tokens (ya29.),
  service account private_key_id detection added
- [🚧] JWT tokens — regex detection in token worker + file rescan
- [🚧] API keys — path-key inference for api_key/apikey fields
- [🚧] OAuth tokens — Bearer token + ya29. detection
- [📋] Private keys — PEM block detection in file rescan (packet-level TODO)
- [🚧] Discord tokens — mfa. + base64-dot-base64 pattern detection
- [🚧] GitHub tokens — ghp_/gho_/ghs_/ghu_/github_pat_ detection
- [🚧] Extracted file rescan — "Rescan for Artifacts" button scans extracted/
  carved file bytes for embedded secrets (covers ZIP-extracted,
  decompressed, PGP-decrypted content)

### YARA Integration

> **Status:** 📋 Planned.

- [ ] Scan extracted artifacts
- [ ] Scan payloads
- [ ] Custom rule support
- [ ] Rule hit reporting

---

## Visualization & investigation

### Packet Relationship View

> **Status:** 🟡 Partial — host-targeted filter, Prev/Next, and stream
> grouping ship. A visual flow map is still TODO.

- [🟡] Show linked packets — stream filter ships.
- [🟡] Follow packet chains — Conv follow-stream ships.
- [🟡] Track protocol transitions — `tcp.proto` vs `udp.proto` vs
  `app.proto` keys ship.
- [📋] Visual flow mapping

### Packet Tagging System

> **Status:** 📋 Planned.

- [ ] User-defined tags
- [ ] Color coding
- [ ] Investigation notes (separate from the Notes tab)
- [ ] Tag-based filtering

### Saved Investigations

> **Status:** 🟡 Partial — session save/load + Notes tab cover most of
> this. A first-class "Investigation" entity with cases, evidence, and
> per-investigator state is still TODO.

- [🟡] Case management — session save/load ships.
- [🟡] Investigator notes — Notes tab ships.
- [🟡] Bookmarks — packet + host + keychain ships.
- [🟡] Evidence tracking — session save includes carves + keystore.
- [🟡] Export reports — Summary export + LLM distillation ships.
- [📋] Per-investigator audit trail

---

## Protocol support

### ISO 8583 (Financial)

> **Status:** ✅ Shipped.

ISO 8583 financial protocol decoder added to both the backend
(`src/backend/decoders/iso8583.py`) and the Conv decoder
(`src/ui/decoders/conv/iso8583.js`). Decodes MTI, primary/secondary
bitmap, and standard data elements from ISO 8583 messages over TCP.
Supports both ASCII-hex and binary bitmap encodings, ASCII and binary
variable-length field prefixes, and transparently strips 2- or 4-byte
TPDU/message-length framing prefixes common in ISO 8583 over TCP.
Auto-detect routes matching traffic (ports 8583, 5000, 5001, 14401)
to the new decoder. Sample captures
`samples/pcaps/iso8583_ascii_sample.pcapng` and
`samples/pcaps/iso8583_bin_sample.pcapng` ship for quick smoke-testing.
Coverage: `tests/iso8583_conv_decoder.test.js` (8 tests) and
`tests/test_backend_iso8583_decoder.py` (6 tests).

### QUIC Support

> **Status:** 📋 Planned.

- [ ] Stream analysis
- [ ] Metadata extraction
- [ ] Session reconstruction

### WebSocket Support

> **Status:** 📋 Planned.

- [ ] Message reconstruction
- [ ] Frame analysis
- [ ] Payload decoding

### gRPC Support

> **Status:** 📋 Planned.

- [ ] Service identification
- [ ] Method extraction
- [ ] Message decoding

### WireGuard Support

> **Status:** 📋 Planned.

- [ ] Handshake detection
- [ ] Peer identification
- [ ] Tunnel statistics

### ICS / SCADA protocol decoders

> **Status:** 📋 Planned — none shipped. Industrial control traffic
> is a routine ask in OT forensics and currently surfaces in PacketSnitch
> only as opaque TCP payloads.

These three decoders share the same shape (request/response over TCP,
fixed transaction-id header, function-code / object dictionary): a
backend parser walking the registered function/objects, and a
corresponding Conv stream decoder in
`src/ui/decoders/conv/` that surfaces registers, coils, and typed
objects as a tree. Auto-detect routes on the IANA-assigned port and
the well-known protocol magic (MBAP length-prefix for Modbus, 0x0564
DNP3 sync bytes, S7comm TPKT/COTP ISO-on-TCP framing).

#### Modbus/TCP

- [ ] Function-code decode (read/write coils, holding/input
  registers, diagnostics)
- [ ] Unit-id / transaction-id correlation
- [ ] Exception responses (function-code | 0x80)
- [ ] Auto-detect on TCP/502
- **Priority:** P0 · **Complexity:** Low · **Est. dev time:** 0.5–1 day

#### DNP3

- [ ] Link-layer framing (0x0564 sync, length, control, destination,
  source, CRC)
- [ ] Transport-layer sequence + segment reassembly
- [ ] Application-layer object library (binary inputs / counters /
  analog inputs / events)
- [ ] Auto-detect on TCP/20000 + UDP/20000
- **Priority:** P1 · **Complexity:** Medium · **Est. dev time:** 1–2 days

#### S7comm (Siemens S7 PLC)

- [ ] TPKT / COTP ISO-on-TCP framing (port 102)
- [ ] S7 header + parameter / data block walks
- [ ] Request / response correlation by userdata
- [ ] DB read/write, upload/download station, Pi/PB services
- **Priority:** P1 · **Complexity:** Medium · **Est. dev time:** 1–2 days

### Routing / network-control protocol decoders

> **Status:** 📋 Planned — none shipped. These protocols surface
> backbone / control-plane behaviour that today's HTTP / transport
> layers can't explain (gateway failover, neighbour loss, link
> aggregation membership, vendor discovery).

Routing-protocol decoders are backend-only (they run over raw IP or
link-layer multicast, not TCP/UDP-against-port). The Conv decodes
subtab gets a sidebar-only entry per protocol so analysts can pick it
when the packet's `link.proto` already names the protocol family.

#### OSPF

- [x] Hello / DBD / LSR / LSU / LSAck walks
- [x] LSA type library (Router, Network, Summary, External, Opaque)
- [x] Area + neighbour topology extraction
- [x] IP protocol 89 auto-detect
- **Priority:** P1 · **Complexity:** Medium · **Est. dev time:** 1–2 days

#### HSRP / VRRP

- [ ] HSRP state machine (Initial → Learn → Listen → Speak → Standby
  → Active), priority, group, virtual IP
- [ ] VRRPv2 / VRRPv3 (RFC 5798) advertisement walks
- [ ] Failover event correlation (priority-change deltas)
- [ ] HSRP UDP/1985 (v1) + multicast 224.0.0.2 (v2); VRRP IP proto 112
- **Priority:** P2 · **Complexity:** Low · **Est. dev time:** 0.5–1 day

#### BFD

- [ ] Control / Echo packet decode (RFC 5880/5881)
- [ ] Discriminator pairing for session correlation
- [ ] Detect-time / multiplier extraction (failure timing analysis)
- [ ] UDP/3784 + UDP/4784 (multi-hop)
- **Priority:** P2 · **Complexity:** Low · **Est. dev time:** 0.5–1 day

#### LACP

- [ ] Slow-protocol decode (subtype 0x01)
- [ ] Partner / Actor LACP PDUs (system-id, port-id, key, state)
- [ ] Aggregator + collector correlation
- [ ] Auto-detect via link-layer `slow protocols` ethertype (0x8809)
- **Priority:** P2 · **Complexity:** Low · **Est. dev time:** 0.5–1 day

#### CDP (Cisco Discovery Protocol)

- [ ] TLV walks (Device ID, Platform, Version, Port ID, IP address,
  capabilities, VTP, VLAN, power)
- [ ] Multicast destination 01:00:0C:CC:CC:CC
- [ ] Cache neighbour inventory per capture
- **Priority:** P2 · **Complexity:** Low · **Est. dev time:** 0.5–1 day

#### MNDP (MikroTik Neighbor Discovery)

- [ ] TLV walk mirroring the CDP TLV list (MikroTik extends it with
  RouterOS version, board, uptime)
- [ ] Multicast destination 01:00:0E:8F:88:0F
- [ ] Auto-detect via CDP-style magic + vendor TLV
- **Priority:** P3 · **Complexity:** Low · **Est. dev time:** 0.5 day

### Service-discovery / LAN protocol decoders

> **Status:** 📋 Planned — none shipped. These protocols are pure
> LAN / multicast name-resolution and IoT-enumeration surfaces;
> analysts routinely see them in office / home captures and
> currently only get UDP blobs to look at.

Service-discovery decoders live alongside DNS in the Conv subtab and
auto-detect via port + name-pattern heuristics. They share a single
RR-walk helper with the DNS / DHCPv6 / LLMNR decoders.

#### mDNS / Bonjour (RFC 6762)

- [ ] Question / answer / authority / additional RR walks
- [ ] Service-instance-name (SRV + TXT) browsing (`_http._tcp`,
  `_ipp._tcp`, `_airplay._tcp`, …)
- [ ] Cache-flush bit handling
- [ ] UDP/5353 + 224.0.0.251 multicast
- **Priority:** P1 · **Complexity:** Medium · **Est. dev time:** 1–2 days

#### SSDP / UPnP (RFC 2616 / UPnP Device Architecture)

- [ ] M-SEARCH / NOTIFY walks (ST, USN, LOCATION, Cache-Control)
- [ ] UPnP device + service type parsing from LOCATION URL
- [ ] Discovery / description / control / event subscription state
- [ ] UDP/1900 + 239.255.255.250 multicast
- **Priority:** P1 · **Complexity:** Medium · **Est. dev time:** 1–2 days

#### AMQP (RabbitMQ / enterprise messaging)

- [ ] AMQP 0-9-1 protocol header + connection / channel / frame walks
- [ ] Method class/id table (Connection.Start, Channel.Open,
  Basic.Publish / Consume / Ack, Queue.Declare)
- [ ] Content-header + body frames (Basic.Deliver vs Basic.Get)
- [ ] Auto-detect on TCP/5672 (plain) + 5673 (TLS)
- **Priority:** P2 · **Complexity:** Medium · **Est. dev time:** 1–2 days

### Crypto / secure-channel metadata parsers

> **Status:** 📋 Planned (TLS) / 📋 Planned (SSH) / 📋 Planned (RTP,
> Syslog). The TLS / SSH handshake decoders surface metadata
> (algorithms, certificates, fingerprints) **without** attempting
> payload decryption — they slot in next to the existing **Crypt →
> Wifi** / **Crypt → OpenSSH** decoders as a metadata-only view.

These are non-invasive parsers: they read the handshake / control
messages and leave encrypted bytes alone, so they compose with the
existing TLS / OpenSSH keystore paths without conflicting.

#### TLS handshake parser

> Pairs with the existing TLS Fingerprinting roadmap entry (JA3 /
> JA4 generation is `🟡` partial). The parser is the missing
> foundation that the fingerprint hashes will read from.

- [ ] ClientHello / ServerHello walks (version, random, session-id,
  cipher suites, compression)
- [ ] Extension decode (SNI, ALPN, supported_groups, signature_algorithms,
  extended_master_secret, …)
- [ ] Certificate + CertificateRequest walks
- [ ] Certificate chain → JA3 / JA3-Server / JA4 hash feed
- **Priority:** P0 · **Complexity:** Medium · **Est. dev time:** 1–2 days

#### SSH handshake parser

> Pairs with the existing **Crypt → OpenSSH** keystroke-reconstruction
> decoder (which already needs the negotiated algorithms). The parser
> surfaces the negotiation so analysts see exactly which kex /
> cipher / MAC / host-key the session picked.

- [ ] Protocol version exchange (SSH-2.0 banners)
- [ ] KexInit walks (kex algorithms, server host key algorithms,
  encryption / MAC / compression choices)
- [ ] Host key fingerprint (SHA-256 of the public key blob)
- [ ] New keys / re-key events marked on the timeline
- **Priority:** P1 · **Complexity:** Low · **Est. dev time:** 0.5–1 day

#### RTP (Real-time Transport, RFC 3550)

- [ ] RTP header walks (version, padding, extension, CSRC count,
  marker, payload type, sequence, timestamp, SSRC)
- [ ] RTCP packet types (SR, RR, SDES, BYE, APP) + jitter / loss stats
- [ ] Payload-type → codec lookup (PT 0 = PCMU, 8 = PCMA, dynamic =
  opus/vp8/…)
- [ ] RTP-detection heuristic for UDP streams without explicit
  Session Description
- **Priority:** P2 · **Complexity:** Medium · **Est. dev time:** 1–2 days

#### Syslog (RFC 5424 + RFC 3164)

- [ ] BSD / RFC 3164 + RFC 5424 framing (PRI value, structured
  data, MSGID, timestamp)
- [ ] Transport over UDP/514, TCP/514 (TLS-wrapped variant at 6514),
  and RELP
- [ ] Severity / facility extraction
- [ ] Optional ship-to-Notes integration (one note per Syslog
  message for the active capture)
- **Priority:** P2 · **Complexity:** Low · **Est. dev time:** 0.5–1 day

> Already shipped as backend decoders (since 1.x): HTTP/2, SIP, FTP,
> SMTP, POP3, IMAP, Telnet, IRC, MTP, LDAP, MySQL, PostgreSQL, XMPP,
> SMB, MQTT, RTSP, TFTP, BGP, NNTP, RADIUS, SNMP, ICMP, DHCP, NTP,
> Kerberos 5, Soulseek, BitTorrent, SMPP, SIGTRAN, IGMP, LLDP, PPP,
> PPPoE, Brotli detection, HTTP decompression, DNS, DHCPv6, ISO 8583.
>
> The Conv **Decodes** subtab also has front-end stream decoders for
> HTTP, FTP, SMB/Samba, Telnet, SSH/OpenSSH, POP3, IMAP, SMTP, DNS,
> SNMP, DHCP, DHCPv6, EPMAP, LLMNR, NBNS, NBDGM, LDAP (upgraded for
> search/filters/entries + typed attribute tree), SIP, SMPP, Soulseek,
> BitTorrent, Kerberos (krb5), ISO 8583 (financial), and generic
> JSON / XML / YAML / Protobuf / MessagePack / BSON / ASN.1 BER /
> ASN.1 DER.

---

## AI features

### OpenRouter / Multi-Provider LLM

> **Status:** 🟡 Partial — the provider-agnostic `llm:generate` IPC
> channel ships with **Ollama** (local, default model
> `minimax-m3:cloud`) and **OpenRouter** (`openrouter.ai`, ships
> with five defaults: `openai/gpt-4o-mini`, `openai/gpt-4o`,
> `anthropic/claude-3.5-sonnet`, `google/gemini-pro-1.5`,
> `meta-llama/llama-3.1-405b-instruct`) as first-class providers.
> The Settings → LLM tab exposes a Provider dropdown that drives
> the rest of the UI (model catalog, generation IPC, diagnostics).
> Per-call `{ maxTokens, temperature, think }` overrides flow
> through both providers, and the `openrouter-api` preload bridge
> (`listModels` / `getModel` / `getStatus`) is wired alongside the
> Ollama bridge. An in-app inactive-LLM dialog surfaces when the
> active provider fails the reachability probe. A third provider
> (Anthropic-direct, Azure OpenAI, local vLLM, etc.) is a
> one-line `registerProviderHandler(name, fn)` call away.

- [✅] Ollama provider — ships.
- [✅] OpenRouter provider — ships with five defaults.
- [✅] Provider-agnostic IPC channel (`llm:generate`) — ships;
  `ollama:generate` kept as a backward-compat alias.
- [✅] Per-call model overrides (maxTokens / temperature / think) —
  ships.
- [✅] Inactive-LLM dialog — ships.
- [📋] Custom provider registration from a plugin
- [📋] Bring-your-own-API-key per model
- **Priority:** P0 · **Complexity:** Medium · **Est. remaining:**
  0.5–1 day (per additional provider)

### Ask The Capture

> **Status:** 🟡 Partial — the LLM is in the frontend (provider
> chosen via Settings → LLM → Provider; defaults to Ollama
> `minimax-m3:cloud`, OpenRouter also wired). Per-stream and
> per-distill prompts go through the provider-agnostic
> `llm:generate` channel. The right-click context menu's **Ask
> PacketSnitch...** submenu ships for Ask a question / Explain
> this data / Summarize this packet, and the **Session Threat
> Score** card adds a Get LLM Assessment action. Free-form
> natural-language "ask the capture" UI is still TODO.

- [🟡] Packet-aware prompting — Ask PacketSnitch... submenu ships.
- [🟡] Host summaries — LLM distillation on the Summary tab; Session
  Threat Score → Get LLM Assessment ships.
- [📋] Natural language querying
- [📋] Threat hunting assistance
- [✅] Investigation recommendations — Session Threat Score → "Get LLM
  Assessment" ships the "up to 5 concrete next actions" block via
  `buildSessionThreatLlmPrompt` in
  [src/ui/panels/threat-intel-scorer.js](src/ui/panels/threat-intel-scorer.js).
- [✅] Automatic anomaly explanation — the Session Threat Score
  breakdown (per-component weighted scoring) ships, and the Stats →
  Anomalies sub-tab surfaces four structured detectors
  (port-scan, brute-force, baseline outliers, embedded high-entropy
  cleartext) that share the same engine. The remaining TODO is a
  unified click-to-filter overlay that links every anomaly back to
  its affected packets in the List and Conv tabs — tracked under
  AI Investigation Assistant.

### AI Investigation Assistant

> **Status:** 🟡 Partial — Summary distillation ships, the Session
> Threat Score → "Get LLM Assessment" action produces a short analyst
> narrative plus up to 5 concrete next actions, and a ranked
> **Highlight Unusual Behavior** view is in progress on the Stats →
> Anomalies sub-tab. The Stats → Anomalies detector engine is shared
> with the Session Threat Score so the two views never disagree, and
> every per-target lookup feeds the next score recompute.

- [✅] Generate findings — distilled summary ships (see
  `buildSummaryDistillPrompt` / `distillSummaryMarkdownWithLLM` in
  [src/ui/main-frontend.js](src/ui/main-frontend.js)).
- [✅] Score-driven recommendations — Session Threat Score → "Get LLM
  Assessment" ships. The prompt built by
  `buildSessionThreatLlmPrompt` in
  [src/ui/panels/threat-intel-scorer.js](src/ui/panels/threat-intel-scorer.js)
  asks the LLM for a ~400-char analyst narrative plus up to 5
  concrete next actions based on the deterministic score breakdown.
- [✅] AI next steps — same Session Threat Score → "Get LLM
  Assessment" path. `buildSessionThreatLlmPrompt` caps the
  recommendation list at 5 actions and the renderer renders them as
  a structured next-actions block on the card.
- [🚧] Highlight unusual behavior (anomaly-driven, not just LLM-driven) —
  the **Stats → Anomalies** sub-tab now ships four structured
  detectors that share an engine with the Session Threat Score
  (`detectStatsAnomaliesPortscan`, `detectStatsAnomaliesBruteForce`
  for FTP/SSH/Telnet/SMTP/POP3/IMAP/RDP/VNC/LDAP, the per-minute
  packet-count / length baseline outlier detector
  `detectStatsAnomaliesBaselineOutliers`, and the high-entropy
  cleartext detector `detectStatsAnomaliesEmbeddedContent`), and the
  findings surface as click-to-filter cards. A unified
  anomaly-highlight overlay that links every anomaly back to the
  affected packets in the List and Conv tabs is still TODO.

---

## Long-term (1.0+)

### Alert Rules + Notifications

> **Status:** 📋 Planned.

- [ ] Saved detections
- [ ] Background monitoring
- [ ] Event notifications
- **Priority:** P1 · **Complexity:** Medium · **Est. dev time:** 1–2 days

### Redaction Profiles

> **Status:** 📋 Planned.

- [ ] Mask secrets in UI
- [ ] Mask secrets in exports
- [ ] Custom redaction policies
- **Priority:** P1 · **Complexity:** Medium · **Est. dev time:** 1 day

### Local Plugin API

> **Status:** 🟡 Partial — plugin capabilities JSON, capability
> enforcement, sample `hello-snitch.zip` plugin, and plugin UI handler
> ship. A full sandboxed extension API is still TODO.

- [📋] Custom protocol decoders (full API)
- [🟡] Extension framework — capabilities system ships.
- [📋] Sandboxed execution
- **Priority:** P2 · **Complexity:** Very High · **Est. remaining:**
  1–2 weeks

### Mini Decoder Scripting

> **Status:** 📋 Planned.

- [ ] User-defined parsers
- [ ] Lightweight decoder runtime
- [ ] Custom protocol support
- **Priority:** P3 · **Complexity:** Very High · **Est. dev time:**
  1–2 weeks

### Live Capture Mode

> **Status:** 📋 Planned.

- [ ] Interface selection
- [ ] Rolling capture ingestion
- [ ] Continuous analysis
- [ ] Long-running session support
- **Priority:** P2 · **Complexity:** Very High · **Est. dev time:**
  2–3 weeks

---

## Future / advanced ideas

### Attack Path Reconstruction

> **Status:** 📋 Planned.

- [ ] Lateral movement tracking
- [ ] Initial access identification
- [ ] Compromise timeline generation

### Traffic Baseline Engine

> **Status:** 📋 Planned.

- [ ] Learn normal behavior
- [ ] Detect anomalies
- [ ] Compare captures to baseline

### MITRE ATT&CK Mapping

> **Status:** 📋 Planned.

- [ ] Technique identification
- [ ] ATT&CK coverage reporting
- [ ] Detection mapping

### Threat Score System

> **Status:** 🟡 Partial — the **Session Threat Score** ships in the
> Threat Intel sub-tab as a 0-100 score with `Clean` / `Low` / `Medium` /
> `High` / `Critical` banded pill, a color-graded weight breakdown of
> every contributing indicator (IPSum, Tor, VirusTotal malicious /
> suspicious verdicts, high-entropy cleartext, portscan / brute-force /
> baseline outliers from the Stats → Anomalies sub-tab, public-IP /
> domain / URL / hash counts, and the current Conv input entropy), and
> a **Capture Footprint** summary. **Recompute** / **Get LLM
> Assessment** / **Send to Notes** actions live on the card. The
> VirusTotal results panel (v2.7.1657) now keeps every lookup
> across the session as stacked result cards
> (`virustotalResults[]` plumbed through session save/load) and
> exposes the full VirusTotal attribute surface (size,
> type_description, magic, tags, type_tags, last_analysis_results,
> sigma_analysis_results, sigma_analysis_stats, plus the raw
> payload), and the `analysis` lookup type routes
> `GET /analyses/{id}` so analysts can walk the full analysis
> chain. IPSum / Tor cards are now hidden by default
> (`#subnet-ti-ipsum-card` / `#subnet-ti-tor-card` with
> `setOptionalThreatIntelCardVisibility`) so the panel only
> shows reputation sources the analyst actually consulted.
> Per-host and per-conversation risk scores are still TODO.

### Automatic Report Generator

> **Status:** 🟡 Partial — LLM distillation + Summary export ships.
> Per-template (incident-response / triage) HTML/PDF report generation
> is still TODO. The base HTML and PDF export paths are wired (see
> **Report Templates** above).

- [🟡] Executive summary — Summary tab ships.
- [🟡] Technical findings — distilled summary ships.
- [🟡] IOC appendix — partial via Stats.
- [🟡] Artifact appendix — partial via carvable files.
- [✅] Export to HTML / PDF — Markdown / Text / HTML ship via the
  context-menu **Reports...** submenu, and PDF ships via the Summary
  header **Save as PDF** button + the context-menu **Save Report
  (PDF)** entry (Electron `webContents.printToPDF`, no third-party
  PDF dependency).

---

## Suggested execution order

The original `ideas.txt` suggested this sequence. Items marked `[DONE]`
have been absorbed into recent releases; items marked `[NEXT]` are
where to pick up next; items marked `[NEW]` are additions based on
work that's landed since.

1. [🟡] Saved Filter Library *(mostly done — finish categories/export)*
2. [📋] Rule-Based Highlights
3. [🟡] IOC Extraction Panel *(basic data ships — needs dedicated panel)*
4. [🟡] One-Click IOC Export *(JSON ships — needs CSV + selective)*
5. [🟡] Report Templates *(Summary ships — needs templates + PDF)*
6. [📋] Diff Two Packets
7. [🟡] DNS Threat Lens *(aggregation ships — needs heuristics)*
8. [🟡] Protocol Anomaly Heuristics *(Anomalies sub-tab ships portscan, brute-force, baseline outlier, and high-entropy cleartext detection — needs scored correlation with Threat Intel)*
9. [📋] Batch Analysis
10. [📋] Expert Events Feed
11. [🟡] Stream Reassembly *(foundation ships — finish missing-packet UX)*
12. [🟡] HTTP Object Extraction *(body + carve ships — needs objects panel)*
13. [📋] Timeline View
14. [📋] Conversation Graph
15. [🟡] Live Capture Mode *(large effort — start scoping)*
16. [🟡] Local Plugin API *(capabilities ship — needs sandbox)*

`[NEW]` follow-ups worth queuing after the above:

- [📋] Alert Rules + Notifications
- [📋] Redaction Profiles
- [📋] Traffic Baseline Engine
- [📋] MITRE ATT&CK Mapping
- [📋] Threat Score System
- [📋] YARA Integration
- [📋] QUIC / WebSocket / gRPC / WireGuard decoders
- [📋] TLS handshake parser (unlocks JA3/JA4 + anomaly detection)
- [📋] SSH handshake parser (negotiation metadata for OpenSSH
  keystroke decoder)
- [📋] Modbus/TCP, DNP3, S7comm (ICS / SCADA suite)
- [📋] mDNS / Bonjour, SSDP / UPnP, AMQP (LAN / service discovery)
- [📋] OSPF, HSRP / VRRP, BFD, LACP, CDP, MNDP (routing /
  network-control suite)
- [📋] RTP, Syslog (media + log transport)
- [📋] Secret Detection pass (AWS, Azure, GCP, JWT, OAuth, private keys)
- [📋] PCAP Diff Mode

---

## Backend optimizations

> **Status:** 🟡 Partial — a number of these have already been added in
> 1.x / 2.x; the per-phase instrumentation request from the original
> `ideas.txt` is still open.

Add phase timers inside packet processing (not just threading) for:

- [🟡] `getDatatypes` — inference work is timed at the *packet* level via
  the backend's overall timing; per-phase sub-timers still TODO.
- [🟡] `getTraits` — same.
- [📋] `reverseDnsLookup` — instrument per-call latency.
- [📋] `getServBanner` — instrument per-call latency.
- [🟡] GeoIP lookup — cached (see 1.1.195 "O(1) lookups, GeoIP cache"),

> per-call instrumentation still TODO.

Already shipped (so we don't redo them):

- ✅ Backend multi-job processing with job IDs (2.0)
- ✅ Backend chunked push to renderer (1.7.848)
- ✅ Lazy-load packets from disk (1.7.848)
- ✅ Dynamic CPU core count (1.9.1442)
- ✅ GeoIP cache + thread safety (1.1.195)
- ✅ Backend scheduler optimizations (1.9.1442)
- ✅ Streamlined frontend with stream payload caches (2.4.2115)
- ✅ `.psb` (gzipped BSON) session format default (2.0)
- ✅ Backend HTTP API (`/status`, `/version`, JSON endpoints) (1.9.1442)
- ✅ Statically linked backend via `staticx` (Unreleased) — single
  self-contained `snitch` + `snitch-extract` binary pair that no
  longer needs a co-located Python or system libraries; content-
  hashed build cache in `scripts/build-cache.js`; `with-libs-path.js`
  env wrapper keeps the in-test backend booting on Kali, fresh
  containers, and minimal CI images.

---

## Recently shipped (release history mirror)

> Short mirror of `RELEASE_NOTES.md` so this single file is enough to
> skim. The full per-version notes still live in `RELEASE_NOTES.md`.

### v2.7.1657 — 2026-08-31

- **Features**
  - **OpenRouter LLM provider (Settings → LLM)** — the
    `llm:generate` IPC channel now dispatches to both Ollama and
    OpenRouter. The Settings → LLM tab exposes a **Provider**
    dropdown and ships five OpenRouter defaults
    (`openai/gpt-4o-mini`, `openai/gpt-4o`,
    `anthropic/claude-3.5-sonnet`, `google/gemini-pro-1.5`,
    `meta-llama/llama-3.1-405b-instruct`) in
    `config/models.json` under a new `openrouter.defaultModels`
    block. The `openrouter-api` preload bridge
    (`listModels` / `getModel` / `getStatus`) is wired alongside
    the Ollama bridge, and an in-app inactive-LLM dialog surfaces
    when the active provider fails the reachability probe.
    `ollama:generate` is kept as a backward-compat alias.
  - **Theme engine overhaul (Settings → Themes + storefront)** —
    shared `src/ui/common-frontend.js` helpers, license-tier
    badges, fixed-aspect-ratio per-theme previews, developer-tier
    first-launch path, grouped-by-license storefront, sandbox-
    banner `paddleEnv`/`sandbox` fallback, and the
    `tests/test_catalog_listable_gate.py` listable-only gate.
  - **ISO 8583 financial protocol decoder (Conv → Decodes)** —
    MTI / primary+secondary bitmap / data elements per ISO
    8583:1987/1993; ASCII-hex and binary bitmap encodings; ASCII
    and binary LLVAR/LLLVAR; 2- or 4-byte TPDU stripping;
    false-positive rejection via MTI table + first-field parse;
    auto-detect routes ports 8583, 5000, 5001, 14401. Sample
    pcaps + 14 tests ship.
  - **Data transformations in Conv (`Invert / Endian / Bit-order /
    Transpose`)** — composable transformations in
    `src/ui/data-transformations.js`, wired through a dedicated
    **Data Transformations** block in the Conv output panel
    (`#data-tools-transform-row`). **Reset Output** is
    non-destructive; the Conv input is never modified. Covered
    by `tests/data_transformations.test.js`.
  - **Threat Intel → VirusTotal results panel (history + multi-
    result cards)** — `virustotalResults[]` plumbed through
    session save/load; IPSum / Tor cards hidden by default;
    full attribute surface (size, type_description, magic, tags,
    type_tags, last_analysis_results, sigma_analysis_results,
    sigma_analysis_stats); new `analysis` lookup type routes
    `GET /analyses/{id}`; `confirmed_timeout` / `failure` /
    `type_unsupported` stats fields; truncated
    `attributes.names` cap to keep the card readable.
  - **Provider-agnostic `llm:generate` IPC channel** — canonical
    channel reads `settings.llm.provider` and dispatches to the
    registered handler; `ollama:generate` kept as alias.
  - **Inactive-LLM dialog** — surfaces when the active provider
    fails the reachability probe, with a link to Settings → LLM.
- **Fixes**
  - **Threat Intel → shorter labels fit smaller windows**.
  - **Theme-engine UX plumbing** — fixed-aspect-ratio previews,
    consistent license-tier badge, end-to-end developer-license
    first-launch path.
  - **Host Data info-pane grouping** — `current-stream-packet`,
    `current-filtered-packet`, and `timestamp` readouts moved
    into a dedicated **General Information** block at the top of
    the active-recon scroll so the analyst never loses the
    timestamp when the toolbar overflows.
  - **ETA countdown, backend respawn, and frontend ingestion**.
  - **UI lag reduced on theme engine + periodic backend
    crashes**.
  - **Metrics endpoint + clone counter**.
- **Tests**
  - `tests/data_transformations.test.js`,
    `tests/test_catalog_listable_gate.py`,
    `tests/test_catalog_admin_portal.py`,
    `tests/test_catalog_schema_migration.py`,
    `tests/test_catalog_smtp_use_tls.py`,
    `tests/threat_intel_virustotal_ui.test.js` (extended),
    `tests/test_backend_iso8583_decoder.py`,
    `tests/iso8583_conv_decoder.test.js`,
    `tests/themes_subtab.test.js` (extended).

### v2.6.1629 — 2026-08-20

- **Features**
  - **OpenSSH keystroke-timing decoder (Crypt → OpenSSH sub-tab)** —
    full keystroke-reconstruction engine under
    `src/ui/decoders/ssh-keystrokes/` (`index.js` + `markov.js`,
    `calibration.js`, `auto-calibrate.js`, `boundary-warmstart.js`,
    `chunk-label.js`, `chunker-slider.js`, `clock-skew.js`,
    `backspace-detect.js`, `compression-heuristic.js`,
    `padding-detection.js`, `session-confidence.js`, `ssdeep.js`,
    `truth-align.js`, `score-envelopes.js`, `markov-loader.js`,
    `worker.js`, `export/`). Scores inter-packet delays against a
    per-QWERTY-digraph Gaussian model (`src/data/qwerty-model.json`),
    runs an N-best Viterbi over printable ASCII, and renders a Plotly
    delay histogram. The bundled `shell_corpus_sorted.txt` is
    precomputed at startup in a `worker_threads` worker and cached in
    `userData`; the renderer pulls it via the new `markovapi` preload
    bridge. New `opensshapi` (`loadQwertyModel` / `decode`) and
    `llmapi.generate` (per-call `{ maxTokens, temperature, think }`
    overrides) preload bridges ship. The OpenSSH sub-tab has a full
    settings surface wired through the new `keystroke` settings block
    (`markovMinCommandLength`, `concisenessBonusMultiplier`) and the
    extended `llm` block (`language`, `llmWeightPercent`, `preset`,
    `autotuneEnabled`).
  - **hashes.com reverse-lookup integration (Conv → Hashes)** — a
    dedicated **Hash Reverse** section (`#data-tools-hash-reverse-*`)
    lets the analyst POST an MD5/SHA-1/SHA-256/… hash to hashes.com
    `/en/api/search` and render plaintext matches, or GET the
    `/en/api/identifier` endpoint to list candidate algorithms. Three
    new IPC handlers (`hashes-com:search`, `hashes-com:identify`,
    `hashes-com:diagnostics`) coalesce concurrent callers and cache a
    recent successful probe for 30s; the Settings tab renders four
    pills (reachability, key validity, last cost, last lookup result)
    with a `cachedHashesComLastLookup` tracker so the zero-credit
    diagnostic probe is never conflated with a real reverse. The API
    key lives in `settings.apiKeys.hashesComApiKey`.
  - **Crypt → Hashes sub-tab** — the Crypt workspace now opens on a
    dedicated **Hashes** sub-tab (`#crypt-hashes-panel`,
    `CRYPT_HASHES_SUBTAB`) that mirrors the Conv → Hashes panel via the
    new `renderCryptHashesFromConvInput` helper, so analysts can inspect
    digests without flipping workspaces. Hashes is the default Crypt
    sub-tab on a fresh install.
  - **Lazy packet hydration + backend reuse at startup** — the
    renderer no longer materialises the full capture into memory up
    front (`capture-store.js` builds an in-memory store; the
    `.packets.ndjson` disk write is gone). A new
    `backendEarlyYieldPacketThreshold` (~5000 packets) tells the
    renderer to load the first backend snapshot, defer, then do a
    clean full swap when the backend completes. On GUI startup the
    bridge now **reuses** an already-running backend on the
    configured HTTP port instead of spawning a conflicting one
    (`reusedExistingBackendAtStartup` in `src/back-comm.js`),
    eliminating the port-conflict respawn loop that churned on large
    captures. `backendPacketChunkSize` default dropped 2000 → 500 for
    smoother progressive pushes.
  - **Per-call LLM overrides + thinking-mode bypass** —
    `ollama:generate` now accepts a second `options` argument
    (`{ maxTokens, temperature, think }`) that overrides the user's
    `maxSummaryTokens` / temperature per call. The renderer can pass
    `think: false` to disable the model's internal-reasoning channel —
    Ollama cloud models like `minimax-m3:cloud` use thinking mode by
    default and can consume the entire response budget in reasoning
    with nothing emitted as `response`. The new `llmapi.generate`
    preload bridge exposes this to the renderer.
  - **Website moved to its own submodule** — the docs site is now a
    git submodule at `docs/PacketSnitch-Website` (added to
    `.gitignore`), the app homepage in `forge.config.js` and
    `package.json` points at `https://packetsnitch.com/`, and the
    bundled `shell_corpus.txt` extraResource in `forge.config.js`
    now references the sorted corpus (`src/data/shell_corpus_sorted.txt`).
- **Fixes**
  - **Theme preview loading** — the theme catalog's 400×250 preview
    fetch now retries once on a transient undici failure and surfaces
    a "preview unavailable" state instead of leaving a broken image
    card; the sandbox-banner logic correctly reads `paddleEnv` (with
    the legacy `sandbox` flag fallback) so test purchases can never be
    mistaken for real ones.
  - **Heatmap convergence animation + backend reuse** — the heatmap's
    convergence leader lines now animate, and the backend is reused
    across animation passes instead of being continuously respawned.
    The vendored Plotly (`src/assets/vendor/plotly-2.35.2.min.js`) is
    loaded only on the OpenSSH sub-tab so it doesn't slow the main
    render path.
  - **Backend reclaim no longer drops data on re-runs** — the startup
    reclaim path now stops any current jobs and reuses the running
    service rather than spawning a conflicting backend; previously
    the port was held by a stale process and the new backend silently
    failed to bind.
  - **Session-bound state survives wifi-keys reruns** — a
    `pendingSessionRerunSnapshot` (current session name, filter query,
    selected host) is taken at the start of a wifi-keys rerun and
    re-applied when the rerun completes, so the user's session
    identity and view state survive the silent background re-run. A
    `sessionExplicitlyClosed` flag distinguishes a user-initiated "new
    capture" from a background rerun so the Save-Session flow prompts
    for a fresh name only when the user actually closed the session.
- **Tests**
  - `tests/openssh_keystrokes.test.js`
  - `tests/{auto_calibrate,boundary_warmstart,chunk_label,chunker_max_packet_wiring,chunker_slider,clock_skew,score_envelopes,ssh_backspace_detection,ssh_keystroke_markov,ssh_keystrokes_compression_heuristic,ssh_padding_detection,ssh_session_confidence,ssh_timing,truth_align,weight_envelope_migration}.test.js`
  - `tests/hash_reverse_helpers.test.js`,
    `tests/hashes_com_diagnostics.test.js`,
    `tests/hashes_com_identifier.test.js`
  - `tests/listentries_fast_path.test.js`,
    `tests/test_network_metadata.test.js`
  - `tests/wifi_keys_rerun_session_following.test.js`
  - `tests/test_regex_issue.test.js`,
    `tests/packet_timestamp_parse.test.js`,
    `tests/decoder_layer1_envelope.test.js`,
    `tests/ssdeep.test.js`
- **Build & packaging**
  - Website moved to its own submodule at
    `docs/PacketSnitch-Website`; app homepage now
    `https://packetsnitch.com/`; bundled corpus references
    `src/data/shell_corpus_sorted.txt`.

### Unreleased

- **Features**
  - Help button opens docs hub in an in-app browser window locked to a
    whitelisted set of hosts (`packetsnitch.com`, GitHub, BMC, VT).
  - New Kerberos 5 (`krb5`) Conv decoder (AS-REQ/REP, TGS-REQ/REP,
    AP-REQ/REP, KRB-ERROR, KRB-PRIV, KRB-CRED).
  - New Conv Decodes dropdown entries + stream decoders for **DNS,
    SNMP, DHCP, DHCPv6** (auto-detect + protocol/port hints;
    RR/option/TLV walks with typed rdata preview).
  - Conv Decodes entries for **EPMAP, LLMNR, NBNS, NBDGM (NetBIOS
    Datagram Service)**, plus upgraded LDAP (search/filters/entries,
    typed attribute tree).
  - **Crypt → Wifi subtab** with 802.11 / RadioTap decoding, WPA2
    4-way handshake PTK derivation (PBKDF2-HMAC-SHA1 PMK → PRF-384
    PTK per IEEE 802.11i §8.5.1), AES-CCMP / TKIP / WEP decryption,
    SSID/BSSID filter, "decryptable with my keys" filter, keystore-
    backed `wifi-wep` / `wifi-wpa-psk` / `wifi-pmk` keys, and
    auto-rerun after `setBackendWifiKeys`.
  - **Stats → Anomalies sub-tab**: portscan, brute-force login bursts
    (FTP/SSH/Telnet/SMTP/POP3/IMAP/RDP/VNC/LDAP), baseline packet-
    length / per-minute outliers, high-entropy cleartext payloads —
    click-to-filter cards. Shares the engine with the Threat Intel
    sub-tab so the two views never disagree.
  - **Session Threat Score** in the Threat Intel sub-tab: 0-100 score
    with `Clean` / `Low` / `Medium` / `High` / `Critical` banded pill,
    color-graded weight breakdown of every contributing indicator,
    Capture Footprint (public IPs / unique domains / URLs / hashes /
    reputation lookups / protocol anomalies), **Recompute** /
    **Get LLM Assessment** / **Send to Notes** actions. Every per-
    target lookup feeds the next recompute.
  - **Save Report...** submenu in the right-click context menu with
    Markdown / Text / HTML / **PDF** export backed by an LLM
    distillation pass (dedupe + chronological sort + importance
    re-rank) with a clean fallback to the un-distilled report. PDF
    reuses the same self-contained HTML the HTML exporter builds
    and hands it to Electron's `webContents.printToPDF` (no
    third-party PDF dependency); the Summary header **Save as PDF**
    button calls the same path.
  - Wifi keys round-trip through sessions — saved sessions carry
    802.11 keys, and on restore the bridge re-sends them to the
    backend so re-opening a wifi capture still decrypts without
    manual re-entry.
  - Notes tab now auto-feeds the Summary tab under "Inferred Data
    (from Notes)"; per-note "Mark as verified" toggle moves the note
    to "Verified Notes (from Notes)".
  - Dedicated SMB follow-stream path in the Conv Decodes subtab
    (per-message tree, file content, offsets), backed by
    `src/ui/decoders/conv/smb-helpers.js`.
- **Fixes**
  - Single-block Conv decode regression.
  - Inline decoder wiring now matches the dropdown entries.
  - **Wifi rerun no longer drops decryption on the second run** —
    legacy spawn path now stages the per-job `wifi-keys.json` in
    `testcaseOutputDir` (a sibling of `jobOutputDir`) with a unique
    `wifi-keys-<jobId>.json` filename, and the bridge cleans it up
    after the backend closes.
  - **Restore defaults** button is now confirmable via a new in-app
    overlay (`#settings-reset-confirm-dialog`) with `Restore` /
    `Cancel` buttons and full keyboard support; falls back to
    `window.confirm` if the DOM nodes are missing.
  - **All-Hosts sentinel survives across snapshot refreshes** — the
    `0.0.0.0` "All Hosts" virtual option stays bound to the full
    packet set after a backend progressive snapshot or rerun.
- **Tests**
  - `tests/kerberos_conv_decoder.test.js`
  - `tests/{dns,snmp,dhcp,dhcpv6}_conv_decoder.test.js`
  - `tests/{epmap,llmnr,nbns,nbdgm,ldap}_conv_decoder.test.js`
  - `tests/notes_summary_integration.test.js`
  - `tests/conv_decodes_stream_stack.test.js`
  - `tests/smb_conv_decoder.test.js`
  - `tests/stats_anomalies.test.js`
  - `tests/threat_intel_scorer.test.js`
  - `tests/threat_intel_stats_anomalies.test.js`
  - `tests/wifi_keys_legacy_spawn_placement.test.js`
  - `tests/wifi_keys_rerun_path_mode.test.js`
  - `tests/legacy_all_host_sentinel.test.js`
  - `summary_stats_weaving.test.js` extensions
  - `tests/windows_elevation_check.test.js` extensions
  - `tests/test_backend_{compile,json,server}.py` extensions
- **Build & packaging**
  - **Statically linked backend** via `staticx` — the snitch Python
    backend is now a single self-contained binary that no longer
    needs a co-located Python or system libraries to launch. The
    `scripts/with-libs-path.js` env wrapper keeps the in-test backend
    booting on Kali, fresh containers, and minimal CI images.
  - **Backend build cache** (`scripts/build-cache.js`) — content-hashed
    wrapper around PyInstaller + staticx + snitch-extract so unchanged
    rebuilds skip the slow steps; produces a single canonical
    `snitch` + `snitch-extract` pair for packaging.
  - **Windows installer hardening** — Start-menu shortcut (correctly
    under `Programs\PacketSnitch`) and desktop icon now flow from the
    same PowerShell helper so per-machine vs. per-user installs can
    no longer disagree, and a re-install no longer produces duplicate
    shortcuts. New `tests/windows_elevation_check.test.js` cases lock
    this in.
  - **Self-hostable backend env** — `scripts/with-libs-path.js` is the
    single env wrapper that augments `LD_LIBRARY_PATH` / `PATH` (and
    Windows equivalents) before launching the snitch binary, and
    `src/back-comm.js` calls into it for the new
    `testcaseOutputDir`-based keys-file staging.
  - **Extraction panel handles archives** — extractor now natively
    unpacks `cab`, `7zip`, `zip`, `tar`, `gz`, `bzip2`, and `zstd`
    archives and compression, with magic-first detection falling
    back to extension matching and consistent per-entry carve
    context menu (load into Extraction / Decoders, send to
    VirusTotal) across nested entries.
  - **"Load full packet (with headers) into Conv"** via the
    right-click context menu — the selected packet (link-layer
    headers and all) lands in the Conv tab as the analysis input
    so analysts can walk the L2/L3/L4 structure in the data-tools
    panel without a separate Wireshark hop.
  - **Metrics install UUID is now minted exactly once** — the
    install-UUID minting path that powers `metricsInstallId` no
    longer regenerates the UUID on every settings-save or consent
    decision, so install identity stays stable across upgrades,
    settings changes, and a "restore defaults" pass.
  - **Default Ollama model updated to `minimax-m3:cloud`** — a
    clean install no longer requests a model the user doesn't
    have.

### v2.4.2169 — 2026-07-27

- **Features**
  - Halved installer sizes.
  - Anonymous, opt-in usage metrics (`src/metrics.js` + `metricsapi`).
  - First-run consent overlay; Privacy subtab to manage it.
  - Self-hostable metrics endpoint (`src/metrics/server.py`) with
    NDJSON-on-disk sink and `/healthz`.
  - "Analyze IP..." submenu in context menu; Subnet Calc and Threat
    Intel drill-in.
  - Carved-file context menu entries (load into Extraction/Decoders
    with auto-extension hinting, send to VirusTotal).
  - `runThreatIntelIpLookup` / `setAnalysisInput` exposed on Subnet
    Calculator.
  - Backend port reclaim on startup.
- **Fixes**
  - Heatmap map projection calibration consolidated into
    `MAP_PROJECTION_CALIBRATION` constant in `src/settings.js`.
  - VirusTotal startup diagnostic coalesced with a 30s dedupe window
    - `invalidateVirusTotalDiagnosticsCache()` hook.
  - Privacy block in `settings-update` is now deep-merged.
  - Metrics flush loop now actually fires (paired renderer listener +
    `beforeunload` final-flush).
  - Install-screen consent overlay only auto-shows on clean installs.
  - Resolved a stale merge marker in the Conv Decodes protocol
    dropdown.
  - Context menu dividers no longer orphan the new entries.
- **Removed**
  - Duplicated heatmap calibration constants.
- **Improvements**
  - New tests: `consent_overlay`, `metrics_privacy`,
    `metrics_tab_tracking`, `test_metrics_server`,
    `heatmap_projection_calibration`.
  - `packetsnitch:settings-updated` event listener re-syncs in-memory
    settings.
  - Metrics tracking respects a strict `SAFE_PROP_KEYS` allowlist.
  - Default Ollama model updated to `qwen2.5-coder:7b`.
  - Metrics endpoint URL is user-configurable.

### v2.4.2115 — 2026-07-26

- **Features**
  - Threat Intel sub-tab under Conv (VirusTotal + hash cross-ref).
  - Subnet calculator panel in Conv (GeoIP + IP reputation).
  - Nmap scan support and IP/Subnet analyzer rearrangements.
  - Shodan support in IP information.
  - High-resolution raster worldmap for Heatmap.
  - More sample pcaps.
  - Better plugin capabilities enforcement; `hello-snitch.zip` sample
    plugin.
  - Backend ico, distiller for the summary report generator, "bugfixer"
    on the website, more LLM context.
- **Fixes**
  - File importing errors, Stats Total Traffic indicator, path
    traversal in `snitch.py`, docs layout shifts, Conv hex input
    scrolling, filter bleed + autocomplete.
- **Removed**
  - Lots of old dead code.
- **Improvements**
  - Major code cleanup, stream payload caches, frontend optimizations,
    HTTP body and file carving fix, Subnet Calc UI cleanups, Heatmap
    zoom, backend scheduler optimizations, better stream hydration,
    parted-out backend decoders, sidebar renderer move, more backend
    test coverage, docs font shipping, markdown in Summary, better
    filter bar logic, search/replace in Conv, file carving section in
    Stats, better Conv→Notes, Conv "load more" button, summary auto-gen
    disable setting.

### v2.3.1694 — 2026-07-23

- **Removed:** `patchall` from `make` on Windows.
- **Fixes:** quieter backend HTTP error on stop, PyInstaller `--icon`
  replaced with `.spec` icon, backend ICO of the snitch.

### v2.2.1638 — 2026-07-18

- **Features**
  - IPv6 support improvements (brackets on port, delimiters).
  - Threat Intel sub-tab under Conv (VirusTotal).
  - Backend HTTP server (refined).
  - More sample pcaps, docs TOC, better stream hydration,
    filter autocomplete.
- **Fixes**
  - List panel blank bug, big-endian nanosecond pcap, `ports.json`
    removed from samples.
- **Removed**
  - `ports.json` from samples, frontend docs screenshots.
- **Improvements**
  - Backend pushes packets in chunks; lazyload from drive; more
    decoders; keystore autoadd; backend existence check; filter
    query status updates; explicit filter clear log; stream stats
    in Host Data + Stats; Conv data saved with session; docs
    context-menu reference; `tcp.proto` vs `udp.proto` vs `app.proto`
    split; city listing via `loc.src.city || loc.dst.city`; globbing
    regex in filter; Brotli detection; Help button + new window.

### v2.1.1606 — 2026-07-16

- **Features**
  - Soulseek, BitTorrent, SMPP support; better PPP/PPPoE/LLDP.
  - Improved plugin capabilities; better crypt for ambiguous data;
    better XML/JSON/YAML; generic decoders renamed; updated build
    config; backend fails on unknown filetype magic; GitHub workflow
    fixes.
- **Fixes:** list panel blank bug, big-endian nanosecond pcaps.
- **Removed:** non-clickable password badge from UI.
- **Improvements:** plugin enforcement tests, widened settings
  panels, plugin UI handler, plugin support groundwork, decoders
  parted out, sidebars widened, backend chunk size arbitrary, stream
  payload caches, fixed creds uniqing, fixed HTTP body + carving,
  cleaned UI.

### v2.0.1573 — 2026-07-15 (major)

- **Breaking:** new `.psb` (gzipped BSON) session format; old
  sessions are not compatible.
- **Features**
  - `.psb` debug default, multi-job backend+frontend with job IDs,
    common/ library fix, Conv tab retool, List tab columns hidden by
    default, LDAP/Samba decoder improvements, markdown for LLM and
    send-to-Notes shapes, startup splash, `/status` endpoint, major
    serialization bug fix, streamlined ingestion, zero-payload
    support, frontend logging tunables, List column rearranging,
    settings tab improvements, backend version line, themes bundled,
    updated Python spec.
- **Fixes**
  - SIP, Conv pagination, Conv formatting, filter bleed, word
    wrap, settings overlap, virtualized list scrolling, Host Data
    hidden bug, zero payload bug, dropdown theme colors, common/
    finding bug.
- **Removed:** unnecessary testcases dir creation in HTTP mode.
- **Improvements**
  - Version bump, spec file update, fade-out timing, longer startup
    time, one-shot override for decodes subtab, session picker
    updates, better LDAP, updated Samba, removed testcases dir
    creation in HTTP, User-Agent updated, Help tab new domain,
    settings tab updates, release check + download button, SnitchBitch
    theme update, favicon, more backend test coverage, plugin
    capabilities enforcement.

### v2.0.1566 — 2026-07-14

- `.psb` debug default, backend common/ fix, multi-job processing,
  new BSON session format, major serialization fix, SIP improvements,
  LDAP/Samba improvements.

### v1.9.1518 — 2026-07-11

- **Removed:** `models.txt` references, test auto-run, map crosshair.
- **Fixes:** MAC address IP bleed, backend kickoff, map updates,

> crosshair removal, smoother map animations.

- **Improvements:** map animation, frontend streamlining, stream
  payload caches, frontend optimizations, creds uniqing, backend
  chunk size arbitrary, sidebars widened, test auto-run removed,
  SnitchBitch theme update, favicon, sponsorship updates, release
  check, download button, runtime main-process data, download link
  generation, Windows/RedHat/Debian detection, better Nmap support,
  Shodan support, threat intelligence under IP info, more
  documentation.

### v1.9.1442 — 2026-07-05

- **Features**
  - Worldmap, backend HTTP server, PGP workspace, settings tab,
    frontend LLM, heatmap with Wikipedia images, layer fix, statusbar
    forward, better default zoom/offset, heatmap zoom, worldmap view,
    threat intel under IP info, credentials count + readout in Stats,
    rudimentary SIGTRAN/SS7, anime theme, new pastels theme, better
    theme engine, PGP tab (decrypt + verify), backend JSON HTTP API,
    better filter history (saved + labeled), better filter bar.
- **Fixes**
  - Backend JSON duplicates, preprocessor legacy keys cleaned up
    (**breaking** — old sessions may not load), Conv hex input
    scrolling, filter validation, group-by-stream initial check, small
    aesthetic changes, removed `threads` var.
- **Breaking:** saved sessions may need to be discarded and rebuilt.
- **Removed:** non-dot-notation keys, `threads` var, backend JSON
  duplicates.
- **Improvements**
  - New themes (pastels, Sub7), light theme tweaks, new ico location,
    encodings hidden import, conditional forge builds, Windows
    installer icons fixed, .deb fixes under Kali, .desktop template,
    UPX packing option (off by default), installer splash, backend
    scheduler optimizations, List column resize/show-hide, backend
    version string, version check, PGP autoloads secrets, heatmap
    scales, FRAME/unknown fallback hardening, normalized key format,
    src/dst port aliases, retuned map zoom, map calibration edits,
    Prev/Next repositioned, LLM diagnostics in activity log, backend
    server correctness.

### v1.8.1384 — 2026-07-01

- **Removed:** unneeded reqs, Ollama dep from backend, LLM
  references/calls, `_dirname`/`_filename` patches.
- **Fixes:** `requirements.txt` cleanup, Windows PyInstaller spec,
  startup hardening, DefinePlugin + dirname fallback, runtime bug
  attempts, Ollama compile attempt.
- **Improvements:** version bump, Ollama runtime check, longer LLM
  default timeout, per-stream LLM calls in frontend, LLM moves out of
  backend, better scaling, "marked" for tables, markdown + note edit
  mode, stream-size warning setting, settings tab, theme engine
  (quit button, two new themes, light theme tweaks, fixed pretty JSON,
  `snitch.py` chunk size, credentials counter, context-aware LLM,
  per-stream targeted Ollama, improved filter grep, keystore filter,
  logging touchups, theme engine carryover fix, theme engine logo
  replacement, settings logging to activity log, theme selection
  decision matrix).

### v1.8.1332 — 2026-06-28

- **Fixes:** array-type guards, zero-packets warnings, clear-on-zero
  flow, valid-key check on zero-packet filter, license link.
- **Improvements:** initial frontend LLM test, per-packet/key filter
  - group, Total Traffic fix, beginning of heatmap.

### v1.7.969 — 2026-06-24

- **Features:** globbing regex in filter, Brotli detection, Help
  button + docs window, docs access controls, extensive features
  list, more sample captures, new compression sample, new filter
  keys.
- **Fixes:** backend clobbering on new session before done, layer
  correctness, User-Agent = PacketSnitch, demo gif YouTube link,
  more Help URL guards, `hideAllData` guards, BGP data type list
  hiding, Overview 1→3 columns in Stats.
- **Improvements:** `link.proto` context menu, transport/application
  filter relabeling, proper protocol keys in backend for filtering,
  globbing examples.

### v1.7.935 — 2026-06-21

- **Features:** SIP and FTP decoders (with keychain auto-populate),
  `tcp.retransmission` key + retransmission/out-of-order keys,
  retransmission stats in Stats, data type guesses for endpoints
  - MAC, date/time type identifiers, single byte data type guessing,
  Save Raw Conv data via context menu, streamlined protocol matching,
  HTTP following (full body to Conv + export), decompression-aware
  context menu, more sample data, preliminary IGMP backend, non-TCP
  packet handling, lower-level protocol identifiers in Stats,
  improved protocols-used readout in Host Data, protocol auth
  extractors, bookmarked-host filter, large-stream warning, keystore
  autoadd with lazyload metadata, table coloring.
- **Fixes:** data types frame auto-hide, exploit pcap renamed.
- **Improvements:** better targeted context menu, uppercased
  application-layer protocols in Stats.

### v1.7.848 — 2026-06-17

- **Features:** backend chunked push, lazyload from drive, status
  update 10s, JSON/pcap/pcapng constraint in session picker, more
  decoders, keystore autoadd objects, session vs pcap check, backend
  existence check, filter query status, explicit filter clear log,
  stream stats on left, stream stats in Host Data + Stats, Conv
  data in session, docs context-menu reference, `tcp.proto`/
  `udp.proto`/`app.proto` split, location click → city query, DNS
  qname stray-IP cleanup.
- **Removed:** stray IPs from DNS qname in Stats, divider above
  Exports submenu.
- **Fixes:** packet array sync, autosave guards (real session
  only, no dummy), autosave on exit + log write, session-open
  check before save, new session clears old, port click searches
  both TCP+UDP, `back-comm.js` loader handles new format, no tab
  jumping during ingest, no repeated List view log, no unary space
  on `[Snitch]`.
- **Improvements:** save button moved to bottom, divider removed,
  shorter context items, app+transport protocol filter contribution,
  gif demo, static gif width, workflow/daily runs rename, repo stats
  GH action, picker dim retention, `persistSessionToDisk` null
  session name on autosave, autosave fix, exit button exits picker
  not PS, no save/export/reprocess during preprocess, session
  restoring reloads payload data, log renderer thread tag, error
  message fix, reprocess-too-soon catch, more docs screenshots, docs
  correction, stream order + filter context in Host Data, auto host
  targeted filtering, session manager saves pcap.

### v1.6.807 — 2026-06-14

- **Features:** autosave on exit + log write, new compressed session
  format.
- **Removed:** dependency on manual save on exit.
- **Fixes:** autosave on real session only, dummy session discard
  (<5KB), session-open check before save, new session button
  clears old, loading screen dim, blank hosts list for 0.0.0.0,
  packet array sync.

### v1.5.731 — 2026-06-07

- **Features:** encodings hidden import, snitch binary location
  swap, conditional forge builds per OS, .desktop template, UPX
  option (off by default), installer splash.
- **Fixes:** Windows installer icons, stripped backend package,
  .deb under Kali, .desktop metadata, compression block notice.
- **Improvements:** build metadata, description + uninstaller ico,
  installer loop gif, some docs, new ico location, docs AI redo,
  terminal explicit false in .desktop.
- **Removed:** unneeded backend package stuff.

### v1.5.705 — 2026-06-03

- **Features**
  - Width/height config for small screens, dynamic CPU core count,
    Conv color coding improvements, Conv input history UI, Conv
    output visibility mapping, hide redundant conv output pane,
    clamp + constrain conversion panel columns, fix Conv output
    expansion toggle, fix Conv background color, prevent drag-drop
    text editing in Conv/filter/host inputs, fix Conv hex output
    mouse-drag, refine Conv highlight map fallbacks, harden Conv
    selection sync, Conv hex color coding + cross-frame selection
    sync, guard conv output expand handlers, conv output expand/
    collapse interaction, Conv text type heuristics, refine Conv
    guess scan + context-menu derive, chunked Conv guess scanning
    - context derive, sanitize host target filter query terms,
    `guessDataType` refactor (UUID/JWT regex constants, base64
    score constants), sync target host selection with filter bar,
    tighten JWT regex, data type guessing (hashes, base64, PGP,
    JWT, UUID) below MIME type in Conv, restrict keystore reset
    to unlock mode, guard nested keystore reset, polish keystore
    dialog wipe button, refine keystore dialog reset flow, keychain
    wipe action to unlock dialog, log renderer console.error to
    activity log, tidy keystore password confirm, fix keystore
    reset function scope, centralize keystore reset warning text,
    centralize keystore minimum password length constant, keystore
    password reset with wipe warning, keep loading screen visible
    until packets render, modified Python `requirements.txt` for
    Linux.
- **Removed:** `threads` var in backend config.
- **Improvements:** normalize/remove duplicates, logging
  congruence, build-from-source README, RPM builder patch, logging
  code update, frontend in installed screen, installed-files
  locator, removed compiled backend dir + added tagline logo, gif
  update, paths fix, `patchup` removed from `npm run make` on
  Windows, version update.

### v1.5.618 — 2026-05-30

- **Features:** frontend in installed screen, installed-files
  locator.

### v1.5.610 — 2026-05-29

- **Removed:** compiled backend dir, `patchup` from `npm run make`.
- **Improvements:** gif update, tagline purple, paths fix, README
  update.

### v1.4.508 — 2026-05-26

- **Features**
  - Stream filter when selecting packet from List/Stats, hash
    algorithm outputs (MD5, SHA-1, SHA-256/384/512, SHA3-256/512,
    RIPEMD-160, Whirlpool) in Conv, `@noble/hashes` + `whirlpool-js`,
    refactor Conv hash to pure JS, reorganize context menu, HTTP
    file context menu, cookie jar autoadd, "Add to Keystore" for
    highlighted text, load-raw-payload-into-Conv action, multi-
    level submenu viewport positioning, extract cookies + POST
    body credentials to keystore, auto-detect HTTP/SMTP/POP3/IMAP/
    Telnet creds, session key bookmarking, password-gated keychain,
    first-time keychain password setup, IndexedDB keystore
    persistence, split keystore panel, move keystore to standalone
    panel, tighten Telnet auto-detection, HTTP/Telnet/SSH/POP3/IMAP/
    SMTP decoders in Conv, Crypt tab with SSL workspace + persistent
    keystore, filter validation + error reporting, context menu
    explicit parens, no double-wrapping negated clauses, unary `!`
    - is-not actions, explicit `&&`/`||` filter-append, Clear and...
    submenu, no double `[Console]`, backend logs `[Console][Backend]`,
    backend errors `[Console][Backend]`, UI logs `[GUI][UI]`, log
    console output to activity log, tab bar width + Prev/Next
    placement, Prev/Next to far right, swap Stats/Data tab
    positions, rename Data → Conv, tighten context menu active
    cursor guards, normalize context menu active packet cursor,
    sync active packet cursor for context menu helpers, use active
    packet accessor in context menu export, flip context submenus
    inside viewport, restructure context menu into convert/filter/
    export branches, TLSv1.2 context, allow min TLS1.2, TLS probe
    reliability with SNI fallback, explicit TLSv1.2 banner probe,
    refine HTTPS service checks + SNI, harden TLS context + tidy
    HTTPS detection, fix TLS encryption details for HTTPS, replace
    filter history popup with select dropdown, Conv tooltip, hex
    copy actions in right-click menu, unify right-click context
    menus + conditional copy visibility, right-click menu with
    copy/paste/save JSON, blank right panel on List/Stats, darken
    selected packet row on hover, Unknown fallback for stream
    grouping, sortable packet-list columns, List tab enhancements
    (hover highlight, bookmark column, stream grouping), new List
    tab between Stats and Log, filter aliases and text matching
    for `wire.proto`/`eth.src.vendor`/`mime.type`/`dns.qname`,
    capture stats page, polish query highlight loop, refine
    query-history empty-state styling, improve query syntax UI
    accessibility/keyboard, allow empty query-history dropdown,
    syntax highlighting for filter query input + history, packet
    query history dropdown, cached host value in logging,
    normalize error log helpers, log all frontend error paths,
    harden activity timeframe parsing, fix IPC placement, activity
    log UI + persistence, stream filter when selecting packet,
    simplify `packetsForHost` fallback, preserve active filter and
    packet on Host Data reopen.
- **Fixes**
  - Prev/Next positioning, UI tweaks + more error messages, tab
    opacity, taller data tools input, port/Network Class context
    menu filter detection, port handling, context filter query
    sanitization, context filter value handling, context-menu
    filters append to existing, context filter parsing edge cases,
    editable target checks for paste, no deprecated `execCommand`,
    context-menu paste targeting + reorder save option, save-json
    handling + visibility flag, success status feedback for copy,
    review nits, catch blocks + byteIndex naming, hex grid
    iterator rename, context menu closing + hidden state, review
    nits, refine context conversion validation, box sizing, log
    search box, fixed column widths in packet list, normalize/
    sanitize stats entries, hex grid cell square, simplify hex
    grid cell wrapping rule.
- **Improvements**
  - Author line, removed eslint backup, chardet in backend reqs,
    some theme changes, docs updates, list screenshot.

### v1.3.353 — 2026-05-24

- **Features**
  - Electron forge updates, Python reqs, log search box, List tab
    between Stats and Log, fixed column widths, removed unused
    CSS class, stats screenshot, normalize/sanitize stats, filter
    aliases for `wire.proto`/`eth.src.vendor`/`mime.type`/
    `dns.qname`, capture stats page, query highlight polish, query-
    history empty-state, query syntax UI accessibility/keys,
    empty query-history dropdown, syntax highlighting for filter
    - history, query history dropdown, cached host value, error
    log helpers, log all frontend error paths, activity timeframe
    hardening, IPC placement, activity log UI + persistence,
    simplified `packetsForHost` fallback, hex grid cell rule +
    square cells, chardet in backend reqs.
- **Improvements**
  - Removed eslint backup, theme changes, README screenshot,
    screenshot 24.
- **Removed**
  - `eslint` backup.

### v1.2.310 — 2026-04-23

- **Features**
  - Safely read MAC fields when Ethernet Frame may be N/A, MAC
    info when one IP is private + the other internet, save JSON
    from in-memory, README image, off-by-one fix for first packet
    in host list, sync bookmark dropdown when target host
    changes, `syncBookmarkDropdown` helper, sync bookmark
    dropdown with packet navigation, eslint fixes, resolve all
    JS errors in `src/`, linting config update, remove
    `.progress-ps.html`, hosts.json 1s delay load, RADIUS TCP
    per RFC 6614, wire new protocol decoders into frontend
    pipeline, FTP/SMTP/POP3/IMAP/Telnet/IRC/MTP/LDAP/MySQL/
    PostgreSQL/XMPP/SMB/MQTT/RTSP/TFTP/BGP/HTTP2/NNTP/RADIUS
    decoders, extract protocol decoders into `decoders.js`,
    `CopyPlugin` for `src/assets`, replace inline base64 PNGs with
    files, backend `onedir` (saves 4s, no unpack), status shows
    PS version, `SOFTWARE_VERSION`, install-complete screen on
    new version, README rewrite.
- **Improvements**
  - Hide menu bar, fix images, filter docs link, filter keys
    update.

### v1.2.254 — 2026-04-16

- **Features**
  - Filters.md link, comprehensive Filters.md, README with
    donation options, QR codes, organized docs, Frontend.md
    install, `numWorkerThreads` = 2× CPU cores, draggable top
    bar, aria-label, removed frame, README revisions, zoomed map
    out, error auto-clear, README update, Backend.md/Frontend.md
    split, HTTP backend+frontend decoder, `packet.protocol` →
    `packet.proto`, SNMP/ICMP/SIP/DHCP/NTP, UDP/DNS backend+
    frontend, default save to Documents, filesave worker pointer,
    copy `hosts.json` to dest (no IPC), threaded save-JSON,
    removed save functions, silent exit when output dir exists,
    reset on reload, snake_case → camelCase in `snitch.py` and
    `scripts.js`, code review fixes, descriptive variable names,
    target host selection with filter readout, Save JSON with
    save-as, reloading with optimized backend, removed .exe,
    removed useless icons, nollm call fix, LLM enable/disable
    - `--no-llm` flag, dev install, README with images/usage,
    version, bookmark fixes, off-by-one, horizontal scroll
    disabled, remove `dns.hostnames` non-leaf, Searchable
    Attributes, README update, new screenshot, version, fixed
    timestamp + recon, payloadascii tooltip, removed old samples,
    new search params, load time timer, packet size + filter
    result size readout, packet counting on sidebar,
    positioning/z-index, zoom bug, version bump, initial display
    bug fixes, no-packets-from-filter handling, screenshot, better
    filtering, index fix, better filter, more filter, filter
    almost working, starting filter functions, better
    compression, better DNS host + catchall error, better error
    - blink, summary box tweaks, encryption undefined fix, error
    message, squirrel install, failsafes, screenshot, version,
    data box bug + new data points, new extra info pane, loading
    screen, backend dead on quit, installer/exe icons, first
    working bins, Windows builds, OS detection, build
    adjustments, backend install hook, initial commit.
- **Fixes**
  - Box resize, parens grouping, Unix path, JS errors,
    payloadascii tooltip, linting, eslint fixes.
- **Removed**
  - Window frame, old unworking samples.
- **Improvements**
  - UI improvements, version, screenshot, .exe + useless icons,
    bookmark code.

### v1.2.227 — 2026-04-15

- HTTP backend+frontend decoder, `packet.protocol` →
  `packet.proto`, SNMP/ICMP/SIP/DHCP/NTP, UDP/DNS, save to
  Documents, filesave worker, copy `hosts.json` to dest,
  threaded save-JSON, snake_case → camelCase, reset on reload,
  Save JSON, LLM enable + `--no-llm`, dev install, README,
  version, bookmark fixes, off-by-one, horizontal scroll,
  old samples, new search params, timer, packet/filter size
  readout, packet counting, positioning, zoom, compression,
  DNS, error handling, summary box, encryption undefined, error
  message, squirrel, failsafes, data box, info pane, loading
  screen, backend quit, installer/exe icons, first bins,
  Windows, OS detection, build, backend hook, initial commit.

### v1.1.195 — 2026-04-13

- **Removed:** useless icons.
- **Features:** icons, new ver, LLM toggle, `--no-llm`, dev
  install, README, bookmark fixes, off-by-one, horizontal scroll.
- **Improvements:** optimized `snitch.py` (O(1) lookups, GeoIP
  cache, thread safety, bug fixes), backed off threads.

### v1.1.184 — 2026-04-12

- **Features:** version, bookmark fixes, off-by-one, horizontal
  scroll, Searchable Attributes, README + screenshot, version,
  timestamp + recon, payloadascii tooltip, old samples, new
  search params, timer, packet/filter size, packet counting,
  positioning, zoom, version, initial display bug fixes, no
  packets from filter, better filter, better compression, better
  DNS, better error, nice loading screen, cleaned code, initial
  commit.
- **Removed:** old unworking samples.
- **Improvements:** box resize, parens grouping, UI improvements.

### v1.0.175 — 2026-04-13

- **Removed:** useless icons.
- **Improvements:** icons, version bump, version update.

### v1.0.158 — 2026-04-01 (major)

- **Removed:** window frame.
- **Features:** first stable 1.0; app framework, backend Python,
  Electron UI, filter system, bookmark system, hex grid, info
  panel + packet details, data box, loading screen, frameless
  window, cross-platform installers, auto-update, statistics
  tab, stream stats, compression + encoding detection, network
  class detection, GeoIP, hostname resolution, backend LLM.
- **Fixes:** initial display bugs, filter + bookmark improvements,
  backend process management, various UI bugs.
- **Improvements:** various.

### v0.9.130alpha — 2026-03-24

- **Features:** alpha release, initial working bins, app
  framework, `snitch.py`, Electron UI, filter, bookmark, hex
  grid, info panel, statistics, GeoIP, hostname, squirrel
  installer, OS detection, icons, branding, build config.

### Initial Development — 2026-02-17 to 2026-03-24

- Pre-alpha: project scaffolding, Electron + Python backend
  architecture, bookmarks/Prev-Next, logos, screenshots, hex
  grid + payload, two-pane UI, checksum table, encryption
  fallback, package detection, backend IPC bridge, location
  logic, README, GNU GPLv3 reference, screenshot 14, more UI
  alignment work, location sidebar, sort-of help menu, backend
  icon, hex payload + payload pane, info pane, screenshot
  updates, multi-pane mockups, icon placeholders, doc cleanup.

---

## How to update this file

When you land a new feature, open this file and:

1. Find the matching item in **Status legend**-style sections above.
2. Bump its sub-bullet from `[ ]` → `[🟡]` or `[✅]`.
3. If the whole item is done, flip the section-level status to
   **Shipped** and add a bullet under `### Unreleased` in
   `RELEASE_NOTES.md` as well.
4. If scope shifts, update the **Est. remaining** or **Complexity**
   line. Re-check the estimate against the
   [Release velocity](#release-velocity-how-fast-this-project-actually-ships)
   table at the top — if your new estimate doesn't fit, it probably
   needs to be re-scoped (this project genuinely ships in days,
   not weeks).
5. If you add a brand-new idea not on this list, add a section in the
   right thematic group with a fresh status.

This file should never shrink — only grow and turn green.
