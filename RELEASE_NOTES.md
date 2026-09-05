# Release Notes

## v2.8.0 - 2026-09-04

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

- **Stats → Capture Sources** — merged sessions can mask individual capture
  sources, compare source statistics with each other or the whole session, and
  optionally color-code source rows in List view.
- **Load carved file into Decoders** — carved files can be loaded directly
  into the Conv decoder workspace.
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
- **PCAP import cleanup hardening** — while zeroing capture state in
  preparation for a new PCAP import, log output is now suppressed
  and external function calls to non-localhost sites are blocked, so
  a partially-zeroed state can't leak data or fan out telemetry to
  remote endpoints mid-transition.
