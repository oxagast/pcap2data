# Release Notes

## v2.8.2 - 2026-09-05

**Type:** patch

> PCAP merge enhancements, six new protocol decoders (SSDP UPnP, gRPC,
> DHCPv6, mDNS, LLMNR, EPMAP), improved plain-text decoder, and
gRPC stream reassembly fix.

### ✨ Features

- **Six new protocol decoders — SSDP UPnP, gRPC, DHCPv6, mDNS, LLMNR,
  EPMAP (Conv → Decodes + sidebar)** — extends protocol coverage with
  **SSDP** (Simple Service Discovery Protocol / UPnP), **gRPC**
  (Google RPC over HTTP2), **DHCPv6**, **mDNS** (multicast DNS),
  **LLMNR** (Link-Local Multicast Name Resolution), and **EPMAP**
  (DCE/RPC Endpoint Mapper). All are registered in
  `SUPPORTED_DECODER_PROTOS` and auto-detected via
  `PROTOCOL_DECODER_HINTS` / `PORT_DECODER_HINTS`.
- **gRPC stream reassembly fix** — fixed a bug in the gRPC decoder
  where stream fragments were not being correctly reassembled,
  causing partial or corrupted output for multi-frame gRPC calls.
  The decoder now properly buffers and reassembles streaming RPC
  responses.
- **Plain-text decoder improvements** — the generic plain-text decoder
  was enhanced with better boundary detection and charset handling
  for more reliable text extraction from raw streams.
- **PCAP merge detail buckets** — the Stats → PCAP Comparison subtab
  now shows per-bucket detail (packet counts, byte totals, timing
  distribution) rather than just aggregate stats, making it easier
  to identify which traffic segments differ between captures.
- **Shannon entropy color-coding improvements** — the entropy
  visualization in PCAP comparison now has finer color gradation
  for better differentiation of low/medium/high entropy regions,
  and the entropy symbol was corrected for consistency.
- **Multi-source bookmarking and targeting fix** — fixed bookmark
  creation and target resolution when a session has multiple
  capture sources, ensuring bookmarks correctly reference the
  intended source and stream.
- **Better merge support** — various improvements to the PCAP merge
  workflow including better handling of overlapping time ranges and
  deduplication of duplicate packets across sources.

### 🐛 Fixes

- **gRPC stream reassembly** — see Features above.
