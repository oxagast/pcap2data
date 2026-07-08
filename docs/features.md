
## PacketSnitch Feature List

PacketSnitch is a full-featured network packet analysis tool with a Python backend for deep protocol parsing and an Electron desktop frontend for interactive browsing, filtering, and forensic investigation. This document lists all available features.

---

### Capture Loading

- Load `.pcap` and `.pcapng` capture files directly from within the app (**Load PCAP** button).
- Load pre-processed `hosts.json` backend output (**Load JSON** button).
- Load previously saved PacketSnitch session files (compressed `.json.xz` or `.json.gz`).
- Session-backed PCAP reprocessing: saved sessions retain the source capture as base64 so the backend can be re-run later without manually re-selecting the file.
- Progressive capture loading: backend emits chunked host snapshots every 500 packets; the UI becomes interactive after the first chunk arrives while processing continues in the background.
- Optional backend HTTP data mode: the bridge can stream incremental JSON snapshots directly over the backend HTTP response instead of waiting on `hosts-*.json` files on disk.
- Lazy packet hydration: packet stubs are built immediately and full payloads are fetched on demand, keeping the UI responsive for large captures.
- Left-panel partial-data warning shown while incremental backend processing is in progress.
- Backend preprocessing blocks session save/export until complete, preventing persistence of incomplete data.

---

### Session Management

- Save full sessions with all UI state: packet cursor position, filter history, active tab, bookmarks, notes, and session keychain.
- Autosave on a 5-minute timer to prevent data loss.
- Session files are compressed with LZMA (`lzma-native`) or gzip as a fallback, keeping saved session sizes small.
- Session library picker (`session-picker`) for browsing and restoring previously saved sessions.
- Session restore skips eager keychain rebuild (deferred to idle time) so the UI opens quickly.

---

### Settings Workspace

- Dedicated **Settings** tab with four sub-tabs: **General**, **LLM**, **Debug**, and **Backend**.
- Settings are persisted to `userData/config/settings.json` via main-process IPC (`settings-get`, `settings-save`, `settings-update`).
- **General** settings:
  - **Theme** selector (`general.themeId`) using discovered theme JSON files.
  - **Conv JSON indent spaces** (`general.convJsonIndentSpaces`) for packet JSON pretty-print formatting.
  - **Status reset delay (seconds)** (`general.statusResetSeconds`) controlling status message timeout.
  - **Default backend packet chunk size** (`general.backendPacketChunkSize`) with allowed values `25`, `100`, `250`, `500`, `2000`.
  - **Backend worker threads** (`general.backendWorkerThreads`) with a default of `2 x CPU cores`.
  - **Stream warning threshold (packets)** (`general.streamContextWarnPacketThreshold`) for follow-stream Conv/Crypt warnings, defaulting to `20` with a minimum accepted value of `5`.
- **LLM** settings:
  - **Ollama model** (`llm.ollamaModel`).
  - **Ollama API key** (`llm.ollamaApiKey`) stored locally in settings.
  - **Active by default** (`llm.activeByDefault`) for the load dialog LLM toggle.
  - **LLM trigger delay (seconds)** (`llm.triggerDelaySeconds`) for stream-summary idle scheduling.
  - **Max tokens for stream summary** (`llm.maxSummaryTokens`) applied to Ollama `num_predict`.
  - **LLM request timeout (seconds)** (`llm.ollamaRequestTimeoutSeconds`) for request headers/body reads.
  - **LLM retries** (`llm.retryCount`) for automatic retry attempts after failed calls.
- **Debug** settings:
  - **Enable backend HTTP data mode** (`debug.backendHttpDataModeEnabled`) to stream in-memory incremental JSON snapshots from the backend HTTP service.
  - **Map projection zoom/offset calibration** (`debug.mapProjectionZoomX`, `debug.mapProjectionZoomY`, `debug.mapProjectionOffsetX`, `debug.mapProjectionOffsetY`) for the worldmap overlay.
  - **Projection lock** (`debug.mapProjectionCalibrationLocked`) to preserve the current calibration.
  - **Ungrouped list virtualization** (`debug.ungroupedListVirtualizationEnabled`) for large List-tab datasets.
- **Backend** settings:
  - **TCP host** (`backend.tcpHost`) and **TCP port** (`backend.tcpPort`) for the bridge HTTP service.
  - **Force legacy backend spawn mode** (`backend.forceLegacySpawn`) to disable service mode and launch the backend per run.
- **Save settings** writes normalized values to disk; **Restore defaults** resets to app defaults.

---

### Theme Engine

- Theme system is file-driven and runtime-discoverable.
- Built-in defaults are bundled in `themes/*.json` and mirrored into `userData/themes` on startup.
- Renderer discovers themes using `themeapi.list()` and applies them using `themeapi.get(themeId)`.
- Theme JSON schema supports:
  - `id`, `name`, `description`
  - `variables` object (CSS custom properties only, keys must start with `--`)
  - optional `logoImage` (`png` or `jpg`, base64 payload)
- Theme IDs are sanitized to lowercase `a-z`, `0-9`, `_`, `-`; invalid IDs fall back safely.
- Invalid theme files are skipped without crashing, and duplicate IDs are de-duplicated.
- Selected theme is persisted through `general.themeId` in settings and applied on startup.
- Theme logo override uses a data URI generated from the JSON `logoImage`; fallback restores default app logo.
- Theme directory path is exposed in Settings (`themes-directory` IPC) to guide custom theme placement.

---

### Packet Navigation

- **Prev / Next** buttons to step through packets one at a time.
- **Target Host** dropdown to scope navigation to a specific source/destination IP pair.
- **All Hosts** (`0.0.0.0`) virtual option routes navigation across every packet in the capture.
- Navigation follows the active filtered packet set when a filter is applied.
- Packets are ordered strictly by capture timestamp, then `Packet Processed`, then index.
- Packet bookmarks: mark any packet with a star; bookmarked state is saved in the session.
- **★** bookmark indicator in the List tab and filter support via `bookmark:true`.
- Click any row in the List tab to jump directly to that packet in the Host Data view.

---

### Host Data View

#### Packet Info Pane

- **IP-to-IP Routing**: source → destination address display for quick flow identification.
- **Network Information**: source/destination port, IANA service name, and ICANN port description.
- **Data Type List**: detected MIME type, character set, content encoding, and magic-identified type (hidden by default for ARP/RARP/IGMP with an inline reveal toggle).
- **Active Recon** section (when backend was run with `-a`):
  - Identified application-layer protocols.
  - Payload compression method.
  - SSL/TLS version and cipher suite.
  - Fetched website title.
  - Reverse DNS hostnames.
- **Protocols Used** panel with deduped, layered protocol entries (Link / Network / Transport / Application / Encryption / Decoded).
- TCP stream arrival status labels: In-order, Out-of-order arrival, Retransmission, Retransmission (out-of-order arrival).

#### Packet Payload Pane

- **ASCII View**: consecutive runs of printable characters extracted from raw payload bytes.
- **Hex Grid**: interactive hex dump of the full raw payload with click-to-highlight cells; clicking a byte highlights it and shows the printable ASCII sequence starting at that offset.

#### Right Sidebar

- **Datagram Frame**: protocol-specific lower-layer field tables (DNS, HTTP, SNMP, DHCP, NTP, SIP, checksums, etc.) that update per packet.
- **Location Panel**: GeoIP table showing country, city, postal code, and time zone for source and destination IPs; `Localnet` label for private addresses.
- **Payload Entropy**: Shannon entropy value with graphical indicator (Low / Medium / High labels).

---

### Protocol Decoders (Backend)

The backend extracts rich, queryable metadata for the following protocols:

| Layer | Protocols |
|---|---|
| **Link / WAN** | Ethernet, ATM, Token Ring, Frame Relay, SDLC, HDLC, SLIP, PPP (LCP/NCP/LAP), ARP, RARP |
| **Network** | IPv4, ICMP, IGMP |
| **Transport** | TCP (with flags, sequence/ack numbers, retransmission tracking), UDP |
| **Application** | HTTP/1.x, HTTP/2, HTTPS, DNS, SNMP, DHCP, NTP, FTP, SMTP, POP3, IMAP, Telnet, IRC, SIP, SMB (v1 & v2/v3), MQTT, RTSP, TFTP, BGP, XMPP, LDAP, MySQL, PostgreSQL, NNTP, MTP/MMS, RADIUS |

Each protocol contributes dot-notation metadata keys usable in the filter bar.

---

### Filter Engine

- Real-time filter bar supporting a rich expression language.
- **Key:value** equality: `ip.src.addr:10.0.0.1`
- **Comparison operators**: `==`, `!=`, `>`, `>=`, `<`, `<=` (e.g. `payload.entropy:>=7.0`).
- **Boolean combinators**: `&&` (AND) and `||` (OR) with AND taking higher precedence.
- **Parentheses** for explicit grouping: `(tcp.dst.port:80 || tcp.dst.port:443) && payload.entropy:>=6.0`.
- **Inversion** with `!`: `!tcp.dst.port:443`, `!(tcp.dst.port:80 || tcp.dst.port:443)`.
- **Bookmark filter**: `bookmark:true` / `bookmark:false` (client-side, composable with backend expressions).
- **`decoded-proto` alias**: aggregates transport + decoded protocol names including link-control for queries like `decoded-proto:ppp`.
- Case-insensitive key normalization: spaces and hyphens are interchangeable (e.g. `wire-length` = `wire.len`).
- Substring matching for vendor, MIME, and DNS name fields.
- Filter history tracked per session and accessible from the filter bar.
- Saved-filter library persisted in user config (`config/filters.json`) with labeled entries merged into the filter history dropdown.
- Right-click save/remove flow for the current filter query via in-app modal dialog (no native `window.prompt` dependency).
- Context menu shortcuts to build filter clauses from current packet attributes (IP, port, MAC, protocol, MIME type).
- Context menu parenthesis helpers: **Append (**, **Append )**, **Wrap with (...)**.
- Filter results update the **Filtered Packets** counter in the left sidebar.
- Clicking a Stats tag pre-fills the filter bar with the matching filter expression.

#### Filterable Packet Attributes (highlights)

- Core: timestamp, transport proto, raw hex.
- Ethernet: MAC addresses, MAC vendor.
- IP: source/destination address, checksum, length, network class.
- TCP: ports, checksum, flags, urgent pointer, length, service name, sequence/ack numbers, payload length, retransmission/out-of-order flags.
- UDP: ports, checksum, length, service name.
- ICMP: type, code, id, sequence, checksum.
- Payload: hex, ASCII, length, MIME type, Shannon entropy, charset, encoding, distinct byte count, decompressed hex/ASCII.
- GeoIP: country, city, postal code, timezone for source and destination.
- Active recon: server banner.
- All protocol-specific keys listed in [Filter Reference](filters.md).

---

### Statistics Tab

Aggregate statistics over the entire loaded capture, presented as clickable tag clouds:

- **Capture Overview**: total packets, unique hosts, encrypted vs. unencrypted counts, unique protocol count, unique GeoIP location count.
- **Capture Overview** now also includes `Total Traffic` (sum of payload bytes) and `Credentials Found` (current active keychain entry count).
- **Top Talkers**: top IPs by packet participation (source + destination); clicking an entry applies an IP src/dst filter.
- **Application Protocols**: all distinct application-layer protocols.
- **Transport Protocols**: TCP, UDP, ICMP breakdown.
- **All Hosts Addressed**: unique source and destination IP addresses.
- **Hostnames (DNS)**: resolved hostnames from DNS or reverse lookup.
- **Physical Locations**: city/country pairs with occurrence counts (sorted by frequency).
- **Ports Seen**: all source and destination port numbers observed.
- **MAC Vendors**: Ethernet OUI vendor strings.
- **MIME Types**: all distinct payload MIME types.
- **Data Types**: all distinct magic-identified type strings.
- **Carvable Files**: discovered carve candidates across HTTP/FTP/NFS/SMB streams; clicking a candidate loads the carved bytes directly into Conv.
- **ARP/RARP Operations**: ARP/RARP operation type counts.
- **IGMP Message Types**: IGMP type distribution.
- Clicking any tag (except location) pre-fills the filter bar with the corresponding filter expression.

#### Internet Heatmap / Worldmap

- Worldmap-style Internet Heatmap based on public GeoIP coordinates for source and destination addresses.
- Basemap is rendered from a bundled SVG world map and themed at runtime to match the current UI colors.
- **Aggregate By** toggle: whole capture vs. currently filtered packet set.
- **Intensity By** toggle: packet hits vs. payload bytes.
- Interactive controls for map zoom, intensity, point size, tightness, and blur.
- Clickable location dots highlight individual geolocated points; selection zoom helps inspect dense regions.
- Heatmap summary text reports geolocated host count and current metric total for the active scope.
- Private/local addresses are excluded; only routable addresses with GeoIP coordinates are plotted.

---

### List Tab

- Searchable, sortable table of all packets across all hosts.
- Real-time text filter by host, IP, port, or protocol name.
- **Group by stream** toggle: groups rows by bidirectional stream (canonical 5-tuple) before sorting.
- Sortable columns: index, bookmark, stream group, host, source IP, destination IP, source port, destination port, transport, application protocol.
- Click any row to navigate directly to that packet in the Host Data view.
- Bookmark indicator column (★) with visual fill for bookmarked packets.

---

### Conv Tab (Data Conversion Workspace)

#### Conversions Sub-tab

- Input formats: Base64, Binary, Hex, ASCII/UTF-8, Decimal bytes.
- Simultaneous output in: Hex, Binary, Decimal bytes, Decimal integer (big-endian), ASCII, Base64.
- Input history dropdown for the current session.
- Manual file import into Conv from context menu with size warning threshold and configurable maximum size.
- **Data Insights**: byte length, MIME type (magic detection), detected text language, up to three ranked data-type guesses (JWT, bcrypt hash, Base64, etc.) with High/Medium/Low confidence, Shannon entropy with Low/Medium/High label.
- **Filename Guess** in Data Insights, including carved/loaded filename context when available.
- Entropy range: 0.0–8.0 bits/byte; Low < 4.5, Medium 4.5–6.8, High > 6.8.

#### Hashes Sub-tab

- Hash-as-you-type from any input text.
- Algorithms: MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, RIPEMD-160, Whirlpool.
- Supports escape sequences (`\n`, `\r`, `\t`, `\\`, `\xNN`) for exact byte hashing without raw binary paste.
- **Convert** in Conversions sub-tab automatically propagates input bytes to the Hashed Input field.

#### Decodes Sub-tab

- Protocol decoder with auto-detect and manual protocol selection.
- Supported protocols: HTTP, Telnet, SSH/OpenSSH, POP3, IMAP, SMTP, SIP.
- Auto-detect identifies the likely protocol from byte patterns (SIP detected via INVITE/ACK/SIP/2.0 regex, etc.).
- **Follow stream to Conv**: assembles a full bidirectional TCP stream into Conv with async chunked scanning and loading overlay to prevent UI freezes on large streams.

---

### Crypt Tab (Encryption Workspace)

#### SSL Sub-tab

- **Encountered SSL/TLS**: list of all distinct TLS sessions detected in the capture.
- Per-session details: SSL version, cipher suite, certificate text.
- **Filter packets**: one-click filter to show only packets from the selected TLS session.
- **Load cert text**: copy the session certificate into the Certificate Loader.
- **Certificate Loader**: load a PEM certificate from file or paste PEM text; parsed preview displayed.
- **Private Key Loader**: load a PEM private key from file or paste PEM text; parsed preview displayed.
- **TLS/SSL Decrypt**: RSA decryption of the selected session's payload using the loaded private key; decrypted hex and ASCII preview; **Send to Conv** button.

#### PGP Sub-tab

- **PGP Messages In Capture**: scans loaded packet payloads for ASCII-armored OpenPGP blocks and lists them by packet.
- **Refresh** re-scans the current capture; **Load selected** copies the chosen block into the PGP input area.
- **PGP Input** accepts either ASCII armor or binary hex and can:
  - **Analyze** detected structure (message, signature, public key, private key, cleartext signed message)
  - Convert **To ASCII armor**
  - Convert **To binary hex**
- **Key Material** inputs:
  - Optional private key input for decryption
  - Optional public key input for signature verification
  - Passphrase input plus auto-discovered passphrase candidates recovered from packet text and metadata
- **Decrypt / Verify** handles encrypted messages and cleartext signed messages using `openpgp` in the renderer.
- Successful decrypt/verify output can be **Sent to Conv** and validated private key/passphrase material can be promoted into the session keystore.

#### OpenSSH Sub-tab

Reserved workspace for future OpenSSH key and session tooling. The Conv decoder can still parse SSH/OpenSSH text structures today.

---

### Keystore Tab (Local Credential Store)

- Two keychains: **Session** (in-memory, resets on close) and **Persistent** (AES-GCM encrypted, stored in IndexedDB).
- First-use password setup dialog; subsequent launches prompt for unlock passphrase.
- **Reset keychain password**: wipes persistent entries and sets new encryption password (confirmation required).
- Entry types: password/secret, private key, certificate, session cookie, URL.
- **Open link** button: open URL-type entries directly in the system browser.
- **Send to persistent**: promote a session entry to the encrypted persistent keychain.
- **Delete selected**: permanently remove a persistent entry.
- Details preview pane: type, label, source, creation timestamp, content summary.
- **Session keychain filter bar**: quick-search session entries by type, label, and content; hidden while viewing persistent keychain mode.
- **Export keystore**: export session or persistent keychain entries to CSV, JSON, or XML via context menu submenu.

#### Auto-population from Packet Data

Automatically extracts and adds entries to the Session keychain when a capture is loaded:

- **HTTP Basic Auth**: username and password from `Authorization: Basic` headers.
- **HTTP form credentials**: username/password fields extracted from POST bodies.
- **HTTP cookies**: `Cookie` and `Set-Cookie` header values; structured `cookie.*` metadata fields.
- **HTTP request targets**: raw URI and constructed full URL (with `Host` header or fallback to packet IP).
- **FTP credentials**: USER/PASS commands (validated to port 21).
- **SMTP credentials**: AUTH login (validated to ports 25/465/587).
- **IMAP credentials**: LOGIN command (validated to ports 143/993).
- **RDP credentials**: user:/pass: fields (validated to port 3389).
- **SIP credentials**: Digest auth response (labeled as hashed), Basic auth username/password, email addresses from From/To headers (validated to ports 5060/5061).
- **Hostnames, IPv4 addresses, emails, and URLs** extracted from packet text payloads.
- Auto-population runs in the background via `requestIdleCallback` to avoid blocking the UI.
- Stub packets are hydrated on demand via `captureapi.getPacket` during keychain rebuild.
- Keychain rebuild re-triggers after backend progressive loading completes.

---

### Notes Tab (Session Notes)

- Create freeform text notes tied to the current session.
- Color-tag notes with a color picker (visual coding per note).
- Full-width editable text area; edits reflect immediately in the notes list preview.
- Remove individual notes.
- Export all notes to a plain-text file with `---` dividers.
- Notes are saved as part of the session file.
- **Send to Notes** context menu submenu: send selected/context text, List row visible data, Conv output, or Conv hashes to a new note.

---

### Activity Log Tab

- Timestamped log of all GUI actions, backend events, and console output.
- Entry prefixes: `[GUI][UI]`, `[Console][UI]`, `[Console][Backend]`.
- Real-time search/filter bar (case-insensitive substring match).
- Log written to a persistent file on disk; file path shown at the top of the panel.
- Duplicate log suppression: identical renderer console entries are suppressed for 5 seconds.
- Incremental backend refresh log lines suppressed to avoid noise.

---

### Context Menu (Right-Click)

Available in packet views, payload panes, Conv tab, and other data panels. Adapts dynamically to context.

#### Copy

- **Copy**: copy highlighted text to clipboard.
- **Copy Hex**: copy raw payload as a hex string.
- **Copy ASCII**: copy printable ASCII representation of the payload.
- **Copy Raw payload**: copy raw payload bytes.
- **Copy Cookies**: copy all session cookie jar entries as a formatted string.

#### Paste

- Paste clipboard text into the focused input element.

#### Convert to...

- Load selection or packet/context data into the Conv tab with a pre-selected input format and auto-run Convert.
- Options: Hex, Binary, Base64, Decimal bytes, ASCII/UTF-8.
- **Derive Type**: run the data-type guesser on selected/context text and show ranked guesses in Conv Data Insights.
- **Cursor ASCII to Conv tab**: load the ASCII string at the current hex-grid cursor position into Conv.
- **Raw Payload to Conv tab**: load the current packet's full raw payload as hex into Conv.
- **Decompress to Conv tab**: when Conv input appears compressed (gzip/deflate/brotli), decompress and load decompressed bytes into Conv.
- **Import file to Conv tab**: open a local file and load its bytes into Conv as hex, subject to manual-import size policy.

#### Follow stream...

- **Stream to Conv tab**: reassemble a bidirectional stream and load it into Conv as hex.
- **Stream to Conv tab (decompressed)**: reassemble stream payload, attempt decompression, then load into Conv.
- **Stream to Crypt tab**: reassemble stream payload and load ASCII output into the Crypt workspace.
- Large streams can trigger a confirmation prompt before loading.

#### Filter...

- Build and append filter clauses from current packet attributes.
- Sub-menus: **Add with &&**, **Add with ||**, **is not** (negated &&), **Clear and...**, **Parentheses**.
- Attribute options per sub-menu: IP, Port, MAC, Link Proto, Transport Proto, Application Proto, Both Protos, MIME Type.
- Parentheses options: **Append (**, **Append )**, **Wrap with (...)**.
- Filter-input context action: **Save current filter...** to store named filters in the persistent filter library.

#### Add to Keystore...

- Save highlighted text or context data to the Session or Persistent keychain.
- Entry types: Password, Private Key, Certificate, Session Cookie, Manual URI/URL.

#### Send to Notes...

- Send selected/context data, List row visible data, Conv output, or Conv hashes to a new session note.

#### Export...

- **Packet** / **Payload**: export packet or payload data.
- **Conv input** / **Conv Raw** / **Conv output** (hex, binary, decimal, integer, ASCII, base64).
- **Conv hashes** and **Conv decode output** exports.
- **Cookie Jar**: save extracted cookies to disk.

#### HTTP Body...

Shown when the current packet contains an HTTP response body:

- **Body to Conv tab**: load body bytes as hex into Conv.
- **Body to Conv tab (decompressed)**: decompress body first, then load into Conv.
- **Browser preview**: open the HTTP body in the system browser.
- **Browser preview (decompressed)**: decompress first, then preview in browser.
- HTTP body reassembly uses same-direction stream packets, trimmed by Content-Length or chunked framing.

#### File Carving...

Shown when a carve target is available:

- **HTTP body to file**: save extracted HTTP response body to a file (Content-Type infers extension).
- **HTTP body to file (decompressed)**: decompress first, then save.
- **SMB file to disk**: detect and pick a file from the current SMB stream, then save as binary.
- **NFS file to disk**: detect and pick a file from the current NFS stream, then save as binary.
- **FTP file to disk**: carve FTP data-channel bytes (direct streams or inferred from PORT/EPRT/PASV/EPSV + RETR/STOR/APPE/LIST/NLST control-channel hints), then save as binary.

#### LLM Actions

- **Explain this Packet...** submenu: groups packet-focused LLM actions in the context menu.
- **Explain this Packet > Ask PS a question...**: opens a context dialog, sends packet context plus optional selected text and user question to the LLM, then writes answer to Notes.
- **Explain this Packet > Explain this data...**: sends selected/context data plus packet context to the LLM for a concise analyst-focused explanation and writes result to Notes.
- **Explain this Packet > Summarize this packet...**: sends the full current packet JSON to the LLM and writes a concise analyst-focused summary to Notes.
- LLM actions are only shown when LLM is enabled in Settings.

---

### LLM-Powered Analysis (Ollama)

- Optional Ollama integration for AI-powered capture analysis.
- LLM calls are initiated from the frontend/main-process bridge (`window.llmapi -> ipcMain('ollama:generate')`), not from the Python backend parser.
- **Use LLM** toggle in the load dialog mirrors the persisted `llm.activeByDefault` runtime preference.
- Generated report is displayed in the **Summary** tab and extended by stream-context follow-up summaries while navigating.
- LLM defaults are configured in the **Settings → LLM** sub-tab and persisted in app settings.
- LLM diagnostics are surfaced in Settings: install status, local daemon reachability, cloud API reachability, and last call result code.
- LLM context-menu actions are gated by the same runtime LLM setting and are hidden when LLM is disabled.
- Stream-context summary generation: while navigating packets, the frontend summarizes the active conversation stream after a short idle delay and appends new findings to the Summary pane.
- Summary deduping/persistence: already-summarized stream keys are tracked to reduce repeat calls, and `currentSummary` is saved/restored with session files.

---

### Backend HTTP Service / Bridge

- The Electron bridge can initialize the Python backend in long-lived HTTP service mode instead of spawning a fresh parser process per run.
- Service health check endpoint: `GET /ping`.
- Service version endpoint: `GET /version`.
- Capture-processing endpoint: `POST /process`.
- Control endpoint: `POST /control` for stop/shutdown requests and runtime updates (`set-runtime-config`).
- When the backend advertises NDJSON (`application/x-ndjson`), the bridge forwards incremental progress and capture snapshots to the renderer as they arrive.
- If HTTP service mode is unavailable, the bridge automatically falls back to legacy per-run spawn mode unless disabled by settings.
- Backend host/port and force-legacy behavior are configurable in **Settings → Backend**.

---

### GeoIP Enrichment

- MaxMind GeoLite2 City database bundled with the backend.
- Country, city, postal code, and timezone resolved for all routable (non-private) IP addresses.
- GeoIP data displayed in the Packet Info right sidebar Location panel.
- Filterable via `loc.src.*` and `loc.dst.*` keys.
- Physical Locations section in Stats tab with occurrence-sorted city/country pairs.

---

### Active Reconnaissance (Optional)

Requires the `-a` flag when running the backend:

- Fetches server banners from destination hosts.
- Retrieves SSL/TLS certificate details.
- Fetches web page titles via HTTP.
- Performs reverse DNS lookups; results stored in `dns.hostnames`.
- All active recon data is filterable and displayed in the Active Recon sub-section of the Packet Info pane.

---

### Backend CLI

```bash
python3 snitch.py traffic.pcap -o output_dir [-s SRC_PORT] [-d DST_PORT] [-T TIMEOUT] [-a] [-c conf.yaml] [-v]
```

| Argument | Description |
|---|---|
| `traffic.pcap` | Input `.pcap` or `.pcapng` file. |
| `-o / --output` | Output directory for testcase files (default: `testcases`). |
| `-s / --source-port` | Filter: only process packets from this source port. |
| `-d / --dest-port` | Filter: only process packets to this destination port. |
| `-T / --timeout` | Timeout for active recon network requests (default: 3 s). |
| `-a / --active-recon` | Enable active reconnaissance (banners, SSL, titles, reverse DNS). |
| `-c / --conf` | Path to YAML config file (default: `conf.yaml`). |
| `-v / --verbose` | Increase verbosity (repeatable for more detail). |

---

### Backend Output

- Raw payload binary testcases: `output_dir/<dst_port>/pcap.data_packet.<index>.dat`
- Per-packet JSON metadata: `output_dir/<dst_port>/pcap.info_packet.<index>.json`
- Consolidated output: `hosts.json` (all packets/hosts in one file)
- Progressive NDJSON snapshots (`hosts-<N>.json`) emitted every 500 packets for streaming to the frontend.

---

### Payload Analysis

- MIME type detection via `python-magic` (magic byte inspection).
- Shannon entropy calculation using NumPy/SciPy.
- Character set detection via `chardet`.
- Distinct byte value count (`payload.chars.used`).
- Automatic decompression of gzip/zlib compressed payloads; decompressed hex and ASCII stored separately.
- Data-type guesser with confidence scoring (JWT, bcrypt, base64, etc.) in the Conv tab.

---

### Link-Layer & Non-IP Protocol Support

- ARP/RARP decoding: operation type, source/destination IP and MAC, filterable via `arp.*` and `rarp.*` keys.
- IGMP decoding: type, version, group, checksum, max-response time; filterable via `decoded-proto`.
- WAN/link-control protocols: ATM, Token Ring, Frame Relay, SDLC, HDLC, SLIP, PPP, LCP, LAP, NCP; stored as `Protocol: LINK` with `wan.proto.*` keys.
- Non-IP link packets are processed rather than dropped; the backend exits only when the capture has zero packets.
- `decoded-proto` alias aggregates all transport, decoded, and link-control protocol names for unified filtering.

---

### TCP Stream Analysis

- Retransmission detection and classification per packet (in-order, out-of-order, retransmission, retransmission out-of-order).
- Sequence and acknowledgment number tracking (`tcp.seq`, `tcp.ack`, `tcp.payload.len`).
- Bidirectional stream grouping by canonical 5-tuple in the List tab.
- Follow-stream: async chunked assembly of full TCP streams into the Conv tab with renderer yields and loading overlay.
- `tcp.stream.retransmission` and `tcp.stream.badorder` filter keys.

---

### Session Keystore Export

- Export session or persistent keychain entries to CSV, JSON, or XML.
- Accessible via the context menu on the Keystore tab (Export submenu).
- Save dialog per format via dedicated IPC handler.

---

### Packaging & Distribution

- Built with Electron Forge and Webpack.
- Distributed as RPM (Fedora/RHEL/CentOS), DEB (Debian/Kali/Ubuntu), and Windows installer (NSIS `.exe`).
- Python backend bundled as a standalone PyInstaller binary (`snitch`); no Python installation required on end-user systems.
- `npm run patch-rpm-build` helper for Fedora-specific RPM spec patching.
