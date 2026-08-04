# Backend

## Backend Documentation

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [Output Structure](#output-structure)
- [HTTP Service Mode](#http-service-mode)
- [Crypt tab / 802.11 (Wi-Fi) decryption](#crypt-tab--80211-wi-fi-decryption)
- [Searchable Attributes](#searchable-attributes)
- [Notes](#notes)
- [License](#license)
- [Author](#author)

### Overview

PacketSnitch is a Python tool for extracting payloads and rich metadata from network packet capture (`.pcap`) files. It generates testcases for fuzzing, protocol analysis, and research by saving raw packet data and detailed information about each packet, including protocol, entropy, geoip, banners, and more. The tool optionally performs active reconnaissance to enrich output with server banners, SSL certificate info, and web page titles.

In the desktop app, this parser is wrapped by an Electron bridge that can either spawn the backend per capture run or launch `snitch.py` in HTTP service mode and stream incremental results to the renderer.

### Features

- Extracts TCP, UDP, and ICMP payloads from `.pcap` files and saves them as binary testcase files.
- Generates JSON info files for each testcase, containing:
  - Packet metadata (timestamps, MAC/IP addresses, ports, flags, checksums)
  - MIME type and magic description
  - Shannon entropy and character statistics
  - GeoIP lookup for source/destination IPs
  - Port descriptions (ICANN database)
  - MAC vendor lookup
  - Protocol-specific fields for link/WAN (ARP/RARP/PPP families, IEEE 802.11 / Wi-Fi), network (ICMP/IGMP), transport (TCP/UDP/SCTP), and application protocols including DNS, HTTP/HTTP2, SNMP, DHCP, NTP, SIP, FTP, SMTP, POP3, IMAP, Telnet, IRC, SMB, MQTT, RTSP, TFTP, BGP, XMPP, LDAP, MySQL, PostgreSQL, NNTP, MTP/MMS, RADIUS, WebSocket, NFS, Kerberos, SSH, SMPP, Soulseek, and BitTorrent
  - Active recon: server banners, SSL certificate info, web page titles (optional)
  - **IEEE 802.11 (Wi-Fi) link-layer metadata and decryption** — the `wireless_80211.py` decoder surfaces SSID, BSSID, frame type/subtype, channel, cipher, RSN/IE info, and RadioTap signal/noise/rate on every 802.11 frame, and decrypts WEP / WPA-PSK (AES-CCMP) / pre-computed PMK payloads when the renderer supplies matching keys via the `--wifi-keys-file` flag. See the [Crypt tab / 802.11 (Wi-Fi) decryption](#crypt-tab--80211-wi-fi-decryption) section below for the full contract.
- Consolidates all testcase info into `hosts.json`.
- Supports incremental chunk snapshots (`hosts-<N>.json`) for progressive frontend loading.
- Supports an HTTP service mode used by the Electron bridge for status/stats, `ping`, `version`, `process`, and control requests.
- Supports filtering by source/destination port.
- Handles compressed payloads (gzip/zlib).
- Verbose/debug output modes.

### Requirements

- Python 3.7+
- Dependencies:
  - scapy
  - numpy
  - requests
  - pyyaml
  - python-magic
  - chardet
  - geoip2
  - beautifulsoup4
  - scipy
- Databases:
  - GeoIP database (MaxMind `.mmdb`)
  - MAC vendor CSV
  - ICANN port description CSV

### Usage

```bash
python3 snitch.py traffic.pcap -o output_dir [-s SRC_PORT] [-d DST_PORT] [-T TIMEOUT] [-a] [-c conf.yaml] [--host-chunk-size N] [--worker-threads N] [--server --server-host HOST --server-port PORT] [-v]
```

```bash
python3 snitch.py --version
```

#### Arguments

| Argument             | Description                                           |
| -------------------- | ----------------------------------------------------- |
| `traffic.pcap`       | Path to the `.pcap` file to parse.                    |
| `-o, --output`       | Output directory for testcases (default: `testcases`) |
| `-s, --source-port`  | Only generate testcases from this source port.        |
| `-d, --dest-port`    | Only generate testcases for this destination port.    |
| `-T, --timeout`      | Timeout for network requests (default: 3 seconds)     |
| `-a, --active-recon` | Perform active recon (banners, SSL, titles)           |
| `-c, --conf`         | Path to YAML config file (default: `conf.yaml`)       |
| `--version`          | Print backend version and exit                         |
| `--use-tor-check`    | Enable Tor exit-node enrichment (default: on)          |
| `--no-tor-check`     | Disable Tor exit-node enrichment                       |
| `--host-chunk-size`  | Packet count per incremental host snapshot             |
| `--worker-threads`   | Backend parser worker thread count                     |
| `--server`           | Run in HTTP service mode                               |
| `--server-host`      | Bind host for HTTP service mode (default: `127.0.0.1`) |
| `--server-port`      | Bind port for HTTP service mode (default: `9020`)      |
| `--wifi-keys-file`   | Path to a JSON file containing 802.11 decryption keys passed in by the renderer (Crypt → Wireless sub-tab). Format: `[{"ssid": "...", "bssid": "...", "psk": "passphrase", "pmkHex": "32-byte-hex", "wepKeyHex": "5/13/16-byte-hex"}, ...]`. See [Crypt tab / 802.11 (Wi-Fi) decryption](#crypt-tab--80211-wi-fi-decryption) below for the contract. |
| `-v, --verbose`      | Increase verbosity (repeat for more detail)           |

#### Example

```bash
python3 snitch.py traffic.pcap -o output_dir -T 5 -a -v
```

### Output Structure

- `output_dir/<dest_port>/pcap.data_packet.<index>.dat`: Raw payloads
- `output_dir/<dest_port>/pcap.info_packet.<index>.json`: Metadata for each testcase
- `hosts.json`: Consolidated info for all testcases
- `hosts-<N>.json`: Progressive chunk snapshots emitted during long capture processing for the desktop bridge/UI

### HTTP Service Mode

When the Electron bridge has access to the Python backend, it can request long-lived HTTP service mode instead of spawning a fresh process for each capture.

Current bridge-facing endpoints:

- `GET /` and `GET /status`: backend runtime status/statistics payload (uptime, runtime config, active job metadata)
- `GET /ping`: readiness probe used before capture work is submitted
- `GET /version`: reports backend service/app version metadata
- `POST /process`: parse a PCAP and emit either accumulated JSON or NDJSON progress events
- `POST /control`: control actions such as stop-processing, shutdown, and runtime config updates (`set-runtime-config`/`set-config`/`configure`)

Lookup/enrichment endpoints used by frontend tooling (including Conv Analyze Subnet):

- `GET /geoip?ip=<addr>&side=src|dst`: GeoIP lookup
- `GET /whois?ip=<addr>`: WHOIS lookup
- `GET /ipsum?ip=<addr>`: IP reputation lookup
- `GET /tor?ip=<addr>`: Tor exit-node presence lookup
- `GET /shodan?ip=<addr>`: Shodan InternetDB lookup

Important behavior:

- Progress events may include filesystem snapshot paths or full in-memory capture payloads.
- NDJSON mode is used for incremental progress streaming.
- If service mode is unavailable, the Electron bridge falls back to legacy spawn mode.

### Crypt tab / 802.11 (Wi-Fi) decryption

The backend ships an end-to-end 802.11 frame decoder and decryptor in [src/backend/decoders/wireless_80211.py](../src/backend/decoders/wireless_80211.py) (with the WPA2 4-way PTK derivation in [src/backend/decoders/wpa2_ptk.py](../src/backend/decoders/wpa2_ptk.py)). The frontend surfaces it as the **Crypt → Wireless** sub-tab; the backend contract is documented here so both halves of the round-trip stay in sync.

#### Decoder responsibilities

- **Frame recognition**: auto-detects Dot11 / RadioTap frames, walks management (Beacon, Probe Req/Resp, Auth, Assoc Req/Resp, Reassoc, Disassoc, Deauth, Action), control (RTS, CTS, ACK, Block Ack, PS-Poll, CF-End), and data sub-types. A4 / QoS / ToDS / FromDS layout is resolved to recover BSSID, source MAC (SA), destination MAC (DA), and station MAC.
- **Metadata**: every 802.11 frame populates the `link.proto = "IEEE 802.11"` field plus a `Wireless` sub-section (see the [802.11 fields table](#ieee-80211-wi-fi-fields) below).
- **Decryption candidates**: the decoder recognises `Dot11CCMP`, `Dot11TKIP`, `Dot11WEP`, and the generic `Dot11Encrypted` layers and tries each path in turn with the active Wi-Fi key set.

#### Key delivery (`--wifi-keys-file`)

Keys are pushed in by the renderer's `setBackendWifiKeys` IPC, which stages them on disk in `testcaseOutputDir/wifi-keys-<jobId>.json` (a sibling of the per-job `jobOutputDir` so the spawn-path `fs.rmSync(jobOutputDir)` cleanup cannot drop the file mid-run). The file is removed in the bridge's `backendProc.on('close', ...)` handler. The CLI / spawn argv is:

```
python3 snitch.py traffic.pcap -o output_dir --wifi-keys-file <path>
```

The file is a JSON array; each element is one candidate key. At least one of `psk`, `pmkHex`, or `wepKeyHex` must be set; `ssid` and `bssid` are optional filters and can be omitted for "try this key against every frame":

```json
[
  {
    "ssid": "Coherer",
    "bssid": "00:0c:41:82:b2:55",
    "psk": "Induction"
  },
  {
    "bssid": "c0:4a:00:80:76:e4",
    "wepKeyHex": "A48153B4CF"
  },
  {
    "ssid": "Lab-5G",
    "bssid": "aa:bb:cc:dd:ee:ff",
    "pmkHex": "a288fcf0caaacda9a9f58633ff35e8992a01d9c10ba5e02efdf8cb5d730ce7bc"
  }
]
```

| Field        | Type   | Description                                                                                                  |
| ------------ | ------ | ------------------------------------------------------------------------------------------------------------ |
| `ssid`       | string | Optional. Restricts the key to frames whose SSID matches (case-insensitive).                                |
| `bssid`      | string | Optional. Restricts the key to frames whose BSSID matches (colon-formatted or unspaced 12 hex).             |
| `psk`        | string | WPA / WPA2 / WPA3 passphrase. Combined with `ssid` via PBKDF2-HMAC-SHA1 (4096 iterations) to derive the PMK. |
| `pmkHex`     | string | Pre-computed Pairwise Master Key as 32-byte (64 hex char) hex. Skips the PBKDF2 step.                        |
| `wepKeyHex`  | string | Hex WEP key, 10 / 26 / 32 chars (5 / 13 / 16 bytes = WEP-40 / WEP-104 / WEP-128).                            |

#### WPA2 / AES-CCMP decryption

- The backend scans every EAPOL-Key frame once via `populateWifiHandshakeCache` and buckets the captured (ANonce, SNonce) pairs by `(BSSID, client MAC)`. ToDS / FromDS / WDS addressing is resolved per IEEE 802.11 §9.3.2.1.
- The cache is then queried with the data frame's `(BSSID, client MAC)` tuple. When both nonces are present and a `psk` / `pmkHex` entry exists for the BSSID, `populatePtkForBssid` derives the 64-byte PTK per IEEE 802.11i §8.5.1.1 (PRF-384 over the six-field canonical input `Min(AA,SA) || Max(AA,SA) || Min(ANonce,SNonce) || Max(ANonce,SNonce) || BSSID || ANonce`) and stores the TK portion.
- The CCMP frame is then decrypted using the same per-block AES-CCM primitive that airdecap-ng uses (manual RFC 3610 implementation so the output is byte-compatible with Wireshark). AAD layout, PN endianness, and CTR counter construction all match the airdecap-ng / libnl80211 reference.
- When a frame decrypts successfully, the inner LLC/SNAP+IP packet is spliced back into the regular packet loop and re-decoded as if it had been a normal Ethernet/IP frame. The host loop's `link.proto` for that packet becomes `"IEEE 802.11"`, the source/destination MAC addresses are added to `link.src.mac.addr` / `link.dst.mac.addr`, the wireless metadata is included under `Wireless`, and `wifi.decrypt.ok = true` plus `wifi.decrypt.algorithm = "CCMP"` are set. Link-layer protocol names (`WIFI`, `IEEE 802.11`, …) are never prepended to `packet.decoded_protocols` so the renderer's **App Protocol** column always reports the real application-layer protocol of the decrypted payload.

#### WEP decryption

- `_wepDecrypt(weKey, wepBody)` takes the raw WEP body (3-byte IV + 1-byte KeyID + ciphertext + 4-byte ICV) and RC4-decrypts it. The decryptor pulls `ARC4` from `cryptography.hazmat.decrepit.ciphers.algorithms` (with a fallback to the legacy `cryptography.hazmat.primitives.ciphers.algorithms` path so the code keeps working on `cryptography < 43`).
- The WEP ICV (CRC-32 of the plaintext, little-endian) is verified leniently — real WEP pcaps in the wild often have a corrupt or zeroed ICV, so the ICV is reported (`icv_ok`) but not used to gate the verdict. The "ok" verdict instead comes from `_wepPlaintextLooksValid`, which requires the plaintext to look like an 802.2 LLC / SNAP header (`DSAP=0xAA SSAP=0xAA Control=0x03`, I/G and C/R bits stripped) plus an IANA-assigned EtherType, or a raw Ethernet-II header with a known EtherType. A wrong key therefore never produces a false positive.
- When scapy's `Dot11WEP` layer is not present but the FC protected bit is set, the WEP body is sliced out of the raw frame using the 802.11 MAC header length (24 bytes for non-QoS, 26 for QoS, 30 for 4-address ToDS+FromDS frames).

#### Decryption status attributes

Every 802.11 frame that was a decryption candidate (CCMP / TKIP / WEP / generic `Dot11Encrypted`) carries the following attributes in `packet.info` so the renderer can render a per-frame decrypt status pill:

| Attribute               | Type    | Description                                                                                       |
| ----------------------- | ------- | ------------------------------------------------------------------------------------------------- |
| `wifi.decrypt.ok`       | boolean | `true` when the decryptor produced a valid plaintext for this frame.                              |
| `wifi.decrypt.algorithm`| string  | `CCMP`, `TKIP`, or `WEP` for the path that succeeded; `"None"` for a frame that could not be decrypted with the supplied keys. |
| `wifi.decrypt.error`    | string  | Optional. Error message for the failed decrypt path (e.g. `"MIC mismatch"`, `"key length invalid"`). |

#### End-to-end decrypt result shape

`decryptWifiPayload` returns the same dict shape for every algorithm so the renderer's `crypt-wifi-decrypt-preview` / **Send to Conv** path can be algorithm-agnostic:

```json
{
  "ok": true,
  "plaintextHex": "aaaa03000000080045000054...",
  "algorithm": "CCMP",
  "ssid": "Coherer",
  "bssid": "00:0c:41:82:b2:55"
}
```

#### Sample captures

The repo ships two ready-to-use Wi-Fi captures for end-to-end smoke testing:

| File                                              | BSSID                  | Algorithm | Key                                                                                  |
| ------------------------------------------------- | ---------------------- | --------- | ------------------------------------------------------------------------------------ |
| `samples/pcaps/wifi-Coherer-Induction.pcap`       | `00:0c:41:82:b2:55`    | CCMP      | SSID `Coherer`, PSK `Induction` (PMK `a288fcf0caaacda9a9f58633ff35e8992a01d9c10ba5e02efdf8cb5d730ce7bc`) |
| `samples/pcaps/wep-A4-81-53-B4-CF.pcap`           | `c0:4a:00:80:76:e4`    | WEP       | WEP-40 key `A4:81:53:B4:CF`                                                          |

### Searchable Attributes

Each testcase JSON contains the following dot-notation keys as leaf nodes, which can be used to search, filter, or query testcase data in the frontend or via `hosts.json`. The <a href="/docu/filters">filter syntax</a> uses `key:value` notation with optional comparison operators (`==`, `!=`, `>`, `>=`, `<`, `<=`) and boolean combinators (`&&`, `||`) with parentheses for grouping.

#### Core Packet Fields

| Attribute          | Type   | Description                                                     |
| ------------------ | ------ | --------------------------------------------------------------- |
| `packet.timestamp` | string | Timestamp of the captured packet (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| `packet.hex`       | string | Full raw packet bytes as a hex string                           |
| `packet.proto`     | string | Transport protocol key (e.g. `tcp`, `udp`, `icmp`)              |

#### Ethernet Fields

| Attribute              | Type   | Description                                 |
| ---------------------- | ------ | ------------------------------------------- |
| `ether.src.mac.addr`   | string | Source MAC address                          |
| `ether.dst.mac.addr`   | string | Destination MAC address                     |
| `ether.src.mac.vendor` | string | Vendor name for the source MAC address      |
| `ether.dst.mac.vendor` | string | Vendor name for the destination MAC address |

> **Note:** Ethernet frame attributes (`ether.*`) are only populated when both source and destination IPs resolve to the local network.

#### IP Fields

| Attribute      | Type    | Description                                                     |
| -------------- | ------- | --------------------------------------------------------------- |
| `ip.src.addr`  | string  | Source IP address                                               |
| `ip.dst.addr`  | string  | Destination IP address                                          |
| `ip.chksum`    | string  | IP header checksum (hex)                                        |
| `ip.len`       | integer | IP layer length in bytes                                        |
| `ip.src.class` | string  | Network class of the source IP (e.g. `Localnet`, `A`, `B`, `C`) |
| `ip.dst.class` | string  | Network class of the destination IP                             |

#### TCP Fields

| Attribute      | Type    | Description                                     |
| -------------- | ------- | ----------------------------------------------- |
| `tcp.src.port` | integer | TCP source port number                          |
| `tcp.dst.port` | integer | TCP destination port number                     |
| `tcp.chksum`   | string  | TCP checksum (hex)                              |
| `tcp.urgptr`   | boolean | Whether the TCP urgent pointer is set           |
| `tcp.flags`    | string  | Active TCP flags (e.g. `SYN\|ACK`)              |
| `tcp.options`  | list    | TCP options list                                |
| `tcp.len`      | integer | TCP header length in bytes                      |
| `tcp.proto`    | string  | Service/protocol name for the destination port  |
| `tcp.desc`     | string  | ICANN port description for the destination port |

#### UDP Fields

| Attribute      | Type    | Description                  |
| -------------- | ------- | ---------------------------- |
| `udp.src.port` | integer | UDP source port number       |
| `udp.dst.port` | integer | UDP destination port number  |
| `udp.chksum`   | string  | UDP checksum (hex)           |
| `udp.len`      | integer | UDP datagram length in bytes |

#### ICMP Fields

| Attribute     | Type    | Description                                                               |
| ------------- | ------- | ------------------------------------------------------------------------- |
| `icmp.type`   | string  | ICMP message type string (e.g. `Echo Request`, `Destination Unreachable`) |
| `icmp.code`   | integer | ICMP code value                                                           |
| `icmp.id`     | integer | ICMP identifier field                                                     |
| `icmp.seq`    | integer | ICMP sequence number                                                      |
| `icmp.chksum` | string  | ICMP checksum (hex)                                                       |

#### Wire / Payload Fields

| Attribute                    | Type    | Description                                                                    |
| ---------------------------- | ------- | ------------------------------------------------------------------------------ |
| `wire.len`                   | integer | Total wire length of the segment in bytes                                      |
| `payload.hex`                | string  | Raw payload as a hex string                                                    |
| `payload.ascii`              | string  | Raw payload decoded as ASCII (lossy)                                           |
| `payload.len`                | integer | Length of the payload in bytes                                                 |
| `payload.mime`               | string  | MIME type of the payload (e.g. `text/html`, `application/octet-stream`)        |
| `payload.entropy`            | float   | Shannon entropy of the payload (bits per byte)                                 |
| `payload.charset`            | string  | `ascii` if all bytes are printable ASCII, otherwise `binary`                   |
| `payload.encoding`           | string  | Detected character encoding (e.g. `utf-8`, `iso-8859-1`)                       |
| `payload.chars.used`         | integer | Number of distinct byte values present in the payload                          |
| `payload.decompressed.hex`   | string  | Decompressed payload as a hex string (only present if payload was compressed)  |
| `payload.decompressed.ascii` | string  | Decompressed payload decoded as ASCII (only present if payload was compressed) |

#### GeoIP / Location Fields

| Attribute          | Type   | Description                                                    |
| ------------------ | ------ | -------------------------------------------------------------- |
| `loc.src.country`  | string | Country of the source IP (GeoIP lookup)                        |
| `loc.src.city`     | string | City of the source IP (GeoIP lookup)                           |
| `loc.src.postal`   | string | Postal code of the source IP (GeoIP lookup)                    |
| `loc.src.tz`       | string | Time zone of the source IP — alias for `loc.src.timezone`      |
| `loc.src.timezone` | string | Time zone of the source IP (GeoIP lookup)                      |
| `loc.dst.country`  | string | Country of the destination IP (GeoIP lookup)                   |
| `loc.dst.city`     | string | City of the destination IP (GeoIP lookup)                      |
| `loc.dst.postal`   | string | Postal code of the destination IP (GeoIP lookup)               |
| `loc.dst.tz`       | string | Time zone of the destination IP — alias for `loc.dst.timezone` |
| `loc.dst.timezone` | string | Time zone of the destination IP (GeoIP lookup)                 |

> **Note:** GeoIP attributes (`loc.*`) are only populated for non-private/routable IP addresses.

#### Active Recon Fields

| Attribute     | Type   | Description                                              |
| ------------- | ------ | -------------------------------------------------------- |
| `host.banner` | string | Server banner retrieved via active recon (requires `-a`) |

> **Note:** `host.banner` is only populated when the `-a` (active recon) flag is used.

#### DNS Fields (UDP/TCP port 53)

| Attribute       | Type    | Description                                      |
| --------------- | ------- | ------------------------------------------------ |
| `dns.id`        | integer | DNS transaction ID                               |
| `dns.qr`        | boolean | `true` if this is a response, `false` if a query |
| `dns.qname`     | string  | First queried domain name                        |
| `dns.qnames`    | list    | All queried domain names                         |
| `dns.aname`     | string  | First answer name from DNS response              |
| `dns.anames`    | list    | All answer names from DNS response               |
| `dns.aip`       | string  | First resolved IP address from DNS response      |
| `dns.aips`      | list    | All resolved IP addresses from DNS response      |
| `dns.qdcount`   | integer | Number of questions in the DNS message           |
| `dns.ancount`   | integer | Number of answer records in the DNS message      |
| `dns.hostnames` | object  | Resolved hostnames from reverse DNS lookup       |

#### HTTP Fields (TCP port 80/443/8080/8443)

| Attribute                | Type   | Description                                              |
| ------------------------ | ------ | -------------------------------------------------------- |
| `http.type`              | string | Message type: `Request` or `Response`                    |
| `http.method`            | string | HTTP request method (e.g. `GET`, `POST`) — requests only |
| `http.url`               | string | Request URL path — requests only                         |
| `http.version`           | string | HTTP version (e.g. `HTTP/1.1`)                           |
| `http.host`              | string | `Host` header value — requests only                      |
| `http.user_agent`        | string | `User-Agent` header value — requests only                |
| `http.content_type`      | string | `Content-Type` header value                              |
| `http.content_length`    | string | `Content-Length` header value                            |
| `http.referer`           | string | `Referer` header value — requests only                   |
| `http.accept`            | string | `Accept` header value — requests only                    |
| `http.accept_encoding`   | string | `Accept-Encoding` header value — requests only           |
| `http.connection`        | string | `Connection` header value                                |
| `http.status_code`       | string | HTTP status code (e.g. `200`) — responses only           |
| `http.status_msg`        | string | HTTP status message (e.g. `OK`) — responses only         |
| `http.server`            | string | `Server` header value — responses only                   |
| `http.content_encoding`  | string | `Content-Encoding` header value — responses only         |
| `http.transfer_encoding` | string | `Transfer-Encoding` header value — responses only        |
| `http.location`          | string | `Location` redirect header — responses only              |

#### SNMP Fields (UDP/TCP port 161/162)

| Attribute        | Type   | Description                                              |
| ---------------- | ------ | -------------------------------------------------------- |
| `snmp.version`   | string | SNMP version string (e.g. `v1`, `v2c`, `v3`)             |
| `snmp.community` | string | SNMP community string                                    |
| `snmp.pdu_type`  | string | SNMP PDU type (e.g. `GetRequest`, `GetResponse`, `Trap`) |

#### DHCP Fields (UDP port 67/68)

| Attribute       | Type   | Description                                                    |
| --------------- | ------ | -------------------------------------------------------------- |
| `dhcp.msg_type` | string | DHCP message type (e.g. `DISCOVER`, `OFFER`, `REQUEST`, `ACK`) |
| `dhcp.xid`      | string | Transaction ID (hex)                                           |
| `dhcp.ciaddr`   | string | Client IP address                                              |
| `dhcp.yiaddr`   | string | Your (offered) IP address                                      |
| `dhcp.siaddr`   | string | Server IP address                                              |

#### NTP Fields (UDP port 123)

| Attribute     | Type    | Description                                                      |
| ------------- | ------- | ---------------------------------------------------------------- |
| `ntp.leap`    | string  | Leap indicator status (e.g. `no warning`, `last minute has 61s`) |
| `ntp.version` | integer | NTP version number                                               |
| `ntp.mode`    | string  | NTP mode string (e.g. `client`, `server`, `broadcast`)           |
| `ntp.stratum` | integer | Stratum level (0 = unspecified, 1 = primary, 2+ = secondary)     |
| `ntp.ref_id`  | string  | Reference ID (IP address or 4-character ASCII string)            |

#### SIP Fields (UDP/TCP port 5060/5061)

| Attribute         | Type   | Description                                                    |
| ----------------- | ------ | -------------------------------------------------------------- |
| `sip.type`        | string | Message type: `Request` or `Response`                          |
| `sip.method`      | string | SIP request method (e.g. `INVITE`, `REGISTER`) — requests only |
| `sip.uri`         | string | Request URI — requests only                                    |
| `sip.from`        | string | `From` header value                                            |
| `sip.to`          | string | `To` header value                                              |
| `sip.call_id`     | string | `Call-ID` header value                                         |
| `sip.status_code` | string | SIP status code (e.g. `200`) — responses only                  |
| `sip.status_msg`  | string | SIP status message (e.g. `OK`) — responses only                |

#### IEEE 802.11 (Wi-Fi) Fields

The following dot-notation keys are populated for every IEEE 802.11 frame detected in the capture. Decryption-related fields are only present on frames that were decryption candidates (CCMP / TKIP / WEP / generic `Dot11Encrypted`); see the [Crypt tab / 802.11 (Wi-Fi) decryption](#crypt-tab--80211-wi-fi-decryption) section above for the algorithm-specific contracts.

| Attribute                | Type    | Description                                                                                |
| ------------------------ | ------- | ------------------------------------------------------------------------------------------ |
| `link.proto`             | string  | Set to `"IEEE 802.11"` for every 802.11 frame (carries link-layer identity on the packet). |
| `link.src.mac.addr`      | string  | 802.11 source MAC (SA / TA)                                                               |
| `link.dst.mac.addr`      | string  | 802.11 destination MAC (DA / RA)                                                          |
| `link.src.mac.vendor`    | string  | OUI vendor lookup for the source MAC                                                       |
| `link.dst.mac.vendor`    | string  | OUI vendor lookup for the destination MAC                                                  |
| `wireless.wifi.ssid`     | string  | SSID recovered from Beacon / Probe Req / Probe Resp (`Hidden/N/A` when redacted)           |
| `wireless.wifi.bssid`    | string  | BSSID (AP MAC) for the frame                                                              |
| `wireless.wifi.type`     | string  | Dot11 type label: `Management` / `Control` / `Data` / `Extension`                          |
| `wireless.wifi.subtype`  | string  | Dot11 subtype label (e.g. `Beacon`, `QoS Data`, `Action`)                                 |
| `wireless.wifi.subtype_num` | integer | Numeric subtype nibble (0-15) of the frame                                              |
| `wireless.wifi.channel`  | string  | Operating channel as recovered from RadioTap / Dot11                                       |
| `wireless.wifi.frequency` | string | Operating frequency (`<N> MHz`)                                                            |
| `wireless.wifi.cipher`   | string  | Detected cipher: `Open`, `WEP`, `TKIP (RC4)`, `CCMP-128 (AES)`, etc.                      |
| `wireless.wifi.crypto`   | string  | Crypto suite label: `Open`, `WPA`, `WPA2`, `WPA3`                                          |
| `wireless.wifi.signal_dbm` | string | RadioTap signal strength (e.g. `-58 dBm`)                                                  |
| `wireless.wifi.noise_dbm` | string  | RadioTap noise floor (e.g. `-95 dBm`)                                                      |
| `wireless.wifi.rate_mbps` | string  | RadioTap data rate (e.g. `54.0 Mbps`)                                                      |
| `wireless.wifi.rsn`      | object  | Parsed RSN IE (version, group cipher, pairwise ciphers, AKM suites) when present            |
| `wireless.wifi.vendor_ies` | list   | Vendor IEs (WPA / Microsoft) when present in the frame                                     |
| `wifi.decrypt.ok`        | boolean | `true` when the decryptor produced a valid plaintext for this frame                        |
| `wifi.decrypt.algorithm` | string  | `CCMP`, `TKIP`, `WEP`, or `None`                                                          |
| `wifi.decrypt.error`     | string  | Optional error message for the failed decrypt path                                         |

### Notes

- Active recon (`-a`) may take longer and requires network access.
- Ensure database files are present and paths are correct in `conf.yaml`.
- The tool will prompt before overwriting output directories.
- LLM summaries are now handled by the Electron frontend/main-process bridge, not by the Python parser itself.

### License

GPL v3

### Author

Marshall Whittaker
