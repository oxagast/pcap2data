<style>

    </style>

<p align="center">
<a href="https://oxasploits.github.io/PacketSnitch/"><img width="360" height="60" alt="PacketSnitch by oxasploits" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/logo/ps-tagline-flicker.gif"></a>
</p>

## Backend Documentation

### Overview

PacketSnitch is a Python tool for extracting payloads and rich metadata from network packet capture (`.pcap`) files. It generates testcases for fuzzing, protocol analysis, and research by saving raw packet data and detailed information about each packet, including protocol, entropy, geoip, banners, and more. The tool optionally performs active reconnaissance to enrich output with server banners, SSL certificate info, and web page titles.

### Features

- Extracts TCP, UDP, and ICMP payloads from `.pcap` files and saves them as binary testcase files.
- Generates JSON info files for each testcase, containing:
  - Packet metadata (timestamps, MAC/IP addresses, ports, flags, checksums)
  - MIME type and magic description
  - Shannon entropy and character statistics
  - GeoIP lookup for source/destination IPs
  - Port descriptions (ICANN database)
  - MAC vendor lookup
  - Protocol-specific fields for DNS, HTTP, SNMP, DHCP, NTP, SIP, and ICMP
  - Active recon: server banners, SSL certificate info, web page titles (optional)
- Consolidates all testcase info into `hosts.json`.
- Supports filtering by source/destination port.
- Handles compressed payloads (gzip/zlib).
- LLM-powered summaries via Ollama integration.
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
  - ollama
- Databases:
  - GeoIP database (MaxMind `.mmdb`)
  - MAC vendor CSV
  - ICANN port description CSV

### Usage

```bash
python3 snitch.py traffic.pcap -o output_dir [-s SRC_PORT] [-d DST_PORT] [-T TIMEOUT] [-a] [-c conf.yaml] [-v]
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
| `-v, --verbose`      | Increase verbosity (repeat for more detail)           |

#### Example

```bash
python3 snitch.py traffic.pcap -o output_dir -T 5 -a -v
```

### Output Structure

- `output_dir/<dest_port>/pcap.data_packet.<index>.dat`: Raw payloads
- `output_dir/<dest_port>/pcap.info_packet.<index>.json`: Metadata for each testcase
- `hosts.json`: Consolidated info for all testcases

### Searchable Attributes

Each testcase JSON contains the following dot-notation keys as leaf nodes, which can be used to search, filter, or query testcase data in the frontend or via `hosts.json`. The filter syntax uses `key:value` notation with optional comparison operators (`==`, `!=`, `>`, `>=`, `<`, `<=`) and boolean combinators (`&&`, `||`) with parentheses for grouping.

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

### Notes

- Active recon (`-a`) may take longer and requires network access.
- Ensure database files are present and paths are correct in `conf.yaml`.
- The tool will prompt before overwriting output directories.
- LLM summaries require a running Ollama server (`minimax-m2.5:cloud` model by default).

### License

GPL v3

### Author

Marshall Whittaker
