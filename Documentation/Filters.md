![PacketSnitch by oxasploits](https://raw.githubusercontent.com/oxasploits/PacketSnitch/main/Logo/packet-snitch-tag-transp-whitetext.png)

# Filter Reference

## Overview

PacketSnitch's filter bar lets you search and narrow down the packets displayed in the frontend. Filters are evaluated over the full loaded dataset (all hosts), not just the currently selected host. Results update immediately after pressing **Enter** in the filter bar, and the **Filtered Packets** counter in the left sidebar updates to reflect the number of matching packets.

---

## Syntax

### Basic equality

```
key:value
```

Matches packets where `key` equals `value`. String comparisons are **case-insensitive**.

```
ip.src.addr:192.168.1.1
tcp.dst.port:443
payload.mime:text/html
```

### Comparison operators

Prefix the value with a comparison operator to perform numeric or lexicographic comparisons.

```
key:==value    (explicit equality — same as key:value)
key:!=value    (not equal)
key:>value     (greater than)
key:>=value    (greater than or equal)
key:<value     (less than)
key:<=value    (less than or equal)
```

```
payload.entropy:>=7.0
ip.len:>100
tcp.dst.port:!=80
payload.len:<64
```

### Boolean combinators

Use `&&` (AND) and `||` (OR) to combine multiple conditions. AND has higher precedence than OR.

```
ip.src.addr:10.0.0.1 && tcp.dst.port:443
tcp.dst.port:80 || tcp.dst.port:443
```

### Grouping with parentheses

Use parentheses to override precedence and group sub-expressions.

```
(tcp.dst.port:80 || tcp.dst.port:443) && payload.entropy:>=6.0
(payload.mime:text/html || payload.mime:application/json) && ip.dst.addr:10.0.0.1
```

### Inversion with `!`

Use `!` to invert either a single expression or a grouped expression.

```
!tcp.dst.port:443
!(tcp.dst.port:80 || tcp.dst.port:443)
ip.src.addr:10.0.0.1 && !(mime.type:text/html || mime.type:application/json)
```

### Clearing the filter

Delete all text from the filter bar and press **Enter** to show all packets again.

---

## How Keys Work

Filter keys correspond directly to the dot-notation leaf-node names embedded in each packet's JSON. The filter engine normalizes keys to **lowercase** with **spaces replaced by hyphens**, so both the machine-readable dot-notation form (`wire.len`) and the normalized human-readable form (`wire-length`) are accepted interchangeably. This document uses the canonical dot-notation names throughout.

Additional shorthand aliases are also supported: `wire.proto`, `eth.src.vendor`, and `mime.type`. Text queries for `eth.src.vendor`, `mime.type`, and `dns.qname` are matched case-insensitively using substring matching.

Protocol-specific keys (e.g., `dns.*`, `http.*`) are only present in packets where that protocol was detected, so filtering on them automatically scopes results to the relevant protocol traffic.

---

## Filter Key Reference

### Core Packet Fields

| Filter Key         | Type    | Description                                                  |
| ------------------ | ------- | ------------------------------------------------------------ |
| `packet.timestamp` | string  | Capture timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`)             |
| `packet.proto`     | string  | Transport protocol (`tcp`, `udp`, `icmp`)                    |
| `packet.hex`       | string  | Full raw packet as a hex string                              |

### Ethernet Fields

> Only populated when both source and destination IPs are on the local network.

| Filter Key             | Type   | Description                                 |
| ---------------------- | ------ | ------------------------------------------- |
| `ether.src.mac.addr`   | string | Source MAC address                          |
| `ether.dst.mac.addr`   | string | Destination MAC address                     |
| `ether.src.mac.vendor` | string | Hardware vendor of the source MAC           |
| `ether.dst.mac.vendor` | string | Hardware vendor of the destination MAC      |

### IP Fields

| Filter Key     | Type    | Description                                                       |
| -------------- | ------- | ----------------------------------------------------------------- |
| `ip.src.addr`  | string  | Source IP address                                                 |
| `ip.dst.addr`  | string  | Destination IP address                                            |
| `ip.chksum`    | string  | IP header checksum (hex, e.g. `0xd1ae`)                           |
| `ip.len`       | integer | IP layer length in bytes                                          |
| `ip.src.class` | string  | Network class of the source IP (`Localnet`, `A`, `B`, `C`)        |
| `ip.dst.class` | string  | Network class of the destination IP (`Localnet`, `A`, `B`, `C`)  |

### TCP Fields

| Filter Key     | Type    | Description                                              |
| -------------- | ------- | -------------------------------------------------------- |
| `tcp.src.port` | integer | TCP source port                                          |
| `tcp.dst.port` | integer | TCP destination port                                     |
| `tcp.chksum`   | string  | TCP checksum (hex)                                       |
| `tcp.urgptr`   | boolean | Whether the urgent pointer is set (`true` / `false`)     |
| `tcp.flags`    | string  | Active TCP flags (e.g. `SYN`, `ACK\|PSH`, `SYN\|ACK`)   |
| `tcp.len`      | integer | TCP header length in bytes                               |
| `tcp.proto`    | string  | IANA service name for the destination port (e.g. `https`) |
| `tcp.desc`     | string  | ICANN port description for the destination port          |

### UDP Fields

| Filter Key     | Type    | Description                   |
| -------------- | ------- | ----------------------------- |
| `udp.src.port` | integer | UDP source port               |
| `udp.dst.port` | integer | UDP destination port          |
| `udp.chksum`   | string  | UDP checksum (hex)            |
| `udp.len`      | integer | UDP datagram length in bytes  |

### ICMP Fields

| Filter Key    | Type    | Description                                                        |
| ------------- | ------- | ------------------------------------------------------------------ |
| `icmp.type`   | string  | ICMP message type (e.g. `Echo Request`, `Destination Unreachable`) |
| `icmp.code`   | integer | ICMP code value                                                    |
| `icmp.id`     | integer | ICMP identifier field                                              |
| `icmp.seq`    | integer | ICMP sequence number                                               |
| `icmp.chksum` | string  | ICMP checksum (hex)                                                |

### Wire / Payload Fields

| Filter Key                   | Type    | Description                                                                    |
| ---------------------------- | ------- | ------------------------------------------------------------------------------ |
| `wire.len`                   | integer | Total wire length of the segment in bytes                                      |
| `payload.hex`                | string  | Raw payload as a hex string                                                    |
| `payload.ascii`              | string  | Raw payload decoded as ASCII                                                   |
| `payload.len`                | integer | Payload length in bytes                                                        |
| `payload.mime`               | string  | MIME type (e.g. `text/html`, `application/octet-stream`)                       |
| `payload.entropy`            | float   | Shannon entropy of the payload (bits per byte, 0.0 – 8.0)                     |
| `payload.charset`            | string  | `ascii` if all bytes are printable ASCII, otherwise `binary`                   |
| `payload.encoding`           | string  | Detected character encoding (e.g. `utf-8`, `iso-8859-1`)                      |
| `payload.chars.used`         | integer | Number of distinct byte values present in the payload                          |
| `payload.decompressed.hex`   | string  | Decompressed payload as a hex string (only present if payload was compressed)  |
| `payload.decompressed.ascii` | string  | Decompressed payload as ASCII (only present if payload was compressed)         |

### GeoIP / Location Fields

> Only populated for routable (non-private) IP addresses.

| Filter Key         | Type   | Description                                  |
| ------------------ | ------ | -------------------------------------------- |
| `loc.src.country`  | string | Country of the source IP                     |
| `loc.src.city`     | string | City of the source IP                        |
| `loc.src.postal`   | string | Postal code of the source IP                 |
| `loc.src.tz`       | string | Time zone of the source IP (short alias)     |
| `loc.src.timezone` | string | Time zone of the source IP (full name)       |
| `loc.dst.country`  | string | Country of the destination IP                |
| `loc.dst.city`     | string | City of the destination IP                   |
| `loc.dst.postal`   | string | Postal code of the destination IP            |
| `loc.dst.tz`       | string | Time zone of the destination IP (short alias) |
| `loc.dst.timezone` | string | Time zone of the destination IP (full name)  |

### Active Recon Fields

> Only populated when the backend was run with `-a` (active recon).

| Filter Key    | Type   | Description                          |
| ------------- | ------ | ------------------------------------ |
| `host.banner` | string | Server banner retrieved via active recon |

### DNS Fields

> Only present on packets captured on UDP/TCP port 53.

| Filter Key       | Type    | Description                                      |
| ---------------- | ------- | ------------------------------------------------ |
| `dns.id`         | integer | DNS transaction ID                               |
| `dns.qr`         | boolean | `true` = response, `false` = query               |
| `dns.qname`      | string  | First queried domain name                        |
| `dns.qnames`     | array   | All queried domain names in the message          |
| `dns.aname`      | string  | First answer name                                |
| `dns.anames`     | array   | All answer names in the message                  |
| `dns.aip`        | string  | First resolved IP address from the response      |
| `dns.aips`       | array   | All resolved IP addresses from the response      |
| `dns.qdcount`    | integer | Number of questions in the message               |
| `dns.ancount`    | integer | Number of answer records in the message          |
| `dns.hostnames`  | array   | Hostnames resolved via active recon (requires `-a`) |

### HTTP Fields

> Only present on packets captured on TCP port 80, 443, 8080, or 8443.

| Filter Key               | Type   | Description                                              |
| ------------------------ | ------ | -------------------------------------------------------- |
| `http.type`              | string | `Request` or `Response`                                  |
| `http.method`            | string | HTTP method (`GET`, `POST`, `PUT`, etc.) — requests only |
| `http.url`               | string | Request URL path — requests only                         |
| `http.version`           | string | HTTP version (e.g. `HTTP/1.1`)                           |
| `http.host`              | string | `Host` header — requests only                            |
| `http.user_agent`        | string | `User-Agent` header — requests only                      |
| `http.content_type`      | string | `Content-Type` header                                    |
| `http.content_length`    | string | `Content-Length` header                                  |
| `http.referer`           | string | `Referer` header — requests only                         |
| `http.accept`            | string | `Accept` header — requests only                          |
| `http.accept_encoding`   | string | `Accept-Encoding` header — requests only                 |
| `http.connection`        | string | `Connection` header                                      |
| `http.status_code`       | string | HTTP status code (e.g. `200`) — responses only           |
| `http.status_msg`        | string | HTTP status message (e.g. `OK`) — responses only         |
| `http.server`            | string | `Server` header — responses only                         |
| `http.content_encoding`  | string | `Content-Encoding` header — responses only               |
| `http.transfer_encoding` | string | `Transfer-Encoding` header — responses only              |
| `http.location`          | string | `Location` redirect header — responses only              |

### SNMP Fields

> Only present on packets captured on UDP/TCP port 161 or 162.

| Filter Key       | Type   | Description                                               |
| ---------------- | ------ | --------------------------------------------------------- |
| `snmp.version`   | string | SNMP version (`v1`, `v2c`, `v3`)                          |
| `snmp.community` | string | SNMP community string                                     |
| `snmp.pdu_type`  | string | PDU type (`GetRequest`, `GetResponse`, `Trap`, etc.)      |

### DHCP Fields

> Only present on packets captured on UDP port 67 or 68.

| Filter Key      | Type   | Description                                                    |
| --------------- | ------ | -------------------------------------------------------------- |
| `dhcp.msg_type` | string | DHCP message type (`Discover`, `Offer`, `Request`, `Decline`, `ACK`, `NAK`, `Release`, `Inform`) |
| `dhcp.xid`      | string | Transaction ID (hex)                                           |
| `dhcp.ciaddr`   | string | Client IP address                                              |
| `dhcp.yiaddr`   | string | Offered IP address                                             |
| `dhcp.siaddr`   | string | Server IP address                                              |

### NTP Fields

> Only present on packets captured on UDP port 123.

| Filter Key    | Type    | Description                                                        |
| ------------- | ------- | ------------------------------------------------------------------ |
| `ntp.leap`    | string  | Leap indicator (`no warning`, `last minute has 61s`, etc.)         |
| `ntp.version` | integer | NTP version number                                                 |
| `ntp.mode`    | string  | NTP mode (`client`, `server`, `broadcast`, etc.)                   |
| `ntp.stratum` | integer | Stratum level (0 = unspecified, 1 = primary, 2+ = secondary)       |
| `ntp.ref_id`  | string  | Reference ID (IP address or 4-character ASCII string)              |

### SIP Fields

> Only present on packets captured on UDP/TCP port 5060 or 5061.

| Filter Key        | Type   | Description                                                   |
| ----------------- | ------ | ------------------------------------------------------------- |
| `sip.type`        | string | `Request` or `Response`                                       |
| `sip.method`      | string | SIP method (`INVITE`, `REGISTER`, `BYE`, etc.) — requests only |
| `sip.uri`         | string | Request URI — requests only                                   |
| `sip.from`        | string | `From` header                                                 |
| `sip.to`          | string | `To` header                                                   |
| `sip.call_id`     | string | `Call-ID` header                                              |
| `sip.status_code` | string | SIP status code (e.g. `200`) — responses only                 |
| `sip.status_msg`  | string | SIP status message (e.g. `OK`) — responses only               |

### FTP Fields

> Only present on packets captured on TCP port 20 or 21.

| Filter Key       | Type   | Description                                                  |
| ---------------- | ------ | ------------------------------------------------------------ |
| `ftp.type`       | string | `Command` or `Response`                                      |
| `ftp.command`    | string | FTP command (e.g. `USER`, `RETR`, `LIST`) — commands only    |
| `ftp.argument`   | string | Argument passed to the command — commands only               |
| `ftp.status_code`| string | FTP status code (e.g. `220`, `230`) — responses only         |
| `ftp.message`    | string | Status message text — responses only                         |

### SMTP Fields

> Only present on packets captured on TCP port 25, 587, or 465.

| Filter Key        | Type   | Description                                                    |
| ----------------- | ------ | -------------------------------------------------------------- |
| `smtp.type`       | string | `Command` or `Response`                                        |
| `smtp.command`    | string | SMTP command (e.g. `EHLO`, `MAIL`, `RCPT`) — commands only    |
| `smtp.argument`   | string | Argument passed to the command — commands only                 |
| `smtp.status_code`| string | SMTP status code (e.g. `250`, `354`) — responses only          |
| `smtp.message`    | string | Status message text — responses only                           |

### POP3 Fields

> Only present on packets captured on TCP port 110 or 995.

| Filter Key       | Type   | Description                                                    |
| ---------------- | ------ | -------------------------------------------------------------- |
| `pop3.type`      | string | `Command` or `Response`                                        |
| `pop3.command`   | string | POP3 command (e.g. `USER`, `RETR`, `LIST`) — commands only    |
| `pop3.argument`  | string | Argument passed to the command — commands only                 |
| `pop3.status`    | string | Response status indicator (`+OK` or `-ERR`) — responses only  |
| `pop3.message`   | string | Response message text — responses only                         |

### IMAP Fields

> Only present on packets captured on TCP port 143 or 993.

| Filter Key      | Type   | Description                                                                 |
| --------------- | ------ | --------------------------------------------------------------------------- |
| `imap.type`     | string | `Command`, `Response`, or `Untagged`                                        |
| `imap.tag`      | string | IMAP tag (e.g. `A001`) — commands and responses only                        |
| `imap.command`  | string | IMAP command (e.g. `LOGIN`, `SELECT`, `FETCH`) — commands only              |
| `imap.argument` | string | Command argument — commands only                                            |
| `imap.status`   | string | Status keyword (`OK`, `NO`, `BAD`, or untagged keyword) — responses/untagged|
| `imap.info`     | string | Additional info text — untagged responses only                              |
| `imap.message`  | string | Response message text — tagged responses only                               |

### Telnet Fields

> Only present on packets captured on TCP port 23.

| Filter Key           | Type   | Description                                               |
| -------------------- | ------ | --------------------------------------------------------- |
| `telnet.negotiations`| array  | List of Telnet IAC negotiation option names               |
| `telnet.text`        | string | Printable ASCII text extracted from the payload (≤ 200 chars) |

### IRC Fields

> Only present on packets captured on TCP port 6667, 6668, or 6669.

| Filter Key      | Type    | Description                                              |
| --------------- | ------- | -------------------------------------------------------- |
| `irc.command`   | string  | IRC command from the first parsed message (e.g. `PRIVMSG`) |
| `irc.prefix`    | string  | Message prefix (nick/server) from the first parsed message |
| `irc.params`    | string  | Command parameters from the first parsed message         |
| `irc.msg_count` | integer | Total number of IRC messages parsed in the payload       |

### MTP / MMS Fields

> Only present on packets captured on TCP port 1755.

| Filter Key    | Type    | Description                                              |
| ------------- | ------- | -------------------------------------------------------- |
| `mtp.protocol`| string  | Always `MMS/MTP`                                         |
| `mtp.cmd_id`  | string  | Command ID as a hex string (e.g. `0x00040001`)           |
| `mtp.command` | string  | Human-readable command name                              |
| `mtp.length`  | integer | Declared message length in bytes                         |

### LDAP Fields

> Only present on packets captured on TCP or UDP port 389 or 636.

| Filter Key      | Type    | Description                          |
| --------------- | ------- | ------------------------------------ |
| `ldap.msg_id`   | integer | LDAP message ID                      |
| `ldap.operation`| string  | LDAP operation name (e.g. `BindRequest`, `SearchRequest`) |

### MySQL Fields

> Only present on packets captured on TCP port 3306.

| Filter Key            | Type    | Description                                                      |
| --------------------- | ------- | ---------------------------------------------------------------- |
| `mysql.type`          | string  | Packet type: `Server Greeting`, `OK`, `Error`, or `Command`     |
| `mysql.seq`           | integer | MySQL sequence number                                            |
| `mysql.proto_version` | integer | Protocol version (always `10`) — Server Greeting only            |
| `mysql.server_version`| string  | MySQL server version string — Server Greeting only               |
| `mysql.error_code`    | integer | MySQL error code — Error only                                    |
| `mysql.error_msg`     | string  | MySQL error message — Error only                                 |
| `mysql.command`       | string  | Command type name (e.g. `Query`, `Quit`) — Command only          |
| `mysql.query`         | string  | SQL query text — Command only                                    |

### PostgreSQL Fields

> Only present on packets captured on TCP port 5432.

| Filter Key          | Type    | Description                                                      |
| ------------------- | ------- | ---------------------------------------------------------------- |
| `pg.type`           | string  | Message type (e.g. `Query`, `ReadyForQuery`, `StartupMessage`)   |
| `pg.direction`      | string  | `Backend` (server→client) or `Frontend` (client→server)         |
| `pg.msg_length`     | integer | Declared message length in bytes                                 |
| `pg.proto_version`  | string  | Protocol version (e.g. `3.0`) — StartupMessage only             |
| `pg.body`           | string  | Decoded body text — Frontend messages only                       |

### XMPP Fields

> Only present on packets captured on TCP port 5222 or 5223.

| Filter Key    | Type   | Description                                   |
| ------------- | ------ | --------------------------------------------- |
| `xmpp.stanza` | string | Stanza type (e.g. `message`, `presence`, `iq`) |
| `xmpp.to`     | string | `to` attribute of the stanza                  |
| `xmpp.from`   | string | `from` attribute of the stanza                |

### SMB Fields

> Only present on packets captured on TCP port 139 or 445.

| Filter Key      | Type    | Description                                               |
| --------------- | ------- | --------------------------------------------------------- |
| `smb.version`   | string  | `SMBv1` or `SMBv2/v3`                                     |
| `smb.command`   | string  | SMB command name (e.g. `SMB_COM_NEGOTIATE`, `Create`)     |
| `smb.status`    | string  | NT status code as a hex string (e.g. `0x00000000`)        |
| `smb.is_response`| boolean| `true` if this is a server response, `false` if a request |

### MQTT Fields

> Only present on packets captured on TCP or UDP port 1883 or 8883.

| Filter Key      | Type    | Description                                                      |
| --------------- | ------- | ---------------------------------------------------------------- |
| `mqtt.msg_type` | string  | MQTT message type (e.g. `CONNECT`, `PUBLISH`, `SUBSCRIBE`)       |
| `mqtt.qos`      | integer | Quality of Service level (0, 1, or 2)                            |
| `mqtt.dup`      | boolean | Whether the DUP flag is set                                      |
| `mqtt.retain`   | boolean | Whether the RETAIN flag is set                                   |
| `mqtt.topic`    | string  | Topic string — PUBLISH messages only                             |

### RTSP Fields

> Only present on packets captured on TCP port 554.

| Filter Key            | Type   | Description                                                       |
| --------------------- | ------ | ----------------------------------------------------------------- |
| `rtsp.type`           | string | `Request` or `Response`                                           |
| `rtsp.version`        | string | RTSP version (e.g. `RTSP/1.0`)                                    |
| `rtsp.method`         | string | RTSP method (e.g. `DESCRIBE`, `SETUP`, `PLAY`) — requests only    |
| `rtsp.url`            | string | Request URL — requests only                                       |
| `rtsp.cseq`           | string | `CSeq` header value                                               |
| `rtsp.session`        | string | `Session` header value                                            |
| `rtsp.transport`      | string | `Transport` header value — requests only                          |
| `rtsp.status_code`    | string | RTSP status code (e.g. `200`) — responses only                    |
| `rtsp.status_msg`     | string | RTSP status message (e.g. `OK`) — responses only                  |
| `rtsp.content_type`   | string | `Content-Type` header — responses only                            |
| `rtsp.content_length` | string | `Content-Length` header — responses only                          |

### TFTP Fields

> Only present on packets captured on UDP port 69.

| Filter Key        | Type    | Description                                                        |
| ----------------- | ------- | ------------------------------------------------------------------ |
| `tftp.opcode`     | string  | TFTP opcode (`Read Request`, `Write Request`, `Data`, `Acknowledgment`, `Error`) |
| `tftp.filename`   | string  | File name — Read/Write Request only                                |
| `tftp.mode`       | string  | Transfer mode (e.g. `octet`, `netascii`) — Read/Write Request only |
| `tftp.block`      | integer | Block number — Data and Acknowledgment only                        |
| `tftp.data_len`   | integer | Length of the data payload in bytes — Data only                    |
| `tftp.error_code` | integer | TFTP error code — Error only                                       |
| `tftp.error_desc` | string  | Standard error description — Error only                            |
| `tftp.error_msg`  | string  | Custom error message — Error only                                  |

### BGP Fields

> Only present on packets captured on TCP port 179.

| Filter Key          | Type    | Description                                                          |
| ------------------- | ------- | -------------------------------------------------------------------- |
| `bgp.type`          | string  | BGP message type (`OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`, `ROUTE-REFRESH`) |
| `bgp.length`        | integer | Total message length in bytes                                        |
| `bgp.version`       | integer | BGP version number — OPEN only                                       |
| `bgp.asn`           | integer | Sender's Autonomous System Number — OPEN only                        |
| `bgp.hold_time`     | integer | Negotiated hold time in seconds — OPEN only                          |
| `bgp.router_id`     | string  | BGP router ID (dotted-decimal IP) — OPEN only                        |
| `bgp.error_code`    | integer | Error code — NOTIFICATION only                                       |
| `bgp.error_name`    | string  | Human-readable error name — NOTIFICATION only                        |
| `bgp.error_subcode` | integer | Error subcode — NOTIFICATION only                                    |

### HTTP/2 Fields

> Detected on any TCP port when a binary HTTP/2 frame or connection preface is found.

| Filter Key           | Type    | Description                                                      |
| -------------------- | ------- | ---------------------------------------------------------------- |
| `http2.preface`      | boolean | `true` if the HTTP/2 connection preface (`PRI * HTTP/2.0…`) was detected |
| `http2.frame_type`   | string  | Frame type (e.g. `DATA`, `HEADERS`, `SETTINGS`, `PING`, `GOAWAY`) |
| `http2.frame_length` | integer | Frame payload length in bytes                                    |
| `http2.frame_flags`  | string  | Frame flags as a hex string (e.g. `0x04`)                        |
| `http2.stream_id`    | integer | Stream identifier                                                |

### NNTP Fields

> Only present on packets captured on TCP port 119.

| Filter Key         | Type   | Description                                                |
| ------------------ | ------ | ---------------------------------------------------------- |
| `nntp.type`        | string | `Command` or `Response`                                    |
| `nntp.command`     | string | NNTP command (e.g. `GROUP`, `ARTICLE`, `POST`) — commands only |
| `nntp.argument`    | string | Command argument — commands only                           |
| `nntp.status_code` | string | NNTP status code (e.g. `211`, `420`) — responses only      |
| `nntp.message`     | string | Response message text — responses only                     |

### RADIUS Fields

> Only present on packets captured on TCP or UDP port 1812, 1813, 1645, or 1646.

| Filter Key     | Type    | Description                                                          |
| -------------- | ------- | -------------------------------------------------------------------- |
| `radius.code`  | string  | RADIUS packet code (e.g. `Access-Request`, `Access-Accept`, `Accounting-Request`) |
| `radius.id`    | integer | Packet identifier                                                    |
| `radius.length`| integer | Total packet length in bytes                                         |
| `radius.attrs` | array   | List of decoded RADIUS attributes (`{Type, Value}` objects)          |

---

## Examples

### IP and Port Filtering

```
# Packets from a specific source IP
ip.src.addr:192.168.1.10

# Packets going to a specific destination IP
ip.dst.addr:10.0.0.1

# Traffic on destination port 443
tcp.dst.port:443

# Traffic from a source port range (above 1024 — high ephemeral ports)
tcp.src.port:>1024

# Traffic between two specific hosts
ip.src.addr:10.0.0.5 && ip.dst.addr:10.0.0.1

# All HTTP and HTTPS traffic
tcp.dst.port:80 || tcp.dst.port:443

# Large IP packets
ip.len:>1000
```

### Payload and Entropy Filtering

```
# Payloads likely encrypted or compressed (high entropy)
payload.entropy:>=7.0

# Small payloads
payload.len:<64

# HTML responses
payload.mime:text/html

# JSON payloads
payload.mime:application/json

# Plain-text (ASCII) payloads only
payload.charset:ascii

# Payloads encoded as UTF-8
payload.encoding:utf-8

# Packets that contained a compressed payload
payload.decompressed.ascii:!=

# High-entropy HTML traffic — likely HTTPS with cleartext body
(tcp.dst.port:80 || tcp.dst.port:443) && payload.entropy:>=6.0

# JSON payloads from a specific host
payload.mime:application/json && ip.src.addr:10.0.0.5
```

### GeoIP / Location Filtering

```
# Packets originating from China (GeoIP)
loc.src.country:China

# Packets destined for Germany
loc.dst.country:Germany

# Packets from a specific city
loc.src.city:Hangzhou

# Traffic from China going to local network
loc.src.country:China && ip.dst.class:Localnet

# Outbound traffic to a foreign country
ip.src.class:Localnet && loc.dst.country:Russia
```

### Protocol-Specific Filtering

```
# DNS queries only (not responses)
dns.qr:false

# DNS queries for a specific domain
dns.qname:example.com

# All DNS responses
dns.qr:true

# HTTP POST requests
http.method:POST

# HTTP responses with a 404 status
http.status_code:404

# HTTP responses from a specific server
http.server:nginx

# HTTP requests to a specific host header
http.host:api.example.com

# HTTPS responses (port 443) with error status
tcp.dst.port:443 && http.status_code:>=400

# SNMP packets using the "public" community string
snmp.community:public

# SNMP traps
snmp.pdu_type:Trap

# DHCP DISCOVER messages
dhcp.msg_type:Discover

# NTP client requests
ntp.mode:client

# NTP with a non-primary stratum
ntp.stratum:>1

# SIP INVITE requests
sip.method:INVITE

# SIP calls from a specific URI
sip.from:sip:alice@example.com
```

### TCP Flags

```
# SYN packets (connection initiation)
tcp.flags:SYN

# RST packets (connection reset)
tcp.flags:RST

# FIN packets (connection teardown)
tcp.flags:FIN

# Packets with both ACK and PSH set
tcp.flags:ACK|PSH
```

### Ethernet / MAC Filtering

```
# Packets from a specific MAC address
ether.src.mac.addr:08:9d:f4:84:e9:28

# Packets from a specific vendor
ether.src.mac.vendor:Intel

# Local traffic between two known MAC addresses
ether.src.mac.addr:08:9d:f4:84:e9:28 && ether.dst.mac.addr:b8:3a:08:bc:4e:70
```

### Active Recon

```
# Hosts running Apache
host.banner:Apache

# Hosts running nginx
host.banner:nginx

# Any host where a banner was retrieved
host.banner:!=Active recon not performed
```

### Complex Multi-Condition Queries

```
# High-entropy traffic from China to local network on common web ports
(tcp.dst.port:80 || tcp.dst.port:443) && loc.src.country:China && payload.entropy:>=6.0

# DNS queries from internal hosts
dns.qr:false && ip.src.class:Localnet

# All SNMP and DHCP management traffic
(snmp.community:public || snmp.pdu_type:Trap) || (dhcp.msg_type:DISCOVER || dhcp.msg_type:OFFER)

# Large encrypted TCP packets from external sources
tcp.dst.port:443 && payload.len:>500 && payload.entropy:>=7.0 && ip.src.class:!=Localnet

# HTTP POST requests carrying JSON payloads
http.method:POST && payload.mime:application/json

# SIP calls destined for a specific domain
sip.method:INVITE && sip.to:example.com
```

---

## Tips

- **Press Enter** to apply the filter after typing in the filter bar. The filter is not applied as you type.
- **String matching is case-insensitive.** `loc.dst.country:china` matches the same packets as `loc.dst.country:China`.
- **Protocol-specific keys only exist when that protocol was detected.** Filtering on `http.method:GET` will return only HTTP packets where the method field was parsed.
- **GeoIP keys are absent for private/local IPs.** Use `ip.src.class:Localnet` to identify local traffic instead of relying on `loc.src.*` fields.
- **Active recon keys require the `-a` flag** when running the backend. Without it, `host.banner` will contain `Active recon not performed` for all packets.
- **An empty filter bar shows all packets.** Clear the filter and press Enter to reset the view.

---

## License

GPL v3

## Author

Marshall Whittaker
