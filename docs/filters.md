# Filters

## Filter Reference

- [Overview](#overview)
- [Syntax](#syntax)
- [How Keys Work](#how-keys-work)
- [Filter Key Reference](#filter-key-reference)
- [Examples](#examples)
- [Tips](#tips)
- [License](#license)
- [Author](#author)

### Overview

PacketSnitch's filter bar lets you search and narrow down the packets displayed in the <a href="/frontend">frontend</a>. Filters are evaluated over the full loaded dataset (all hosts), not just the currently selected host. Results update immediately after pressing **Enter** in the filter bar, and the **Filtered Packets** counter in the left sidebar updates to reflect the number of matching packets.

The filter dropdown merges session history with saved named filters from the user filter library. Right-clicking the filter input provides a **Save current filter...** flow to label and persist the current query.

---

### Syntax

#### Basic equality

```
key:value
```

Matches packets where `key` equals `value`. String comparisons are **case-insensitive**.

```
ip.src.addr:192.168.1.1
tcp.dst.port:443
payload.mime:text/html
```

#### Comparison operators

Prefix the value with a comparison operator to perform numeric or lexicographic comparisons, globbing supported.

```
key:==value    (explicit equality — same as key:value)
key:!=value    (not equal)
key:>value     (greater than)
key:>=value    (greater than or equal)
key:<value     (less than)
key:<=value    (less than or equal)
key:value*       (globbing, or matching part of the string)
```

```
payload.entropy:>=7.0
ip.len:>100
tcp.dst.port:!=80
payload.len:<64
mime.type: text/*
```

#### Boolean combinators

Use `&&` (AND) and `||` (OR) to combine multiple conditions. AND has higher precedence than OR.

```
ip.src.addr:10.0.0.1 && tcp.dst.port:443
tcp.dst.port:80 || tcp.dst.port:443
```

#### Grouping with parentheses

Use parentheses to override precedence and group sub-expressions.

```
(tcp.dst.port:80 || tcp.dst.port:443) && payload.entropy:>=6.0
(payload.mime:text/html || payload.mime:application/json) && ip.dst.addr:10.0.0.1
```

The context menu also supports explicit parenthesis editing via **Add to filter... → Parentheses...**, including **Append (**, **Append )**, and **Wrap current query with (...)**.

#### Inversion with `!`

Use `!` to invert either a single expression or a grouped expression.

```
!tcp.dst.port:443
!(tcp.dst.port:80 || tcp.dst.port:443)
ip.src.addr:10.0.0.1 && !(mime.type:text/html || mime.type:application/json)
```

#### Clearing the filter

Delete all text from the filter bar and press **Enter** to show all packets again.

---

### How Keys Work

Filter keys correspond directly to the dot-notation leaf-node names embedded in each packet's JSON. The filter engine normalizes keys to **lowercase** with **spaces replaced by hyphens**, so both the machine-readable dot-notation form (`wire.len`) and the normalized human-readable form (`wire-length`) are accepted interchangeably. This document uses the canonical dot-notation names throughout.

Additional shorthand aliases are also supported: `wire.proto`, `eth.src.vendor`, and `mime.type`. Text queries for `eth.src.vendor`, `mime.type`, and `dns.qname` are matched case-insensitively using substring matching.

Protocol-specific keys (e.g., `dns.*`, `http.*`) are only present in packets where that protocol was detected, so filtering on them automatically scopes results to the relevant protocol traffic.

---

### Filter Key Reference

#### Core Packet Fields

| Filter Key         | Type   | Description                                      |
| ------------------ | ------ | ------------------------------------------------ |
| `packet.timestamp` | string | Capture timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| `packet.proto`     | string | Transport protocol (`tcp`, `udp`, `icmp`)        |
| `packet.hex`       | string | Full raw packet as a hex string                  |

#### Ethernet Fields

> Only populated when both source and destination IPs are on the local network.

| Filter Key             | Type   | Description                            |
| ---------------------- | ------ | -------------------------------------- |
| `ether.src.mac.addr`   | string | Source MAC address                     |
| `ether.dst.mac.addr`   | string | Destination MAC address                |
| `ether.src.mac.vendor` | string | Hardware vendor of the source MAC      |
| `ether.dst.mac.vendor` | string | Hardware vendor of the destination MAC |

#### IP Fields

| Filter Key     | Type    | Description                                                     |
| -------------- | ------- | --------------------------------------------------------------- |
| `ip.src.addr`  | string  | Source IP address                                               |
| `ip.dst.addr`  | string  | Destination IP address                                          |
| `ip.chksum`    | string  | IP header checksum (hex, e.g. `0xd1ae`)                         |
| `ip.len`       | integer | IP layer length in bytes                                        |
| `ip.src.class` | string  | Network class of the source IP (`Localnet`, `A`, `B`, `C`)      |
| `ip.dst.class` | string  | Network class of the destination IP (`Localnet`, `A`, `B`, `C`) |

#### TCP Fields

| Filter Key     | Type    | Description                                               |
| -------------- | ------- | --------------------------------------------------------- |
| `tcp.src.port` | integer | TCP source port                                           |
| `tcp.dst.port` | integer | TCP destination port                                      |
| `tcp.chksum`   | string  | TCP checksum (hex)                                        |
| `tcp.urgptr`   | boolean | Whether the urgent pointer is set (`true` / `false`)      |
| `tcp.flags`    | string  | Active TCP flags (e.g. `SYN`, `ACK\|PSH`, `SYN\|ACK`)     |
| `tcp.len`      | integer | TCP header length in bytes                                |
| `tcp.proto`    | string  | IANA service name for the destination port (e.g. `https`) |
| `tcp.desc`     | string  | ICANN port description for the destination port           |
| `app.proto`    | string  | Catchall IANA port service                                |

#### UDP Fields

| Filter Key     | Type    | Description                  |
| -------------- | ------- | ---------------------------- |
| `udp.src.port` | integer | UDP source port              |
| `udp.dst.port` | integer | UDP destination port         |
| `udp.chksum`   | string  | UDP checksum (hex)           |
| `udp.len`      | integer | UDP datagram length in bytes |
| `udp.proto`    | string  | UDP IANA port service name   |
| `app.proto`    | string  | Catchall IANA port service   |

#### ICMP Fields

| Filter Key    | Type    | Description                                                        |
| ------------- | ------- | ------------------------------------------------------------------ |
| `icmp.type`   | string  | ICMP message type (e.g. `Echo Request`, `Destination Unreachable`) |
| `icmp.code`   | integer | ICMP code value                                                    |
| `icmp.id`     | integer | ICMP identifier field                                              |
| `icmp.seq`    | integer | ICMP sequence number                                               |
| `icmp.chksum` | string  | ICMP checksum (hex)                                                |

#### Wire / Payload Fields

| Filter Key                   | Type    | Description                                                                   |
| ---------------------------- | ------- | ----------------------------------------------------------------------------- |
| `wire.len`                   | integer | Total wire length of the segment in bytes                                     |
| `payload.hex`                | string  | Raw payload as a hex string                                                   |
| `payload.ascii`              | string  | Raw payload decoded as ASCII                                                  |
| `payload.len`                | integer | Payload length in bytes                                                       |
| `payload.mime`               | string  | MIME type (e.g. `text/html`, `application/octet-stream`)                      |
| `payload.entropy`            | float   | Shannon entropy of the payload (bits per byte, 0.0 – 8.0)                     |
| `payload.charset`            | string  | `ascii` if all bytes are printable ASCII, otherwise `binary`                  |
| `payload.encoding`           | string  | Detected character encoding (e.g. `utf-8`, `iso-8859-1`)                      |
| `payload.chars.used`         | integer | Number of distinct byte values present in the payload                         |
| `payload.decompressed.hex`   | string  | Decompressed payload as a hex string (only present if payload was compressed) |
| `payload.decompressed.ascii` | string  | Decompressed payload as ASCII (only present if payload was compressed)        |

#### GeoIP / Location Fields

> Only populated for routable (non-private) IP addresses.

| Filter Key         | Type   | Description                                   |
| ------------------ | ------ | --------------------------------------------- |
| `loc.src.country`  | string | Country of the source IP                      |
| `loc.src.city`     | string | City of the source IP                         |
| `loc.src.postal`   | string | Postal code of the source IP                  |
| `loc.src.tz`       | string | Time zone of the source IP (short alias)      |
| `loc.src.timezone` | string | Time zone of the source IP (full name)        |
| `loc.dst.country`  | string | Country of the destination IP                 |
| `loc.dst.city`     | string | City of the destination IP                    |
| `loc.dst.postal`   | string | Postal code of the destination IP             |
| `loc.dst.tz`       | string | Time zone of the destination IP (short alias) |
| `loc.dst.timezone` | string | Time zone of the destination IP (full name)   |

#### Active Recon Fields

> Only populated when the backend was run with `-a` (active recon).

| Filter Key    | Type   | Description                              |
| ------------- | ------ | ---------------------------------------- |
| `host.banner` | string | Server banner retrieved via active recon |

#### DNS Fields

> Only present on packets captured on UDP/TCP port 53.

| Filter Key      | Type    | Description                                         |
| --------------- | ------- | --------------------------------------------------- |
| `dns.id`        | integer | DNS transaction ID                                  |
| `dns.qr`        | boolean | `true` = response, `false` = query                  |
| `dns.qname`     | string  | First queried domain name                           |
| `dns.qnames`    | array   | All queried domain names in the message             |
| `dns.aname`     | string  | First answer name                                   |
| `dns.anames`    | array   | All answer names in the message                     |
| `dns.aip`       | string  | First resolved IP address from the response         |
| `dns.aips`      | array   | All resolved IP addresses from the response         |
| `dns.qdcount`   | integer | Number of questions in the message                  |
| `dns.ancount`   | integer | Number of answer records in the message             |
| `dns.hostnames` | array   | Hostnames resolved via active recon (requires `-a`) |

#### HTTP Fields

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

#### SNMP Fields

> Only present on packets captured on UDP/TCP port 161 or 162.

| Filter Key       | Type   | Description                                          |
| ---------------- | ------ | ---------------------------------------------------- |
| `snmp.version`   | string | SNMP version (`v1`, `v2c`, `v3`)                     |
| `snmp.community` | string | SNMP community string                                |
| `snmp.pdu_type`  | string | PDU type (`GetRequest`, `GetResponse`, `Trap`, etc.) |

#### DHCP Fields

> Only present on packets captured on UDP port 67 or 68.

| Filter Key      | Type   | Description                                                                                      |
| --------------- | ------ | ------------------------------------------------------------------------------------------------ |
| `dhcp.msg_type` | string | DHCP message type (`Discover`, `Offer`, `Request`, `Decline`, `ACK`, `NAK`, `Release`, `Inform`) |
| `dhcp.xid`      | string | Transaction ID (hex)                                                                             |
| `dhcp.ciaddr`   | string | Client IP address                                                                                |
| `dhcp.yiaddr`   | string | Offered IP address                                                                               |
| `dhcp.siaddr`   | string | Server IP address                                                                                |

#### NTP Fields

> Only present on packets captured on UDP port 123.

| Filter Key    | Type    | Description                                                  |
| ------------- | ------- | ------------------------------------------------------------ |
| `ntp.leap`    | string  | Leap indicator (`no warning`, `last minute has 61s`, etc.)   |
| `ntp.version` | integer | NTP version number                                           |
| `ntp.mode`    | string  | NTP mode (`client`, `server`, `broadcast`, etc.)             |
| `ntp.stratum` | integer | Stratum level (0 = unspecified, 1 = primary, 2+ = secondary) |
| `ntp.ref_id`  | string  | Reference ID (IP address or 4-character ASCII string)        |

#### SIP Fields

> Only present on packets captured on UDP/TCP port 5060 or 5061.

| Filter Key        | Type   | Description                                                    |
| ----------------- | ------ | -------------------------------------------------------------- |
| `sip.type`        | string | `Request` or `Response`                                        |
| `sip.method`      | string | SIP method (`INVITE`, `REGISTER`, `BYE`, etc.) — requests only |
| `sip.uri`         | string | Request URI — requests only                                    |
| `sip.from`        | string | `From` header                                                  |
| `sip.to`          | string | `To` header                                                    |
| `sip.call_id`     | string | `Call-ID` header                                               |
| `sip.authorization` | string | `Authorization` header (e.g. Digest/Basic auth data)         |
| `sip.proxy_authorization` | string | `Proxy-Authorization` header                           |
| `sip.status_code` | string | SIP status code (e.g. `200`) — responses only                  |
| `sip.status_msg`  | string | SIP status message (e.g. `OK`) — responses only                |

#### FTP Fields

> Only present on packets captured on TCP port 20 or 21.

| Filter Key        | Type   | Description                                               |
| ----------------- | ------ | --------------------------------------------------------- |
| `ftp.type`        | string | `Command` or `Response`                                   |
| `ftp.command`     | string | FTP command (e.g. `USER`, `RETR`, `LIST`) — commands only |
| `ftp.argument`    | string | Argument passed to the command — commands only            |
| `ftp.status_code` | string | FTP status code (e.g. `220`, `230`) — responses only      |
| `ftp.message`     | string | Status message text — responses only                      |

#### SMTP Fields

> Only present on packets captured on TCP port 25, 587, or 465.

| Filter Key         | Type   | Description                                                |
| ------------------ | ------ | ---------------------------------------------------------- |
| `smtp.type`        | string | `Command` or `Response`                                    |
| `smtp.command`     | string | SMTP command (e.g. `EHLO`, `MAIL`, `RCPT`) — commands only |
| `smtp.argument`    | string | Argument passed to the command — commands only             |
| `smtp.status_code` | string | SMTP status code (e.g. `250`, `354`) — responses only      |
| `smtp.message`     | string | Status message text — responses only                       |

#### POP3 Fields

> Only present on packets captured on TCP port 110 or 995.

| Filter Key      | Type   | Description                                                  |
| --------------- | ------ | ------------------------------------------------------------ |
| `pop3.type`     | string | `Command` or `Response`                                      |
| `pop3.command`  | string | POP3 command (e.g. `USER`, `RETR`, `LIST`) — commands only   |
| `pop3.argument` | string | Argument passed to the command — commands only               |
| `pop3.status`   | string | Response status indicator (`+OK` or `-ERR`) — responses only |
| `pop3.message`  | string | Response message text — responses only                       |

#### IMAP Fields

> Only present on packets captured on TCP port 143 or 993.

| Filter Key      | Type   | Description                                                                  |
| --------------- | ------ | ---------------------------------------------------------------------------- |
| `imap.type`     | string | `Command`, `Response`, or `Untagged`                                         |
| `imap.tag`      | string | IMAP tag (e.g. `A001`) — commands and responses only                         |
| `imap.command`  | string | IMAP command (e.g. `LOGIN`, `SELECT`, `FETCH`) — commands only               |
| `imap.argument` | string | Command argument — commands only                                             |
| `imap.status`   | string | Status keyword (`OK`, `NO`, `BAD`, or untagged keyword) — responses/untagged |
| `imap.info`     | string | Additional info text — untagged responses only                               |
| `imap.message`  | string | Response message text — tagged responses only                                |

#### Telnet Fields

> Only present on packets captured on TCP port 23.

| Filter Key            | Type   | Description                                                   |
| --------------------- | ------ | ------------------------------------------------------------- |
| `telnet.negotiations` | array  | List of Telnet IAC negotiation option names                   |
| `telnet.text`         | string | Printable ASCII text extracted from the payload (≤ 200 chars) |

#### IRC Fields

> Only present on packets captured on TCP port 6667, 6668, or 6669.

| Filter Key      | Type    | Description                                                |
| --------------- | ------- | ---------------------------------------------------------- |
| `irc.command`   | string  | IRC command from the first parsed message (e.g. `PRIVMSG`) |
| `irc.prefix`    | string  | Message prefix (nick/server) from the first parsed message |
| `irc.params`    | string  | Command parameters from the first parsed message           |
| `irc.msg_count` | integer | Total number of IRC messages parsed in the payload         |

#### MTP / MMS Fields

> Only present on packets captured on TCP port 1755.

| Filter Key     | Type    | Description                                    |
| -------------- | ------- | ---------------------------------------------- |
| `mtp.protocol` | string  | Always `MMS/MTP`                               |
| `mtp.cmd_id`   | string  | Command ID as a hex string (e.g. `0x00040001`) |
| `mtp.command`  | string  | Human-readable command name                    |
| `mtp.length`   | integer | Declared message length in bytes               |

#### LDAP Fields

> Only present on packets captured on TCP or UDP port 389 or 636.

| Filter Key       | Type    | Description                                               |
| ---------------- | ------- | --------------------------------------------------------- |
| `ldap.msg_id`    | integer | LDAP message ID                                           |
| `ldap.operation` | string  | LDAP operation name (e.g. `BindRequest`, `SearchRequest`) |

#### MySQL Fields

> Only present on packets captured on TCP port 3306.

| Filter Key             | Type    | Description                                                 |
| ---------------------- | ------- | ----------------------------------------------------------- |
| `mysql.type`           | string  | Packet type: `Server Greeting`, `OK`, `Error`, or `Command` |
| `mysql.seq`            | integer | MySQL sequence number                                       |
| `mysql.proto_version`  | integer | Protocol version (always `10`) — Server Greeting only       |
| `mysql.server_version` | string  | MySQL server version string — Server Greeting only          |
| `mysql.error_code`     | integer | MySQL error code — Error only                               |
| `mysql.error_msg`      | string  | MySQL error message — Error only                            |
| `mysql.command`        | string  | Command type name (e.g. `Query`, `Quit`) — Command only     |
| `mysql.query`          | string  | SQL query text — Command only                               |

#### PostgreSQL Fields

> Only present on packets captured on TCP port 5432.

| Filter Key         | Type    | Description                                                    |
| ------------------ | ------- | -------------------------------------------------------------- |
| `pg.type`          | string  | Message type (e.g. `Query`, `ReadyForQuery`, `StartupMessage`) |
| `pg.direction`     | string  | `Backend` (server→client) or `Frontend` (client→server)        |
| `pg.msg_length`    | integer | Declared message length in bytes                               |
| `pg.proto_version` | string  | Protocol version (e.g. `3.0`) — StartupMessage only            |
| `pg.body`          | string  | Decoded body text — Frontend messages only                     |

#### XMPP Fields

> Only present on packets captured on TCP port 5222 or 5223.

| Filter Key    | Type   | Description                                    |
| ------------- | ------ | ---------------------------------------------- |
| `xmpp.stanza` | string | Stanza type (e.g. `message`, `presence`, `iq`) |
| `xmpp.to`     | string | `to` attribute of the stanza                   |
| `xmpp.from`   | string | `from` attribute of the stanza                 |

#### SMB Fields

> Only present on packets captured on TCP port 139 or 445.

| Filter Key        | Type    | Description                                               |
| ----------------- | ------- | --------------------------------------------------------- |
| `smb.version`     | string  | `SMBv1` or `SMBv2/v3`                                     |
| `smb.command`     | string  | SMB command name (e.g. `SMB_COM_NEGOTIATE`, `Create`)     |
| `smb.status`      | string  | NT status code as a hex string (e.g. `0x00000000`)        |
| `smb.is_response` | boolean | `true` if this is a server response, `false` if a request |
| `smb.ntlm.type`   | string  | NTLM signature detected in Session Setup payload (`NTLMSSP`) |
| `smb.ntlm.message_type` | integer | NTLM message type (1=Negotiate, 2=Challenge, 3=Authenticate) |
| `smb.ntlm.target_name` | string | NTLM target/workgroup name (when present)              |
| `smb.auth.domain` | string  | Parsed NTLM authenticate domain name                       |
| `smb.auth.username` | string | Parsed NTLM authenticate username                         |
| `smb.auth.workstation` | string | Parsed NTLM authenticate workstation                    |
| `smb.auth.lm_response` | string | LM response bytes (hex) from NTLM authenticate         |
| `smb.auth.ntlm_response` | string | NTLM response bytes (hex) from NTLM authenticate    |

#### MQTT Fields

> Only present on packets captured on TCP or UDP port 1883 or 8883.

| Filter Key      | Type    | Description                                                |
| --------------- | ------- | ---------------------------------------------------------- |
| `mqtt.msg_type` | string  | MQTT message type (e.g. `CONNECT`, `PUBLISH`, `SUBSCRIBE`) |
| `mqtt.qos`      | integer | Quality of Service level (0, 1, or 2)                      |
| `mqtt.dup`      | boolean | Whether the DUP flag is set                                |
| `mqtt.retain`   | boolean | Whether the RETAIN flag is set                             |
| `mqtt.topic`    | string  | Topic string — PUBLISH messages only                       |

#### RTSP Fields

> Only present on packets captured on TCP port 554.

| Filter Key            | Type   | Description                                                    |
| --------------------- | ------ | -------------------------------------------------------------- |
| `rtsp.type`           | string | `Request` or `Response`                                        |
| `rtsp.version`        | string | RTSP version (e.g. `RTSP/1.0`)                                 |
| `rtsp.method`         | string | RTSP method (e.g. `DESCRIBE`, `SETUP`, `PLAY`) — requests only |
| `rtsp.url`            | string | Request URL — requests only                                    |
| `rtsp.cseq`           | string | `CSeq` header value                                            |
| `rtsp.session`        | string | `Session` header value                                         |
| `rtsp.transport`      | string | `Transport` header value — requests only                       |
| `rtsp.status_code`    | string | RTSP status code (e.g. `200`) — responses only                 |
| `rtsp.status_msg`     | string | RTSP status message (e.g. `OK`) — responses only               |
| `rtsp.content_type`   | string | `Content-Type` header — responses only                         |
| `rtsp.content_length` | string | `Content-Length` header — responses only                       |

#### TFTP Fields

> Only present on packets captured on UDP port 69.

| Filter Key        | Type    | Description                                                                      |
| ----------------- | ------- | -------------------------------------------------------------------------------- |
| `tftp.opcode`     | string  | TFTP opcode (`Read Request`, `Write Request`, `Data`, `Acknowledgment`, `Error`) |
| `tftp.filename`   | string  | File name — Read/Write Request only                                              |
| `tftp.mode`       | string  | Transfer mode (e.g. `octet`, `netascii`) — Read/Write Request only               |
| `tftp.block`      | integer | Block number — Data and Acknowledgment only                                      |
| `tftp.data_len`   | integer | Length of the data payload in bytes — Data only                                  |
| `tftp.error_code` | integer | TFTP error code — Error only                                                     |
| `tftp.error_desc` | string  | Standard error description — Error only                                          |
| `tftp.error_msg`  | string  | Custom error message — Error only                                                |

#### BGP Fields

> Only present on packets captured on TCP port 179.

| Filter Key          | Type    | Description                                                                       |
| ------------------- | ------- | --------------------------------------------------------------------------------- |
| `bgp.type`          | string  | BGP message type (`OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`, `ROUTE-REFRESH`) |
| `bgp.length`        | integer | Total message length in bytes                                                     |
| `bgp.version`       | integer | BGP version number — OPEN only                                                    |
| `bgp.asn`           | integer | Sender's Autonomous System Number — OPEN only                                     |
| `bgp.hold_time`     | integer | Negotiated hold time in seconds — OPEN only                                       |
| `bgp.router_id`     | string  | BGP router ID (dotted-decimal IP) — OPEN only                                     |
| `bgp.error_code`    | integer | Error code — NOTIFICATION only                                                    |
| `bgp.error_name`    | string  | Human-readable error name — NOTIFICATION only                                     |
| `bgp.error_subcode` | integer | Error subcode — NOTIFICATION only                                                 |

#### HTTP/2 Fields

> Detected on any TCP port when a binary HTTP/2 frame or connection preface is found.

| Filter Key           | Type    | Description                                                              |
| -------------------- | ------- | ------------------------------------------------------------------------ |
| `http2.preface`      | boolean | `true` if the HTTP/2 connection preface (`PRI * HTTP/2.0…`) was detected |
| `http2.frame_type`   | string  | Frame type (e.g. `DATA`, `HEADERS`, `SETTINGS`, `PING`, `GOAWAY`)        |
| `http2.frame_length` | integer | Frame payload length in bytes                                            |
| `http2.frame_flags`  | string  | Frame flags as a hex string (e.g. `0x04`)                                |
| `http2.stream_id`    | integer | Stream identifier                                                        |

#### NNTP Fields

> Only present on packets captured on TCP port 119.

| Filter Key         | Type   | Description                                                    |
| ------------------ | ------ | -------------------------------------------------------------- |
| `nntp.type`        | string | `Command` or `Response`                                        |
| `nntp.command`     | string | NNTP command (e.g. `GROUP`, `ARTICLE`, `POST`) — commands only |
| `nntp.argument`    | string | Command argument — commands only                               |
| `nntp.status_code` | string | NNTP status code (e.g. `211`, `420`) — responses only          |
| `nntp.message`     | string | Response message text — responses only                         |

#### RADIUS Fields

> Only present on packets captured on TCP or UDP port 1812, 1813, 1645, or 1646.

| Filter Key      | Type    | Description                                                                       |
| --------------- | ------- | --------------------------------------------------------------------------------- |
| `radius.code`   | string  | RADIUS packet code (e.g. `Access-Request`, `Access-Accept`, `Accounting-Request`) |
| `radius.id`     | integer | Packet identifier                                                                 |
| `radius.length` | integer | Total packet length in bytes                                                      |
| `radius.attrs`  | array   | List of decoded RADIUS attributes (`{Type, Value}` objects)                       |

#### SMPP Fields

> Only present on packets captured on TCP port 2775 or 3550.

| Filter Key             | Type    | Description                                                           |
| ---------------------- | ------- | --------------------------------------------------------------------- |
| `smpp.command_length`  | integer | Declared SMPP PDU length in bytes                                     |
| `smpp.command_id`      | string  | SMPP command ID as hex (e.g. `0x00000004`)                            |
| `smpp.command`         | string  | SMPP command name (e.g. `submit_sm`, `deliver_sm`, `bind_transmitter`) |
| `smpp.is_response`     | boolean | `true` when response bit (`0x80000000`) is set in `command_id`        |
| `smpp.command_status`  | integer | SMPP command status code                                               |
| `smpp.sequence`        | integer | SMPP sequence number                                                   |
| `smpp.body_length`     | integer | Payload bytes after the 16-byte SMPP header                           |

#### Soulseek Fields

> Only present on packets captured on common Soulseek TCP ports (2234, 2240, 2242).

| Filter Key            | Type    | Description                                            |
| --------------------- | ------- | ------------------------------------------------------ |
| `soulseek.length`     | integer | Soulseek envelope message length (little-endian value) |
| `soulseek.code`       | integer | Soulseek message code                                  |
| `soulseek.code_hex`   | string  | Soulseek message code in hex (e.g. `0x0010`)          |
| `soulseek.body_length` | integer | Soulseek body length in bytes                         |
| `soulseek.preview`    | string  | Text preview extracted from message body               |

#### BitTorrent Fields

> Present when a BitTorrent handshake, peer-wire frame, or DHT KRPC payload is detected.

| Filter Key                 | Type    | Description                                                    |
| -------------------------- | ------- | -------------------------------------------------------------- |
| `bittorrent.type`          | string  | Decoder subtype: `handshake`, `peer_wire`, or `dht`           |
| `bittorrent.protocol`      | string  | Handshake protocol name (typically `BitTorrent protocol`)      |
| `bittorrent.reserved`      | string  | Handshake reserved bytes (hex)                                 |
| `bittorrent.info_hash`     | string  | Torrent info hash (hex)                                        |
| `bittorrent.peer_id`       | string  | Decoded peer ID (printable form, when available)               |
| `bittorrent.peer_id_hex`   | string  | Raw peer ID bytes (hex)                                        |
| `bittorrent.message`       | string  | Peer-wire message name (e.g. `have`, `piece`, `keepalive`)     |
| `bittorrent.message_id`    | integer | Peer-wire message numeric ID                                   |
| `bittorrent.length`        | integer | Peer-wire message length                                       |
| `bittorrent.transaction_type` | string | DHT KRPC transaction type (`q`, `r`, etc.)                   |
| `bittorrent.query`         | string  | DHT KRPC query method name                                     |
| `bittorrent.signature`     | string  | Detection signature (`handshake`, `peer_wire`, `dht`)          |

#### SSH Fields

> Present on packets captured on TCP port 22/2222 or payloads matching SSH framing.

| Filter Key              | Type    | Description                                                      |
| ----------------------- | ------- | ---------------------------------------------------------------- |
| `ssh.type`              | string  | SSH decoder subtype: `Identification` or `Binary Packet`         |
| `ssh.banner`            | string  | SSH identification banner line (e.g. `SSH-2.0-OpenSSH_9.8`)      |
| `ssh.protocol_version`  | string  | Parsed SSH protocol version from banner                          |
| `ssh.software_version`  | string  | Parsed SSH software identifier from banner                       |
| `ssh.comments`          | string  | Optional trailing banner comment                                 |
| `ssh.direction`         | string  | Heuristic packet direction (`Client Identification`/`Server Identification`) |
| `ssh.packet_length`     | integer | SSH binary packet declared length                                |
| `ssh.padding_length`    | integer | SSH binary packet padding length                                 |
| `ssh.msg_type`          | string  | SSH message type name (e.g. `KEXINIT`, `USERAUTH_REQUEST`)       |
| `ssh.msg_type_num`      | integer | SSH message type number                                          |
| `ssh.likely_encrypted`  | boolean | `true` if payload likely post-key-exchange encrypted data         |

#### WebSocket Fields

> Present on TCP traffic where an HTTP WebSocket upgrade or frame format is detected.

| Filter Key       | Type    | Description                                                   |
| ---------------- | ------- | ------------------------------------------------------------- |
| `ws.type`        | string  | `Upgrade` for handshake headers, or `Frame` for data frames  |
| `ws.upgrade`     | string  | `Upgrade` header value from WebSocket handshake              |
| `ws.host`        | string  | `Host` header from WebSocket handshake                       |
| `ws.key`         | string  | `Sec-WebSocket-Key` header value                             |
| `ws.version`     | string  | `Sec-WebSocket-Version` header value                         |
| `ws.opcode`      | string  | Decoded frame opcode name (`Text`, `Binary`, `Ping`, etc.)  |
| `ws.fin`         | boolean | WebSocket FIN flag                                             |
| `ws.masked`      | boolean | Whether the frame is masked                                   |
| `ws.payload_len` | integer | WebSocket frame payload length                                |

#### Kerberos Fields

> Only present on packets captured on TCP/UDP port 88 where Kerberos framing is detected.

| Filter Key       | Type    | Description                                                  |
| ---------------- | ------- | ------------------------------------------------------------ |
| `krb5.msg_type`  | string  | Kerberos message type (e.g. `AS-REQ`, `AS-REP`, `TGS-REQ`)  |
| `krb5.pvno`      | integer | Kerberos protocol version number (when parsable)            |

#### NFS / RPC Fields

> Present on packets captured on NFS/RPC ports (commonly TCP 2049 or 111).

| Filter Key          | Type    | Description                                                    |
| ------------------- | ------- | -------------------------------------------------------------- |
| `rpc.xid`           | string  | RPC transaction ID as hex (e.g. `0x5A2C0011`)                 |
| `rpc.msg_type`      | string  | RPC message type (`Call` or `Reply`)                          |
| `rpc.version`       | integer | RPC version (calls only)                                       |
| `rpc.program`       | string  | RPC program name (e.g. `NFS`, `Portmapper`)                   |
| `rpc.prog_version`  | integer | RPC program version                                            |
| `rpc.procedure`     | string  | RPC/NFS procedure name                                         |
| `rpc.reply_status`  | string  | RPC reply status (`Accepted` or `Denied`)                     |

#### SCTP / SIGTRAN Fields

> Present on SCTP traffic (IP protocol 132), including SIGTRAN/M3UA metadata when detected.

| Filter Key                   | Type    | Description                                                      |
| ---------------------------- | ------- | ---------------------------------------------------------------- |
| `sctp.src.port`              | integer | SCTP source port                                                 |
| `sctp.dst.port`              | integer | SCTP destination port                                            |
| `sctp.vtag`                  | integer | SCTP verification tag                                            |
| `sctp.chksum`                | string  | SCTP checksum (hex)                                              |
| `sctp.chunk.count`           | integer | Number of parsed SCTP chunks                                     |
| `sctp.chunks`                | array   | List of parsed SCTP chunk type names                             |
| `sctp.chunk.details`         | array   | Per-chunk detail objects with type/flags/length/payload metadata |
| `sctp.chunk.type`            | integer | Chunk type number (within `sctp.chunk.details`)                 |
| `sctp.chunk.type_name`       | string  | Chunk type name (within `sctp.chunk.details`)                   |
| `sctp.chunk.flags`           | integer | Chunk flags bitfield (within `sctp.chunk.details`)              |
| `sctp.chunk.length`          | integer | Chunk length in bytes (within `sctp.chunk.details`)             |
| `sctp.chunk.payload.len`     | integer | Chunk payload length (within `sctp.chunk.details`)              |
| `sctp.chunk.payload.preview` | string  | First payload bytes (hex preview)                                |
| `transport.sctp.src.port`    | integer | SCTP source port alias under transport namespace                 |
| `transport.sctp.dst.port`    | integer | SCTP destination port alias under transport namespace            |
| `sigtran.proto`              | string  | SIGTRAN adaptation protocol (e.g. `M3UA`, `SUA`)                |
| `sigtran.signaling`          | string  | High-level signaling family description                          |
| `sigtran.version`            | integer | SIGTRAN message version (M3UA)                                   |
| `sigtran.reserved`           | integer | SIGTRAN reserved byte (M3UA)                                     |
| `sigtran.message.class`      | integer | SIGTRAN message class code (M3UA)                                |
| `sigtran.message.class_name` | string  | SIGTRAN message class name (M3UA)                                |
| `sigtran.message.type`       | integer | SIGTRAN message type code (M3UA)                                 |
| `sigtran.length`             | integer | SIGTRAN message length                                            |
| `sigtran.payload.len`        | integer | SIGTRAN payload length (post-header)                              |
| `sigtran.payload.preview`    | string  | SIGTRAN payload preview (hex)                                     |

#### WAN / Link-Control Fields

> Present when WAN/link-control protocols are decoded (PPP/PPPoE/LLDP/ATM/HDLC/etc.).

| Filter Key          | Type   | Description                                                        |
| ------------------- | ------ | ------------------------------------------------------------------ |
| `wan.detected`      | array  | List of detected WAN/link-control protocol names                   |
| `wan.layers`        | array  | Raw layer names detected in the packet                             |
| `wan.primary`       | string | Primary inferred WAN/link-control protocol                         |
| `ppp.proto_field`   | string | PPP protocol field (hex + mapped protocol name)                    |
| `pppoe.code`        | string | PPPoE code (hex + semantic label)                                  |
| `pppoe.session_id`  | string | PPPoE session ID (hex)                                              |
| `pppoe.stage`       | string | PPPoE stage (`Discovery` or `Session`)                              |
| `lldp.chassis_id`   | string | LLDP chassis identifier                                              |
| `lldp.port_id`      | string | LLDP port identifier                                                 |
| `lldp.ttl`          | integer | LLDP time-to-live value                                            |
| `atm.encapsulation` | string | ATM encapsulation type (e.g. CLIP, PPPoA, AAL5)                    |
| `ether.type`        | string | Ethernet EtherType observed while decoding link-control layers      |
| `wan.proto.ppp`     | string | Convenience presence key for PPP detection                           |
| `wan.proto.pppoe`   | string | Convenience presence key for PPPoE detection                         |
| `wan.proto.lcp`     | string | Convenience presence key for LCP detection                           |
| `wan.proto.ncp`     | string | Convenience presence key for NCP detection                           |
| `wan.proto.lldp`    | string | Convenience presence key for LLDP detection                          |
| `wan.proto.atm`     | string | Convenience presence key for ATM detection                           |
| `wan.proto.frame_relay` | string | Convenience presence key for Frame Relay detection             |
| `wan.proto.hdlc`    | string | Convenience presence key for HDLC detection                          |
| `wan.proto.sdlc`    | string | Convenience presence key for SDLC detection                          |
| `wan.proto.slip`    | string | Convenience presence key for SLIP detection                          |
| `wan.proto.lap`     | string | Convenience presence key for LAP detection                           |
| `wan.proto.token_ring` | string | Convenience presence key for Token Ring detection               |

#### Tor Enrichment Fields

> Present when Tor exit-node enrichment is enabled during backend processing.

| Filter Key       | Type    | Description                                           |
| ---------------- | ------- | ----------------------------------------------------- |
| `tor.exit.node`  | boolean | `true` when destination IP matched known Tor exit node |
| `tor.nickname`   | string  | Tor relay nickname for matched exit node               |
| `tor.platform`   | string  | Tor relay platform string for matched exit node        |

#### Stream related Fields

> These keys filter based on tcp stream charactaristics.

| Filter Key                   | Type    | Description                                              |
| ---------------------------- | ------- | -------------------------------------------------------- |
| `tcp.stream.retransmission`  | boolean | If this is a retransmission packet                       |
| `tcp.stream.badorder`        | boolean | If this packet came, but was not in stream order         |

#### Misc

> These are otherwise uncatagorized filter keys

| Filter Key     | Type    | Description
| -------------- | ------- | ---------------------------------------------- |
| `bookmark`     | boolean | If the packet has been bookmarked in the UI    |


---

### Examples

#### IP and Port Filtering

```
# Packets from a specific source IP
ip.src.addr:192.168.1.10

# Packets coming from your home or vpn network
ip.src.addr:10.0.1.* || ip.src.addr:10.0.2.*

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

#### Payload Filtering

```
# Payloads likely encrypted or compressed (high entropy)
payload.entropy:>=7.0

# Small payloads
payload.len:<64

# All text based responses
payload.mime:text/*

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

#### GeoIP / Location Filtering

```
# Packets originating from China (GeoIP)
loc.src.country:China

# Packets destined for anywhere except Germany
!loc.dst.country:Germany

# Packets from a specific city
loc.src.city:Hangzhou

# Traffic from China going to local network
loc.src.country:China && ip.dst.class:Localnet

# Outbound traffic to a foreign country
ip.src.class:Localnet && loc.dst.country:Russia
```

#### Protocol-Specific Filtering

```
# DNS queries only (not responses)
dns.qr:false

# DNS queries for a specific domain
dns.qname:example.com

# DNS queries to a subdomain of google.com
dns.qname:*.google.com

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

#### TCP Flags

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

#### Ethernet / MAC Filtering

```
# Packets from a specific MAC address
ether.src.mac.addr:08:9d:f4:84:e9:28

# Packets from a specific vendor
ether.src.mac.vendor:Intel

# Local traffic between two known MAC addresses
ether.src.mac.addr:08:9d:f4:84:e9:28 && ether.dst.mac.addr:b8:3a:08:bc:4e:70
```

#### Active Recon

```
# Hosts running Apache
host.banner:Apache

# Hosts running nginx
host.banner:nginx

# Any host where a banner was retrieved
host.banner:!=Active recon not performed
```

#### Complex Multi-Condition Queries

```
# High-entropy traffic from China to local network on common web ports
(tcp.dst.port:80 || tcp.dst.port:443) && loc.src.country:China && payload.entropy:>=6.0

# DNS queries from internal hosts
dns.qr:false && ip.src.class:Localnet

# All SNMP and DHCP management traffic
(snmp.community:public || snmp.pdu_type:Trap) || (dhcp.msg_type:DISCOVER || dhcp.msg_type:OFFER)

# Large encrypted TCP packets from external sources
tcp.dst.port:443 && payload.len:>500 && payload.entropy:>=7.0 && ip.src.class:!=Localnet

# HTTP POST requests carrying JSON payloads that don't go to the oxasploits.com domain
(http.method:POST && payload.mime:application/json) && !dns.qname:oxasploits.com

# SIP calls destined for a specific domain
sip.method:INVITE && sip.to:example.com
```

---

### Tips

- **Press Enter** to apply the filter after typing in the filter bar. The filter is not applied as you type.
- **String matching is case-insensitive.** `loc.dst.country:china` matches the same packets as `loc.dst.country:China`.
- **Protocol-specific keys only exist when that protocol was detected.** Filtering on `http.method:GET` will return only HTTP packets where the method field was parsed.
- **GeoIP keys are absent for private/local IPs.** Use `ip.src.class:Localnet` to identify local traffic instead of relying on `loc.src.*` fields.
- **Active recon keys require the `-a` flag** when running the <a href="/backend">backend</a>. Without it, `host.banner` will contain `Active recon not performed` for all packets.
- **An empty filter bar shows all packets.** Clear the filter and press Enter to reset the view.

---

### License

GPL v3

### Author

Marshall Whittaker/ oxagast
