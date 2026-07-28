# PacketSnitch Metrics Endpoint

A small, dependency-free HTTP server that accepts anonymous opt-in metrics
from PacketSnitch desktop clients. Its only job is to durably land incoming
event batches on disk in formats that drop straight into a log aggregation
stack (ElasticSearch, Graylog, Loki, Splunk, Vector, etc.).

## Why an NDJSON file sink?

NDJSON is the universal ingest format. Every popular log shipper — Filebeat,
Logstash, Vector, Fluent Bit, NXLog, Prometheus-Elasticsearch-Exporter, etc.
— reads NDJSON without a transform pipeline. Graylog's built-in "JSON file"
input expects it directly. By writing one event per line with the
ElasticSearch-shaped keys (`@timestamp`, `event`, `props`), the same files
feed any of these backends with zero glue code.

## Quick start

```bash
# Default port 8088, data dir ./var/metrics
python3 src/metrics/server.py

# Production-style override
PSN_METRICS_PORT=8088 \
PSN_METRICS_DATA_DIR=/var/lib/packetsnitch/metrics \
PSN_METRICS_GZIP_OLD=7 \
PSN_METRICS_MAX_BODY=1048576 \
python3 src/metrics/server.py
```

The server is a normal stdlib `http.server` — run it under systemd, runit,
supervisord, Docker, or behind any reverse proxy (nginx, Caddy, Traefik).

## Configuration (env vars)

| Variable                    | Default               | Description                                       |
| --------------------------- | --------------------- | ------------------------------------------------- |
| `PSN_METRICS_PORT`          | `8088`                | TCP listen port                                   |
| `PSN_METRICS_HOST`          | `0.0.0.0`             | Bind address                                      |
| `PSN_METRICS_DATA_DIR`      | `./var/metrics`       | Where NDJSON files are written                    |
| `PSN_METRICS_MAX_BODY`      | `1048576` (1 MiB)     | Max POST body size in bytes                       |
| `PSN_METRICS_MAX_QUEUE`     | `1024`                | Max in-flight batches buffered in memory          |
| `PSN_METRICS_GZIP_OLD`      | `7`                   | Compress files older than N days on rotate (`0` = always, no way to disable) |
| `PSN_METRICS_ACK_TIMEOUT`   | `5`                   | Seconds the HTTP client waits for disk ack        |
| `PSN_METRICS_TRUST_XFF`     | `0`                   | Honor `X-Forwarded-For` from a trusted proxy      |
| `PSN_METRICS_LOG_LEVEL`     | `info`                | `debug`, `info`, `warn`, `error`                  |

## Wire protocol

```
POST /mhook
Content-Type: application/json

{
  "installId":  "<uuidv4>",            // opaque, server-validated
  "appVersion": "1.4.0",                // client semver
  "platform":    "linux" | "darwin" | "win32",
  "sentAt":      "2026-01-01T00:00:00Z", // ISO 8601 from client
  "events": [
    {
      "ts":    "2026-01-01T00:00:00Z",
      "name":  "tab.open",
      "props": { "tab": "summary" }
    }
  ]
}
```

Server returns `202 Accepted` once the batch is fsynced to disk. Error
codes: `400` (bad payload), `413` (too big), `503` (queue full), `504`
(ack timeout). All responses are JSON.

`GET /healthz` returns the current queue depth, totals, and the last
client seen — useful for liveness probes and Grafana dashboards.

## On-disk layout

```
$PSN_METRICS_DATA_DIR/
├── events-2026-01-26.ndjson     # one line per event (ES-shape)
├── events-2026-01-25.ndjson.gz  # older files auto-gzipped
├── installs-2026-01-26.ndjson   # one line per install heartbeat
├── installs-2026-01-25.ndjson.gz
├── errors-2026-01-26.ndjson     # subset where event name starts with error.
├── errors-2026-01-25.ndjson.gz
├── state.json                   # totals (durable across restarts)
└── health.json                  # last-seen + unique install count
```

### NDJSON row shape

```json
{
  "@timestamp":   "2026-01-26T12:34:56.789Z",
  "received_at":  "2026-01-26T12:34:56.901Z",
  "client_ip":    "203.0.113.42",
  "install_id":   "01234567-89ab-cdef-0123-456789abcdef",
  "app_version":  "1.4.0",
  "platform":     "linux",
  "event":        "tab.open",
  "props":        { "tab": "summary" },
  "host":         "metrics-01"
}
```

The `@timestamp` field is the canonical ES/Graylog timestamp; the row is
already single-line JSON, so any shipper can index it as-is.

## Shipping into aggregators

### ElasticSearch (via Filebeat)

```yaml
# filebeat.yml
filebeat.inputs:
  - type: filestream
    id: packetsnitch-metrics
    paths:
      - /var/lib/packetsnitch/metrics/events-*.ndjson*
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
    fields:
      dataset: packetsnitch.metrics
    fields_under_root: true
output.elasticsearch:
  hosts: ["https://es.internal:9200"]
  index: "psn-metrics-%{+yyyy.MM.dd}"
```

### Graylog (built-in "JSON file" input)

Point a Graylog JSON-file input at the directory and set
`JSON keys: @timestamp,event,props,install_id,...` — the server already
shapes rows for it. Add an extractor for `event` to split by `.` so
`tab.open` becomes a structured field.

### Vector

```toml
[sources.psn]
type = "file"
include = ["/var/lib/packetsnitch/metrics/events-*.ndjson*"]
data_dir = "/var/lib/vector"

[transforms.parsed]
type = "remap"
inputs = ["psn"]
source = '''
. = parse_json!(.message)
'''

[sinks.es]
type = "elasticsearch"
inputs = ["parsed"]
endpoints = ["https://es.internal:9200"]
index = "psn-metrics-%Y.%m.%d"
```

## Property allow-list (defence in depth)

The renderer applies an allow-list before sending (`SAFE_PROP_KEYS` in
`src/metrics.js`). The server re-validates with the same list so a custom
client build with the sanitiser stripped cannot poison the data:

`tab`, `subtab`, `source`, `bytes`, `resultCount`, `model`, `ok`,
`durationMs`, `kind`, `context`, `action`, `protocol`, `resetToDefaults`,
`capability`, `okCount`, `failCount`, `evictedCount`

Anything else is silently dropped server-side. Event names are validated
against `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$`.

## Testing

```bash
python3 -m unittest tests/test_metrics_server.py -v
```

The tests are stdlib-only, run in-process, and cover:

- Property + event name sanitisation
- Sink persistence (events, errors, installs, state, health)
- Daily rotation and gzip compaction
- HTTP edge cases (400/404/413/503/504)
- Concurrent client writes
- X-Forwarded-For trust when behind a proxy

## Production notes

- The server is `ThreadingHTTPServer`-based. Disk writes are serialised
  through a single writer thread that drains a bounded `deque`, which
  keeps the in-flight count trivially observable for `/healthz`.
- Every accepted batch is `fsync`'d before the HTTP 202 is returned. A
  kernel-level crash cannot lose a confirmed batch.
- The server never reads NDJSON files back; it only appends. All
  ingestion happens through Filebeat/Vector/your shipper of choice.
- Set `PSN_METRICS_TRUST_XFF=1` only when behind a reverse proxy that
  strips client-supplied `X-Forwarded-For` from external traffic.
- Client disconnects (TCP reset, broken pipe, idle NAT timeouts) are
  swallowed in `MetricsRequestHandler.handle` and logged at debug level
  so a noisy scanner doesn't fill the supervisor's stderr.

## Running under systemd

The unit file ships next to the server at
`src/metrics/packetsnitch-metrics.service`. It is intentionally
parameterised — every value the operator is expected to override is
flagged with an `; EDIT N —` comment block inside the file. The same
unit works for both a per-user daemon and a system-wide install.

```bash
# Per-user install. The unit is parameterised so the defaults can be
# used as-is once the data dir exists.
install -d -m 0755 ~/.local/share/packetsnitch/metrics
mkdir -p ~/.config/systemd/user
cp src/metrics/packetsnitch-metrics.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now packetsnitch-metrics

# Status + tail the journal.
systemctl --user status packetsnitch-metrics
journalctl --user -u packetsnitch-metrics -f

# Health probe.
curl -s http://127.0.0.1:8088/healthz | jq
```

To make the service survive logout, enable lingering once:

```bash
sudo loginctl enable-linger "$USER"
```

For a system-wide install, copy the unit to
`/etc/systemd/system/packetsnitch-metrics.service`, walk through the
`EDIT` blocks in the file to switch the paths and user, then reload:

```bash
sudo cp src/metrics/packetsnitch-metrics.service \
        /etc/systemd/system/packetsnitch-metrics.service
# Open the file and update EDIT 2 (running user), EDIT 4 (data dir)
# and EDIT 6/8 (interpreter + filesystem paths) to point at the
# service account's home and data dir, e.g. /var/lib/packetsnitch.
sudo install -d -o packetsnitch -g packetsnitch -m 0750 \
        /var/lib/packetsnitch/metrics
sudo install -d -o packetsnitch -g packetsnitch -m 0755 \
        /var/lib/packetsnitch/app
sudo systemctl daemon-reload
sudo systemctl enable --now packetsnitch-metrics
```
