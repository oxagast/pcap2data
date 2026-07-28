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
# Default port 8088, data dir ./var/metrics, config /etc/ps-metrics.yaml
# (or ./ps-metrics.yaml if no /etc file is present).
python3 src/metrics/ps-metrics.py

# See the merged config (secrets redacted; safe to share).
python3 src/metrics/ps-metrics.py --print-config

# Write a fully-commented starter config and exit.
python3 src/metrics/ps-metrics.py --generate-config /etc/ps-metrics.yaml

# Generate a high-entropy admin API key.
python3 src/metrics/ps-metrics.py --generate-api-key
```

The server is a normal stdlib `http.server` — run it under systemd, runit,
supervisord, Docker, or behind any reverse proxy (nginx, Caddy, Traefik).

## Configuration

The canonical config file is `/etc/ps-metrics.yaml`. Any key there can be
overridden by a `PSN_METRICS_<KEY>` environment variable (e.g.
`PSN_METRICS_PORT=9000` overrides `server.port`). The precedence is, from
highest to lowest:

1. `PSN_METRICS_*` environment variables
2. `--config <path>` CLI flag (or `PSN_METRICS_CONFIG`)
3. `/etc/ps-metrics.yaml`
4. `$XDG_CONFIG_HOME/ps-metrics.yaml` (or `~/.config/ps-metrics.yaml`)
5. `./ps-metrics.yaml` in the current working directory
6. Built-in defaults

The shipped example (`src/metrics/ps-metrics.yaml.example`) documents every
key. The three top-level sections are:

| Section   | Keys                                                            |
| --------- | --------------------------------------------------------------- |
| `server`  | `host`, `port`, `log_level`, `trust_xff`                        |
| `storage` | `data_dir`, `max_body`, `max_queue`, `gzip_after_days`, `ack_timeout_seconds` |
| `admin`   | `api_key`, `list_limit`                                         |

The `admin.api_key` value is a high-entropy shared secret. Leave it
empty to disable the admin endpoints entirely (they will return 404 in
that mode). Generate one with `ps-metrics.py --generate-api-key`.

### Legacy env vars

A few settings retain their old single-name env vars for backwards
compatibility. They map to the YAML keys below:

| Env var                       | YAML key                       |
| ----------------------------- | ------------------------------ |
| `PSN_METRICS_DATA_DIR`        | `storage.data_dir`             |
| `PSN_METRICS_MAX_BODY`        | `storage.max_body`             |
| `PSN_METRICS_MAX_QUEUE`       | `storage.max_queue`            |
| `PSN_METRICS_GZIP_OLD`        | `storage.gzip_after_days`      |
| `PSN_METRICS_ACK_TIMEOUT`     | `storage.ack_timeout_seconds`  |
| `PSN_METRICS_API_KEY`         | `admin.api_key`                |
| `PSN_METRICS_LIST_LIMIT`      | `admin.list_limit`             |

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

## Talking to the endpoint with curl

The server is a plain HTTP/1.1 socket, so any HTTP client works. The
recipes below assume the server is running locally on `127.0.0.1:8088`
and that an admin API key has been written into `/etc/ps-metrics.yaml`
as `admin.api_key`. Replace the host/port/key to match your install.

### Submit a batch

```bash
curl -sS -X POST http://127.0.0.1:8088/mhook \
    -H 'Content-Type: application/json' \
    --data-binary '{
  "installId": "01234567-89ab-cdef-0123-456789abcdef",
  "appVersion": "1.4.0",
  "platform": "linux",
  "sentAt": "2026-07-28T12:00:00Z",
  "events": [
    { "ts": "2026-07-28T12:00:00Z", "name": "tab.open",
      "props": { "tab": "summary" } },
    { "ts": "2026-07-28T12:00:01Z", "name": "filter.apply",
      "props": { "ok": true, "durationMs": 12.5 } }
  ]
}'
# {"status":"accepted","events":2}
```

A successful response is `202 Accepted`:

```bash
curl -sS -o /dev/null -w "%{http_code}\n" -X POST \
    http://127.0.0.1:8088/mhook \
    -H 'Content-Type: application/json' \
    --data-binary '{"installId":"01234567-89ab-cdef-0123-456789abcdef","appVersion":"1.4.0","platform":"linux","sentAt":"2026-07-28T12:00:00Z","events":[]}'
# 202
```

### Healthz (no auth required)

```bash
curl -sS http://127.0.0.1:8088/healthz | jq
# {
#   "uptime_s": 1234,
#   "queue_depth": 0,
#   "totals": {
#     "events": 42,
#     "installs": 7,
#     "errors": 1,
#     "batches": 5,
#     "rejected": 0
#   },
#   "unique_installs": 7,
#   "last_client_at": "2026-07-28T12:00:00Z",
#   "last_client_ip": "203.0.113.42"
# }
```

Use it as a Kubernetes / systemd liveness probe:

```yaml
# pod spec
livenessProbe:
  httpGet: { path: /healthz, port: 8088 }
  periodSeconds: 30
```

### Admin endpoints (behind the API key)

The three `/admin/*` routes are gated by `X-Admin-Key` (or
`Authorization: Bearer ...`). All three return JSON. Send the key via
either header — neither is preferred, pick whichever fits your tooling.

```bash
ADMIN_KEY='KEYGOESHERE'  # from --generate-api-key

# Aggregated counters + queue depth + uptime.
curl -sS -H "X-Admin-Key: $ADMIN_KEY" \
    http://127.0.0.1:8088/admin/stats | jq

# Last 100 install heartbeats (cap with ?limit=N up to 1000).
curl -sS -H "X-Admin-Key: $ADMIN_KEY" \
    'http://127.0.0.1:8088/admin/installs?limit=20' | jq

# Last 100 error.* events. Same limit parameter.
curl -sS -H "X-Admin-Key: $ADMIN_KEY" \
    'http://127.0.0.1:8088/admin/errors?limit=50' | jq

# Bearer form is equivalent.
curl -sS -H "Authorization: Bearer $ADMIN_KEY" \
    http://127.0.0.1:8088/admin/stats | jq
```

Without a key you get a 401:

```bash
curl -sS -o /dev/null -w "%{http_code}\n" \
    http://127.0.0.1:8088/admin/stats
# 401
```

If `admin.api_key` is empty in the config, the endpoints are turned off
entirely and return 404 — so a typo will never silently expose admin
data:

```bash
curl -sS -o /dev/null -w "%{http_code}\n" \
    -H "X-Admin-Key: $ADMIN_KEY" \
    http://127.0.0.1:8088/admin/stats
# 404
```

### One-liner smoke test

After a fresh install, run the whole loop in one shell:

```bash
ADMIN_KEY="$(python3 src/metrics/ps-metrics.py --generate-api-key)"
echo "admin.api_key: \"$ADMIN_KEY\"" >> /etc/ps-metrics.yaml
sudo systemctl restart packetsnitch-metrics

curl -sS http://127.0.0.1:8088/healthz | jq
curl -sS -X POST http://127.0.0.1:8088/mhook \
    -H 'Content-Type: application/json' \
    -d '{"installId":"01234567-89ab-cdef-0123-456789abcdef","appVersion":"1.4.0","platform":"linux","sentAt":"2026-07-28T12:00:00Z","events":[]}'
curl -sS -H "X-Admin-Key: $ADMIN_KEY" http://127.0.0.1:8088/admin/stats | jq
```

### curl flags worth knowing

| Flag                       | Why                                                      |
| -------------------------- | -------------------------------------------------------- |
| `--data-binary @file.json` | Send a batch from disk without shell quoting headaches.  |
| `-w "\n%{http_code}\n"`    | Print the status code after the body for quick checks.   |
| `--max-time 5`             | Cap the request so a stuck server can't hang your script. |
| `-H 'X-Forwarded-For: ...'`| Test `trust_xff: true` behaviour without a real proxy.   |

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
.venv/bin/python -m pytest tests/test_metrics_server.py -v
```

The tests are stdlib-only, run in-process, and cover:

- Property + event name sanitisation
- Sink persistence (events, errors, installs, state, health)
- Daily rotation and gzip compaction
- HTTP edge cases (400/404/413/503/504)
- Concurrent client writes
- X-Forwarded-For trust when behind a proxy
- Dropped-connection teardown (`ConnectionResetError`, broken pipe)
- YAML config loader, env-var precedence, and `/admin/*` auth gating

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
flagged with an `; EDIT` comment block inside the file. The same
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

For a system-wide install, use the helper script — it lays down the
binary, the unit, the `/etc/ps-metrics.yaml` starter config, and an
admin API key in one shot:

```bash
sudo scripts/install-metrics.sh
sudo journalctl -u packetsnitch-metrics -f
curl -s http://127.0.0.1:8088/healthz | jq
```

If you'd rather drive the install by hand, copy the unit to
`/etc/systemd/system/packetsnitch-metrics.service`, walk through the
`EDIT` blocks in the file to switch the paths and user, then reload:

```bash
sudo cp src/metrics/packetsnitch-metrics.service \
        /etc/systemd/system/packetsnitch-metrics.service
# Open the file and update EDIT 1 (running user), EDIT 2 (config
# path) and EDIT 3 (data dir) to point at the service account's
# home and data dir, e.g. /var/lib/packetsnitch.
sudo install -d -o packetsnitch -g packetsnitch -m 0750 \
        /var/lib/packetsnitch/metrics
sudo install -d -o packetsnitch -g packetsnitch -m 0755 \
        /var/lib/packetsnitch/app
sudo systemctl daemon-reload
sudo systemctl enable --now packetsnitch-metrics
```

The unit reads its settings from `/etc/ps-metrics.yaml`. Override any
single key by exporting a matching `PSN_METRICS_*` env var inside the
unit, or by passing `--config /path/to/other.yaml` to `ExecStart`.
See [Configuration](#configuration) above for the full precedence
list.
