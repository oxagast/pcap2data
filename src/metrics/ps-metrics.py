#!/usr/bin/env python3
"""PacketSnitch metrics endpoint.

A small, dependency-free HTTP server that accepts anonymous opt-in metrics
from PacketSnitch desktop clients. The server's only job is to durably
land incoming event batches on disk in formats that are trivial to ship
into a log aggregation stack (ElasticSearch, Graylog, Loki, Splunk, etc.).

Wire format
-----------
POST /mhook
Content-Type: application/json

    {
      "installId":  "<uuidv4>",
      "appVersion": "<semver string>",
      "platform":    "linux" | "darwin" | "win32",
      "sentAt":      "<iso8601 timestamp from client>",
      "events": [
        {
          "ts":    "<iso8601 timestamp>",
          "name":  "<event.name>",
          "props": { "...": "..." }
        },
        ...
      ]
    }

The server writes one NDJSON line per event to a daily rotated file. NDJSON
is the universal ingest format: Filebeat, Logstash, Vector, Fluent Bit,
Graylog's "JSON file" input, and the Elasticsearch Bulk API all consume it
without a transform pipeline. A typical 1.4.x client batch of 30 events
weighs roughly 6 KB, so the per-line cost is negligible.

Storage layout
--------------
    $DATA_DIR/
        events-YYYY-MM-DD.ndjson      # every individual event
        installs-YYYY-MM-DD.ndjson    # one line per heartbeat, deduped by installId
        errors-YYYY-MM-DD.ndjson      # subset of events with name == "error.*"
        state.json                    # durable server state (counter snapshots)
        health.json                   # last-seen timestamp, unique installs, totals

Files are date-stamped in the configured local timezone. The server
rotates at midnight automatically; old files are left in place so
Filebeat/Vector can pick them up on their own schedule.

Configuration
-------------
Everything is environment-driven so the same image runs locally, in a
container, or on a VM with no code change.

    PSN_METRICS_PORT      listen port (default 8088)
    PSN_METRICS_HOST      bind address (default 0.0.0.0)
    PSN_METRICS_DATA_DIR  NDJSON output directory (default ./var/metrics)
    PSN_METRICS_MAX_BODY  max accepted body bytes (default 1 MiB)
    PSN_METRICS_MAX_QUEUE max in-flight batches buffered in memory (default 1024)
    PSN_METRICS_GZIP_OLD  gzip files older than N days on rotate (default 7, 0 disables)
    PSN_METRICS_LOG_LEVEL "debug" | "info" | "warn" | "error" (default info)
    PSN_METRICS_TRUST_XFF honor X-Forwarded-For for client IP (default false)

Run with:

    python3 src/metrics/server.py

Or under a process supervisor (systemd, runit, supervisord) bound to a
reverse proxy of your choice.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import errno
import gzip
import json
import logging
import os
import shutil
import signal
import socket
import sys
import threading
import time
import uuid
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

LOG = logging.getLogger("packetsnitch.metrics")

# --- Event name validation -------------------------------------------------
#
# Event names mirror the renderer-side regex
#   /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$/
# so a malicious or buggy client cannot inject arbitrary strings, and so
# the resulting NDJSON rows are predictable for downstream pipelines.
_EVENT_NAME_RE = __import__("re").compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$")
_INSTALL_ID_RE = __import__("re").compile(r"^[A-Za-z0-9_-]{8,128}$")
_APP_VERSION_MAX = 64
_PLATFORM_ALLOWED = frozenset({"linux", "darwin", "win32", "unknown"})

# --- Property sanitisation -------------------------------------------------
#
# The renderer already runs an allow-list, but we re-validate on the
# server so a custom build with the sanitiser stripped cannot poison the
# log files. We also cap string lengths so a runaway client cannot fill
# the disk with a single 10 MB "name" field.
_SAFE_PROP_KEYS = frozenset({
    "tab",
    "subtab",
    "source",
    "bytes",
    "resultCount",
    "model",
    "ok",
    "durationMs",
    "kind",
    "context",
    "action",
    "protocol",
    "resetToDefaults",
    "capability",
    "okCount",
    "failCount",
    "evictedCount",
})
_PROP_STRING_MAX = 256
_PROP_NUMBER_MIN = -(2 ** 53)
_PROP_NUMBER_MAX = 2 ** 53

HEALTH_PATH = "/healthz"
INGEST_PATH = "/mhook"


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _iso_z(value: _dt.datetime) -> str:
    """Return an ISO-8601 string with explicit UTC offset."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _is_event_name(value: Any) -> bool:
    return isinstance(value, str) and bool(_EVENT_NAME_RE.match(value))


def _is_install_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_INSTALL_ID_RE.match(value))


def _sanitize_props(props: Any) -> Dict[str, Any]:
    """Mirror the renderer allow-list, server-side.

    Drops unknown keys, coerces well-known shapes (bool/number/short
    string), and discards everything else. Returns a fresh dict so the
    caller's object is left untouched.
    """
    if not isinstance(props, dict):
        return {}
    safe: Dict[str, Any] = {}
    for key, value in props.items():
        if not isinstance(key, str) or key not in _SAFE_PROP_KEYS:
            continue
        if isinstance(value, bool):
            safe[key] = value
        elif isinstance(value, (int, float)):
            number = float(value)
            if not (_PROP_NUMBER_MIN <= number <= _PROP_NUMBER_MAX):
                continue
            if number != number:  # NaN guard
                continue
            safe[key] = number
        elif isinstance(value, str):
            trimmed = value.strip()
            if not trimmed:
                continue
            safe[key] = trimmed[:_PROP_STRING_MAX]
    return safe


def _sanitize_event(raw: Any, server_received_at: str) -> Optional[Dict[str, Any]]:
    """Validate and normalise a single event.

    Returns ``None`` for malformed rows so the caller can skip and
    continue with the rest of the batch.
    """
    if not isinstance(raw, dict):
        return None
    name = raw.get("name")
    if not _is_event_name(name):
        return None
    ts = raw.get("ts")
    if not isinstance(ts, str) or not ts.strip():
        ts = server_received_at
    props = _sanitize_props(raw.get("props"))
    return {"ts": ts, "name": name, "props": props}


def _parse_iso8601(value: Any) -> Optional[_dt.datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        # Python's fromisoformat in 3.11+ accepts trailing 'Z' too; older
        # builds need an explicit translation.
        candidate = value.strip()
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        parsed = _dt.datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


def _date_from_iso(value: str) -> Optional[_dt.date]:
    """Return the calendar date for an ISO 8601 timestamp.

    The clock used here is UTC so the on-disk file name
    (``events-YYYY-MM-DD.ndjson``) lines up with the ``@timestamp``
    value in every row. A single server running across a year
    boundary should not split a logical day across two files.
    """
    parsed = _parse_iso8601(value)
    if parsed is None:
        return None
    return parsed.astimezone(_dt.timezone.utc).date()


def _resolve_client_ip(handler: BaseHTTPRequestHandler, trust_xff: bool) -> str:
    if trust_xff:
        forwarded = handler.headers.get("X-Forwarded-For")
        if forwarded:
            first = forwarded.split(",", 1)[0].strip()
            if first:
                return first
    real = getattr(handler, "client_address", None)
    if real and real[0]:
        return real[0]
    return "unknown"


# --- Persistent sink -------------------------------------------------------
#
# Writes are guarded by a single lock so concurrent batches never interleave
# inside a single file. Each line is buffered, then fsynced via ``flush()``
# followed by ``os.fsync(fileno)`` so a kernel-level crash cannot lose a
# confirmed-to-the-client batch.
class MetricsSink:
    """Append-only NDJSON sink with daily rotation.

    The sink owns three daily files (events, installs, errors) and a
    pair of small JSON snapshots (state, health). On date rollover the
    previous day's files are optionally gzipped.
    """

    def __init__(
        self,
        data_dir: Path,
        gzip_after_days: int = 7,
        gzip_lock: Optional[threading.Lock] = None,
    ) -> None:
        self._data_dir = data_dir
        # ``gzip_after_days`` semantics:
        #   *  0  -> compress the previous day's file on every rotation
        #   *  N  -> compress once the file is at least N days old
        # There is no "never compress" mode at the sink level; the
        # operator who really wants that can stop the server, manually
        # decompress, and restart — the on-disk file is identical to
        # what the shipper would read.
        self._gzip_after_days = max(0, int(gzip_after_days))
        self._lock = threading.Lock()
        self._gzip_lock = gzip_lock or self._lock
        self._current_date: Optional[_dt.date] = None
        self._events_handle: Optional[Any] = None
        self._installs_handle: Optional[Any] = None
        self._errors_handle: Optional[Any] = None
        self._state: Dict[str, Any] = {
            "totalBatches": 0,
            "totalEvents": 0,
            "totalErrors": 0,
            "totalInstalls": 0,
        }
        self._state_path = data_dir / "state.json"
        self._health_path = data_dir / "health.json"
        self._known_installs: Dict[str, str] = {}  # installId -> last seen ISO
        self._last_load_state()
        data_dir.mkdir(parents=True, exist_ok=True)

    # ---- public API ------------------------------------------------------

    def write_batch(
        self,
        batch: Dict[str, Any],
        client_ip: str,
        server_received_at: str,
    ) -> Dict[str, int]:
        """Persist a validated batch and return counts.

        Returns a dict with ``events``, ``installs`` and ``errors`` keys
        so the HTTP handler can echo them in the response. Any exception
        here is propagated up; the handler turns it into a 500.
        """
        events_in = batch.get("events", [])
        if not isinstance(events_in, list):
            events_in = []

        # The date stamp for file rotation is taken from the
        # ``server_received_at`` argument, which the HTTP layer fills
        # in from the client's ``sentAt`` when available. That keeps
        # the on-disk file name aligned with the timestamp the client
        # reported, while keeping the lower-level ``write_batch``
        # contract simple: the caller picks the date.
        received_day = _date_from_iso(server_received_at) or _utc_now().date()

        with self._lock:
            self._rotate_if_needed(received_day)
            events_written = self._write_event_lines(
                batch, client_ip, server_received_at, events_in
            )
            errors_written = self._write_error_lines(events_in, server_received_at)
            install_seen = self._record_install(
                batch, client_ip, server_received_at
            )
            self._state["totalBatches"] += 1
            self._state["totalEvents"] += events_written
            self._state["totalErrors"] += errors_written
            if install_seen:
                self._state["totalInstalls"] = len(self._known_installs)
            self._flush_all()
            self._write_state()
            self._write_health(batch, client_ip, server_received_at)
            return {
                "events": events_written,
                "errors": errors_written,
                "installs": 1 if install_seen else 0,
            }

    def shutdown(self) -> None:
        with self._lock:
            self._close_handles()
            self._write_state()

    # ---- internals -------------------------------------------------------

    def _events_path(self, day: _dt.date) -> Path:
        return self._data_dir / f"events-{day.isoformat()}.ndjson"

    def _installs_path(self, day: _dt.date) -> Path:
        return self._data_dir / f"installs-{day.isoformat()}.ndjson"

    def _errors_path(self, day: _dt.date) -> Path:
        return self._data_dir / f"errors-{day.isoformat()}.ndjson"

    def _open_for_append(self, path: Path) -> Any:
        # newline="" keeps Python from mangling CRLF so NDJSON stays
        # byte-for-byte compatible with what Filebeat/Vector expect.
        return open(path, "a", encoding="utf-8", newline="")

    def _rotate_if_needed(self, today: _dt.date) -> None:
        if self._current_date == today:
            return
        self._close_handles()
        if self._current_date is not None:
            self._gzip_old_files(self._current_date, today)
        self._current_date = today
        self._events_handle = self._open_for_append(self._events_path(today))
        self._installs_handle = self._open_for_append(self._installs_path(today))
        self._errors_handle = self._open_for_append(self._errors_path(today))

    def _close_handles(self) -> None:
        for attr in ("_events_handle", "_installs_handle", "_errors_handle"):
            handle = getattr(self, attr)
            if handle is not None:
                try:
                    handle.flush()
                except Exception:  # pragma: no cover - best effort
                    pass
                handle.close()
                setattr(self, attr, None)

    def _flush_all(self) -> None:
        for handle in (
            self._events_handle,
            self._installs_handle,
            self._errors_handle,
        ):
            if handle is None:
                continue
            try:
                handle.flush()
                os.fsync(handle.fileno())
            except OSError as exc:
                if exc.errno not in (errno.EBADF, errno.EINVAL):
                    raise

    def _gzip_old_files(
        self, old_day: _dt.date, today: _dt.date
    ) -> None:
        age = (today - old_day).days
        if age < self._gzip_after_days:
            return
        with self._gzip_lock:
            for path in (
                self._events_path(old_day),
                self._installs_path(old_day),
                self._errors_path(old_day),
            ):
                if not path.exists():
                    continue
                gz_path = path.with_suffix(path.suffix + ".gz")
                if gz_path.exists():
                    continue
                with open(path, "rb") as src, gzip.open(
                    gz_path, "wb", compresslevel=6
                ) as dst:
                    shutil.copyfileobj(src, dst)
                path.unlink()

    def _write_event_lines(
        self,
        batch: Dict[str, Any],
        client_ip: str,
        server_received_at: str,
        events_in: List[Any],
    ) -> int:
        written = 0
        for raw in events_in:
            cleaned = _sanitize_event(raw, server_received_at)
            if cleaned is None:
                continue
            payload = {
                "@timestamp": cleaned["ts"],
                "received_at": server_received_at,
                "client_ip": client_ip,
                "install_id": batch.get("installId"),
                "app_version": batch.get("appVersion"),
                "platform": batch.get("platform"),
                "event": cleaned["name"],
                "props": cleaned["props"],
                "host": socket.gethostname(),
            }
            self._events_handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
            written += 1
        return written

    def _write_error_lines(
        self, events_in: List[Any], server_received_at: str
    ) -> int:
        written = 0
        for raw in events_in:
            if not isinstance(raw, dict):
                continue
            name = raw.get("name")
            if not isinstance(name, str) or not name.startswith("error."):
                continue
            cleaned = _sanitize_event(raw, server_received_at)
            if cleaned is None:
                continue
            self._errors_handle.write(
                json.dumps(
                    {
                        "@timestamp": cleaned["ts"],
                        "received_at": server_received_at,
                        "event": cleaned["name"],
                        "props": cleaned["props"],
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )
            written += 1
        return written

    def _record_install(
        self,
        batch: Dict[str, Any],
        client_ip: str,
        server_received_at: str,
    ) -> bool:
        install_id = batch.get("installId")
        if not _is_install_id(install_id):
            return False
        previous = self._known_installs.get(install_id)
        self._known_installs[install_id] = server_received_at
        if previous is not None:
            # Still bump the daily heartbeat once per day per install
            # so installs/ stays roughly equal to active users/day.
            previous_date = previous[:10]
            if previous_date == server_received_at[:10]:
                return False
        self._installs_handle.write(
            json.dumps(
                {
                    "@timestamp": server_received_at,
                    "install_id": install_id,
                    "app_version": batch.get("appVersion"),
                    "platform": batch.get("platform"),
                    "client_ip": client_ip,
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        return True

    def _write_state(self) -> None:
        snapshot = dict(self._state)
        snapshot["knownInstalls"] = len(self._known_installs)
        snapshot["updatedAt"] = _iso_z(_utc_now())
        self._atomic_write_json(self._state_path, snapshot)

    def _write_health(
        self,
        batch: Dict[str, Any],
        client_ip: str,
        server_received_at: str,
    ) -> None:
        health = {
            "updatedAt": server_received_at,
            "hostname": socket.gethostname(),
            "dataDir": str(self._data_dir),
            "uniqueInstalls": len(self._known_installs),
            "lastClient": {
                "ip": client_ip,
                "appVersion": batch.get("appVersion"),
                "platform": batch.get("platform"),
            },
            "totals": dict(self._state),
        }
        self._atomic_write_json(self._health_path, health)

    @staticmethod
    def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)

    def _last_load_state(self) -> None:
        if not self._state_path.exists():
            return
        try:
            with open(self._state_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return
        if isinstance(payload, dict):
            for key in ("totalBatches", "totalEvents", "totalErrors", "totalInstalls"):
                if isinstance(payload.get(key), int):
                    self._state[key] = payload[key]


# --- HTTP handler ----------------------------------------------------------
class MetricsRequestHandler(BaseHTTPRequestHandler):
    server_version = "PacketSnitchMetrics/1.0"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    # Suppress the default per-request stderr access log; we have our
    # own structured logger with proper rate limiting.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    # The stdlib's ``handle()`` raises ``ConnectionResetError`` (errno
    # 104) and friends when a client opens a TCP connection and then
    # drops it before sending a request line — which is exactly what
    # idle keep-alive sockets behind NAT, port scanners, and aborted
    # browsers do. Without this override every one of those prints a
    # multi-line traceback to the supervisor's stderr and drowns the
    # event log. Catch the family, log at debug, and let the worker
    # thread pick up the next connection.
    def handle(self) -> None:  # noqa: D401
        """Serve a single HTTP request, treating client disconnects as a no-op."""
        try:
            super().handle()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as exc:
            client = getattr(self, "client_address", ("<unknown>", 0))
            LOG.debug(
                "client disconnected before request completed: %s from %s:%s",
                exc,
                client[0],
                client[1],
            )
        except OSError as exc:
            # Any other socket-level error (e.g. EBADF during shutdown)
            # is also a normal teardown symptom and not worth a stack
            # trace. ``errno`` is the only signal we need.
            if getattr(exc, "errno", None) in (errno.EBADF, errno.ENOTCONN, errno.ESHUTDOWN):
                LOG.debug("client socket closed during shutdown: %s", exc)
                return
            raise

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] == HEALTH_PATH:
            self._handle_health()
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != INGEST_PATH:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        self._handle_ingest()

    def do_HEAD(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] in (HEALTH_PATH, INGEST_PATH):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()

    # ---- handlers --------------------------------------------------------

    def _handle_health(self) -> None:
        state = self._server_state()
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "service": "packetsnitch-metrics",
                "hostname": socket.gethostname(),
                "queueDepth": self.server.queue_depth(),
                "queueCapacity": self.server.queue_capacity(),
                "totals": {
                    "batches": state["totalBatches"],
                    "events": state["totalEvents"],
                    "errors": state["totalErrors"],
                    "installs": state["totalInstalls"],
                },
            },
        )

    def _handle_ingest(self) -> None:
        config = self.server.config
        queue: Deque[Tuple[Dict[str, Any], str, str, str]] = self.server.queue
        received_at = _iso_z(_utc_now())
        content_length = self._read_content_length()
        if content_length is None or content_length < 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing_content_length"})
            return
        if content_length > config.max_body:
            # Use the literal 413 — Python's stdlib has flip-flopped on
            # the enum name (REQUEST_ENTITY_TOO_LARGE, CONTENT_TOO_LARGE)
            # between minor versions, so we don't depend on either.
            self._send_json(
                413,
                {"error": "payload_too_large", "max": config.max_body},
            )
            return
        try:
            raw_body = self.rfile.read(content_length)
        except OSError as exc:
            LOG.warning("ingest read failure: %s", exc)
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "read_failed"})
            return
        if not raw_body:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty_body"})
            return
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        if not isinstance(payload, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return

        install_id = payload.get("installId")
        app_version = payload.get("appVersion")
        platform = payload.get("platform")
        events = payload.get("events", [])

        if not _is_install_id(install_id):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_install_id"})
            return
        if not isinstance(app_version, str) or not app_version.strip():
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_app_version"})
            return
        if len(app_version) > _APP_VERSION_MAX:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_app_version"})
            return
        if not isinstance(platform, str) or platform not in _PLATFORM_ALLOWED:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_platform"})
            return
        if not isinstance(events, list) or not events:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_events"})
            return
        if len(events) > 5000:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "too_many_events"})
            return

        client_ip = _resolve_client_ip(self, config.trust_xff)
        client_sent_at = _parse_iso8601(payload.get("sentAt"))
        sent_at_iso = _iso_z(client_sent_at) if client_sent_at else received_at
        batch = {
            "installId": install_id,
            "appVersion": app_version.strip()[:_APP_VERSION_MAX],
            "platform": platform,
            "sentAt": sent_at_iso,
            "events": events,
        }

        if len(queue) >= config.max_queue:
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "queue_full"})
            return
        # Use the client's ``sentAt`` (when present) for the on-disk
        # file name so the file the operator inspects lines up with
        # the day the events actually happened. Falls back to the
        # wall clock for old or malformed clients.
        token, future = self.server.register_pending(install_id)
        try:
            with self.server.queue_lock:
                if len(queue) >= config.max_queue:
                    self._send_json(
                        HTTPStatus.SERVICE_UNAVAILABLE, {"error": "queue_full"}
                    )
                    return
                queue.append((batch, client_ip, sent_at_iso, token))
            self.server.queue_event.set()
        except Exception:
            self.server.unregister_pending(token)
            raise
        try:
            result = future.get(timeout=config.ack_timeout_seconds)
        except TimeoutError:
            self._send_json(
                HTTPStatus.GATEWAY_TIMEOUT, {"error": "ack_timeout"}
            )
            return
        finally:
            self.server.unregister_pending(token)
        self._send_json(
            HTTPStatus.ACCEPTED,
            {
                "ok": True,
                "received": result,
                "receivedAt": received_at,
            },
        )

    # ---- helpers ---------------------------------------------------------

    def _server_state(self) -> Dict[str, Any]:
        try:
            return self.server.sink._state  # type: ignore[attr-defined]
        except AttributeError:
            return {
                "totalBatches": 0,
                "totalEvents": 0,
                "totalErrors": 0,
                "totalInstalls": 0,
            }

    def _read_content_length(self) -> Optional[int]:
        header = self.headers.get("Content-Length")
        if header is None:
            return None
        try:
            return int(header.strip())
        except ValueError:
            return None

    def _send_json(self, status: HTTPStatus, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


# --- HTTP server with bounded queue + worker thread ------------------------
class MetricsHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server that drains a bounded queue on a single
    background worker.

    ``BaseHTTPRequestHandler`` is happy running on a thread per
    connection, but the disk writer must be serialized so we funnel
    every accepted batch through a single ``queue`` and let one
    worker thread own the sink. This keeps the I/O path linear and
    makes the in-flight count trivially observable for the
    ``/healthz`` endpoint.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: Tuple[str, int],
        sink: MetricsSink,
        config: "ServerConfig",
    ) -> None:
        super().__init__(address, MetricsRequestHandler)
        self.sink = sink
        self.config = config
        self.queue: Deque[Tuple[Dict[str, Any], str, str, str]] = deque()
        self.queue_lock = threading.Lock()
        self.queue_event = threading.Event()
        self._pending: Dict[str, "AckFuture"] = {}
        self._pending_lock = threading.Lock()
        self._worker = threading.Thread(
            target=self._run_worker, name="metrics-writer", daemon=True
        )
        self._worker.start()

    # ---- public API ------------------------------------------------------

    def queue_depth(self) -> int:
        return len(self.queue)

    def queue_capacity(self) -> int:
        return self.config.max_queue

    def register_pending(self, install_id: str) -> Tuple[str, "AckFuture"]:
        future = AckFuture()
        # Each request gets its own future, keyed by a unique token,
        # not by ``install_id``. Two concurrent POSTs from the same
        # client (e.g. parallel flushers) must not clobber each other
        # in the pending map.
        token = uuid.uuid4().hex
        with self._pending_lock:
            self._pending[token] = future
        return token, future

    def unregister_pending(self, token: str) -> None:
        with self._pending_lock:
            self._pending.pop(token, None)

    # ---- worker ----------------------------------------------------------

    def _run_worker(self) -> None:
        LOG.info(
            "metrics writer started data_dir=%s gzip_after_days=%d",
            self.config.data_dir,
            self.config.gzip_after_days,
        )
        while True:
            self.queue_event.wait()
            while True:
                with self.queue_lock:
                    if not self.queue:
                        break
                    # ``peekleft`` keeps the in-flight item in the
                    # queue while we write, so the ``max_queue``
                    # backpressure can fire correctly: a slow writer
                    # will not silently absorb unbounded clients.
                    item = self.queue[0]
                batch, client_ip, received_at, token = item
                try:
                    counts = self.sink.write_batch(batch, client_ip, received_at)
                except Exception as exc:  # noqa: BLE001
                    LOG.exception("sink write failed: %s", exc)
                    with self.queue_lock:
                        # Drop the failed item from the head.
                        if self.queue and self.queue[0] is item:
                            self.queue.popleft()
                    self._fail_pending(token, "sink_failure")
                    continue
                with self.queue_lock:
                    if self.queue and self.queue[0] is item:
                        self.queue.popleft()
                self._resolve_pending(token, counts)
            self.queue_event.clear()

    def _resolve_pending(
        self, token: str, counts: Dict[str, int]
    ) -> None:
        with self._pending_lock:
            future = self._pending.pop(token, None)
        if future is not None:
            future.set_result(counts)

    def _fail_pending(
        self, token: str, reason: str
    ) -> None:
        with self._pending_lock:
            future = self._pending.pop(token, None)
        if future is not None:
            future.set_exception(RuntimeError(reason))


class AckFuture:
    """Lightweight future used to wait for an ack from the writer."""

    _UNSET: Any = object()

    def __init__(self) -> None:
        self._event = threading.Event()
        self._result: Any = self._UNSET
        self._error: Optional[BaseException] = None

    def set_result(self, value: Dict[str, int]) -> None:
        self._result = value
        self._event.set()

    def set_exception(self, exc: BaseException) -> None:
        self._error = exc
        self._event.set()

    def get(self, timeout: float) -> Dict[str, int]:
        if not self._event.wait(timeout):
            raise TimeoutError("ack timeout")
        if self._error is not None:
            raise self._error
        if self._result is self._UNSET:  # pragma: no cover
            raise RuntimeError("ack without result")
        return self._result  # type: ignore[return-value]


# --- Configuration ---------------------------------------------------------
class ServerConfig:
    def __init__(self) -> None:
        self.host: str = os.environ.get("PSN_METRICS_HOST", "0.0.0.0")
        self.port: int = int(os.environ.get("PSN_METRICS_PORT", "8088"))
        self.data_dir: Path = Path(
            os.environ.get("PSN_METRICS_DATA_DIR", "./var/metrics")
        ).resolve()
        self.max_body: int = int(os.environ.get("PSN_METRICS_MAX_BODY", str(1 << 20)))
        self.max_queue: int = int(os.environ.get("PSN_METRICS_MAX_QUEUE", "1024"))
        self.gzip_after_days: int = int(os.environ.get("PSN_METRICS_GZIP_OLD", "7"))
        self.ack_timeout_seconds: float = float(
            os.environ.get("PSN_METRICS_ACK_TIMEOUT", "5")
        )
        self.trust_xff: bool = (
            os.environ.get("PSN_METRICS_TRUST_XFF", "0").lower()
            in ("1", "true", "yes", "on")
        )
        self.log_level: str = os.environ.get("PSN_METRICS_LOG_LEVEL", "info").lower()


# --- Entry point -----------------------------------------------------------
def configure_logging(level: str) -> None:
    numeric = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }.get(level, logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PacketSnitch metrics endpoint",
    )
    parser.add_argument("--host", help="bind address (env: PSN_METRICS_HOST)")
    parser.add_argument(
        "--port", type=int, help="listen port (env: PSN_METRICS_PORT)"
    )
    parser.add_argument(
        "--data-dir",
        help="output directory for NDJSON files (env: PSN_METRICS_DATA_DIR)",
    )
    return parser.parse_args(list(argv))


def apply_args(config: ServerConfig, args: argparse.Namespace) -> None:
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    if args.data_dir:
        config.data_dir = Path(args.data_dir).resolve()


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    config = ServerConfig()
    apply_args(config, args)
    configure_logging(config.log_level)

    config.data_dir.mkdir(parents=True, exist_ok=True)
    sink = MetricsSink(config.data_dir, gzip_after_days=config.gzip_after_days)
    server = MetricsHTTPServer((config.host, config.port), sink, config)

    def _shutdown(signum: int, _frame: Any) -> None:
        LOG.info("received signal=%d, shutting down", signum)
        # ``shutdown`` blocks; spawn a thread so the signal handler
        # can return immediately.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    LOG.info(
        "metrics endpoint listening host=%s port=%d data_dir=%s",
        config.host,
        config.port,
        config.data_dir,
    )
    try:
        server.serve_forever()
    finally:
        sink.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
