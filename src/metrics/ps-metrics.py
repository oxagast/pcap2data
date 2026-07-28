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
Settings can come from either a YAML file or environment variables. The
file is the canonical source; environment variables named
``PSN_METRICS_*`` override it so systemd overrides and ``--host`` work
as before.

    /etc/ps-metrics.yaml        # default location
    PSN_METRICS_CONFIG          # override the path entirely
    PSN_METRICS_PORT            # any ``PSN_METRICS_*`` env var overrides
                                # the matching config-file key

Run with:

    python3 src/metrics/ps-metrics.py
    python3 src/metrics/ps-metrics.py --print-config   # dump effective config

Or under a process supervisor (systemd, runit, supervisord) bound to a
reverse proxy of your choice.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import errno
import gzip
import hmac
import json
import logging
import os
import secrets
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

# ``main`` records the wall-clock moment it was called so the final
# ``shutdown complete`` log line can report a real uptime. Lives at
# module scope because the helper functions don't have it passed
# in. Defaulting to ``0.0`` keeps the formatter usable from any
# other entry point (e.g. tests that import ``main`` indirectly).
_startup_monotonic: float = 0.0

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
ADMIN_PREFIX = "/admin"
ADMIN_KEY_HEADER = "X-Admin-Key"
ADMIN_LIST_LIMIT_DEFAULT = 100
ADMIN_LIST_LIMIT_MAX = 1000


class ConfigError(RuntimeError):
    """Raised when the YAML config file is malformed or unreadable."""


# --- Minimal YAML loader -------------------------------------------------
#
# The server is intentionally dependency-free. We only need a small
# subset of YAML: nested mappings (no flow style), quoted and unquoted
# scalars, booleans, ints, floats, and ``null``/``~``. Anything exotic
# (anchors, multi-line scalars, flow style) is rejected with a message
# that points at the line so the operator can fix it.
_YAML_BOOL_TRUE = frozenset({"true", "yes", "on", "y"})
_YAML_BOOL_FALSE = frozenset({"false", "no", "off", "n"})
_YAML_NULL = frozenset({"null", "none", "~", ""})


def _yaml_strip_inline_comment(value: str) -> str:
    """Drop a trailing ``# comment`` from an unquoted scalar.

    Only fires when the ``#`` is preceded by whitespace or is the first
    character, so a hash inside a quoted string is left alone. Bracketed
    scalars (``"foo #bar"``) are never touched here because the lexer
    already knows whether the value is quoted.
    """
    if not value or value[0] in ("'", '"'):
        return value
    # Walk character by character so we ignore ``#`` characters inside
    # obvious shell-like contexts. The mini-DSL we accept is small
    # enough that this is sufficient.
    in_single = False
    in_double = False
    for index, char in enumerate(value):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            if index == 0 or value[index - 1] in (" ", "\t"):
                return value[:index].rstrip()
    return value


def _yaml_unquote(value: str) -> str:
    """Strip a matching pair of outer quotes and unescape simple chars."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        body = value[1:-1]
        if value[0] == '"':
            return body.encode("utf-8").decode("unicode_escape")
        return body
    return value


def _yaml_parse_scalar(raw: str) -> Any:
    """Convert a raw scalar string into the obvious Python type."""
    candidate = raw.strip()
    if not candidate or candidate.lower() in _YAML_NULL:
        return None
    if candidate.lower() in _YAML_BOOL_TRUE:
        return True
    if candidate.lower() in _YAML_BOOL_FALSE:
        return False
    # Numbers: integers first, then floats. ``int("3.0")`` raises so
    # the float branch gets its turn.
    try:
        return int(candidate)
    except ValueError:
        pass
    try:
        return float(candidate)
    except ValueError:
        pass
    return _yaml_unquote(candidate)


def _yaml_load_mapping(text: str) -> Dict[str, Any]:
    """Parse a flat-or-nested YAML mapping into a Python ``dict``.

    The loader is line-oriented and only understands two-space block
    indentation. Two-space blocks match what every editor defaults to
    and what the sample config ships with. The function raises
    ``ConfigError`` with the exact line number on any structural
    problem so the operator can fix the file in place.
    """
    root: Dict[str, Any] = {}
    # Stack of (indent, container) pairs so we can descend into nested
    # mappings without a recursive descent parser.
    stack: List[Tuple[int, Any]] = [(-1, root)]
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        # Strip the trailing newline and any blank/whitespace-only/#
        # comment-only lines so the rest of the loop is simple.
        line = raw_line.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # Tabs are forbidden in YAML block style; refuse them rather
        # than silently misparse an indented block.
        if "\t" in line:
            raise ConfigError(
                f"line {line_number}: tabs are not allowed in YAML config"
            )
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if ":" not in body:
            raise ConfigError(
                f"line {line_number}: expected 'key: value' or 'key:', got {body!r}"
            )
        key, _, value = body.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            raise ConfigError(f"line {line_number}: empty key")
        # Pop containers until we find one whose indent is strictly
        # less than the current line. Closing nested blocks is
        # implicit in YAML; we model it by walking the stack.
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack:
            raise ConfigError(
                f"line {line_number}: indentation stepped back beyond the root"
            )
        parent = stack[-1][1]
        if not isinstance(parent, dict):
            raise ConfigError(
                f"line {line_number}: cannot add a key to a scalar value"
            )
        if not value:
            # ``key:`` with nothing after — start of a nested mapping.
            nested: Dict[str, Any] = {}
            parent[key] = nested
            stack.append((indent, nested))
        else:
            value = _yaml_strip_inline_comment(value)
            if ":" in value and not (
                value.startswith('"') or value.startswith("'")
            ):
                # Split on the first ``:`` so URL-like values
                # (e.g. ``http://localhost:8088``) survive intact.
                head, _, tail = value.partition(":")
                head = head.strip()
                tail = tail.strip()
                if ":" not in tail and _yaml_strip_inline_comment(head) == head:
                    # ``host:port`` style — re-assemble.
                    value = f"{head}:{tail}"
            parent[key] = _yaml_parse_scalar(value)
    return root


def _yaml_default_config() -> Dict[str, Any]:
    """Return the configuration the server uses when no file is present.

    Mirrors the historical environment-variable defaults so the
    repository's tests and the documentation still match. The sample
    config file ships with this same shape, but with comments.
    """
    return {
        "server": {
            "host": "0.0.0.0",
            "port": 8088,
            "log_level": "info",
            "log_file": "",
            "trust_xff": False,
        },
        "storage": {
            "data_dir": "./var/metrics",
            "max_body": 1 << 20,
            "max_queue": 1024,
            "gzip_after_days": 7,
            "ack_timeout_seconds": 5.0,
        },
        "admin": {
            "api_key": "",
            "list_limit": ADMIN_LIST_LIMIT_DEFAULT,
        },
    }


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``override`` into ``base`` and return ``base``.

    Lists and scalars in ``override`` replace the corresponding value in
    ``base``; mappings are merged key-by-key. Used so the file only
    needs to mention the keys the operator actually wants to change.
    """
    for key, value in override.items():
        if (
            key in base
            and isinstance(base[key], dict)
            and isinstance(value, dict)
        ):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def _coerce_typed(raw: Any, fallback: Any) -> Any:
    """Coerce a YAML scalar into the type of ``fallback`` when sensible.

    Keeps the rest of the server code path-agnostic — it always deals
    with the right Python type — without forcing the operator to write
    ``"true"`` instead of ``Yes`` in the YAML file.
    """
    if raw is None:
        return fallback
    if isinstance(fallback, bool):
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            return raw.strip().lower() in _YAML_BOOL_TRUE
        return bool(raw)
    if isinstance(fallback, int):
        try:
            return int(raw)
        except (TypeError, ValueError):
            return fallback
    if isinstance(fallback, float):
        try:
            return float(raw)
        except (TypeError, ValueError):
            return fallback
    if isinstance(fallback, str):
        if isinstance(raw, str):
            return raw
        return str(raw)
    return raw


def _flat_env_to_dict(env: Dict[str, str]) -> Dict[str, Any]:
    """Translate ``PSN_METRICS_*`` env vars into a nested dict.

    The mapping is fixed so the historical env-var names continue to
    land in the correct section of the new YAML config (e.g.
    ``PSN_METRICS_DATA_DIR`` parks under ``storage.data_dir`` even
    though the YAML key is the same string). Names that are not in
    the explicit map fall through to the ``server`` section so
    operators can add their own keys without forking the loader.

    The first lookup table picks the *section*; the second one
    rewrites the historical env-var key (e.g. ``ack_timeout``) to
    the YAML key (e.g. ``ack_timeout_seconds``). Anything not in
    either table passes through unchanged.
    """
    # Section overrides for the legacy names. Anything not listed
    # here goes to ``server`` (the most common case).
    _SECTION_OVERRIDES = {
        "data_dir": "storage",
        "max_body": "storage",
        "max_queue": "storage",
        "gzip_after_days": "storage",
        "ack_timeout": "storage",
        "ack_timeout_seconds": "storage",
        "api_key": "admin",
        "list_limit": "admin",
        "log_file": "server",
        "config": "_meta",  # PSN_METRICS_CONFIG — handled by the loader.
    }
    # ``trust_xff`` already lives under ``server`` and the key
    # matches the YAML key, so the default ``server`` mapping is
    # correct. Mention it here so the rename table stays the only
    # place operators need to look.
    # Key renames so the legacy env-var name lands on the YAML key
    # the loader actually consumes.
    _KEY_RENAMES = {
        "ack_timeout": "ack_timeout_seconds",
        "gzip_old": "gzip_after_days",
    }
    out: Dict[str, Any] = {}
    for name, value in env.items():
        if not name.startswith("PSN_METRICS_"):
            continue
        suffix = name[len("PSN_METRICS_") :].lower()
        if suffix == "config":
            # ``PSN_METRICS_CONFIG`` is the path to the YAML file,
            # not a setting to merge. Skip it here so it does not
            # accidentally override the config-file path.
            continue
        if suffix == "trust_xff":
            # ``trust_xff`` already lives under ``server`` and the
            # key matches the YAML key, so the default mapping is
            # correct. Mention it here so the rename table stays
            # the only place operators need to look.
            pass
        parts = suffix.split("__", 1)
        if len(parts) == 1:
            section = _SECTION_OVERRIDES.get(parts[0], "server")
            key = _KEY_RENAMES.get(parts[0], parts[0])
        else:
            section, key = parts[0], parts[1]
        out.setdefault(section, {})[key] = value
    return out


def _env_overrides() -> Dict[str, Any]:
    """Public wrapper that pulls ``PSN_METRICS_*`` from ``os.environ``."""
    return _flat_env_to_dict(os.environ)


def _resolve_config_path(explicit: Optional[str]) -> Path:
    """Return the config file path following the documented precedence.

    Precedence (highest first):
      1. ``--config`` CLI argument
      2. ``PSN_METRICS_CONFIG`` environment variable
      3. ``/etc/ps-metrics.yaml`` if it exists
      4. ``$XDG_CONFIG_HOME/ps-metrics/config.yaml`` for per-user installs
      5. ``./ps-metrics.yaml`` in the current working directory
    """
    if explicit:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("PSN_METRICS_CONFIG")
    if env:
        return Path(env).expanduser().resolve()
    for candidate in (
        Path("/etc/ps-metrics.yaml"),
        Path(os.environ.get("XDG_CONFIG_HOME", "~/.config")).expanduser()
        / "ps-metrics"
        / "config.yaml",
        Path.cwd() / "ps-metrics.yaml",
    ):
        if candidate.exists():
            return candidate
    # No file found — return the canonical /etc/ path so the log
    # message tells the operator where to put one.
    return Path("/etc/ps-metrics.yaml")


def load_config(
    explicit_path: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Read the YAML config file, layer env vars on top, return a dict.

    Used by ``ServerConfig`` and by ``--print-config``. The contract is
    that the returned dict always has the keys
    ``server``, ``storage``, and ``admin`` populated (with sensible
    defaults) so callers do not need to deal with missing keys.
    """
    env_map = env if env is not None else dict(os.environ)
    path = _resolve_config_path(explicit_path)
    merged = _yaml_default_config()
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as handle:
                raw = handle.read()
        except OSError as exc:
            raise ConfigError(f"could not read config {path}: {exc}") from exc
        parsed = _yaml_load_mapping(raw)
        _deep_merge(merged, parsed)
        loaded_from = path
    else:
        loaded_from = None
    # Layer env vars on top so a unit file can override the file
    # without the operator having to duplicate the whole config.
    overrides = _flat_env_to_dict(env_map)
    _deep_merge(merged, overrides)
    # Stash where the config came from so ``--print-config`` can say so.
    merged["_loaded_from"] = str(loaded_from) if loaded_from else None
    return merged


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
        #   *  < 0  -> never compress; let an external tool (e.g.
        #              logrotate with the ``copytruncate``/``delaycompress``
        #              options, Vector, Filebeat) own compression. Files
        #              are left in place as plain NDJSON on every rotation.
        #   *  0    -> compress the previous day's file on every rotation
        #   *  N    -> compress once the file is at least N days old
        # The default is 7 so the on-disk state stays bounded without
        # a daily rewrite cycle, but the negative sentinel exists for
        # operators who prefer to wire up logrotate themselves.
        self._gzip_after_days = int(gzip_after_days)
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
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            # The sink cannot function without a writable directory,
            # so log the failure with the full path and let the
            # caller (``main``) convert it into a clean exit.
            LOG.error(
                "data_dir mkdir failed path=%s errno=%s error=%s",
                data_dir,
                getattr(exc, "errno", None),
                exc,
            )
            raise

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
        # Open each handle one at a time so an EACCES/ENOENT on one
        # file logs the exact path that failed — instead of a stack
        # trace that just says "open() failed somewhere".
        for attr, pathGetter in (
            ("_events_handle", lambda: self._events_path(today)),
            ("_installs_handle", lambda: self._installs_path(today)),
            ("_errors_handle", lambda: self._errors_path(today)),
        ):
            path = pathGetter()
            try:
                setattr(self, attr, self._open_for_append(path))
            except OSError as exc:
                LOG.error(
                    "open failed path=%s errno=%s error=%s",
                    path,
                    getattr(exc, "errno", None),
                    exc,
                )
                raise

    def _close_handles(self) -> None:
        for attr in ("_events_handle", "_installs_handle", "_errors_handle"):
            handle = getattr(self, attr)
            if handle is not None:
                path = getattr(handle, "name", None)
                try:
                    handle.flush()
                except Exception as exc:  # pragma: no cover - best effort
                    LOG.warning(
                        "close flush failed path=%s error=%s",
                        path or "<unknown>",
                        exc,
                    )
                try:
                    handle.close()
                except Exception as exc:  # pragma: no cover - best effort
                    LOG.warning(
                        "close handle failed path=%s error=%s",
                        path or "<unknown>",
                        exc,
                    )
                setattr(self, attr, None)

    def _flush_all(self) -> None:
        for handle in (
            self._events_handle,
            self._installs_handle,
            self._errors_handle,
        ):
            if handle is None:
                continue
            path = getattr(handle, "name", None)
            try:
                handle.flush()
                os.fsync(handle.fileno())
            except OSError as exc:
                if exc.errno in (errno.EBADF, errno.EINVAL):
                    # EBADF/EINVAL during shutdown are not worth a
                    # warning — they happen on every clean close.
                    continue
                LOG.error(
                    "fsync failed path=%s errno=%s error=%s",
                    path or "<unknown>",
                    getattr(exc, "errno", None),
                    exc,
                )
                raise

    def _gzip_old_files(
        self, old_day: _dt.date, today: _dt.date
    ) -> None:
        # ``gzip_after_days < 0`` is the explicit "off" sentinel: the
        # operator wants logrotate (or a similar external tool) to
        # manage rotation and compression, so we must not touch the
        # on-disk files ourselves. Skipping here also avoids racing
        # with a logrotate ``copytruncate`` step, which would see the
        # half-written copy-truncate target if we tried to gzip on
        # top of it.
        if self._gzip_after_days < 0:
            return
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
                try:
                    with open(path, "rb") as src, gzip.open(
                        gz_path, "wb", compresslevel=6
                    ) as dst:
                        shutil.copyfileobj(src, dst)
                    path.unlink()
                except OSError as exc:
                    # A failed gzip should not silently break the
                    # daily rotation. The plain file is left in place
                    # and we log a single warning with the path so the
                    # operator can see which day's file failed.
                    LOG.warning(
                        "gzip failed path=%s errno=%s error=%s",
                        path,
                        getattr(exc, "errno", None),
                        exc,
                    )

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
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            # Full-disk, permission denied, the parent directory
            # disappearing mid-write — every one of those should land
            # in the operator's journal with the path so they can
            # correlate with whatever broke underneath the server.
            LOG.error(
                "write failed path=%s errno=%s error=%s",
                tmp,
                getattr(exc, "errno", None),
                exc,
            )
            # Try to clean up the half-written temp file so a
            # subsequent retry does not see a stale ``.tmp`` left
            # behind by a crashed writer.
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            raise
        try:
            os.replace(tmp, path)
        except OSError as exc:
            LOG.error(
                "rename failed src=%s dst=%s errno=%s error=%s",
                tmp,
                path,
                getattr(exc, "errno", None),
                exc,
            )
            raise

    def _last_load_state(self) -> None:
        if not self._state_path.exists():
            return
        try:
            with open(self._state_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except OSError as exc:
            # ``state.json`` is best-effort durability — log the
            # failure but do not abort startup. The server can
            # recreate a fresh state file on the first batch.
            LOG.warning(
                "state.json read failed path=%s errno=%s error=%s",
                self._state_path,
                getattr(exc, "errno", None),
                exc,
            )
            return
        except json.JSONDecodeError as exc:
            LOG.warning(
                "state.json parse failed path=%s error=%s",
                self._state_path,
                exc,
            )
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
    # own structured access logger (see ``log_request`` below) that
    # records one line per request with method/path/status/bytes.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def setup(self) -> None:  # noqa: D401
        """Capture the wall-clock moment we accepted the connection.

        Used by ``log_request`` to compute the elapsed time we
        report in the access-log line. The default ``setup`` is a
        no-op so we have to call ``super().setup()`` ourselves.
        """
        try:
            super().setup()
        except Exception:  # pragma: no cover - never expected
            pass
        self._request_started_at = time.monotonic()
        self._response_bytes = 0

    def log_request(
        self,
        code: int = -1,
        size: int = -1,
        duration_ms: Optional[float] = None,
    ) -> None:
        """Emit one structured access-log line per request.

        Called by the stdlib ``BaseHTTPRequestHandler.send_response``
        and ``handle_one_request`` paths. ``send_response`` invokes
        us with the actual status code; the
        ``handle_one_request``-driven call (if any) provides the
        final byte count after ``wfile.flush()``. We rely on the
        byte counter (``_response_bytes``) we update in
        ``_send_json`` and ``_require_admin`` so the size we log
        matches what we put on the wire, regardless of which call
        path triggers the log line.

        Format mirrors the classic combined-log shape:

            <iso8601-utc> <client_ip>:<port> "<method> <path> <proto>" <status> <bytes> <duration_ms>ms

        with the ``method``, ``path``, ``status``, ``bytes`` and
        ``duration`` fields the operator asked for so every request
        can be greppable for status codes, hot paths, slow handlers
        and clients with their log line alone.
        """
        if code < 0:
            code = getattr(self, "code", 200) or 200
        if size < 0:
            size = getattr(self, "_response_bytes", 0) or 0
        if duration_ms is None:
            started = getattr(self, "_request_started_at", None)
            if started is not None:
                duration_ms = (time.monotonic() - started) * 1000.0
            else:
                duration_ms = 0.0
        client = getattr(self, "client_address", None) or ("unknown", 0)
        client_ip = str(client[0] if len(client) > 0 else "unknown")
        client_port = int(client[1] if len(client) > 1 else 0)
        method = str(getattr(self, "command", "-") or "-")
        full_path = str(getattr(self, "path", "-") or "-")
        # Strip query string for the access log; query params land in
        # their own debug-level line if the operator needs them.
        path_only = full_path.split("?", 1)[0]
        protocol = str(getattr(self, "request_version", "HTTP/1.1") or "HTTP/1.1")
        LOG.info(
            'access %s %s:%d "%s %s %s" %d %d %.2fms',
            _iso_z(_utc_now()),
            client_ip,
            client_port,
            method,
            path_only,
            protocol,
            int(code),
            int(size),
            float(duration_ms),
        )

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
        path = self.path.split("?", 1)[0]
        if path == HEALTH_PATH:
            self._handle_health()
            return
        if path.startswith(ADMIN_PREFIX):
            self._handle_admin(path)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path != INGEST_PATH:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        self._handle_ingest()

    def do_HEAD(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        # Set ``code``/``_response_bytes`` BEFORE ``send_response`` so
        # ``log_request`` (called from inside ``send_response``)
        # sees the real values. HEAD requests legitimately have a
        # zero-length body, which is why we set ``_response_bytes``
        # to 0 here.
        if path in (HEALTH_PATH, INGEST_PATH):
            try:
                self.code = int(HTTPStatus.OK)
            except Exception:
                self.code = 200
            self._response_bytes = 0
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        try:
            self.code = int(HTTPStatus.NOT_FOUND)
        except Exception:
            self.code = 404
        self._response_bytes = 0
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

    # ---- admin endpoints ------------------------------------------------
    #
    # The admin surface is intentionally minimal and only useful to
    # operators: a stats endpoint that mirrors the on-disk totals, a
    # recent-installs endpoint that reads the last lines of
    # ``installs-YYYY-MM-DD.ndjson``, and a recent-errors endpoint that
    # does the same for ``errors-*.ndjson``. All three are gated by a
    # single config-managed API key and disabled (return 404) when no
    # key is configured. We deliberately do NOT expose a query that
    # reveals individual install IDs past heartbeat timestamps — the
    # on-disk heartbeat file already records those for debuggability,
    # but the wire response only forwards counts and the moment an
    # install was last seen so the api operator can confirm the
    # pipeline is moving without being able to fingerprint users.

    def _client_admin_key(self) -> Optional[str]:
        """Extract the API key from the request, supporting two header styles.

        Accepts either ``X-Admin-Key: <key>`` (preferred) or
        ``Authorization: Bearer <key>`` (a common convention for
        proxies that strip custom headers). Both are honoured so a
        prometheus/blackbox-exporter-style script can hit the endpoint
        without a custom header parser.
        """
        custom = self.headers.get(ADMIN_KEY_HEADER)
        if isinstance(custom, str) and custom.strip():
            return custom.strip()
        auth = self.headers.get("Authorization")
        if isinstance(auth, str):
            scheme, _, token = auth.partition(" ")
            if scheme.lower() == "bearer" and token.strip():
                return token.strip()
        return None

    def _require_admin(self) -> bool:
        """Return True when the request is authenticated for admin access.

        Sends a 401 with a ``WWW-Authenticate`` header on failure so
        the client has a hint at the right protocol. 404 is sent when
        admin is disabled entirely — the endpoint should not exist at
        all in that case, and the silent 404 keeps scanners from
        learning that the binary supports admin mode.
        """
        config = self.server.config
        if not config.admin_enabled():
            return False
        if not config.admin_auth_ok(self._client_admin_key()):
            body = json.dumps({"error": "unauthorized"}).encode("utf-8")
            # Track the response byte count and status BEFORE
            # ``send_response``: ``BaseHTTPRequestHandler.send_response``
            # invokes ``log_request`` internally and we want the
            # access log to carry the real numbers, not the defaults.
            self._response_bytes = len(body)
            try:
                self.code = int(HTTPStatus.UNAUTHORIZED)
            except Exception:
                self.code = 401
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("Content-Type", "application/json")
            self.send_header("WWW-Authenticate", 'Bearer realm="ps-metrics-admin"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    LOG.debug(
                        "client disconnected before 401 body was sent"
                    )
            return False
        return True

    def _handle_admin(self, path: str) -> None:
        if not self._require_admin():
            # ``_require_admin`` either wrote the response or admin
            # is disabled, in which case we mirror the "endpoint does
            # not exist" 404 from the rest of the router.
            if self.server.config.admin_enabled():
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        if path == "/admin/stats":
            self._handle_admin_stats()
            return
        if path == "/admin/installs":
            self._handle_admin_installs()
            return
        if path == "/admin/errors":
            self._handle_admin_errors()
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def _handle_admin_stats(self) -> None:
        state = self._server_state()
        config = self.server.config
        sink = self.server.sink
        health_path = (
            sink._health_path if hasattr(sink, "_health_path") else None
        )
        last_seen = None
        if health_path is not None and health_path.exists():
            try:
                with open(health_path, "r", encoding="utf-8") as handle:
                    last_seen = json.load(handle)
            except (OSError, json.JSONDecodeError):
                last_seen = None
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "service": "packetsnitch-metrics",
                "hostname": socket.gethostname(),
                "startedAt": _iso_z(_utc_now()),
                "queueDepth": self.server.queue_depth(),
                "queueCapacity": self.server.queue_capacity(),
                "totals": {
                    "batches": state["totalBatches"],
                    "events": state["totalEvents"],
                    "errors": state["totalErrors"],
                    "installs": state["totalInstalls"],
                },
                "dataDir": str(config.data_dir),
                "lastSeen": last_seen,
            },
        )

    def _tail_ndjson(self, path: Path, limit: int) -> List[Dict[str, Any]]:
        """Return up to ``limit`` most recent parsed rows from an NDJSON file.

        Reads the file once and trims. The file is small (a single
        day's worth of heartbeats is well under a megabyte) so an
        O(N) tail is fine; we are not after streaming.
        """
        if not path.exists() or limit <= 0:
            return []
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except OSError:
            return []
        rows: List[Dict[str, Any]] = []
        for raw in lines[-limit:]:
            raw = raw.strip()
            if not raw:
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        return rows

    def _handle_admin_installs(self) -> None:
        config = self.server.config
        sink = self.server.sink
        today = _utc_now().date()
        # Read both today and yesterday so a query near midnight still
        # surfaces the most recent heartbeat for an active install.
        candidates = [sink._installs_path(today), sink._installs_path(today)]
        yesterday = today - _dt.timedelta(days=1)
        candidates.append(sink._installs_path(yesterday))
        rows: List[Dict[str, Any]] = []
        seen_ids: set = set()
        for path in candidates:
            for row in self._tail_ndjson(path, config.admin_list_limit):
                install_id = row.get("install_id")
                if isinstance(install_id, str) and install_id in seen_ids:
                    continue
                if isinstance(install_id, str):
                    seen_ids.add(install_id)
                # Heartbeat privacy: never echo the client IP out of
                # the wire response. Operators do not need it for
                # debugging and stripping it makes an accidental log
                # scrape less damaging.
                row = {k: v for k, v in row.items() if k != "client_ip"}
                rows.append(row)
                if len(rows) >= config.admin_list_limit:
                    break
            if len(rows) >= config.admin_list_limit:
                break
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "count": len(rows),
                "limit": config.admin_list_limit,
                "installs": rows,
            },
        )

    def _handle_admin_errors(self) -> None:
        config = self.server.config
        sink = self.server.sink
        today = _utc_now().date()
        yesterday = today - _dt.timedelta(days=1)
        rows: List[Dict[str, Any]] = []
        for path in (sink._errors_path(today), sink._errors_path(yesterday)):
            rows.extend(self._tail_ndjson(path, config.admin_list_limit))
            if len(rows) >= config.admin_list_limit:
                rows = rows[-config.admin_list_limit:]
                break
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "count": len(rows),
                "limit": config.admin_list_limit,
                "errors": rows,
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
        # Track the byte count and the status code BEFORE calling
        # ``send_response``: ``BaseHTTPRequestHandler.send_response``
        # invokes ``log_request`` internally, and we want the access
        # log line to carry the real response size, not the zeroed
        # default from ``setup``.
        self._response_bytes = len(body)
        try:
            self.code = int(status)
        except Exception:
            self.code = 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                # The client vanished before they could read the
                # body. Surface a debug-level line so the operator
                # can see it without a stack trace in the log; the
                # access log already records the response size, so
                # they can correlate.
                LOG.debug(
                    "client disconnected before response body was sent: %d bytes",
                    len(body),
                )


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

    # ``_socket_bound`` is flipped to ``True`` only when
    # ``server_bind`` returns without raising, so ``server_close``
    # can distinguish a clean teardown from a no-op cleanup after a
    # failed bind and skip its "server socket closed" line in the
    # latter case.
    _socket_bound: bool = False

    def __init__(
        self,
        address: Tuple[str, int],
        sink: MetricsSink,
        config: "ServerConfig",
    ) -> None:
        # Bind happens inside ``super().__init__`` via ``server_bind``
        # and the listening socket is wired up in ``server_activate``.
        # Both are overridden below so the bind and the start of the
        # ``accept()`` loop each produce one access-log line. We
        # don't log here because ``server_bind`` already emits a
        # ``bind ok``/``bind failed`` line — adding a second one
        # would duplicate the operator's view.
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

    def server_bind(self) -> None:
        """Wrap the bind() call so we log success/failure with context.

        ``HTTPServer.server_bind`` resolves a ``0`` port (the kernel
        picks) into the real port number before returning. Logging
        after the call captures that resolved port so the operator
        knows which port to point a load balancer at even when the
        config asks for an ephemeral one.
        """
        try:
            super().server_bind()
        except OSError as exc:
            LOG.error(
                "bind failed host=%s port=%s errno=%s error=%s",
                self.server_address[0],
                self.server_address[1],
                getattr(exc, "errno", None),
                exc,
            )
            raise
        host = self.server_address[0]
        port = self.server_address[1]
        LOG.info("bind ok host=%s port=%d", host, port)
        self._socket_bound = True

    def server_activate(self) -> None:
        """Wrap the listen() call so we log the moment the socket is live.

        Without this override the only signal an operator has that the
        server is ready to accept connections is the implicit "no
        errors so far" absence. Logging here turns the silent step
        between ``bind()`` and the first ``accept()`` into a
        greppable "ready" line.
        """
        try:
            super().server_activate()
        except OSError as exc:
            LOG.error(
                "listen failed host=%s port=%d errno=%s error=%s",
                self.server_address[0],
                self.server_address[1],
                getattr(exc, "errno", None),
                exc,
            )
            raise
        host = self.server_address[0]
        port = self.server_address[1]
        LOG.info(
            "listen ok host=%s port=%d socket_family=%s backlog=%d",
            host,
            port,
            self.address_family,
            self.request_queue_size,
        )

    def server_close(self) -> None:
        """Log the socket teardown so the lifecycle is symmetric.

        Without this override the operator only ever sees a single
        "shutting down" line on SIGTERM and then silence — there is
        no signal that the socket actually closed and the port is
        free again. Logging here closes that gap. We skip the log
        when ``server_bind`` never succeeded (e.g. ``EADDRINUSE``)
        because there is no socket to talk about — the cleanup is
        a no-op in that case.
        """
        bound = bool(getattr(self, "_socket_bound", False))
        try:
            super().server_close()
        except OSError as exc:
            LOG.warning("server_close raised: %s", exc)
            return
        if bound:
            LOG.info(
                "server socket closed host=%s port=%d",
                self.server_address[0],
                self.server_address[1],
            )

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
            "metrics writer started data_dir=%s gzip_after_days=%d "
            "max_queue=%d ack_timeout_seconds=%.2f",
            self.config.data_dir,
            self.config.gzip_after_days,
            self.config.max_queue,
            self.config.ack_timeout_seconds,
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
    """Strongly-typed view of the merged YAML + env-var config.

    The single source of truth is the dict returned by ``load_config``;
    this class just exposes the fields the rest of the server actually
    uses as plain attributes. Values are coerced so callers do not have
    to deal with the YAML loader's "everything is a string" version of
    reality.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        merged = config if config is not None else load_config()
        server = merged.get("server", {}) or {}
        storage = merged.get("storage", {}) or {}
        admin = merged.get("admin", {}) or {}
        self.host: str = str(_coerce_typed(server.get("host"), "0.0.0.0"))
        self.port: int = int(_coerce_typed(server.get("port"), 8088))
        self.log_level: str = str(_coerce_typed(server.get("log_level"), "info")).lower()
        # ``server.log_file`` is the path to an additional log
        # destination on top of stderr. The empty string (the
        # default) means "stderr only", which matches the historic
        # behaviour where the supervisor (systemd / docker / a
        # reverse proxy) owns log routing. A non-empty value
        # triggers a ``FileHandler`` in ``configure_logging`` so the
        # operator gets a single-file view of every line without
        # having to scrape journald. ``None`` here means "not set",
        # so the call sites can use ``is None`` to decide whether
        # to attach the file handler.
        log_file_raw = _coerce_typed(server.get("log_file"), "")
        if isinstance(log_file_raw, str) and log_file_raw.strip():
            self.log_file: Optional[Path] = Path(log_file_raw.strip()).expanduser()
        else:
            self.log_file: Optional[Path] = None
        self.trust_xff: bool = _coerce_typed(server.get("trust_xff"), False)
        data_dir = storage.get("data_dir", "./var/metrics")
        self.data_dir: Path = Path(str(data_dir)).expanduser().resolve()
        self.max_body: int = int(_coerce_typed(storage.get("max_body"), 1 << 20))
        self.max_queue: int = int(_coerce_typed(storage.get("max_queue"), 1024))
        self.gzip_after_days: int = int(
            _coerce_typed(storage.get("gzip_after_days"), 7)
        )
        self.ack_timeout_seconds: float = float(
            _coerce_typed(storage.get("ack_timeout_seconds"), 5.0)
        )
        # ``admin.api_key`` is intentionally a ``str`` so an unset
        # secret is the empty string — easy to test, easy to log.
        self.admin_api_key: str = str(_coerce_typed(admin.get("api_key"), ""))
        self.admin_list_limit: int = max(
            1,
            min(
                int(_coerce_typed(admin.get("list_limit"), ADMIN_LIST_LIMIT_DEFAULT)),
                ADMIN_LIST_LIMIT_MAX,
            ),
        )
        # Where this config came from — exposed via ``--print-config``
        # so the operator can verify which file was actually loaded.
        self.loaded_from: Optional[str] = merged.get("_loaded_from")

    # ---- admin helpers ---------------------------------------------------

    def admin_enabled(self) -> bool:
        """``True`` when an admin API key is configured.

        Failing closed (no key, no admin endpoints) means a fresh
        install with an empty config file never accidentally exposes
        ``/admin/*`` to the network.
        """
        return bool(self.admin_api_key)

    def admin_auth_ok(self, presented: Optional[str]) -> bool:
        """Constant-time compare of the presented key against the configured one.

        Uses ``hmac.compare_digest`` so a request count cannot infer
        the key through timing differences. ``False`` for an empty
        config (admin disabled) and for any wrong key.
        """
        if not self.admin_enabled():
            return False
        if not isinstance(presented, str) or not presented:
            return False
        return hmac.compare_digest(presented, self.admin_api_key)


# --- Entry point -----------------------------------------------------------
_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
_LOG_DATEFMT = "%Y-%m-%dT%H:%M:%S%z"


def configure_logging(
    level: str,
    log_file: Optional[Path] = None,
) -> None:
    """Configure root logging so every line goes to stderr + (optionally) a file.

    ``level`` is the textual level name (``debug`` / ``info`` /
    ``warn`` / ``error``) as it appears in the YAML config. Unknown
    values fall back to ``INFO`` to match the historical behaviour
    where typos in the config never silently disabled the log.

    ``log_file`` is an optional path; when set, an additional
    ``FileHandler`` with the same format and level is attached so
    every log line lands both on stderr (for journald/docker logs)
    and on disk (for ``tail -f`` / Filebeat / Vector). The parent
    directory is created if it does not yet exist so the operator
    does not have to ``mkdir -p`` before each fresh install.

    The function is idempotent: a second call with the same
    arguments replaces the prior handlers instead of stacking new
    ones, so a unit-test harness that calls it twice does not see
    duplicate lines.

    Raises ``OSError`` if ``log_file`` cannot be opened — the
    operator picked the path deliberately, so silently falling back
    to stderr would hide a real misconfiguration. The caller
    (``main``) catches and exits non-zero with a clear message.
    """
    numeric = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }.get(level, logging.INFO)

    # ``basicConfig`` is a no-op if any handler is already attached
    # on the root logger, so on second-and-later calls we have to
    # reach in and re-shape the handler list ourselves. Walk every
    # existing handler and either replace its level (for the
    # stderr one) or drop it (we always re-add the file handler
    # below).
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    logging.basicConfig(
        level=numeric,
        format=_LOG_FORMAT,
        datefmt=_LOG_DATEFMT,
    )

    if log_file is not None:
        # ``Path`` objects from ``Path(...)`` already normalise
        # through ``expanduser`` in ``ServerConfig``; we still
        # ``resolve`` here so a relative path passed via the CLI is
        # pinned to the operator's cwd rather than the server's
        # later cwd (which would change if systemd restarts us).
        target = Path(log_file).expanduser()
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            # A failure to create the parent directory is fatal:
            # the operator asked for a file and we cannot honour it,
            # so surface the error and let ``main`` decide whether
            # to continue with stderr-only logging or bail.
            raise FileNotFoundError(
                f"could not create log_file parent directory {target.parent}: {exc}"
            ) from exc
        try:
            file_handler = logging.FileHandler(target, encoding="utf-8")
        except OSError as exc:
            raise FileNotFoundError(
                f"could not open log_file {target}: {exc}"
            ) from exc
        file_handler.setLevel(numeric)
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
        root.addHandler(file_handler)
        # Surface the resolved path through the package logger so
        # the operator can grep for it in their existing log feed
        # even if the file handler itself silently fails later.
        LOG.info(
            "log_file enabled path=%s level=%s",
            target,
            logging.getLevelName(numeric),
        )


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PacketSnitch metrics endpoint",
    )
    parser.add_argument(
        "--config",
        help=(
            "path to the YAML config file (default: /etc/ps-metrics.yaml, "
            "or $PSN_METRICS_CONFIG, or ./ps-metrics.yaml)"
        ),
    )
    parser.add_argument("--host", help="bind address (env: PSN_METRICS_HOST)")
    parser.add_argument(
        "--port", type=int, help="listen port (env: PSN_METRICS_PORT)"
    )
    parser.add_argument(
        "--data-dir",
        help="output directory for NDJSON files (env: PSN_METRICS_DATA_DIR)",
    )
    parser.add_argument(
        "--print-config",
        action="store_true",
        help="print the merged config (file + env) as JSON and exit",
    )
    parser.add_argument(
        "--generate-config",
        metavar="PATH",
        help="write a documented sample config to PATH and exit",
    )
    parser.add_argument(
        "--generate-api-key",
        action="store_true",
        help="print a fresh random admin API key and exit",
    )
    return parser.parse_args(list(argv))


def apply_args(config: ServerConfig, args: argparse.Namespace) -> None:
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    if args.data_dir:
        config.data_dir = Path(args.data_dir).expanduser().resolve()


def _redactConfigForLog(config: ServerConfig) -> Dict[str, Any]:
    """Return a safe-to-log view of the resolved config.

    The admin API key is replaced with a constant redaction marker
    so a multi-tenant operator who shares ``journalctl -u
    packetsnitch-metrics`` output with the rest of the team does not
    accidentally leak the secret. Every other field is preserved
    verbatim so the startup line is genuinely useful when debugging
    bind/listen/storage issues — the redaction only kicks in for
    fields that contain operator secrets.

    Returned as a dict so the caller can pass it directly into
    ``logging.info("config %s", payload)`` without quoting worries.
    """
    api_key_set = config.admin_enabled()
    return {
        "server": {
            "host": config.host,
            "port": config.port,
            "log_level": config.log_level,
            # ``log_file`` is an operator-chosen path, not a secret,
            # so we surface it verbatim. ``None`` (no file
            # configured) renders as the string ``"(none)"`` in the
            # log so the operator can grep for it.
            "log_file": str(config.log_file) if config.log_file else "(none)",
            "trust_xff": config.trust_xff,
        },
        "storage": {
            "data_dir": str(config.data_dir),
            "max_body": config.max_body,
            "max_queue": config.max_queue,
            "gzip_after_days": config.gzip_after_days,
            "ack_timeout_seconds": config.ack_timeout_seconds,
        },
        "admin": {
            "api_key": "<redacted>" if api_key_set else "",
            "api_key_set": api_key_set,
            "list_limit": config.admin_list_limit,
        },
        "_loaded_from": config.loaded_from,
    }


def _logStartupConfig(config: ServerConfig) -> None:
    """Emit one structured ``config`` line with redacted secrets.

    Called once during ``main`` so the operator's journal already
    shows the resolved bind/storage/admin settings before the first
    request lands. The shape mirrors ``--print-config`` so the
    operator can correlate the two with a diff.
    """
    safe = _redactConfigForLog(config)
    LOG.info(
        "config host=%s port=%d log_level=%s log_file=%s trust_xff=%s "
        "data_dir=%s max_body=%d max_queue=%d gzip_after_days=%d "
        "ack_timeout_seconds=%.2f admin_api_key=%s admin_key_set=%s "
        "loaded_from=%s",
        safe["server"]["host"],
        safe["server"]["port"],
        safe["server"]["log_level"],
        safe["server"]["log_file"],
        safe["server"]["trust_xff"],
        safe["storage"]["data_dir"],
        safe["storage"]["max_body"],
        safe["storage"]["max_queue"],
        safe["storage"]["gzip_after_days"],
        safe["storage"]["ack_timeout_seconds"],
        safe["admin"]["api_key"],
        safe["admin"]["api_key_set"],
        safe["_loaded_from"] or "(none)",
    )


def _sample_config_text() -> str:
    """Return the canonical sample config shipped with the server.

    The block is intentionally inline so the ``--generate-config``
    flag is self-contained and so the unit tests can assert against
    the same template.
    """
    return (
        "# PacketSnitch metrics endpoint configuration.\n"
        "#\n"
        "# Canonical location is /etc/ps-metrics.yaml. Override via\n"
        "# PSN_METRICS_CONFIG or the --config CLI flag. Any key here\n"
        "# can be overridden by a matching PSN_METRICS_* env var (e.g.\n"
        "# PSN_METRICS_PORT=9000 overrides server.port).\n"
        "#\n"
        "# An admin API key is required to query the /admin/* endpoints.\n"
        "# Generate one with:  python3 src/metrics/ps-metrics.py --generate-api-key\n"
        "#\n"
        "# Leave admin.api_key empty (the default) to disable admin\n"
        "# endpoints entirely — they will return 404 in that mode.\n"
        "\n"
        "server:\n"
        "  host: 0.0.0.0              # bind address. Use 127.0.0.1 for local-only.\n"
        "  port: 8088                 # listen port.\n"
        "  log_level: info            # debug | info | warn | error.\n"
        "  log_file: \"\"               # Optional path to also write log lines to a file.\n"
        "                             # Empty = stderr only. A non-empty path also\n"
        "                             # opens a FileHandler so journalctl-equivalent\n"
        "                             # lines land on disk for tail -f / Vector.\n"
        "  trust_xff: false           # true when behind a reverse proxy that forwards client IPs.\n"
        "\n"
        "storage:\n"
        "  data_dir: /var/log/packetsnitch-metrics   # where NDJSON files are written.\n"
        "  max_body: 1048576          # max accepted POST body in bytes (1 MiB).\n"
        "  max_queue: 1024            # max in-flight batches before /mhook returns 503.\n"
        "  gzip_after_days: 7         # 0 = compress yesterdays file on every rotation.\n"
        "  ack_timeout_seconds: 5.0   # how long HTTP clients wait for the disk ack.\n"
        "\n"
        "admin:\n"
        "  # A random, high-entropy string. Required for /admin/* endpoints.\n"
        "  api_key: \"\"\n"
        "  list_limit: 100            # max rows returned by /admin/installs and /admin/errors.\n"
    )


def main(argv: Optional[List[str]] = None) -> int:
    # Wall-clock anchor so the final ``shutdown complete`` line can
    # report a real uptime without having to plumb the start time
    # through every helper along the way. ``time.monotonic`` is the
    # right tool here because it ignores NTP slews.
    global _startup_monotonic
    _startup_monotonic = time.monotonic()
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.generate_api_key:
        # 32 url-safe bytes (~43 chars) keyed by the RNG. Print to
        # stdout so the operator can ``--generate-api-key | pbcopy`` it
        # into their config file without touching a temporary file.
        print(secrets.token_urlsafe(32))
        return 0
    if args.generate_config:
        target = Path(args.generate_config).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(_sample_config_text())
        print(f"wrote sample config to {target}")
        return 0
    config = ServerConfig(load_config(args.config))
    if args.print_config:
        # Merge the resolved defaults so the operator sees what the
        # server actually loaded, not just the contents of the file.
        print(
            json.dumps(
                {
                    "server": {
                        "host": config.host,
                        "port": config.port,
                        "log_level": config.log_level,
                        # ``None`` (no file) prints as ``null`` so
                        # the operator can tell at a glance whether
                        # stderr-only logging is active.
                        "log_file": str(config.log_file) if config.log_file else None,
                        "trust_xff": config.trust_xff,
                    },
                    "storage": {
                        "data_dir": str(config.data_dir),
                        "max_body": config.max_body,
                        "max_queue": config.max_queue,
                        "gzip_after_days": config.gzip_after_days,
                        "ack_timeout_seconds": config.ack_timeout_seconds,
                    },
                    "admin": {
                        # Never echo the secret. Just show whether it is set.
                        "api_key_set": config.admin_enabled(),
                        "list_limit": config.admin_list_limit,
                    },
                    "_loaded_from": config.loaded_from,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    apply_args(config, args)
    try:
        configure_logging(config.log_level, config.log_file)
    except (FileNotFoundError, OSError) as exc:
        # ``configure_logging`` raises ``FileNotFoundError`` when the
        # configured ``log_file`` cannot be opened. The operator
        # picked the path deliberately, so we surface the failure
        # and exit non-zero instead of silently degrading to
        # stderr-only logging — that would hide a real
        # misconfiguration from the very person who asked for the
        # feature.
        print(f"ps-metrics: failed to configure log_file: {exc}", file=sys.stderr)
        return 1
    # Operator-visible "I am starting up" line. Captures PID, the
    # Python version, and the on-disk executable path so the journal
    # can answer "what version is actually running on this host?"
    # without an operator having to attach to the process. The
    # resolved config follows on the next line with secrets redacted.
    LOG.info(
        "startup pid=%d python=%s exe=%s",
        os.getpid(),
        ".".join(str(part) for part in sys.version_info[:3]),
        sys.executable,
    )
    _logStartupConfig(config)

    try:
        config.data_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # ``data_dir`` is where every event lands. A bind failure
        # here is fatal: log it loudly and bail so the operator does
        # not chase "where are my events?" symptoms later.
        LOG.error(
            "data_dir create failed path=%s errno=%s error=%s",
            config.data_dir,
            getattr(exc, "errno", None),
            exc,
        )
        return 1
    sink = MetricsSink(config.data_dir, gzip_after_days=config.gzip_after_days)
    try:
        server = MetricsHTTPServer((config.host, config.port), sink, config)
    except OSError as exc:
        # ``MetricsHTTPServer.__init__`` already logs the bind
        # failure with full context. We only need to convert the
        # raised ``OSError`` into a clean exit code so systemd does
        # not treat the failure as a crash loop.
        LOG.error(
            "server init failed errno=%s error=%s",
            getattr(exc, "errno", None),
            exc,
        )
        return 1

    def _shutdown(signum: int, _frame: Any) -> None:
        LOG.info("received signal=%d, shutting down", signum)
        # ``shutdown`` blocks; spawn a thread so the signal handler
        # can return immediately.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    LOG.info(
        "metrics endpoint listening host=%s port=%d data_dir=%s admin=%s config=%s",
        config.host,
        config.port,
        config.data_dir,
        "enabled" if config.admin_enabled() else "disabled",
        config.loaded_from or "(none)",
    )
    try:
        server.serve_forever()
    finally:
        LOG.info("server loop exited, closing socket")
        sink.shutdown()
    LOG.info(
        "shutdown complete pid=%d uptime_s=%.3f",
        os.getpid(),
        time.monotonic() - _startup_monotonic,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
