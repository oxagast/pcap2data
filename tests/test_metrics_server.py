#!/usr/bin/env python3
"""Tests for the PacketSnitch metrics endpoint.

These tests run in-process against the HTTP handler and the sink so we
cover the full path from a POST through to on-disk NDJSON without any
network plumbing. They use the standard library only so they run on
any machine that has Python 3.10+ available.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import importlib.util
import io
import json
import logging
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from collections import deque
from http.client import HTTPConnection
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple
from unittest import mock

# Make the metrics package importable when run from anywhere.
_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent

# We import via importlib so we don't have to mutate sys.path and so the
# test file works whether it's discovered from the project root or from
# the tests/ directory. The shipping module name is ``ps-metrics.py``
# (the dashed filename keeps systemd + the old README happy), which is
# not a valid Python identifier, so importlib is the only sane way to
# load it.
_spec = importlib.util.spec_from_file_location(
    "metrics_server_test_module",
    _PROJECT_ROOT / "src" / "metrics" / "ps-metrics.py",
)
server = importlib.util.module_from_spec(_spec)  # type: ignore[assignment]
sys.modules[_spec.name] = server
_spec.loader.exec_module(server)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _make_batch(
    *,
    install_id: str = "01234567-89ab-cdef-0123-456789abcdef",
    app_version: str = "1.4.0",
    platform: str = "linux",
    events: List[Dict[str, Any]] = None,
    sent_at: str = "2026-01-01T00:00:00Z",
) -> Dict[str, Any]:
    return {
        "installId": install_id,
        "appVersion": app_version,
        "platform": platform,
        "sentAt": sent_at,
        "events": events
        if events is not None
        else [
            {"ts": "2026-01-01T00:00:00Z", "name": "tab.open", "props": {"tab": "summary"}},
        ],
    }


def _raw_http_post(
    host: str,
    port: int,
    body: bytes,
    content_type: str = "application/json",
) -> Tuple[int, Dict[str, str], bytes]:
    """Send a request manually so we can exercise error paths like
    malformed Content-Length, which the high-level client hides.
    """
    conn = HTTPConnection(host, port, timeout=5)
    conn.request(
        "POST",
        server.INGEST_PATH,
        body=body,
        headers={"Content-Type": content_type},
    )
    response = conn.getresponse()
    headers = {key.lower(): value for key, value in response.getheaders()}
    data = response.read()
    conn.close()
    return response.status, headers, data


class _ServerThread:
    """Run a real MetricsHTTPServer in a background thread for tests."""

    def __init__(self, config: server.ServerConfig) -> None:
        self.config = config
        self.tmpdir = Path(tempfile.mkdtemp(prefix="psn-metrics-"))
        config.data_dir = self.tmpdir
        self.sink = server.MetricsSink(self.tmpdir)
        self.server = server.MetricsHTTPServer(
            ("127.0.0.1", _find_free_port()), self.sink, config
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()

    @property
    def address(self) -> Tuple[str, int]:
        return self.server.server_address

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.sink.shutdown()


@contextlib.contextmanager
def _running_server(
    config: server.ServerConfig = None,
) -> Iterator[_ServerThread]:
    config = config or server.ServerConfig()
    runner = _ServerThread(config)
    try:
        yield runner
    finally:
        runner.stop()


def _read_ndjson(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


class SanitisationTests(unittest.TestCase):
    def test_event_name_rejects_uppercase_and_punctuation(self):
        for bad in ("Tab.Open", "tab open", "tab/open", "", None, 5):
            with self.subTest(bad=bad):
                self.assertFalse(server._is_event_name(bad))

    def test_event_name_accepts_dotted_segments(self):
        self.assertTrue(server._is_event_name("tab.open"))
        self.assertTrue(server._is_event_name("error.conv_decode"))
        self.assertTrue(server._is_event_name("flush"))

    def test_install_id_rejects_short_and_pathological_inputs(self):
        for bad in ("", "short", "../etc/passwd", None, 123, "x" * 200):
            with self.subTest(bad=bad):
                self.assertFalse(server._is_install_id(bad))

    def test_sanitize_props_strips_unknown_keys(self):
        result = server._sanitize_props(
            {"tab": "summary", "evil": "x", "ok": True, "durationMs": 12.5}
        )
        self.assertEqual(
            result,
            {"tab": "summary", "ok": True, "durationMs": 12.5},
        )

    def test_sanitize_props_truncates_long_strings(self):
        long_value = "x" * 1024
        result = server._sanitize_props({"action": long_value})
        self.assertEqual(result["action"], "x" * server._PROP_STRING_MAX)

    def test_sanitize_props_drops_nan_and_overflow(self):
        result = server._sanitize_props(
            {"bytes": float("nan"), "resultCount": 10 ** 20}
        )
        self.assertNotIn("bytes", result)
        self.assertNotIn("resultCount", result)

    def test_sanitize_event_replaces_missing_timestamp(self):
        event = server._sanitize_event({"name": "tab.open"}, "2026-01-01T00:00:00Z")
        self.assertIsNotNone(event)
        self.assertEqual(event["ts"], "2026-01-01T00:00:00Z")

    def test_sanitize_event_drops_bad_name(self):
        self.assertIsNone(server._sanitize_event({"name": "BAD"}, "x"))
        self.assertIsNone(server._sanitize_event({"name": ""}, "x"))
        self.assertIsNone(server._sanitize_event({}, "x"))


class SinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="psn-metrics-sink-"))

    def tearDown(self) -> None:
        # Close any sinks the test created so file handles do not
        # leak across tests (the OS would close them at process
        # exit but Python surfaces a ResourceWarning otherwise).
        for value in list(vars(self).values()):
            if isinstance(value, server.MetricsSink):
                with contextlib.suppress(Exception):
                    value.shutdown()
        # Best-effort cleanup; the tmp dir is local and small.
        for child in self.tmp.glob("*"):
            with contextlib.suppress(OSError):
                if child.is_file():
                    child.unlink()
                else:
                    child.rmdir()
        with contextlib.suppress(OSError):
            self.tmp.rmdir()

    def test_writes_one_event_line_per_event(self):
        self.sink = server.MetricsSink(self.tmp)
        batch = _make_batch(
            events=[
                {"ts": "2026-01-01T00:00:00Z", "name": "tab.open", "props": {"tab": "summary"}},
                {"ts": "2026-01-01T00:00:01Z", "name": "tab.open", "props": {"tab": "data"}},
            ]
        )
        self.sink.write_batch(batch, client_ip="127.0.0.1", server_received_at="2026-01-01T00:00:00Z")

        events_path = self.tmp / "events-2026-01-01.ndjson"
        rows = _read_ndjson(events_path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["event"], "tab.open")
        self.assertEqual(rows[0]["install_id"], batch["installId"])
        self.assertEqual(rows[0]["props"], {"tab": "summary"})
        self.assertEqual(rows[1]["props"], {"tab": "data"})

    def test_separates_error_events_into_errors_file(self):
        self.sink = server.MetricsSink(self.tmp)
        batch = _make_batch(
            events=[
                {"ts": "2026-01-01T00:00:00Z", "name": "tab.open", "props": {"tab": "summary"}},
                {
                    "ts": "2026-01-01T00:00:02Z",
                    "name": "error.conv_decode",
                    "props": {"kind": "boom"},
                },
            ]
        )
        self.sink.write_batch(batch, client_ip="127.0.0.1", server_received_at="2026-01-01T00:00:00Z")
        self.assertEqual(len(_read_ndjson(self.tmp / "events-2026-01-01.ndjson")), 2)
        self.assertEqual(len(_read_ndjson(self.tmp / "errors-2026-01-01.ndjson")), 1)

    def test_installs_file_records_each_install_once_per_day(self):
        self.sink = server.MetricsSink(self.tmp)
        received = "2026-01-01T00:00:00Z"
        self.sink.write_batch(_make_batch(), client_ip="127.0.0.1", server_received_at=received)
        self.sink.write_batch(_make_batch(), client_ip="127.0.0.1", server_received_at=received)
        # Same installId, same day -> one row total.
        rows = _read_ndjson(self.tmp / "installs-2026-01-01.ndjson")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["install_id"], _make_batch()["installId"])

    def test_install_heartbeat_rotates_with_day_change(self):
        self.sink = server.MetricsSink(self.tmp)
        # Force the first day, then a different day.
        self.sink.write_batch(_make_batch(), client_ip="127.0.0.1", server_received_at="2026-01-01T00:00:00Z")
        self.sink.write_batch(_make_batch(), client_ip="127.0.0.1", server_received_at="2026-01-02T00:00:00Z")
        self.assertEqual(len(_read_ndjson(self.tmp / "installs-2026-01-01.ndjson")), 1)
        self.assertEqual(len(_read_ndjson(self.tmp / "installs-2026-01-02.ndjson")), 1)

    def test_rotates_to_next_day_file(self):
        self.sink = server.MetricsSink(self.tmp)
        self.sink.write_batch(_make_batch(), client_ip="127.0.0.1", server_received_at="2026-01-01T00:00:00Z")
        self.sink.write_batch(_make_batch(), client_ip="127.0.0.1", server_received_at="2026-01-02T00:00:00Z")
        self.assertTrue((self.tmp / "events-2026-01-01.ndjson").exists())
        self.assertTrue((self.tmp / "events-2026-01-02.ndjson").exists())

    def test_health_json_is_overwritten_each_batch(self):
        self.sink = server.MetricsSink(self.tmp)
        self.sink.write_batch(_make_batch(), client_ip="127.0.0.1", server_received_at="2026-01-01T00:00:00Z")
        health = json.loads((self.tmp / "health.json").read_text())
        self.assertEqual(health["lastClient"]["ip"], "127.0.0.1")
        self.assertEqual(health["uniqueInstalls"], 1)

    def test_state_counts_advance_correctly(self):
        self.sink = server.MetricsSink(self.tmp)
        batch = _make_batch(
            events=[
                {"ts": "2026-01-01T00:00:00Z", "name": "tab.open", "props": {"tab": "summary"}},
                {"ts": "2026-01-01T00:00:01Z", "name": "error.bad", "props": {"kind": "x"}},
            ]
        )
        self.sink.write_batch(batch, client_ip="127.0.0.1", server_received_at="2026-01-01T00:00:00Z")
        self.sink.write_batch(_make_batch(), client_ip="127.0.0.1", server_received_at="2026-01-01T00:00:00Z")
        self.assertEqual(self.sink._state["totalBatches"], 2)
        self.assertEqual(self.sink._state["totalEvents"], 3)
        self.assertEqual(self.sink._state["totalErrors"], 1)
        self.assertEqual(self.sink._state["totalInstalls"], 1)

    def test_invalid_event_is_dropped_but_batch_proceeds(self):
        self.sink = server.MetricsSink(self.tmp)
        batch = _make_batch(
            events=[
                {"ts": "2026-01-01T00:00:00Z", "name": "tab.open", "props": {"tab": "summary"}},
                {"ts": "2026-01-01T00:00:01Z", "name": "BAD/NAME"},
                "not-a-dict",
            ]
        )
        counts = self.sink.write_batch(
            batch, client_ip="127.0.0.1", server_received_at="2026-01-01T00:00:00Z"
        )
        self.assertEqual(counts["events"], 1)


class HttpServerTests(unittest.TestCase):
    def test_health_endpoint_returns_200(self):
        with _running_server() as runner:
            host, port = runner.address
            conn = HTTPConnection(host, port, timeout=5)
            conn.request("GET", server.HEALTH_PATH)
            response = conn.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["queueDepth"], 0)

    def test_post_round_trip_persists_events(self):
        with _running_server() as runner:
            host, port = runner.address
            body = json.dumps(
                _make_batch(
                    events=[
                        {"ts": "2026-01-01T00:00:00Z", "name": "tab.open", "props": {"tab": "summary"}}
                    ]
                )
            ).encode("utf-8")
            status, _, payload_bytes = _raw_http_post(host, port, body)
            self.assertEqual(status, 202)
            payload = json.loads(payload_bytes)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["received"]["events"], 1)
            # Allow the worker to finish writing before we inspect disk.
            time.sleep(0.1)
            rows = _read_ndjson(runner.tmpdir / "events-2026-01-01.ndjson")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["event"], "tab.open")

    def test_unknown_route_returns_404(self):
        with _running_server() as runner:
            host, port = runner.address
            conn = HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/nope")
            self.assertEqual(conn.getresponse().status, 404)

    def test_invalid_json_body_returns_400(self):
        with _running_server() as runner:
            host, port = runner.address
            status, _, _ = _raw_http_post(host, port, b"not-json")
            self.assertEqual(status, 400)

    def test_missing_content_length_returns_400(self):
        with _running_server() as runner:
            host, port = runner.address
            # Build a raw HTTP request without Content-Length.
            import socket as _socket
            with _socket.create_connection((host, port), timeout=5) as sock:
                payload = b'{"installId":"01234567-89ab-cdef-0123-456789abcdef","appVersion":"1.4.0","platform":"linux","sentAt":"2026-01-01T00:00:00Z","events":[{"ts":"2026-01-01T00:00:00Z","name":"tab.open","props":{"tab":"summary"}}]}'
                request = (
                    f"POST {server.INGEST_PATH} HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Content-Type: application/json\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode() + payload
                sock.sendall(request)
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            self.assertIn(b"400 Bad Request", response.splitlines()[0])

    def test_payload_too_large_returns_413(self):
        config = server.ServerConfig()
        config.max_body = 256
        with _running_server(config) as runner:
            host, port = runner.address
            huge = _make_batch(events=[
                {"ts": "2026-01-01T00:00:00Z", "name": "tab.open", "props": {"tab": "x" * 1024}}
            ])
            body = json.dumps(huge).encode("utf-8")
            status, _, _ = _raw_http_post(host, port, body)
            self.assertEqual(status, 413)

    def test_invalid_install_id_returns_400(self):
        with _running_server() as runner:
            host, port = runner.address
            batch = _make_batch(install_id="../etc/passwd")
            body = json.dumps(batch).encode("utf-8")
            status, _, _ = _raw_http_post(host, port, body)
            self.assertEqual(status, 400)

    def test_unknown_platform_returns_400(self):
        with _running_server() as runner:
            host, port = runner.address
            body = json.dumps(_make_batch(platform="plan9")).encode("utf-8")
            status, _, _ = _raw_http_post(host, port, body)
            self.assertEqual(status, 400)

    def test_empty_events_returns_400(self):
        with _running_server() as runner:
            host, port = runner.address
            body = json.dumps(_make_batch(events=[])).encode("utf-8")
            status, _, _ = _raw_http_post(host, port, body)
            self.assertEqual(status, 400)

    def test_too_many_events_returns_400(self):
        with _running_server() as runner:
            host, port = runner.address
            events = [
                {"ts": "2026-01-01T00:00:00Z", "name": "tab.open", "props": {"tab": "summary"}}
            ] * 5001
            body = json.dumps(_make_batch(events=events)).encode("utf-8")
            status, _, _ = _raw_http_post(host, port, body)
            self.assertEqual(status, 400)

    def test_queue_full_returns_503(self):
        config = server.ServerConfig()
        config.max_queue = 1
        with _running_server(config) as runner:
            host, port = runner.address
            # Block the writer thread so the second request fills the queue.
            with mock.patch.object(runner.sink, "write_batch", side_effect=lambda *a, **k: time.sleep(0.5)):
                body = json.dumps(_make_batch()).encode("utf-8")
                # Fire both POSTs concurrently so the second arrives
                # while the worker is still busy with the first. The
                # server holds the in-flight item in the queue while
                # writing, so ``max_queue=1`` rejects the second.
                import threading as _threading
                results: list = []
                def _post() -> None:
                    results.append(_raw_http_post(host, port, body))
                first = _threading.Thread(target=_post)
                first.start()
                time.sleep(0.05)  # let the first POST reach the server
                second = _threading.Thread(target=_post)
                second.start()
                first.join(timeout=5)
                second.join(timeout=5)
                statuses = sorted(r[0] for r in results)
                self.assertEqual(statuses, [202, 503])

    def test_concurrent_clients_are_serialised_by_sink(self):
        with _running_server() as runner:
            host, port = runner.address
            bodies = [
                json.dumps(
                    _make_batch(
                        events=[
                            {
                                "ts": "2026-01-01T00:00:00Z",
                                "name": "tab.open",
                                "props": {"tab": f"t-{i}"},
                            }
                        ]
                    )
                ).encode("utf-8")
                for i in range(8)
            ]
            statuses = []
            for body in bodies:
                status, _, _ = _raw_http_post(host, port, body)
                statuses.append(status)
            self.assertEqual(statuses, [202] * 8)
            time.sleep(0.2)
            rows = _read_ndjson(runner.tmpdir / "events-2026-01-01.ndjson")
            self.assertEqual(len(rows), 8)

    def test_x_forwarded_for_honored_when_trusted(self):
        config = server.ServerConfig()
        config.trust_xff = True
        with _running_server(config) as runner:
            host, port = runner.address
            body = json.dumps(_make_batch()).encode("utf-8")
            conn = HTTPConnection(host, port, timeout=5)
            conn.request(
                "POST",
                server.INGEST_PATH,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Forwarded-For": "203.0.113.42",
                },
            )
            self.assertEqual(conn.getresponse().status, 202)
            time.sleep(0.1)
            health = json.loads((runner.tmpdir / "health.json").read_text())
            self.assertEqual(health["lastClient"]["ip"], "203.0.113.42")


class GzipRotationTests(unittest.TestCase):
    def test_old_file_is_compressed(self):
        tmp = Path(tempfile.mkdtemp(prefix="psn-metrics-gz-"))
        sink = server.MetricsSink(tmp, gzip_after_days=0)
        try:
            # gzip_after_days=0 means compress immediately on the
            # first rotation, which we trigger by writing a batch and
            # then forcing a different day.
            sink.write_batch(_make_batch(), client_ip="127.0.0.1", server_received_at="2026-01-01T00:00:00Z")
            sink._rotate_if_needed(_dt.date(2026, 1, 2))
            self.assertFalse((tmp / "events-2026-01-01.ndjson").exists())
            self.assertTrue((tmp / "events-2026-01-01.ndjson.gz").exists())
        finally:
            with contextlib.suppress(Exception):
                sink.shutdown()
            for child in tmp.glob("*"):
                with contextlib.suppress(OSError):
                    child.unlink()
            with contextlib.suppress(OSError):
                tmp.rmdir()

    def test_disabled_keeps_plain_file(self):
        # ``gzip_after_days=-1`` is the "off" sentinel: the sink must
        # leave yesterday's files as plain ``.ndjson`` on disk so an
        # external tool (typically ``logrotate`` with ``copytruncate``)
        # can own rotation and compression. The gzip step is
        # completely skipped — no ``.gz`` file is ever produced and the
        # plain file is left untouched for the next rotation to keep
        # appending to.
        tmp = Path(tempfile.mkdtemp(prefix="psn-metrics-gz-off-"))
        sink = server.MetricsSink(tmp, gzip_after_days=-1)
        try:
            sink.write_batch(
                _make_batch(),
                client_ip="127.0.0.1",
                server_received_at="2026-01-01T00:00:00Z",
            )
            # Force a rotation several days forward — without the off
            # sentinel a sane default (e.g. 7) would have compressed
            # the old file by now.
            sink._rotate_if_needed(_dt.date(2026, 1, 30))
            self.assertTrue((tmp / "events-2026-01-01.ndjson").exists())
            self.assertFalse((tmp / "events-2026-01-01.ndjson.gz").exists())
            self.assertTrue((tmp / "installs-2026-01-01.ndjson").exists())
            self.assertFalse((tmp / "installs-2026-01-01.ndjson.gz").exists())
            self.assertTrue((tmp / "errors-2026-01-01.ndjson").exists())
            self.assertFalse((tmp / "errors-2026-01-01.ndjson.gz").exists())
        finally:
            with contextlib.suppress(Exception):
                sink.shutdown()
            for child in tmp.glob("*"):
                with contextlib.suppress(OSError):
                    child.unlink()
            with contextlib.suppress(OSError):
                tmp.rmdir()

    def test_any_negative_value_disables_gzip(self):
        # The docstring promises ``-1`` is the sentinel; defensively
        # we accept any negative value so a typo (``-7`` instead of
        # ``7``) does not silently start gzipping on every rotation.
        tmp = Path(tempfile.mkdtemp(prefix="psn-metrics-gz-neg-"))
        sink = server.MetricsSink(tmp, gzip_after_days=-365)
        try:
            sink.write_batch(
                _make_batch(),
                client_ip="127.0.0.1",
                server_received_at="2026-01-01T00:00:00Z",
            )
            sink._rotate_if_needed(_dt.date(2026, 12, 31))
            self.assertTrue((tmp / "events-2026-01-01.ndjson").exists())
            self.assertFalse((tmp / "events-2026-01-01.ndjson.gz").exists())
        finally:
            with contextlib.suppress(Exception):
                sink.shutdown()
            for child in tmp.glob("*"):
                with contextlib.suppress(OSError):
                    child.unlink()
            with contextlib.suppress(OSError):
                tmp.rmdir()


class FutureTests(unittest.TestCase):
    def test_future_returns_result(self):
        f = server.AckFuture()
        f.set_result({"events": 1, "errors": 0, "installs": 1})
        self.assertEqual(f.get(timeout=0.1), {"events": 1, "errors": 0, "installs": 1})

    def test_future_propagates_exception(self):
        f = server.AckFuture()
        f.set_exception(RuntimeError("boom"))
        with self.assertRaises(RuntimeError):
            f.get(timeout=0.1)

    def test_future_times_out(self):
        f = server.AckFuture()
        with self.assertRaises(TimeoutError):
            f.get(timeout=0.05)


class ConnectionTeardownTests(unittest.TestCase):
    """Regression coverage for clients that vanish mid-request.

    Idle keep-alive sockets behind NAT, port scanners, and aborted
    browsers all generate a stream of TCP connections that close before
    the request line is fully transmitted. The stdlib's ``serve_forever``
    loop handles the connection object, but the default ``handle()``
    raises ``ConnectionResetError`` (errno 104) — which previously
    dumped a multi-line traceback into the supervisor's stderr for
    every such probe. The override in ``MetricsRequestHandler.handle``
    must swallow that family and let the worker thread move on.
    """

    def _make_handler(self) -> server.MetricsRequestHandler:
        # The handler's ``__init__`` talks to a real socket, so build a
        # connected socketpair instead and feed the request side to it.
        # Using ``socketpair`` avoids needing a bound listener and keeps
        # the test hermetic and fast.
        client_sock, server_sock = socket.socketpair(socket.AF_UNIX)
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        # Stub out the constructor so we can populate the few
        # attributes ``handle()`` touches without performing the real
        # setup dance (rfile/wfile/client_address).
        with mock.patch.object(server.MetricsRequestHandler, "__init__", lambda self: None):
            handler = server.MetricsRequestHandler()
        handler.client_address = ("127.0.0.1", 0)
        handler.rfile = io.BytesIO(b"")
        handler.wfile = io.BytesIO()
        handler.headers = {}
        handler.command = "GET"
        handler.request_version = "HTTP/1.1"
        handler.raw_requestline = b""
        handler.close_connection = True
        return handler

    def test_handle_swallows_connection_reset(self):
        handler = self._make_handler()
        with mock.patch.object(
            server.BaseHTTPRequestHandler,
            "handle",
            side_effect=ConnectionResetError(104, "Connection reset by peer"),
        ):
            # Must not raise — the whole point of the override.
            handler.handle()

    def test_handle_swallows_connection_aborted(self):
        handler = self._make_handler()
        with mock.patch.object(
            server.BaseHTTPRequestHandler,
            "handle",
            side_effect=ConnectionAbortedError(103, "Software caused connection abort"),
        ):
            handler.handle()

    def test_handle_swallows_broken_pipe(self):
        handler = self._make_handler()
        with mock.patch.object(
            server.BaseHTTPRequestHandler,
            "handle",
            side_effect=BrokenPipeError(32, "Broken pipe"),
        ):
            handler.handle()

    def test_handle_swallows_shutdown_ebadf(self):
        handler = self._make_handler()
        with mock.patch.object(
            server.BaseHTTPRequestHandler,
            "handle",
            side_effect=OSError(9, "Bad file descriptor"),
        ):
            handler.handle()

    def test_handle_still_propagates_unexpected_errors(self):
        handler = self._make_handler()
        with mock.patch.object(
            server.BaseHTTPRequestHandler,
            "handle",
            side_effect=RuntimeError("synthetic programming error"),
        ):
            with self.assertRaises(RuntimeError):
                handler.handle()


class EndToEndBatchTests(unittest.TestCase):
    def test_full_event_persists_in_elasticsearch_shape(self):
        """Validate that the row we write matches the field names a
        Logstash/Elastic pipeline would expect (``@timestamp``,
        nested ``props``, etc.) and is single-line JSON.
        """
        with _running_server() as runner:
            host, port = runner.address
            body = json.dumps(
                _make_batch(
                    events=[
                        {
                            "ts": "2026-01-01T00:00:00Z",
                            "name": "tab.open",
                            "props": {"tab": "summary", "durationMs": 12.5},
                        }
                    ]
                )
            ).encode("utf-8")
            status, _, _ = _raw_http_post(host, port, body)
            self.assertEqual(status, 202)
            time.sleep(0.1)
            path = runner.tmpdir / "events-2026-01-01.ndjson"
            with open(path, "r", encoding="utf-8") as handle:
                line = handle.readline()
            payload = json.loads(line)
            self.assertEqual(payload["@timestamp"], "2026-01-01T00:00:00Z")
            self.assertEqual(payload["event"], "tab.open")
            self.assertEqual(payload["install_id"], _make_batch()["installId"])
            self.assertEqual(payload["props"]["tab"], "summary")
            self.assertEqual(payload["props"]["durationMs"], 12.5)


class ServerLoggingTests(unittest.TestCase):
    """Coverage for the line-by-line server log.

    Every request the server accepts produces exactly one access-log
    line on the ``packetsnitch.metrics`` logger. Operators rely on
    these lines to grep for status codes, hot paths, slow handlers
    and the bind/listen lifecycle, so the tests pin the format and
    the field set the operator asked for: startup, shutdown, bind,
    listen, config (with the API key redacted), disk errors, and
    per-request status codes.
    """

    def setUp(self) -> None:
        # Capture log records on the metrics logger so we can assert
        # that ``log_request``, ``server_bind``, ``server_activate``,
        # the startup line, and the disk-error paths each emit one
        # well-formed log record per event.
        self._records: List[logging.LogRecord] = []
        handler = logging.Handler()
        handler.setLevel(logging.DEBUG)
        handler.emit = self._records.append  # type: ignore[assignment]
        self._handler = handler
        self._logger = logging.getLogger("packetsnitch.metrics")
        self._logger.addHandler(handler)
        self._logger.setLevel(logging.DEBUG)

    def tearDown(self) -> None:
        self._logger.removeHandler(self._handler)

    def _access_records(self) -> List[logging.LogRecord]:
        return [r for r in self._records if r.getMessage().startswith("access ")]

    def _access_lines(self) -> List[str]:
        return [self._format(record) for record in self._access_records()]

    def _status_from_access_line(self, line: str) -> str:
        # Format:
        #   access <iso8601> <client_ip:port> "<method> <path> <proto>" <status> <bytes> <duration>ms
        # ``rsplit`` from the right with ``maxsplit=4`` peels off the
        # trailing ``<duration>ms`` and ``<bytes>`` fields and lands
        # on the status. The quoted request line before it is the
        # field we want intact.
        tail = line.rsplit(" ", 4)
        return tail[-3]

    @staticmethod
    def _format(record: logging.LogRecord) -> str:
        # Mirror the production formatter (``logging.basicConfig``
        # uses ``%(asctime)s %(levelname)s %(name)s %(message)s``).
        return f"{record.levelname} {record.name} {record.getMessage()}"

    # ---- request-side access log --------------------------------------

    def test_get_health_emits_access_line_with_status_and_bytes(self):
        with _running_server() as runner:
            host, port = runner.address
            conn = HTTPConnection(host, port, timeout=5)
            conn.request("GET", server.HEALTH_PATH)
            response = conn.getresponse()
            response.read()
        access = self._access_lines()
        self.assertEqual(len(access), 1)
        line = access[0]
        self.assertIn("GET /healthz HTTP/1.1", line)
        self.assertIn(" 200 ", line)
        # Bytes should be a non-negative integer.
        parts = line.rsplit(" ", 2)
        self.assertTrue(parts[-2].isdigit())
        # Duration like "0.50ms" is always present.
        self.assertRegex(parts[-1], r"^\d+\.\d{2}ms$")

    def test_post_ingest_accepted_logs_202(self):
        with _running_server() as runner:
            host, port = runner.address
            body = json.dumps(_make_batch()).encode("utf-8")
            status, _, _ = _raw_http_post(host, port, body)
            self.assertEqual(status, 202)
        access = self._access_lines()
        self.assertEqual(len(access), 1)
        self.assertIn(f"POST {server.INGEST_PATH}", access[0])
        self.assertIn(" 202 ", access[0])

    def test_404_unknown_route_logs_404(self):
        with _running_server() as runner:
            host, port = runner.address
            conn = HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/nope")
            self.assertEqual(conn.getresponse().status, 404)
        access = self._access_lines()
        self.assertEqual(len(access), 1)
        self.assertIn("GET /nope", access[0])
        self.assertIn(" 404 ", access[0])

    def test_400_invalid_payload_logs_400(self):
        with _running_server() as runner:
            host, port = runner.address
            status, _, _ = _raw_http_post(host, port, b"not-json")
            self.assertEqual(status, 400)
        access = self._access_lines()
        self.assertEqual(len(access), 1)
        self.assertIn(f"POST {server.INGEST_PATH}", access[0])
        self.assertIn(" 400 ", access[0])

    def test_413_payload_too_large_logs_413(self):
        config = server.ServerConfig()
        config.max_body = 256
        with _running_server(config) as runner:
            host, port = runner.address
            huge = _make_batch(events=[
                {"ts": "2026-01-01T00:00:00Z", "name": "tab.open", "props": {"tab": "x" * 1024}}
            ])
            body = json.dumps(huge).encode("utf-8")
            status, _, _ = _raw_http_post(host, port, body)
            self.assertEqual(status, 413)
        access = self._access_lines()
        self.assertEqual(len(access), 1)
        self.assertIn(" 413 ", access[0])

    def test_503_queue_full_logs_503(self):
        config = server.ServerConfig()
        config.max_queue = 1
        with _running_server(config) as runner:
            host, port = runner.address
            with mock.patch.object(runner.sink, "write_batch", side_effect=lambda *a, **k: time.sleep(0.5)):
                body = json.dumps(_make_batch()).encode("utf-8")
                results: list = []
                def _post() -> None:
                    results.append(_raw_http_post(host, port, body))
                first = threading.Thread(target=_post)
                first.start()
                time.sleep(0.05)
                second = threading.Thread(target=_post)
                second.start()
                first.join(timeout=5)
                second.join(timeout=5)
                statuses = sorted(r[0] for r in results)
                self.assertEqual(statuses, [202, 503])
        access = self._access_lines()
        self.assertEqual(len(access), 2)
        seen = sorted(self._status_from_access_line(line) for line in access)
        self.assertEqual(seen, ["202", "503"])

    def test_query_string_is_stripped_from_path(self):
        with _running_server() as runner:
            host, port = runner.address
            conn = HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/healthz?token=hunter2")
            self.assertEqual(conn.getresponse().status, 200)
        access = self._access_lines()
        self.assertEqual(len(access), 1)
        self.assertIn("GET /healthz HTTP/1.1", access[0])
        self.assertNotIn("hunter2", access[0])

    def test_client_ip_and_port_present_in_access_line(self):
        with _running_server() as runner:
            host, port = runner.address
            conn = HTTPConnection(host, port, timeout=5)
            conn.request("GET", server.HEALTH_PATH)
            conn.getresponse().read()
        records = self._access_records()
        self.assertEqual(len(records), 1)
        # The ``LOG.info(...)`` call uses positional args, so the
        # access line's structured fields land in ``record.args``.
        # Index layout matches the production call:
        #   0: iso8601 timestamp
        #   1: client_ip
        #   2: client_port
        #   3: method
        #   4: path
        #   5: protocol
        #   6: status
        #   7: bytes
        #   8: duration_ms
        record = records[0]
        args = record.args
        self.assertEqual(args[0][-1], "Z")
        self.assertEqual(args[1], "127.0.0.1")
        self.assertIsInstance(args[2], int)
        self.assertGreater(args[2], 0)
        self.assertEqual(args[3], "GET")
        self.assertEqual(args[4], "/healthz")
        self.assertEqual(args[5], "HTTP/1.1")
        self.assertEqual(args[6], 200)
        self.assertIsInstance(args[7], int)
        self.assertGreaterEqual(args[7], 0)
        self.assertIsInstance(args[8], float)
        self.assertGreaterEqual(args[8], 0.0)
        # And the rendered message is still recognisable as an access line.
        self.assertIn('"GET /healthz HTTP/1.1" 200', record.getMessage())

    # ---- bind / listen / config ---------------------------------------

    def test_bind_and_listen_lines_are_emitted_on_startup(self):
        # The simplest possible signal that bind+listen logging works
        # at all: a freshly built server emits both lines.
        config = server.ServerConfig()
        config.data_dir = Path(tempfile.mkdtemp(prefix="psn-metrics-bind-"))
        sink = server.MetricsSink(config.data_dir)
        try:
            with server.MetricsHTTPServer(
                ("127.0.0.1", _find_free_port()), sink, config
            ) as httpd:
                host, port = httpd.server_address
                messages = [r.getMessage() for r in self._records]
                bind_lines = [m for m in messages if m.startswith("bind ok ")]
                listen_lines = [
                    m for m in messages if m.startswith("listen ok ")
                ]
                self.assertTrue(bind_lines, msg=f"messages: {messages}")
                self.assertTrue(listen_lines, msg=f"messages: {messages}")
                self.assertIn(f"host={host}", bind_lines[0])
                self.assertIn(f"port={port}", bind_lines[0])
                self.assertIn(f"host={host}", listen_lines[0])
                self.assertIn(f"port={port}", listen_lines[0])
        finally:
            sink.shutdown()

    def test_config_summary_redacts_api_key(self):
        # Build a config with a real key and check the redacted view
        # actually replaces it with ``<redacted>``. This is the line
        # the operator sees in ``journalctl`` so a leaked key would
        # be a serious bug — pin the redaction.
        config = server.ServerConfig()
        config.admin_api_key = "this-must-not-leak-please"
        safe = server._redactConfigForLog(config)
        dumped = json.dumps(safe)
        self.assertIn("<redacted>", dumped)
        self.assertNotIn("this-must-not-leak-please", dumped)
        self.assertTrue(safe["admin"]["api_key_set"])

    def test_config_summary_keeps_empty_api_key_visible(self):
        # An empty key (admin disabled) should stay visible as the
        # empty string so the operator can confirm the disable was
        # intentional rather than mysterious.
        config = server.ServerConfig()
        config.admin_api_key = ""
        safe = server._redactConfigForLog(config)
        self.assertEqual(safe["admin"]["api_key"], "")
        self.assertFalse(safe["admin"]["api_key_set"])

    def test_log_startup_config_writes_one_line(self):
        # ``_logStartupConfig`` must always emit exactly one INFO
        # record so a `journalctl -u packetsnitch-metrics` always
        # contains the operator-visible config snapshot. Pin both the
        # level and the message shape.
        config = server.ServerConfig()
        config.admin_api_key = "secret-value"
        before = len(self._records)
        server._logStartupConfig(config)
        added = self._records[before:]
        self.assertEqual(len(added), 1)
        record = added[0]
        self.assertEqual(record.levelname, "INFO")
        self.assertTrue(record.getMessage().startswith("config "))
        self.assertIn("host=", record.getMessage())
        self.assertIn("port=", record.getMessage())
        self.assertIn("data_dir=", record.getMessage())
        # The redacted marker must be in the line, the secret must not.
        self.assertIn("<redacted>", record.getMessage())
        self.assertNotIn("secret-value", record.getMessage())

    # ---- disk read/write error paths ----------------------------------

    def test_write_error_logs_path_and_raises(self):
        # ``_atomic_write_json`` must log the failure path with the
        # underlying ``errno`` and re-raise so the caller (sink
        # writer thread) can decide what to do with the batch.
        captured: List[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = captured.append  # type: ignore[assignment]
        logger = logging.getLogger("packetsnitch.metrics")
        logger.addHandler(handler)
        try:
            with mock.patch(
                "builtins.open",
                side_effect=OSError(28, "No space left on device"),
            ):
                with self.assertRaises(OSError):
                    server.MetricsSink._atomic_write_json(
                        Path("/tmp/no-such-path.json"), {"x": 1}
                    )
            self.assertTrue(captured)
            messages = [r.getMessage() for r in captured]
            self.assertTrue(
                any("write failed" in m for m in messages),
                msg=f"messages: {messages}",
            )
            # The log line should include the tmp path and the errno
            # so the operator can grep for the broken disk.
            joined = "\n".join(messages)
            self.assertIn("errno=28", joined)
            self.assertIn("No space left on device", joined)
        finally:
            logger.removeHandler(handler)

    def test_gzip_failure_logs_path_and_continues(self):
        # A failed gzip should not abort the rotation; the plain file
        # is left in place and a warning is logged with the path so
        # the operator can repair permissions.
        tmp = Path(tempfile.mkdtemp(prefix="psn-metrics-gzerr-"))
        sink = server.MetricsSink(tmp, gzip_after_days=0)
        try:
            sink.write_batch(
                _make_batch(),
                client_ip="127.0.0.1",
                server_received_at="2026-01-01T00:00:00Z",
            )
            captured: List[logging.LogRecord] = []
            handler = logging.Handler()
            handler.emit = captured.append  # type: ignore[assignment]
            logger = logging.getLogger("packetsnitch.metrics")
            logger.addHandler(handler)
            try:
                with mock.patch(
                    "gzip.open",
                    side_effect=OSError(13, "Permission denied"),
                ):
                    sink._rotate_if_needed(_dt.date(2026, 1, 2))
            finally:
                logger.removeHandler(handler)
            self.assertTrue(captured)
            messages = [r.getMessage() for r in captured]
            self.assertTrue(
                any("gzip failed" in m for m in messages),
                msg=f"messages: {messages}",
            )
            joined = "\n".join(messages)
            self.assertIn("errno=13", joined)
            self.assertIn("Permission denied", joined)
            # The plain file is preserved so a manual rotation can
            # still pick it up.
            self.assertTrue((tmp / "events-2026-01-01.ndjson").exists())
        finally:
            with contextlib.suppress(Exception):
                sink.shutdown()

    def test_state_json_read_failure_logs_warning(self):
        # ``_last_load_state`` swallows read/parse errors and logs a
        # warning; pin both paths so a regression that raises instead
        # of warning fails the test.
        tmp = Path(tempfile.mkdtemp(prefix="psn-metrics-state-"))
        sink = server.MetricsSink.__new__(server.MetricsSink)
        sink._state = {
            "totalBatches": 0,
            "totalEvents": 0,
            "totalErrors": 0,
            "totalInstalls": 0,
        }
        sink._data_dir = tmp
        sink._state_path = tmp / "state.json"
        sink._health_path = tmp / "health.json"
        sink._known_installs = {}
        sink._gzip_after_days = 7
        sink._lock = threading.Lock()
        sink._gzip_lock = sink._lock
        sink._current_date = None
        sink._events_handle = None
        sink._installs_handle = None
        sink._errors_handle = None
        captured: List[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = captured.append  # type: ignore[assignment]
        logger = logging.getLogger("packetsnitch.metrics")
        logger.addHandler(handler)
        try:
            sink._state_path.write_text("{not valid json")
            sink._last_load_state()
            messages = [r.getMessage() for r in captured]
            self.assertTrue(
                any("state.json" in m for m in messages),
                msg=f"messages: {messages}",
            )
        finally:
            logger.removeHandler(handler)

    # ---- bind failure path -------------------------------------------

    def test_bind_failure_is_logged_and_raises(self):
        # The bind hook must log the failed address and re-raise so
        # the operator's startup script can detect EADDRINUSE cleanly.
        captured: List[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = captured.append  # type: ignore[assignment]
        logger = logging.getLogger("packetsnitch.metrics")
        logger.addHandler(handler)
        try:
            config = server.ServerConfig()
            config.data_dir = Path(tempfile.mkdtemp(prefix="psn-metrics-bindfail-"))
            sink = server.MetricsSink(config.data_dir)
            try:
                # An obviously invalid host forces the kernel to
                # reject the bind with EADDRNOTAVAIL.
                with self.assertRaises(OSError):
                    server.MetricsHTTPServer(
                        ("300.300.300.300", _find_free_port()),
                        sink,
                        config,
                    )
                messages = [r.getMessage() for r in captured]
                self.assertTrue(
                    any("bind failed" in m for m in messages),
                    msg=f"messages: {messages}",
                )
            finally:
                sink.shutdown()
        finally:
            logger.removeHandler(handler)


class LogFileTests(unittest.TestCase):
    """Coverage for the ``server.log_file`` config knob.

    Operators who run the metrics endpoint without a log aggregator
    in front of systemd/docker need a plain text file they can
    ``tail -f``. The server should respect ``log_file`` by opening
    a ``FileHandler`` so every line lands both on stderr (default)
    and on the operator-chosen file. Misconfigured paths should
    surface as a clean startup failure rather than silently
    degrading to stderr-only logging.
    """

    def setUp(self) -> None:
        # Make sure no leftover handlers leak between tests.
        root = logging.getLogger()
        for handler in list(root.handlers):
            root.removeHandler(handler)

    def tearDown(self) -> None:
        root = logging.getLogger()
        for handler in list(root.handlers):
            root.removeHandler(handler)

    def test_default_log_file_is_none(self):
        # When ``server.log_file`` is unset (the shipped default),
        # ``ServerConfig`` should expose ``None`` so callers can
        # use a simple ``is None`` check to skip the file handler.
        config = server.ServerConfig()
        self.assertIsNone(config.log_file)

    def test_log_file_resolves_to_path_when_set(self):
        config = server.ServerConfig({"server": {"log_file": "/var/log/packetsnitch-metrics/ps-metrics.log"}})
        self.assertEqual(
            str(config.log_file),
            "/var/log/packetsnitch-metrics/ps-metrics.log",
        )

    def test_log_file_blank_string_is_treated_as_unset(self):
        # An empty / whitespace-only value should map to ``None``,
        # so a stray blank line in the YAML does not silently
        # change behaviour later.
        for value in ("", "   "):
            with self.subTest(value=value):
                config = server.ServerConfig(
                    {"server": {"log_file": value}}
                )
                self.assertIsNone(config.log_file)

    def test_log_file_expands_user_and_tilde(self):
        # ``~`` should resolve to the user's home, so a config
        # entry like ``~/ps-metrics.log`` works without the
        # operator having to hardcode ``$HOME``.
        config = server.ServerConfig(
            {"server": {"log_file": "~/ps-metrics.log"}}
        )
        resolved = config.log_file
        self.assertNotIn("~", str(resolved))
        self.assertTrue(str(resolved).endswith("ps-metrics.log"))

    def test_configure_logging_writes_lines_to_file(self):
        # Happy path: a fresh log file receives a real INFO line
        # emitted after ``configure_logging`` returns. We use a
        # temp dir so the test is hermetic and can run on systems
        # without write access to ``/var/log``.
        tmp = Path(tempfile.mkdtemp(prefix="psn-logfile-"))
        try:
            log_path = tmp / "ps-metrics.log"
            server.configure_logging("info", log_path)
            try:
                server.LOG.info("hello from log_file test")
            finally:
                # Force every handler to flush before we read.
                for handler in logging.getLogger().handlers:
                    handler.flush()
            content = log_path.read_text(encoding="utf-8")
            self.assertIn("hello from log_file test", content)
            self.assertIn("INFO packetsnitch.metrics", content)
        finally:
            with contextlib.suppress(Exception):
                shutil.rmtree(tmp, ignore_errors=True)

    def test_configure_logging_creates_parent_directory(self):
        # The parent directory should be created on demand so a
        # fresh install on a clean box does not have to ``mkdir -p``
        # before the first run. Use a deeply nested temp path.
        tmp = Path(tempfile.mkdtemp(prefix="psn-logfile-dirs-"))
        try:
            log_path = tmp / "nested" / "deeper" / "ps-metrics.log"
            self.assertFalse(log_path.parent.exists())
            server.configure_logging("info", log_path)
            try:
                self.assertTrue(log_path.parent.is_dir())
                server.LOG.info("nested write ok")
            finally:
                for handler in logging.getLogger().handlers:
                    handler.flush()
            self.assertTrue(log_path.exists())
        finally:
            with contextlib.suppress(Exception):
                shutil.rmtree(tmp, ignore_errors=True)

    def test_configure_logging_unwritable_path_raises(self):
        # A path under a non-existent mount point (we pick
        # ``/proc/...`` here because it cannot be created as a
        # directory of regular files) must surface a clear error so
        # the operator sees the misconfiguration in their journal
        # rather than silently getting stderr-only logging.
        bogus = Path("/proc/this-should-not-exist/ps-metrics.log")
        with self.assertRaises((FileNotFoundError, OSError)) as ctx:
            server.configure_logging("info", bogus)
        message = str(ctx.exception)
        self.assertIn("log_file", message)

    def test_configure_logging_is_idempotent(self):
        # Calling ``configure_logging`` twice (e.g. from a test
        # harness that re-runs setup) should not stack handlers;
        # otherwise every log line ends up duplicated N times.
        tmp = Path(tempfile.mkdtemp(prefix="psn-logfile-idem-"))
        try:
            log_path = tmp / "ps-metrics.log"
            server.configure_logging("info", log_path)
            server.configure_logging("info", log_path)
            handlers = logging.getLogger().handlers
            self.assertEqual(
                len(handlers),
                2,
                msg=(
                    "expected exactly one stderr + one file handler, got "
                    f"{[type(h).__name__ for h in handlers]}"
                ),
            )
        finally:
            with contextlib.suppress(Exception):
                shutil.rmtree(tmp, ignore_errors=True)

    def test_log_file_emits_log_file_enabled_line(self):
        # A ``log_file enabled path=...`` line should appear once
        # each time ``configure_logging`` flips into file-logging
        # mode. Pin the line by reading the log file itself — the
        # file handler is attached at configure-time and flushed
        # before the call returns, so by the time ``configure_logging``
        # returns the line is on disk.
        tmp = Path(tempfile.mkdtemp(prefix="psn-logfile-flag-"))
        try:
            log_path = tmp / "ps-metrics.log"
            server.configure_logging("info", log_path)
            # Flush before reading so the FileHandler actually
            # commits the line.
            for handler in logging.getLogger().handlers:
                handler.flush()
            content = log_path.read_text(encoding="utf-8")
            self.assertIn("log_file enabled", content)
            self.assertIn(str(log_path), content)
            self.assertIn("level=INFO", content)
        finally:
            with contextlib.suppress(Exception):
                shutil.rmtree(tmp, ignore_errors=True)

    def test_log_file_surfaces_in_print_config(self):
        # ``--print-config`` should show the resolved log file so
        # operators can verify which path will be opened at
        # startup.
        config = server.ServerConfig({"server": {"log_file": "/tmp/example.log"}})
        printed = json.dumps(
            {
                "server": {
                    "host": config.host,
                    "port": config.port,
                    "log_level": config.log_level,
                    "log_file": str(config.log_file) if config.log_file else None,
                    "trust_xff": config.trust_xff,
                },
            }
        )
        self.assertIn("/tmp/example.log", printed)

    def test_log_file_path_is_in_startup_config_log(self):
        # The ``config`` log line on startup must surface
        # ``log_file`` so a remote operator (no shell access) can
        # confirm the resolved path from ``journalctl`` alone.
        captured: List[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = captured.append  # type: ignore[assignment]
        logger = logging.getLogger("packetsnitch.metrics")
        logger.addHandler(handler)
        try:
            config = server.ServerConfig(
                {"server": {"log_file": "/tmp/some-config.log"}}
            )
            server._logStartupConfig(config)
            messages = [r.getMessage() for r in captured]
            self.assertTrue(
                any(m.startswith("config ") for m in messages),
                msg=f"messages: {messages}",
            )
            joined = "\n".join(messages)
            self.assertIn("/tmp/some-config.log", joined)
            # And the unset case should render as ``(none)`` so an
            # operator can grep for it without false positives.
            config_no_file = server.ServerConfig({})
            captured.clear()
            server._logStartupConfig(config_no_file)
            joined2 = "\n".join(r.getMessage() for r in captured)
            self.assertIn("log_file=(none)", joined2)
        finally:
            logger.removeHandler(handler)


if __name__ == "__main__":
    unittest.main(verbosity=2)
