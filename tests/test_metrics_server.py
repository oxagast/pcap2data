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
import os
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
# the tests/ directory.
_spec = importlib.util.spec_from_file_location(
    "metrics_server_test_module",
    _PROJECT_ROOT / "src" / "metrics" / "server.py",
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
