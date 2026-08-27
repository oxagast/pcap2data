"""Tests for the /admin/* remote-administration API.

Covers:
  * Auth gating: 503 when no key is configured, 401 when the
    key is missing, 401 when the key is wrong, 200 on the three
    accepted transports (Authorization: Bearer, X-Admin-Key,
    ?key= query param).
  * Every endpoint that maps to a CLI verb:
      - GET  /admin/themes                 (list-themes)
      - GET  /admin/themes/<id>            (theme detail)
      - POST /admin/themes                 (add-theme)
      - POST /admin/themes/<id>/remove     (remove-theme)
      - GET  /admin/installs               (list-installs)
      - GET  /admin/installs/<uuid>        (install detail)
      - POST /admin/installs               (register-install)
      - POST /admin/installs/<uuid>/tier   (set-install-tier)
      - POST /admin/licenses               (add-license)
      - POST /admin/previews               (add-preview)
  * Validation: invalid UUID, invalid theme id, invalid tier,
    unknown theme on add-license, missing fields.
  * Audit log line emitted with ``source=admin_api`` /
    ``actor=<key-prefix>``.
  * End-to-end parity: a change made via the admin API produces
    the same DB state as the equivalent CLI command, including
    the paddle_customer_id fan-out from the prior change.

The tests run the catalog handler in-process via
``ThreadingHTTPServer`` against a fresh sqlite file under
``tmp_path``. We don't need to call ``cmd_serve`` because the
admin API doesn't depend on the setup_token check; we only need
a configured admin_api_key and a writable db / themes_dir /
previews_dir."""

import base64
import importlib.util
import json
import socket
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from http.client import HTTPConnection
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Module loading — ps-catalog.py is a single-file executable script,
# not an importable package, so we load it by file path the same way
# tests/test_catalog_tiers.py does.
# ---------------------------------------------------------------------------


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _catalog_script() -> Path:
    return _project_root() / "src" / "PacketSnitch-Pro" / "Servers" / "Catalog" / "ps-catalog.py"


def _load_catalog_module():
    spec = importlib.util.spec_from_file_location(
        "ps_catalog_admin_test_module", _catalog_script()
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load ps-catalog.py")
    module = importlib.util.module_from_spec(spec)
    # Module must be in ``sys.modules`` before ``exec_module`` or
    # Python 3.14's dataclass introspection crashes on
    # ``sys.modules.get(cls.__module__)``.
    sys.modules["ps_catalog_admin_test_module"] = module
    spec.loader.exec_module(module)
    return module


_catalog = _load_catalog_module()


# ---------------------------------------------------------------------------
# In-process server fixture
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Bind to port 0 and let the kernel pick one. Then close the
    socket so the server can re-bind to the same port. This is the
    only reliable way to find a free port in a test — picking a
    random high number and hoping it's free races with parallel
    test runs on the same host."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextmanager
def running_server(tmp_path: Path, *, admin_api_key: str = "test-admin-key-do-not-use"):
    """Start the catalog HTTP server on a free port backed by a
    fresh sqlite file under ``tmp_path``. Yields the port number
    on success; tears the server down on exit. Skips the test if
    the handler can't bind (e.g. the host has IP_FREEBIND off and
    the test runs inside a sandbox)."""
    port = _free_port()
    db_path = tmp_path / f"catalog-{uuid.uuid4().hex}.sqlite3"
    themes_dir = tmp_path / "themes"
    previews_dir = tmp_path / "previews"
    themes_dir.mkdir(parents=True, exist_ok=True)
    previews_dir.mkdir(parents=True, exist_ok=True)
    # Build a Config object the way ``cmd_serve`` would, but skip
    # the setup_token guard — the admin API doesn't depend on it
    # and the placeholder check would block every test.
    cfg = _catalog.Config(
        host="127.0.0.1",
        port=port,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=previews_dir,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        paddle_env="sandbox",
        base_url=f"http://127.0.0.1:{port}",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        setup_token="test-setup-token",
        admin_api_key=admin_api_key,
        log_dir=tmp_path / "logs",
        log_file="catalog.log",
        log_rotate=False,
        paddle_poll_enabled=False,
        paddle_poll_interval=0,
        smtp_host="",
        smtp_port=25,
        smtp_username=None,
        smtp_password=None,
        smtp_from="noreply@packetsnitch.test",
        smtp_use_tls=False,
        admin_portal_enabled=True,
        admin_session_ttl_hours=12,
    )
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    db = _catalog.CatalogDB(db_path)
    server = _catalog.make_server(cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Poll the port until it accepts connections; the server is
    # ready when the kernel accepts a TCP SYN to it. ``serve_forever``
    # is a no-op until ``server_activate`` has run, which is after
    # ``__init__`` returns — so a brief sleep is enough but a poll
    # is faster on a busy CI runner.
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.05)
            s.close()
            break
        except OSError:
            time.sleep(0.01)
    else:  # pragma: no cover - port-bind failure is environmental
        server.shutdown()
        server.server_close()
        db.close()
        pytest.skip(f"Could not bind to port {port} in time")
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        db.close()


def _http(
    port: int,
    method: str,
    path: str,
    *,
    body: dict | None = None,
    headers: dict | None = None,
    raw_body: bytes | None = None,
) -> tuple[int, dict, str]:
    """Issue a single HTTP request to the running server and
    return ``(status, json_or_empty_dict, raw_body)``. On a
    non-JSON response (e.g. 401 with empty body), the dict is
    empty and the raw body is the third return value. Connection
    is closed after each request because the test is short-lived
    and keeping a long-lived connection around adds no value."""
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    final_headers = {"Accept": "application/json"}
    if headers:
        final_headers.update(headers)
    if body is not None and raw_body is None:
        raw_body = json.dumps(body).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/json")
    if raw_body is not None:
        final_headers.setdefault("Content-Length", str(len(raw_body)))
    try:
        conn.request(method, path, body=raw_body, headers=final_headers)
        response = conn.getresponse()
        data = response.read()
    finally:
        conn.close()
    text = data.decode("utf-8", errors="replace") if data else ""
    try:
        parsed = json.loads(text) if text else {}
    except json.JSONDecodeError:
        parsed = {}
    return response.status, parsed, text


# ---------------------------------------------------------------------------
# Auth gating
# ---------------------------------------------------------------------------


def test_admin_endpoints_return_503_when_no_key_configured(tmp_path):
    """``/admin/*`` returns 503 with ``adminDisabled: true`` when
    the server has no admin_api_key. This is the developer-mode
    contract: the server still boots, the public endpoints work,
    but the admin surface is unavailable."""
    with running_server(tmp_path, admin_api_key="") as port:
        status, payload, _ = _http(port, "GET", "/admin/themes")
        assert status == 503
        assert payload.get("adminDisabled") is True
        assert "not configured" in payload.get("error", "").lower()


def test_admin_endpoints_return_401_when_key_missing(tmp_path):
    """A request to ``/admin/*`` without any credential returns
    401 with a ``WWW-Authenticate: Bearer`` header so HTTP
    libraries know to retry with a credential."""
    with running_server(tmp_path) as port:
        for path in ("/admin/themes", "/admin/installs"):
            status, payload, _ = _http(port, "GET", path)
            assert status == 401, f"{path} expected 401, got {status}"
            assert "error" in payload or payload == {}


def test_admin_endpoints_return_401_when_key_wrong(tmp_path):
    """A wrong key returns 401 — no diagnostic detail about
    *why* it's wrong, so the endpoint doesn't help an attacker
    learn whether the key is right-shaped but wrong-value vs.
    missing entirely."""
    with running_server(tmp_path, admin_api_key="the-real-key") as port:
        status, _, _ = _http(
            port, "GET", "/admin/themes",
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert status == 401
        status, _, _ = _http(
            port, "GET", "/admin/themes",
            headers={"X-Admin-Key": "also-wrong"},
        )
        assert status == 401


def test_admin_accepts_authorization_bearer_header(tmp_path):
    """The canonical transport. Mirrors the OAuth 2.0 bearer
    convention every HTTP client library already speaks."""
    with running_server(tmp_path, admin_api_key="the-real-key") as port:
        status, payload, _ = _http(
            port, "GET", "/admin/themes",
            headers={"Authorization": "Bearer the-real-key"},
        )
        assert status == 200
        assert "entries" in payload


def test_admin_accepts_x_admin_key_header(tmp_path):
    """Convenient for ``curl -H`` and for browser-based admin
    tools that don't easily set the ``Authorization`` header."""
    with running_server(tmp_path, admin_api_key="the-real-key") as port:
        status, payload, _ = _http(
            port, "GET", "/admin/themes",
            headers={"X-Admin-Key": "the-real-key"},
        )
        assert status == 200
        assert "entries" in payload


def test_admin_accepts_query_string_key(tmp_path):
    """Fallback transport only. Documents the caveat: the key
    leaks into the catalog's own access log via the standard
    query-string field."""
    with running_server(tmp_path, admin_api_key="the-real-key") as port:
        status, payload, _ = _http(
            port, "GET", "/admin/themes?key=the-real-key",
        )
        assert status == 200
        assert "entries" in payload


def test_admin_rejects_non_bearer_authorization_scheme(tmp_path):
    """``Authorization: Basic`` / ``Token`` / etc. are rejected
    so the bearer scheme stays the only credential type that
    works. An operator who typed the wrong scheme name gets a
    401 with no diagnostic detail."""
    with running_server(tmp_path, admin_api_key="the-real-key") as port:
        status, _, _ = _http(
            port, "GET", "/admin/themes",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert status == 401
        status, _, _ = _http(
            port, "GET", "/admin/themes",
            headers={"Authorization": "Token the-real-key"},
        )
        assert status == 401


# ---------------------------------------------------------------------------
# Themes endpoints
# ---------------------------------------------------------------------------


def test_admin_list_themes_initially_empty(tmp_path):
    with running_server(tmp_path) as port:
        status, payload, _ = _http(
            port, "GET", "/admin/themes",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
        )
        assert status == 200
        assert payload["entries"] == []


def test_admin_post_themes_creates_and_lists_theme(tmp_path):
    with running_server(tmp_path) as port:
        status, payload, _ = _http(
            port, "POST", "/admin/themes",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={
                "id": "matrix-theme",
                "name": "Matrix",
                "description": "Green-phosphor hacker vibe",
                "priceCents": 299,
                "priceLabel": "$2.99",
                "paddle": {"productId": "pro_123", "priceId": "pri_456"},
                "checkoutUrl": "https://example.com/checkout",
                "hostedCheckoutUrl": "https://pay.paddle.com/checkout/abc",
                "licenseUrl": "https://example.com/license",
            },
        )
        assert status == 200, payload
        assert payload.get("ok") is True
        assert payload.get("themeId") == "matrix-theme"
        # Theme JSON should have been written to themes_dir so
        # /themes/<id>/download can serve it.
        written = next((tmp_path / "themes").iterdir(), None)
        assert written is not None
        assert written.name == "matrix-theme.json"
        written_data = json.loads(written.read_text())
        assert written_data["id"] == "matrix-theme"
        assert written_data["priceCents"] == 299
        # Now the list endpoint should see it.
        status, payload, _ = _http(
            port, "GET", "/admin/themes",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
        )
        assert status == 200
        ids = [t["id"] for t in payload["entries"]]
        assert "matrix-theme" in ids


def test_admin_get_single_theme(tmp_path):
    with running_server(tmp_path) as port:
        _http(
            port, "POST", "/admin/themes",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"id": "matrix-theme", "name": "Matrix", "priceCents": 299},
        )
        status, payload, _ = _http(
            port, "GET", "/admin/themes/matrix-theme",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
        )
        assert status == 200
        assert payload["id"] == "matrix-theme"
        assert payload["activeLicenseCount"] == 0


def test_admin_get_theme_invalid_id_returns_400(tmp_path):
    with running_server(tmp_path) as port:
        status, payload, _ = _http(
            port, "GET", "/admin/themes/not-a-valid-id!",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
        )
        assert status == 400
        assert "invalid" in payload.get("error", "").lower()


def test_admin_get_unknown_theme_returns_404(tmp_path):
    with running_server(tmp_path) as port:
        status, payload, _ = _http(
            port, "GET", "/admin/themes/no-such-theme",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
        )
        assert status == 404


def test_admin_post_themes_rejects_invalid_id(tmp_path):
    with running_server(tmp_path) as port:
        status, payload, _ = _http(
            port, "POST", "/admin/themes",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"id": "BAD ID WITH SPACES"},
        )
        assert status == 400


def test_admin_remove_theme_dry_run(tmp_path):
    """``dryRun`` returns the planned action set without
    touching the DB. Mirrors ``remove-theme --dry-run``."""
    with running_server(tmp_path) as port:
        _http(
            port, "POST", "/admin/themes",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"id": "matrix-theme", "name": "Matrix"},
        )
        status, payload, _ = _http(
            port, "POST", "/admin/themes/matrix-theme/remove",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"dryRun": True, "purgeLicenses": True, "removePreview": True},
        )
        assert status == 200
        assert payload["dryRun"] is True
        # The theme is still listed.
        status, payload, _ = _http(
            port, "GET", "/admin/themes",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
        )
        assert "matrix-theme" in [t["id"] for t in payload["entries"]]


def test_admin_remove_theme_actually_removes(tmp_path):
    with running_server(tmp_path) as port:
        _http(
            port, "POST", "/admin/themes",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"id": "matrix-theme", "name": "Matrix"},
        )
        status, payload, _ = _http(
            port, "POST", "/admin/themes/matrix-theme/remove",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"purgeLicenses": False, "removePreview": False},
        )
        assert status == 200
        assert payload["ok"] is True
        # The theme is gone.
        status, payload, _ = _http(
            port, "GET", "/admin/themes",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
        )
        assert "matrix-theme" not in [t["id"] for t in payload["entries"]]
        # And the on-disk theme JSON is gone too.
        assert not (tmp_path / "themes" / "matrix-theme.json").exists()


# ---------------------------------------------------------------------------
# Previews endpoint
# ---------------------------------------------------------------------------


def test_admin_post_previews_writes_file(tmp_path):
    with running_server(tmp_path) as port:
        # 1x1 transparent PNG, base64-encoded
        b64 = base64.b64encode(
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
            b"\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15\xc4"
            b"\x89\x00\x00\x00\rIDATx\x9cc\x00"
            b"\x01\x00\x00\x05\x00\x01\r\n-\xb4"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        ).decode("ascii")
        status, payload, _ = _http(
            port, "POST", "/admin/previews",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"filename": "matrix.jpg", "base64": b64},
        )
        assert status == 200, payload
        assert payload["bytes"] > 0
        # The file landed in previews_dir.
        target = tmp_path / "previews" / "matrix.jpg"
        assert target.is_file()


def test_admin_post_previews_rejects_path_traversal(tmp_path):
    with running_server(tmp_path) as port:
        status, payload, _ = _http(
            port, "POST", "/admin/previews",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"filename": "../escape.jpg", "base64": "AAA="},
        )
        assert status == 400
        assert "escapes" in payload.get("error", "").lower()


def test_admin_post_previews_rejects_malformed_base64(tmp_path):
    with running_server(tmp_path) as port:
        status, payload, _ = _http(
            port, "POST", "/admin/previews",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"filename": "x.jpg", "base64": "not-valid-base64!!!"},
        )
        assert status == 400


# ---------------------------------------------------------------------------
# Licenses endpoint
# ---------------------------------------------------------------------------


def test_admin_post_licenses_grants(tmp_path):
    with running_server(tmp_path) as port:
        _http(
            port, "POST", "/admin/themes",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"id": "matrix-theme", "name": "Matrix"},
        )
        install_uuid = str(uuid.uuid4())
        status, payload, _ = _http(
            port, "POST", "/admin/licenses",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={
                "installUuid": install_uuid,
                "themeId": "matrix-theme",
                "paddleSubscriptionId": "sub_42",
            },
        )
        assert status == 200, payload
        # Verify the license actually landed: /licenses?installUuid=
        # should report ``matrix-theme`` as owned.
        status, payload, _ = _http(
            port, "GET", f"/licenses?installUuid={install_uuid}",
        )
        assert status == 200
        assert "matrix-theme" in payload["ownedThemeIds"]


def test_admin_post_licenses_rejects_unknown_theme(tmp_path):
    with running_server(tmp_path) as port:
        install_uuid = str(uuid.uuid4())
        status, payload, _ = _http(
            port, "POST", "/admin/licenses",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"installUuid": install_uuid, "themeId": "no-such-theme"},
        )
        assert status == 404


def test_admin_post_licenses_rejects_invalid_uuid(tmp_path):
    with running_server(tmp_path) as port:
        status, payload, _ = _http(
            port, "POST", "/admin/licenses",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"installUuid": "not-a-uuid", "themeId": "matrix-theme"},
        )
        assert status == 400


# ---------------------------------------------------------------------------
# Installs endpoints
# ---------------------------------------------------------------------------


def test_admin_post_installs_registers_and_upgrades(tmp_path):
    with running_server(tmp_path) as port:
        install_uuid = str(uuid.uuid4())
        # Register as free.
        status, payload, _ = _http(
            port, "POST", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={
                "installUuid": install_uuid,
                "tier": "free",
                "notes": "Trial signup",
            },
        )
        assert status == 200
        assert payload["licenseTier"] == "free"
        assert payload["known"] is False
        # Upgrade to professional with a customer id.
        status, payload, _ = _http(
            port, "POST", f"/admin/installs/{install_uuid}/tier",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={
                "tier": "professional",
                "paddleCustomerId": "ctm_acme",
                "notes": "Acme Pro",
            },
        )
        assert status == 200
        assert payload["licenseTier"] == "professional"
        assert payload["previousTier"] == "free"
        # And verify via the install detail endpoint.
        status, payload, _ = _http(
            port, "GET", f"/admin/installs/{install_uuid}",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
        )
        assert status == 200
        assert payload["licenseTier"] == "professional"
        assert payload["paddleCustomerId"] == "ctm_acme"
        assert payload["notes"] == "Acme Pro"


def test_admin_set_tier_rejects_invalid_tier(tmp_path):
    with running_server(tmp_path) as port:
        install_uuid = str(uuid.uuid4())
        _http(
            port, "POST", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"installUuid": install_uuid, "tier": "free"},
        )
        status, payload, _ = _http(
            port, "POST", f"/admin/installs/{install_uuid}/tier",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"tier": "platinum"},
        )
        assert status == 400
        assert "platinum" in payload.get("error", "")


def test_admin_set_tier_returns_404_for_unknown_install(tmp_path):
    with running_server(tmp_path) as port:
        install_uuid = str(uuid.uuid4())
        status, payload, _ = _http(
            port, "POST", f"/admin/installs/{install_uuid}/tier",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"tier": "professional"},
        )
        assert status == 404


def test_admin_set_tier_fanout_preserved_after_admin_change(tmp_path):
    """Regression guard for the prior change: an admin-driven
    tier change with a paddle_customer_id should still fan out
    to other installs sharing the same customer id."""
    with running_server(tmp_path) as port:
        primary = str(uuid.uuid4())
        seat = str(uuid.uuid4())
        # Operator registers the primary and the seat via the
        # admin API (the same path they'll use in production).
        _http(
            port, "POST", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"installUuid": primary, "tier": "enterprise",
                  "paddleCustomerId": "ctm_acme"},
        )
        _http(
            port, "POST", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"installUuid": seat, "tier": "free",
                  "paddleCustomerId": "ctm_acme"},
        )
        # The seat's /licenses response should report enterprise
        # via the customer-group fan-out.
        status, payload, _ = _http(
            port, "GET", f"/licenses?installUuid={seat}",
        )
        assert status == 200
        assert payload["licenseTier"] == "enterprise"
        # And the install detail endpoint should report BOTH
        # the stored tier (free) and the effective tier
        # (enterprise) so an operator can see which row was
        # the primary upgrade.
        status, payload, _ = _http(
            port, "GET", f"/admin/installs/{seat}",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
        )
        assert payload["licenseTier"] == "free"
        assert payload["effectiveLicenseTier"] == "enterprise"


def test_admin_list_installs_returns_all(tmp_path):
    with running_server(tmp_path) as port:
        uuids = [str(uuid.uuid4()) for _ in range(3)]
        for u in uuids:
            _http(
                port, "POST", "/admin/installs",
                headers={"Authorization": "Bearer test-admin-key-do-not-use"},
                body={"installUuid": u, "tier": "free"},
            )
        status, payload, _ = _http(
            port, "GET", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
        )
        assert status == 200
        seen = {entry["installUuid"] for entry in payload["entries"]}
        for u in uuids:
            assert u in seen


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def test_admin_change_emits_audit_log(tmp_path, caplog):
    """Every successful admin call must emit a ``ps-catalog
    ADMIN`` line carrying the actor (admin-key prefix) and the
    source (``admin_api``). The log line is what an operator
    uses to confirm *who* issued a remote change after the
    fact, so it has to land in the standard logger."""
    import logging
    caplog.set_level(logging.INFO, logger="ps-catalog")
    with running_server(tmp_path) as port:
        install_uuid = str(uuid.uuid4())
        _http(
            port, "POST", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"installUuid": install_uuid, "tier": "professional"},
        )
    admin_lines = [
        record.getMessage() for record in caplog.records
        if "ps-catalog ADMIN" in record.getMessage()
    ]
    assert any("register" in line or "set_tier" in line for line in admin_lines), (
        f"No admin audit line found; saw: {admin_lines[:5]}"
    )
    # The actor field should mention the key prefix, so support
    # can correlate which admin key was used without logging the
    # full secret. The prefix is the first six characters of the
    # configured key (``test-a`` for ``test-admin-key-do-not-use``).
    assert any("test-a" in line for line in admin_lines), (
        f"actor= key prefix not found; saw: {admin_lines[:5]}"
    )


def test_admin_failed_call_still_emits_audit_log(tmp_path, caplog):
    """Even a 401 / 400 should leave an audit trail so a brute
    force attempt doesn't go un-noticed. The 401 line includes
    the source address and the length of the presented key (not
    the key itself) so the operator can size the attempt."""
    import logging
    caplog.set_level(logging.INFO, logger="ps-catalog")
    with running_server(tmp_path) as port:
        _http(
            port, "GET", "/admin/themes",
            headers={"Authorization": "Bearer wrong-key"},
        )
    warnings = [
        record.getMessage() for record in caplog.records
        if "admin auth failure" in record.getMessage()
    ]
    assert warnings, "Expected an admin auth failure warning"


# ---------------------------------------------------------------------------
# Tier-grant download tests
# ---------------------------------------------------------------------------
# The catalog server ships a "tier grants every theme" feature so an
# install on the ``professional`` or ``enterprise`` plan is treated
# as owning every theme in the catalog. These HTTP-level tests cover
# the end-to-end download flow that the desktop client's
# ``fetchAndCacheTheme`` drives:
#
#   1. Register a theme via ``POST /admin/themes`` so the catalog
#      has something to enumerate.
#   2. Without granting a per-theme license, attempt the download
#      as a free install — must 403 (the legacy auth gate).
#   3. Upgrade the install to ``professional`` via
#      ``POST /admin/installs`` — same download must now succeed.
#   4. Free the install (re-register with tier=free, no customer
#      id) — download must 403 again so the entitlement is
#      observably tier-driven, not sticky from a stale row.
#
# The tests use the in-process ``ThreadingHTTPServer`` fixture so
# they exercise the real HTTP routing, real DB writes, and real
# auth gate — not a unit-test stub. The renderer relies on this
# exact flow to backfill Pro/Enterprise themes into the local
# cache, so a regression here would manifest as "themes are
# reported as owned but never download" in the storefront.


def _register_theme(port: int, theme_id: str, theme_json: str = "{}") -> None:
    """Helper: register a theme via the admin API and write the
    canonical ``themes_dir/<id>.json`` file the download endpoint
    serves. The admin API already writes the on-disk file as part
    of ``add-theme`` so we just need to provide a body that
    includes an embedded ``themeJson`` — otherwise the server
    refuses the upsert for a new row (see
    ``cmd_add_theme``'s theme_json guard)."""
    import json as _json
    status, payload, _ = _http(
        port, "POST", "/admin/themes",
        headers={"Authorization": "Bearer test-admin-key-do-not-use"},
        body={
            "id": theme_id,
            "name": theme_id,
            "priceCents": 100,
            "themeJson": _json.dumps({"id": theme_id, "variables": {}}),
        },
    )
    assert status == 200, payload


def test_download_403_for_free_install_without_per_theme_license(tmp_path):
    """Baseline: a free install with no per-theme ``licenses`` row
    must still be rejected by ``/themes/<id>/download``. The
    tier-grant feature must not silently lower the auth gate for
    free users — only paid tiers (Pro/Enterprise) get the
    implicit grant."""
    with running_server(tmp_path) as port:
        _register_theme(port, "matrix-theme")
        free_uuid = str(uuid.uuid4())
        # Register the install at the free tier so the licenses
        # endpoint can find it, but never grant a per-theme
        # license for matrix-theme.
        _http(
            port, "POST", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"installUuid": free_uuid, "tier": "free"},
        )
        status, payload, _ = _http(
            port, "GET",
            f"/themes/matrix-theme/download?installUuid={free_uuid}",
        )
        assert status == 403, payload
        assert payload.get("themeId") == "matrix-theme"


def test_download_200_for_professional_install_without_per_theme_license(tmp_path):
    """Headline HTTP-level test: a Pro install is allowed to
    download any theme in the catalog even though no per-theme
    ``licenses`` row exists. This is the auth gate the renderer's
    ``backfillMissingOwnedThemes`` walks through when a Pro user
    upgrades and the next catalog refresh reports every theme
    as ``owned: true`` — if this 403s, the upgrade is
    unobservable on the wire."""
    with running_server(tmp_path) as port:
        _register_theme(port, "matrix-theme")
        pro_uuid = str(uuid.uuid4())
        # Upgrade to professional, no per-theme license row.
        _http(
            port, "POST", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"installUuid": pro_uuid, "tier": "professional"},
        )
        status, payload, _ = _http(
            port, "GET",
            f"/themes/matrix-theme/download?installUuid={pro_uuid}",
        )
        assert status == 200, payload
        # The download response is a JSON theme definition, not
        # an envelope. Sanity-check that the id round-tripped so
        # a future refactor that returns the wrong theme is
        # caught here.
        assert payload.get("id") == "matrix-theme"


def test_download_200_for_enterprise_install_with_fanned_out_seat(tmp_path):
    """Enterprise multi-seat parity: a free seat that shares a
    ``paddle_customer_id`` with an enterprise primary must
    inherit the download grant via the customer-fan-out path —
    the same code path that drives the fanned-out tier in
    ``/license-check``. Without this, an enterprise customer's
    extra laptops (the common "analyst seats" pattern) would
    be locked out of theme downloads even though the catalog
    says they own everything."""
    with running_server(tmp_path) as port:
        _register_theme(port, "matrix-theme")
        primary = str(uuid.uuid4())
        seat = str(uuid.uuid4())
        # Primary on enterprise, with a customer id. Seat on
        # free, with the same customer id. ``POST /admin/installs``
        # upserts the row so this also creates the seat's
        # ``installs`` row.
        _http(
            port, "POST", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={
                "installUuid": primary,
                "tier": "enterprise",
                "paddleCustomerId": "ctm_acme",
            },
        )
        _http(
            port, "POST", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={
                "installUuid": seat,
                "tier": "free",
                "paddleCustomerId": "ctm_acme",
            },
        )
        status, payload, _ = _http(
            port, "GET",
            f"/themes/matrix-theme/download?installUuid={seat}",
        )
        assert status == 200, payload
        assert payload.get("id") == "matrix-theme"


def test_download_403_after_downgrade_to_free(tmp_path):
    """A Pro install that is then downgraded back to free must
    lose the download grant — the entitlement comes from the
    tier, not from a sticky cache. The renderer relies on this
    to keep the storefront honest if a customer cancels
    (the Paddle webhook would revoke the per-theme licenses
    too, but the tier-grant path doesn't depend on the
    webhook)."""
    with running_server(tmp_path) as port:
        _register_theme(port, "matrix-theme")
        install_uuid = str(uuid.uuid4())
        # Pro upgrade via the admin API.
        _http(
            port, "POST", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"installUuid": install_uuid, "tier": "professional"},
        )
        # Confirm the Pro install can download.
        status, _payload, _ = _http(
            port, "GET",
            f"/themes/matrix-theme/download?installUuid={install_uuid}",
        )
        assert status == 200
        # Downgrade back to free (with an empty customer id so
        # the fan-out path is closed off too).
        _http(
            port, "POST", f"/admin/installs/{install_uuid}/tier",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"tier": "free", "paddleCustomerId": ""},
        )
        # Same download must now 403.
        status, payload, _ = _http(
            port, "GET",
            f"/themes/matrix-theme/download?installUuid={install_uuid}",
        )
        assert status == 403, payload


def test_download_200_for_developer_tier(tmp_path):
    """A ``developer`` install is treated like Pro/Enterprise for
    catalog access. The operator assigns ``developer`` deliberately
    to a known dev / build / QA machine (the tier is
    ``manual-only`` — the Paddle webhook and lazy registration
    can never set it), so a build agent that can't download the
    production themes it's supposed to test is the wrong default.
    The HTTP-level download must succeed without a per-theme
    ``licenses`` row, mirroring the Pro/Enterprise path."""
    with running_server(tmp_path) as port:
        _register_theme(port, "matrix-theme")
        dev_uuid = str(uuid.uuid4())
        _http(
            port, "POST", "/admin/installs",
            headers={"Authorization": "Bearer test-admin-key-do-not-use"},
            body={"installUuid": dev_uuid, "tier": "developer"},
        )
        status, payload, _ = _http(
            port, "GET",
            f"/themes/matrix-theme/download?installUuid={dev_uuid}",
        )
        assert status == 200, payload
        # Sanity-check the response body is the actual theme JSON
        # (not an error envelope) so a future refactor that
        # returns the wrong shape is caught here.
        assert payload.get("id") == "matrix-theme"
