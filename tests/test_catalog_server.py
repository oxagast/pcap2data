# -*- coding: utf-8 -*-
"""Tests for src/catalog/ps-catalog.py.

These tests instantiate the CatalogDB against a tmp sqlite file and spin up
the HTTP handler in-process against a loopback port. No external services
are required.
"""

import base64
import hashlib
import hmac
import http.client
import io
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "src" / "catalog" / "ps-catalog.py"

# ps-catalog.py is a script with module-level argparse + main(); we import it
# via importlib so we can call the helpers directly without spawning a
# subprocess for every test.
import importlib.util  # noqa: E402
import sys  # noqa: E402

_spec = importlib.util.spec_from_file_location("ps_catalog", CATALOG_PATH)
ps_catalog = importlib.util.module_from_spec(_spec)
sys.modules["ps_catalog"] = ps_catalog
assert _spec.loader is not None
_spec.loader.exec_module(ps_catalog)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _request(
    conn: http.client.HTTPConnection,
    method: str,
    path: str,
    body: bytes = b"",
    headers: dict = None,
):
    headers = dict(headers or {})
    headers.setdefault("Content-Length", str(len(body)))
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    return resp.status, dict(resp.getheaders()), data


@pytest.fixture()
def tmp_root(tmp_path, monkeypatch):
    """Provide a tmp catalog root with empty themes/ and previews/ dirs."""
    themes = tmp_path / "themes"
    previews = tmp_path / "previews"
    db = tmp_path / "catalog.sqlite3"
    themes.mkdir()
    previews.mkdir()
    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=_free_port(),
        db_path=db,
        themes_dir=themes,
        previews_dir=previews,
        paddle_webhook_secret="test-webhook-secret",
        paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
        base_url=f"http://127.0.0.1:{_free_port()}_placeholder",
    )
    # Note: base_url is a placeholder until we know the real bound port;
    # the server uses `cfg.base_url` only to build response URLs.
    return cfg, themes, previews, db


@pytest.fixture()
def server(tmp_root):
    cfg, themes, previews, db_path = tmp_root
    db = ps_catalog.CatalogDB(db_path)
    real_port = _free_port()
    real_cfg = ps_catalog.Config(
        host=cfg.host,
        port=real_port,
        db_path=cfg.db_path,
        themes_dir=cfg.themes_dir,
        previews_dir=cfg.previews_dir,
        paddle_webhook_secret=cfg.paddle_webhook_secret,
        paddle_public_key=cfg.paddle_public_key,
        paddle_api_key=cfg.paddle_api_key,
        paddle_env=cfg.paddle_env,
        base_url=f"http://127.0.0.1:{real_port}",
        success_url=cfg.success_url,
        cancel_url=cfg.cancel_url,
        allow_insecure_return_urls=cfg.allow_insecure_return_urls,
        tls_cert=cfg.tls_cert,
        tls_key=cfg.tls_key,
    )
    server = ps_catalog.make_server(real_cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Wait until the server is accepting (typically immediate).
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            with socket.create_connection((real_cfg.host, real_cfg.port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.01)
    else:
        raise RuntimeError("server did not start listening")
    yield server, real_cfg, themes, previews, db
    server.shutdown()
    server.server_close()
    db.close()


@pytest.fixture()
def client(server):
    server, cfg, themes, previews, db = server
    conn = http.client.HTTPConnection(cfg.host, cfg.port, timeout=5)
    yield conn, server, cfg, themes, previews, db
    conn.close()


def _add_theme(
    db: ps_catalog.CatalogDB,
    themes_dir: Path,
    theme_id: str = "snitchbitch",
    price_cents: int = 500,
    paddle_price_id: str = "pri_test_123",
):
    body = {
        "id": theme_id,
        "name": theme_id.title(),
        "description": f"The {theme_id} theme",
        "priceCents": price_cents,
        "priceLabel": "$5.00",
        "paddle": {"productId": "pro_test_123", "priceId": paddle_price_id},
    }
    target = themes_dir / f"{theme_id}.json"
    target.write_text(json.dumps(body))
    db.upsert_theme(
        theme_id=theme_id,
        name=body["name"],
        description=body["description"],
        price_cents=price_cents,
        price_label=body["priceLabel"],
        paddle_product_id="pro_test_123",
        paddle_price_id=paddle_price_id,
        preview_image="",
        preview_filename="",
        checkout_url="",
        license_url="",
    )
    return target


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------


def test_catalog_db_creates_schema(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    db = ps_catalog.CatalogDB(db_path)
    # Tables should exist.
    rows = db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    names = {row["name"] for row in rows}
    assert {"themes", "licenses"}.issubset(names)
    db.close()


def test_upsert_then_grant_then_revoke(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    db = ps_catalog.CatalogDB(db_path)
    db.upsert_theme(
        theme_id="alpha",
        name="Alpha",
        description="",
        price_cents=100,
        price_label="$1",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        license_url="",
    )
    install_uuid = str(uuid.uuid4())
    db.grant_license(install_uuid, "alpha", paddle_subscription_id="sub_1")
    owned = db.list_owned_theme_ids(install_uuid)
    assert owned == ["alpha"]
    db.revoke_license(install_uuid, "alpha")
    assert db.list_owned_theme_ids(install_uuid) == []
    db.close()


def test_grant_resurrects_revoked_license(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    db = ps_catalog.CatalogDB(db_path)
    db.upsert_theme(
        theme_id="alpha",
        name="Alpha",
        description="",
        price_cents=None,
        price_label="",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        license_url="",
    )
    install_uuid = str(uuid.uuid4())
    db.grant_license(install_uuid, "alpha", paddle_subscription_id="sub_1")
    db.revoke_license(install_uuid, "alpha")
    db.grant_license(install_uuid, "alpha", paddle_subscription_id="sub_2")
    owned = db.list_owned_theme_ids(install_uuid)
    assert owned == ["alpha"]
    db.close()


# ---------------------------------------------------------------------------
# Paddle API client (create_paddle_transaction)
# ---------------------------------------------------------------------------


def _make_cfg(
    api_key="pdl_test",
    env="sandbox",
    base_url="http://127.0.0.1:9021",
    allow_insecure=True,
):
    return ps_catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=Path("/tmp/dummy.sqlite3"),
        themes_dir=Path("/tmp/themes"),
        previews_dir=Path("/tmp/previews"),
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=api_key,
        paddle_env=env,
        base_url=base_url,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=allow_insecure,
        tls_cert=None,
        tls_key=None,
    )


def test_create_paddle_transaction_sends_correct_payload(tmp_path, monkeypatch):
    cfg = _make_cfg(env="sandbox")
    install_uuid = str(uuid.uuid4())
    captured = []

    class FakeResp:
        def __init__(self, body, status=200):
            self._body = body
            self.status = status

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        captured.append((req.full_url, req.data.decode("utf-8")))
        return FakeResp(
            json.dumps(
                {
                    "data": {
                        "id": "txn_test",
                        "checkout": {
                            "url": "https://sandbox-pay.paddle.io/hsc_abc"
                        },
                    }
                }
            ).encode("utf-8")
        )

    monkeypatch.setattr(ps_catalog.urllib.request, "urlopen", fake_urlopen)

    url, txn_id = ps_catalog.create_paddle_transaction(
        cfg,
        price_id="pri_test",
        install_uuid=install_uuid,
        theme_id="matrix",
        success_url="https://packetsnitch.example.com/ok",
        cancel_url="https://packetsnitch.example.com/cancel",
    )
    assert url == "https://sandbox-pay.paddle.io/hsc_abc"
    assert txn_id == "txn_test"
    assert captured[0][0] == "https://sandbox-api.paddle.com/transactions"
    body = json.loads(captured[0][1])
    assert body["items"] == [{"price_id": "pri_test", "quantity": 1}]
    assert body["custom_data"]["installUuid"] == install_uuid
    assert body["custom_data"]["themeId"] == "matrix"
    assert body["checkout"]["success_url"] == "https://packetsnitch.example.com/ok"
    assert body["checkout"]["cancel_url"] == "https://packetsnitch.example.com/cancel"


def test_create_paddle_transaction_uses_live_url_by_default(tmp_path, monkeypatch):
    cfg = _make_cfg(env="live")
    captured = []

    class FakeResp:
        def __init__(self, body):
            self._body = body
            self.status = 200

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        captured.append(req.full_url)
        return FakeResp(
            json.dumps(
                {"data": {"checkout": {"url": "https://pay.paddle.com/hsc_live"}}}
            ).encode("utf-8")
        )

    monkeypatch.setattr(ps_catalog.urllib.request, "urlopen", fake_urlopen)

    url, txn_id = ps_catalog.create_paddle_transaction(
        cfg, price_id="pri", install_uuid=str(uuid.uuid4()), theme_id="x"
    )
    assert url == "https://pay.paddle.com/hsc_live"
    # No ``id`` in the fake response — txn_id should be empty.
    assert txn_id == ""
    assert captured[0] == "https://api.paddle.com/transactions"


def test_create_paddle_transaction_raises_without_api_key():
    cfg = _make_cfg(api_key=None)
    with pytest.raises(ps_catalog.PaddleError) as exc_info:
        ps_catalog.create_paddle_transaction(
            cfg, price_id="pri", install_uuid=str(uuid.uuid4()), theme_id="x"
        )
    assert "API key" in str(exc_info.value)


def test_create_paddle_transaction_raises_on_http_error(tmp_path, monkeypatch):
    cfg = _make_cfg()

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 401, "Unauthorized", {}, None
        )

    monkeypatch.setattr(ps_catalog.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(ps_catalog.PaddleError) as exc_info:
        ps_catalog.create_paddle_transaction(
            cfg, price_id="pri", install_uuid=str(uuid.uuid4()), theme_id="x"
        )
    assert exc_info.value.status == 401


def test_create_paddle_transaction_raises_when_no_checkout_url(tmp_path, monkeypatch):
    cfg = _make_cfg()

    class FakeResp:
        status = 200

        def read(self):
            return json.dumps({"data": {"id": "txn_no_checkout"}}).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        ps_catalog.urllib.request,
        "urlopen",
        lambda req, timeout=None: FakeResp(),
    )
    with pytest.raises(ps_catalog.PaddleError) as exc_info:
        ps_catalog.create_paddle_transaction(
            cfg, price_id="pri", install_uuid=str(uuid.uuid4()), theme_id="x"
        )
    assert "checkout URL" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Endpoint tests
# ---------------------------------------------------------------------------


def test_health(client):
    conn, server, cfg, themes, previews, db = client
    status, headers, body = _request(conn, "GET", "/health")
    assert status == 200
    payload = json.loads(body)
    assert payload == {"ok": True}


def test_catalog_returns_entries(client):
    conn, server, cfg, themes, previews, db = client
    _add_theme(db, themes, theme_id="snitchbitch")
    status, _, body = _request(conn, "GET", "/catalog")
    assert status == 200
    payload = json.loads(body)
    assert len(payload["entries"]) == 1
    entry = payload["entries"][0]
    assert entry["id"] == "snitchbitch"
    assert entry["priceCents"] == 500
    assert entry["owned"] is False
    assert entry["installed"] is False
    assert entry["previewUrl"].endswith("/themes/snitchbitch/preview")


def test_catalog_marks_owned_themes(client):
    conn, server, cfg, themes, previews, db = client
    _add_theme(db, themes, theme_id="alpha")
    _add_theme(db, themes, theme_id="beta")
    install_uuid = str(uuid.uuid4())
    db.grant_license(install_uuid, "alpha")
    status, _, body = _request(
        conn,
        "GET",
        f"/catalog?installUuid={install_uuid}",
    )
    payload = json.loads(body)
    owned = {e["id"]: e["owned"] for e in payload["entries"]}
    assert owned == {"alpha": True, "beta": False}


def test_theme_download_requires_license(client):
    conn, server, cfg, themes, previews, db = client
    _add_theme(db, themes, theme_id="alpha")
    status, _, body = _request(conn, "GET", "/themes/alpha/download")
    assert status == 400
    status, _, body = _request(
        conn, "GET", f"/themes/alpha/download?installUuid={uuid.uuid4()}"
    )
    assert status == 403


def test_theme_download_succeeds_with_license(client):
    conn, server, cfg, themes, previews, db = client
    target = _add_theme(db, themes, theme_id="alpha")
    install_uuid = str(uuid.uuid4())
    db.grant_license(install_uuid, "alpha")
    status, headers, body = _request(
        conn, "GET", f"/themes/alpha/download?installUuid={install_uuid}"
    )
    assert status == 200
    assert headers.get("Content-Type", "").startswith("application/json")
    payload = json.loads(body)
    assert payload["id"] == "alpha"


def test_theme_download_404_when_missing(client):
    conn, server, cfg, themes, previews, db = client
    install_uuid = str(uuid.uuid4())
    db.upsert_theme(
        theme_id="ghost",
        name="Ghost",
        description="",
        price_cents=None,
        price_label="",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        license_url="",
    )
    db.grant_license(install_uuid, "ghost")
    status, _, _ = _request(
        conn, "GET", f"/themes/ghost/download?installUuid={install_uuid}"
    )
    assert status == 500  # file missing on disk


def test_theme_preview_falls_back_to_previews_dir(client):
    conn, server, cfg, themes, previews, db = client
    preview_path = previews / "alpha.jpg"
    preview_path.write_bytes(b"\xff\xd8\xff\xe0fake-jpeg")
    db.upsert_theme(
        theme_id="alpha",
        name="Alpha",
        description="",
        price_cents=None,
        price_label="",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="alpha.jpg",
        checkout_url="",
        license_url="",
    )
    status, headers, body = _request(conn, "GET", "/themes/alpha/preview")
    assert status == 200
    assert body == b"\xff\xd8\xff\xe0fake-jpeg"
    assert headers.get("Content-Type", "").startswith("image/")


def test_licenses_returns_owned_ids(client):
    conn, server, cfg, themes, previews, db = client
    _add_theme(db, themes, theme_id="alpha")
    _add_theme(db, themes, theme_id="beta")
    install_uuid = str(uuid.uuid4())
    db.grant_license(install_uuid, "alpha")
    db.grant_license(install_uuid, "beta")
    db.revoke_license(install_uuid, "beta")
    status, _, body = _request(
        conn, "GET", f"/licenses?installUuid={install_uuid}"
    )
    assert status == 200
    payload = json.loads(body)
    assert sorted(payload["ownedThemeIds"]) == ["alpha"]


def test_licenses_rejects_invalid_uuid(client):
    conn, server, cfg, themes, previews, db = client
    status, _, body = _request(conn, "GET", "/licenses?installUuid=not-a-uuid")
    assert status == 400


def test_checkout_requires_install_uuid_when_no_static_url(client):
    """When the theme has no static checkout_url and the catalog server has no
    API key, the handler must demand installUuid (and a paddlePriceId) before
    attempting the dynamic flow."""
    conn, server, cfg, themes, previews, db = client
    db.upsert_theme(
        theme_id="alpha",
        name="Alpha",
        description="",
        price_cents=500,
        price_label="",
        paddle_product_id="",
        paddle_price_id="pri_abc",
        preview_image="",
        preview_filename="",
        checkout_url="",
        license_url="",
    )
    # No installUuid -> 400
    status, _, body = _request(conn, "GET", "/checkout/alpha")
    assert status == 400
    payload = json.loads(body)
    assert "installUuid" in payload["error"]


def test_checkout_static_url_still_wins(client):
    """The static checkout_url field is still respected — useful for sandbox
    testing with a one-shot hsc_... token."""
    conn, server, cfg, themes, previews, db = client
    db.upsert_theme(
        theme_id="alpha",
        name="Alpha",
        description="",
        price_cents=500,
        price_label="",
        paddle_product_id="",
        paddle_price_id="pri_abc",
        preview_image="",
        preview_filename="",
        checkout_url="https://sandbox-pay.paddle.io/hsc_TESTTOKEN",
        license_url="",
    )
    install_uuid = str(uuid.uuid4())
    status, headers, _ = _request(
        conn, "GET", f"/checkout/alpha?installUuid={install_uuid}"
    )
    assert status == 302
    assert (
        headers["Location"] == "https://sandbox-pay.paddle.io/hsc_TESTTOKEN"
    )


def test_checkout_hosted_url_appends_recovery_params(client):
    """A theme with a hosted_checkout_url should redirect to that URL with
    installUuid + themeId appended (preserving any pre-existing query
    params on the URL). The new column takes precedence over the legacy
    checkout_url field when both are set."""
    conn, server, cfg, themes, previews, db = client
    db.upsert_theme(
        theme_id="alpha",
        name="Alpha",
        description="",
        price_cents=500,
        price_label="",
        paddle_product_id="",
        paddle_price_id="pri_abc",
        preview_image="",
        preview_filename="",
        checkout_url="https://sandbox-pay.paddle.io/hsc_OLD_LEGACY",
        hosted_checkout_url=(
            "https://sandbox-pay.paddle.io/hsc_NEWTOKEN?passthrough=abc"
        ),
        license_url="",
    )
    install_uuid = str(uuid.uuid4())
    status, headers, _ = _request(
        conn, "GET", f"/checkout/alpha?installUuid={install_uuid}"
    )
    assert status == 302
    location = headers["Location"]
    # The hosted URL wins over the legacy one.
    assert location.startswith("https://sandbox-pay.paddle.io/hsc_NEWTOKEN")
    # Pre-existing query params must be preserved.
    assert "passthrough=abc" in location
    # installUuid + themeId appended.
    assert f"installUuid={install_uuid}" in location
    assert "themeId=alpha" in location


def test_checkout_hosted_url_preserves_user_supplied_query_params(client):
    """If the buyer manually appends installUuid to the URL we should not
    clobber it (setdefault semantics)."""
    conn, server, cfg, themes, previews, db = client
    db.upsert_theme(
        theme_id="beta",
        name="Beta",
        description="",
        price_cents=0,
        price_label="",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="https://example.com/checkout",
        license_url="",
    )
    supplied = str(uuid.uuid4())
    status, headers, _ = _request(
        conn, "GET", f"/checkout/beta?installUuid={supplied}"
    )
    assert status == 302
    location = headers["Location"]
    assert f"installUuid={supplied}" in location
    assert "themeId=beta" in location


def test_checkout_dynamic_creates_paddle_transaction(tmp_path, monkeypatch):
    """End-to-end: a server with --paddle-api-key calls Paddle /transactions
    and redirects to the returned checkout URL. We monkeypatch
    urllib.request.urlopen to return a fake Paddle response."""
    themes = tmp_path / "themes"
    previews = tmp_path / "previews"
    db_path = tmp_path / "catalog.sqlite3"
    themes.mkdir()
    previews.mkdir()

    db = ps_catalog.CatalogDB(db_path)
    real_port = _free_port()
    real_cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=real_port,
        db_path=db_path,
        themes_dir=themes,
        previews_dir=previews,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key="pdl_test_api_key",
        paddle_env="sandbox",
        base_url=f"http://127.0.0.1:{real_port}",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
    )
    db.upsert_theme(
        theme_id="matrix",
        name="Matrix",
        description="",
        price_cents=500,
        price_label="",
        paddle_product_id="pro_matrix",
        paddle_price_id="pri_matrix",
        preview_image="",
        preview_filename="",
        checkout_url="",
        license_url="",
    )

    server = ps_catalog.make_server(real_cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                with socket.create_connection(
                    (real_cfg.host, real_cfg.port), timeout=0.5
                ):
                    break
            except OSError:
                time.sleep(0.01)

        # Patch urlopen so we don't actually hit Paddle.
        captured_requests: list = []

        class FakeResponse:
            def __init__(self, body_bytes: bytes, status_code: int = 200):
                self._body = body_bytes
                self.status = status_code

            def read(self) -> bytes:
                return self._body

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(req, timeout=None):  # noqa: ARG001
            captured_requests.append(
                {
                    "url": req.full_url,
                    "method": req.get_method(),
                    "authorization": req.get_header("Authorization"),
                    "body": req.data.decode("utf-8") if req.data else "",
                }
            )
            payload = {
                "data": {
                    "id": "txn_test_123",
                    "checkout": {
                        "url": (
                            "https://sandbox-pay.paddle.io/"
                            "hsc_testtoken_wq5xjm1203478k6pw768zp2swt40czb2"
                        )
                    },
                }
            }
            return FakeResponse(json.dumps(payload).encode("utf-8"), 200)

        monkeypatch.setattr(ps_catalog.urllib.request, "urlopen", fake_urlopen)

        conn = http.client.HTTPConnection(real_cfg.host, real_cfg.port, timeout=5)
        install_uuid = str(uuid.uuid4())
        status, headers, body = _request(
            conn, "GET", f"/checkout/matrix?installUuid={install_uuid}"
        )
        assert status == 302
        assert headers["Location"].startswith(
            "https://sandbox-pay.paddle.io/hsc_testtoken_"
        )

        # Verify the outbound call had the right shape.
        assert len(captured_requests) == 1
        req = captured_requests[0]
        assert req["method"] == "POST"
        assert req["url"] == "https://sandbox-api.paddle.com/transactions"
        assert req["authorization"] == "Bearer pdl_test_api_key"
        outbound = json.loads(req["body"])
        assert outbound["items"] == [
            {"price_id": "pri_matrix", "quantity": 1}
        ]
        assert outbound["custom_data"]["installUuid"] == install_uuid
        assert outbound["custom_data"]["themeId"] == "matrix"
        assert (
            outbound["checkout"]["success_url"]
            == f"http://127.0.0.1:{real_port}/checkout-success?installUuid={install_uuid}&themeId=matrix"
        )

        conn.close()
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_checkout_dynamic_uses_static_fallback_when_paddle_returns_non_hosted_url(
    tmp_path, monkeypatch
):
    """When the price has no Paddle-hosted checkout configured, the
    ``POST /transactions`` API still succeeds but returns a
    ``checkout.url`` that points at the merchant's bare domain (with
    ``_ptxn=...`` appended). The catalog should treat that URL as a
    static fallback: append ``installUuid`` + ``themeId`` query params
    so the success/cancel pages can recover license context."""
    themes = tmp_path / "themes"
    previews = tmp_path / "previews"
    db_path = tmp_path / "catalog.sqlite3"
    themes.mkdir()
    previews.mkdir()

    db = ps_catalog.CatalogDB(db_path)
    real_port = _free_port()
    real_cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=real_port,
        db_path=db_path,
        themes_dir=themes,
        previews_dir=previews,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key="pdl_test_api_key",
        paddle_env="sandbox",
        base_url=f"http://127.0.0.1:{real_port}",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
    )
    db.upsert_theme(
        theme_id="nilla",
        name="Nilla",
        description="",
        price_cents=399,
        price_label="",
        paddle_product_id="pro_nilla",
        paddle_price_id="pri_nilla",
        preview_image="",
        preview_filename="",
        checkout_url="",
        license_url="",
    )

    server = ps_catalog.make_server(real_cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                with socket.create_connection(
                    (real_cfg.host, real_cfg.port), timeout=0.5
                ):
                    break
            except OSError:
                time.sleep(0.01)

        class FakeResponse:
            def __init__(self, body_bytes: bytes, status_code: int = 200):
                self._body = body_bytes
                self.status = status_code

            def read(self) -> bytes:
                return self._body

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        # Paddle returns a non-hosted checkout URL (the merchant's
        # bare domain with ``_ptxn=...`` appended) — exactly what
        # happens when the price has no hosted-checkout form
        # configured.
        def fake_urlopen(req, timeout=None):  # noqa: ARG001
            payload = {
                "data": {
                    "id": "txn_nonhosted_xyz",
                    "checkout": {
                        "url": "https://oxasploits.com:9021?_ptxn=txn_nonhosted_xyz"
                    },
                }
            }
            return FakeResponse(json.dumps(payload).encode("utf-8"), 200)

        monkeypatch.setattr(ps_catalog.urllib.request, "urlopen", fake_urlopen)

        conn = http.client.HTTPConnection(real_cfg.host, real_cfg.port, timeout=5)
        install_uuid = str(uuid.uuid4())
        status, headers, _body = _request(
            conn, "GET", f"/checkout/nilla?installUuid={install_uuid}"
        )
        assert status == 302
        location = headers["Location"]
        # The redirect goes to the URL Paddle gave us, with the
        # recovery params appended.
        assert location.startswith("https://oxasploits.com:9021")
        assert "_ptxn=txn_nonhosted_xyz" in location
        assert f"installUuid={install_uuid}" in location
        assert "themeId=nilla" in location

        # The transaction intent was recorded so the success page
        # can recover the installUuid/themeId even without an API
        # call.
        intent = db.get_transaction_intent("txn_nonhosted_xyz")
        assert intent["installUuid"] == install_uuid
        assert intent["themeId"] == "nilla"

        conn.close()
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_checkout_dynamic_falls_back_to_static_on_paddle_error(
    tmp_path, monkeypatch
):
    """When ``POST /transactions`` fails AND the theme has a
    pre-stored static ``hosted_checkout_url``, the catalog should
    fall back to that URL with recovery params appended instead of
    surfacing the Paddle error to the buyer."""
    themes = tmp_path / "themes"
    previews = tmp_path / "previews"
    db_path = tmp_path / "catalog.sqlite3"
    themes.mkdir()
    previews.mkdir()

    db = ps_catalog.CatalogDB(db_path)
    real_port = _free_port()
    real_cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=real_port,
        db_path=db_path,
        themes_dir=themes,
        previews_dir=previews,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key="pdl_test_api_key",
        paddle_env="sandbox",
        base_url=f"http://127.0.0.1:{real_port}",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
    )
    db.upsert_theme(
        theme_id="fallback",
        name="Fallback",
        description="",
        price_cents=399,
        price_label="",
        paddle_product_id="pro_fallback",
        paddle_price_id="pri_fallback",
        preview_image="",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="https://example.com/buy-now?token=abc",
        license_url="",
    )

    server = ps_catalog.make_server(real_cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                with socket.create_connection(
                    (real_cfg.host, real_cfg.port), timeout=0.5
                ):
                    break
            except OSError:
                time.sleep(0.01)

        # Paddle returns a 400 (price doesn't exist, wrong env, etc.)
        def fake_urlopen(req, timeout=None):  # noqa: ARG001
            raise urllib.error.HTTPError(
                req.full_url,
                400,
                "Bad Request",
                {},
                io.BytesIO(b'{"error":{"type":"request_error"}}'),
            )

        monkeypatch.setattr(ps_catalog.urllib.request, "urlopen", fake_urlopen)

        conn = http.client.HTTPConnection(real_cfg.host, real_cfg.port, timeout=5)
        install_uuid = str(uuid.uuid4())
        status, headers, _body = _request(
            conn,
            "GET",
            f"/checkout/fallback?installUuid={install_uuid}",
        )
        assert status == 302
        location = headers["Location"]
        assert location.startswith("https://example.com/buy-now")
        assert "token=abc" in location
        assert f"installUuid={install_uuid}" in location
        assert "themeId=fallback" in location

        conn.close()
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_checkout_dynamic_503_when_no_api_key(client):
    """If the theme has no static URL and no paddle_api_key is configured, the
    handler returns 503 instead of silently redirecting to a broken URL."""
    conn, server, cfg, themes, previews, db = client
    db.upsert_theme(
        theme_id="alpha",
        name="Alpha",
        description="",
        price_cents=500,
        price_label="",
        paddle_product_id="",
        paddle_price_id="pri_abc",
        preview_image="",
        preview_filename="",
        checkout_url="",
        license_url="",
    )
    install_uuid = str(uuid.uuid4())
    status, _, body = _request(
        conn, "GET", f"/checkout/alpha?installUuid={install_uuid}"
    )
    assert status == 503
    payload = json.loads(body)
    assert "Paddle API key" in payload["error"]


def test_checkout_dynamic_400_when_no_paddle_price_id(client):
    """Even with an API key, a theme with no paddlePriceId can't be checked out."""
    conn, server, cfg, themes, previews, db = client
    # Server's paddle_api_key is None in the default fixture; we want to
    # exercise the "no price ID" path which is checked first.
    db.upsert_theme(
        theme_id="alpha",
        name="Alpha",
        description="",
        price_cents=500,
        price_label="",
        paddle_product_id="",
        paddle_price_id="",  # missing
        preview_image="",
        preview_filename="",
        checkout_url="",
        license_url="",
    )
    install_uuid = str(uuid.uuid4())
    status, _, body = _request(
        conn, "GET", f"/checkout/alpha?installUuid={install_uuid}"
    )
    assert status == 400
    payload = json.loads(body)
    assert "paddlePriceId" in payload["error"]


def test_checkout_success_page_renders(client):
    """Paddle redirects buyers to /checkout-success after a successful
    purchase; render an HTML thank-you page so they aren't staring at a
    blank tab."""
    conn, server, cfg, themes, previews, db = client
    install_uuid = str(uuid.uuid4())
    status, headers, body = _request(
        conn,
        "GET",
        f"/checkout-success?installUuid={install_uuid}&themeId=matrix",
    )
    assert status == 200
    assert headers.get("Content-Type", "").startswith("text/html")
    assert b"Purchase complete" in body
    assert install_uuid.encode() in body
    assert b"matrix" in body


def test_checkout_success_deeplink_button_visible(client):
    """When installUuid/themeId are known, the success page should offer
    a packetsnitch:// deeplink so PacketSnitch can pick up the
    purchase automatically."""
    conn, server, cfg, themes, previews, db = client
    install_uuid = str(uuid.uuid4())
    status, _, body = _request(
        conn,
        "GET",
        f"/checkout-success?installUuid={install_uuid}&themeId=matrix",
    )
    assert status == 200
    assert b"packetsnitch://checkout-success" in body
    assert f"installUuid={install_uuid}".encode() in body
    assert b"themeId=matrix" in body


def test_checkout_success_proactive_grant_on_transaction_id(
    tmp_root, monkeypatch
):
    """When Paddle only forwards ``transaction_id`` (the sandbox
    redirect quirk), the catalog server should look the transaction up
    via the Paddle API and grant the license server-side as a fallback
    for setups where the webhook never arrives."""

    cfg_template, themes, previews, db_path = tmp_root
    install_uuid = str(uuid.uuid4())
    transaction_id = "txn_test_42"

    # Monkeypatch the Paddle API lookup to return a completed transaction
    # with our installUuid / themeId in custom_data.
    def fake_lookup(self, txn_id):
        assert txn_id == transaction_id
        return {
            "installUuid": install_uuid,
            "themeId": "matrix",
            "customerEmail": "buyer@example.com",
            "status": "completed",
        }

    monkeypatch.setattr(
        ps_catalog.CatalogHandler,
        "_paddle_lookup_transaction",
        fake_lookup,
    )

    db = ps_catalog.CatalogDB(db_path)
    _add_theme(db, themes, theme_id="matrix")
    real_port = _free_port()
    real_cfg = ps_catalog.Config(
        host=cfg_template.host,
        port=real_port,
        db_path=cfg_template.db_path,
        themes_dir=cfg_template.themes_dir,
        previews_dir=cfg_template.previews_dir,
        paddle_webhook_secret=cfg_template.paddle_webhook_secret,
        paddle_public_key=None,
        paddle_api_key="pdl_test_key",  # any non-empty value enables the lookup
        paddle_env="sandbox",
        base_url=f"http://127.0.0.1:{real_port}",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
    )
    server = ps_catalog.make_server(real_cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                with socket.create_connection(
                    (real_cfg.host, real_cfg.port), timeout=0.5
                ):
                    break
            except OSError:
                time.sleep(0.01)
        else:
            raise RuntimeError("server did not start")

        conn = http.client.HTTPConnection(real_cfg.host, real_cfg.port, timeout=5)
        try:
            # Hit the success page with only transaction_id. The server
            # should look up the transaction, see status=completed, and
            # grant the license.
            status, _, body = _request(
                conn,
                "GET",
                f"/checkout-success?transaction_id={transaction_id}",
            )
            assert status == 200
            assert b"Purchase complete" in body
            assert b"has been activated" in body  # proactive-grant message
        finally:
            conn.close()

        # The license should now be in the DB.
        owned = db.list_owned_theme_ids(install_uuid)
        assert owned == ["matrix"]
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_checkout_success_pending_status_does_not_grant_via_api(
    tmp_root, monkeypatch
):
    """When the URL only carries a transaction_id (the Paddle sandbox
    redirect quirk), the catalog server falls back to the Paddle API
    lookup. The lookup resolves installUuid/themeId from custom_data,
    but if the transaction's Paddle status is still pending, do NOT
    grant the license — wait for the webhook or a paid-status
    refresh.

    When the URL also carries installUuid+themeId explicitly, the
    catalog grants directly (see
    test_checkout_success_proactive_grant_on_transaction_id)."""
    cfg_template, themes, previews, db_path = tmp_root
    install_uuid = str(uuid.uuid4())
    transaction_id = "txn_test_pending"

    def fake_lookup(self, txn_id):
        return {
            "installUuid": install_uuid,
            "themeId": "matrix",
            "customerEmail": "",
            "status": "pending",
        }

    monkeypatch.setattr(
        ps_catalog.CatalogHandler,
        "_paddle_lookup_transaction",
        fake_lookup,
    )

    db = ps_catalog.CatalogDB(db_path)
    _add_theme(db, themes, theme_id="matrix")
    real_port = _free_port()
    real_cfg = ps_catalog.Config(
        host=cfg_template.host,
        port=real_port,
        db_path=cfg_template.db_path,
        themes_dir=cfg_template.themes_dir,
        previews_dir=cfg_template.previews_dir,
        paddle_webhook_secret=cfg_template.paddle_webhook_secret,
        paddle_public_key=None,
        paddle_api_key="pdl_test_key",
        paddle_env="sandbox",
        base_url=f"http://127.0.0.1:{real_port}",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
    )
    server = ps_catalog.make_server(real_cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                with socket.create_connection(
                    (real_cfg.host, real_cfg.port), timeout=0.5
                ):
                    break
            except OSError:
                time.sleep(0.01)
        conn = http.client.HTTPConnection(real_cfg.host, real_cfg.port, timeout=5)
        try:
            # Only transaction_id in the URL — no installUuid/themeId.
            # The Paddle lookup populates the IDs from custom_data but
            # the status is pending, so the license is NOT granted and
            # the page still shows "will be granted".
            status, _, body = _request(
                conn,
                "GET",
                f"/checkout-success?transaction_id={transaction_id}",
            )
            assert status == 200
            assert b"will be granted" in body
        finally:
            conn.close()

        owned = db.list_owned_theme_ids(install_uuid)
        assert owned == []
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_checkout_success_paid_status_grants_via_api(
    tmp_root, monkeypatch
):
    """End-to-end of the bare-transaction_id redirect path: the URL has
    only a transaction_id, the Paddle API lookup returns
    status=completed with installUuid/themeId in custom_data, and the
    catalog grants the license server-side without needing the
    webhook."""
    cfg_template, themes, previews, db_path = tmp_root
    install_uuid = str(uuid.uuid4())
    transaction_id = "txn_test_completed_via_api"

    def fake_lookup(self, txn_id):
        return {
            "installUuid": install_uuid,
            "themeId": "matrix",
            "customerEmail": "buyer@example.com",
            "status": "completed",
        }

    monkeypatch.setattr(
        ps_catalog.CatalogHandler,
        "_paddle_lookup_transaction",
        fake_lookup,
    )

    db = ps_catalog.CatalogDB(db_path)
    _add_theme(db, themes, theme_id="matrix")
    real_port = _free_port()
    real_cfg = ps_catalog.Config(
        host=cfg_template.host,
        port=real_port,
        db_path=cfg_template.db_path,
        themes_dir=cfg_template.themes_dir,
        previews_dir=cfg_template.previews_dir,
        paddle_webhook_secret=cfg_template.paddle_webhook_secret,
        paddle_public_key=None,
        paddle_api_key="pdl_test_key",
        paddle_env="sandbox",
        base_url=f"http://127.0.0.1:{real_port}",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
    )
    server = ps_catalog.make_server(real_cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                with socket.create_connection(
                    (real_cfg.host, real_cfg.port), timeout=0.5
                ):
                    break
            except OSError:
                time.sleep(0.01)
        conn = http.client.HTTPConnection(real_cfg.host, real_cfg.port, timeout=5)
        try:
            status, _, body = _request(
                conn,
                "GET",
                f"/checkout-success?transaction_id={transaction_id}",
            )
            assert status == 200
            assert b"has been activated" in body
        finally:
            conn.close()

        owned = db.list_owned_theme_ids(install_uuid)
        assert owned == ["matrix"]
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_checkout_success_uses_local_intent_table_when_paddle_returns_no_custom_data(
    tmp_root, monkeypatch
):
    """End-to-end of the local-intent-table fallback: even when the
    Paddle API doesn't echo custom_data back, the catalog can still
    recover installUuid/themeId from the local transaction_intent
    table and grant the license server-side."""
    cfg_template, themes, previews, db_path = tmp_root
    install_uuid = str(uuid.uuid4())
    transaction_id = "txn_local_intent"

    # Paddle returns the transaction but with no custom_data (the
    # common sandbox case we want to survive).
    def fake_lookup(self, txn_id):
        return {
            "installUuid": "",
            "themeId": "",
            "customerEmail": "",
            "status": "completed",
        }

    monkeypatch.setattr(
        ps_catalog.CatalogHandler,
        "_paddle_lookup_transaction",
        fake_lookup,
    )

    db = ps_catalog.CatalogDB(db_path)
    _add_theme(db, themes, theme_id="matrix")
    # Pre-populate the local intent table as if a previous checkout
    # had recorded it. (In production this happens at transaction
    # creation time.)
    db.record_transaction_intent(
        transaction_id=transaction_id,
        install_uuid=install_uuid,
        theme_id="matrix",
        paddle_customer_id="ctm_test",
        customer_email="buyer@example.com",
    )
    real_port = _free_port()
    real_cfg = ps_catalog.Config(
        host=cfg_template.host,
        port=real_port,
        db_path=cfg_template.db_path,
        themes_dir=cfg_template.themes_dir,
        previews_dir=cfg_template.previews_dir,
        paddle_webhook_secret=cfg_template.paddle_webhook_secret,
        paddle_public_key=None,
        paddle_api_key="pdl_test_key",
        paddle_env="sandbox",
        base_url=f"http://127.0.0.1:{real_port}",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
    )
    server = ps_catalog.make_server(real_cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                with socket.create_connection(
                    (real_cfg.host, real_cfg.port), timeout=0.5
                ):
                    break
            except OSError:
                time.sleep(0.01)
        conn = http.client.HTTPConnection(real_cfg.host, real_cfg.port, timeout=5)
        try:
            # Only transaction_id in the URL. The catalog server should
            # recover installUuid/themeId from the local intent table
            # (not the Paddle API response) and grant the license.
            status, _, body = _request(
                conn,
                "GET",
                f"/checkout-success?transaction_id={transaction_id}",
            )
            assert status == 200
            assert b"has been activated" in body
            # The deeplink button should include the recovered IDs.
            assert f"installUuid={install_uuid}".encode() in body
            assert b"themeId=matrix" in body
        finally:
            conn.close()

        owned = db.list_owned_theme_ids(install_uuid)
        assert owned == ["matrix"]
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_root_with_ptxn_routes_to_checkout_success(tmp_root, monkeypatch):
    """Paddle sandbox sometimes ignores the configured success_url and
    redirects the buyer to the merchant's bare domain with
    ``_ptxn=<id>`` appended. The catalog server should detect that
    pattern and route the request through the checkout-success
    handler so the proactive-grant + deeplink flow runs (instead of
    returning a healthcheck JSON)."""
    cfg_template, themes, previews, db_path = tmp_root
    install_uuid = str(uuid.uuid4())
    transaction_id = "txn_ptxn_redirect"

    # Paddle returns a completed transaction with installUuid/themeId
    # echoed back so the proactive grant kicks in. The mock returns
    # the normalized top-level shape that
    # ``_paddle_lookup_transaction`` produces.
    def fake_lookup(self, txn_id):
        return {
            "status": "completed",
            "installUuid": install_uuid,
            "themeId": "matrix",
            "customerEmail": "buyer@example.com",
        }

    monkeypatch.setattr(
        ps_catalog.CatalogHandler,
        "_paddle_lookup_transaction",
        fake_lookup,
    )

    db = ps_catalog.CatalogDB(db_path)
    _add_theme(db, themes, theme_id="matrix")
    real_port = _free_port()
    real_cfg = ps_catalog.Config(
        host=cfg_template.host,
        port=real_port,
        db_path=cfg_template.db_path,
        themes_dir=cfg_template.themes_dir,
        previews_dir=cfg_template.previews_dir,
        paddle_webhook_secret=cfg_template.paddle_webhook_secret,
        paddle_public_key=None,
        paddle_api_key="pdl_test_key",
        paddle_env="sandbox",
        base_url=f"http://127.0.0.1:{real_port}",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
    )
    server = ps_catalog.make_server(real_cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                with socket.create_connection(
                    (real_cfg.host, real_cfg.port), timeout=0.5
                ):
                    break
            except OSError:
                time.sleep(0.01)
        conn = http.client.HTTPConnection(real_cfg.host, real_cfg.port, timeout=5)
        try:
            status, _, body = _request(
                conn,
                "GET",
                f"/?_ptxn={transaction_id}",
            )
            assert status == 200
            # The checkout-success page should be rendered, not the
            # healthcheck JSON.
            assert b"Purchase complete" in body
            assert b"has been activated" in body
            assert b"themeId=matrix" in body
            assert f"installUuid={install_uuid}".encode() in body
        finally:
            conn.close()

        # License was proactively granted.
        owned = db.list_owned_theme_ids(install_uuid)
        assert owned == ["matrix"]
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_checkout_cancel_page_renders(client):
    conn, server, cfg, themes, previews, db = client
    install_uuid = str(uuid.uuid4())
    status, headers, body = _request(
        conn,
        "GET",
        f"/checkout-cancel?installUuid={install_uuid}&themeId=matrix",
    )
    assert status == 200
    assert headers.get("Content-Type", "").startswith("text/html")
    assert b"Checkout cancelled" in body


def test_plugin_route_returns_501(client):
    conn, server, cfg, themes, previews, db = client
    status, _, body = _request(conn, "GET", "/plugins/foo/download")
    assert status == 501
    payload = json.loads(body)
    assert payload["pluginId"] == "foo"


# ---------------------------------------------------------------------------
# Paddle webhook
# ---------------------------------------------------------------------------


def _paddle_signed(
    secret: str, payload: dict, ts: str | None = None
) -> tuple[str, str, bytes]:
    body = json.dumps(payload).encode("utf-8")
    ts = ts or str(int(time.time()))
    signed = f"{ts}:{body.decode('utf-8')}".encode("utf-8")
    sig = base64.b64encode(
        hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).digest()
    ).decode("ascii")
    header = f"ts={ts};h1={sig}"
    return header, ts, body


def test_paddle_webhook_grants_on_subscription_created(client):
    conn, server, cfg, themes, previews, db = client
    _add_theme(db, themes, theme_id="alpha")
    install_uuid = str(uuid.uuid4())
    header, _, body = _paddle_signed(
        cfg.paddle_webhook_secret,
        {
            "event_type": "subscription.created",
            "data": {
                "subscription_id": "sub_123",
                "customer_id": "ctm_456",
                "custom_data": {
                    "installUuid": install_uuid,
                    "themeId": "alpha",
                },
            },
        },
    )
    status, _, resp_body = _request(
        conn,
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": header},
    )
    assert status == 200
    payload = json.loads(resp_body)
    assert payload["granted"] is True
    assert db.list_owned_theme_ids(install_uuid) == ["alpha"]


def test_paddle_webhook_rejects_bad_signature(client):
    conn, server, cfg, themes, previews, db = client
    _add_theme(db, themes, theme_id="alpha")
    install_uuid = str(uuid.uuid4())
    header, _, body = _paddle_signed(
        "WRONG-SECRET",
        {
            "event_type": "subscription.created",
            "data": {
                "custom_data": {
                    "installUuid": install_uuid,
                    "themeId": "alpha",
                }
            },
        },
    )
    status, _, _ = _request(
        conn,
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": header},
    )
    assert status == 401


def test_paddle_webhook_resolves_theme_via_paddle_id(client):
    conn, server, cfg, themes, previews, db = client
    _add_theme(db, themes, theme_id="alpha", paddle_price_id="pri_xyz")
    install_uuid = str(uuid.uuid4())
    header, _, body = _paddle_signed(
        cfg.paddle_webhook_secret,
        {
            "event_type": "subscription.created",
            "data": {
                "items": [{"price_id": "pri_xyz"}],
                "custom_data": {"installUuid": install_uuid},
            },
        },
    )
    status, _, _ = _request(
        conn,
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": header},
    )
    assert status == 200
    assert db.list_owned_theme_ids(install_uuid) == ["alpha"]


def test_paddle_webhook_revoke_on_canceled(client):
    conn, server, cfg, themes, previews, db = client
    _add_theme(db, themes, theme_id="alpha")
    install_uuid = str(uuid.uuid4())
    db.grant_license(install_uuid, "alpha")
    header, _, body = _paddle_signed(
        cfg.paddle_webhook_secret,
        {
            "event_type": "subscription.canceled",
            "data": {
                "custom_data": {
                    "installUuid": install_uuid,
                    "themeId": "alpha",
                }
            },
        },
    )
    status, _, _ = _request(
        conn,
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": header},
    )
    assert status == 200
    assert db.list_owned_theme_ids(install_uuid) == []


def test_paddle_webhook_503_when_secret_missing(tmp_root):
    cfg, themes, previews, db_path = tmp_root
    db = ps_catalog.CatalogDB(db_path)
    real_port = _free_port()
    server = ps_catalog.make_server(
        ps_catalog.Config(
            host=cfg.host,
            port=real_port,
            db_path=cfg.db_path,
            themes_dir=cfg.themes_dir,
            previews_dir=cfg.previews_dir,
            paddle_webhook_secret=None,  # no secret
            paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
            base_url=f"http://127.0.0.1:{real_port}",
        ),
        db,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection(cfg.host, real_port, timeout=5)
        status, _, _ = _request(
            conn,
            "POST",
            "/paddle/webhook",
            body=b'{"event_type":"subscription.created"}',
        )
        assert status == 503
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_paddle_webhook_unknown_event_acked(client):
    conn, server, cfg, themes, previews, db = client
    install_uuid = str(uuid.uuid4())
    header, _, body = _paddle_signed(
        cfg.paddle_webhook_secret,
        {
            "event_type": "subscription.payment_succeeded",
            "data": {
                "custom_data": {
                    "installUuid": install_uuid,
                    "themeId": "alpha",
                }
            },
        },
    )
    status, _, resp_body = _request(
        conn,
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": header},
    )
    assert status == 200
    payload = json.loads(resp_body)
    assert payload.get("ignored") is True


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------


def test_cli_init_and_add_license(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    themes_dir = tmp_path / "themes"
    themes_dir.mkdir()
    theme_path = themes_dir / "alpha.json"
    theme_path.write_text(json.dumps({"id": "alpha", "name": "Alpha"}))

    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=tmp_path / "previews",
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
    )

    init_args = argparse_for(["--db", str(db_path), "init"])
    assert ps_catalog.cmd_init(init_args, cfg) == 0
    assert db_path.exists()

    add_theme_args = argparse_for(
        ["--db", str(db_path), "--themes-dir", str(themes_dir), "add-theme", str(theme_path)]
    )
    assert ps_catalog.cmd_add_theme(add_theme_args, cfg) == 0

    db = ps_catalog.CatalogDB(db_path)
    assert db.get_theme("alpha") is not None
    db.close()

    install_uuid = str(uuid.uuid4())
    add_lic_args = argparse_for(
        ["--db", str(db_path), "add-license", install_uuid, "alpha"]
    )
    assert ps_catalog.cmd_add_license(add_lic_args, cfg) == 0

    db = ps_catalog.CatalogDB(db_path)
    assert db.list_owned_theme_ids(install_uuid) == ["alpha"]
    db.close()


def test_cli_add_theme_with_paddle_flags(tmp_path):
    """The --paddle-product-id / --paddle-price-id / --checkout-url flags must
    be accepted by argparse and persisted into the themes table."""
    db_path = tmp_path / "catalog.sqlite3"
    themes_dir = tmp_path / "themes"
    themes_dir.mkdir()
    theme_path = themes_dir / "alpha.json"
    theme_path.write_text(json.dumps({"id": "alpha", "name": "Alpha"}))

    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=tmp_path / "previews",
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
    )

    # initialize schema
    assert ps_catalog.cmd_init(argparse_for(["--db", str(db_path), "init"]), cfg) == 0

    # add-theme with all three Paddle flags
    args = argparse_for(
        [
            "--db",
            str(db_path),
            "--themes-dir",
            str(themes_dir),
            "add-theme",
            str(theme_path),
            "--paddle-product-id",
            "pro_test_alpha",
            "--paddle-price-id",
            "pri_test_alpha",
            "--checkout-url",
            "https://buy.paddle.com/product/alpha/checkout",
        ]
    )
    assert ps_catalog.cmd_add_theme(args, cfg) == 0

    db = ps_catalog.CatalogDB(db_path)
    try:
        theme = db.get_theme("alpha")
        assert theme is not None
        assert theme["paddle_product_id"] == "pro_test_alpha"
        assert theme["paddle_price_id"] == "pri_test_alpha"
        assert theme["checkout_url"] == "https://buy.paddle.com/product/alpha/checkout"
    finally:
        db.close()


def test_cli_add_theme_falls_back_to_json_paddle_block(tmp_path):
    """When the CLI flags are omitted, the paddle.productId / paddle.priceId
    fields inside the theme JSON should be used."""
    db_path = tmp_path / "catalog.sqlite3"
    themes_dir = tmp_path / "themes"
    themes_dir.mkdir()
    theme_path = themes_dir / "beta.json"
    theme_path.write_text(
        json.dumps(
            {
                "id": "beta",
                "name": "Beta",
                "paddle": {"productId": "pro_from_json", "priceId": "pri_from_json"},
            }
        )
    )

    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=tmp_path / "previews",
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
    )

    assert ps_catalog.cmd_init(argparse_for(["--db", str(db_path), "init"]), cfg) == 0
    assert ps_catalog.cmd_add_theme(
        argparse_for(
            [
                "--db",
                str(db_path),
                "--themes-dir",
                str(themes_dir),
                "add-theme",
                str(theme_path),
            ]
        ),
        cfg,
    ) == 0

    db = ps_catalog.CatalogDB(db_path)
    try:
        theme = db.get_theme("beta")
        assert theme["paddle_product_id"] == "pro_from_json"
        assert theme["paddle_price_id"] == "pri_from_json"
        assert theme["checkout_url"] == ""  # not set -> redirect auto-builds
    finally:
        db.close()


def argparse_for(argv):
    parser = ps_catalog.build_arg_parser()
    return parser.parse_args(ps_catalog._hoist_global_flags(list(argv)))


# ---------------------------------------------------------------------------
# Return URL validation
# ---------------------------------------------------------------------------


def test_create_paddle_transaction_rejects_http_when_insecure_disabled():
    """When allow_insecure_return_urls is False (live mode default), http://
    return URLs are rejected with PaddleError."""
    cfg = _make_cfg(allow_insecure=False)
    with pytest.raises(ps_catalog.PaddleError) as exc_info:
        ps_catalog.create_paddle_transaction(
            cfg,
            price_id="pri",
            install_uuid=str(uuid.uuid4()),
            theme_id="x",
            success_url="http://catalog.example.com/success",
        )
    assert "http" in str(exc_info.value).lower()
    assert "https" in str(exc_info.value).lower()


def test_create_paddle_transaction_accepts_http_when_insecure_allowed():
    """When allow_insecure_return_urls is True (sandbox default), http://
    URLs are accepted without raising."""
    cfg = _make_cfg(allow_insecure=True)

    class FakeResp:
        status = 200

        def read(self):
            return json.dumps(
                {
                    "data": {
                        "checkout": {"url": "https://sandbox-pay.paddle.io/x"}
                    }
                }
            ).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    import urllib.request as _ur
    ps_catalog.urllib.request.urlopen = lambda req, timeout=None: FakeResp()
    try:
        url, txn_id = ps_catalog.create_paddle_transaction(
            cfg,
            price_id="pri",
            install_uuid=str(uuid.uuid4()),
            theme_id="x",
            success_url="http://localhost:9021/checkout-success",
        )
        assert url == "https://sandbox-pay.paddle.io/x"
        assert txn_id == ""
    finally:
        # No cleanup needed — monkeypatch-less direct setattr; subsequent
        # tests don't depend on the prior urlopen.
        del ps_catalog.urllib.request.urlopen


def test_create_paddle_transaction_accepts_https_always():
    cfg = _make_cfg(allow_insecure=False)

    class FakeResp:
        status = 200

        def read(self):
            return json.dumps(
                {"data": {"checkout": {"url": "https://pay.paddle.com/x"}}}
            ).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    ps_catalog.urllib.request.urlopen = lambda req, timeout=None: FakeResp()
    try:
        url, txn_id = ps_catalog.create_paddle_transaction(
            cfg,
            price_id="pri",
            install_uuid=str(uuid.uuid4()),
            theme_id="x",
            success_url="https://catalog.example.com/success",
        )
        assert url == "https://pay.paddle.com/x"
        assert txn_id == ""
    finally:
        del ps_catalog.urllib.request.urlopen


def test_create_paddle_transaction_rejects_invalid_scheme():
    cfg = _make_cfg()
    with pytest.raises(ps_catalog.PaddleError) as exc_info:
        ps_catalog.create_paddle_transaction(
            cfg,
            price_id="pri",
            install_uuid=str(uuid.uuid4()),
            theme_id="x",
            success_url="ftp://catalog.example.com/x",
        )
    assert "scheme" in str(exc_info.value).lower() or "http" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# HTTPS server support
# ---------------------------------------------------------------------------


def _generate_self_signed_cert(tmp_path):
    """Generate an ephemeral self-signed cert using openssl. Returns (cert_path, key_path).
    Skips the test if openssl isn't available."""
    import shutil
    import subprocess

    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl not available on this machine")

    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert_path, key_path


def test_make_server_serves_https_when_cert_and_key_provided(tmp_path):
    """When --tls-cert and --tls-key are set, make_server() wraps the
    listening socket in TLS so HTTPS requests succeed."""
    import ssl
    cert_path, key_path = _generate_self_signed_cert(tmp_path)
    db_path = tmp_path / "catalog.sqlite3"
    db = ps_catalog.CatalogDB(db_path)
    real_port = _free_port()
    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=real_port,
        db_path=db_path,
        themes_dir=tmp_path / "themes",
        previews_dir=tmp_path / "previews",
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        paddle_env="sandbox",
        base_url=f"https://127.0.0.1:{real_port}",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=cert_path,
        tls_key=key_path,
    )
    assert cfg.use_tls is True
    assert cfg.scheme == "https"
    server = ps_catalog.make_server(cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # Wait for it.
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", real_port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.01)

        # Plain HTTP should fail because the socket is wrapped in TLS.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(
            ("127.0.0.1", real_port), timeout=2
        ) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname="127.0.0.1") as tls_sock:
                tls_sock.sendall(
                    b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    b"Connection: close\r\n\r\n"
                )
                response = b""
                while True:
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
        assert b"200 OK" in response
        assert b'"ok": true' in response
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_make_server_serves_http_when_no_cert(tmp_path):
    """Without --tls-cert/--tls-key the server is plain HTTP and HTTPS
    requests fail."""
    db_path = tmp_path / "catalog.sqlite3"
    db = ps_catalog.CatalogDB(db_path)
    real_port = _free_port()
    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=real_port,
        db_path=db_path,
        themes_dir=tmp_path / "themes",
        previews_dir=tmp_path / "previews",
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        paddle_env="sandbox",
        base_url=f"http://127.0.0.1:{real_port}",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
    )
    assert cfg.use_tls is False
    server = ps_catalog.make_server(cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", real_port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.01)

        conn = http.client.HTTPConnection("127.0.0.1", real_port, timeout=2)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        assert resp.status == 200
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_make_server_exits_when_only_cert_is_provided(tmp_path):
    """If only --tls-cert is set without --tls-key, Config.from_env_and_args
    raises SystemExit so we don't silently launch a server without TLS."""
    cert_path = tmp_path / "cert.pem"
    cert_path.write_text("placeholder")
    # Simulate the call from_env_and_args does.
    args = argparse_for(
        [
            "--tls-cert",
            str(cert_path),
            "serve",
        ]
    )
    with pytest.raises(SystemExit):
        ps_catalog.Config.from_env_and_args(args)


def test_config_defaults_allow_insecure_in_sandbox(tmp_path, monkeypatch):
    """Without an explicit --allow-insecure-return-urls flag and env var,
    Config.from_env_and_args() defaults to insecure allowed in sandbox
    and insecure rejected in live."""
    monkeypatch.delenv("PS_CATALOG_ALLOW_INSECURE_RETURN_URLS", raising=False)
    sandbox_cfg = ps_catalog.Config.from_env_and_args(
        argparse_for(["--paddle-env", "sandbox", "serve"])
    )
    assert sandbox_cfg.allow_insecure_return_urls is True
    live_cfg = ps_catalog.Config.from_env_and_args(
        argparse_for(["--paddle-env", "live", "serve"])
    )
    assert live_cfg.allow_insecure_return_urls is False


def test_config_base_url_defaults_to_https_when_tls_configured(tmp_path, monkeypatch):
    """When --tls-cert/--tls-key are set, the auto-derived base_url upgrades
    from http to https so Paddle gets an https:// success_url by default."""
    monkeypatch.delenv("PS_CATALOG_BASE_URL", raising=False)
    monkeypatch.delenv("PS_CATALOG_TLS_CERT", raising=False)
    monkeypatch.delenv("PS_CATALOG_TLS_KEY", raising=False)
    cert_path, key_path = _generate_self_signed_cert(tmp_path)
    cfg = ps_catalog.Config.from_env_and_args(
        argparse_for(
            [
                "--port",
                "9101",
                "--tls-cert",
                str(cert_path),
                "--tls-key",
                str(key_path),
                "serve",
            ]
        )
    )
    assert cfg.base_url.startswith("https://")
    assert cfg.use_tls is True

    # Without TLS, base_url stays http.
    cfg_no_tls = ps_catalog.Config.from_env_and_args(
        argparse_for(["--port", "9101", "serve"])
    )
    assert cfg_no_tls.base_url.startswith("http://")
    assert cfg_no_tls.use_tls is False


# ---------------------------------------------------------------------------
# remove-theme CLI
# ---------------------------------------------------------------------------


def test_cli_remove_theme_drops_row_and_file(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    themes_dir = tmp_path / "themes"
    previews_dir = tmp_path / "previews"
    themes_dir.mkdir()
    previews_dir.mkdir()
    theme_path = themes_dir / "alpha.json"
    theme_path.write_text(json.dumps({"id": "alpha", "name": "Alpha"}))

    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=previews_dir,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
    )
    assert ps_catalog.cmd_init(argparse_for(["--db", str(db_path), "init"]), cfg) == 0
    assert ps_catalog.cmd_add_theme(
        argparse_for(
            [
                "--db",
                str(db_path),
                "--themes-dir",
                str(themes_dir),
                "add-theme",
                str(theme_path),
            ]
        ),
        cfg,
    ) == 0

    # Now remove it.
    args = argparse_for(
        [
            "--db",
            str(db_path),
            "--themes-dir",
            str(themes_dir),
            "--previews-dir",
            str(previews_dir),
            "remove-theme",
            "alpha",
        ]
    )
    assert ps_catalog.cmd_remove_theme(args, cfg) == 0

    db = ps_catalog.CatalogDB(db_path)
    try:
        assert db.get_theme("alpha") is None
    finally:
        db.close()
    assert not theme_path.exists()


def test_cli_remove_theme_keeps_licenses_by_default(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    themes_dir = tmp_path / "themes"
    previews_dir = tmp_path / "previews"
    themes_dir.mkdir()
    previews_dir.mkdir()
    theme_path = themes_dir / "alpha.json"
    theme_path.write_text(json.dumps({"id": "alpha", "name": "Alpha"}))

    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=previews_dir,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
    )
    assert ps_catalog.cmd_init(argparse_for(["--db", str(db_path), "init"]), cfg) == 0
    assert ps_catalog.cmd_add_theme(
        argparse_for(
            [
                "--db",
                str(db_path),
                "--themes-dir",
                str(themes_dir),
                "add-theme",
                str(theme_path),
            ]
        ),
        cfg,
    ) == 0

    install_uuid = str(uuid.uuid4())
    db = ps_catalog.CatalogDB(db_path)
    try:
        db.grant_license(install_uuid, "alpha")
    finally:
        db.close()

    args = argparse_for(
        [
            "--db",
            str(db_path),
            "--themes-dir",
            str(themes_dir),
            "--previews-dir",
            str(previews_dir),
            "remove-theme",
            "alpha",
        ]
    )
    assert ps_catalog.cmd_remove_theme(args, cfg) == 0

    db = ps_catalog.CatalogDB(db_path)
    try:
        assert db.get_theme("alpha") is None
        # License row should still exist because we didn't pass --purge-licenses.
        assert db.get_license(install_uuid, "alpha") is not None
    finally:
        db.close()


def test_cli_remove_theme_purge_licenses_drops_them(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    themes_dir = tmp_path / "themes"
    previews_dir = tmp_path / "previews"
    themes_dir.mkdir()
    previews_dir.mkdir()
    theme_path = themes_dir / "alpha.json"
    theme_path.write_text(json.dumps({"id": "alpha", "name": "Alpha"}))

    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=previews_dir,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
    )
    assert ps_catalog.cmd_init(argparse_for(["--db", str(db_path), "init"]), cfg) == 0
    assert ps_catalog.cmd_add_theme(
        argparse_for(
            [
                "--db",
                str(db_path),
                "--themes-dir",
                str(themes_dir),
                "add-theme",
                str(theme_path),
            ]
        ),
        cfg,
    ) == 0

    install_uuid = str(uuid.uuid4())
    db = ps_catalog.CatalogDB(db_path)
    try:
        db.grant_license(install_uuid, "alpha")
    finally:
        db.close()

    args = argparse_for(
        [
            "--db",
            str(db_path),
            "--themes-dir",
            str(themes_dir),
            "--previews-dir",
            str(previews_dir),
            "remove-theme",
            "alpha",
            "--purge-licenses",
        ]
    )
    assert ps_catalog.cmd_remove_theme(args, cfg) == 0

    db = ps_catalog.CatalogDB(db_path)
    try:
        assert db.get_theme("alpha") is None
        # License row should be gone.
        assert db.get_license(install_uuid, "alpha") is None
    finally:
        db.close()


def test_cli_remove_theme_remove_preview(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    themes_dir = tmp_path / "themes"
    previews_dir = tmp_path / "previews"
    themes_dir.mkdir()
    previews_dir.mkdir()
    theme_path = themes_dir / "alpha.json"
    theme_path.write_text(json.dumps({"id": "alpha", "name": "Alpha"}))
    preview_path = previews_dir / "alpha.jpg"
    preview_path.write_bytes(b"\xff\xd8\xff\xe0fake-jpeg")

    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=previews_dir,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
    )
    assert ps_catalog.cmd_init(argparse_for(["--db", str(db_path), "init"]), cfg) == 0
    assert ps_catalog.cmd_add_theme(
        argparse_for(
            [
                "--db",
                str(db_path),
                "--themes-dir",
                str(themes_dir),
                "add-theme",
                str(theme_path),
                "--preview-filename",
                "alpha.jpg",
            ]
        ),
        cfg,
    ) == 0

    args = argparse_for(
        [
            "--db",
            str(db_path),
            "--themes-dir",
            str(themes_dir),
            "--previews-dir",
            str(previews_dir),
            "remove-theme",
            "alpha",
            "--remove-preview",
        ]
    )
    assert ps_catalog.cmd_remove_theme(args, cfg) == 0
    assert not preview_path.exists()


def test_cli_remove_theme_dry_run_leaves_everything(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    themes_dir = tmp_path / "themes"
    previews_dir = tmp_path / "previews"
    themes_dir.mkdir()
    previews_dir.mkdir()
    theme_path = themes_dir / "alpha.json"
    theme_path.write_text(json.dumps({"id": "alpha", "name": "Alpha"}))

    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=previews_dir,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
    )
    assert ps_catalog.cmd_init(argparse_for(["--db", str(db_path), "init"]), cfg) == 0
    assert ps_catalog.cmd_add_theme(
        argparse_for(
            [
                "--db",
                str(db_path),
                "--themes-dir",
                str(themes_dir),
                "add-theme",
                str(theme_path),
            ]
        ),
        cfg,
    ) == 0

    args = argparse_for(
        [
            "--db",
            str(db_path),
            "--themes-dir",
            str(themes_dir),
            "--previews-dir",
            str(previews_dir),
            "remove-theme",
            "alpha",
            "--purge-licenses",
            "--dry-run",
        ]
    )
    assert ps_catalog.cmd_remove_theme(args, cfg) == 0

    db = ps_catalog.CatalogDB(db_path)
    try:
        assert db.get_theme("alpha") is not None
    finally:
        db.close()
    assert theme_path.exists()


def test_cli_remove_theme_rejects_unknown_id(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    themes_dir = tmp_path / "themes"
    previews_dir = tmp_path / "previews"
    themes_dir.mkdir()
    previews_dir.mkdir()

    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=previews_dir,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
    )
    assert ps_catalog.cmd_init(argparse_for(["--db", str(db_path), "init"]), cfg) == 0

    args = argparse_for(
        [
            "--db",
            str(db_path),
            "--themes-dir",
            str(themes_dir),
            "--previews-dir",
            str(previews_dir),
            "remove-theme",
            "nope",
        ]
    )
    assert ps_catalog.cmd_remove_theme(args, cfg) == 2


def test_cli_remove_theme_rejects_invalid_id(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    themes_dir = tmp_path / "themes"
    previews_dir = tmp_path / "previews"
    themes_dir.mkdir()
    previews_dir.mkdir()

    cfg = ps_catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=previews_dir,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
    )
    assert ps_catalog.cmd_init(argparse_for(["--db", str(db_path), "init"]), cfg) == 0

    args = argparse_for(
        [
            "--db",
            str(db_path),
            "--themes-dir",
            str(themes_dir),
            "--previews-dir",
            str(previews_dir),
            "remove-theme",
            "INVALID ID",
        ]
    )
    assert ps_catalog.cmd_remove_theme(args, cfg) == 2
