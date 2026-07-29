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
import json
import os
import re
import socket
import threading
import time
import urllib.parse
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
        base_url=f"http://127.0.0.1:{real_port}",
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


def test_checkout_redirects_to_paddle(client):
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
    status, headers, body = _request(conn, "GET", "/checkout/alpha")
    assert status == 302
    location = headers.get("Location", "")
    assert location.startswith("https://buy.paddle.com/product/alpha")
    assert "price=pri_abc" in location


def test_checkout_prefers_stored_url(client):
    conn, server, cfg, themes, previews, db = client
    db.upsert_theme(
        theme_id="alpha",
        name="Alpha",
        description="",
        price_cents=500,
        price_label="",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="https://buy.paddle.com/checkout/custom/alpha",
        license_url="",
    )
    status, headers, _ = _request(conn, "GET", "/checkout/alpha")
    assert status == 302
    assert headers["Location"] == "https://buy.paddle.com/checkout/custom/alpha"


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
    return parser.parse_args(argv)


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
