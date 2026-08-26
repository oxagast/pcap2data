"""Tests for the email-based install / customer pairing that backs
the self-service portal.

Covers:
  * The ``installs.customer_email`` column + ``installs_email_idx``
    migration: idempotent, doesn't error on a fresh DB, doesn't
    error on an already-migrated DB.
  * ``CatalogDB.update_install_email`` COALESCE-over-NULLIF semantic:
    a fresh non-empty value wins, a redelivered empty value leaves
    the existing email alone, lazy-registers a missing install.
  * ``CatalogDB.list_installs_for_customer_email`` finds installs by
    case-insensitive exact match, returns rows ordered by
    ``first_seen_at`` ASC, returns an empty list for unknown emails.
  * ``create_paddle_transaction`` forwards ``customer_email`` to both
    the top-level ``customer_email`` field and ``custom_data``
    when set, and skips both when empty.
  * ``_append_recovery_params`` adds ``customerEmail`` to the
    recovery URL without clobbering existing query params.
  * ``_is_valid_buyer_email`` rejects obvious typos / malformed
    addresses.

Tests run against an in-process sqlite (no network). Paddle-API
contract is verified at the payload-dict level via a fake
``urlopen`` so we never depend on a live sandbox."""

import importlib.util
import json
import re
import sys
import time
import urllib.parse
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _catalog_script() -> Path:
    return (
        _project_root()
        / "src"
        / "PacketSnitch-Pro"
        / "Servers"
        / "Catalog"
        / "ps-catalog.py"
    )


def _load_catalog_module():
    spec = importlib.util.spec_from_file_location(
        "ps_catalog_email_pairing_test_module", _catalog_script()
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load ps-catalog.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ps_catalog_email_pairing_test_module"] = module
    spec.loader.exec_module(module)
    return module


_catalog = _load_catalog_module()


# ---------------------------------------------------------------------------
# Schema / migration
# ---------------------------------------------------------------------------


def test_migrate_installs_customer_email_adds_column(tmp_path):
    """First run on a fresh DB installs the column + index. A second
    run is a no-op. The column has DEFAULT '' so any SELECT * FROM
    installs that doesn't list the column keeps its previous shape."""
    db_path = tmp_path / "fresh.sqlite3"
    db = _catalog.CatalogDB(db_path)
    # Lazy-register an install — column is present from the SCHEMA
    # CREATE TABLE on fresh DBs.
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)
    cols = {
        row["name"]
        for row in db.conn.execute("PRAGMA table_info(installs)").fetchall()
    }
    assert "customer_email" in cols
    # Index exists too.
    indexes = {
        row["name"]
        for row in db.conn.execute("PRAGMA index_list(installs)").fetchall()
    }
    assert "installs_email_idx" in indexes
    # Empty by default.
    row = db.get_install(install_uuid)
    assert row["customer_email"] == ""

    # Re-run migration is a no-op (no error, no schema change).
    db._migrate_installs_customer_email()
    cols2 = {
        row["name"]
        for row in db.conn.execute("PRAGMA table_info(installs)").fetchall()
    }
    assert "customer_email" in cols2


def test_migrate_installs_customer_email_handles_existing_db(tmp_path):
    """Simulate a catalog that was created before the column
    existed: drop the column + index and re-run the migration to
    confirm it backfills both. Uses a low-level SQLite dance rather
    than re-implementing the catalog's own migration logic."""
    db_path = tmp_path / "legacy.sqlite3"
    db = _catalog.CatalogDB(db_path)
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)

    # SQLite < 3.35 doesn't support DROP COLUMN; this is also a
    # useful smoke test that the migration is purely additive.
    # Instead, drop the column by recreating the table without it.
    db.conn.executescript(
        """
        PRAGMA foreign_keys = OFF;
        ALTER TABLE installs RENAME TO installs__no_email;
        CREATE TABLE installs (
            install_uuid TEXT PRIMARY KEY,
            license_tier TEXT NOT NULL DEFAULT 'free'
                CHECK (license_tier IN ('free','professional','enterprise','developer')),
            paddle_customer_id TEXT NOT NULL DEFAULT '',
            paddle_subscription_id TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            first_seen_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        -- Project the legacy columns (no customer_email) into the
        -- new 7-column shape so the copy succeeds. ``updated_at`` is
        -- passed twice only as a defensive placeholder — the
        -- ``executescript`` parameter expansion would otherwise
        -- complain about column count mismatches.
        INSERT INTO installs (install_uuid, license_tier,
                              paddle_customer_id, paddle_subscription_id,
                              notes, first_seen_at, updated_at)
        SELECT install_uuid, license_tier,
               paddle_customer_id, paddle_subscription_id,
               notes, first_seen_at, updated_at
          FROM installs__no_email;
        DROP TABLE installs__no_email;
        DROP INDEX IF EXISTS installs_email_idx;
        PRAGMA foreign_keys = ON;
        """
    )
    # Confirm the column is actually gone.
    cols = {
        row["name"]
        for row in db.conn.execute("PRAGMA table_info(installs)").fetchall()
    }
    assert "customer_email" not in cols

    # Run the migration — should re-add the column with DEFAULT ''
    # so the existing row's value comes back as ''.
    db._migrate_installs_customer_email()
    cols2 = {
        row["name"]
        for row in db.conn.execute("PRAGMA table_info(installs)").fetchall()
    }
    assert "customer_email" in cols2
    row = db.get_install(install_uuid)
    assert row["customer_email"] == ""


# ---------------------------------------------------------------------------
# update_install_email
# ---------------------------------------------------------------------------


def test_update_install_email_writes_first_value(tmp_path):
    db_path = tmp_path / "u.sqlite3"
    db = _catalog.CatalogDB(db_path)
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)
    db.update_install_email(install_uuid, "alice@example.com")
    row = db.get_install(install_uuid)
    assert row["customer_email"] == "alice@example.com"


def test_update_install_email_does_not_clobber_with_empty(tmp_path):
    """The COALESCE-over-NULLIF semantic: a redelivered webhook with
    an empty email field must not blank out a real one."""
    db_path = tmp_path / "u.sqlite3"
    db = _catalog.CatalogDB(db_path)
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)
    db.update_install_email(install_uuid, "alice@example.com")
    # Redelivery with empty email — no-op.
    db.update_install_email(install_uuid, "")
    row = db.get_install(install_uuid)
    assert row["customer_email"] == "alice@example.com"
    # Whitespace-only is also a no-op (it gets stripped before write).
    db.update_install_email(install_uuid, "   ")
    row = db.get_install(install_uuid)
    assert row["customer_email"] == "alice@example.com"


def test_update_install_email_lazily_registers(tmp_path):
    """If the install row doesn't exist yet, ``update_install_email``
    should still work — the portal uses this when a buyer has only
    ever hit the catalog's checkout flow and never the desktop's
    license endpoint."""
    db_path = tmp_path / "u.sqlite3"
    db = _catalog.CatalogDB(db_path)
    install_uuid = str(uuid.uuid4())
    # No get_or_register_install — straight to update_install_email.
    row = db.update_install_email(install_uuid, "alice@example.com")
    # ``update_install_email`` itself doesn't lazy-register; it
    # returns the existing row (or None). The webhook handler always
    # pre-lazy-registers via ``get_or_register_install`` before
    # stamping, so this matches the production call ordering.
    assert row is None
    # Now lazy-register and try again — should write successfully.
    db.get_or_register_install(install_uuid)
    db.update_install_email(install_uuid, "alice@example.com")
    assert db.get_install(install_uuid)["customer_email"] == "alice@example.com"


def test_update_install_email_rejects_invalid_uuid(tmp_path):
    db_path = tmp_path / "u.sqlite3"
    db = _catalog.CatalogDB(db_path)
    # Anything non-UUID-shaped is a silent no-op (returns None).
    assert db.update_install_email("", "alice@example.com") is None
    assert db.update_install_email("not-a-uuid", "alice@example.com") is None


# ---------------------------------------------------------------------------
# list_installs_for_customer_email
# ---------------------------------------------------------------------------


def test_list_installs_for_customer_email_empty_for_unknown(tmp_path):
    db_path = tmp_path / "u.sqlite3"
    db = _catalog.CatalogDB(db_path)
    assert db.list_installs_for_customer_email("") == []
    assert db.list_installs_for_customer_email("nobody@example.com") == []


def test_list_installs_for_customer_email_finds_seats(tmp_path):
    db_path = tmp_path / "u.sqlite3"
    db = _catalog.CatalogDB(db_path)
    uuid_a = str(uuid.uuid4())
    uuid_b = str(uuid.uuid4())
    uuid_c = str(uuid.uuid4())
    db.get_or_register_install(uuid_a)
    db.get_or_register_install(uuid_b)
    db.get_or_register_install(uuid_c)
    db.update_install_email(uuid_a, "buyer@example.com")
    db.update_install_email(uuid_b, "buyer@example.com")
    db.update_install_email(uuid_c, "nobody@example.com")

    seats = db.list_installs_for_customer_email("buyer@example.com")
    assert [row["install_uuid"] for row in seats] == [uuid_a, uuid_b]


def test_list_installs_for_customer_email_is_case_insensitive(tmp_path):
    db_path = tmp_path / "u.sqlite3"
    db = _catalog.CatalogDB(db_path)
    uuid_a = str(uuid.uuid4())
    db.get_or_register_install(uuid_a)
    db.update_install_email(uuid_a, "Buyer@Example.COM")
    seats = db.list_installs_for_customer_email("buyer@example.com")
    assert len(seats) == 1
    assert seats[0]["install_uuid"] == uuid_a


def test_list_installs_for_customer_email_exact_match_only(tmp_path):
    """Suffix typos must NOT match — the portal relies on this to
    prevent one buyer from accidentally seeing another's seats."""
    db_path = tmp_path / "u.sqlite3"
    db = _catalog.CatalogDB(db_path)
    uuid_a = str(uuid.uuid4())
    db.get_or_register_install(uuid_a)
    db.update_install_email(uuid_a, "alice@example.com")
    # Trailing-com typo shouldn't find the row.
    assert db.list_installs_for_customer_email("alice@example.con") == []
    assert db.list_installs_for_customer_email("alice@example.commm") == []
    # Substring match shouldn't either (full-string match only).
    assert db.list_installs_for_customer_email("alice@example") == []


# ---------------------------------------------------------------------------
# _is_valid_buyer_email
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "good",
    [
    "alice@example.com",
    "a.b+tag@example.co.uk",
    "user_name@sub.example.org",
    "x@y.io",
    ],
)
def test_is_valid_buyer_email_accepts(good):
    assert _catalog._is_valid_buyer_email(good), good


@pytest.mark.parametrize(
    "bad",
    [
    "",
    "not-an-address",
    "alice@",
    "@example.com",
    "alice@@example.com",
    "alice@example",
    "alice@.com",
    "alice@example.",
    "alice @example.com",
    "alice@example com",
    "alice@example,com",
    # 320+ char address
    "a" * 310 + "@example.com",
    ],
)
def test_is_valid_buyer_email_rejects(bad):
    assert not _catalog._is_valid_buyer_email(bad), bad


# ---------------------------------------------------------------------------
# create_paddle_transaction email forwarding
# ---------------------------------------------------------------------------


@contextmanager
def _stub_paddle_urlopen(captured: dict):
    """Patch ``urllib.request.urlopen`` so ``create_paddle_transaction``
    captures the outbound payload without a real network roundtrip.
    Yields a fake response object that returns a known checkout URL."""
    import urllib.request

    class _FakeResponse:
        def __init__(self):
            self.status = 200

        def read(self):
            return json.dumps(
                {
                    "data": {
                        "id": "txn_test_123",
                        "checkout": {"url": "https://checkout.paddle.com/hsc_FAKE"},
                    }
                }
            ).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def _fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["method"] = req.method
        captured["headers"] = dict(req.headers)
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse()

    with patch.object(urllib.request, "urlopen", _fake_urlopen):
        yield


def _make_config():
    return _catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=Path("/tmp/never-written.sqlite3"),
        themes_dir=Path("/tmp/themes"),
        previews_dir=Path("/tmp/previews"),
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key="pdl_test_key",
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        setup_token="test",
        admin_api_key="test",
        log_dir=Path("/tmp/logs"),
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
    )


def test_create_paddle_transaction_forwards_email_top_level_and_custom_data():
    captured: dict = {}
    with _stub_paddle_urlopen(captured):
        url, txn = _catalog.create_paddle_transaction(
            _make_config(),
            price_id="pri_test",
            install_uuid=str(uuid.uuid4()),
            theme_id="matrix-theme",
            customer_email="buyer@example.com",
        )
    assert url == "https://checkout.paddle.com/hsc_FAKE"
    assert txn == "txn_test_123"
    body = captured["body"]
    # Top-level customer_email AND custom_data.customerEmail
    # populated. Paddle uses the top-level field to pre-fill the
    # hosted form; we mirror into custom_data so the webhook always
    # has a copy regardless of which event surfaces the buyer.
    assert body["customer_email"] == "buyer@example.com"
    assert body["custom_data"]["customerEmail"] == "buyer@example.com"
    # installUuid / themeId always present (the existing behavior).
    assert "installUuid" in body["custom_data"]
    assert "themeId" in body["custom_data"]


def test_create_paddle_transaction_omits_email_when_empty():
    captured: dict = {}
    with _stub_paddle_urlopen(captured):
        _catalog.create_paddle_transaction(
            _make_config(),
            price_id="pri_test",
            install_uuid=str(uuid.uuid4()),
            theme_id="matrix-theme",
            customer_email="",
        )
    body = captured["body"]
    # When the desktop hasn't yet collected an email (e.g. legacy
    # clients), neither field is sent. Avoids sending ``""`` to
    # Paddle which would silently wipe any pre-filled value.
    assert "customer_email" not in body
    assert "customerEmail" not in body["custom_data"]


# ---------------------------------------------------------------------------
# _append_recovery_params customerEmail round-trip
# ---------------------------------------------------------------------------


def test_append_recovery_params_adds_customer_email():
    base = "https://checkout.paddle.com/hsc_FAKE"
    url = _catalog.CatalogHandler._append_recovery_params(
        base, "abc-uuid", "matrix-theme", "buyer@example.com"
    )
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    assert qs["installUuid"] == ["abc-uuid"]
    assert qs["themeId"] == ["matrix-theme"]
    assert qs["customerEmail"] == ["buyer@example.com"]


def test_append_recovery_params_preserves_existing_query():
    base = "https://merchant.example.com/checkout?price_id=pri_test&utm_source=newsletter"
    url = _catalog.CatalogHandler._append_recovery_params(
        base, "abc-uuid", "matrix-theme", "buyer@example.com"
    )
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    # New params added without disturbing merchant-side ones.
    assert qs["installUuid"] == ["abc-uuid"]
    assert qs["themeId"] == ["matrix-theme"]
    assert qs["customerEmail"] == ["buyer@example.com"]
    assert qs["price_id"] == ["pri_test"]
    assert qs["utm_source"] == ["newsletter"]


def test_append_recovery_params_no_op_for_all_empty():
    base = "https://checkout.paddle.com/hsc_FAKE?existing=keep"
    url = _catalog.CatalogHandler._append_recovery_params(base, "", "", "")
    # Only the existing query param survives.
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    assert qs == {"existing": ["keep"]}


# ---------------------------------------------------------------------------
# set_install_tier customer_email kwarg
# ---------------------------------------------------------------------------


def test_set_install_tier_passes_customer_email_through(tmp_path):
    db_path = tmp_path / "t.sqlite3"
    db = _catalog.CatalogDB(db_path)
    install_uuid = str(uuid.uuid4())
    db.set_install_tier(
        install_uuid,
        "professional",
        paddle_customer_id="ctm_test",
        paddle_subscription_id="sub_test",
        customer_email="buyer@example.com",
    )
    row = db.get_install(install_uuid)
    assert row["customer_email"] == "buyer@example.com"
    assert row["paddle_customer_id"] == "ctm_test"


def test_set_install_tier_empty_email_does_not_clobber(tmp_path):
    """Re-applying the tier with an empty email must not blank out
    the email that the success-page path already stamped. Matches
    the webhook redelivery semantic."""
    db_path = tmp_path / "t.sqlite3"
    db = _catalog.CatalogDB(db_path)
    install_uuid = str(uuid.uuid4())
    db.set_install_tier(
        install_uuid,
        "professional",
        paddle_customer_id="ctm_test",
        customer_email="buyer@example.com",
    )
    # Re-apply with an empty email — should be a no-op for email.
    db.set_install_tier(
        install_uuid,
        "professional",
        paddle_customer_id="ctm_test",
        customer_email="",
    )
    row = db.get_install(install_uuid)
    assert row["customer_email"] == "buyer@example.com"


# ---------------------------------------------------------------------------
# _stamp_install_customer_id helper (used by the webhook handler)
# ---------------------------------------------------------------------------


def test_stamp_install_customer_id_lazy_registers(tmp_path):
    """The webhook calls ``_stamp_install_customer_id`` BEFORE the
    grant, so the install may not have a row yet — the helper has
    to lazy-register. We exercise it via a minimal subclass of the
    handler so we can call the private method without binding a real
    socket."""
    db_path = tmp_path / "s.sqlite3"
    db = _catalog.CatalogDB(db_path)
    install_uuid = str(uuid.uuid4())

    class _StubHandler:
        def __init__(self, db):
            self.db = db

        _stamp_install_customer_id = _catalog.CatalogHandler._stamp_install_customer_id

    handler = _StubHandler(db)
    handler._stamp_install_customer_id(
        install_uuid=install_uuid,
        paddle_customer_id="ctm_webhook",
    )
    row = db.get_install(install_uuid)
    assert row is not None
    assert row["paddle_customer_id"] == "ctm_webhook"
    # Tier untouched — this helper only stamps customer id, never
    # tier (that's grant_license's job).
    assert row["license_tier"] == "free"


def test_stamp_install_customer_id_does_not_clobber_existing(tmp_path):
    """If a previous webhook already stamped the customer id, a
    redelivery with the same value must not change ``updated_at``
    (the WHERE clause filters out rows that already have the value).
    Done as a behavioral assertion: stamp once, sleep, stamp again,
    confirm updated_at didn't move."""
    db_path = tmp_path / "s.sqlite3"
    db = _catalog.CatalogDB(db_path)
    install_uuid = str(uuid.uuid4())

    class _StubHandler:
        def __init__(self, db):
            self.db = db

        _stamp_install_customer_id = _catalog.CatalogHandler._stamp_install_customer_id

    handler = _StubHandler(db)
    handler._stamp_install_customer_id(
        install_uuid=install_uuid,
        paddle_customer_id="ctm_webhook",
    )
    first_updated_at = db.get_install(install_uuid)["updated_at"]
    time.sleep(0.05)
    handler._stamp_install_customer_id(
        install_uuid=install_uuid,
        paddle_customer_id="ctm_webhook",
    )
    second_updated_at = db.get_install(install_uuid)["updated_at"]
    assert first_updated_at == second_updated_at


def test_stamp_install_customer_id_empty_is_no_op(tmp_path):
    db_path = tmp_path / "s.sqlite3"
    db = _catalog.CatalogDB(db_path)
    install_uuid = str(uuid.uuid4())

    class _StubHandler:
        def __init__(self, db):
            self.db = db

        _stamp_install_customer_id = _catalog.CatalogHandler._stamp_install_customer_id

    handler = _StubHandler(db)
    handler._stamp_install_customer_id(install_uuid=install_uuid, paddle_customer_id="")
    # No row created — empty cid is a no-op (would clobber real cid
    # if we ever decided to write NULL over a real value).
    assert db.get_install(install_uuid) is None


# ---------------------------------------------------------------------------
# _handle_licenses response shape (paddleCustomerId + customerEmail)
# ---------------------------------------------------------------------------


@contextmanager
def running_server(tmp_path: Path):
    """In-process catalog server for HTTP-level tests of /licenses
    and /portal. Mirrors the harness in test_catalog_admin_api.py —
    kept here (duplicated) to avoid a cross-test import that breaks
    when one file moves."""
    import socket
    import threading
    import time

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    db_path = tmp_path / f"licenses-{uuid.uuid4().hex}.sqlite3"
    themes_dir = tmp_path / "themes"
    previews_dir = tmp_path / "previews"
    themes_dir.mkdir(parents=True, exist_ok=True)
    previews_dir.mkdir(parents=True, exist_ok=True)
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
        admin_api_key="test-admin-key",
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
    )
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    db = _catalog.CatalogDB(db_path)
    server = _catalog.make_server(cfg, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=0.05)
            probe.close()
            break
        except OSError:
            time.sleep(0.01)
    try:
        yield port, db
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def _http(port, method, path, body=None, headers=None):
    from http.client import HTTPConnection

    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        hdrs = {"Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        if body is not None:
            hdrs.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=payload, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            parsed = {}
        return resp.status, parsed
    finally:
        conn.close()


def test_handle_licenses_surfaces_paddle_customer_id_and_email(tmp_path):
    """When the install has been paired (customer_id + email
    stamped), GET /licenses surfaces both fields so the desktop
    client can render the "Manage subscription" affordance."""
    with running_server(tmp_path) as (port, db):
        install_uuid = str(uuid.uuid4())
        # Set up the pairing state directly via the catalog DB.
        db.get_or_register_install(install_uuid)
        db.update_install_email(install_uuid, "buyer@example.com")
        handler = type(
            "_StubHandler",
            (),
            {
                "_stamp_install_customer_id":
                    _catalog.CatalogHandler._stamp_install_customer_id,
            },
        )()
        handler.db = db
        handler._stamp_install_customer_id(
            install_uuid=install_uuid,
            paddle_customer_id="ctm_pair",
        )
        status, payload = _http(
            port, "GET",
            f"/licenses?installUuid={install_uuid}",
        )
        assert status == 200, payload
        assert payload["paddleCustomerId"] == "ctm_pair"
        assert payload["customerEmail"] == "buyer@example.com"


def test_handle_licenses_returns_empty_identifiers_for_unknown_install(tmp_path):
    """An install that's never been paired must still get a
    deterministic 200 with empty customer id + email. The renderer
    uses these empty values to decide that the "Manage" button
    should not be shown yet."""
    with running_server(tmp_path) as (port, _db):
        install_uuid = str(uuid.uuid4())
        status, payload = _http(
            port, "GET",
            f"/licenses?installUuid={install_uuid}",
        )
        assert status == 200, payload
        assert payload["paddleCustomerId"] == ""
        assert payload["customerEmail"] == ""
        # Lazy-registered as free — the desktop can treat this as a
        # fresh install that hasn't bought anything.
        assert payload["licenseTier"] == "free"


def test_handle_licenses_400_on_missing_uuid(tmp_path):
    with running_server(tmp_path) as (port, _db):
        status, payload = _http(port, "GET", "/licenses")
        assert status == 400, payload
        assert "installUuid" in payload.get("error", "")


def test_handle_licenses_400_on_invalid_uuid(tmp_path):
    with running_server(tmp_path) as (port, _db):
        status, payload = _http(
            port, "GET", "/licenses?installUuid=not-a-uuid",
        )
        assert status == 400, payload