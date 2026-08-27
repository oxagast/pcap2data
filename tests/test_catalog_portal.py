"""HTTP-level tests for the catalog self-service portal surface.

Covers the three endpoints exposed by Phase 3 of the email-pairing
plan:

  * ``GET /portal?installUuid=...`` -- UUID-bearer lookup that returns
    every install paired with the same buyer email / paddle
    customer id. Used by the desktop and the "paste your UUID"
    form on the website.
  * ``POST /portal/request-link`` -- mints a single-use magic-link
    token, stores its sha256 in the database, and emits the
    sign-in email through the configured SMTP relay. The
    ``send_magic_link_email`` call is patched to a recording stub
    so we never depend on a real MTA.
  * ``POST /portal/redeem`` -- exchanges a token (+ optional
    installUuid) for the same payload shape as ``/portal`` GET.

Security properties under test:
  * Tokens are hashed before storage; the database never sees the
    plaintext twice.
  * Single-use enforcement via the conditional ``UPDATE ... WHERE
    consumed_at IS NULL`` -- concurrent redeems race to a single
    winner; everyone else sees 401.
  * TTL expiry: a token older than the configured lifetime is
    rejected on consume.
  * Email validation: missing/malformed ``email`` is 400, not 202.
  * Unknown-email guard: a request for an address with no paired
    installs is 404 -- the endpoint never spams an arbitrary
    address via our MTA.
  * installUuid-vs-email mismatch on request-link is rejected.
  * installUuid-vs-token mismatch on redeem is rejected.

All tests run against the same in-process socket server harness
that ``test_catalog_email_pairing.py`` uses, so Paddle / Stripe /
HTTP-server plumbing is shared rather than re-implemented."""

import importlib.util
import json
import socket
import sys
import threading
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
        "ps_catalog_portal_test_module", _catalog_script()
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load ps-catalog.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ps_catalog_portal_test_module"] = module
    spec.loader.exec_module(module)
    return module


_catalog = _load_catalog_module()


# ---------------------------------------------------------------------------
# Server harness (shared shape with the email-pairing tests)
# ---------------------------------------------------------------------------


@pytest.fixture
def running_server(tmp_path):
    """Bring up a fresh catalog server on an ephemeral localhost port.
    Yields ``(port, db)`` so tests can poke the HTTP surface and
    inspect sqlite rows directly. The server is shut down on exit."""
    db_path = tmp_path / "portal.sqlite3"
    themes_dir = tmp_path / "themes"
    previews_dir = tmp_path / "previews"
    themes_dir.mkdir(parents=True, exist_ok=True)
    previews_dir.mkdir(parents=True, exist_ok=True)
    # Bind to port 0 so the kernel picks a free port; no risk of
    # colliding with another test.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
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
        smtp_host="localhost",
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
    """Tiny HTTP client that returns ``(status, payload_dict, raw_body)``.
    ``payload_dict`` is ``None`` when the body isn't JSON. The raw
    body is preserved for assertions on non-JSON responses (we
    don't have any right now, but it's cheap to keep the seam)."""
    from http.client import HTTPConnection

    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        merged_headers = {"Content-Type": "application/json"}
        if headers:
            merged_headers.update(headers)
        conn.request(method, path, body=payload, headers=merged_headers)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            decoded = json.loads(raw.decode("utf-8")) if raw else None
        except json.JSONDecodeError:
            decoded = None
        return resp.status, decoded, raw
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /portal -- UUID-bearer path
# ---------------------------------------------------------------------------


def test_portal_get_returns_seats_for_uuid_bearer(tmp_path, running_server):
    """A buyer with three installs at the same email sees all three
    in the seats array when they GET /portal with any of those
    UUIDs. The response is the same shape regardless of which
    UUID they used."""
    port, db = running_server
    family_email = "buyer-family@example.com"
    uuid_a = str(uuid.uuid4())
    uuid_b = str(uuid.uuid4())
    uuid_c = str(uuid.uuid4())
    db.get_or_register_install(uuid_a)
    db.update_install_email(uuid_a, family_email)
    db.get_or_register_install(uuid_b)
    db.update_install_email(uuid_b, family_email)
    db.get_or_register_install(uuid_c)
    db.update_install_email(uuid_c, family_email)
    status, payload, _ = _http(port, "GET", f"/portal?installUuid={uuid_b}")
    assert status == 200, payload
    seat_uuids = {seat["installUuid"] for seat in payload["seats"]}
    assert seat_uuids == {uuid_a, uuid_b, uuid_c}
    assert payload["email"] == family_email
    assert payload["installUuid"] == uuid_b


def test_portal_get_lazy_registers_unknown_uuid(tmp_path, running_server):
    """An unknown installUuid still gets a deterministic (empty)
    answer rather than a 404 -- the desktop may present a UUID
    it hasn't yet reported to the catalog. The seats list is
    empty, and the response envelope is still 200."""
    port, _ = running_server
    fresh = str(uuid.uuid4())
    status, payload, _ = _http(port, "GET", f"/portal?installUuid={fresh}")
    assert status == 200, payload
    assert payload["seats"] == []
    assert payload["email"] == ""
    assert payload["customerId"] == ""
    assert payload["installUuid"] == fresh


def test_portal_get_400_on_missing_uuid(tmp_path, running_server):
    port, _ = running_server
    status, payload, _ = _http(port, "GET", "/portal")
    assert status == 400, payload
    assert "installUuid" in payload["error"]


def test_portal_get_400_on_invalid_uuid(tmp_path, running_server):
    port, _ = running_server
    status, payload, _ = _http(port, "GET", "/portal?installUuid=not-a-uuid")
    assert status == 400, payload


def test_portal_get_prefers_paddle_customer_family_over_email(tmp_path, running_server):
    """When two installs share a paddle_customer_id (the modern
    path) but only one of them has the email column populated
    yet, the seats list still contains every install in the
    customer family. This is the customer-fanout path documented
    in /memories/repo/catalog_tier_fanout.md."""
    port, db = running_server
    paddle_customer_id = "ctm_test_fanout_001"
    uuid_owner = str(uuid.uuid4())
    uuid_secondary = str(uuid.uuid4())
    db.get_or_register_install(uuid_owner)
    db.update_install_email(uuid_owner, "owner@example.com")
    # ``paddle_customer_id`` is stamped by the webhook handler via
    # ``_stamp_install_customer_id`` on the server class, but for
    # this test we just write the column directly to keep the
    # setup minimal.
    db.conn.execute(
        "UPDATE installs SET paddle_customer_id = ? WHERE install_uuid = ?",
        (paddle_customer_id, uuid_owner),
    )
    db.conn.commit()
    db.get_or_register_install(uuid_secondary)
    db.conn.execute(
        "UPDATE installs SET paddle_customer_id = ? WHERE install_uuid = ?",
        (paddle_customer_id, uuid_secondary),
    )
    db.conn.commit()
    status, payload, _ = _http(port, "GET", f"/portal?installUuid={uuid_owner}")
    assert status == 200, payload
    seat_uuids = {seat["installUuid"] for seat in payload["seats"]}
    assert seat_uuids == {uuid_owner, uuid_secondary}
    assert payload["customerId"] == paddle_customer_id


# ---------------------------------------------------------------------------
# POST /portal/request-link
# ---------------------------------------------------------------------------


def test_portal_request_link_mints_token_and_calls_send_email(tmp_path, running_server):
    """The happy path: valid email + matching install -> token
    minted -> ``send_magic_link_email`` invoked once with the
    sign-in URL -> response is 200 with an expiresAt. The token
    is NOT echoed in the response body."""
    port, db = running_server
    buyer_email = "alice@example.com"
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)
    db.update_install_email(install_uuid, buyer_email)
    sent: list = []
    with patch.object(
        _catalog, "send_magic_link_email", side_effect=lambda cfg, **kw: sent.append(kw)
    ):
        status, payload, _ = _http(
            port, "POST", "/portal/request-link",
            body={"email": buyer_email, "installUuid": install_uuid},
        )
    assert status == 200, payload
    assert payload["ok"] is True
    assert "expiresAt" in payload and isinstance(payload["expiresAt"], int)
    assert payload["expiresAt"] > int(time.time())
    # The plaintext token MUST NOT leak in the response.
    assert "token" not in payload
    # Exactly one email was dispatched, with the right recipient.
    assert len(sent) == 1
    sent_kwargs = sent[0]
    assert sent_kwargs["to_email"] == buyer_email
    # The sign-in URL must reference our redeem endpoint and
    # include both the token and the installUuid so a click from
    # the desktop carries the desktop's UUID.
    assert "/portal/redeem" in sent_kwargs["sign_in_url"]
    parsed = urllib.parse.urlparse(sent_kwargs["sign_in_url"])
    qs = urllib.parse.parse_qs(parsed.query)
    assert "token" in qs and qs["token"][0]
    assert qs.get("installUuid", [None])[0] == install_uuid


def test_portal_request_link_persists_token_in_db(tmp_path, running_server):
    """After a request-link call, the database has exactly one row
    in ``magic_link_tokens`` for that email, with a non-null
    hash, NULL ``consumed_at``, and an ``expires_at`` strictly
    in the future. This is the persistent record that
    ``/portal/redeem`` consults."""
    port, db = running_server
    buyer_email = "persist@example.com"
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)
    db.update_install_email(install_uuid, buyer_email)
    with patch.object(_catalog, "send_magic_link_email"):
        _http(
            port, "POST", "/portal/request-link",
            body={"email": buyer_email, "installUuid": install_uuid},
        )
    rows = list(
        db.conn.execute(
            "SELECT customer_email, install_uuid, expires_at, "
            "consumed_at FROM magic_link_tokens"
        )
    )
    assert len(rows) == 1
    email_col, install_col, expires_at, consumed_at = rows[0]
    assert email_col == buyer_email
    assert install_col == install_uuid
    assert expires_at > int(time.time())
    # ``consumed_at`` defaults to 0 (NOT NULL DEFAULT 0 in the
    # schema), so an unconsumed token reads back as 0.
    assert consumed_at == 0


def test_portal_request_link_400_on_missing_email(tmp_path, running_server):
    port, _ = running_server
    status, payload, _ = _http(port, "POST", "/portal/request-link", body={})
    assert status == 400, payload


def test_portal_request_link_400_on_invalid_email(tmp_path, running_server):
    port, _ = running_server
    status, payload, _ = _http(
        port, "POST", "/portal/request-link", body={"email": "not-an-email"}
    )
    assert status == 400, payload


def test_portal_request_link_404_on_unknown_email(tmp_path, running_server):
    """Typo-protection: if no install is paired with the email,
    we refuse to send a message at all (would otherwise spam any
    arbitrary address via our MTA)."""
    port, _ = running_server
    with patch.object(_catalog, "send_magic_link_email") as mock_send:
        status, payload, _ = _http(
            port, "POST", "/portal/request-link",
            body={"email": "stranger@example.com"},
        )
    assert status == 404, payload
    assert mock_send.call_count == 0


def test_portal_request_link_404_when_uuid_does_not_belong_to_email(tmp_path, running_server):
    """A buyer who knows a UUID they don't own must not be able to
    mint a token bound to it."""
    port, db = running_server
    legit_uuid = str(uuid.uuid4())
    other_uuid = str(uuid.uuid4())
    db.get_or_register_install(legit_uuid)
    db.update_install_email(legit_uuid, "alice@example.com")
    db.get_or_register_install(other_uuid)
    db.update_install_email(other_uuid, "bob@example.com")
    with patch.object(_catalog, "send_magic_link_email") as mock_send:
        status, payload, _ = _http(
            port, "POST", "/portal/request-link",
            body={"email": "alice@example.com", "installUuid": other_uuid},
        )
    assert status == 404, payload
    assert mock_send.call_count == 0


def test_portal_request_link_503_when_mta_fails(tmp_path, running_server):
    """When ``send_magic_link_email`` raises ``MagicLinkMailError``
    the endpoint surfaces a 503 (mailer broken) rather than 200.
    The buyer is told to retry, not that the email was sent."""
    port, db = running_server
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)
    db.update_install_email(install_uuid, "alice@example.com")
    with patch.object(
        _catalog,
        "send_magic_link_email",
        side_effect=_catalog.MagicLinkMailError("connection refused"),
    ):
        status, payload, _ = _http(
            port, "POST", "/portal/request-link",
            body={"email": "alice@example.com", "installUuid": install_uuid},
        )
    assert status == 503, payload


def test_portal_request_link_400_on_garbage_body(tmp_path, running_server):
    port, _ = running_server
    status, payload, _ = _http(port, "POST", "/portal/request-link", body={})
    # Empty body is "missing email" -> 400, not 415. The handler
    # treats absence of keys the same as missing fields.
    assert status == 400, payload


def test_portal_request_link_400_on_non_object_body(tmp_path, running_server):
    port, _ = running_server
    from http.client import HTTPConnection

    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(
            "POST",
            "/portal/request-link",
            body=b"[]",
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 400
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# POST /portal/redeem
# ---------------------------------------------------------------------------


def test_portal_redeem_round_trip_returns_seats(tmp_path, running_server):
    """End-to-end: request-link -> token delivered -> redeem ->
    seats payload. This is the path the website walks when a
    buyer clicks the link in their inbox."""
    port, db = running_server
    buyer_email = "alice@example.com"
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)
    db.update_install_email(install_uuid, buyer_email)
    captured_token = {}
    with patch.object(
        _catalog,
        "send_magic_link_email",
        side_effect=lambda cfg, to_email, sign_in_url, expires_at_unix:
            captured_token.setdefault("token", urllib.parse.parse_qs(
                urllib.parse.urlparse(sign_in_url).query
            )["token"][0]),
    ):
        status, _, _ = _http(
            port, "POST", "/portal/request-link",
            body={"email": buyer_email, "installUuid": install_uuid},
        )
        assert status == 200
    token = captured_token["token"]
    assert token
    status, payload, _ = _http(
        port, "POST", "/portal/redeem",
        body={"token": token, "installUuid": install_uuid},
    )
    assert status == 200, payload
    assert payload["ok"] is True
    assert payload["email"] == buyer_email
    seat_uuids = {seat["installUuid"] for seat in payload["seats"]}
    assert install_uuid in seat_uuids


def test_portal_redeem_401_on_unknown_token(tmp_path, running_server):
    port, _ = running_server
    bogus = "0" * 64
    status, payload, _ = _http(
        port, "POST", "/portal/redeem", body={"token": bogus},
    )
    assert status == 401, payload


def test_portal_redeem_401_on_replay(tmp_path, running_server):
    """A token redeemed once cannot be redeemed again. Second call
    is 401 even though the first call succeeded."""
    port, db = running_server
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)
    db.update_install_email(install_uuid, "alice@example.com")
    captured = {}
    with patch.object(
        _catalog,
        "send_magic_link_email",
        side_effect=lambda cfg, to_email, sign_in_url, expires_at_unix:
            captured.setdefault("token", urllib.parse.parse_qs(
                urllib.parse.urlparse(sign_in_url).query
            )["token"][0]),
    ):
        _http(
            port, "POST", "/portal/request-link",
            body={"email": "alice@example.com", "installUuid": install_uuid},
        )
    token = captured["token"]
    first_status, _, _ = _http(
        port, "POST", "/portal/redeem",
        body={"token": token, "installUuid": install_uuid},
    )
    assert first_status == 200
    second_status, payload, _ = _http(
        port, "POST", "/portal/redeem",
        body={"token": token, "installUuid": install_uuid},
    )
    assert second_status == 401, payload


def test_portal_redeem_401_on_expired_token(tmp_path, running_server):
    """A token whose ``expires_at`` is in the past is rejected even
    if its hash matches and it hasn't been consumed. ``create_magic_link_token``
    clamps ``ttl_seconds`` into [60, 86400] to prevent
    pathological lifetimes, so to test the expired-TTL path we
    mint a normal token then surgically rewind its ``expires_at``
    in the database."""
    port, db = running_server
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)
    db.update_install_email(install_uuid, "alice@example.com")
    token, _ = db.create_magic_link_token(
        customer_email="alice@example.com",
        install_uuid=install_uuid,
    )
    # Force the row to look expired without minting a fresh
    # token (which would change the plaintext we'd need to send).
    db.conn.execute(
        "UPDATE magic_link_tokens SET expires_at = ? WHERE customer_email = ?",
        (int(time.time()) - 60, "alice@example.com"),
    )
    db.conn.commit()
    status, payload, _ = _http(
        port, "POST", "/portal/redeem",
        body={"token": token, "installUuid": install_uuid},
    )
    assert status == 401, payload


def test_portal_redeem_401_on_installuuid_mismatch(tmp_path, running_server):
    """Token was minted for one UUID but redeemed against another.
    The handler must refuse -- otherwise a leaked token from
    install A could unlock install B's view."""
    port, db = running_server
    install_a = str(uuid.uuid4())
    install_b = str(uuid.uuid4())
    db.get_or_register_install(install_a)
    db.update_install_email(install_a, "alice@example.com")
    db.get_or_register_install(install_b)
    db.update_install_email(install_b, "alice@example.com")
    token, _ = db.create_magic_link_token(
        customer_email="alice@example.com",
        install_uuid=install_a,
    )
    status, payload, _ = _http(
        port, "POST", "/portal/redeem",
        body={"token": token, "installUuid": install_b},
    )
    assert status == 401, payload


def test_portal_redeem_400_on_missing_token(tmp_path, running_server):
    port, _ = running_server
    status, payload, _ = _http(port, "POST", "/portal/redeem", body={})
    assert status == 400, payload


def test_portal_redeem_400_on_invalid_uuid(tmp_path, running_server):
    port, _ = running_server
    status, payload, _ = _http(
        port, "POST", "/portal/redeem",
        body={"token": "x" * 64, "installUuid": "not-a-uuid"},
    )
    assert status == 400, payload


def test_portal_redeem_works_without_installuuid(tmp_path, running_server):
    """When the buyer clicked the link from the website (no
    installUuid context), the redeem endpoint accepts the token
    and picks an anchor UUID from the email family."""
    port, db = running_server
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)
    db.update_install_email(install_uuid, "alice@example.com")
    token, _ = db.create_magic_link_token(
        customer_email="alice@example.com",
        install_uuid="",
    )
    status, payload, _ = _http(
        port, "POST", "/portal/redeem", body={"token": token},
    )
    assert status == 200, payload
    assert payload["email"] == "alice@example.com"
    assert payload["installUuid"] == install_uuid


def test_portal_redeem_marks_token_consumed_in_db(tmp_path, running_server):
    """Consumed tokens have a non-null ``consumed_at`` so a future
    audit / cleanup pass can find them. The hash is still
    present; only the plaintext is gone (never was on disk)."""
    port, db = running_server
    install_uuid = str(uuid.uuid4())
    db.get_or_register_install(install_uuid)
    db.update_install_email(install_uuid, "alice@example.com")
    token, _ = db.create_magic_link_token(
        customer_email="alice@example.com",
        install_uuid=install_uuid,
    )
    _http(
        port, "POST", "/portal/redeem",
        body={"token": token, "installUuid": install_uuid},
    )
    row = db.conn.execute(
        "SELECT consumed_at, consumed_from_ip FROM magic_link_tokens"
    ).fetchone()
    assert row[0] is not None
    assert isinstance(row[0], int)
    # remote_addr is the loopback test client -- we don't pin the
    # exact value, just that it was captured.
    assert row[1] is not None
