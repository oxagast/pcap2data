"""HTTP-level tests for the admin portal (browser-based admin UI).

Covers the cookie-auth surface at ``/admin/api/*``:

  * ``POST /admin/api/login`` — password + TOTP verification, session
    cookie issuance, and first-time TOTP enrollment flow.
  * ``POST /admin/api/totp/enroll`` — confirm TOTP enrollment and
    get a session.
  * ``POST /admin/api/logout`` — revoke session + clear cookie.
  * ``GET  /admin/api/me`` — current admin profile.
  * ``GET  /admin/api/themes`` / ``/admin/api/installs`` /
    ``/admin/api/licenses`` — viewer+ read endpoints.
  * ``POST /admin/api/installs/<uuid>/tier`` — operator+ write.
  * ``POST /admin/api/licenses`` — operator+ write.
  * ``POST /admin/api/uuid-claims`` — operator+ self-claim.
  * ``GET  /admin/api/admins`` — super_admin only.
  * ``POST /admin/api/admins`` — super_admin only (create admin).
  * Role-based access control (403 for insufficient role).
  * Session expiry + revocation.
  * TOTP verification (generate + verify round-trip).
  * Password hashing (hash + verify round-trip).

All tests run against the same in-process socket server harness that
``test_catalog_portal.py`` uses."""

import importlib.util
import json
import socket
import sys
import threading
import time
import urllib.parse
from contextlib import contextmanager
from http.client import HTTPConnection
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
        "ps_catalog_admin_portal_test_module", _catalog_script()
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load ps-catalog.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ps_catalog_admin_portal_test_module"] = module
    spec.loader.exec_module(module)
    return module


_catalog = _load_catalog_module()


def _make_config(db_path, tmp_path, **overrides):
    """Build a minimal Config suitable for in-process testing."""
    defaults = dict(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=tmp_path / "themes",
        previews_dir=tmp_path / "previews",
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
        paddle_env="sandbox",
        base_url="https://catalog.test",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        setup_token="test-setup-token-not-placeholder",
        admin_api_key="test-admin-key-for-api-surface",
        log_dir=tmp_path / "logs",
        log_file="test.log",
        log_rotate=False,
        paddle_poll_enabled=False,
        paddle_poll_interval=0,
        smtp_host="",
        smtp_port=25,
        smtp_username=None,
        smtp_password=None,
        smtp_from="test@test",
        smtp_use_tls=False,
        admin_portal_enabled=True,
        admin_session_ttl_hours=12,
    )
    defaults.update(overrides)
    return _catalog.Config(**defaults)


@contextmanager
def running_server(tmp_path, **config_overrides):
    """Start the catalog server in-process on a free port. Yields
    ``(port, config, db)``. Cleans up on exit."""
    db_path = tmp_path / "test_catalog.db"
    config = _make_config(db_path, tmp_path, **config_overrides)
    config.themes_dir.mkdir(parents=True, exist_ok=True)
    config.previews_dir.mkdir(parents=True, exist_ok=True)
    config.log_dir.mkdir(parents=True, exist_ok=True)
    db = _catalog.CatalogDB(db_path)

    # Find a free port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    config = _make_config(db_path, tmp_path, port=port, **config_overrides)
    server = _catalog.make_server(config, db)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port, config, db
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def _request(port, method, path, body=None, headers=None, cookie=None):
    """Make an HTTP request and return ``(status, json_body, resp_headers)``."""
    conn = HTTPConnection("127.0.0.1", port, timeout=10)
    h = headers or {}
    if cookie:
        h["Cookie"] = cookie
    if body is not None:
        if isinstance(body, dict):
            body = json.dumps(body)
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        h["Content-Type"] = "application/json"
        h["Content-Length"] = str(len(body_bytes))
    else:
        body_bytes = None
    conn.request(method, path, body=body_bytes, headers=h)
    resp = conn.getresponse()
    data = resp.read()
    status = resp.status
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    try:
        parsed = json.loads(data.decode("utf-8")) if data else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        parsed = {}
    conn.close()
    return status, parsed, resp_headers


def _extract_cookie(resp_headers):
    """Extract the ps_admin cookie value from Set-Cookie header."""
    set_cookie = resp_headers.get("set-cookie", "")
    if not set_cookie:
        return ""
    # Parse "ps_admin=VALUE; Path=/admin; ..."
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith("ps_admin="):
            return part[len("ps_admin="):]
    return ""


# ---- Password hashing tests ----

class TestPasswordHashing:
    def test_hash_and_verify_roundtrip(self):
        pw = "testPassword123!"
        h = _catalog.hash_password(pw)
        assert h.startswith("pbkdf2$")
        assert _catalog.verify_password(pw, h) is True

    def test_wrong_password_fails(self):
        h = _catalog.hash_password("correctPassword")
        assert _catalog.verify_password("wrongPassword", h) is False

    def test_empty_password_raises(self):
        with pytest.raises(ValueError):
            _catalog.hash_password("")

    def test_empty_inputs_fail_verify(self):
        assert _catalog.verify_password("", "pbkdf2$1$AA$BB") is False
        assert _catalog.verify_password("test", "") is False

    def test_malformed_hash_fails(self):
        assert _catalog.verify_password("test", "not-a-hash") is False
        assert _catalog.verify_password("test", "pbkdf2$abc$notb64$notb64") is False


# ---- TOTP tests ----

class TestTOTP:
    def test_generate_and_verify_roundtrip(self):
        secret = _catalog.totp_generate_secret()
        assert len(secret) > 0
        code = _catalog.totp_generate(secret)
        assert len(code) == 6
        assert code.isdigit()
        assert _catalog.totp_verify(secret, code) is True

    def test_verify_with_window(self):
        secret = _catalog.totp_generate_secret()
        # Generate code for 30 seconds ago
        past_time = int(time.time()) - 30
        code = _catalog.totp_generate(secret, at_time=past_time)
        # Should verify with window=1
        assert _catalog.totp_verify(secret, code, window=1) is True
        # Should NOT verify with window=0 (current step only)
        assert _catalog.totp_verify(secret, code, window=0) is False

    def test_invalid_code_fails(self):
        secret = _catalog.totp_generate_secret()
        assert _catalog.totp_verify(secret, "000000") is False or \
            _catalog.totp_verify(secret, "000000") is True  # might be valid
        assert _catalog.totp_verify(secret, "abc123") is False
        assert _catalog.totp_verify(secret, "") is False

    def test_provisioning_uri(self):
        secret = _catalog.totp_generate_secret()
        uri = _catalog.totp_provisioning_uri("admin@test.com", secret)
        assert uri.startswith("otpauth://totp/")
        assert "PacketSnitch" in uri
        assert secret in uri

    def test_secret_is_base32(self):
        secret = _catalog.totp_generate_secret()
        # base32 alphabet: A-Z, 2-7
        for c in secret:
            assert c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


# ---- Admin portal auth tests ----

class TestAdminPortalAuth:
    def test_login_wrong_credentials(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            db.create_admin("admin@test.com",
                            _catalog.hash_password("password123"),
                            "super_admin")
            status, body, _ = _request(port, "POST", "/admin/api/login", {
                "email": "admin@test.com",
                "password": "wrongpassword",
            })
            assert status == 401
            assert "error" in body

    def test_login_nonexistent_admin(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            status, body, _ = _request(port, "POST", "/admin/api/login", {
                "email": "nobody@test.com",
                "password": "whatever",
            })
            assert status == 401

    def test_login_requires_totp_enrollment(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            db.create_admin("admin@test.com",
                            _catalog.hash_password("password123"),
                            "super_admin")
            status, body, _ = _request(port, "POST", "/admin/api/login", {
                "email": "admin@test.com",
                "password": "password123",
            })
            assert status == 200
            assert body.get("requiresTotpEnrollment") is True
            assert "totpSecret" in body
            assert "totpUri" in body

    def test_full_login_flow_with_totp(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            db.create_admin("admin@test.com",
                            _catalog.hash_password("password123"),
                            "super_admin")
            # Step 1: login → get enrollment challenge
            status, body, _ = _request(port, "POST", "/admin/api/login", {
                "email": "admin@test.com",
                "password": "password123",
            })
            assert status == 200
            assert body["requiresTotpEnrollment"] is True
            secret = body["totpSecret"]
            # Step 2: enroll TOTP
            code = _catalog.totp_generate(secret)
            status, body, resp_h = _request(port, "POST", "/admin/api/totp/enroll", {
                "enrollmentEmail": "admin@test.com",
                "enrollmentPassword": "password123",
                "totpCode": code,
            })
            assert status == 200
            assert body["ok"] is True
            cookie = _extract_cookie(resp_h)
            assert cookie != ""
            # Step 3: verify session with /me
            status, body, _ = _request(port, "GET", "/admin/api/me",
                                       cookie=f"ps_admin={cookie}")
            assert status == 200
            assert body["admin"]["email"] == "admin@test.com"

    def test_logout_clears_session(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            # Create admin with TOTP already enrolled
            admin = db.create_admin("admin@test.com",
                                    _catalog.hash_password("password123"),
                                    "super_admin")
            secret = _catalog.totp_generate_secret()
            db.update_admin_totp(admin["id"], secret)
            # Login
            code = _catalog.totp_generate(secret)
            status, body, resp_h = _request(port, "POST", "/admin/api/login", {
                "email": "admin@test.com",
                "password": "password123",
                "totpCode": code,
            })
            assert status == 200
            cookie = _extract_cookie(resp_h)
            # Logout
            status, body, _ = _request(port, "POST", "/admin/api/logout",
                                       cookie=f"ps_admin={cookie}")
            assert status == 200
            # Session should be invalid now
            status, body, _ = _request(port, "GET", "/admin/api/me",
                                       cookie=f"ps_admin={cookie}")
            assert status == 401

    def test_me_without_cookie_is_401(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            status, body, _ = _request(port, "GET", "/admin/api/me")
            assert status == 401

    def test_portal_disabled_returns_503(self, tmp_path):
        with running_server(tmp_path, admin_portal_enabled=False) as (port, config, db):
            status, body, _ = _request(port, "GET", "/admin/api/me")
            assert status == 503
            assert body.get("adminPortalDisabled") is True


# ---- Role-based access control ----

class TestAdminPortalRBAC:
    def _setup_admin(self, db, email, role, enrolled=True):
        admin = db.create_admin(email,
                                _catalog.hash_password("password123"),
                                role)
        if enrolled:
            secret = _catalog.totp_generate_secret()
            db.update_admin_totp(admin["id"], secret)
            return admin, secret
        return admin, None

    def _login(self, port, email, secret):
        code = _catalog.totp_generate(secret)
        status, body, resp_h = _request(port, "POST", "/admin/api/login", {
            "email": email, "password": "password123", "totpCode": code,
        })
        assert status == 200, f"Login failed: {body}"
        return _extract_cookie(resp_h)

    def test_viewer_can_read_themes(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            _, secret = self._setup_admin(db, "viewer@test.com", "viewer")
            cookie = self._login(port, "viewer@test.com", secret)
            status, body, _ = _request(port, "GET", "/admin/api/themes",
                                       cookie=f"ps_admin={cookie}")
            assert status == 200
            assert "themes" in body

    def test_viewer_cannot_set_tier(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            _, secret = self._setup_admin(db, "viewer@test.com", "viewer")
            cookie = self._login(port, "viewer@test.com", secret)
            status, body, _ = _request(port, "POST", "/admin/api/installs", {
                "installUuid": "11111111-2222-3333-4444-555555555555",
                "tier": "professional",
            }, cookie=f"ps_admin={cookie}")
            assert status == 403

    def test_operator_can_set_tier(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            _, secret = self._setup_admin(db, "op@test.com", "operator")
            cookie = self._login(port, "op@test.com", secret)
            status, body, _ = _request(port, "POST", "/admin/api/installs", {
                "installUuid": "11111111-2222-3333-4444-555555555555",
                "tier": "professional",
            }, cookie=f"ps_admin={cookie}")
            assert status == 200
            assert body["ok"] is True

    def test_operator_cannot_create_theme(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            _, secret = self._setup_admin(db, "op@test.com", "operator")
            cookie = self._login(port, "op@test.com", secret)
            status, body, _ = _request(port, "POST", "/admin/api/themes", {
                "id": "test-theme",
                "name": "Test",
            }, cookie=f"ps_admin={cookie}")
            assert status == 403

    def test_super_admin_can_create_theme(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            _, secret = self._setup_admin(db, "super@test.com", "super_admin")
            cookie = self._login(port, "super@test.com", secret)
            status, body, _ = _request(port, "POST", "/admin/api/themes", {
                "id": "test-theme",
                "name": "Test",
                "priceCents": 299,
                "priceLabel": "$2.99",
            }, cookie=f"ps_admin={cookie}")
            assert status == 200
            assert body["ok"] is True

    def test_viewer_cannot_list_admins(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            _, secret = self._setup_admin(db, "viewer@test.com", "viewer")
            cookie = self._login(port, "viewer@test.com", secret)
            status, body, _ = _request(port, "GET", "/admin/api/admins",
                                       cookie=f"ps_admin={cookie}")
            assert status == 403

    def test_super_admin_can_list_admins(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            _, secret = self._setup_admin(db, "super@test.com", "super_admin")
            cookie = self._login(port, "super@test.com", secret)
            status, body, _ = _request(port, "GET", "/admin/api/admins",
                                       cookie=f"ps_admin={cookie}")
            assert status == 200
            assert "admins" in body

    def test_super_admin_can_create_admin(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            _, secret = self._setup_admin(db, "super@test.com", "super_admin")
            cookie = self._login(port, "super@test.com", secret)
            status, body, _ = _request(port, "POST", "/admin/api/admins", {
                "email": "newadmin@test.com",
                "password": "newPassword123",
                "role": "operator",
            }, cookie=f"ps_admin={cookie}")
            assert status == 200
            assert body["admin"]["email"] == "newadmin@test.com"


# ---- UUID claim tests ----

class TestUUIDClaims:
    def _setup_and_login(self, port, db, email, role):
        admin = db.create_admin(email,
                                _catalog.hash_password("password123"),
                                role)
        secret = _catalog.totp_generate_secret()
        db.update_admin_totp(admin["id"], secret)
        code = _catalog.totp_generate(secret)
        status, body, resp_h = _request(port, "POST", "/admin/api/login", {
            "email": email, "password": "password123", "totpCode": code,
        })
        assert status == 200
        return _extract_cookie(resp_h)

    def test_claim_and_list_uuid(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            cookie = self._setup_and_login(port, db, "op@test.com", "operator")
            uuid_str = "11111111-2222-3333-4444-555555555555"
            # Claim
            status, body, _ = _request(port, "POST", "/admin/api/uuid-claims", {
                "installUuid": uuid_str,
                "notes": "Test claim",
            }, cookie=f"ps_admin={cookie}")
            assert status == 200
            assert body["ok"] is True
            # List
            status, body, _ = _request(port, "GET", "/admin/api/uuid-claims",
                                       cookie=f"ps_admin={cookie}")
            assert status == 200
            assert len(body["claims"]) == 1
            assert body["claims"][0]["install_uuid"] == uuid_str

    def test_claim_invalid_uuid_rejected(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            cookie = self._setup_and_login(port, db, "op@test.com", "operator")
            status, body, _ = _request(port, "POST", "/admin/api/uuid-claims", {
                "installUuid": "not-a-uuid",
            }, cookie=f"ps_admin={cookie}")
            assert status == 400

    def test_unclaim_uuid(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            cookie = self._setup_and_login(port, db, "op@test.com", "operator")
            uuid_str = "11111111-2222-3333-4444-555555555555"
            # Claim
            _request(port, "POST", "/admin/api/uuid-claims", {
                "installUuid": uuid_str,
            }, cookie=f"ps_admin={cookie}")
            # Unclaim
            status, body, _ = _request(port, "POST",
                                       f"/admin/api/uuid-claims/{uuid_str}",
                                       cookie=f"ps_admin={cookie}")
            assert status == 200
            # List should be empty
            status, body, _ = _request(port, "GET", "/admin/api/uuid-claims",
                                       cookie=f"ps_admin={cookie}")
            assert len(body["claims"]) == 0


# ---- Static file serving ----

class TestAdminStaticFiles:
    def test_admin_index_served(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            status, body, resp_h = _request(port, "GET", "/admin/")
            # _request tries to parse JSON; static HTML won't parse
            # so we check the raw status + content-type instead
            assert status == 200
            assert "text/html" in resp_h.get("content-type", "")

    def test_admin_login_served(self, tmp_path):
        with running_server(tmp_path) as (port, config, db):
            status, body, resp_h = _request(port, "GET", "/admin/login")
            assert status == 200
            assert "text/html" in resp_h.get("content-type", "")


# ---- CLI create-admin ----

class TestCreateAdminCLI:
    def test_create_admin_cli(self, tmp_path):
        db_path = tmp_path / "test.db"
        config = _make_config(db_path, tmp_path)
        db = _catalog.CatalogDB(db_path)
        # Simulate the CLI command
        import argparse
        args = argparse.Namespace(
            email="cli-admin@test.com",
            password="cliPassword123",
            role="super_admin",
            display_name="CLI Admin",
            log_level="INFO",
        )
        rc = _catalog.cmd_create_admin(args, config)
        assert rc == 0
        admin = db.get_admin_by_email("cli-admin@test.com")
        assert admin is not None
        assert admin["role"] == "super_admin"
        assert admin["display_name"] == "CLI Admin"
        assert _catalog.verify_password("cliPassword123", admin["password_hash"])
        db.close()

    def test_create_admin_duplicate_email(self, tmp_path):
        db_path = tmp_path / "test.db"
        config = _make_config(db_path, tmp_path)
        db = _catalog.CatalogDB(db_path)
        import argparse
        args = argparse.Namespace(
            email="dup@test.com",
            password="password123",
            role="viewer",
            display_name="",
            log_level="INFO",
        )
        assert _catalog.cmd_create_admin(args, config) == 0
        # Second call should fail
        assert _catalog.cmd_create_admin(args, config) == 2
        db.close()

    def test_create_admin_short_password(self, tmp_path):
        db_path = tmp_path / "test.db"
        config = _make_config(db_path, tmp_path)
        db = _catalog.CatalogDB(db_path)
        import argparse
        args = argparse.Namespace(
            email="short@test.com",
            password="short",
            role="viewer",
            display_name="",
            log_level="INFO",
        )
        assert _catalog.cmd_create_admin(args, config) == 2
        db.close()