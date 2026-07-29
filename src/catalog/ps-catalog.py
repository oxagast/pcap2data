#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PacketSnitch theme catalog server (ps-catalog.py).

Serves the PacketSnitch desktop app's theme catalog and license-gated theme
downloads. Built on the Python stdlib (http.server + sqlite3) so the server
can run anywhere Python 3.10+ is installed without extra dependencies.

Endpoints
---------
GET  /health                                  -> {"ok": true}
GET  /catalog                                 -> {"entries": [...]}
GET  /catalog?installUuid=...                 -> same, server-side personalization
                                               (owned/installed flags)
GET  /themes/<id>/download                    -> theme.json body, only if the
                                               installUuid has a license for it
GET  /themes/<id>/preview                     -> preview JPG bytes (optional;
                                               falls back to /previews/<id>.jpg
                                               on disk if not inlined in the
                                               catalog entry)
GET  /previews/<file>                         -> static preview JPG
GET  /checkout/<id>?installUuid=...           -> 302 to the Paddle checkout URL
                                               for the theme (or HTML fallback)
POST /paddle/webhook                          -> Paddle webhook receiver that
                                               grants licenses on
                                               subscription.created /
                                               subscription.updated / etc.
GET  /licenses?installUuid=...                -> {"ownedThemeIds": [...]}
GET  /plugins/<id>/download                   -> 501 stub for now; returns
                                               JSON {"error":"..."} so future
                                               plugin support can be added
                                               without route changes.

CLI
---
    ps-catalog.py --init                              # create sqlite db
    ps-catalog.py --add-theme PATH/TO/theme.json      # register a theme
    ps-catalog.py --remove-theme THEMEID [--purge-licenses] [--remove-preview] [--dry-run]
    ps-catalog.py --add-preview PATH/TO/preview.jpg ID
    ps-catalog.py --add-license INSTALLUUID THEMEID [--subscription SUBID]
    ps-catalog.py --list-themes
    ps-catalog.py --serve [--host 127.0.0.1] [--port 9021]

Environment variables (all optional; CLI flags override):
    PS_CATALOG_HOST       default 127.0.0.1
    PS_CATALOG_PORT       default 9021
    PS_CATALOG_DB         default ./catalog.sqlite3
    PS_CATALOG_THEMES     default ./themes
    PS_CATALOG_PREVIEWS   default ./previews
    PS_CATALOG_PADDLE_WEBHOOK_SECRET  default unset (required to verify
                                                 Paddle webhook signatures)
    PS_CATALOG_PADDLE_PUBLIC_KEY      default unset (recommended; used for
                                                 webhook signature verification)
    PS_CATALOG_PADDLE_API_KEY         default unset (required to create
                                                 dynamic Hosted Checkout
                                                 sessions per click)
    PS_CATALOG_PADDLE_ENV             "live" or "sandbox" (default "live")
    PS_CATALOG_BASE_URL   default http://127.0.0.1:9021   (used to build
                                                          absolute checkout
                                                          URLs)
    PS_CATALOG_TLS_CERT   default unset (PEM cert file; pair with
                                   PS_CATALOG_TLS_KEY to enable HTTPS)
    PS_CATALOG_TLS_KEY    default unset (PEM private key file)
    PS_CATALOG_SUCCESS_URL default unset (override Paddle success return URL)
    PS_CATALOG_CANCEL_URL  default unset (override Paddle cancel return URL)
    PS_CATALOG_ALLOW_INSECURE_RETURN_URLS  default 1 in sandbox / 0 in live

Paddle integration
------------------
The server is deliberately Paddle-agnostic on the read path: the catalog and
`/licenses` endpoints just look at the local sqlite table. The write path is
the `/paddle/webhook` endpoint, which verifies the signature header, parses
the event, and grants a license row keyed by (installUuid, themeId) when the
event type indicates an active subscription or one-time purchase. Without the
webhook secret configured, the endpoint returns 503 to avoid silently
granting licenses without verification.

For development without a real Paddle webhook, you can manually grant
licenses via `--add-license INSTALLUUID THEMEID`.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import ssl
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9021
DEFAULT_DB = "catalog.sqlite3"
DEFAULT_THEMES_DIR = "themes"
DEFAULT_PREVIEWS_DIR = "previews"

# Paddle API base URLs. Sandbox is used when PADDLE_ENV=sandbox; otherwise live.
# https://developer.paddle.com/api-reference/overview
PADDLE_API_BASE_LIVE = "https://api.paddle.com"
PADDLE_API_BASE_SANDBOX = "https://sandbox-api.paddle.com"
# Hosted-checkout URLs returned by the transactions API begin with one of these.
PADDLE_CHECKOUT_HOST_LIVE = "https://pay.paddle.com"
PADDLE_CHECKOUT_HOST_SANDBOX = "https://sandbox-pay.paddle.io"

THEME_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
INSTALL_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Paddle event types that should grant (or refresh) a theme license.
# https://developer.paddle.com/webhooks/subscriptions/subscription-created
PADDLE_GRANTING_EVENT_TYPES = {
    "subscription.created",
    "subscription.activated",
    "subscription.updated",
    "transaction.completed",
    "transaction.paid",
}

# Paddle event types that should revoke a theme license.
PADDLE_REVOKING_EVENT_TYPES = {
    "subscription.canceled",
    "subscription.expired",
    "subscription.past_due",
    "transaction.refunded",
    "transaction.disputed",
}

LOG = logging.getLogger("ps-catalog")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    db_path: Path
    themes_dir: Path
    previews_dir: Path
    paddle_webhook_secret: Optional[str]
    paddle_public_key: Optional[str]
    paddle_api_key: Optional[str]
    paddle_env: str  # "live" or "sandbox"
    base_url: str
    success_url: Optional[str]
    cancel_url: Optional[str]
    allow_insecure_return_urls: bool
    tls_cert: Optional[Path]
    tls_key: Optional[Path]

    @property
    def use_tls(self) -> bool:
        return self.tls_cert is not None and self.tls_key is not None

    @property
    def scheme(self) -> str:
        return "https" if self.use_tls else "http"

    @property
    def paddle_api_base(self) -> str:
        return (
            PADDLE_API_BASE_SANDBOX
            if self.paddle_env == "sandbox"
            else PADDLE_API_BASE_LIVE
        )

    @property
    def paddle_checkout_host(self) -> str:
        return (
            PADDLE_CHECKOUT_HOST_SANDBOX
            if self.paddle_env == "sandbox"
            else PADDLE_CHECKOUT_HOST_LIVE
        )

    @classmethod
    def from_env_and_args(cls, args: argparse.Namespace) -> "Config":
        host = args.host or os.environ.get("PS_CATALOG_HOST", DEFAULT_HOST)
        port = args.port or int(os.environ.get("PS_CATALOG_PORT", DEFAULT_PORT))
        db_path = Path(
            args.db or os.environ.get("PS_CATALOG_DB", DEFAULT_DB)
        ).resolve()
        themes_dir = Path(
            args.themes_dir or os.environ.get("PS_CATALOG_THEMES", DEFAULT_THEMES_DIR)
        ).resolve()
        previews_dir = Path(
            args.previews_dir
            or os.environ.get("PS_CATALOG_PREVIEWS", DEFAULT_PREVIEWS_DIR)
        ).resolve()
        paddle_webhook_secret = (
            args.paddle_webhook_secret
            or os.environ.get("PS_CATALOG_PADDLE_WEBHOOK_SECRET")
            or None
        )
        paddle_public_key = (
            args.paddle_public_key
            or os.environ.get("PS_CATALOG_PADDLE_PUBLIC_KEY")
            or None
        )
        paddle_api_key = (
            args.paddle_api_key
            or os.environ.get("PS_CATALOG_PADDLE_API_KEY")
            or None
        )
        paddle_env = (
            args.paddle_env
            or os.environ.get("PS_CATALOG_PADDLE_ENV")
            or "live"
        ).strip().lower()
        if paddle_env not in ("live", "sandbox"):
            paddle_env = "live"
        success_url = (
            getattr(args, "success_url", None)
            or os.environ.get("PS_CATALOG_SUCCESS_URL")
            or None
        )
        cancel_url = (
            getattr(args, "cancel_url", None)
            or os.environ.get("PS_CATALOG_CANCEL_URL")
            or None
        )
        if getattr(args, "allow_insecure_return_urls", None) is not None:
            allow_insecure = bool(args.allow_insecure_return_urls)
        else:
            env_flag = os.environ.get(
                "PS_CATALOG_ALLOW_INSECURE_RETURN_URLS"
            )
            if env_flag is None:
                # Default: allow http:// for sandbox, require https:// for live.
                allow_insecure = paddle_env == "sandbox"
            else:
                allow_insecure = env_flag.strip().lower() in (
                    "1", "true", "yes", "on"
                )

        tls_cert_str = (
            getattr(args, "tls_cert", None)
            or os.environ.get("PS_CATALOG_TLS_CERT")
        )
        tls_key_str = (
            getattr(args, "tls_key", None)
            or os.environ.get("PS_CATALOG_TLS_KEY")
        )
        tls_cert = Path(tls_cert_str).resolve() if tls_cert_str else None
        tls_key = Path(tls_key_str).resolve() if tls_key_str else None
        if (tls_cert is None) != (tls_key is None):
            raise SystemExit(
                "Both --tls-cert and --tls-key must be provided together "
                "(or both omitted for plain HTTP)."
            )

        # If TLS is configured and the operator didn't override base_url, force
        # it to https:// so the success_url / cancel_url Paddle receives is
        # itself https://. (Paddle refuses to redirect back to plain http://
        # for non-localhost URLs.)
        base_url_default = f"http://{host}:{port}"
        if (
            tls_cert is not None
            and not (args.base_url or os.environ.get("PS_CATALOG_BASE_URL"))
        ):
            base_url_default = f"https://{host}:{port}"
        base_url = (
            args.base_url
            or os.environ.get("PS_CATALOG_BASE_URL")
            or base_url_default
        )

        return cls(
            host=host,
            port=port,
            db_path=db_path,
            themes_dir=themes_dir,
            previews_dir=previews_dir,
            paddle_webhook_secret=paddle_webhook_secret,
            paddle_public_key=paddle_public_key,
            paddle_api_key=paddle_api_key,
            paddle_env=paddle_env,
            base_url=base_url.rstrip("/"),
            success_url=success_url,
            cancel_url=cancel_url,
            allow_insecure_return_urls=allow_insecure,
            tls_cert=tls_cert,
            tls_key=tls_key,
        )


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------


class PaddleError(Exception):
    """Raised when Paddle returns an error or the call cannot complete."""

    def __init__(self, message: str, status: int = 0, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


def create_paddle_transaction(
    config: "Config",
    *,
    price_id: str,
    install_uuid: str,
    theme_id: str,
    success_url: Optional[str] = None,
    cancel_url: Optional[str] = None,
    timeout_s: float = 10.0,
) -> str:
    """Create a new Paddle transaction and return the hosted-checkout URL.

    Paddle returns a unique `https://.../hsc_<token>` URL per call, which
    can be opened in the user's default browser. The transaction is bound
    to ``price_id`` plus a ``custom_data`` payload carrying our ``installUuid``
    and ``themeId`` so the webhook handler knows which license to grant.

    Requires ``config.paddle_api_key``. Raises ``PaddleError`` on any HTTP
    or parse error.
    """
    import json as _json
    import urllib.error
    import urllib.request

    if not config.paddle_api_key:
        raise PaddleError(
            "Paddle API key is not configured (set --paddle-api-key or "
            "PS_CATALOG_PADDLE_API_KEY)"
        )
    if not price_id:
        raise PaddleError("price_id is required")

    def _validate_return_url(value: Optional[str], label: str) -> Optional[str]:
        if not value:
            return None
        try:
            parsed = urllib.parse.urlparse(value)
        except ValueError as exc:
            raise PaddleError(f"{label} is not a valid URL: {exc}") from exc
        if parsed.scheme not in ("https", "http"):
            raise PaddleError(
                f"{label} must use http(s); got {parsed.scheme!r}"
            )
        if parsed.scheme == "http" and not config.allow_insecure_return_urls:
            raise PaddleError(
                f"{label} uses plain http:// but the catalog is configured "
                "to require https:// return URLs. Pass "
                "--allow-insecure-return-urls (or set "
                "PS_CATALOG_ALLOW_INSECURE_RETURN_URLS=1) for local "
                "development, or serve the catalog over TLS and pass "
                "--tls-cert/--tls-key."
            )
        return value

    success_url = _validate_return_url(success_url, "success_url")
    cancel_url = _validate_return_url(cancel_url, "cancel_url")

    payload = {
        "items": [{"price_id": price_id, "quantity": 1}],
        "custom_data": {
            "installUuid": install_uuid,
            "themeId": theme_id,
        },
    }
    if success_url or cancel_url:
        # Paddle accepts return URLs on the transaction so the buyer lands
        # somewhere sensible after a successful/cancelled checkout. If the
        # server is HTTPS-only we always pass https://; if it's running in
        # sandbox with --allow-insecure-return-urls, http://localhost is
        # acceptable to Paddle's API.
        if success_url:
            payload["checkout"] = payload.get("checkout", {})
            payload["checkout"]["success_url"] = success_url
        if cancel_url:
            payload["checkout"] = payload.get("checkout", {})
            payload["checkout"]["cancel_url"] = cancel_url

    body = _json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=f"{config.paddle_api_base}/transactions",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {config.paddle_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            response_body = resp.read().decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        raise PaddleError(
            f"Paddle responded with HTTP {exc.code}: {exc.reason}",
            status=exc.code,
            body=response_body,
        ) from exc
    except urllib.error.URLError as exc:
        raise PaddleError(
            f"Could not reach Paddle API: {exc.reason}"
        ) from exc

    if status >= 400:
        raise PaddleError(
            f"Paddle responded with HTTP {status}",
            status=status,
            body=response_body,
        )

    try:
        parsed = _json.loads(response_body)
    except _json.JSONDecodeError as exc:
        raise PaddleError(
            "Paddle response was not valid JSON",
            status=status,
            body=response_body,
        ) from exc

    checkout_url = (
        parsed.get("data", {}).get("checkout", {}).get("url")
        or parsed.get("data", {}).get("checkout_url")
        or ""
    )
    if not checkout_url:
        raise PaddleError(
            "Paddle response did not include a checkout URL",
            status=status,
            body=response_body,
        )
    return checkout_url


SCHEMA = """
CREATE TABLE IF NOT EXISTS themes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    price_cents INTEGER,
    price_label TEXT NOT NULL DEFAULT '',
    paddle_product_id TEXT NOT NULL DEFAULT '',
    paddle_price_id TEXT NOT NULL DEFAULT '',
    preview_image TEXT NOT NULL DEFAULT '',
    preview_filename TEXT NOT NULL DEFAULT '',
    checkout_url TEXT NOT NULL DEFAULT '',
    license_url TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS licenses (
    install_uuid TEXT NOT NULL,
    theme_id TEXT NOT NULL,
    paddle_subscription_id TEXT NOT NULL DEFAULT '',
    paddle_customer_id TEXT NOT NULL DEFAULT '',
    granted_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER,
    PRIMARY KEY (install_uuid, theme_id),
    FOREIGN KEY (theme_id) REFERENCES themes(id)
);

CREATE INDEX IF NOT EXISTS licenses_install_idx
    ON licenses(install_uuid);
CREATE INDEX IF NOT EXISTS licenses_theme_idx
    ON licenses(theme_id);
"""


class CatalogDB:
    """Thin wrapper around sqlite3 for the catalog store."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False lets us reuse a single CatalogDB instance
        # from the HTTP server thread and CLI helpers. We serialize access
        # with self._lock so writes remain atomic.
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(
            str(path),
            isolation_level=None,
            check_same_thread=False,
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)

    # ---- themes ----

    def upsert_theme(
        self,
        theme_id: str,
        name: str,
        description: str,
        price_cents: Optional[int],
        price_label: str,
        paddle_product_id: str,
        paddle_price_id: str,
        preview_image: str,
        preview_filename: str,
        checkout_url: str,
        license_url: str,
    ) -> None:
        now = int(time.time())
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO themes (
                    id, name, description, price_cents, price_label,
                    paddle_product_id, paddle_price_id,
                    preview_image, preview_filename, checkout_url, license_url,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    description=excluded.description,
                    price_cents=excluded.price_cents,
                    price_label=excluded.price_label,
                    paddle_product_id=excluded.paddle_product_id,
                    paddle_price_id=excluded.paddle_price_id,
                    preview_image=excluded.preview_image,
                    preview_filename=excluded.preview_filename,
                    checkout_url=excluded.checkout_url,
                    license_url=excluded.license_url,
                    updated_at=excluded.updated_at
                """,
                (
                    theme_id,
                    name,
                    description,
                    price_cents,
                    price_label,
                    paddle_product_id,
                    paddle_price_id,
                    preview_image,
                    preview_filename,
                    checkout_url,
                    license_url,
                    now,
                    now,
                ),
            )

    def get_theme(self, theme_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM themes WHERE id = ?", (theme_id,)
            ).fetchone()

    def list_themes(self) -> List[sqlite3.Row]:
        with self._lock:
            return list(
                self.conn.execute(
                    "SELECT * FROM themes ORDER BY id COLLATE NOCASE"
                )
            )

    def delete_theme(self, theme_id: str) -> None:
        """Remove a theme row but keep any existing license rows.

        SQLite enforces `FOREIGN KEY (theme_id) REFERENCES themes(id)` and
        `PRAGMA foreign_keys=ON` is set, so a plain DELETE would fail when
        licenses still reference the theme. We temporarily disable FK
        enforcement inside this transaction so the theme row can be
        removed without revoking anyone's license.

        Use `delete_theme_cascade` instead if you also want to drop the
        license rows.
        """
        with self._lock:
            old = self.conn.execute("PRAGMA foreign_keys").fetchone()[0]
            try:
                self.conn.execute("PRAGMA foreign_keys = OFF")
                self.conn.execute("DELETE FROM themes WHERE id = ?", (theme_id,))
            finally:
                self.conn.execute(f"PRAGMA foreign_keys = {old}")

    def delete_theme_cascade(self, theme_id: str) -> int:
        """Remove a theme and every license row that references it.

        Returns the number of license rows that were deleted (0 if the theme
        had no buyers yet). Caller is responsible for removing the theme's
        JSON file from `themes_dir` afterwards.
        """
        with self._lock:
            cursor = self.conn.execute(
                "DELETE FROM licenses WHERE theme_id = ?", (theme_id,)
            )
            license_count = cursor.rowcount
            self.conn.execute("DELETE FROM themes WHERE id = ?", (theme_id,))
            return license_count

    # ---- licenses ----

    def grant_license(
        self,
        install_uuid: str,
        theme_id: str,
        paddle_subscription_id: str = "",
        paddle_customer_id: str = "",
        expires_at: Optional[int] = None,
    ) -> None:
        now = int(time.time())
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO licenses (
                    install_uuid, theme_id, paddle_subscription_id,
                    paddle_customer_id, granted_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(install_uuid, theme_id) DO UPDATE SET
                    paddle_subscription_id=excluded.paddle_subscription_id,
                    paddle_customer_id=excluded.paddle_customer_id,
                    granted_at=excluded.granted_at,
                    expires_at=excluded.expires_at,
                    revoked_at=NULL
                """,
                (install_uuid, theme_id, paddle_subscription_id,
                 paddle_customer_id, now, expires_at),
            )

    def revoke_license(self, install_uuid: str, theme_id: str) -> None:
        now = int(time.time())
        with self._lock:
            self.conn.execute(
                """
                UPDATE licenses
                   SET revoked_at = ?
                 WHERE install_uuid = ? AND theme_id = ? AND revoked_at IS NULL
                """,
                (now, install_uuid, theme_id),
            )

    def list_owned_theme_ids(self, install_uuid: str) -> List[str]:
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT theme_id
                  FROM licenses
                 WHERE install_uuid = ?
                   AND revoked_at IS NULL
                """,
                (install_uuid,),
            ).fetchall()
        return [row["theme_id"] for row in rows]

    def list_owned_install_uuids_for_theme(self, theme_id: str) -> List[str]:
        """Return the installUuids that currently hold an unrevoked license
        for the given theme. Used by `remove-theme --purge-licenses` for
        auditing before deletion."""
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT install_uuid
                  FROM licenses
                 WHERE theme_id = ?
                   AND revoked_at IS NULL
                """,
                (theme_id,),
            ).fetchall()
        return [row["install_uuid"] for row in rows]

    def count_active_licenses_for_theme(self, theme_id: str) -> int:
        with self._lock:
            row = self.conn.execute(
                """
                SELECT COUNT(*) AS c
                  FROM licenses
                 WHERE theme_id = ? AND revoked_at IS NULL
                """,
                (theme_id,),
            ).fetchone()
        return int(row["c"]) if row else 0

    def get_license(
        self, install_uuid: str, theme_id: str
    ) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                """
                SELECT *
                  FROM licenses
                 WHERE install_uuid = ? AND theme_id = ? AND revoked_at IS NULL
                """,
                (install_uuid, theme_id),
            ).fetchone()

    def close(self) -> None:
        with self._lock:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------


class CatalogHandler(BaseHTTPRequestHandler):
    server_version = "ps-catalog/0.1"

    # Subclasses / server sets these.
    config: Config = None  # type: ignore[assignment]
    db: CatalogDB = None  # type: ignore[assignment]

    # ---- helpers ----

    def _write_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _write_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        cache_control: str = "no-store",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self.end_headers()
        self.wfile.write(body)

    def _write_redirect(self, location: str) -> None:
        # Tiny HTML fallback so even a curl/lynx user sees something useful.
        body = (
            b'<!DOCTYPE html><html><head><meta charset="utf-8">'
            b'<meta http-equiv="refresh" content="0; url='
            + location.encode("utf-8")
            + b'">'
            b'<title>Redirecting to checkout...</title></head>'
            b'<body><p>Redirecting to checkout... If your browser does not '
            b'redirect, <a href="'
            + location.encode("utf-8")
            + b'">click here</a>.</p></body></html>'
        )
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        if length > 5 * 1024 * 1024:
            raise ValueError("Request body too large")
        return self.rfile.read(length)

    def _catalog_entry(
        self,
        theme: sqlite3.Row,
        owned_ids: Iterable[str],
        installed_ids: Iterable[str],
    ) -> Dict[str, Any]:
        owned_set = set(owned_ids)
        installed_set = set(installed_ids)
        return {
            "id": theme["id"],
            "name": theme["name"],
            "description": theme["description"],
            "priceCents": theme["price_cents"],
            "priceLabel": theme["price_label"],
            "checkoutUrl": self._build_checkout_url(theme["id"]),
            "previewImage": theme["preview_image"],
            "previewUrl": self._build_preview_url(
                theme["id"], theme["preview_filename"]
            ),
            "licenseUrl": theme["license_url"],
            "owned": theme["id"] in owned_set,
            "installed": theme["id"] in installed_set,
        }

    def _build_checkout_url(self, theme_id: str) -> str:
        return f"{self.config.base_url}/checkout/{urllib.parse.quote(theme_id)}"

    def _build_preview_url(self, theme_id: str, preview_filename: str) -> str:
        if preview_filename:
            return (
                f"{self.config.base_url}/previews/"
                + urllib.parse.quote(preview_filename)
            )
        return f"{self.config.base_url}/themes/{urllib.parse.quote(theme_id)}/preview"

    # ---- routing ----

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        try:
            self._dispatch_get()
        except Exception:  # pragma: no cover - defensive
            LOG.exception("Unhandled GET error")
            self._write_json(500, {"error": "Internal server error"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._dispatch_post()
        except Exception:  # pragma: no cover - defensive
            LOG.exception("Unhandled POST error")
            self._write_json(500, {"error": "Internal server error"})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        LOG.info("%s - %s", self.address_string(), format % args)

    # ---- GET handlers ----

    def _dispatch_get(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = urllib.parse.parse_qs(parsed.query)
        first = lambda key: params.get(key, [""])[0]  # noqa: E731

        if path == "/" or path == "/health":
            return self._write_json(200, {"ok": True})

        if path == "/catalog":
            return self._handle_catalog(first("installUuid"))

        if path.startswith("/themes/"):
            return self._handle_theme_get(path, first("installUuid"))

        if path.startswith("/previews/"):
            return self._handle_preview_file(path)

        if path == "/checkout-success" or path == "/checkout-cancel":
            return self._handle_checkout_return(path, parsed)

        # /checkout/<id>  (exactly two path segments)
        if path.startswith("/checkout/"):
            segments = path.split("/")
            if len(segments) == 3 and segments[0] == "" and segments[1] == "checkout":
                return self._handle_checkout_get(path)
            return self._write_json(404, {"error": "Not found"})

        if path == "/licenses":
            return self._handle_licenses(first("installUuid"))

        if path.startswith("/plugins/"):
            return self._handle_plugin_get(path)

        return self._write_json(404, {"error": "Not found"})

    def _handle_checkout_return(
        self, path: str, parsed: urllib.parse.ParseResult
    ) -> None:
        """Render a simple HTML thank-you / cancelled page after Paddle redirects the
        buyer back to us. Paddle will append ``installUuid`` and ``themeId`` query
        params to whichever URL we passed as ``success_url`` / ``cancel_url``."""
        install_uuid = urllib.parse.parse_qs(parsed.query).get("installUuid", [""])[0]
        theme_id = urllib.parse.parse_qs(parsed.query).get("themeId", [""])[0]
        is_success = path == "/checkout-success"
        title = "Purchase complete" if is_success else "Checkout cancelled"
        body = (
            "Your license will be granted automatically when Paddle finishes "
            "processing the transaction. You can close this tab and return to "
            "PacketSnitch."
            if is_success
            else
            "No charges were made. You can close this tab and try again from "
            "the PacketSnitch Themes subtab."
        )
        html = (
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
            f"<title>{title}</title>"
            "<style>body{font-family:sans-serif;max-width:520px;margin:48px "
            "auto;padding:0 16px;color:#222}h1{font-size:22px}a{color:#3a6df0}"
            "</style></head><body>"
            f"<h1>{title}</h1>"
            f"<p>{body}</p>"
            f"<p>installUuid: <code>{install_uuid}</code></p>"
            f"<p>themeId: <code>{theme_id}</code></p>"
            "</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html.encode("utf-8"))))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _handle_catalog(self, install_uuid: str) -> None:
        themes = self.db.list_themes()
        owned_ids = (
            self.db.list_owned_theme_ids(install_uuid) if install_uuid else []
        )
        # We don't actually track installed state on the server; that is a
        # client-side concept (the renderer knows what is in userData/theme-cache).
        entries = [
            self._catalog_entry(theme, owned_ids, installed_ids=[])
            for theme in themes
        ]
        return self._write_json(200, {"entries": entries})

    def _handle_theme_get(
        self, path: str, install_uuid: str
    ) -> None:
        # /themes/<id>/download or /themes/<id>/preview
        parts = path.split("/")
        # parts: ['', 'themes', '<id>', 'download' | 'preview']
        if len(parts) != 4 or parts[0] != "" or parts[1] != "themes":
            return self._write_json(404, {"error": "Not found"})
        theme_id = parts[2]
        action = parts[3]

        if not THEME_ID_RE.match(theme_id):
            return self._write_json(400, {"error": "Invalid theme id"})

        theme = self.db.get_theme(theme_id)
        if theme is None:
            return self._write_json(404, {"error": "Theme not found"})

        if action == "download":
            return self._handle_theme_download(theme, install_uuid)
        if action == "preview":
            return self._handle_theme_preview(theme)
        return self._write_json(404, {"error": "Not found"})

    def _handle_theme_download(
        self, theme: sqlite3.Row, install_uuid: str
    ) -> None:
        if not install_uuid:
            return self._write_json(
                400,
                {"error": "installUuid query parameter is required for downloads"},
            )
        if not INSTALL_UUID_RE.match(install_uuid):
            return self._write_json(400, {"error": "Invalid installUuid"})

        owned = self.db.get_license(install_uuid, theme["id"])
        if owned is None:
            return self._write_json(
                403,
                {
                    "error": "No license for this installUuid/theme combination",
                    "themeId": theme["id"],
                },
            )

        theme_path = self.config.themes_dir / f"{theme['id']}.json"
        if not theme_path.is_file():
            LOG.error(
                "Theme %s is licensed but the file %s is missing on disk",
                theme["id"],
                theme_path,
            )
            return self._write_json(
                500, {"error": "Theme file missing on server"}
            )

        try:
            body = theme_path.read_bytes()
        except OSError:
            LOG.exception("Failed to read theme file %s", theme_path)
            return self._write_json(500, {"error": "Failed to read theme file"})
        self._write_bytes(
            200,
            body,
            "application/json; charset=utf-8",
            cache_control="private, max-age=60",
        )

    def _handle_theme_preview(self, theme: sqlite3.Row) -> None:
        if theme["preview_filename"]:
            path = self.config.previews_dir / theme["preview_filename"]
            if path.is_file():
                try:
                    body = path.read_bytes()
                except OSError:
                    return self._write_json(
                        500, {"error": "Failed to read preview file"}
                    )
                mime, _ = mimetypes.guess_type(str(path))
                return self._write_bytes(
                    200,
                    body,
                    mime or "image/jpeg",
                    cache_control="public, max-age=3600",
                )
        return self._write_json(404, {"error": "Preview not available"})

    def _handle_preview_file(self, path: str) -> None:
        # path: "/previews/"
        filename = urllib.parse.unquote(path[len("/previews/"):])
        if "/" in filename or ".." in filename:
            return self._write_json(400, {"error": "Invalid preview filename"})
        full = self.config.previews_dir / filename
        try:
            full.relative_to(self.config.previews_dir)
        except ValueError:
            return self._write_json(400, {"error": "Invalid preview filename"})
        if not full.is_file():
            return self._write_json(404, {"error": "Preview not found"})
        try:
            body = full.read_bytes()
        except OSError:
            return self._write_json(500, {"error": "Failed to read preview file"})
        mime, _ = mimetypes.guess_type(str(full))
        return self._write_bytes(
            200,
            body,
            mime or "application/octet-stream",
            cache_control="public, max-age=3600",
        )

    def _handle_checkout_get(self, path: str) -> None:
        # /checkout/<id>?installUuid=<uuid>
        parts = path.split("/")
        if len(parts) != 3 or parts[0] != "" or parts[1] != "checkout":
            return self._write_json(404, {"error": "Not found"})
        theme_id = parts[2]
        if not THEME_ID_RE.match(theme_id):
            return self._write_json(400, {"error": "Invalid theme id"})

        theme = self.db.get_theme(theme_id)
        if theme is None:
            return self._write_json(404, {"error": "Theme not found"})

        # If the operator pre-stored a static checkout URL, just redirect to
        # it. Useful for sandbox testing with a single-use hsc_... token.
        if theme["checkout_url"]:
            return self._write_redirect(theme["checkout_url"])

        # No static URL: create a fresh Paddle Hosted Checkout session per
        # click so each buyer gets a unique token (HSC tokens are one-shot).
        install_uuid = self._query_param("installUuid")
        if not install_uuid:
            return self._write_json(
                400,
                {"error": "installUuid query parameter is required"},
            )
        if not INSTALL_UUID_RE.match(install_uuid):
            return self._write_json(400, {"error": "Invalid installUuid"})

        if not theme["paddle_price_id"]:
            return self._write_json(
                400,
                {
                    "error": (
                        "Theme has no paddlePriceId and no static "
                        "checkoutUrl; cannot start checkout"
                    )
                },
            )
        if not self.config.paddle_api_key:
            return self._write_json(
                503,
                {
                    "error": (
                        "Paddle API key is not configured on the catalog "
                        "server (set --paddle-api-key or "
                        "PS_CATALOG_PADDLE_API_KEY)"
                    )
                },
            )

        try:
            checkout_url = create_paddle_transaction(
                self.config,
                price_id=theme["paddle_price_id"],
                install_uuid=install_uuid,
                theme_id=theme_id,
                success_url=f"{self.config.base_url}/checkout-success?installUuid={install_uuid}&themeId={theme_id}",
                cancel_url=f"{self.config.base_url}/checkout-cancel?installUuid={install_uuid}&themeId={theme_id}",
            )
        except PaddleError as exc:
            LOG.warning(
                "Failed to create Paddle transaction theme=%s installUuid=%s: %s",
                theme_id,
                install_uuid,
                exc,
            )
            return self._write_json(
                502,
                {
                    "error": f"Failed to create checkout session: {exc}",
                    "paddleStatus": exc.status,
                },
            )

        LOG.info(
            "Created Paddle transaction theme=%s installUuid=%s url=%s",
            theme_id,
            install_uuid,
            checkout_url,
        )
        return self._write_redirect(checkout_url)

    def _query_param(self, key: str) -> str:
        """Return the first value of `?key=…` from the current request path."""
        parsed = urllib.parse.urlparse(self.path)
        values = urllib.parse.parse_qs(parsed.query)
        if key not in values or not values[key]:
            return ""
        return values[key][0]

    def _handle_licenses(self, install_uuid: str) -> None:
        if not install_uuid:
            return self._write_json(
                400, {"error": "installUuid query parameter is required"}
            )
        if not INSTALL_UUID_RE.match(install_uuid):
            return self._write_json(400, {"error": "Invalid installUuid"})
        owned = self.db.list_owned_theme_ids(install_uuid)
        return self._write_json(200, {"ownedThemeIds": owned})

    def _handle_plugin_get(self, path: str) -> None:
        # /plugins/<id>/download
        parts = path.split("/")
        if len(parts) != 4 or parts[0] != "" or parts[1] != "plugins":
            return self._write_json(404, {"error": "Not found"})
        # plugins/<id>/download
        return self._write_json(
            501,
            {
                "error": "Plugin downloads are not implemented in this version",
                "pluginId": parts[2],
            },
        )

    # ---- POST handlers ----

    def _dispatch_post(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/paddle/webhook":
            return self._handle_paddle_webhook()

        return self._write_json(404, {"error": "Not found"})

    def _handle_paddle_webhook(self) -> None:
        # Require a configured secret so we never silently grant licenses.
        if not self.config.paddle_webhook_secret:
            return self._write_json(
                503,
                {"error": "Paddle webhook secret is not configured"},
            )

        try:
            raw = self._read_body()
        except ValueError as exc:
            return self._write_json(413, {"error": str(exc)})

        # Paddle signs each webhook with HMAC-SHA256 keyed by the webhook secret.
        # The signature is sent in the Paddle-Signature header as a base64
        # blob. We verify the signature before trusting the payload.
        signature_header = self.headers.get("Paddle-Signature", "")
        timestamp = ""
        signature_b64 = ""
        for part in signature_header.split(";"):
            part = part.strip()
            if part.startswith("ts="):
                timestamp = part[3:]
            elif part.startswith("h1="):
                signature_b64 = part[3:]

        if not timestamp or not signature_b64:
            return self._write_json(
                401, {"error": "Missing Paddle-Signature header parts"}
            )

        signed_payload = f"{timestamp}:{raw.decode('utf-8', errors='replace')}".encode(
            "utf-8"
        )
        expected_sig = hmac.new(
            self.config.paddle_webhook_secret.encode("utf-8"),
            signed_payload,
            hashlib.sha256,
        ).digest()
        try:
            import base64

            provided_sig = base64.b64decode(signature_b64, validate=True)
        except Exception:
            return self._write_json(401, {"error": "Malformed signature"})

        if not hmac.compare_digest(expected_sig, provided_sig):
            LOG.warning(
                "Paddle webhook signature mismatch from %s", self.address_string()
            )
            return self._write_json(401, {"error": "Invalid signature"})

        try:
            event = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return self._write_json(400, {"error": "Body is not valid JSON"})

        event_type = event.get("event_type") or event.get("type") or ""
        data = event.get("data") or {}
        if not isinstance(data, dict):
            data = {}

        # Extract installUuid from the custom_data field (we expect the
        # client to pass it through when initiating checkout via
        # `passthrough`/`custom_data`). Fall back to the customer email
        # hash if present.
        custom = data.get("custom_data") or data.get("passthrough") or {}
        if isinstance(custom, str):
            try:
                custom = json.loads(custom)
            except json.JSONDecodeError:
                custom = {}
        install_uuid = (
            custom.get("installUuid")
            or custom.get("install_uuid")
            or ""
        )
        theme_id = (
            custom.get("themeId")
            or custom.get("theme_id")
            or ""
        )

        # If installUuid wasn't passed explicitly, try to find it on items[].
        if not install_uuid:
            for item in data.get("items", []) or []:
                if not isinstance(item, dict):
                    continue
                item_custom = item.get("custom_data") or item.get("passthrough") or {}
                if isinstance(item_custom, str):
                    try:
                        item_custom = json.loads(item_custom)
                    except json.JSONDecodeError:
                        item_custom = {}
                if isinstance(item_custom, dict):
                    if not install_uuid and (
                        item_custom.get("installUuid")
                        or item_custom.get("install_uuid")
                    ):
                        install_uuid = (
                            item_custom.get("installUuid")
                            or item_custom.get("install_uuid")
                        )
                    if not theme_id and (
                        item_custom.get("themeId")
                        or item_custom.get("theme_id")
                    ):
                        theme_id = (
                            item_custom.get("themeId")
                            or item_custom.get("theme_id")
                        )

        if not install_uuid or not INSTALL_UUID_RE.match(install_uuid):
            return self._write_json(
                400,
                {
                    "error": "Webhook missing valid installUuid in custom_data",
                    "eventType": event_type,
                },
            )

        # If no themeId was set, fall back to the item's product id mapped via
        # the themes table.
        if not theme_id:
            for item in data.get("items", []) or []:
                if not isinstance(item, dict):
                    continue
                product_id = item.get("product_id") or item.get("price_id") or ""
                if product_id:
                    row = self._find_theme_by_paddle_id(product_id)
                    if row:
                        theme_id = row["id"]
                        break

        if not theme_id or not THEME_ID_RE.match(theme_id):
            return self._write_json(
                400,
                {
                    "error": "Webhook missing valid themeId in custom_data",
                    "eventType": event_type,
                },
            )

        subscription_id = (
            data.get("subscription_id")
            or data.get("id")
            or ""
        )
        customer_id = (
            data.get("customer_id")
            or (data.get("customer") or {}).get("id")
            or ""
        )

        if event_type in PADDLE_GRANTING_EVENT_TYPES:
            self.db.grant_license(
                install_uuid=install_uuid,
                theme_id=theme_id,
                paddle_subscription_id=str(subscription_id),
                paddle_customer_id=str(customer_id),
            )
            LOG.info(
                "Granted license installUuid=%s themeId=%s via %s",
                install_uuid,
                theme_id,
                event_type,
            )
            return self._write_json(
                200,
                {"ok": True, "granted": True, "themeId": theme_id},
            )

        if event_type in PADDLE_REVOKING_EVENT_TYPES:
            self.db.revoke_license(install_uuid, theme_id)
            LOG.info(
                "Revoked license installUuid=%s themeId=%s via %s",
                install_uuid,
                theme_id,
                event_type,
            )
            return self._write_json(
                200,
                {"ok": True, "revoked": True, "themeId": theme_id},
            )

        # Acknowledge unknown event types so Paddle doesn't retry forever,
        # but don't change license state.
        return self._write_json(
            200,
            {"ok": True, "ignored": True, "eventType": event_type},
        )

    def _find_theme_by_paddle_id(self, paddle_id: str) -> Optional[sqlite3.Row]:
        for theme in self.db.list_themes():
            if (
                theme["paddle_price_id"] == paddle_id
                or theme["paddle_product_id"] == paddle_id
            ):
                return theme
        return None


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------


def make_server(config: Config, db: CatalogDB) -> ThreadingHTTPServer:
    CatalogHandler.config = config
    CatalogHandler.db = db
    server = ThreadingHTTPServer((config.host, config.port), CatalogHandler)
    if config.use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # We deliberately don't enable CERT_REQUIRED here — the catalog
        # server is a public endpoint, not a Paddle-controlled client. Set
        # PS_CATALOG_TLS_CERT/PS_CATALOG_TLS_KEY to paths of PEM files.
        try:
            ctx.load_cert_chain(
                certfile=str(config.tls_cert),
                keyfile=str(config.tls_key),
            )
        except (ssl.SSLError, FileNotFoundError, OSError) as exc:
            raise SystemExit(
                f"Failed to load TLS certificate: {exc}"
            ) from exc
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace, config: Config) -> int:
    db = CatalogDB(config.db_path)
    LOG.info("Initialized catalog db at %s", config.db_path)
    db.close()
    return 0


def cmd_add_theme(args: argparse.Namespace, config: Config) -> int:
    db = CatalogDB(config.db_path)
    theme_path = Path(args.theme_path).resolve()
    if not theme_path.is_file():
        LOG.error("Theme file not found: %s", theme_path)
        return 2
    try:
        raw = json.loads(theme_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        LOG.error("Failed to read/parse %s: %s", theme_path, exc)
        return 2

    theme_id = str(
        raw.get("id") or theme_path.stem
    ).strip()
    if not THEME_ID_RE.match(theme_id):
        LOG.error("Invalid theme id %r (must match %s)", theme_id, THEME_ID_RE.pattern)
        return 2

    # If the theme file isn't under themes_dir, copy it there so /download
    # can serve it directly.
    target = config.themes_dir / f"{theme_id}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    if theme_path != target:
        shutil.copyfile(theme_path, target)

    name = str(raw.get("name") or theme_id)
    description = str(raw.get("description") or "")
    preview_image = raw.get("previewImage")
    if isinstance(preview_image, dict):
        # Stored compactly: only keep data + mime; everything else is dropped.
        preview_image = json.dumps(preview_image, separators=(",", ":"))
    elif preview_image is None:
        preview_image = ""
    else:
        preview_image = str(preview_image)

    paddle = raw.get("paddle") or {}
    paddle_product_id = str(
        args.paddle_product_id
        if getattr(args, "paddle_product_id", None)
        else paddle.get("productId") or ""
    )
    paddle_price_id = str(
        args.paddle_price_id
        if getattr(args, "paddle_price_id", None)
        else paddle.get("priceId") or ""
    )
    checkout_url = str(
        args.checkout_url
        if getattr(args, "checkout_url", None)
        else raw.get("checkoutUrl") or ""
    )

    db.upsert_theme(
        theme_id=theme_id,
        name=name,
        description=description,
        price_cents=_safe_int(raw.get("priceCents")),
        price_label=str(raw.get("priceLabel") or ""),
        paddle_product_id=paddle_product_id,
        paddle_price_id=paddle_price_id,
        preview_image=preview_image,
        preview_filename=str(args.preview_filename or ""),
        checkout_url=checkout_url,
        license_url=str(raw.get("licenseUrl") or ""),
    )
    LOG.info(
        "Registered theme %s (file=%s, paddle_product=%s, paddle_price=%s, checkout=%s)",
        theme_id,
        target,
        paddle_product_id or "-",
        paddle_price_id or "-",
        checkout_url or "(auto)",
    )
    db.close()
    return 0


def cmd_remove_theme(args: argparse.Namespace, config: Config) -> int:
    """Unregister a theme and clean up its on-disk artifacts.

    By default this only removes the database row + theme JSON under
    themes_dir, leaving any already-granted licenses intact so buyers
    aren't silently de-licensed. Pass --purge-licenses to also drop every
    license row that references the theme (use this when you are sure you
    want to invalidate every existing customer's access).

    The matching preview image under previews_dir is removed only when
    --remove-preview is passed, because the same file might be referenced
    by other themes.
    """
    theme_id = str(args.theme_id or "").strip()
    if not THEME_ID_RE.match(theme_id):
        LOG.error("Invalid theme id %r (must match %s)", theme_id, THEME_ID_RE.pattern)
        return 2

    purge_licenses = bool(getattr(args, "purge_licenses", False))
    remove_preview = bool(getattr(args, "remove_preview", False))
    dry_run = bool(getattr(args, "dry_run", False))

    db = CatalogDB(config.db_path)
    try:
        theme = db.get_theme(theme_id)
        if theme is None:
            LOG.error("Theme %s is not registered", theme_id)
            return 2

        owned_count = db.count_active_licenses_for_theme(theme_id)
        theme_path = config.themes_dir / f"{theme_id}.json"
        preview_filename = theme["preview_filename"]
        preview_path = (
            config.previews_dir / preview_filename
            if preview_filename
            else None
        )

        LOG.info(
            "remove-theme theme=%s file=%s purge_licenses=%s remove_preview=%s owned_licenses=%d",
            theme_id,
            theme_path,
            purge_licenses,
            remove_preview,
            owned_count,
        )

        if dry_run:
            LOG.info("--dry-run: not making changes")
            return 0

        removed_licenses = 0
        if purge_licenses:
            removed_licenses = db.delete_theme_cascade(theme_id)
        else:
            db.delete_theme(theme_id)

        removed_file = False
        try:
            if theme_path.is_file():
                theme_path.unlink()
                removed_file = True
        except OSError as exc:
            LOG.warning("Failed to remove theme file %s: %s", theme_path, exc)

        removed_preview = False
        if remove_preview and preview_path is not None:
            try:
                if preview_path.is_file():
                    preview_path.unlink()
                    removed_preview = True
            except OSError as exc:
                LOG.warning("Failed to remove preview %s: %s", preview_path, exc)

        LOG.info(
            "Removed theme %s (db row deleted, licenses_removed=%d, file_removed=%s, preview_removed=%s)",
            theme_id,
            removed_licenses,
            removed_file,
            removed_preview,
        )
        return 0
    finally:
        db.close()


def cmd_add_preview(args: argparse.Namespace, config: Config) -> int:
    src = Path(args.preview_path).resolve()
    if not src.is_file():
        LOG.error("Preview file not found: %s", src)
        return 2
    target = config.previews_dir / src.name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, target)
    LOG.info("Copied preview %s -> %s", src, target)
    return 0


def cmd_add_license(args: argparse.Namespace, config: Config) -> int:
    db = CatalogDB(config.db_path)
    install_uuid = args.install_uuid
    theme_id = args.theme_id
    if not INSTALL_UUID_RE.match(install_uuid):
        LOG.error("Invalid installUuid %r", install_uuid)
        return 2
    if not THEME_ID_RE.match(theme_id):
        LOG.error("Invalid theme id %r", theme_id)
        return 2
    if db.get_theme(theme_id) is None:
        LOG.error("Theme %s is not registered. Run --add-theme first.", theme_id)
        return 2
    db.grant_license(
        install_uuid=install_uuid,
        theme_id=theme_id,
        paddle_subscription_id=args.subscription or "",
    )
    LOG.info("Granted license installUuid=%s themeId=%s", install_uuid, theme_id)
    db.close()
    return 0


def cmd_list_themes(args: argparse.Namespace, config: Config) -> int:
    db = CatalogDB(config.db_path)
    try:
        for theme in db.list_themes():
            with db._lock:
                owned_count = db.conn.execute(
                    "SELECT COUNT(*) AS c FROM licenses WHERE theme_id = ? AND revoked_at IS NULL",
                    (theme["id"],),
                ).fetchone()["c"]
            print(
                f"{theme['id']:30s}  ${(theme['price_cents'] or 0)/100:.2f}  "
                f"licenses={owned_count}"
            )
    finally:
        db.close()
    return 0


def cmd_serve(args: argparse.Namespace, config: Config) -> int:
    db = CatalogDB(config.db_path)
    server = make_server(config, db)
    LOG.info(
        "ps-catalog listening on %s://%s:%d (db=%s, themes=%s, previews=%s, paddle_env=%s)",
        config.scheme,
        config.host,
        config.port,
        config.db_path,
        config.themes_dir,
        config.previews_dir,
        config.paddle_env,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Shutting down")
    finally:
        server.server_close()
        db.close()
    return 0


def _safe_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ps-catalog",
        description=(
            "PacketSnitch theme catalog server. See module docstring for "
            "endpoint and CLI usage."
        ),
    )
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--db", default=None)
    parser.add_argument("--themes-dir", default=None)
    parser.add_argument("--previews-dir", default=None)
    parser.add_argument("--paddle-webhook-secret", default=None)
    parser.add_argument("--paddle-public-key", default=None)
    parser.add_argument(
        "--paddle-api-key",
        default=None,
        help=(
            "Paddle API key used to create hosted-checkout sessions per click. "
            "Env: PS_CATALOG_PADDLE_API_KEY. Without this, dynamic checkout is "
            "disabled and only themes with a pre-stored checkoutUrl will work."
        ),
    )
    parser.add_argument(
        "--paddle-env",
        choices=("live", "sandbox"),
        default=None,
        help=(
            "Which Paddle environment to talk to. 'sandbox' uses "
            "sandbox-api.paddle.com + sandbox-pay.paddle.io; 'live' uses "
            "api.paddle.com + pay.paddle.com. Env: PS_CATALOG_PADDLE_ENV."
        ),
    )
    parser.add_argument(
        "--tls-cert",
        default=None,
        help=(
            "Path to a PEM-encoded TLS certificate. When provided with "
            "--tls-key, the server speaks HTTPS instead of HTTP. "
            "Env: PS_CATALOG_TLS_CERT."
        ),
    )
    parser.add_argument(
        "--tls-key",
        default=None,
        help=(
            "Path to a PEM-encoded TLS private key. Required together with "
            "--tls-cert. Env: PS_CATALOG_TLS_KEY."
        ),
    )
    parser.add_argument(
        "--success-url",
        default=None,
        help=(
            "Override the success_url passed to Paddle transactions. "
            "Env: PS_CATALOG_SUCCESS_URL."
        ),
    )
    parser.add_argument(
        "--cancel-url",
        default=None,
        help=(
            "Override the cancel_url passed to Paddle transactions. "
            "Env: PS_CATALOG_CANCEL_URL."
        ),
    )
    parser.add_argument(
        "--allow-insecure-return-urls",
        action="store_true",
        default=None,
        help=(
            "Permit http:// (not just https://) in Paddle success_url / "
            "cancel_url. Default: enabled in sandbox, disabled in live. "
            "Env: PS_CATALOG_ALLOW_INSECURE_RETURN_URLS=1|0."
        ),
    )
    parser.add_argument("--base-url", default=None)
    parser.add_argument(
        "--log-level",
        default=os.environ.get("PS_CATALOG_LOG_LEVEL", "INFO"),
        help="Python logging level (default INFO)",
    )

    sub = parser.add_subparsers(dest="command", required=False)

    p_init = sub.add_parser("init", help="Create the sqlite database file")
    p_init.set_defaults(func=cmd_init)

    p_serve = sub.add_parser("serve", help="Run the HTTP server")
    p_serve.set_defaults(func=cmd_serve)

    p_add_theme = sub.add_parser("add-theme", help="Register a theme JSON file")
    p_add_theme.add_argument("theme_path")
    p_add_theme.add_argument(
        "--preview-filename",
        default=None,
        help="Optional preview filename in the previews dir",
    )
    p_add_theme.add_argument(
        "--paddle-product-id",
        dest="paddle_product_id",
        default=None,
        help="Paddle product ID (e.g. pro_01hxxx). Overrides JSON's paddle.productId.",
    )
    p_add_theme.add_argument(
        "--paddle-price-id",
        dest="paddle_price_id",
        default=None,
        help="Paddle price ID (e.g. pri_01hxxx). Overrides JSON's paddle.priceId.",
    )
    p_add_theme.add_argument(
        "--checkout-url",
        dest="checkout_url",
        default=None,
        help="Pre-built Paddle checkout URL to redirect buyers to.",
    )
    p_add_theme.set_defaults(func=cmd_add_theme)

    p_remove_theme = sub.add_parser(
        "remove-theme",
        help="Unregister a theme and (optionally) revoke its licenses / preview",
    )
    p_remove_theme.add_argument("theme_id")
    p_remove_theme.add_argument(
        "--purge-licenses",
        action="store_true",
        help=(
            "Also delete every license row referencing this theme. "
            "Without this flag, existing buyers keep their access."
        ),
    )
    p_remove_theme.add_argument(
        "--remove-preview",
        action="store_true",
        help="Also delete the preview image file referenced by the theme row.",
    )
    p_remove_theme.add_argument(
        "--dry-run",
        action="store_true",
        help="Log what would happen without making any changes.",
    )
    p_remove_theme.set_defaults(func=cmd_remove_theme)

    p_add_preview = sub.add_parser(
        "add-preview", help="Copy a preview image into the previews dir"
    )
    p_add_preview.add_argument("preview_path")
    p_add_preview.add_argument("theme_id")
    p_add_preview.set_defaults(func=cmd_add_preview)

    p_add_license = sub.add_parser(
        "add-license", help="Manually grant a license (for dev/testing)"
    )
    p_add_license.add_argument("install_uuid")
    p_add_license.add_argument("theme_id")
    p_add_license.add_argument("--subscription", default=None)
    p_add_license.set_defaults(func=cmd_add_license)

    p_list = sub.add_parser("list-themes", help="List all registered themes")
    p_list.set_defaults(func=cmd_list_themes)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = Config.from_env_and_args(args)
    func = getattr(args, "func", None)
    if func is None:
        # Default to serve for convenience.
        return cmd_serve(args, config)
    return func(args, config)


if __name__ == "__main__":
    sys.exit(main())
