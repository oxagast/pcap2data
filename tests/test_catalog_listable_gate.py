"""Tests for the ``/catalog`` listable gate.

The catalog endpoint (``GET /catalog``) builds a list of
"purchasable" themes by joining Paddle's product list with the
local ``themes`` table. To prevent the desktop storefront from
showing broken cards, every entry must pass the
``_is_theme_listable`` gate before being advertised — the four
required pieces are:

  1. ``theme_json`` — non-empty (so the install button has
     something to download).
  2. ``paddle_product_id`` — non-empty (so the row is linked to
     a real Paddle product).
  3. ``paddle_price_id`` — non-empty (so the hosted-checkout URL
     is valid).
  4. A usable preview — either an embedded data URI in
     ``preview_image`` or ``preview_filename`` pointing at a real
     file under ``previews_dir``.

The tests cover:

  * Direct exercise of the ``_is_theme_listable`` helper for each
    missing-field permutation. ``theme_json`` / Paddle ids are
    easy to test in isolation; the preview branch needs a real
    ``previews_dir`` on disk so the ``is_file()`` probe can run.
  * End-to-end exercise through ``CatalogHandler._handle_catalog``
    so we know a half-configured Paddle product is silently
    dropped from the catalog payload and a fully-configured one
    survives.

We don't mock the network: ``_paddle_fetch_products_with_prices``
is monkey-patched to a stub that returns a controlled product
list so the test runs without an API key.
"""

import importlib.util
import json
import sys
import uuid
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Module loading — same pattern as tests/test_catalog_paddle_poller.py
# ---------------------------------------------------------------------------


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
        "ps_catalog_listable_test_module", _catalog_script()
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load ps-catalog.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ps_catalog_listable_test_module"] = module
    spec.loader.exec_module(module)
    return module


_catalog = _load_catalog_module()


def _make_config(
    *, db_path: Path, themes_dir: Path, previews_dir: Path
) -> "_catalog.Config":
    """Minimal ``Config`` — only the fields the gate and the
    handler read are populated; the rest are placeholders so
    the dataclass constructor accepts the call."""
    return _catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=previews_dir,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key="test_paddle_key",
        paddle_env="sandbox",
        base_url="http://127.0.0.1:0",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        setup_token="test_token",
        admin_api_key="test_admin_key",
        log_dir=db_path.parent,
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
        metrics_log_path="",
        nginx_log_path="",
        nginx_err_log_path="",
    )


@pytest.fixture
def env(tmp_path):
    """Yield a (db, config) pair backed by fresh sqlite / themes /
    previews directories under ``tmp_path``. The directories are
    pre-created so the test doesn't have to remember that the
    Config dataclass doesn't ``mkdir`` on its own."""
    db_path = tmp_path / f"catalog-{uuid.uuid4().hex}.sqlite3"
    themes_dir = tmp_path / "themes"
    previews_dir = tmp_path / "previews"
    themes_dir.mkdir()
    previews_dir.mkdir()
    config = _make_config(
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=previews_dir,
    )
    db = _catalog.CatalogDB(db_path)
    try:
        yield db, config
    finally:
        db.close()


def _fully_loaded_theme(**overrides) -> dict:
    """Build a kwargs dict for ``upsert_theme`` that satisfies the
    listable gate. Tests use it as the baseline and then drop one
    field at a time to exercise the missing-field branches."""
    defaults = dict(
        theme_id="matrix",
        name="Matrix Theme",
        description="",
        price_cents=1999,
        price_label="$19.99/month",
        paddle_product_id="pro_01ABC",
        paddle_price_id="pri_01XYZ",
        preview_image="data:image/png;base64,iVBORw0KGgo=",
        preview_filename="",
        checkout_url="https://pay.paddle.com/hsc_test?price_id=pri_01XYZ",
        hosted_checkout_url="https://pay.paddle.com/hsc_test?price_id=pri_01XYZ",
        license_url="",
        theme_json='{"id":"matrix","name":"Matrix Theme"}',
    )
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# _is_theme_listable — direct helper tests
# ---------------------------------------------------------------------------


def test_is_theme_listable_passes_when_all_required_fields_present(env):
    """A theme with theme_json, both Paddle ids, and a preview
    data URI must pass the gate."""
    db, config = env
    db.upsert_theme(**_fully_loaded_theme())
    theme = db.get_theme("matrix")
    ok, reason = _catalog._is_theme_listable(theme, config.previews_dir)
    assert ok is True, f"expected listable, got skip reason {reason!r}"
    assert reason == ""


def test_is_theme_listable_rejects_missing_theme_row(env):
    """``None`` (no local row at all) is rejected with the
    explicit 'no local theme row' reason so the operator's
    first action is ``add-theme`` rather than editing a
    partial row."""
    _db, config = env
    ok, reason = _catalog._is_theme_listable(None, config.previews_dir)
    assert ok is False
    assert reason == "no local theme row"


def test_is_theme_listable_rejects_empty_theme_json(env):
    """A theme row with empty ``theme_json`` (the desktop has
    nothing to install) is rejected."""
    db, config = env
    db.upsert_theme(**_fully_loaded_theme(theme_json=""))
    theme = db.get_theme("matrix")
    ok, reason = _catalog._is_theme_listable(theme, config.previews_dir)
    assert ok is False
    assert reason == "missing theme_json"


def test_is_theme_listable_rejects_whitespace_only_theme_json(env):
    """Whitespace-only ``theme_json`` is treated the same as an
    empty string — the desktop would still 404 the install
    button because the response body would be a blank JSON
    document."""
    db, config = env
    db.upsert_theme(**_fully_loaded_theme(theme_json="   \n  "))
    theme = db.get_theme("matrix")
    ok, reason = _catalog._is_theme_listable(theme, config.previews_dir)
    assert ok is False
    assert reason == "missing theme_json"


def test_is_theme_listable_rejects_missing_paddle_product_id(env):
    """A theme with no ``paddle_product_id`` is rejected so the
    poller can never correlate the row with the Paddle
    product — and the ``/checkout`` redirect would not know
    where to send the buyer."""
    db, config = env
    db.upsert_theme(**_fully_loaded_theme(paddle_product_id=""))
    theme = db.get_theme("matrix")
    ok, reason = _catalog._is_theme_listable(theme, config.previews_dir)
    assert ok is False
    assert reason == "missing paddle_product_id"


def test_is_theme_listable_rejects_missing_paddle_price_id(env):
    """Symmetric to ``paddle_product_id``: an empty price id
    produces a hosted-checkout URL Paddle will reject."""
    db, config = env
    db.upsert_theme(**_fully_loaded_theme(paddle_price_id=""))
    theme = db.get_theme("matrix")
    ok, reason = _catalog._is_theme_listable(theme, config.previews_dir)
    assert ok is False
    assert reason == "missing paddle_price_id"


def test_is_theme_listable_rejects_no_preview_at_all(env):
    """A theme with neither embedded image nor preview file is
    rejected. The storefront card would render with no
    thumbnail."""
    db, config = env
    db.upsert_theme(**_fully_loaded_theme(
        preview_image="", preview_filename=""
    ))
    theme = db.get_theme("matrix")
    ok, reason = _catalog._is_theme_listable(theme, config.previews_dir)
    assert ok is False
    assert reason == "missing preview"


def test_is_theme_listable_rejects_missing_preview_file(env):
    """A theme that names a ``preview_filename`` whose file has
    been deleted (a real data-integrity scenario) is
    rejected — same outcome as no preview, but for a
    different reason that surfaces in the operator's log."""
    db, config = env
    db.upsert_theme(**_fully_loaded_theme(
        preview_image="",
        preview_filename="does-not-exist.jpg",
    ))
    theme = db.get_theme("matrix")
    ok, reason = _catalog._is_theme_listable(theme, config.previews_dir)
    assert ok is False
    assert reason == "missing preview"


def test_is_theme_listable_accepts_real_preview_file(env):
    """A theme with a real preview file on disk under
    ``previews_dir`` passes the gate even when
    ``preview_image`` is empty. The file branch is the
    canonical ``add-preview`` + ``add-theme`` upload path."""
    db, config = env
    preview_path = config.previews_dir / "matrix.jpg"
    preview_path.write_bytes(b"\xff\xd8\xff\xe0fake-jpeg")
    db.upsert_theme(**_fully_loaded_theme(
        preview_image="",
        preview_filename="matrix.jpg",
    ))
    theme = db.get_theme("matrix")
    ok, reason = _catalog._is_theme_listable(theme, config.previews_dir)
    assert ok is True, f"expected listable, got skip reason {reason!r}"
    assert reason == ""


# ---------------------------------------------------------------------------
# _handle_catalog — end-to-end gate through the HTTP handler
# ---------------------------------------------------------------------------


class _StubHandler:
    """Stand-in for ``CatalogHandler`` that exposes the methods
    the gate actually calls. We don't need a real socket pair
    because the gate touches only ``self.db`` / ``self.config``;
    by binding those attributes on a lightweight object we get
    near-handler coverage without the ceremony of ``HTTPServer``
    + thread + ``http.client`` round-trip.

    The real ``CatalogHandler.do_GET`` dispatches ``/catalog``
    to ``self._handle_catalog(install_uuid)`` so we replicate
    that call shape. Calling the unbound
    ``CatalogHandler._handle_catalog`` against ``self`` works
    because Python's attribute lookup finds
    ``_paddle_fetch_products_with_prices`` on the stub instance
    before falling through to the class, and
    ``_write_envelope_json`` on the stub records the payload
    instead of writing to a socket.
    """

    def __init__(self, db, config, products):
        self.db = db
        self.config = config
        self._stub_products = products
        # Pre-populate the response capture. ``_handle_catalog``
        # calls ``self._write_envelope_json(status, payload)``
        # which on the real handler emits JSON over the wire.
        self.response = {"status": None, "payload": None}

    def _write_envelope_json(self, status, payload):
        self.response["status"] = status
        self.response["payload"] = payload

    def _paddle_fetch_products_with_prices(self):
        """Return a controlled product list instead of calling
        Paddle. The shape mirrors what
        ``_paddle_fetch_products_with_prices_impl`` produces so
        the handler code under test sees the same input it
        would in production."""
        return self._stub_products


def _invoke_catalog_handler(db, config, products):
    """Run ``_handle_catalog`` against a stubbed handler and
    return the JSON payload that would have been written to
    the wire. Python's attribute lookup finds
    ``_paddle_fetch_products_with_prices`` on the stub instance
    before falling through to ``CatalogHandler``, so the unbound
    method call below sees the controlled product list without
    any monkey-patching."""
    handler = _StubHandler(db, config, products)
    _catalog.CatalogHandler._handle_catalog(handler, "")
    return handler.response["payload"]


def _sample_product(
    *,
    product_id: str = "pro_01ABC",
    price_id: str = "pri_01XYZ",
    theme_id: str = "matrix",
    product_name: str = "Matrix Theme",
    amount: str = "1999",
    hosted_checkout: str = "https://pay.paddle.com/hsc_test?price_id=pri_01XYZ",
) -> dict:
    """A minimal Paddle-shaped product dict; only the fields
    ``_handle_catalog`` actually reads are populated."""
    return {
        "product_id": product_id,
        "price_id": price_id,
        "product_name": product_name,
        "theme_id": theme_id,
        "type": "theme",
        "amount": amount,
        "currency": "USD",
        "billing_cycle": {"interval": "month"},
        "hosted_checkout": hosted_checkout,
    }


def test_handle_catalog_drops_theme_missing_theme_json(env):
    """A Paddle product whose local row has empty theme_json
    must NOT appear in the catalog payload — the gate runs
    before the entry is appended."""
    db, config = env
    db.upsert_theme(**_fully_loaded_theme(theme_json=""))
    payload = _invoke_catalog_handler(
        db, config, [_sample_product()]
    )
    assert payload is not None
    assert payload["entries"] == [], (
        "expected empty entries when only theme has no theme_json"
    )


def test_handle_catalog_drops_theme_missing_paddle_ids(env):
    """A theme with Paddle ids missing is dropped from the
    catalog. ``_handle_catalog`` matches the Paddle product
    by ``theme_id`` (which defaults to ``product_id``) so the
    local row exists but its ``paddle_product_id`` /
    ``paddle_price_id`` are blank."""
    db, config = env
    db.upsert_theme(**_fully_loaded_theme(
        paddle_product_id="",
        paddle_price_id="",
    ))
    payload = _invoke_catalog_handler(
        db, config, [_sample_product()]
    )
    assert payload["entries"] == []


def test_handle_catalog_drops_theme_with_no_preview(env):
    """A theme with no usable preview is dropped from the
    catalog."""
    db, config = env
    db.upsert_theme(**_fully_loaded_theme(
        preview_image="",
        preview_filename="",
    ))
    payload = _invoke_catalog_handler(
        db, config, [_sample_product()]
    )
    assert payload["entries"] == []


def test_handle_catalog_drops_theme_with_no_local_row(env):
    """A Paddle product with no corresponding local row at
    all is dropped from the catalog. This is the common
    "Paddle product arrived but operator hasn't run add-theme"
    state — better to show nothing than a half-configured
    card."""
    _db, config = env
    # Don't insert anything into the DB — only the Paddle
    # stub product exists.
    payload = _invoke_catalog_handler(
        _db, config, [_sample_product()]
    )
    assert payload["entries"] == []


def test_handle_catalog_includes_fully_configured_theme(env):
    """A Paddle product whose local row passes the gate is
    included in the catalog payload. This is the
    happy-path control: if the gate is too strict and
    rejects everything, this test catches it."""
    db, config = env
    db.upsert_theme(**_fully_loaded_theme())
    payload = _invoke_catalog_handler(
        db, config, [_sample_product()]
    )
    entries = payload["entries"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["id"] == "matrix"
    assert entry["name"] == "Matrix Theme"
    assert entry["priceCents"] == 1999
    # The embedded preview data URI is preserved.
    assert entry["previewImage"].startswith("data:image/png;base64,")


def test_handle_catalog_partitions_listable_from_unlistable(env):
    """When the Paddle product list mixes listable and
    unlistable themes, only the listable ones appear in
    the payload. This is the multi-entry smoke test that
    proves the ``continue`` branch in the handler loop
    actually advances to the next product rather than
    short-circuiting the whole response."""
    db, config = env
    # Theme A: fully configured → included.
    db.upsert_theme(**_fully_loaded_theme(theme_id="alpha"))
    # Theme B: missing paddle_product_id → dropped.
    db.upsert_theme(**_fully_loaded_theme(
        theme_id="bravo",
        paddle_product_id="",
    ))
    # Theme C: missing theme_json → dropped.
    db.upsert_theme(**_fully_loaded_theme(
        theme_id="charlie",
        theme_json="",
    ))
    # Theme D: no preview → dropped.
    db.upsert_theme(**_fully_loaded_theme(
        theme_id="delta",
        preview_image="",
        preview_filename="",
    ))
    products = [
        _sample_product(theme_id="alpha", product_name="Alpha"),
        _sample_product(
            product_id="pro_02", price_id="pri_02",
            theme_id="bravo", product_name="Bravo",
        ),
        _sample_product(
            product_id="pro_03", price_id="pri_03",
            theme_id="charlie", product_name="Charlie",
        ),
        _sample_product(
            product_id="pro_04", price_id="pri_04",
            theme_id="delta", product_name="Delta",
        ),
    ]
    payload = _invoke_catalog_handler(db, config, products)
    ids = [entry["id"] for entry in payload["entries"]]
    assert ids == ["alpha"], (
        f"expected only 'alpha' to be listable, got {ids!r}"
    )