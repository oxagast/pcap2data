"""Tests for the Paddle catalog poller.

The poller reconciles the ``themes`` table with the latest Paddle
product / price list. The contract under test:

  1. Paddle-derived columns (``name``, ``description``,
     ``price_cents``, ``price_label``, ``paddle_product_id``,
     ``paddle_price_id``, ``checkout_url``, ``hosted_checkout_url``)
     are updated from the Paddle response.
  2. Operator-owned columns (``preview_image`` data URI,
     ``preview_filename``, ``theme_json``, ``license_url``) are
     preserved verbatim across a poller pass. This is the
     "don't clobber a buyer's installed theme on a Paddle
     product rename" guarantee.
  3. A new Paddle product with no matching themes row creates
     a row carrying the Paddle-derived fields, but with empty
     operator-owned columns — the operator still has to run
     ``add-theme`` or ``POST /admin/themes`` to attach the
     theme.json + preview.
  4. Running the refresh twice with the same input is a no-op
     on the second pass (``updated == 0``); the helper is
     idempotent.
  5. ``_run_paddle_poll_once`` returns a clean summary dict
     and never raises on a Paddle error (the background thread
     uses this to keep running).

We don't test the actual HTTP fetch against Paddle (the
``_paddle_fetch_products_with_prices_impl`` is well covered by
the existing ``/catalog`` tests). Instead we feed
``CatalogDB.refresh_themes_from_paddle`` a fake Paddle product
list directly so the test runs without network and without
mocking the Paddle SDK."""

import importlib.util
import sys
import uuid
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Module loading — same pattern as tests/test_catalog_tiers.py
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
        "ps_catalog_poller_test_module", _catalog_script()
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load ps-catalog.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ps_catalog_poller_test_module"] = module
    spec.loader.exec_module(module)
    return module


_catalog = _load_catalog_module()


def _fresh_db(tmp_path: Path):
    """Return a ``CatalogDB`` backed by a fresh sqlite file under
    ``tmp_path``. The CatalogDB constructor takes a ``Path``, not
    a string — it runs a writable-preflight that uses Path methods
    (``path.exists()``, ``path.stat()``) which a bare ``str`` doesn't
    expose. We hand it the full Path so the test db is created
    inside ``tmp_path`` and cleaned up automatically."""
    db_path = tmp_path / f"catalog-{uuid.uuid4().hex}.sqlite3"
    return _catalog.CatalogDB(db_path), db_path


def _sample_paddle_product(
    *,
    product_id: str = "pro_01",
    price_id: str = "pri_01",
    name: str = "Matrix Theme",
    amount: str = "1999",
    interval: str = "month",
    theme_id: str = "matrix",
    hosted_checkout: str = "https://pay.paddle.com/hsc_test?price_id=pri_01",
) -> dict:
    """Build a fake Paddle product dict shaped like the output of
    ``_paddle_fetch_products_with_prices_impl``. We only fill the
    fields the poller actually reads; everything else defaults to
    sensible Paddle-shaped blanks so a future schema addition
    doesn't break this test."""
    return {
        "product_id": product_id,
        "product_name": name,
        "theme_id": theme_id,
        "type": "theme",
        "price_id": price_id,
        "price_name": "Default",
        "amount": amount,
        "currency": "USD",
        "billing_cycle": {"interval": interval, "frequency": 1},
        "hosted_checkout": hosted_checkout,
    }


@pytest.fixture
def db(tmp_path):
    handle, _path = _fresh_db(tmp_path)
    try:
        yield handle
    finally:
        handle.close()


# ---------------------------------------------------------------------------
# Refresh: Paddle update path
# ---------------------------------------------------------------------------


def test_refresh_updates_paddle_columns_preserves_operator_columns(db):
    """An existing themes row must have its Paddle-derived columns
    updated by a poller pass while the operator-owned columns
    (preview_image / preview_filename / theme_json / license_url)
    are preserved verbatim."""
    db.upsert_theme(
        theme_id="matrix",
        name="Old name",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="pro_01",
        paddle_price_id="pri_01",
        preview_image="data:image/png;base64,PRESERVED_PREVIEW",
        preview_filename="matrix.jpg",
        checkout_url="",
        hosted_checkout_url="https://old.example/checkout",
        license_url="https://example.com/license",
        theme_json='{"variables": {"--accent": "#0f0"}}',
    )
    summary = db.refresh_themes_from_paddle(
        [_sample_paddle_product(
            name="Matrix Theme (renamed)",
            amount="2499",
            hosted_checkout="https://pay.paddle.com/hsc_NEW?price_id=pri_01",
        )]
    )
    assert summary["paddle_count"] == 1
    assert summary["matched"] == 1
    assert summary["updated"] == 1
    assert summary["created"] == 0
    row = db.get_theme("matrix")
    assert row is not None
    # Paddle-derived columns DID change.
    assert row["name"] == "Matrix Theme (renamed)"
    assert row["price_cents"] == 2499
    assert row["price_label"] == "$24.99/month"
    assert row["hosted_checkout_url"] == "https://pay.paddle.com/hsc_NEW?price_id=pri_01"
    # Operator-owned columns were preserved.
    assert row["preview_image"] == "data:image/png;base64,PRESERVED_PREVIEW"
    assert row["preview_filename"] == "matrix.jpg"
    assert row["theme_json"] == '{"variables": {"--accent": "#0f0"}}'
    assert row["license_url"] == "https://example.com/license"


def test_refresh_is_idempotent_on_second_pass(db):
    """Running the poller twice with the same input must not
    re-update anything on the second pass — the per-row change
    detector only flags columns that actually differ."""
    db.upsert_theme(
        theme_id="matrix",
        name="Matrix Theme",
        description="",
        price_cents=1999,
        price_label="$19.99/month",
        paddle_product_id="pro_01",
        paddle_price_id="pri_01",
        preview_image="data:image/png;base64,KEEP",
        preview_filename="matrix.jpg",
        checkout_url="",
        hosted_checkout_url="https://pay.paddle.com/hsc_X?price_id=pri_01",
        license_url="",
        theme_json="{}",
    )
    first = db.refresh_themes_from_paddle([_sample_paddle_product()])
    assert first["updated"] == 1
    second = db.refresh_themes_from_paddle([_sample_paddle_product()])
    # The first pass brought the row in sync; the second pass
    # reports zero actual updates even though matched is still 1.
    assert second["matched"] == 1
    assert second["updated"] == 0
    assert second["created"] == 0


def test_refresh_matches_by_paddle_price_id(db):
    """A theme row with no paddle_product_id but a paddle_price_id
    must still be matched by the poller so a product that was
    added with only a price id gets its product id stamped
    on the first refresh."""
    db.upsert_theme(
        theme_id="matrix",
        name="",
        description="",
        price_cents=None,
        price_label="",
        paddle_product_id="",
        paddle_price_id="pri_01",
        preview_image="data:image/png;base64,KEEP",
        preview_filename="matrix.jpg",
        checkout_url="",
        hosted_checkout_url="",
        license_url="https://example.com/license",
        theme_json="{}",
    )
    summary = db.refresh_themes_from_paddle(
        [_sample_paddle_product(
            product_id="pro_NEW",
            name="Matrix Theme",
            amount="499",
            hosted_checkout="https://pay.paddle.com/hsc_NEW?price_id=pri_01",
        )]
    )
    assert summary["matched"] == 1
    assert summary["updated"] == 1
    row = db.get_theme("matrix")
    assert row is not None
    assert row["paddle_product_id"] == "pro_NEW"
    assert row["paddle_price_id"] == "pri_01"
    # Operator-owned columns are still preserved.
    assert row["preview_image"] == "data:image/png;base64,KEEP"
    assert row["license_url"] == "https://example.com/license"


# ---------------------------------------------------------------------------
# Refresh: new Paddle product path
# ---------------------------------------------------------------------------


def test_refresh_creates_new_theme_row_from_paddle_with_empty_operator_fields(
    db,
):
    """A Paddle product with no matching themes row must produce a
    fresh row carrying the Paddle-derived columns, but the
    operator-owned columns (preview_image / preview_filename /
    theme_json / license_url) must remain empty so the operator
    still has to run add-theme / POST /admin/themes to attach a
    real theme.json + preview before a buyer can install."""
    summary = db.refresh_themes_from_paddle([_sample_paddle_product(
        product_id="pro_brand_new",
        price_id="pri_brand_new",
        name="Brand New Theme",
        amount="3999",
        theme_id="brand-new",
        hosted_checkout="https://pay.paddle.com/hsc_brand_new?price_id=pri_brand_new",
    )])
    assert summary["matched"] == 1
    assert summary["created"] == 1
    assert summary["updated"] == 0
    row = db.get_theme("brand-new")
    assert row is not None
    # Paddle-derived fields populated.
    assert row["name"] == "Brand New Theme"
    assert row["price_cents"] == 3999
    assert row["price_label"] == "$39.99/month"
    assert row["paddle_product_id"] == "pro_brand_new"
    assert row["paddle_price_id"] == "pri_brand_new"
    assert (
        row["hosted_checkout_url"]
        == "https://pay.paddle.com/hsc_brand_new?price_id=pri_brand_new"
    )
    # Operator-owned fields empty: the on-disk theme file is what
    # ``/themes/<id>/download`` serves, so a missing file fails
    # closed at download time (existing behaviour, see
    # ``_handle_theme_download``).
    assert row["preview_image"] == ""
    assert row["preview_filename"] == ""
    assert row["theme_json"] == ""
    assert row["license_url"] == ""


def test_refresh_empty_paddle_response_is_a_noop(db):
    """An empty Paddle response must not crash the poller and
    must report ``paddle_count == 0`` so the operator can grep
    for "we got nothing back from Paddle" in the boot log."""
    summary = db.refresh_themes_from_paddle([])
    assert summary == {
        "paddle_count": 0,
        "matched": 0,
        "updated": 0,
        "created": 0,
    }


# ---------------------------------------------------------------------------
# _run_paddle_poll_once: top-level smoke
# ---------------------------------------------------------------------------


def _fake_config(db, *, paddle_api_key: str = "fake_key") -> "_catalog.Config":
    """Build a minimal ``Config`` for the poller smoke test. The
    fields we don't exercise (host, port, db_path, ...) are filled
    with placeholders so the dataclass constructor accepts it; the
    poller only reads ``paddle_api_key``, ``paddle_env``,
    ``paddle_api_base``, and the URL-construction helpers, all of
    which we set to harmless sandbox values."""
    return _catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=Path("/tmp/unused.sqlite3"),
        themes_dir=Path("/tmp/themes"),
        previews_dir=Path("/tmp/previews"),
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=paddle_api_key,
        paddle_env="sandbox",
        base_url="http://127.0.0.1:9021",
        success_url=None,
        cancel_url=None,
        allow_insecure_return_urls=True,
        tls_cert=None,
        tls_key=None,
        setup_token="test_token",
        admin_api_key="test_admin_key",
        log_dir=Path("/tmp"),
        log_file="catalog-server.log",
        log_rotate=False,
        paddle_poll_enabled=True,
        paddle_poll_interval=600,
        smtp_host="",
        smtp_port=25,
        smtp_username=None,
        smtp_password=None,
        smtp_from="noreply@packetsnitch.test",
        smtp_use_tls=False,
    )


def test_run_paddle_poll_once_swallows_paddle_errors(db, monkeypatch):
    """The top-level poller entry point must never raise on a
    Paddle error — the background thread relies on this property
    to keep running across transient Paddle outages. The function
    returns a summary dict with ``error`` set instead."""
    config = _fake_config(db, paddle_api_key="fake_key")
    def _explode(config, db):
        raise RuntimeError("simulated Paddle outage")
    monkeypatch.setattr(
        _catalog,
        "_paddle_fetch_products_with_prices_impl",
        _explode,
    )
    summary = _catalog._run_paddle_poll_once(config, db)
    assert summary.get("error") == "simulated Paddle outage"
    assert summary["matched"] == 0
    assert summary["updated"] == 0
    assert summary["created"] == 0


def test_run_paddle_poll_once_skips_when_no_api_key(db):
    """When ``paddle_api_key`` is unset the poller should be a
    no-op rather than raising — operators running in dev without
    Paddle credentials still want a clean boot log."""
    config = _fake_config(db, paddle_api_key="")
    summary = _catalog._run_paddle_poll_once(config, db)
    assert summary == {
        "paddle_count": 0,
        "matched": 0,
        "updated": 0,
        "created": 0,
    }
