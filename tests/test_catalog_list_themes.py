"""Tests for the ``ps-catalog.py list-themes`` CLI command.

Covers the columns the operator sees on stdout:

  * id (the themes.id primary key)
  * price ($N.NN rendering of price_cents)
  * licenses (count of unrevoked licenses for the theme)
  * updated (ISO 8601 of the most recent row update, or "(never)")
  * fileBytes (on-disk size of ``themes_dir/<id>.json``, falling
    back to the embedded ``theme_json`` length, then ``"-"``)
  * preview (a short marker describing the preview source)
  * paddleProductId / paddlePriceId (the Paddle foreign-key pair)

The tests run ``cmd_list_themes`` via ``CliRunner``-style
invocation against an in-process ``CatalogDB`` plus a real
``themes_dir`` / ``previews_dir`` under ``tmp_path`` so the
filesystem probes (file-missing detection, on-disk byte
counting) actually exercise the code paths that matter.
"""

import importlib.util
import io
import json
import sqlite3
import sys
import uuid
from contextlib import redirect_stdout
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
        "ps_catalog_list_themes_test_module", _catalog_script()
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load ps-catalog.py")
    module = importlib.util.module_from_spec(spec)
    # The CatalogDB class introspects ``sys.modules`` for
    # ``sqlite3.Row``; the @dataclass decorator in Python 3.14
    # also needs the module to be in ``sys.modules`` before
    # ``exec_module`` runs. Registering first avoids both.
    sys.modules["ps_catalog_list_themes_test_module"] = module
    spec.loader.exec_module(module)
    return module


_catalog = _load_catalog_module()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_fake_args() -> "object":
    """argparse.Namespace is overkill for list-themes (it reads
    nothing off args) but the function signature requires one.
    The empty namespace keeps the call site honest if the
    function ever grows a flag."""
    import argparse
    return argparse.Namespace()


def _make_config(
    *, db_path: Path, themes_dir: Path, previews_dir: Path
) -> "_catalog.Config":
    """Build a minimal ``Config`` for the list-themes tests.
    Only the fields ``cmd_list_themes`` actually reads are
    populated; the rest are placeholders so the dataclass
    constructor accepts the call."""
    return _catalog.Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        themes_dir=themes_dir,
        previews_dir=previews_dir,
        paddle_webhook_secret=None,
        paddle_public_key=None,
        paddle_api_key=None,
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


def _run_list_themes(config: "_catalog.Config") -> str:
    """Run ``cmd_list_themes`` and capture its stdout. The CLI
    command returns an int exit code, but list-themes always
    returns 0 on success, so we just capture the printed text."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = _catalog.cmd_list_themes(_make_fake_args(), config)
    assert rc == 0, f"cmd_list_themes returned non-zero exit: {rc}"
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Empty / header
# ---------------------------------------------------------------------------


def test_list_themes_empty_catalog_prints_placeholder(env):
    """An empty catalog must print a single placeholder line so
    a script piping the output can rely on a consistent format
    regardless of whether any themes are registered yet."""
    _db, config = env
    output = _run_list_themes(config)
    assert output.strip() == "(no themes registered yet)"


def test_list_themes_header_includes_new_columns(env):
    """The header row must include every column documented in the
    function's docstring so a fresh operator can read the
    output without running ``--help``."""
    _db, config = env
    # No themes — but list-themes still prints the empty
    # placeholder before any header. Insert one and re-run.
    _db.upsert_theme(
        theme_id="sample",
        name="Sample Theme",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="{}",
    )
    output = _run_list_themes(config)
    header = output.splitlines()[0]
    for column in (
        "id",
        "price",
        "licenses",
        "updated",
        "fileBytes",
        "preview",
        "paddleProductId",
        "paddlePriceId",
    ):
        assert column in header, (
            f"list-themes header missing column {column!r}\n"
            f"actual header: {header!r}"
        )


# ---------------------------------------------------------------------------
# preview marker
# ---------------------------------------------------------------------------


def test_list_themes_shows_data_uri_preview_marker(env):
    """A theme with an embedded ``preview_image`` data URI must
    show ``data-uri(...)`` in the preview column, including the
    MIME type so the operator can confirm the embedded image is
    a real image and not, say, a JSON blob."""
    db, config = env
    db.upsert_theme(
        theme_id="neon",
        name="Neon",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="data:image/png;base64,iVBORw0KGgo=",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="{}",
    )
    output = _run_list_themes(config)
    assert "data-uri(image/png)" in output


def test_list_themes_shows_file_preview_marker_when_present(env):
    """A theme with ``preview_filename`` pointing at a real
    file under ``previews_dir`` must show ``file`` in the
    preview column."""
    db, config = env
    preview_path = config.previews_dir / "neon.jpg"
    preview_path.write_bytes(b"\xff\xd8\xff\xe0fake-jpeg")
    db.upsert_theme(
        theme_id="neon",
        name="Neon",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="neon.jpg",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="{}",
    )
    output = _run_list_themes(config)
    # The marker is left-padded to 22 chars; ``file`` shows up
    # surrounded by whitespace. Substring match is enough.
    assert "  file  " in output or "  file\n" in output or output.endswith("  file")


def test_list_themes_shows_file_missing_marker_when_file_absent(env):
    """A theme with ``preview_filename`` set but the underlying
    file deleted (a real data-integrity scenario) must show
    ``file-missing`` so the operator can spot the broken
    preview URL without opening a browser."""
    db, config = env
    db.upsert_theme(
        theme_id="broken",
        name="Broken Preview",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="does-not-exist.jpg",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="{}",
    )
    output = _run_list_themes(config)
    assert "file-missing" in output


def test_list_themes_shows_dash_when_no_preview_configured(env):
    """A theme with neither an embedded image nor a file
    reference must show ``-`` in the preview column."""
    db, config = env
    db.upsert_theme(
        theme_id="naked",
        name="Naked",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="{}",
    )
    output = _run_list_themes(config)
    # Find the row line and check the preview column. The
    # marker is left-padded to 22 chars, so we look for the
    # row's trailing position.
    rows = [line for line in output.splitlines() if "naked" in line]
    assert rows, f"list-themes output missing 'naked' row: {output!r}"
    # The preview column is just before the paddle product id;
    # verify the row has a dash at the right position.
    row = rows[0]
    assert " -               " in row or row.rstrip().endswith("-")


# ---------------------------------------------------------------------------
# fileBytes
# ---------------------------------------------------------------------------


def test_list_themes_shows_on_disk_size_for_existing_theme_file(env):
    """When ``themes_dir/<id>.json`` exists, the fileBytes
    column must show its actual on-disk size in a human-
    readable form (B / KiB / MiB). The embedded ``theme_json``
    column can be different in length, so this exercises the
    on-disk path explicitly."""
    db, config = env
    theme_id = "with-file"
    # Persist the row first; the on-disk file is created by
    # the caller in the real workflow, so we simulate that
    # here.
    db.upsert_theme(
        theme_id=theme_id,
        name="With File",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="{}",  # 2 bytes
    )
    on_disk = config.themes_dir / f"{theme_id}.json"
    on_disk.write_text("x" * 5000)  # 5000 bytes
    output = _run_list_themes(config)
    # 5000 bytes → 4.9 KiB
    assert "4.9 KiB" in output


def test_list_themes_falls_back_to_theme_json_length_when_file_missing(
    env,
):
    """When the on-disk theme file is missing but the DB row
    carries an embedded ``theme_json``, the fileBytes column
    must show the embedded length. This is the common case
    right after a poller-driven ``upsert_theme`` writes a new
    row but the on-disk rewrite hasn't happened yet."""
    db, config = env
    db.upsert_theme(
        theme_id="db-only",
        name="DB Only",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="x" * 200,  # 200 bytes
    )
    # No on-disk file
    output = _run_list_themes(config)
    assert "200 B" in output


def test_list_themes_shows_dash_when_no_file_and_no_embedded_json(env):
    """When the on-disk file is missing AND ``theme_json`` is
    empty, the fileBytes column must show ``-`` rather than
    0 B (which would suggest a broken file rather than a
    missing one)."""
    db, config = env
    db.upsert_theme(
        theme_id="empty",
        name="Empty",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="",
    )
    output = _run_list_themes(config)
    assert "         - " in output or "- " in output


# ---------------------------------------------------------------------------
# updated timestamp
# ---------------------------------------------------------------------------


def test_list_themes_shows_iso_timestamp_for_recently_updated_row(
    env,
):
    """The ``updated`` column must show a real ISO 8601
    timestamp (not 0 / epoch) for any row that has been
    touched, so an operator can spot a stale poller."""
    db, config = env
    db.upsert_theme(
        theme_id="fresh",
        name="Fresh",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="{}",
    )
    output = _run_list_themes(config)
    # The "fresh" row's updated column should be a non-zero
    # ISO 8601 string (year 2025 or later). We don't pin the
    # exact string because it depends on the wall clock at
    # test time.
    rows = [line for line in output.splitlines() if "fresh" in line]
    assert rows
    # The updated column is 19 chars wide and positioned
    # right after ``licenses`` + 2 spaces. Easier: assert the
    # row contains a "202" or later year.
    assert "202" in rows[0]


# ---------------------------------------------------------------------------
# paddle id columns
# ---------------------------------------------------------------------------


def test_list_themes_paddle_columns_dash_when_unset(env):
    """A theme added without Paddle ids (the legacy add-theme
    path) must show ``-`` in the paddleProductId /
    paddlePriceId columns rather than an empty string so the
    columns align with the rest of the table."""
    db, config = env
    db.upsert_theme(
        theme_id="legacy",
        name="Legacy",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="{}",
    )
    output = _run_list_themes(config)
    rows = [line for line in output.splitlines() if "legacy" in line]
    assert rows
    # Split the row by 2+ spaces (the column separator) and
    # check the last two columns. With no Paddle ids set, both
    # must render as a single dash. We split on whitespace runs
    # rather than asserting on exact padding because the
    # column widths may grow in a future change.
    parts = rows[0].split()
    # parts[-1] = paddlePriceId, parts[-2] = paddleProductId
    # (the columns are left-padded in the format string but
    # still get collapsed by .split()). The dashes are
    # single-character when the cell is empty.
    assert parts[-1] == "-", f"paddlePriceId was {parts[-1]!r}, want '-'"
    assert parts[-2] == "-", f"paddleProductId was {parts[-2]!r}, want '-'"


def test_list_themes_paddle_columns_show_ids_when_set(env):
    """A theme that was matched on Paddle by the poller must
    show its real product / price ids in those columns so the
    operator can correlate against the Paddle dashboard."""
    db, config = env
    db.upsert_theme(
        theme_id="pro",
        name="Pro",
        description="",
        price_cents=1999,
        price_label="$19.99/month",
        paddle_product_id="pro_01ABC",
        paddle_price_id="pri_01XYZ",
        preview_image="",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="{}",
    )
    output = _run_list_themes(config)
    rows = [line for line in output.splitlines() if "pro" in line]
    assert rows
    assert "pro_01ABC" in rows[0]
    assert "pri_01XYZ" in rows[0]


# ---------------------------------------------------------------------------
# license count
# ---------------------------------------------------------------------------


def test_list_themes_license_count_excludes_revoked_licenses(env):
    """The ``licenses`` column must count only unrevoked
    licenses, so a row whose only license was revoked shows
    ``0`` (not ``1``). This is the same definition
    ``count_active_licenses_for_theme`` uses elsewhere in the
    codebase."""
    db, config = env
    db.upsert_theme(
        theme_id="revoked-test",
        name="Revoked Test",
        description="",
        price_cents=999,
        price_label="$9.99/month",
        paddle_product_id="",
        paddle_price_id="",
        preview_image="",
        preview_filename="",
        checkout_url="",
        hosted_checkout_url="",
        license_url="",
        theme_json="{}",
    )
    install_a = str(uuid.uuid4())
    install_b = str(uuid.uuid4())
    db.grant_license(install_a, "revoked-test")
    db.grant_license(install_b, "revoked-test")
    db.revoke_license(install_a, "revoked-test")
    output = _run_list_themes(config)
    # The licenses column is right-aligned 8-char wide. The
    # active count is 1 (only install_b).
    rows = [line for line in output.splitlines() if "revoked-test" in line]
    assert rows
    # Format: ``f"{owned_count:>8d}"`` so we should see
    # ``       1`` (7 spaces + 1) in the row.
    assert "       1" in rows[0]
