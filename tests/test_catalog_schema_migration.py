"""Regression test for the schema-migration crash on legacy catalogs.

The live catalog server crashed on boot with::

    sqlite3.OperationalError: no such column: customer_email

because the SCHEMA string included ``CREATE INDEX installs_email_idx
ON installs(customer_email)`` and ran via ``executescript`` *before*
the ``_migrate_installs_customer_email`` migration that adds the
``customer_email`` column via ALTER TABLE. On a fresh DB the column
is created by the ``CREATE TABLE installs`` statement, so the index
succeeds; on a legacy DB (built before the portal shipped) the table
already exists without the column, so ``CREATE INDEX`` fails before
the migration ever gets to run.

The fix: the ``installs_email_idx`` index is no longer in the SCHEMA
string. It is created by ``_migrate_installs_customer_email`` after
the column is in place. This test simulates the exact legacy scenario
by creating an old-style ``installs`` table (no ``customer_email``
column) and then opening it with the current ``CatalogDB``, which
must not crash and must end up with the column + index present."""

import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest


def _catalog_script() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "src"
        / "PacketSnitch-Pro"
        / "Servers"
        / "Catalog"
        / "ps-catalog.py"
    )


def _load_catalog_module():
    spec = importlib.util.spec_from_file_location(
        "ps_catalog_schema_migration_test_module", _catalog_script()
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load ps-catalog.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ps_catalog_schema_migration_test_module"] = module
    spec.loader.exec_module(module)
    return module


_catalog = _load_catalog_module()


_LEGACY_INSTALLS_DDL = """
CREATE TABLE installs (
    install_uuid TEXT PRIMARY KEY,
    license_tier TEXT NOT NULL DEFAULT 'free'
        CHECK (license_tier IN ('free','professional','enterprise')),
    paddle_customer_id TEXT NOT NULL DEFAULT '',
    paddle_subscription_id TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    first_seen_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX installs_tier_idx ON installs(license_tier);
CREATE INDEX installs_paddle_customer_idx ON installs(paddle_customer_id);
"""


_LEGACY_INSTALL_UUID = "11111111-1111-4111-8111-111111111111"


def _seed_legacy_db(db_path: Path, install_uuid: str = _LEGACY_INSTALL_UUID) -> None:
    """Create a pre-portal catalog DB: installs table without
    ``customer_email``, no ``magic_link_tokens``, no
    ``installs_email_idx``. This mirrors what the live server had
    before the Phase 3 deploy."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(_LEGACY_INSTALLS_DDL)
        conn.execute(
            "INSERT INTO installs (install_uuid, license_tier, "
            "first_seen_at, updated_at) VALUES (?, 'free', 0, 0)",
            (install_uuid,),
        )
        conn.commit()
    finally:
        conn.close()


def test_legacy_db_boots_without_crash(tmp_path):
    """The exact scenario from the live traceback: a DB built before
    ``customer_email`` existed must boot cleanly under the new code.
    The ``executescript(SCHEMA)`` call must not fail on the missing
    column, and the migration must add it after."""
    db_path = tmp_path / "legacy.sqlite3"
    _seed_legacy_db(db_path)
    # This line used to raise:
    #   sqlite3.OperationalError: no such column: customer_email
    db = _catalog.CatalogDB(db_path)
    try:
        cols = {row["name"] for row in db.conn.execute("PRAGMA table_info(installs)")}
        assert "customer_email" in cols
        idxs = {
            row["name"]
            for row in db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name='installs'"
            )
        }
        assert "installs_email_idx" in idxs
    finally:
        db.close()


def test_legacy_db_preserves_existing_rows(tmp_path):
    """The migration must not drop or alter existing install rows.
    The legacy row we seeded should still be there with its original
    UUID and tier, plus a new empty ``customer_email``."""
    db_path = tmp_path / "legacy.sqlite3"
    install_uuid = "legacy-uuid-0002"
    _seed_legacy_db(db_path, install_uuid=install_uuid)
    db = _catalog.CatalogDB(db_path)
    try:
        row = db.conn.execute(
            "SELECT install_uuid, license_tier, customer_email "
            "FROM installs WHERE install_uuid = ?",
            (install_uuid,),
        ).fetchone()
        assert row["install_uuid"] == install_uuid
        assert row["license_tier"] == "free"
        assert row["customer_email"] == ""
    finally:
        db.close()


def test_legacy_db_then_portal_request_works(tmp_path):
    """After the migration, the portal's email-based lookups work
    against a freshly-migrated legacy DB. This is the end-to-end
    smoke that the migration didn't just not-crash but actually
    produced a usable schema."""
    db_path = tmp_path / "legacy.sqlite3"
    _seed_legacy_db(db_path)
    db = _catalog.CatalogDB(db_path)
    try:
        # list_installs_for_customer_email is the portal's primary
        # lookup; it must work against the newly-added column.
        rows = db.list_installs_for_customer_email("nobody@example.com")
        assert rows == []
        # Stamp an email onto the legacy row and confirm the lookup
        # finds it.
        db.update_install_email(_LEGACY_INSTALL_UUID, "alice@example.com")
        rows = db.list_installs_for_customer_email("alice@example.com")
        assert len(rows) == 1
        assert rows[0]["install_uuid"] == _LEGACY_INSTALL_UUID
    finally:
        db.close()


def test_fresh_db_still_gets_email_index(tmp_path):
    """Fresh DBs (never seen the legacy schema) must still end up
    with the ``installs_email_idx`` index. The column comes from the
    CREATE TABLE in SCHEMA; the index comes from the migration. Both
    paths must produce the same end state as a legacy DB."""
    db_path = tmp_path / "fresh.sqlite3"
    db = _catalog.CatalogDB(db_path)
    try:
        idxs = {
            row["name"]
            for row in db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name='installs'"
            )
        }
        assert "installs_email_idx" in idxs
        cols = {row["name"] for row in db.conn.execute("PRAGMA table_info(installs)")}
        assert "customer_email" in cols
    finally:
        db.close()


def test_migration_is_idempotent_on_reopen(tmp_path):
    """Opening the same migrated DB a second time must be a no-op:
    no crash, column still there, index still there, row still
    there. This guards against a half-finished migration leaving
    the column but not the index (or vice versa) and then crashing
    on the next boot."""
    db_path = tmp_path / "legacy.sqlite3"
    _seed_legacy_db(db_path)
    # First open: runs the migration.
    db1 = _catalog.CatalogDB(db_path)
    db1.close()
    # Second open: must be a clean no-op.
    db2 = _catalog.CatalogDB(db_path)
    try:
        cols = {row["name"] for row in db2.conn.execute("PRAGMA table_info(installs)")}
        assert "customer_email" in cols
        idxs = {
            row["name"]
            for row in db2.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name='installs'"
            )
        }
        assert "installs_email_idx" in idxs
        row = db2.conn.execute(
            "SELECT install_uuid FROM installs"
        ).fetchone()
        assert row["install_uuid"] == _LEGACY_INSTALL_UUID
    finally:
        db2.close()