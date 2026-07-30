#!/usr/bin/env python3
"""One-shot grant helper for transactions that the catalog server couldn't
auto-reconcile.

Usage:
    python3 scripts/grant-license.py <transaction_id> <install_uuid> <theme_id>

The script records the intent in the catalog's transaction_intent table and
grants the license. Use this when a Paddle sandbox transaction has the
Paddle-side status of "paid"/"completed" but Paddle doesn't echo
``custom_data`` back through ``GET /transactions/{id}``, so the catalog
server's normal reconciliation flow can't recover the installUuid/themeId
on its own.

After running this, restart the catalog server (or just re-hit
``/checkout-success?transaction_id=<txn>``) and the proactive grant will fire.
"""

import argparse
import sqlite3
import sys
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db",
        default="/home/marshall/Packetsnitch/src/catalog/catalog.sqlite3",
        help="Path to the catalog's SQLite file.",
    )
    parser.add_argument(
        "--theme-id",
        default="matrix",
        help="Theme id to grant. Default: matrix",
    )
    parser.add_argument(
        "--catalog-source",
        default=None,
        help="Optional explicit path to a ps-catalog.py to load for the "
             "schema bootstrap. If unset, the script searches the "
             "workspace (parent of this file) and the catalog db "
             "directory. Use --no-bootstrap to skip the bootstrap "
             "entirely.",
    )
    parser.add_argument(
        "--no-bootstrap",
        action="store_true",
        help="Skip loading ps-catalog.py for the schema bootstrap. The "
             "catalog server must have run at least once on this DB so "
             "all tables exist.",
    )
    parser.add_argument(
        "transaction_id",
        help="Paddle transaction id (e.g. txn_01kyra4erszf253208cj299rp7)",
    )
    parser.add_argument(
        "install_uuid",
        help="PacketSnitch installUuid that paid for this transaction",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.is_file():
        print(f"ERROR: catalog db not found at {db_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Best-effort schema bootstrap: load ps-catalog.py and run its
    # CatalogDB constructor to ensure all tables (including the new
    # transaction_intent) exist. We swallow any error because the
    # bootstrap is only needed for fresh DBs; an existing DB created
    # by an older server will already have the schema it needs (and
    # might use a slightly different ps_catalog.py that fails to
    # import for unrelated reasons — see ``--no-bootstrap`` to skip).
    if not args.no_bootstrap:
        schema_search_paths = [
            Path(args.catalog_source) if args.catalog_source else None,
            Path(__file__).resolve().parent.parent / "src" / "catalog" / "ps-catalog.py",
            db_path.parent / "ps-catalog.py",
        ]
        schema_path = next(
            (p for p in schema_search_paths if p and p.is_file()),
            None,
        )
        if schema_path:
            try:
                import importlib.util

                spec = importlib.util.spec_from_file_location(
                    "ps_catalog_bootstrap", schema_path
                )
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                mod.CatalogDB(db_path).close()
                print(f"Schema verified at {db_path}")
            except Exception as exc:
                print(
                    f"WARNING: schema bootstrap skipped ({type(exc).__name__}: {exc}). "
                    f"If the catalog DB is missing the ``transaction_intent`` table, "
                    f"re-run the catalog server once to create it.",
                    file=sys.stderr,
                )

    # Verify the theme exists (the licenses table has a FK to themes).
    theme_row = conn.execute(
        "SELECT id, name FROM themes WHERE id = ?", (args.theme_id,)
    ).fetchone()
    if theme_row is None:
        print(
            f"ERROR: theme '{args.theme_id}' is not registered in the "
            f"catalog. Run `ps-catalog.py upsert-theme` first.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"Theme: {theme_row['id']} ({theme_row['name']})")

    # Ensure transaction_intent exists. Older catalog servers may not
    # have created it; this is a no-op if it does.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS transaction_intent (
            transaction_id TEXT PRIMARY KEY,
            install_uuid TEXT NOT NULL,
            theme_id TEXT NOT NULL,
            paddle_customer_id TEXT NOT NULL DEFAULT '',
            customer_email TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        )
        """
    )
    conn.commit()

    # Record intent (idempotent — INSERT OR REPLACE on transaction_id).
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO transaction_intent (
            transaction_id, install_uuid, theme_id,
            paddle_customer_id, customer_email, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(transaction_id) DO UPDATE SET
            install_uuid=excluded.install_uuid,
            theme_id=excluded.theme_id
        """,
        (args.transaction_id, args.install_uuid, args.theme_id, "", "", now),
    )
    print(
        f"Recorded transaction_intent transaction={args.transaction_id} "
        f"installUuid={args.install_uuid} themeId={args.theme_id}"
    )

    # Grant license (idempotent — INSERT OR REPLACE on (install_uuid, theme_id)).
    conn.execute(
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
        (
            args.install_uuid,
            args.theme_id,
            args.transaction_id,
            "",
            now,
            None,
        ),
    )
    conn.commit()
    owned = conn.execute(
        "SELECT theme_id FROM licenses WHERE install_uuid = ? AND revoked_at IS NULL",
        (args.install_uuid,),
    ).fetchall()
    print(f"Owned themes for {args.install_uuid}: {[r['theme_id'] for r in owned]}")
    print("\nDone. Restart the catalog server or hit the success page again to verify.")
    print(
        f"  curl -sk 'https://oxasploits.com:9021/checkout-success?transaction_id={args.transaction_id}'"
    )


if __name__ == "__main__":
    main()
