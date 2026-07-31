"""Reproduce the catalog's Paddle POST and print the actual error body.

Usage: .venv/bin/python tests/repro_paddle.py [theme_id]
"""
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request


def main():
    theme_id = sys.argv[1] if len(sys.argv) > 1 else "nilla-horizon-theme"
    api_key = os.environ.get("PS_CATALOG_PADDLE_API_KEY")
    if not api_key:
        print("NO_API_KEY (set PS_CATALOG_PADDLE_API_KEY)")
        sys.exit(2)

    # The catalog DB lives in ~/Packetsnitch/src/catalog/catalog.db by default
    db_paths = [
        os.path.expanduser("~/Packetsnitch/src/catalog/catalog.db"),
        os.path.expanduser("~/Hacks/projects/packetsnitch/catalog.db"),
        "catalog.db",
    ]
    row = None
    for db_path in db_paths:
        if not os.path.isfile(db_path):
            continue
        c = sqlite3.connect(db_path)
        c.row_factory = sqlite3.Row
        row = c.execute(
            "SELECT * FROM themes WHERE id=?", (theme_id,)
        ).fetchone()
        if row:
            print(f"DB: {db_path}")
            break

    if not row:
        print(f"NO_THEME {theme_id!r} in any of: {db_paths}")
        sys.exit(0)

    print(f"price_id       : {row['paddle_price_id']!r}")
    print(f"product_id     : {row['paddle_product_id']!r}")
    print(f"hosted_url     : {row['hosted_checkout_url'][:80]!r}")
    print(f"checkout_url   : {row['checkout_url'][:80]!r}")

    payload = {
        "items": [{"price_id": row["paddle_price_id"], "quantity": 1}],
        "custom_data": {
            "installUuid": "b48a0cc8-0a11-4846-95b0-cfd977c8eab3",
            "themeId": theme_id,
        },
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url="https://sandbox-api.paddle.com/transactions",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    print("\n--- REQUEST ---")
    print(json.dumps(payload, indent=2))
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            print(f"\nSTATUS: {resp.status}")
            print("BODY:")
            print(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"\nSTATUS: {e.code}")
        print("BODY:")
        print(e.read().decode())


if __name__ == "__main__":
    main()
