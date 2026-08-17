"""Migrate scripts/ssh_proposed_qwerty_baselines.json from v1 → v2.

The v1 file is a flat map of category → {mean, std}. The v2 schema wraps each
entry in a weight envelope:

    "sameKey": {
      "value": { "mean": 220, "std": 45 },
      "weight": {
        "tags": ["baseline"],
        "support": 1211,          # command count from shell_corpus
        "variance": 2025,         # std ** 2
        "std": 45
      }
    }

The script is idempotent: re-running it on a v2 file is a no-op.

Usage:
    python3 scripts/migrate_proposed_baselines_to_v2.py [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASELINES = REPO / "scripts" / "ssh_proposed_qwerty_baselines.json"
CORPUS = REPO / "src" / "data" / "shell_corpus_sorted.txt"


def corpus_command_count(corpus_path: Path) -> int:
    """Count distinct, non-blank shell commands in the corpus."""
    if not corpus_path.exists():
        return 0
    seen: set[str] = set()
    with corpus_path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            seen.add(stripped)
    return len(seen)


def is_v2_envelope(weight_obj: dict) -> bool:
    """v2 envelopes always carry `tags`, `support`, `variance`, `std`."""
    return {"tags", "support", "variance", "std"} <= set(weight_obj.keys())


def wrap(entry: dict, support: int) -> dict:
    """Wrap a v1 {mean, std} entry in a v2 envelope."""
    if not isinstance(entry, dict) or "std" not in entry:
        return entry
    if "weight" in entry and is_v2_envelope(entry["weight"]):
        return entry  # idempotent
    std = entry["std"]
    return {
        "value": dict(entry),
        "weight": {
            "tags": ["baseline"],
            "support": support,
            "variance": std * std,
            "std": std,
        },
    }


def migrate(path: Path, support: int, dry_run: bool) -> bool:
    """Return True if the file was modified."""
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    baselines = data.get("baselines")
    if not isinstance(baselines, dict):
        print(f"  ! no 'baselines' object in {path.name}; skipping", file=sys.stderr)
        return False

    changed = False
    new_baselines: dict[str, dict] = {}
    for category, entry in baselines.items():
        wrapped = wrap(entry, support)
        if wrapped is not entry:
            changed = True
        new_baselines[category] = wrapped

    if not changed:
        print(f"  = {path.name} already at v2; no changes")
        return False

    data["baselines"] = new_baselines
    data["version"] = 2
    payload = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if dry_run:
        print(f"  ~ dry-run: would rewrite {path.name} ({len(payload)} bytes)")
        return True

    path.write_text(payload, encoding="utf-8")
    print(f"  ✓ rewrote {path.name} with envelopes on {len(new_baselines)} categories")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing",
    )
    args = parser.parse_args()

    if not BASELINES.exists():
        print(f"missing {BASELINES}", file=sys.stderr)
        return 2

    support = corpus_command_count(CORPUS)
    print(f"corpus command count: {support}")
    print(f"migrating {BASELINES.relative_to(REPO)} …")
    changed = migrate(BASELINES, support=support, dry_run=args.dry_run)
    print("done" if changed else "no changes")
    return 0


if __name__ == "__main__":
    sys.exit(main())