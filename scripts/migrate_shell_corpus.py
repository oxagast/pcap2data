#!/usr/bin/env python3
"""Migrate ``scripts/shell_corpus_sorted.txt`` from one-shell-per-line text to
NDJSON.

Output: ``scripts/shell_corpus_sorted.ndjson`` -- one JSON object per line with
``{"line": <int>, "tokens": [<str>, ...], "raw": "<original line>"}``.

Notes:

- Empty lines and lines whose first non-whitespace char is ``#`` are dropped
  with a count reported on stderr.
- Tokens are whitespace-split. The original corpus is space-separated shell
  commands, so this matches the historical behaviour.
- ``raw`` preserves the exact original line (including trailing whitespace
  trimmed) so we can reconstruct the original ordering if needed.

Usage::

    python scripts/migrate_shell_corpus.py [--in PATH] [--out PATH]
                                            [--keep-original]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IN = REPO_ROOT / "scripts" / "shell_corpus_sorted.txt"
DEFAULT_OUT = REPO_ROOT / "scripts" / "shell_corpus_sorted.ndjson"


def migrate(in_path: Path, out_path: Path) -> dict:
    """Walk *in_path* line-by-line, write NDJSON to *out_path*.

    Returns a stats dict the caller can print.
    """
    total = 0
    kept = 0
    blank = 0
    comments = 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with (
        in_path.open("r", encoding="utf-8") as src,
        out_path.open("w", encoding="utf-8") as dst,
    ):
        for line_no, raw in enumerate(src, start=1):
            total += 1
            stripped = raw.strip()
            if not stripped:
                blank += 1
                continue
            if stripped.startswith("#"):
                comments += 1
                continue
            tokens = stripped.split()
            record = {"line": line_no, "tokens": tokens, "raw": stripped}
            dst.write(json.dumps(record, ensure_ascii=False))
            dst.write("\n")
            kept += 1

    return {
        "input": str(in_path),
        "output": str(out_path),
        "total_lines": total,
        "kept": kept,
        "blank": blank,
        "comments": comments,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="in_path", type=Path, default=DEFAULT_IN)
    parser.add_argument("--out", dest="out_path", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--keep-original",
        action="store_true",
        help="Leave the .txt file in place (default: same -- the script never deletes it).",
    )
    args = parser.parse_args(argv)

    if not args.in_path.exists():
        print(f"ERROR: input not found: {args.in_path}", file=sys.stderr)
        return 1

    stats = migrate(args.in_path, args.out_path)
    for k, v in stats.items():
        print(f"{k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))