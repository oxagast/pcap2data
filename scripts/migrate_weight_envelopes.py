#!/usr/bin/env python3
"""Migrate PacketSnitch keystroke-recovery artifacts to weight-envelope v2.

Follows `scripts/WEIGHT_SCHEMA.md`. Each script-level artifact gets the right
treatment for its structure:

- ``src/data/qwerty-model.json``  -- already v2 in tree; ``--check`` only.
- ``scripts/ssh_proposed_qwerty_baselines.json`` -- each category block
  (and the top-level) gains ``{"weight": {...}}``.
- ``scripts/shell_markov_model.json`` -- top-level ``{"weight": {...}}``;
  ``transitions`` stays raw observation counts.
- ``scripts/ssh_timing_stats.json`` -- top-level ``{"weight": {...}}``;
  per-direction blocks keep ``count/mean_ms/std_ms/deltas_ms`` untouched.

Usage::

    python scripts/migrate_weight_envelopes.py --dry-run
    python scripts/migrate_weight_envelopes.py --apply
    python scripts/migrate_weight_envelopes.py --check-qwerty-model
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

QWERTY_MODEL = REPO_ROOT / "src" / "data" / "qwerty-model.json"
QWERTY_BASELINES = REPO_ROOT / "scripts" / "ssh_proposed_qwerty_baselines.json"
SHELL_MARKOV = REPO_ROOT / "scripts" / "shell_markov_model.json"
SSH_TIMING = REPO_ROOT / "scripts" / "ssh_timing_stats.json"

NOW_ISO = (
    _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
)


def make_weight(
    *,
    weight: float,
    count: int | None,
    source: str,
    tags: list[str] | None = None,
    last_updated: str | None = None,
    variance: float | None = None,
    notes: str | None = None,
) -> dict:
    """Build a v2 envelope block (FLAT shape per WEIGHT_SCHEMA.md §1).

    The envelope is a dict with keys ``weight``, ``count``, ``source``,
    ``lastUpdated``, plus optional ``variance`` and ``tags``. These
    are SIBLING keys of the parent entry's ``mean``/``std`` —
    callers should splat the envelope into the parent, e.g.
    ``entry.update(envelope)``.

    The decoder (``src/ui/decoders/ssh-keystrokes/score-envelopes.js``)
    accepts both the flat shape (canonical) and the nested
    ``{weight: {…}}`` shape (legacy v0.1). New writes should use the
    flat shape so downstream tooling that introspects the schema
    directly sees consistent keys.
    """
    envelope: dict = {
        "weight": clamp01(float(weight)),
        "count": None if count is None else int(count),
        "source": source,
        "lastUpdated": last_updated or NOW_ISO,
    }
    if variance is not None:
        envelope["variance"] = float(variance)
    if tags is not None:
        envelope["tags"] = list(tags)
    if notes is not None:
        envelope["notes"] = notes
    return envelope


def clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)


def has_weight_envelope(node) -> bool:
    """True if *node* is a dict that already carries v2 envelope keys.

    Accepts both the flat shape (``weight`` is a number) and the
    legacy nested shape (``weight`` is a dict) so re-running the
    migrator on data written by an earlier version is a no-op.
    """
    if not isinstance(node, dict):
        return False
    if "weight" not in node:
        return False
    # Flat shape: ``weight`` is a number, ``count`` may be null.
    if isinstance(node.get("weight"), (int, float)):
        return "source" in node and "lastUpdated" in node
    # Nested shape (legacy): ``weight`` is a dict with envelope fields.
    if isinstance(node.get("weight"), dict):
        w = node["weight"]
        return (
            "weight" in w and "count" in w and "source" in w
            and ("lastUpdated" in w or "last_updated" in w)
        )
    return False


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def dump_json(path: Path, data: dict) -> None:
    """Stable, human-diff-friendly serialisation: 2-space indent, sort keys off."""
    text = json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False)
    # Ensure a single trailing newline (git-friendly).
    if not text.endswith("\n"):
        text += "\n"
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Per-file migrations
# ---------------------------------------------------------------------------


def migrate_qwerty_baselines(path: Path) -> tuple[dict, list[str]]:
    """Wrap each category block in a weight envelope.

    ``ssh_proposed_qwerty_baselines.json`` has the shape
    ``{"version": 1, "baselines": {<category>: {mean, std}}, "notes": {...}}``.
    The migrator descends into ``baselines`` to wrap each category and
    adds a top-level weight envelope recording artifact-wide provenance.
    """
    data = load_json(path)
    notes: list[str] = []
    changed = False

    # Top-level envelope -----------------------------------------------------
    if not has_weight_envelope(data):
        categories = data.get("baselines") if isinstance(data.get("baselines"), dict) else {}
        notes.append(
            f"top-level: {len(categories)} categories wrapped"
        )
        data["weight"] = {
            "confidence": 0.5,
            "sample_size": 0,
            "smoothing": "category_summary",
            "source": "calibration",
            "tags": ["baseline", "category_summary"],
            "last_updated": NOW_ISO,
            "notes": (
                "Top-level envelope for the QWERTY baseline artifact. "
                "Per-category blocks carry their own weight envelope; this "
                "block records artifact-wide provenance."
            ),
        }
        changed = True
    else:
        notes.append("top-level: already wrapped (skipped)")

    # Per-category envelopes -----------------------------------------------
    baselines = data.get("baselines")
    if isinstance(baselines, dict):
        for category, block in list(baselines.items()):
            if not isinstance(block, dict):
                continue
            if "mean" not in block and "std" not in block:
                continue
            if has_weight_envelope(block):
                notes.append(f"category[{category}]: already wrapped (skipped)")
                continue
            new_block = {
                "weight": {
                    "confidence": 0.5,
                    "sample_size": 0,
                    "smoothing": "category_summary",
                    "source": "calibration",
                    "tags": ["baseline", category],
                    "last_updated": NOW_ISO,
                    "notes": (
                        f"Category-level envelope for '{category}'. The true "
                        "empirical sample size for this category is the count "
                        "of shell_corpus_sorted.txt digraphs that fall into "
                        "it; tracked separately in scripts/derive_digraphs.py."
                    ),
                }
            }
            new_block.update(block)
            baselines[category] = new_block
            notes.append(f"category[{category}]: wrapped")
            changed = True

    # Bump schema version whenever the file is at v2 (envelopes present).
    # This runs even when envelopes were already present so a legacy file
    # without schema_version still gets stamped.
    if data.get("schema_version") != 2:
        data["schema_version"] = 2
        changed = True

    return data, notes, changed


def migrate_shell_markov(path: Path) -> tuple[dict, list[str], bool]:
    """Top-level envelope only; ``transitions`` stays raw counts.

    The markov model is a sparse bigram histogram; adding per-bigram envelopes
    would bloat the file ~30x with no information gain. The artifact's overall
    weight is recorded at the top level instead.
    """
    data = load_json(path)
    notes: list[str] = []
    changed = False

    transitions = data.get("transitions")
    if not isinstance(transitions, dict):
        notes.append("WARN: no 'transitions' dict found, writing top-level only")

    bigram_count = sum(
        len(v) for v in transitions.values() if isinstance(v, dict)
    ) if isinstance(transitions, dict) else 0
    context_count = (
        sum(1 for v in transitions.values() if isinstance(v, dict) and v)
        if isinstance(transitions, dict)
        else 0
    )

    if has_weight_envelope(data):
        notes.append("top-level: already wrapped (skipped)")
        if data.get("schema_version") != 2:
            data["schema_version"] = 2
            changed = True
        return data, notes, changed

    data["weight"] = {
        "confidence": 0.7,
        "sample_size": bigram_count,
        "smoothing": "laplace_additive",
        "source": "calibration",
        "tags": ["markov", "shell_corpus"],
        "last_updated": NOW_ISO,
        "notes": (
            f"Top-level envelope for the shell Markov model. "
            f"transitions has {context_count} non-empty contexts and "
            f"{bigram_count} total (context,next_char) observation pairs. "
            "Per-bigram weights are not stored; the empirical counts are the "
            "signal."
        ),
    }
    data["schema_version"] = 2
    changed = True
    notes.append(
        f"top-level: wrapped ({context_count} contexts, {bigram_count} pairs)"
    )
    return data, notes, changed


def migrate_ssh_timing_stats(path: Path) -> tuple[dict, list[str], bool]:
    """Top-level envelope only; per-direction stats untouched."""
    data = load_json(path)
    notes: list[str] = []
    changed = False

    directions = [k for k in data.keys() if isinstance(data.get(k), dict) and "deltas_ms" in data[k]]
    total_samples = sum(data[d].get("count", 0) for d in directions)

    if has_weight_envelope(data):
        notes.append("top-level: already wrapped (skipped)")
        if data.get("schema_version") != 2:
            data["schema_version"] = 2
            changed = True
        return data, notes, changed

    data["weight"] = {
        "confidence": 0.8 if total_samples >= 1000 else 0.5,
        "sample_size": total_samples,
        "smoothing": "empirical",
        "source": "calibration",
        "tags": ["timing", "keystroke"],
        "last_updated": NOW_ISO,
        "notes": (
            f"Top-level envelope for SSH keystroke timing stats. "
            f"{len(directions)} directions: {', '.join(directions)}. "
            "Per-direction count/mean_ms/std_ms/deltas_ms are raw observations."
        ),
    }
    data["schema_version"] = 2
    changed = True
    notes.append(
        f"top-level: wrapped ({len(directions)} directions, {total_samples} samples)"
    )
    return data, notes, changed


def check_qwerty_model(path: Path) -> tuple[bool, list[str]]:
    """Validate the already-migrated qwerty-model.json against the schema."""
    if not path.exists():
        return False, [f"missing: {path}"]
    data = load_json(path)
    notes: list[str] = []

    if not has_weight_envelope(data):
        notes.append("FAIL: top-level missing 'weight'")
        return False, notes

    common = data.get("commonDigraphs")
    if not isinstance(common, list):
        notes.append("FAIL: 'commonDigraphs' missing or not a list")
        return False, notes

    weighted = sum(1 for entry in common if has_weight_envelope(entry))
    notes.append(f"commonDigraphs: {len(common)} entries, {weighted} weighted")

    empirical = data.get("empirical")
    if isinstance(empirical, dict):
        emp_weighted = sum(1 for v in empirical.values() if has_weight_envelope(v))
        notes.append(
            f"empirical: {len(empirical)} keys, {emp_weighted} weighted"
        )

    if weighted == 0:
        notes.append("WARN: no commonDigraphs entries have weight envelopes")

    return weighted > 0, notes


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def run_migrations(apply: bool) -> int:
    failures = 0
    targets = [
        ("qwerty_baselines", QWERTY_BASELINES, migrate_qwerty_baselines),
        ("shell_markov", SHELL_MARKOV, migrate_shell_markov),
        ("ssh_timing", SSH_TIMING, migrate_ssh_timing_stats),
    ]
    for label, path, fn in targets:
        if not path.exists():
            print(f"[skip] {label}: {path} not found")
            continue
        try:
            new_data, notes, changed = fn(path)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[fail] {label}: {exc}")
            failures += 1
            continue

        mode = "APPLY" if apply else "DRY-RUN"
        marker = "CHANGED" if changed else "UNCHANGED"
        print(f"[{mode}] {label}: {path.relative_to(REPO_ROOT)} [{marker}]")
        for line in notes:
            print(f"        - {line}")

        if apply and changed:
            dump_json(path, new_data)
            print(f"        wrote {path}")

    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Persist changes to disk (default is dry-run).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="(default) Show what would change without writing.",
    )
    parser.add_argument(
        "--check-qwerty-model",
        action="store_true",
        help="Validate src/data/qwerty-model.json against the v2 schema only.",
    )
    args = parser.parse_args(argv)

    if args.check_qwerty_model:
        ok, notes = check_qwerty_model(QWERTY_MODEL)
        for line in notes:
            print(line)
        return 0 if ok else 1

    apply = args.apply and not args.dry_run
    return run_migrations(apply=apply)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))