#!/usr/bin/env python3
"""Merge empirical digraphs from scripts/ssh_aligned_digraphs.json into
src/data/qwerty-model.json. Adds entries with count >= 3 unless already
present. New entries are written with v2 weight envelopes (see
scripts/WEIGHT_SCHEMA.md). Legacy v1 entries (no nested ``weight`` object)
are upgraded in place so the file ends up uniformly v2.
"""
import datetime
import json
from pathlib import Path


def derive_weight_and_tags(count: int) -> tuple[float, list[str]]:
    """Map observation count to a v2 weight value and tag list.

    The mapping mirrors the v2 schema's intent:

    - count >= 400: high weight (0.92) — plenty of data, treat as
      near-ground truth.
    - count 200–399: medium weight (0.85) — usable, blend toward
      published prior.
    - count 50–199: low weight (0.72) — sparse; trainer should still
      let it update, but not dominate the prior.
    - count < 50: very low weight (0.55) — essentially a seed.
    """
    if count >= 400:
        return 0.92, ["digraph", "empirical-dense"]
    if count >= 200:
        return 0.85, ["digraph", "empirical"]
    if count >= 50:
        return 0.72, ["digraph", "empirical-sparse"]
    return 0.55, ["digraph", "empirical-seed"]


def today_iso() -> str:
    return datetime.date.today().isoformat()


def make_envelope(count: int, mean_ms: float, std_ms: float) -> dict:
    """Build a v2 weight envelope for an empirical digraph entry."""
    weight, tags = derive_weight_and_tags(count)
    variance = round(std_ms * std_ms, 4) if std_ms else None
    return {
        "weight": weight,
        "count": count,
        "source": "empirical",
        "lastUpdated": today_iso(),
        "variance": variance,
        "tags": tags,
    }


def has_v2_envelope(entry: dict) -> bool:
    """True when the entry already carries the v2 nested weight object."""
    env = entry.get("weight")
    return (
        isinstance(env, dict)
        and "weight" in env
        and "count" in env
        and "source" in env
    )


def upgrade_legacy(existing: dict, src_count: int, mean: float, std: float) -> None:
    """Bring a legacy v1 entry up to the v2 shape in place."""
    existing["mean"] = round(mean, 2)
    existing["std"] = round(std, 2)
    existing["weight"] = make_envelope(src_count, mean, std)


def main() -> int:
    aligned_path = Path(__file__).resolve().parents[1] / "scripts" / "ssh_aligned_digraphs.json"
    model_path = Path(__file__).resolve().parents[1] / "src" / "data" / "qwerty-model.json"

    if not aligned_path.exists():
        print(f"Missing {aligned_path}")
        return 1
    if not model_path.exists():
        print(f"Missing {model_path}")
        return 1

    aligned = json.loads(aligned_path.read_text())
    model = json.loads(model_path.read_text())
    emp = model.get("empirical", {}) or {}

    added = 0
    upgraded = 0
    skipped = 0
    for k, v in aligned.get("digraphs", {}).items():
        try:
            cnt = int(v.get("count", 0))
        except Exception:
            cnt = 0
        if cnt < 3:
            continue
        mean = float(v.get("mean", 0))
        std = float(v.get("std", 0))
        if not mean or not std:
            continue

        if k in emp:
            if has_v2_envelope(emp[k]):
                skipped += 1
            else:
                upgrade_legacy(emp[k], cnt, mean, std)
                upgraded += 1
            continue

        emp[k] = {
            "mean": round(mean, 2),
            "std": round(std, 2),
            "weight": make_envelope(cnt, mean, std),
        }
        added += 1

    # Bump metadata so the file is unambiguously v2.
    meta = model.setdefault("metadata", {})
    if meta.get("schemaVersion") != 2:
        meta["schemaVersion"] = 2
    meta["lastUpdated"] = today_iso()
    meta.setdefault(
        "notes",
        "Weight envelopes added on baselines and empirical entries per scripts/WEIGHT_SCHEMA.md.",
    )
    model["empirical"] = emp

    model_path.write_text(json.dumps(model, indent=4) + "\n")
    print(
        f"Merged {added} new, upgraded {upgraded} legacy entries, "
        f"skipped {skipped} already-v2 entries in {model_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())