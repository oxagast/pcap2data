#!/usr/bin/env python3
"""Merge empirical digraphs from scripts/ssh_aligned_digraphs.json into
src/data/qwerty-model.json. Adds entries with count >= 3 unless already present.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
aligned_path = ROOT / "scripts" / "ssh_aligned_digraphs.json"
model_path = ROOT / "src" / "data" / "qwerty-model.json"

if not aligned_path.exists():
    print(f"Missing {aligned_path}")
    raise SystemExit(1)
if not model_path.exists():
    print(f"Missing {model_path}")
    raise SystemExit(1)

aligned = json.loads(aligned_path.read_text())
model = json.loads(model_path.read_text())
emp = model.get("empirical", {}) or {}

added = 0
for k, v in aligned.get("digraphs", {}).items():
    try:
        cnt = int(v.get("count", 0))
    except Exception:
        cnt = 0
    if cnt < 3:
        continue
    if k in emp:
        continue
    mean = float(v.get("mean", 0))
    std = float(v.get("std", 0))
    if not mean or not std:
        continue
    emp[k] = {"mean": round(mean, 2), "std": round(std, 2)}
    added += 1

model["empirical"] = emp
model_path.write_text(json.dumps(model, indent=4) + "\n")
print(f"Merged {added} new empirical digraphs into {model_path}")
