#!/usr/bin/env python3
"""
Extract printable client->server keystrokes from the SSH transcript and
derive per-digraph timing statistics (mean, std, count).

Outputs:
 - scripts/ssh_empirical_digraphs.json
"""
import json
from pathlib import Path
from collections import defaultdict
from statistics import mean, pstdev

ROOT = Path(__file__).resolve().parents[1]
transcript_path = ROOT / "scripts" / "ssh_transcript.json"
out_path = ROOT / "scripts" / "ssh_empirical_digraphs.json"

if not transcript_path.exists():
    print("Run ssh_transcript_and_timing.py first")
    raise SystemExit(1)

data = json.loads(transcript_path.read_text())
packets = data.get("packets", [])

def printable_text(s):
    if not s:
        return ""
    try:
        # If looks like hex (only 0-9a-f), treat as non-printable
        low = s.lower()
        if all(ch in "0123456789abcdef" for ch in low.replace(" ","")):
            return ""
    except Exception:
        return ""
    # Trim control sequences
    return ''.join(ch for ch in s if 32 <= ord(ch) <= 126)

# Build a time-ordered list of client->server printable character events
events = []  # list of (time, char)
for p in sorted(packets, key=lambda x: x.get("time", 0)):
    if p.get("direction") != "C->S":
        continue
    preview = p.get("payload_preview", "")
    text = printable_text(preview)
    if not text:
        continue
    # Skip long payloads (likely paste/output); only accept short typed fragments
    if len(text) > 6:
        continue
    # If multiple printable chars in one packet, we cannot measure inter-char
    # delay inside the packet; treat packet as a single event carrying its
    # first char only (best-effort).
    first_char = text[0]
    events.append((p.get("time"), first_char.lower()))

if len(events) < 2:
    print("Not enough keystroke events found to derive digraphs")
    raise SystemExit(2)

# Build digraph delta lists
digraphs = defaultdict(list)
prev_time, prev_char = events[0]
for t, ch in events[1:]:
    if prev_char is None or ch is None:
        prev_time, prev_char = t, ch
        continue
    dt_ms = (t - prev_time) * 1000.0
    if dt_ms <= 0 or dt_ms > 2000:
        # ignore implausible long gaps
        prev_time, prev_char = t, ch
        continue
    key = (prev_char + ch)
    digraphs[key].append(dt_ms)
    prev_time, prev_char = t, ch

# Compute stats
empirical = {}
for k, vals in digraphs.items():
    if len(vals) < 3:
        continue
    empirical[k] = {
        "count": len(vals),
        "mean": round(mean(vals), 2),
        "std": round(pstdev(vals), 2),
    }

out_path.write_text(json.dumps({"digraphs": empirical, "total_events": len(events)}, indent=2))
print(f"Wrote {out_path} ({len(empirical)} digraphs / {len(events)} events)")
