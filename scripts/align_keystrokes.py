#!/usr/bin/env python3
"""
Best-effort aligner: extract user-typed characters from the terminal typescript
(`ssh.session.script.txt`) using the visible prompt marker `──>` and map them
sequentially to client->server packet timestamps in `scripts/ssh_transcript.json`.

Outputs:
 - scripts/ssh_aligned_digraphs.json

This is heuristic and will be noisy; inspect results before merging.
"""
import json
import re
from pathlib import Path
from statistics import mean, pstdev
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
transcript_path = ROOT / "scripts" / "ssh_transcript.json"
session_path = ROOT / "ssh.session.script.txt"
out_path = ROOT / "scripts" / "ssh_aligned_digraphs.json"

if not transcript_path.exists() or not session_path.exists():
    print("Missing required files: run earlier steps and ensure ssh.session.script.txt is present")
    raise SystemExit(1)

transcript = json.loads(transcript_path.read_text())
packets = [p for p in sorted(transcript.get("packets", []), key=lambda x: x.get("time", 0)) if p.get("direction") == "C->S"]

# Extract user input fragments from the typescript by locating the prompt arrow '──>'
inputs = []
arrow_re = re.compile(r'──>\s*(.*)')
with session_path.open(errors='ignore') as fh:
    for line in fh:
        m = arrow_re.search(line)
        if m:
            txt = m.group(1).rstrip('\n')
            # strip ANSI escape sequences
            txt = re.sub(r'\x1B\[[0-9;?]*[A-Za-z]', '', txt)
            txt = txt.strip()
            if txt:
                inputs.append(txt)

if not inputs:
    print("No input fragments found using '──>' heuristic")
    raise SystemExit(2)

# Flatten inputs into characters
chars = []
for frag in inputs:
    # keep printable subset
    for ch in frag:
        if 32 <= ord(ch) <= 126:
            chars.append(ch.lower())

if len(chars) < 10:
    print(f"Too few chars extracted ({len(chars)}) — aborting")
    raise SystemExit(3)

# Map characters sequentially to client->server packet timestamps
event_times = [p.get('time') for p in packets]
if len(event_times) < len(chars):
    print(f"Fewer C->S packets ({len(event_times)}) than extracted chars ({len(chars)}). Truncating chars.")
    chars = chars[:len(event_times)]
else:
    event_times = event_times[:len(chars)]

# Build digraphs
digraphs = defaultdict(list)
for i in range(len(chars)-1):
    a = chars[i]
    b = chars[i+1]
    dt_ms = (event_times[i+1] - event_times[i]) * 1000.0
    if dt_ms <= 0 or dt_ms > 2000:
        continue
    key = a + b
    digraphs[key].append(dt_ms)

# Compute stats
empirical = {}
for k, vals in digraphs.items():
    if len(vals) < 3:
        continue
    empirical[k] = {"count": len(vals), "mean": round(mean(vals),2), "std": round(pstdev(vals),2)}

out_path.write_text(json.dumps({"chars_mapped": len(chars), "digraphs": empirical}, indent=2))
print(f"Wrote {out_path} with {len(empirical)} digraphs from {len(chars)} mapped chars")
