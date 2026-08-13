#!/usr/bin/env python3
"""
Generate a mismatch report between decoded SSH transcript and payload text
heuristics, and propose QWERTY baseline parameters from observed inter-packet
delays.

Writes:
 - scripts/ssh_mismatches.json
 - scripts/ssh_proposed_qwerty_baselines.json
"""
import json
from pathlib import Path
from statistics import mean, median, pstdev

ROOT = Path(__file__).resolve().parents[1]
transcript_path = ROOT / "scripts" / "ssh_transcript.json"
stats_path = ROOT / "scripts" / "ssh_timing_stats.json"

if not transcript_path.exists() or not stats_path.exists():
    print("Run ssh_transcript_and_timing.py first")
    raise SystemExit(1)

transcript = json.loads(transcript_path.read_text())
stats = json.loads(stats_path.read_text())

packets = transcript.get("packets", [])

def is_printable_preview(s):
    if not s:
        return False
    # treat hex-only sequences (0-9a-f) as non-printable preview
    t = s.lower()
    # if contains letters/spaces/punctuation assume printable
    for ch in t:
        if ch.isalpha() or ch.isspace() or ch in ",./<>?;:'\"[]{}|`~!@#$%^&*()-=_+":
            return True
    # otherwise probably hex
    return False

mismatches = []
for p in packets:
    preview = p.get("payload_preview", "")
    decoded = p.get("decoded", {})
    likely_enc = decoded.get("ssh.likely_encrypted")
    printable = is_printable_preview(preview)
    # mismatch if preview looks printable but decoder thinks encrypted, or vice versa
    if printable and likely_enc:
        mismatches.append({"index": p.get("index"), "time": p.get("time"), "direction": p.get("direction"), "len": p.get("len"), "preview": preview[:200], "decoded": decoded})
    elif (not printable) and (likely_enc is False):
        mismatches.append({"index": p.get("index"), "time": p.get("time"), "direction": p.get("direction"), "len": p.get("len"), "preview": preview[:200], "decoded": decoded})

out_mismatch = ROOT / "scripts" / "ssh_mismatches.json"
out_mismatch.write_text(json.dumps({"mismatches_count": len(mismatches), "mismatches": mismatches[:200]}, indent=2))

# Propose baselines from client->server typing deltas
client_stats = stats.get("client_to_server", {})
deltas = client_stats.get("deltas_ms", [])
typing_deltas = [d for d in deltas if d is not None and d > 0 and d < 200]

if typing_deltas:
    med = median(typing_deltas)
    avg = mean(typing_deltas)
    std = pstdev(typing_deltas) if len(typing_deltas) > 1 else 0.0
else:
    med = avg = 19.0
    std = 6.0

# Scale heuristic baselines relative to the observed 'adjacent' digraph mean.
# The bundled defaults have adjacentKey mean=95; we scale other baselines by
# the ratio observed/95 to keep relative geometry.
bundle_adj_mean = 95.0
scale = med / bundle_adj_mean

proposed = {
    "version": 1,
    "baselines": {
        "sameKey": {"mean": 220, "std": 45},
        "adjacentKey": {"mean": round(med, 2), "std": round(std, 2)},
        "nearbyKey": {"mean": round(130 * scale, 2), "std": round(30 * scale, 2)},
        "farKey": {"mean": round(175 * scale, 2), "std": round(40 * scale, 2)},
        "crossRow": {"mean": round(200 * scale, 2), "std": round(50 * scale, 2)}
    },
    "notes": {
        "source": "ssh-session-oxasploits.com.pcap",
        "adjacent_empirical_median_ms": med,
        "adjacent_empirical_mean_ms": avg,
        "adjacent_empirical_std_ms": std,
        "typing_sample_count": len(typing_deltas),
    }
}

out_proposed = ROOT / "scripts" / "ssh_proposed_qwerty_baselines.json"
out_proposed.write_text(json.dumps(proposed, indent=2))

print(f"Wrote {out_mismatch} ({len(mismatches)} entries) and {out_proposed}")
