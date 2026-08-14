#!/usr/bin/env python3
"""Targeted cleanup of remaining SSH key references and NAS path issues."""

import re

with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_data", "r", encoding="utf-8") as f:
    lines = f.readlines()

stats = {}
scrubbed = []

ssh_key_patterns = [
    # cat ~/.ssh/id_ed25519 (private key display)
    re.compile(r'^cat\s+~?\.ssh/id_ed25519(\.pub)?\s*$'),
    re.compile(r'^cat\s+~?\.ssh/id_ed25519(\.pub)?\s*\|'),
    # cat ~/.ssh/authorized_keys
    re.compile(r'^cat\s+~?\.ssh/authorized_keys\s*$'),
    # nano ~/.ssh/authorized_keys
    re.compile(r'^nano\s+~?\.ssh/authorized_keys\s*$'),
    # chmod 600 id_ed25519 / authorized_keys (operations on key files)
    re.compile(r'^chmod\s+600\s+(id_ed25519|authorized_keys)'),
    # scp ~/.ssh/id_ed25519*
    re.compile(r'^scp\s+~?\.ssh/id_ed25519'),
    # cp ~/.ssh/id_ed25519*
    re.compile(r'^cp\s+~?\.ssh/id_ed25519'),
    # echo ... >> authorized_keys
    re.compile(r"echo\s+.*>>\s+~?\.ssh/authorized_keys"),
]

for i, line in enumerate(lines):
    orig = line
    line = line.rstrip('\n')
    
    if not line.strip():
        scrubbed.append(line)
        continue
    
    removed = False
    for pat in ssh_key_patterns:
        if pat.search(line):
            scrubbed.append('')
            stats['ssh_key_line_removed'] = stats.get('ssh_key_line_removed', 0) + 1
            removed = True
            break
    
    if removed:
        continue
    
    # Also catch the chmod 600 id_ed25519-old line
    if re.match(r'^chmod\s+600\s+id_ed25519-old', line):
        scrubbed.append('')
        stats['ssh_key_line_removed'] = stats.get('ssh_key_line_removed', 0) + 1
        continue
    
    # The echo REDACTED_SSH_KEY line (line 2465) - it's already partially redacted but let's check
    if "REDACTED_SSH_KEY" in line and "authorized_keys" in line:
        # This is a redacted echo to authorized_keys - leave it, it's already safe
        pass
    
    scrubbed.append(line)

print("=== FINAL CLEANUP STATS ===")
for k, v in sorted(stats.items()):
    print(f"  {k}: {v}")

print(f"\nWriting {len(scrubbed)} lines...")
with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_data", "w", encoding="utf-8") as f:
    for line in scrubbed:
        f.write(line + "\n")
print("Done.")
