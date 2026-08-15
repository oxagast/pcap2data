#!/usr/bin/env python3
"""Remove SSH key cat/nano/scp/cp lines from shell_corpus."""

with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_corpus.txt", "r", encoding="utf-8") as f:
    lines = f.readlines()

target_prefixes = [
    "cat ~/.ssh/id_ed25519",
    "cat ~/.ssh/id_ed25519.pub",
    "cat ~/.ssh/authorized_keys",
    "nano ~/.ssh/authorized_keys",
    "chmod 600 .ssh/authorized_keys",
    "chmod 600 authorized_keys",
    "cp ~/.ssh/id_ed25519",
    "scp ~/.ssh/id_ed25519",
]

result = []
removed = 0

for line in lines:
    stripped = line.rstrip('\n')
    if not stripped.strip():
        result.append(line)
        continue
    
    keep = True
    for prefix in target_prefixes:
        if stripped.startswith(prefix):
            removed += 1
            keep = False
            break
    
    if keep:
        result.append(line)

print(f"Removed {removed} lines")

with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_corpus.txt", "w", encoding="utf-8") as f:
    for line in result:
        f.write(line)

print("Done.")
