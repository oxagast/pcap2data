#!/usr/bin/env python3
"""Final targeted cleanup - catch all SSH key references."""

import re

with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_corpus.txt", "r", encoding="utf-8") as f:
    lines = f.readlines()

stats = {}
scrubbed = []

for line in lines:
    orig = line
    line = line.rstrip('\n')
    
    if not line.strip():
        scrubbed.append(line)
        continue
    
    removed = False
    
    # Cat of private key (id_ed25519 without .pub)
    if re.match(r'^cat\s+~?\.ssh/id_ed25519\s*$', line):
        scrubbed.append('')
        stats['removed'] = stats.get('removed', 0) + 1
        removed = True
    
    # Cat of private key with pipe
    if re.match(r'^cat\s+~?\.ssh/id_ed25519\s*\|', line):
        scrubbed.append('')
        stats['removed'] = stats.get('removed', 0) + 1
        removed = True
    
    # Cat of public key (id_ed25519.pub) - any form
    if re.match(r'^cat\s+~?\.ssh/id_ed25519\.pub\s*\|?', line):
        scrubbed.append('')
        stats['removed'] = stats.get('removed', 0) + 1
        removed = True
    
    # nano ~/.ssh/authorized_keys
    if re.match(r'^nano\s+~?\.ssh/authorized_keys\s*$', line):
        scrubbed.append('')
        stats['removed'] = stats.get('removed', 0) + 1
        removed = True
    
    # chmod 600 .ssh/authorized_keys (with dot prefix)
    if re.match(r'^chmod\s+600\s+\.ssh/authorized_keys', line):
        scrubbed.append('')
        stats['removed'] = stats.get('removed', 0) + 1
        removed = True
    
    # chmod 600 authorized_keys (without dot)
    if re.match(r'^chmod\s+600\s+authorized_keys', line):
        scrubbed.append('')
        stats['removed'] = stats.get('removed', 0) + 1
        removed = True
    
    # cp ~/.ssh/id_ed25519*
    if re.match(r'^cp\s+~?\.ssh/id_ed25519', line):
        scrubbed.append('')
        stats['removed'] = stats.get('removed', 0) + 1
        removed = True
    
    # scp ~/.ssh/id_ed25519*
    if re.match(r'^scp\s+~?\.ssh/id_ed25519', line):
        scrubbed.append('')
        stats['removed'] = stats.get('removed', 0) + 1
        removed = True
    
    if removed:
        continue
    
    scrubbed.append(line)

print("=== TARGETED CLEANUP STATS ===")
for k, v in sorted(stats.items()):
    print(f"  {k}: {v}")

print(f"\nWriting {len(scrubbed)} lines...")
with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_corpus.txt", "w", encoding="utf-8") as f:
    for line in scrubbed:
        f.write(line + "\n")
print("Done.")
