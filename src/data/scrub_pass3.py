#!/usr/bin/env python3
"""Final pass: catch remaining bare username 'marshall' in commands."""

import re

with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_corpus.txt", "r", encoding="utf-8") as f:
    lines = f.readlines()

stats = {}
scrubbed = []

# Commands where marshall is used as a username (PII)
username_in_cmd_patterns = [
    # ssh marshall
    re.compile(r'\bssh\s+marshall\b'),
    # sudo chown marshall
    re.compile(r'chown\s+marshall:'),
    re.compile(r'chown\s+marshall\s'),
    # sudo groupadd ... marshall
    re.compile(r'groupadd\s+.*\s-U\s+marshall\b'),
    re.compile(r'groupadd\s+.*-G\s+marshall\b'),
    # howdy test -U marshall
    re.compile(r'howdy\s+test\s+-U\s+marshall\b'),
    # sudo su marshall
    re.compile(r'sudo\s+su\s+marshall\b'),
    # gpg --enarmour marshall.at (partial email)
    re.compile(r'gpg\s+--enarmour\s+marshall\.at'),
    # fprintd-list marshall
    re.compile(r'fprintd-list\s+marshall\b'),
    # echo marshall |
    re.compile(r'echo\s+marshall\s*\|'),
]

for i, line in enumerate(lines):
    orig = line
    line = line.rstrip('\n')
    
    if not line.strip():
        scrubbed.append(line)
        continue
    
    changed = False
    
    for pat in username_in_cmd_patterns:
        if pat.search(line):
            line = pat.sub(lambda m: m.group(0).replace('marshall', 'REDACTED_USER'), line)
            stats['username_cmd_redacted'] = stats.get('username_cmd_redacted', 0) + 1
            changed = True
    
    # Also catch any remaining standalone "marshall" that's clearly a username
    # in commands like "scp ... marshall@...", "ssh marshall@...", etc.
    if not changed and re.search(r'\bmarshall@', line):
        line = re.sub(r'\bmarshall@', 'REDACTED_USER@', line)
        stats['marshall_at_redacted'] = stats.get('marshall_at_redacted', 0) + 1
        changed = True
    
    scrubbed.append(line)

print("=== FINAL PASS STATS ===")
for k, v in sorted(stats.items()):
    print(f"  {k}: {v}")

print(f"\nWriting {len(scrubbed)} lines...")
with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_corpus.txt", "w", encoding="utf-8") as f:
    for line in scrubbed:
        f.write(line + "\n")
print("Done.")
