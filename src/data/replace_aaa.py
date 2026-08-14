#!/usr/bin/env python3
"""Replace redaction placeholders with 'A' strings of the same length."""

import re

with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_data", "r", encoding="utf-8") as f:
    content = f.read()

# All redaction placeholder patterns we used
placeholders = [
    'REDACTED_USER',
    'REDACTED_EMAIL',
    'REDACTED_HASH',
    'REDACTED_KEYFILE',
    'REDACTED_SSH_KEY',
    'REDACTED_GPG_SECRET_EXPORT',
    'REDACTED',
    'API_KEY_REDACTED',
    'USER_REDACTED_FILENAME',
    'NETWORK_STORAGE',
    'USER',
    # Also catch /home/USER which replaced ~/ and /home/marshall, etc.
    '/home/USER',
]

# Sort by length descending to avoid partial overlaps
placeholders.sort(key=len, reverse=True)

replaced = 0
for ph in placeholders:
    # Replace all occurrences of this placeholder with A's of same length
    count = content.count(ph)
    if count > 0:
        replacement = 'A' * len(ph)
        content = content.replace(ph, replacement)
        replaced += count
        print(f"  {ph} ({len(ph)} chars) → {len(replacement)} A's × {count} occurrences")

print(f"\nTotal replacements: {replaced}")

with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_data", "w", encoding="utf-8") as f:
    f.write(content)

print("Done.")
