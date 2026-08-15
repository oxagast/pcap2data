#!/usr/bin/env python3
"""Scrub PII and problematic characters from shell_corpus."""

import re

with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_corpus.txt", "r", encoding="utf-8", errors="replace") as f:
    lines = f.readlines()

stats = {
    "home_marshall": 0,
    "home_mwhittaker": 0,
    "username_marshall": 0,
    "ssh_keys_removed": 0,
    "pgp_keys_removed": 0,
    "api_keys_removed": 0,
    "nas_paths": 0,
    "bearer_token_redacted": 0,
    "md5_hashes_redacted": 0,
    "email_filename_redacted": 0,
    "form_feed_removed": 0,
    "ansi_escape_removed": 0,
    "other_control_chars": 0,
    "lines_removed": 0,
}

scrubbed = []

# Patterns for lines to remove entirely (cat of sensitive files)
sensitive_cat_patterns = [
    # SSH keys
    re.compile(r'cat\s+~?\.ssh/(authorized_keys|id_ed25519(\.pub)?|id_rsa(\.pub)?|known_hosts)'),
    re.compile(r'cat\s+~?\.ssh/config\b'),
    # NAS keys
    re.compile(r'cat\s+/NAS/(key\.txt|sshkey\.txt)'),
    # Config files with potentially sensitive data
    re.compile(r'cat\s+~?\.config/packetsnitch/(config/settings\.json|theme-cache/.*|activity-log\.txt|hosts\.json)'),
    re.compile(r'cat\s+~?\.config/packetsnitch/sessions/.*'),
    # NPM logs
    re.compile(r'cat\s+~?\.npm/_logs/.*'),
    # App config
    re.compile(r'cat\s+~?\.local/share/applications/.*'),
    re.compile(r'cat\s+~?\.local/share/nvim/.*'),
    re.compile(r'cat\s+~?\.local/share/Trash/.*'),
    re.compile(r'cat\s+~?\.vscode/.*'),
    # History
    re.compile(r'cat\s+~?\.bash_history\b'),
    # Documents/Keys
    re.compile(r'cat\s+~?/Documents/Keys/.*'),
    re.compile(r'cat\s+~?/Documents/(keystroke.*|packet.*|packetsnitch.*|icalout.*|audio\.bin)'),
    re.compile(r'cat\s+~?/Documents/packet\.json\b'),
    # DLs
    re.compile(r'cat\s+~?/DLs/.*'),
    # Autosave
    re.compile(r'cat\s+~?/autosave\.json\b'),
    # blah2
    re.compile(r'cat\s+~?/blah2\.json\b'),
    # packet.json standalone
    re.compile(r'cat\s+~?/packet\.json\b'),
    # API keys
    re.compile(r'cat\s+paddle-api-key\b'),
    re.compile(r'cat\s+marshallwhittaker\.at\.gmail\.com\.sec\.key\.asc'),
    # PGP
    re.compile(r'cat\s+sec\.key\b'),
    re.compile(r'cat\s+~/decrypted-pgp-output\.txt'),
    # OpenVPN configs
    re.compile(r'cat\s+conductor\.ovpn\b'),
    re.compile(r'cat\s+~/Documents/Keys/openvpn-keys/watt\.ovpn'),
    # System files
    re.compile(r'cat\s+/etc/(passwd|group|fstab|auto\.master|os-release|sysctl\.conf|pam\.d/sudo.*|systemd/system/ollama\.service)'),
    re.compile(r'cat\s+/etc/(openvpn/client/.*)'),
    # http-body
    re.compile(r'cat\s+~/http-body\.bin\b'),
    re.compile(r'cat\s+~/hosts\.json\b'),
    # Specific download files with hash in name
    re.compile(r'cat\s+~/Downloads/imgbin_0865a419.*\.png'),
    re.compile(r'cat\s+~/Downloads/moon-clip-art.*\.png'),
    # PNGFind files
    re.compile(r'cat\s+~/Downloads/pngfind\.com-haruhi.*\.png'),
    # Activity log
    re.compile(r'cat\s+~?\.config/packetsnitch/activity-log\.txt'),
    # .ssh/id_ed25519.pub variations
    re.compile(r'cat\s+~?\.ssh/id_ed25519\.pub\s*\|?\s*(tb|wl-copy|wk-copy)'),
]

for i, line in enumerate(lines):
    orig = line
    line = line.rstrip('\n')
    
    # Skip completely empty lines
    if not line.strip():
        scrubbed.append(line)
        continue
    
    # Check if line should be removed
    removed = False
    for pat in sensitive_cat_patterns:
        if pat.search(line):
            scrubbed.append('')
            stats["lines_removed"] += 1
            removed = True
            break
    
    if removed:
        continue
    
    # 1. Remove form-feed characters (0x0C)
    if '\f' in line:
        line = line.replace('\f', '')
        stats["form_feed_removed"] += 1
    
    # 2. Remove ANSI escape sequences
    ansi_before = len(line)
    line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line)
    if len(line) < ansi_before:
        stats["ansi_escape_removed"] += 1
    
    # 3. Redact /home/marshall paths
    if '/home/marshall' in line:
        line = line.replace('/home/marshall', '/home/USER')
        stats["home_marshall"] += 1
    
    # 4. Redact /home/mwhittaker paths
    if '/home/mwhittaker' in line:
        line = line.replace('/home/mwhittaker', '/home/USER')
        stats["home_mwhittaker"] += 1
    
    # 5. Redact ~/ references (replace with /home/USER/)
    if re.search(r'(?<!/home/USER)\b~/', line):
        line = re.sub(r'\b~/', '/home/USER/', line)
        stats["tilde_home"] = stats.get("tilde_home", 0) + 1
    
    # 6. Handle "cd marshall" and "cd marshall-whittaker" 
    line = re.sub(r'\bcd\s+marshall-whittaker(/[^\s]*)?\b', 'cd USER-DIR', line)
    line = re.sub(r'\bcd\s+marshall\b(?!\s*\.)', 'cd USER', line)
    
    # 7. Handle "grep marshall" standalone
    line = re.sub(r'\bgrep\s+marshall\b', 'grep USER', line)
    
    # 8. Redact email in filename
    if 'marshallwhittaker.at.gmail.com' in line:
        line = re.sub(r'marshallwhittaker\.at\.gmail\.com', 'EMAIL_REDACTED', line)
        stats["email_filename_redacted"] += 1
    
    # 9. Redact Bearer token
    if re.search(r'Authorization:\s*Bearer\s+', line):
        line = re.sub(r'Authorization:\s*Bearer\s+\S+', 'Authorization: Bearer REDACTED', line)
        stats["bearer_token_redacted"] += 1
    
    # 10. Redact paddle-api-key references
    if re.search(r'paddle-api-key', line):
        line = re.sub(r'paddle-api-key', 'API_KEY_REDACTED', line)
        stats["api_keys_removed"] += 1
    
    # 11. Redact MD5 hashes in quoted strings (likely password hashes)
    if re.search(r'"[0-9a-f]{32}"', line):
        line = re.sub(r'"[0-9a-f]{32}"', '"REDACTED_HASH"', line)
        stats["md5_hashes_redacted"] += 1
    
    # 12. Redact NAS paths
    if '/NAS' in line or re.search(r'(?<!/NETWORK_STORAGE)/nas(/|$)', line):
        line = re.sub(r'/NAS(/[^\s]*)?', '/NETWORK_STORAGE', line)
        line = re.sub(r'(?<!/NETWORK_STORAGE)/nas(/[^\s]*)?', '/NETWORK_STORAGE', line)
        stats["nas_paths"] += 1
    
    # 13. Remove any remaining control characters (except \n, \t)
    cleaned = []
    for ch in line:
        o = ord(ch)
        if o < 32 and ch not in ('\n', '\t'):
            stats["other_control_chars"] += 1
            continue  # skip
        elif o == 127:  # DEL
            stats["other_control_chars"] += 1
            continue
        else:
            cleaned.append(ch)
    line = ''.join(cleaned)
    
    # 14. Track standalone "marshall" username remaining
    if re.search(r'\bmarshall\b', line) and '/home/USER' not in line and 'USER' not in line:
        stats["username_marshall"] += 1
    
    scrubbed.append(line)


# Stats summary
print("=== SCRUBBING COMPLETE ===")
print(f"Original lines: {len(lines)}")
print(f"Output lines: {len(scrubbed)}")
print()
for k, v in sorted(stats.items()):
    if v > 0:
        print(f"  {k}: {v}")

# Write result
with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_corpus.txt", "w", encoding="utf-8") as f:
    for line in scrubbed:
        f.write(line + "\n")

print("\nFile written successfully.")
