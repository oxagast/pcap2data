#!/usr/bin/env python3
"""Second-pass scrub: catch remaining PII in shell_corpus."""

import re

with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_corpus.txt", "r", encoding="utf-8") as f:
    lines = f.readlines()

stats = {}
scrubbed = []

for i, line in enumerate(lines):
    orig = line
    line = line.rstrip('\n')
    
    if not line.strip():
        scrubbed.append(line)
        continue
    
    # 1. Redact email addresses: marshall@oxasploits.com, marshallwhittaker@...
    email_patterns = [
        re.compile(r'marshall@oxasploits\.com'),
        re.compile(r'marshallwhittaker\.at\.gmail\.com'),
        re.compile(r'marshall@drift'),
    ]
    for pat in email_patterns:
        if pat.search(line):
            line = pat.sub('REDACTED_EMAIL', line)
            stats['email_redacted'] = stats.get('email_redacted', 0) + 1
    
    # 2. Redact output filenames that contain "marshall"
    # e.g. "marshall.jpg", "marshall.png", "marshall.asc", "marshall.at.oxasploits.com.sec.key"
    # But NOT paths that are already redacted
    if re.search(r'\bmarshall\.(jpg|png|asc|key|sec\.key)', line):
        line = re.sub(r'marshall\.(jpg|png|asc|key|sec\.key)', 'USER_REDACTED_FILENAME', line)
        stats['output_filename_redacted'] = stats.get('output_filename_redacted', 0) + 1
    
    # 3. Redact filename references like "marshall.at.oxasploits.com.sec.key"
    if re.search(r'marshall\.at\.oxasploits\.com\.sec\.key', line):
        line = re.sub(r'marshall\.at\.oxasploits\.com\.sec\.key', 'REDACTED_KEYFILE', line)
        stats['keyfile_redacted'] = stats.get('keyfile_redacted', 0) + 1
    
    # 4. Redact "cp ~/Documents/Keys/marshall..." 
    if re.search(r'cp\s+~?/?Documents/Keys/marshall', line):
        line = re.sub(r'cp\s+~?/?Documents/Keys/marshall[^ \t]*', 'cp REDACTED_KEYFILE', line)
        stats['cp_key_redacted'] = stats.get('cp_key_redacted', 0) + 1
    
    # 5. Redact GPG --export-secret-keys (sensitive operation)
    if re.search(r'gpg\s+.*--export-secret-keys', line):
        line = re.sub(r'gpg\s+.*--export-secret-keys.*', 'REDACTED_GPG_SECRET_EXPORT', line)
        stats['gpg_secret_export_redacted'] = stats.get('gpg_secret_export_redacted', 0) + 1
    
    # 6. Redact the SSH public key fingerprint line (contains real key material)
    if re.search(r'ssh-ed25519\s+AAAAC3NzaC1lZDI1NTE5', line):
        line = re.sub(r'ssh-ed25519\s+AAAAC3NzaC1lZDI1NTE5[^\s]+\s+\S+', 'REDACTED_SSH_KEY', line)
        stats['ssh_key_redacted'] = stats.get('ssh_key_redacted', 0) + 1
    
    # 7. Redact "echo marshall" standalone
    if re.search(r'echo\s+marshall\s*\|', line):
        line = re.sub(r'echo\s+marshall\s*\|', 'echo REDACTED_USER |', line)
        stats['echo_marshall_redacted'] = stats.get('echo_marshall_redacted', 0) + 1
    
    # 8. Redact fprintd-list marshall
    if re.search(r'fprintd-list\s+marshall\b', line):
        line = re.sub(r'fprintd-list\s+marshall\b', 'fprintd-list REDACTED_USER', line)
        stats['fprintd_redacted'] = stats.get('fprintd_redacted', 0) + 1
    
    # 9. Redact "convert ... marshall.jpg" and "convert ... marshall.png"
    if re.search(r'convert\s+.*\s+marshall\.(jpg|png)\s*$', line):
        line = re.sub(r'convert\s+.*\s+marshall\.(jpg|png)\s*$', 'convert REDACTED_INPUT REDACTED_OUTPUT', line)
        stats['convert_redacted'] = stats.get('convert_redacted', 0) + 1
    
    # 10. Redact "echo marshall | sp" / "echo marshall | spaste"
    if re.search(r'echo\s+marshall\s*\|', line):
        line = re.sub(r'echo\s+marshall\s*\|', 'echo REDACTED_USER |', line)
    
    # 11. Remove any residual ~/ that wasn't caught
    if re.search(r'(?<!/home/USER)\b~/', line):
        line = re.sub(r'\b~/', '/home/USER/', line)
    
    scrubbed.append(line)

print("=== SECOND PASS STATS ===")
for k, v in sorted(stats.items()):
    print(f"  {k}: {v}")

print(f"\nWriting {len(scrubbed)} lines...")
with open("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_corpus.txt", "w", encoding="utf-8") as f:
    for line in scrubbed:
        f.write(line + "\n")
print("Done.")
