#!/usr/bin/env bash
# Install script for the PacketSnitch metrics endpoint.
#
# This script is intentionally short: it copies the binary + systemd
# unit into the right system locations, then lays down a starter
# config file at /etc/ps-metrics.yaml and generates an admin API key
# on first run.
#
# Re-run safely: any existing config file or admin key is preserved,
# so you can re-run after pulling new changes without breaking the
# running service.
#
# EDIT knobs (defaults shown):
#   USER / GROUP      packetsnitch / packetsnitch   -- the system user
#                                                  that owns the data
#                                                  dir and runs the
#                                                  service.
#   CONFIG_PATH       /etc/ps-metrics.yaml          -- the config file
#                                                  the unit will load.
#   ADMIN_KEY_PATH    /etc/ps-metrics-admin-key    -- the file where
#                                                  the admin API key
#                                                  is stored, mode
#                                                  0640, readable by
#                                                  the service user.
#   DATA_DIR          /var/log/packetsnitch-metrics -- where NDJSON
#                                                  files are written.
set -euo pipefail

# EDIT -- change USER/GROUP if you don't want to create a dedicated
# service account. The default installs a system-wide unit that runs
# as an unprivileged user.
USER=packetsnitch
GROUP=packetsnitch
CONFIG_PATH=/etc/ps-metrics.yaml
ADMIN_KEY_PATH=/etc/ps-metrics-admin-key
DATA_DIR=/var/log/packetsnitch-metrics

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Installing PacketSnitch Metrics Server"

# 1. Make sure the service user + data dir exist. id/create lazy so
#    re-running this script is idempotent.
if ! getent group "$GROUP" >/dev/null; then
    groupadd --system "$GROUP"
fi
if ! id "$USER" >/dev/null 2>&1; then
    useradd --system --gid "$GROUP" --home-dir "$DATA_DIR" \
        --shell /usr/sbin/nologin "$USER"
fi

mkdir -p "$DATA_DIR"
chown "$USER:$GROUP" "$DATA_DIR"
chmod 0750 "$DATA_DIR"

# 2. Copy the binary + unit file. Both are marked read-only for root
#    so the service user can't tamper with them.
install -m 0755 -o root -g root \
    "$REPO_ROOT/src/metrics/ps-metrics.py" /usr/local/bin/ps-metrics.py
# EDIT -- swap this for /usr/lib/systemd/system/ if your distro
# refuses to load units from /etc/systemd/system (notably Debian).
install -m 0644 -o root -g root \
    "$REPO_ROOT/src/metrics/packetsnitch-metrics.service" \
    /etc/systemd/system/packetsnitch-metrics.service

# 3. Lay down a config file on first run. Operators can edit it
#    after install without losing their changes on the next upgrade.
if [[ ! -f "$CONFIG_PATH" ]]; then
    echo "Generating starter config at $CONFIG_PATH"
    python3 /usr/local/bin/ps-metrics.py --generate-config "$CONFIG_PATH"
    chmod 0640 "$CONFIG_PATH"
    chown root:"$GROUP" "$CONFIG_PATH"
fi

# 4. Make sure an admin API key exists. Generate one if missing and
#    store it in a separate file so it can be rotated without
#    touching the rest of the config. The file is readable only by
#    the service group so the service user cannot read it directly;
#    the key is loaded into the running config via the YAML file.
if [[ ! -s "$ADMIN_KEY_PATH" ]]; then
    echo "Generating admin API key at $ADMIN_KEY_PATH"
    python3 /usr/local/bin/ps-metrics.py --generate-api-key > "$ADMIN_KEY_PATH"
    chmod 0640 "$ADMIN_KEY_PATH"
    chown root:"$GROUP" "$ADMIN_KEY_PATH"
fi

# 5. Insert the admin key into the YAML config if admin.api_key is
#    still empty. This keeps the config file the single source of
#    truth that the systemd unit reads.
ADMIN_KEY="$(tr -d '\r\n' < "$ADMIN_KEY_PATH")"
if [[ -n "$ADMIN_KEY" ]] && python3 - "$CONFIG_PATH" "$ADMIN_KEY" <<'PY'
import re, sys
path, key = sys.argv[1], sys.argv[2]
with open(path) as f:
    text = f.read()
if re.search(r'^\s*api_key:\s*"[^"]+"', text, flags=re.MULTILINE):
    sys.exit(0)
new = re.sub(
    r'(^admin:\n(?:[ \t]*#.*\n)*)',
    r'\1  api_key: "%s"\n' % key,
    text,
    count=1,
    flags=re.MULTILINE,
)
if new != text:
    with open(path, "w") as f:
        f.write(new)
    sys.exit(0)
sys.exit(1)
PY
then
    :
fi

# 6. Hand the data dir to the service user (the config + key files
#    are already owned correctly).
chown "$USER:$GROUP" "$DATA_DIR" -R

# 7. Activate the unit.
systemctl daemon-reload
systemctl enable --now packetsnitch-metrics

# 8. Smoke check: the server should respond to /healthz. If this
#    fails, the operator can `journalctl -u packetsnitch-metrics`
#    to see what went wrong.
echo "Service status:"
systemctl --no-pager status packetsnitch-metrics || true
echo
echo "Health check:"
if command -v curl >/dev/null 2>&1; then
    curl -s --max-time 5 http://127.0.0.1:8088/healthz || true
    echo
fi
echo "Admin API key (stored at):"
echo "  $ADMIN_KEY_PATH"
