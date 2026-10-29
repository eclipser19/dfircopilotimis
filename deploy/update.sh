#!/usr/bin/env bash
# Updates the copilot from git (or from files you copied into /opt/dfir-copilot) and restarts it.
#   sudo /opt/dfir-copilot/deploy/update.sh            WHEELS=/path/to/wheels for no internet
# Running questions get up to 10 minutes to finish; one cut off is offered for Continue afterwards.
# Stored descriptions are rebuilt by themselves when the normalizer changed.
set -euo pipefail
APP=/opt/dfir-copilot
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0" >&2; exit 1; }
cd "$APP"
if git remote get-url origin >/dev/null 2>&1 && [ -z "${NO_PULL:-}" ]; then
  git pull --ff-only
fi
if [ -n "${WHEELS:-}" ]; then
  .venv/bin/pip install -q --no-index --find-links "$WHEELS" -r requirements-lock.txt
else
  .venv/bin/pip install -q -r requirements-lock.txt
fi
install -m 0755 deploy/dfir-admin /usr/local/bin/dfir-admin
if [ -d /run/systemd/system ]; then
  install -m 0644 deploy/systemd/* /etc/systemd/system/
  systemctl daemon-reload
fi
dfir-admin config_check || true
systemctl restart dfir-copilot
echo "Updated to $(git log -1 --format='%h %s' 2>/dev/null || echo 'the copied files') and restarted."
