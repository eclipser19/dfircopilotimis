#!/usr/bin/env bash
# Installs DFIR Copilot as a service on SANS SIFT (Ubuntu 22.04) or Ubuntu 24.04. Run as root from the
# checkout at /opt/dfir-copilot:      sudo /opt/dfir-copilot/deploy/install.sh
# It prepares the machine (packages, the dfir account, folders, Python environment, the service), then runs
# `python -m copilot.install setup` as that account, which asks its questions (model, certificate, first admin)
# and installs Velociraptor. Safe to run again: everything that exists is kept.
#
# Options (environment variables):
#   WHEELS=/path/to/wheels        Python packages from this folder (no internet: DEPLOY.md, Linux)
#   VELOCIRAPTOR_BIN=/path/file   use this velociraptor-v0.77.2-linux-amd64 instead of downloading it
#                                 (checked against the SHA-256 the installer pins)
#   INVESTIGATOR_NET=10.20.0.0/16 turn the firewall on: only this network reaches the web app
#   ADMIN_NET=10.20.5.0/24        ... and SSH (22); default INVESTIGATOR_NET
#   SKIP_APT=1                    do not install Ubuntu packages
set -euo pipefail

APP=/opt/dfir-copilot
DATA=/srv/dfir
CONF=/etc/dfir-copilot
HERE="$(cd "$(dirname "$0")/.." && pwd)"

say()  { printf '\n[*] %s\n' "$*"; }
warn() { printf '\n[!] %s\n' "$*" >&2; }
die()  { printf '\n[x] %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo $0"
[ "$HERE" = "$APP" ] || die "The checkout must be at $APP (it is at $HERE): sudo git clone <repository> $APP"
. /etc/os-release 2>/dev/null || true
case "${VERSION_ID:-}" in
  22.04|24.04) ;;
  *) warn "Tested on Ubuntu 22.04 (SIFT) and 24.04; this is ${PRETTY_NAME:-unknown}. Going on." ;;
esac

if [ "${SKIP_APT:-0}" != 1 ]; then
  say "Ubuntu packages"
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3 python3-venv python3-dev build-essential git \
    sqlite3 rsync ufw sudo
fi
PY=$(command -v python3) || die "python3 is missing"
"$PY" -c 'import sys; sys.exit(not (3, 10) <= sys.version_info[:2] <= (3, 12))' \
  || die "Python 3.10-3.12 is needed; this is $("$PY" -V)"

say "Service account 'dfir', folders"
id dfir >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin dfir
install -d -o dfir -g dfir -m 0750 "$DATA" "$DATA/cases" "$DATA/evidence" "$DATA/backups" "$DATA/work"
# The data of the case the app opens before one is picked (the code folder's case.yaml): the app runs in the
# code folder, which belongs to root, so this one folder in it belongs to the service account.
install -d -o dfir -g dfir -m 0750 "$APP/case_data"
# Settings, accounts and the API key live outside the code folder; the service account writes them in setup.
install -d -o root -g dfir -m 0770 "$CONF"
if [ ! -f "$CONF/env" ]; then
  cat > "$CONF/env" <<EOF
# Read by the dfir-copilot service and by dfir-admin. Add HTTPS_PROXY=http://proxy:port if the model endpoint
# is reached through a proxy (and NO_PROXY=localhost,127.0.0.1).
DFIR_SETTINGS=$CONF/server.yaml
DFIR_AUTH_FILE=$CONF/auth.yaml
DFIR_API_CONFIG=$CONF/api_client.yaml
DFIR_CASES_DIR=$DATA/cases
DFIR_LEARNED_FILE=$DATA/learned_knowledge.yaml
HOME=$DATA
EOF
  chown root:dfir "$CONF/env"; chmod 0640 "$CONF/env"
fi

say "Python environment ($APP/.venv)"
[ -x "$APP/.venv/bin/python" ] || "$PY" -m venv "$APP/.venv"
if [ -n "${WHEELS:-}" ]; then
  "$APP/.venv/bin/pip" install -q --no-index --find-links "$WHEELS" -r "$APP/requirements-lock.txt"
else
  "$APP/.venv/bin/pip" install -q --upgrade pip
  "$APP/.venv/bin/pip" install -q -r "$APP/requirements-lock.txt"
fi

if [ -n "${VELOCIRAPTOR_BIN:-}" ]; then
  say "Velociraptor from $VELOCIRAPTOR_BIN"
  want=$(cd "$APP" && "$APP/.venv/bin/python" -c 'from copilot import install; print(install.VELOCIRAPTOR_BUILDS["linux"][1])')
  have=$(sha256sum "$VELOCIRAPTOR_BIN" | cut -d' ' -f1)
  [ "$have" = "$want" ] || die "Its SHA-256 is $have, not the pinned $want: not used."
  install -d -o dfir -g dfir -m 0750 "$DATA/velociraptor"
  install -o dfir -g dfir -m 0755 "$VELOCIRAPTOR_BIN" "$DATA/velociraptor/velociraptor"
fi

say "Admin command and service"
install -m 0755 "$APP/deploy/dfir-admin" /usr/local/bin/dfir-admin
if [ -d /run/systemd/system ]; then
  install -m 0644 "$APP"/deploy/systemd/* /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now dfir-backup.timer >/dev/null
  # The copilot itself starts with start.sh: in a window, or --background to keep it running and start at boot.
else
  warn "No systemd here: the service is not installed (sudo /opt/dfir-copilot/start.sh runs it in a window)."
fi

if [ -t 0 ]; then
  say "Setup (questions: model, certificate, first admin; Velociraptor is installed here)"
  dfir-admin install setup
else
  warn "No terminal to answer setup's questions: run  sudo dfir-admin install setup  yourself."
fi

if [ -n "${INVESTIGATOR_NET:-}" ]; then
  say "Firewall: the web app from $INVESTIGATOR_NET, SSH from ${ADMIN_NET:-$INVESTIGATOR_NET}"
  port=$(sed -n 's/^ *port: *\([0-9]\+\).*/\1/p' "$CONF/server.yaml" 2>/dev/null | head -1)
  ufw allow from "${ADMIN_NET:-$INVESTIGATOR_NET}" to any port 22 proto tcp
  ufw allow from "$INVESTIGATOR_NET" to any port "${port:-8501}" proto tcp
  ufw default deny incoming
  ufw default allow outgoing
  ufw --force enable
fi
