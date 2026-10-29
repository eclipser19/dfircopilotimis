#!/usr/bin/env bash
# Installs DFIR Copilot as a service on Ubuntu 22.04 (SANS SIFT) or 24.04. Run as root from the checkout
# at /opt/dfir-copilot:   sudo /opt/dfir-copilot/deploy/install.sh
# Safe to run again: it creates what is missing and keeps existing settings, keys and data.
#
# Options (environment variables):
#   VELOCIRAPTOR_BIN=/path/to/velociraptor-v0.77.2-linux-amd64   installs that binary as /usr/local/bin/velociraptor
#   WHEELS=/path/to/wheels        install the Python packages from this folder (no internet; see deploy/README.md)
#   INVESTIGATOR_NET=10.20.0.0/16 turn the firewall on: only this network reaches the web page (8501)
#   ADMIN_NET=10.20.5.0/24        ... and SSH (22); default: INVESTIGATOR_NET
#   SKIP_APT=1                    do not install Ubuntu packages (already there, or no package mirror)
set -euo pipefail

APP=/opt/dfir-copilot
DATA=/srv/dfir
CONF=/etc/dfir-copilot
VR=/usr/local/bin/velociraptor
HERE="$(cd "$(dirname "$0")/.." && pwd)"

say()  { printf '\n[*] %s\n' "$*"; }
warn() { printf '\n[!] %s\n' "$*" >&2; }
die()  { printf '\n[x] %s\n' "$*" >&2; exit 1; }
as_dfir() { (cd "$DATA" && sudo -u dfir -H "$@"); }

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo $0"
[ "$HERE" = "$APP" ] || die "The checkout must be at $APP (it is at $HERE): git clone <repo> $APP"
. /etc/os-release 2>/dev/null || true
case "${VERSION_ID:-}" in
  22.04|24.04) ;;
  *) warn "Tested on Ubuntu 22.04 (SIFT) and 24.04; this is ${PRETTY_NAME:-unknown}. Going on." ;;
esac

if [ "${SKIP_APT:-0}" != 1 ]; then
  say "Ubuntu packages"
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3 python3-venv python3-dev build-essential git \
    sqlite3 openssl rsync ufw sudo
fi
PY=$(command -v python3) || die "python3 is missing"
"$PY" -c 'import sys; sys.exit(not (3, 10) <= sys.version_info[:2] <= (3, 12))' \
  || die "Python 3.10-3.12 is needed; this is $("$PY" -V)"

say "Service account 'dfir' and folders"
id dfir >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin dfir
install -d -o dfir -g dfir -m 0750 "$DATA" "$DATA"/{cases,memory,symbols,yara,evidence,deaddisk,velociraptor,backups,work}
install -d -o root -g dfir -m 0750 "$CONF" "$CONF/tls"

say "Python environment ($APP/.venv)"
[ -x "$APP/.venv/bin/python" ] || "$PY" -m venv "$APP/.venv"
if [ -n "${WHEELS:-}" ]; then
  "$APP/.venv/bin/pip" install -q --no-index --find-links "$WHEELS" -r "$APP/requirements-lock.txt"
else
  "$APP/.venv/bin/pip" install -q --upgrade pip
  "$APP/.venv/bin/pip" install -q -r "$APP/requirements-lock.txt"
fi

say "Velociraptor"
if [ -n "${VELOCIRAPTOR_BIN:-}" ]; then
  install -m 0755 "$VELOCIRAPTOR_BIN" "$VR"
fi
[ -x "$VR" ] || die "Velociraptor is missing. Download velociraptor-v0.77.2-linux-amd64 from \
https://github.com/Velocidex/velociraptor/releases, copy it here, then run again with VELOCIRAPTOR_BIN=<that file>."
"$VR" version | sed -n 's/^version: /    version /p'
if [ ! -f "$DATA/velociraptor/server.config.yaml" ]; then
  # Everything on localhost: only the copilot (API) and the dead-disk clients (frontend) talk to it.
  merge=$(printf '{"Frontend":{"bind_address":"127.0.0.1"},"GUI":{"bind_address":"127.0.0.1"},"API":{"bind_address":"127.0.0.1"},"Client":{"server_urls":["https://localhost:8000/"]},"Datastore":{"location":"%s","filestore_directory":"%s"}}' \
    "$DATA/velociraptor/datastore" "$DATA/velociraptor/datastore")
  as_dfir "$VR" config generate --merge "$merge" > "$DATA/velociraptor/server.config.yaml"
  chown dfir:dfir "$DATA/velociraptor/server.config.yaml"
  chmod 0600 "$DATA/velociraptor/server.config.yaml"
fi
if [ ! -f "$DATA/velociraptor/client.config.yaml" ]; then
  as_dfir "$VR" --config "$DATA/velociraptor/server.config.yaml" config client > "$DATA/velociraptor/client.config.yaml"
  chown dfir:dfir "$DATA/velociraptor/client.config.yaml"
fi
if [ ! -f "$CONF/api_client.yaml" ]; then
  # The investigator role can collect artifacts but cannot run commands on the server or write its files.
  as_dfir "$VR" --config "$DATA/velociraptor/server.config.yaml" config api_client --name dfir_copilot \
    --role investigator "$DATA/velociraptor/api_client.yaml" >/dev/null
  install -o root -g dfir -m 0640 "$DATA/velociraptor/api_client.yaml" "$CONF/api_client.yaml"
  rm -f "$DATA/velociraptor/api_client.yaml"
fi

say "Copilot settings ($CONF)"
if [ ! -f "$CONF/server.yaml" ]; then
  sed -e "s#images_dir: .*#images_dir: '$DATA/memory'#" -e "s#symbols_dir: .*#symbols_dir: '$DATA/symbols'#" \
      -e "s#\# yara_dir: .*#yara_dir: '$DATA/yara'#" "$APP/server.example.yaml" > "$CONF/server.yaml"
  chown root:dfir "$CONF/server.yaml"; chmod 0660 "$CONF/server.yaml"
fi
[ -f "$CONF/auth.yaml" ] || install -o dfir -g dfir -m 0600 /dev/null "$CONF/auth.yaml"
if [ ! -f "$CONF/env" ]; then
  cat > "$CONF/env" <<EOF
# Read by the dfir-copilot service and by dfir-admin. Add HTTPS_PROXY=http://proxy:port if the model
# endpoint is reached through a proxy, and DFIR_LLM_API_KEY=... if the key is not in server.yaml.
DFIR_SETTINGS=$CONF/server.yaml
DFIR_AUTH_FILE=$CONF/auth.yaml
DFIR_API_CONFIG=$CONF/api_client.yaml
DFIR_CASES_DIR=$DATA/cases
DFIR_LEARNED_FILE=$DATA/learned_knowledge.yaml
HOME=$DATA
EOF
  chown root:dfir "$CONF/env"; chmod 0640 "$CONF/env"
fi
if [ ! -f "$CONF/tls/cert.pem" ]; then
  # Self-signed until you put a certificate from your own CA here (cert.pem + key.pem, then restart).
  names="DNS:$(hostname),DNS:$(hostname -f 2>/dev/null || hostname)"
  for ip in $(hostname -I 2>/dev/null); do names="$names,IP:$ip"; done
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=$(hostname -f 2>/dev/null || hostname)" \
    -addext "subjectAltName=$names" -keyout "$CONF/tls/key.pem" -out "$CONF/tls/cert.pem" 2>/dev/null
  chown root:dfir "$CONF/tls/key.pem" "$CONF/tls/cert.pem"; chmod 0640 "$CONF/tls/key.pem"
fi

say "Admin command (dfir-admin)"
install -m 0755 "$APP/deploy/dfir-admin" /usr/local/bin/dfir-admin

if [ -d /run/systemd/system ]; then
  say "Services"
  install -m 0644 "$APP"/deploy/systemd/* /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now dfir-velociraptor.service dfir-copilot.service dfir-backup.timer
else
  warn "No systemd here: services not installed."
fi

if [ -n "${INVESTIGATOR_NET:-}" ]; then
  say "Firewall: web page from $INVESTIGATOR_NET, SSH from ${ADMIN_NET:-$INVESTIGATOR_NET}"
  ufw allow from "${ADMIN_NET:-$INVESTIGATOR_NET}" to any port 22 proto tcp
  ufw allow from "$INVESTIGATOR_NET" to any port 8501 proto tcp
  ufw default deny incoming
  ufw default allow outgoing
  ufw --force enable
else
  warn "Firewall left as it is. Run again with INVESTIGATOR_NET=<investigators' network> to allow only them."
fi

cat <<EOF

Done. Next:
  1. First admin account:        sudo dfir-admin auth add <name> --admin
  2. Model and key:              sudo nano $CONF/server.yaml   (llm: base_url, model, api_key)
                                 then: sudo systemctl restart dfir-copilot
  3. An evidence image:          sudo $APP/deploy/add-image.sh <name> <image.E01 or folder>
  4. Memory images:              copy them into $DATA/memory (symbols into $DATA/symbols)
  5. Check:                      sudo dfir-admin config_check && sudo dfir-admin memory check
  6. Open:                       https://$(hostname -I 2>/dev/null | awk '{print $1}'):8501
EOF
