#!/usr/bin/env bash
# Starts Velociraptor, every image's dead-disk client and the web app (python -m copilot.install start), like
# start.ps1 on Windows. On a machine set up by deploy/install.sh it runs them as the dfir account with the
# service's settings.
#   sudo ./start.sh                in this terminal; Ctrl+C stops everything (closing the terminal too)
#   sudo ./start.sh --background   keeps running after you log out, and starts again at every boot
#   sudo ./start.sh --status       running in the background? its last lines
#   sudo ./start.sh --stop         stops the background one (and its start at boot)
# Images: sudo dfir-admin install add-image <image.E01 | folder> --name <short-name>
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
self="$here/$(basename "$0")"
cd "$here"
mode=${1:-}

if [ ! -f /etc/dfir-copilot/env ]; then          # a plain checkout, not installed by deploy/install.sh
  [ -z "$mode" ] || { echo "--background, --status and --stop need deploy/install.sh first." >&2; exit 1; }
  python=./.venv/bin/python; [ -x "$python" ] || python=python3
  exec "$python" -m copilot.install start
fi
[ "$(id -u)" -eq 0 ] || exec sudo "$self" "$@"
running() { systemctl is-active --quiet dfir-copilot 2>/dev/null; }

case "$mode" in
  "")
    if running; then
      echo "It already runs in the background. Stop that first (sudo $self --stop), or leave it running."
      exit 1
    fi
    exec dfir-admin install start ;;
  --background)
    [ -d /run/systemd/system ] || { echo "No systemd here: run it in a terminal (sudo $self)." >&2; exit 1; }
    systemctl enable --now dfir-copilot >/dev/null
    sleep 8
    journalctl -u dfir-copilot --no-pager -n 12 -o cat || true
    echo
    echo "Runs in the background, and at every boot.  Status: sudo $self --status   Stop: sudo $self --stop" ;;
  --status)
    if running; then echo "Runs in the background."; else echo "Not running in the background."; fi
    journalctl -u dfir-copilot --no-pager -n 15 -o cat 2>/dev/null || true ;;
  --stop)
    if running; then echo "Stopping (running questions get up to ten minutes to finish)..."; fi
    systemctl disable --now dfir-copilot >/dev/null 2>&1 || true
    echo "Stopped, and no longer started at boot." ;;
  *)
    sed -n '2,9s/^# \{0,1\}//p' "$self" >&2; exit 1 ;;
esac
