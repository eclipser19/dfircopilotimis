#!/usr/bin/env bash
# Presents an evidence image to Velociraptor as a client of its own, as a service that starts at boot:
#   sudo /opt/dfir-copilot/deploy/add-image.sh <name> <image.E01 | raw image | folder holding Windows and Users>
# <name>: lower-case letters, digits and dashes; it becomes the client's host name in Velociraptor and the
# service dfir-deaddisk@<name>. For an E01, give the first segment (the others must sit next to it).
# Prints the client ID to put in the case (Case tab > Velociraptor client). Running it again for the same
# name only prints the client ID.
set -euo pipefail
DATA=/srv/dfir
APP=/opt/dfir-copilot
VR=/usr/local/bin/velociraptor
die() { printf '[x] %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo $0 $*"
[ $# -eq 2 ] || die "Usage: sudo $0 <name> <image.E01 | folder>"
name=$1
image=$(readlink -f "$2" || true)
[[ $name =~ ^[a-z0-9][a-z0-9-]{0,40}$ ]] || die "The name may hold lower-case letters, digits and dashes only."
[ -n "$image" ] && [ -e "$image" ] || die "No such file or folder: $2"
sudo -u dfir test -r "$image" || die "The service account cannot read $image. Let the dfir group read it \
(chgrp -R dfir <folder>; chmod -R g+rX <folder>), or mount the evidence read-only with gid=dfir."
dir=$DATA/deaddisk/$name

if [ ! -f "$dir/client.config.yaml" ]; then
  install -d -o dfir -g dfir -m 0750 "$dir"
  if [ -d "$image" ]; then add=--add_windows_directory; else add=--add_windows_disk; fi
  (cd "$dir" && sudo -u dfir -H "$VR" deaddisk --hostname "$name" "$add=$image" "$dir/remap.yaml") \
    || die "Velociraptor could not read $image (see above)."
  # Each image gets its own identity (writeback) and queue, so several run side by side as separate clients.
  (cd "$APP" && sudo -u dfir "$APP/.venv/bin/python" - "$DATA/velociraptor/client.config.yaml" "$dir" <<'PY'
import sys
import yaml
source, folder = sys.argv[1], sys.argv[2]
with open(source) as f:
    config = yaml.safe_load(f)
config["Client"]["writeback_linux"] = f"{folder}/writeback.yaml"
config["Client"].setdefault("local_buffer", {})["filename_linux"] = f"{folder}/buffer.bin"
with open(f"{folder}/client.config.yaml", "w") as f:
    yaml.safe_dump(config, f, sort_keys=False)
PY
  )
fi

if [ -d /run/systemd/system ]; then
  systemctl enable --now "dfir-deaddisk@$name.service" >/dev/null
else
  echo "[!] No systemd: start the client yourself:"
  echo "    sudo -u dfir $VR --config $dir/client.config.yaml --remap $dir/remap.yaml client"
fi

printf 'Waiting for the client to enrol'
for _ in $(seq 1 40); do
  id=$(cd "$APP" && sudo -u dfir /bin/bash -c 'set -a; . /etc/dfir-copilot/env; set +a
exec '"$APP"'/.venv/bin/python - "$0"' "$name" <<'PY' 2>/dev/null || true
import sys
from copilot.vql_client import get_vql
res = get_vql().run_vql("SELECT client_id FROM clients() WHERE os_info.hostname = DfirName "
                        "ORDER BY last_seen_at DESC LIMIT 1", env={"DfirName": sys.argv[1]})
rows = res.get("results") or []
print(rows[0]["client_id"] if rows else "")
PY
)
  if [ -n "$id" ]; then
    printf '\nImage %s is client %s. Put it in the case: Case tab > Velociraptor client.\n' "$name" "$id"
    exit 0
  fi
  printf '.'; sleep 3
done
die "No client named $name after 2 minutes: journalctl -u dfir-deaddisk@$name -n 50"
