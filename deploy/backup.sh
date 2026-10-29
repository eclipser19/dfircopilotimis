#!/usr/bin/env bash
# Backs up what cannot be collected again, while the copilot runs: the cases (each database copied safely,
# plus case files, chats and reports), the settings and accounts, Velociraptor's keys and every image's
# client identity (so client IDs stay the same after a restore), and the TLS files. Not the evidence or
# memory images (keep the originals), Velociraptor's datastore, logs or binary (made again by setup).
#   sudo /opt/dfir-copilot/deploy/backup.sh [destination folder]     (nightly: the dfir-backup timer)
# The backup holds keys, accounts and evidence-derived data: store it like the evidence.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0" >&2; exit 1; }
# The data folder setup chose (server.yaml deploy.data_dir) and the cases folder of the service's settings.
DATA=$(sed -n "s/^ *data_dir: *['\"]\{0,1\}\([^'\"]*\).*/\1/p" /etc/dfir-copilot/server.yaml 2>/dev/null | head -1)
DATA=${DATA:-/srv/dfir}
CASES=$(sed -n 's/^DFIR_CASES_DIR=//p' /etc/dfir-copilot/env 2>/dev/null | head -1)
CASES=${CASES:-/srv/dfir/cases}
KEEP=${KEEP:-14}                     # backups kept in the default folder
dest=${1:-/srv/dfir/backups/$(date +%Y-%m-%d_%H%M)}

install -d -m 0700 "$dest" "$dest/cases"
rsync -a --exclude 'case.db' --exclude 'case.db-wal' --exclude 'case.db-shm' "$CASES/" "$dest/cases/"
find "$CASES" -name case.db -type f | while read -r db; do
  out="$dest/cases/${db#"$CASES/"}"
  mkdir -p "$(dirname "$out")"
  sqlite3 "$db" ".backup '$out'"
done
if [ -f /opt/dfir-copilot/case_data/case.db ]; then       # the case the app opens before one is picked
  mkdir -p "$dest/code_case_data"
  sqlite3 /opt/dfir-copilot/case_data/case.db ".backup '$dest/code_case_data/case.db'"
fi
parts=(etc/dfir-copilot)
for p in "$DATA/velociraptor" "$DATA/tls" /srv/dfir/learned_knowledge.yaml; do
  [ -e "$p" ] && parts+=("${p#/}")
done
tar -czf "$dest/settings.tar.gz" -C / --exclude "${DATA#/}/velociraptor/datastore" \
  --exclude "${DATA#/}/velociraptor/velociraptor" --exclude '*.log' "${parts[@]}"
chmod -R go-rwx "$dest"
echo "Backup written to $dest ($(du -sh "$dest" | cut -f1))"

if [ $# -eq 0 ]; then                # prune old ones in the default folder only
  ls -1d /srv/dfir/backups/????-??-??_???? 2>/dev/null | sort | head -n -"$KEEP" | xargs -r rm -rf
fi
