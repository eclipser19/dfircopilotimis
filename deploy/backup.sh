#!/usr/bin/env bash
# Backs up what cannot be collected again, while the copilot runs: the cases (each database copied safely,
# plus case files, chats and reports), the settings and accounts, Velociraptor's keys and every image's
# client identity (so client IDs stay the same after a restore), and the TLS files. Not the evidence or
# memory images (keep the originals), Velociraptor's datastore, logs or binary (made again by setup).
#   sudo /opt/dfir-copilot/deploy/backup.sh [destination folder]     (nightly: the dfir-backup timer)
# The backup holds keys, accounts and evidence-derived data: store it like the evidence.
set -euo pipefail
DATA=/srv/dfir
KEEP=${KEEP:-14}                     # backups kept in the default folder
dest=${1:-$DATA/backups/$(date +%Y-%m-%d_%H%M)}
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0" >&2; exit 1; }

install -d -m 0700 "$dest" "$dest/cases"
rsync -a --exclude 'case.db' --exclude 'case.db-wal' --exclude 'case.db-shm' "$DATA/cases/" "$dest/cases/"
find "$DATA/cases" -name case.db -type f | while read -r db; do
  out="$dest/cases/${db#"$DATA/cases/"}"
  mkdir -p "$(dirname "$out")"
  sqlite3 "$db" ".backup '$out'"
done
parts=(etc/dfir-copilot)
for p in srv/dfir/velociraptor srv/dfir/tls srv/dfir/learned_knowledge.yaml; do
  [ -e "/$p" ] && parts+=("$p")
done
tar -czf "$dest/settings.tar.gz" -C / --exclude 'srv/dfir/velociraptor/datastore' \
  --exclude 'srv/dfir/velociraptor/velociraptor' --exclude '*.log' "${parts[@]}"
chmod -R go-rwx "$dest"
echo "Backup written to $dest ($(du -sh "$dest" | cut -f1))"

if [ $# -eq 0 ]; then                # prune old ones in the default folder only
  ls -1d "$DATA"/backups/????-??-??_???? 2>/dev/null | sort | head -n -"$KEEP" | xargs -r rm -rf
fi
