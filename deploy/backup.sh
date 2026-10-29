#!/usr/bin/env bash
# Backs up what cannot be collected again: the cases (databases copied safely while the app runs, chats,
# reports), the settings and accounts, and the dead-disk clients' identities (so client IDs stay the same).
# Not the evidence or memory images (keep the originals) or Velociraptor's datastore (collected again if needed).
#   sudo /opt/dfir-copilot/deploy/backup.sh [destination folder]     (nightly by the dfir-backup timer)
# The backup holds secrets (keys, accounts) and evidence-derived data: keep it as protected as the evidence.
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
tar -czf "$dest/settings.tar.gz" -C / etc/dfir-copilot srv/dfir/velociraptor/server.config.yaml \
  srv/dfir/velociraptor/client.config.yaml srv/dfir/deaddisk $( [ -f $DATA/learned_knowledge.yaml ] && echo srv/dfir/learned_knowledge.yaml )
chmod -R go-rwx "$dest"
echo "Backup written to $dest ($(du -sh "$dest" | cut -f1))"

if [ $# -eq 0 ]; then                # prune old ones in the default folder only
  ls -1d "$DATA"/backups/????-??-??_???? 2>/dev/null | sort | head -n -"$KEEP" | xargs -r rm -rf
fi
