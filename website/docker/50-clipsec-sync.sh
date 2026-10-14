#!/bin/sh
# Bereitet /downloads vor und startet bei Bedarf den Abgleich mit GitHub-Releases im Hintergrund.
set -eu

uid="${PUID:-99}"
gid="${PGID:-100}"
case "$uid$gid" in *[!0-9]*) echo "[clipsec] PUID/PGID müssen Zahlen sein"; exit 1 ;; esac

mkdir -p /downloads
# Unraid-üblich: nobody:users (99:100). Fehler ignorieren (z. B. NFS ohne chown-Recht).
chown "$uid:$gid" /downloads 2>/dev/null || true

if [ -n "${GITHUB_REPO:-}" ] || [ -n "${RELEASE_API_URL:-}" ]; then
  echo "[clipsec] Abgleich mit ${RELEASE_API_URL:-github.com/${GITHUB_REPO}} alle ${SYNC_INTERVAL_HOURS:-6} h → /downloads (als ${uid}:${gid})"
  su-exec "$uid:$gid" /usr/local/bin/clipsec-sync loop &
else
  echo "[clipsec] GITHUB_REPO ist leer – ClipSec-Setup.exe und latest.json bitte selbst nach /downloads legen"
fi
