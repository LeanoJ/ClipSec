#!/bin/sh
# Holt das neueste ClipSec-Release von GitHub nach /downloads:
#   ClipSec-Setup.exe, SHA256SUMS.txt, latest.json
# Die Prüfsumme der EXE wird gegen die latest.json des Releases verglichen.
#
#   clipsec-sync once   – einmal abgleichen
#   clipsec-sync loop   – dauerhaft alle SYNC_INTERVAL_HOURS Stunden

DIR="/downloads"
REPO="${GITHUB_REPO:-}"
EXE="ClipSec-Setup.exe"
umask 022

log() { echo "[clipsec-sync] $(date '+%Y-%m-%d %H:%M:%S') $*"; }

asset_url() { # $1 = JSON, $2 = Dateiname
  printf '%s' "$1" | jq -r --arg n "$2" '.assets[]? | select(.name == $n) | .browser_download_url' | head -n 1
}

sync_once() {
  # RELEASE_API_URL erlaubt andere Quellen mit GitHub-kompatibler API (z. B. Gitea/Forgejo:
  # https://git.example.org/api/v1/repos/besitzer/repo/releases/latest)
  api="${RELEASE_API_URL:-}"
  if [ -z "$api" ]; then
    if [ -z "$REPO" ]; then log "GITHUB_REPO nicht gesetzt"; return 1; fi
    case "$REPO" in */*) ;; *) log "GITHUB_REPO muss 'besitzer/repo' sein"; return 1 ;; esac
    api="https://api.github.com/repos/${REPO}/releases/latest"
  fi

  json=$(curl -fsSL --max-time 30 \
    -H "Accept: application/vnd.github+json" -H "User-Agent: clipsec-web" \
    "$api") || { log "Release-API nicht erreichbar oder kein Release vorhanden ($api)"; return 1; }

  tag=$(printf '%s' "$json" | jq -r '.tag_name // empty')
  if [ -z "$tag" ]; then log "Kein Release gefunden"; return 1; fi

  if [ -f "$DIR/$EXE" ] && [ -f "$DIR/latest.json" ] &&
     [ "$(jq -r '.tag // empty' "$DIR/latest.json" 2>/dev/null)" = "$tag" ]; then
    log "Aktuell ($tag)"
    return 0
  fi

  exe_url=$(asset_url "$json" "$EXE")
  manifest_url=$(asset_url "$json" "latest.json")
  if [ -z "$exe_url" ]; then log "Release $tag enthält keine $EXE"; return 1; fi

  tmp=$(mktemp -d "$DIR/.sync.XXXXXX") || { log "Kein Schreibzugriff auf $DIR"; return 1; }
  if ! curl -fsSL --max-time 900 -o "$tmp/$EXE" "$exe_url"; then
    log "Download fehlgeschlagen"; rm -rf "$tmp"; return 1
  fi
  sha=$(sha256sum "$tmp/$EXE" | cut -d ' ' -f 1)

  if [ -n "$manifest_url" ] && curl -fsSL --max-time 30 -o "$tmp/latest.json" "$manifest_url"; then
    expected=$(jq -r '.sha256 // empty' "$tmp/latest.json" | tr 'A-F' 'a-f')
    if [ "$sha" != "$expected" ]; then
      log "Prüfsumme passt nicht zu latest.json ($sha ≠ $expected) – verworfen"
      rm -rf "$tmp"; return 1
    fi
  else
    size=$(stat -c %s "$tmp/$EXE")
    jq -n --arg v "${tag#v}" --arg t "$tag" --arg f "$EXE" --arg s "$sha" --arg d "$(date +%F)" --argjson size "$size" \
      '{version: $v, tag: $t, file: $f, url: $f, size: $size, sha256: $s, date: $d}' > "$tmp/latest.json"
  fi
  printf '%s  %s\n' "$sha" "$EXE" > "$tmp/SHA256SUMS.txt"
  chmod 644 "$tmp/$EXE" "$tmp/latest.json" "$tmp/SHA256SUMS.txt"

  # latest.json zuletzt: Die Webseite zeigt erst dann die neue Version an.
  mv -f "$tmp/$EXE" "$DIR/$EXE"
  mv -f "$tmp/SHA256SUMS.txt" "$DIR/SHA256SUMS.txt"
  mv -f "$tmp/latest.json" "$DIR/latest.json"
  rm -rf "$tmp"
  log "Aktualisiert auf $tag (SHA-256 $sha)"
}

case "${1:-once}" in
  once)
    sync_once
    ;;
  loop)
    hours="${SYNC_INTERVAL_HOURS:-6}"
    case "$hours" in ''|*[!0-9]*) hours=6 ;; esac
    [ "$hours" -ge 1 ] || hours=1
    while :; do
      if sync_once; then
        sleep "$((hours * 3600))"
      else
        # z. B. noch kein Release oder GitHub kurz nicht erreichbar → bald erneut versuchen
        sleep 900
      fi
    done
    ;;
  *)
    echo "Aufruf: clipsec-sync once|loop" >&2
    exit 2
    ;;
esac
