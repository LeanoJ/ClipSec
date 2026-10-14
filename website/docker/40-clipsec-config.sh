#!/bin/sh
# Schreibt /config.js aus Umgebungsvariablen (Links auf der Webseite).
set -eu

default="https://github.com/LeanoJ/ClipSec"
url="${GITHUB_URL:-}"
if [ -z "$url" ] && [ -n "${GITHUB_REPO:-}" ]; then
  url="https://github.com/${GITHUB_REPO}"
fi
[ -n "$url" ] || url="$default"

# Wert landet in JavaScript → nur unkritische URL-Zeichen zulassen
case "$url" in
  https://*) ;;
  *) echo "[clipsec] GITHUB_URL muss mit https:// beginnen – verwende Standard"; url="$default" ;;
esac
case "$url" in
  *[!A-Za-z0-9:/._~-]*) echo "[clipsec] GITHUB_URL enthält unzulässige Zeichen – verwende Standard"; url="$default" ;;
esac

cat > /usr/share/nginx/html/config.js <<EOF
// Automatisch erzeugt beim Containerstart
window.CLIPSEC_CONFIG = { githubUrl: "${url}", downloadsPath: "downloads/" };
EOF
echo "[clipsec] GitHub-Link: ${url}"
