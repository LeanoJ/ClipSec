# ClipSec-Webseite: statische Seite + Download-Bereitstellung (nginx)
#
#   docker build -t clipsec-web website
#   docker run -d -p 8085:80 -v /mnt/user/appdata/clipsec-web/downloads:/downloads \
#              -e GITHUB_REPO=LeanoJ/ClipSec clipsec-web
#
# 1.30 = aktuelle stabile nginx-Linie (gerade Minor-Version = stable)
FROM nginx:1.30-alpine

# curl/jq: Abgleich mit GitHub-Releases · su-exec: Abgleich ohne Root-Rechte
RUN apk add --no-cache curl jq su-exec

COPY nginx/default.conf /etc/nginx/conf.d/default.conf
COPY nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY docker/40-clipsec-config.sh docker/50-clipsec-sync.sh /docker-entrypoint.d/
COPY docker/clipsec-sync.sh /usr/local/bin/clipsec-sync
COPY index.html config.js favicon.ico /usr/share/nginx/html/
COPY assets /usr/share/nginx/html/assets

# Zeilenenden absichern (falls unter Windows ausgecheckt) und ausführbar machen
RUN sed -i 's/\r$//' /docker-entrypoint.d/40-clipsec-config.sh /docker-entrypoint.d/50-clipsec-sync.sh /usr/local/bin/clipsec-sync \
 && chmod 755 /docker-entrypoint.d/40-clipsec-config.sh /docker-entrypoint.d/50-clipsec-sync.sh /usr/local/bin/clipsec-sync \
 && mkdir -p /downloads

# GITHUB_REPO leer lassen, wenn die Dateien von Hand nach /downloads kopiert werden.
ENV GITHUB_REPO="" \
    GITHUB_URL="" \
    SYNC_INTERVAL_HOURS="6" \
    PUID="99" \
    PGID="100"

VOLUME ["/downloads"]
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1/healthz || exit 1

LABEL org.opencontainers.image.title="ClipSec Web" \
      org.opencontainers.image.description="Webseite und Download-Bereitstellung für ClipSec" \
      org.opencontainers.image.source="https://github.com/LeanoJ/ClipSec" \
      org.opencontainers.image.licenses="MIT"
