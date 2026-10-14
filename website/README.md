# ClipSec-Webseite

Statische Webseite (HTML/CSS/JS, keine externen Ressourcen) mit Download-Bereitstellung,
ausgeliefert von nginx im Docker-Container. Gedacht für den Betrieb auf einem Unraid-Server.

```
website/
├── index.html, config.js, favicon.ico
├── assets/            CSS, JS, Bilder (Screenshots: tools/ClipSec.Screenshots)
├── nginx/             Server-Konfiguration + Sicherheits-Header (CSP)
├── docker/            Startskripte + Release-Abgleich mit GitHub
├── Dockerfile
├── docker-compose.yml
└── unraid/clipsec-web.xml   Vorlage für „Add Container“
```

## Wie kommt die Setup-Datei auf die Seite?

Die Seite liest `downloads/latest.json` (Version, Größe, SHA-256) und verlinkt `downloads/ClipSec-Setup.exe`.
Beides liegt im Volume `/downloads`. Zwei Wege:

1. **Automatisch (empfohlen):** `GITHUB_REPO=LeanoJ/ClipSec` setzen. Der Container holt beim Start und danach
   alle `SYNC_INTERVAL_HOURS` Stunden das neueste GitHub-Release und prüft die SHA-256 gegen dessen `latest.json`.
2. **Von Hand:** `GITHUB_REPO` leer lassen und `ClipSec-Setup.exe`, `latest.json`, `SHA256SUMS.txt`
   (aus `dist\` nach `.\publish.ps1`) in den Downloads-Ordner kopieren.

Ohne Dateien zeigt die Seite automatisch einen Link zu den GitHub-Releases.

## Variablen

| Variable | Standard | Bedeutung |
|---|---|---|
| `GITHUB_REPO` | *(leer)* | `besitzer/repo` für den automatischen Abgleich |
| `GITHUB_URL` | aus `GITHUB_REPO` | Link „Quellcode“/„GitHub“ auf der Seite |
| `SYNC_INTERVAL_HOURS` | `6` | Abgleich-Intervall |
| `PUID` / `PGID` | `99` / `100` | Besitzer der Dateien im Downloads-Ordner (Unraid: nobody/users) |
| `RELEASE_API_URL` | *(leer)* | Statt GitHub eine andere kompatible Release-API, z. B. Gitea/Forgejo: `https://git.example.org/api/v1/repos/besitzer/repo/releases/latest` |

Port im Container: **80**. Volume: **/downloads**.

## Auf Unraid einrichten

### Variante A – Vorlage (Docker-Tab)

1. Datei `unraid/clipsec-web.xml` nach `/boot/config/plugins/dockerMan/templates-user/my-clipsec-web.xml` kopieren
   (z. B. über die Freigabe `flash`).
2. *Docker → Add Container → Template:* `clipsec-web` wählen, Port prüfen (Standard 8085), *Apply*.
3. Aufrufen: `http://<unraid-ip>:8085/`

### Variante B – Docker Compose (Plugin „Docker Compose Manager“)

```bash
docker compose -f docker-compose.yml up -d
```

### Image

`ghcr.io/leanoj/clipsec-web:latest` wird von GitHub Actions (`.github/workflows/website.yml`) gebaut,
sobald sich `website/` auf `main` ändert oder ein Release-Tag gepusht wird (amd64 + arm64).

> **Wichtig:** Neue Pakete in der GitHub Container Registry sind zunächst **privat**. Damit Unraid das Image ohne
> Login laden kann: GitHub → Profil → *Packages* → `clipsec-web` → *Package settings* → *Change visibility* → **Public**.

Alternativ direkt auf dem Server bauen:

```bash
git clone https://github.com/LeanoJ/ClipSec.git && cd ClipSec/website
docker build -t clipsec-web .
```

## Hinter einem Reverse-Proxy (HTTPS)

Mit Nginx Proxy Manager, SWAG o. Ä. einfach auf `http://<unraid-ip>:8085` weiterleiten.
Der Container sendet bereits CSP, `X-Frame-Options`, `Referrer-Policy` usw.; HSTS bitte am Proxy aktivieren.

## Lokal testen

```powershell
node tools/serve-website.mjs        # ohne Docker, http://localhost:8085 (Downloads aus dist\)
docker build -t clipsec-web website
docker run --rm -p 8085:80 -v ${PWD}/dist:/downloads clipsec-web
```

Logs des Abgleichs: `docker logs clipsec-web` · sofort abgleichen: `docker exec -u 99:100 clipsec-web clipsec-sync once`
