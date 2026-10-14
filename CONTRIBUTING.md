# Mitwirken an ClipSec

Danke für dein Interesse! Fehlerberichte, Ideen und Pull Requests sind willkommen.

## Voraussetzungen

- Windows 10/11 (x64)
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- optional: Docker (für die Webseite)

## Projektstruktur

| Ordner | Inhalt |
|---|---|
| `ClipSec/` | Die App (WPF, .NET 8). `Core/` = Logik & Kryptografie, `UI/` = Fenster, `Native/` = Win32 |
| `ClipSec.Tests/` | Tests ohne externe Abhängigkeiten (Konsolenprogramm) |
| `tools/ClipSec.Screenshots/` | Erzeugt die Screenshots für Webseite und README mit Beispieldaten |
| `website/` | Statische Webseite + Docker-Image (nginx) inkl. Unraid-Vorlage |
| `.github/workflows/` | CI, Release-Build, Webseiten-Image |

## Bauen & Testen

```powershell
dotnet build ClipSec.sln -c Release
$env:CLIPSEC_DATA_DIR = "$env:TEMP\clipsec-test"; dotnet run --project ClipSec.Tests
.\publish.ps1                                # dist\ClipSec-Setup.exe + latest.json + SHA256SUMS.txt
```

`CLIPSEC_DATA_DIR` leitet alle Daten in einen Testordner um – so bleibt dein echter Verlauf unberührt.

Screenshots neu erzeugen (öffnet kurz unsichtbare Fenster außerhalb des Bildschirms):

```powershell
dotnet run --project tools\ClipSec.Screenshots
```

## Richtlinien

- **Sicherheit zuerst:** Keine Klartext-Inhalte auf die Platte, in Logs oder Fehlermeldungen. Neue Metadaten gehören in den verschlüsselten Payload (`ClipPayload`), nicht in `StoredEntry`.
- **Speicherformat:** Änderungen am Payload müssen ältere Einträge weiter lesen können (siehe Tests „v1-Einträge“).
- **Oberfläche:** Deutsch, Hell- und Dunkelmodus prüfen. Farben nur über die Theme-Ressourcen (`UI/Theme.cs`).
- **Tests:** Für Logik (Kryptografie, Erkennung, Format) bitte Tests in `ClipSec.Tests` ergänzen.
- Code-Stil: siehe `.editorconfig`; Kommentare erklären das *Warum*.

## Pull Requests

1. Fork & Branch (`feature/…` oder `fix/…`)
2. Bauen, Tests grün, Änderung im `CHANGELOG.md` unter „Unreleased“ notieren
3. PR mit kurzer Beschreibung und – bei UI-Änderungen – Screenshot

Sicherheitslücken bitte **nicht** als Issue, sondern wie in [SECURITY.md](SECURITY.md) beschrieben melden.
