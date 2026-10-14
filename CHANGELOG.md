# Changelog

Alle wichtigen Änderungen an ClipSec. Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/),
Versionierung nach [SemVer](https://semver.org/lang/de/).

## [1.1.0] – 2026-10-14

### Neu
- Vertrauliche Inhalte (Passwörter, IBAN, Kreditkarten, API-Schlüssel, Tokens, Zugangsdaten) werden erkannt und maskiert; optional erneute Abfrage des Master-Passworts und automatisches Löschen
- Zwischenablage automatisch leeren (bei Vertraulichem, optional nach jedem Einfügen)
- Programme vom Aufnehmen ausschließen
- Formatierung (HTML/RTF) wird gespeichert; Umschalt+Enter fügt als reinen Text ein
- Strg+1…9 Schnellwahl, große Vorschau (Leertaste), Bearbeiten (F2), Kontextmenü
- Textbausteine mit Name und Gruppe, Filter-Chips
- Sperre bei PC-Inaktivität, automatisches Löschen alter Einträge (1–90 Tage)
- Installer pro Benutzer (ohne Adminrechte) mit Deinstallation über „Apps“
- Einstellungen mit Navigation

### Behoben
- Schrift in der Verlaufsliste war im Dunkelmodus schwarz
- Dünne/graue Schrift durch teiltransparentes Fenster (jetzt ClearType, Windows-11-Ecken)
- Absturz bei manipulierter Längenangabe in gespeicherten Einträgen

## [1.0.0] – 2026-10-14

### Neu
- Erste Version: Win+V-Ersatz mit Master-Passwort, gleitendem Sperr-Timer und Kurz-PIN bis Neustart
- Verschlüsselung pro Eintrag (ECDH P-256 + AES-256-GCM), Aufnahme auch im gesperrten Zustand
