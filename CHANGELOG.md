# Changelog

Alle wichtigen Änderungen an ClipSec. Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/),
Versionierung nach [SemVer](https://semver.org/lang/de/).

## [1.2.0] – 2026-10-14

### Neu
- **YubiKey / FIDO2-Sicherheitsschlüssel** (hmac-secret über die Windows-WebAuthn-API, ohne Adminrechte):
  - „Passwort oder Schlüssel“: Berühren + Schlüssel-PIN entsperrt allein
  - „Passwort und Schlüssel“: 2-Faktor, keines von beiden reicht allein
  - mehrere Schlüssel, Testfunktion, Umschalten ohne erneute Registrierung
- Tresor-Format 2 mit Schlüsselfächern; bestehende Tresore werden beim nächsten Entsperren automatisch übernommen

### Behoben
- Erstes Win+V blieb unsichtbar, wenn ClipSec von einem anderen Programm versteckt gestartet wurde

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
