# Sicherheitsrichtlinie

ClipSec ist ein Sicherheitswerkzeug – Hinweise auf Schwachstellen nehme ich sehr ernst.

## Schwachstelle melden

**Bitte keine öffentlichen Issues für Sicherheitslücken.** Nutze stattdessen die
private Meldung über GitHub: *Security → Report a vulnerability* in diesem Repository.

Hilfreich sind:
- betroffene Version (`Einstellungen → Info`) und Windows-Version
- Beschreibung, Auswirkung und Schritte zum Nachvollziehen
- falls vorhanden: ein Proof of Concept

**Bitte niemals echte Passwörter, deinen Verlauf oder deine `vault.json` mitschicken.**

Du bekommst in der Regel innerhalb weniger Tage eine Rückmeldung. Nach dem Fix wird die
Lücke im Changelog und im Release beschrieben; auf Wunsch wirst du namentlich genannt.

## Unterstützte Versionen

Sicherheitsupdates gibt es für die jeweils neueste Version.

## Bedrohungsmodell (Kurzfassung)

ClipSec schützt den **Zwischenablage-Verlauf** vor Personen, die Zugriff auf einen
entsperrten Windows-Rechner haben, sowie vor dem Auslesen der gespeicherten Dateien.

| Im Umfang | Nicht im Umfang |
|---|---|
| Einsehen des Verlaufs ohne Master-Passwort/PIN | Schadsoftware unter deinem Benutzerkonto (Keylogger, Speicher auslesen) |
| Offline-Angriffe auf `vault.json` / `history.dat` | Administratoren / Kernel-Zugriff |
| Manipulation gespeicherter Einträge | Der *aktuelle* Inhalt der Zwischenablage (dafür: automatisches Leeren) |
| Raten von PIN/Passwort in der Oberfläche | Fenster mit Administratorrechten (Windows-UIPI) |

Details zum Verfahren stehen im Abschnitt *Sicherheitskonzept* der [README](README.md).
