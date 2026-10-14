## Was ändert sich?

<!-- Kurz beschreiben, was und warum. Issue verlinken: "Fixes #123" -->

## Checkliste

- [ ] `dotnet build ClipSec.sln -c Release` ohne Warnungen
- [ ] Tests grün (`dotnet run --project ClipSec.Tests`, mit `CLIPSEC_DATA_DIR` auf einen Testordner)
- [ ] Keine Klartext-Inhalte auf Platte, in Logs oder Fehlermeldungen
- [ ] Ältere gespeicherte Einträge bleiben lesbar (falls Speicherformat betroffen)
- [ ] Bei UI-Änderungen: Hell- und Dunkelmodus geprüft, Screenshot angehängt
- [ ] `CHANGELOG.md` ergänzt
