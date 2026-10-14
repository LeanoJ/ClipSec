using System.Diagnostics;
using System.IO;
using System.Text;
using ClipSec.Core;

// Aufruf: dotnet run --project ClipSec.Tests  (setzt CLIPSEC_DATA_DIR auf ein Temp-Verzeichnis)
var failures = 0;
void Check(bool condition, string name)
{
    Console.WriteLine($"{(condition ? "OK  " : "FAIL")}  {name}");
    if (!condition) failures++;
}

var dir = Environment.GetEnvironmentVariable("CLIPSEC_DATA_DIR");
if (string.IsNullOrEmpty(dir) || !dir.Contains("clipsec-test", StringComparison.OrdinalIgnoreCase))
{
    Console.WriteLine("CLIPSEC_DATA_DIR muss auf ein Testverzeichnis (…clipsec-test…) zeigen.");
    return 2;
}
if (Directory.Exists(dir)) Directory.Delete(dir, true);
Directory.CreateDirectory(dir);

var sw = Stopwatch.StartNew();
var vault = CryptoVault.Create("korrekt-pferd-batterie");
Console.WriteLine($"      Tresor erstellt in {sw.ElapsedMilliseconds} ms");
Check(vault.IsUnlocked, "neuer Tresor ist entsperrt");
Check(CryptoVault.Exists(), "vault.json geschrieben");

// Versiegeln / Öffnen
var id = Guid.NewGuid();
var payload = ClipPayload.FromText("Geheimer Text äöü 🔒");
var blob = vault.Seal(payload.Serialize(), id.ToByteArray());
var opened = vault.Open(blob, id.ToByteArray());
Check(opened != null && ClipPayload.Deserialize(opened)!.Text == "Geheimer Text äöü 🔒", "Roundtrip Text");
Check(!Encoding.UTF8.GetString(blob).Contains("Geheimer"), "Blob enthält keinen Klartext");
Check(vault.Open(blob, Guid.NewGuid().ToByteArray()) == null, "falsche AAD (anderer Eintrag) wird abgelehnt");
var tampered = (byte[])blob.Clone();
tampered[^1] ^= 0x01;
Check(vault.Open(tampered, id.ToByteArray()) == null, "manipulierter Blob wird abgelehnt");
Check(!vault.Seal(payload.Serialize(), id.ToByteArray()).AsSpan().SequenceEqual(blob), "gleicher Inhalt → anderer Chiffretext");

// Sperren
vault.Lock();
Check(!vault.IsUnlocked, "gesperrt");
var threw = false;
try { vault.Open(blob, id.ToByteArray()); } catch (InvalidOperationException) { threw = true; }
Check(threw, "Öffnen im gesperrten Zustand nicht möglich");
var lockedBlob = vault.Seal(ClipPayload.FromText("im gesperrten Zustand kopiert").Serialize(), id.ToByteArray());
Check(lockedBlob.Length > 0, "Versiegeln funktioniert auch gesperrt");

// Neu laden + Passwort
var loaded = CryptoVault.Load();
Check(!loaded.IsUnlocked, "geladener Tresor ist gesperrt");
sw.Restart();
Check(!loaded.UnlockWithPassword("falsch"), "falsches Passwort abgelehnt");
Console.WriteLine($"      PBKDF2-Prüfung: {sw.ElapsedMilliseconds} ms");
Check(loaded.UnlockWithPassword("korrekt-pferd-batterie"), "richtiges Passwort akzeptiert");
Check(ClipPayload.Deserialize(loaded.Open(lockedBlob, id.ToByteArray())!)!.Text == "im gesperrten Zustand kopiert",
    "gesperrt versiegelter Eintrag nach Entsperren lesbar");

// PIN
Check(!loaded.PinSessionActive, "ohne PIN keine PIN-Sitzung");
loaded.SetPin("4711");
Check(loaded.HasPin, "PIN gesetzt");
loaded.StartPinSession();
Check(loaded.PinSessionActive, "PIN-Sitzung aktiv nach Passwort-Entsperrung");
loaded.Lock();
Check(loaded.UnlockWithPin("0000", 3) == PinUnlockResult.WrongPin, "falsche PIN abgelehnt");
Check(loaded.RemainingPinAttempts(3) == 2, "Fehlversuch gezählt");
Check(loaded.UnlockWithPin("4711", 3) == PinUnlockResult.Success, "richtige PIN entsperrt");
Check(loaded.Open(blob, id.ToByteArray()) != null, "nach PIN-Entsperrung lesbar");
Check(loaded.RemainingPinAttempts(3) == 3, "Zähler nach Erfolg zurückgesetzt");
loaded.Lock();
loaded.UnlockWithPin("1", 3);
loaded.UnlockWithPin("2", 3);
Check(loaded.UnlockWithPin("3", 3) == PinUnlockResult.Exhausted, "nach 3 Fehlversuchen erschöpft");
Check(!loaded.PinSessionActive, "PIN-Sitzung verworfen");
Check(loaded.UnlockWithPin("4711", 3) == PinUnlockResult.NotAvailable, "danach hilft auch die richtige PIN nicht");

// PIN liegt nicht im Klartext auf der Platte, und neuer Prozess (= Neustart) hat keine PIN-Sitzung
var afterRestart = CryptoVault.Load();
Check(afterRestart.HasPin && !afterRestart.PinSessionActive, "nach \"Neustart\": PIN gespeichert, aber Sitzung erst nach Passwort");
Check(afterRestart.UnlockWithPin("4711", 3) == PinUnlockResult.NotAvailable, "nach \"Neustart\" kein Entsperren per PIN");
Check(!File.ReadAllText(AppPaths.VaultFile).Contains("4711"), "PIN nicht im Klartext gespeichert");

// Passwort ändern
Check(afterRestart.UnlockWithPassword("korrekt-pferd-batterie"), "Entsperren vor Passwortwechsel");
afterRestart.ChangePassword("neues-passwort-123");
var reloaded = CryptoVault.Load();
Check(!reloaded.VerifyPassword("korrekt-pferd-batterie"), "altes Passwort ungültig");
Check(reloaded.UnlockWithPassword("neues-passwort-123"), "neues Passwort gültig");
Check(reloaded.Open(blob, id.ToByteArray()) != null, "alte Einträge nach Passwortwechsel lesbar");
reloaded.StartPinSession();
Check(reloaded.PinSessionActive, "PIN übersteht Passwortwechsel");

// Bild-Payload
var img = new ClipPayload(ClipKind.Image, Enumerable.Range(0, 300_000).Select(i => (byte)i).ToArray());
var imgBlob = reloaded.Seal(img.Serialize(), id.ToByteArray());
var imgBack = ClipPayload.Deserialize(reloaded.Open(imgBlob, id.ToByteArray())!)!;
Check(imgBack.Kind == ClipKind.Image && imgBack.Data.AsSpan().SequenceEqual(img.Data), "Roundtrip Binärdaten 300 KB");

// Format v2: Formatierung + Textbaustein-Metadaten, Rückwärtskompatibilität zu v1
var rich = new ClipPayload(ClipKind.Text, Encoding.UTF8.GetBytes("Hallo **Welt**"))
{
    Html = "Version:0.9\r\nStartHTML:0\r\n<b>Welt</b> äöü",
    Rtf = @"{\rtf1 Hallo \b Welt\b0}",
    Title = "Gruß",
    Group = "Mails",
};
var richBack = ClipPayload.Deserialize(reloaded.Open(reloaded.Seal(rich.Serialize(), id.ToByteArray()), id.ToByteArray())!)!;
Check(richBack.Text == rich.Text && richBack.Html == rich.Html && richBack.Rtf == rich.Rtf &&
      richBack.Title == "Gruß" && richBack.Group == "Mails", "v2: Text, HTML, RTF, Name, Gruppe überstehen Roundtrip");
var legacy = new byte[] { (byte)ClipKind.Text }.Concat(Encoding.UTF8.GetBytes("alter Eintrag")).ToArray();
Check(ClipPayload.Deserialize(legacy)?.Text == "alter Eintrag", "v1-Einträge (vor dem Update) bleiben lesbar");
Check(rich.Hash().AsSpan().SequenceEqual(ClipPayload.FromText("Hallo **Welt**").Hash()), "Duplikaterkennung ignoriert Formatierung/Metadaten");
Check(rich.WithText("neu").Html == null && rich.WithText("neu").Title == "Gruß", "Bearbeiten verwirft Formatierung, behält Namen");
Check(ClipPayload.Deserialize([0xC5, 2, 1, 1, 0xFF, 0xFF, 0xFF, 0x7F]) == null, "kaputte Längenangabe wird abgelehnt");

// Erkennung vertraulicher Inhalte
void Sens(string text, string? expected) =>
    Check(SensitiveDetector.Detect(text) == expected, $"Erkennung: \"{(text.Length > 40 ? text[..40] + "…" : text)}\" → {expected ?? "nichts"}");
Sens("DE89 3704 0044 0532 0130 00", "IBAN");
Sens("Bitte überweisen an DE89370400440532013000, danke!", "IBAN");
Sens("DE89 3704 0044 0532 0130 01", null);                 // Prüfsumme falsch
Sens("4111 1111 1111 1111", "Kreditkarte");
Sens("Bestellnummer 1234 5678 9012 3456", null);           // kein Luhn/kein Präfix
Sens("sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789", "API-Schlüssel");
Sens("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "API-Schlüssel");
Sens("AKIAIOSFODNN7EXAMPLE", "API-Schlüssel");
Sens("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----", "Privater Schlüssel");
Sens("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "Token");
Sens("Server=db;User Id=sa;Password=Geheim123!;", "Zugangsdaten");
Sens("Tr0ub4dor&3x", "Passwort");
Sens("Hallo123!", "Passwort");
Sens("Treffen morgen um 10:30 im Besprechungsraum 2", null);
Sens("https://example.com/Seite?id=42", null);
Sens("max.mustermann@example.com", null);
Sens("C:\\Users\\Leano\\Documents\\Bericht2026.pdf", null);
Sens("bericht_2026.pdf", null);
Sens("System.Text.Json", null);
Sens("3f2504e0-4f89-11d3-9a0c-0305e82c3301", null);
Sens("+49 170 1234567", null);
Sens("Console.WriteLine();", null);

CryptoVault.DeleteAll();
Check(!CryptoVault.Exists(), "Zurücksetzen löscht Tresor");
Directory.Delete(dir, true);

Console.WriteLine(failures == 0 ? "\nAlle Tests bestanden." : $"\n{failures} Test(s) fehlgeschlagen.");
return failures == 0 ? 0 : 1;
