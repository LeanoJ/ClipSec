using System.IO;
using System.Text.Json;

namespace ClipSec.Core;

public enum HotkeyPreset
{
    WinV,
    CtrlShiftV,
    CtrlAltV,
}

/// <summary>
/// Nicht geheime Einstellungen. Änderungen sind nur im entsperrten Zustand möglich (siehe SettingsWindow).
/// </summary>
public sealed class AppSettings
{
    /// <summary>Minuten ohne Benutzung bis zur Sperre. 0 = sofort nach jedem Schließen sperren.</summary>
    public int LockTimeoutMinutes { get; set; } = 5;

    /// <summary>Kurz-PIN erlaubt Entsperren bis zum Neustart/Abmelden (nach einmaliger Passworteingabe).</summary>
    public bool PinEnabled { get; set; }

    public int MaxPinAttempts { get; set; } = 5;

    public bool LockOnWorkstationLock { get; set; } = true;

    /// <summary>Wenn aktiv, wird die PIN beim Sperren von Windows (Win+L) verworfen.</summary>
    public bool ForgetPinOnWorkstationLock { get; set; }

    public bool PersistHistory { get; set; } = true;

    public int MaxItems { get; set; } = 50;

    public int MaxItemSizeMb { get; set; } = 8;

    public bool CaptureImages { get; set; } = true;

    public bool CaptureFiles { get; set; } = true;

    /// <summary>Inhalte, die Passwortmanager als "nicht in Verlauf aufnehmen" markieren, ignorieren.</summary>
    public bool RespectExcludeMarkers { get; set; } = true;

    /// <summary>Nach Auswahl eines Eintrags automatisch Strg+V im vorherigen Fenster senden.</summary>
    public bool AutoPaste { get; set; } = true;

    public HotkeyPreset Hotkey { get; set; } = HotkeyPreset.WinV;

    /// <summary>Formatierung (HTML/RTF) mitspeichern.</summary>
    public bool KeepFormatting { get; set; } = true;

    // ---- Vertrauliche Inhalte ----

    public bool DetectSensitive { get; set; } = true;

    /// <summary>Aufdecken/Einfügen/Bearbeiten vertraulicher Einträge verlangt erneut das Master-Passwort.</summary>
    public bool SensitiveRequiresPassword { get; set; }

    /// <summary>Vertrauliche (nicht angeheftete) Einträge nach X Minuten löschen. 0 = nie.</summary>
    public int SensitiveRetentionMinutes { get; set; }

    // ---- Zwischenablage leeren ----

    /// <summary>Nach Einfügen aus ClipSec die Zwischenablage nach X Sekunden leeren. 0 = aus.</summary>
    public int ClearAfterPasteSeconds { get; set; }

    /// <summary>Liegt Vertrauliches in der Zwischenablage (egal woher), nach X Sekunden leeren. 0 = aus.</summary>
    public int ClearSensitiveSeconds { get; set; } = 30;

    // ---- Ausschlüsse & Aufräumen ----

    /// <summary>Prozessnamen (z. B. "KeePass.exe"), aus denen nichts aufgenommen wird.</summary>
    public List<string> ExcludedApps { get; set; } = [];

    /// <summary>Sperren, wenn der PC so viele Minuten gar nicht benutzt wurde. 0 = aus.</summary>
    public int IdleLockMinutes { get; set; }

    /// <summary>Nicht angeheftete Einträge nach X Tagen löschen. 0 = aus.</summary>
    public int RetentionDays { get; set; }

    /// <summary>"C:\…\KeePass.exe" oder "keepass" → "KeePass.exe"-Form ohne Pfad, mit Endung.</summary>
    public static string NormalizeAppName(string? name)
    {
        name = Path.GetFileName((name ?? "").Trim().Trim('"'));
        if (name.Length == 0) return "";
        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name : name + ".exe";
    }

    public bool IsExcluded(string? processName) =>
        processName != null && ExcludedApps.Contains(NormalizeAppName(processName), StringComparer.OrdinalIgnoreCase);

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(AppPaths.SettingsFile))
            {
                var json = File.ReadAllText(AppPaths.SettingsFile);
                var s = JsonSerializer.Deserialize<AppSettings>(json);
                if (s != null) return s.Normalize();
            }
        }
        catch
        {
            // Defekte Einstellungen → Standardwerte (sicher, weil Standard = sperren).
        }
        return new AppSettings();
    }

    public void Save()
    {
        Normalize();
        AppPaths.WriteAllTextAtomic(AppPaths.SettingsFile,
            JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }

    private AppSettings Normalize()
    {
        LockTimeoutMinutes = Math.Clamp(LockTimeoutMinutes, 0, 240);
        MaxPinAttempts = Math.Clamp(MaxPinAttempts, 1, 10);
        MaxItems = Math.Clamp(MaxItems, 5, 500);
        MaxItemSizeMb = Math.Clamp(MaxItemSizeMb, 1, 64);
        SensitiveRetentionMinutes = Math.Clamp(SensitiveRetentionMinutes, 0, 7 * 24 * 60);
        ClearAfterPasteSeconds = Math.Clamp(ClearAfterPasteSeconds, 0, 3600);
        ClearSensitiveSeconds = Math.Clamp(ClearSensitiveSeconds, 0, 3600);
        IdleLockMinutes = Math.Clamp(IdleLockMinutes, 0, 240);
        RetentionDays = Math.Clamp(RetentionDays, 0, 90);
        ExcludedApps = (ExcludedApps ?? [])
            .Select(NormalizeAppName)
            .Where(a => a.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        return this;
    }
}
