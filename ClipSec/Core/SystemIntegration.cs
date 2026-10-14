using Microsoft.Win32;

namespace ClipSec.Core;

/// <summary>Autostart und Abgleich mit dem eingebauten Windows-Zwischenablageverlauf (nur HKCU, keine Adminrechte).</summary>
internal static class SystemIntegration
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValue = "ClipSec";
    private const string ClipboardKey = @"Software\Microsoft\Clipboard";

    public static bool IsAutostartEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        return key?.GetValue(RunValue) is string;
    }

    public static void SetAutostart(bool enabled, string? exePath = null)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey);
        if (enabled)
            key.SetValue(RunValue, $"\"{exePath ?? Environment.ProcessPath}\" --tray");
        else if (key.GetValue(RunValue) != null)
            key.DeleteValue(RunValue);
    }

    /// <summary>
    /// Ist der eingebaute Windows-Verlauf aktiv, speichert Windows Kopien zusätzlich unverschlüsselt –
    /// das würde ClipSec aushebeln.
    /// </summary>
    public static bool IsWindowsClipboardHistoryEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(ClipboardKey);
        return key?.GetValue("EnableClipboardHistory") is int v && v != 0;
    }

    public static bool IsCloudClipboardEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(ClipboardKey);
        return key?.GetValue("EnableCloudClipboard") is int v && v != 0;
    }

    /// <summary>Öffnet Einstellungen → System → Zwischenablage, damit der Benutzer den Windows-Verlauf selbst abschaltet.</summary>
    public static void OpenWindowsClipboardSettings() =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ms-settings:clipboard") { UseShellExecute = true });
}
