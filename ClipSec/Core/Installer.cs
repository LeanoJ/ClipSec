using System.Diagnostics;
using System.IO;
using System.Reflection;
using Microsoft.Win32;

namespace ClipSec.Core;

/// <summary>
/// Installation pro Benutzer (keine Adminrechte): Programmordner unter %LOCALAPPDATA%\Programs,
/// Startmenü-Verknüpfung und Eintrag in "Apps &amp; Features" zum Deinstallieren.
/// </summary>
internal static class Installer
{
    public const string MutexName = @"Local\ClipSec.SingleInstance";
    public const string ExitEventName = @"Local\ClipSec.Exit";
    private const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\ClipSec";

    public static string InstallDir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "ClipSec");

    public static string InstalledExe => Path.Combine(InstallDir, "ClipSec.exe");

    private static string StartMenuShortcut => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Programs), "ClipSec.lnk");

    private static string DesktopShortcut => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "ClipSec.lnk");

    public static string Version =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    public static bool IsInstalled
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(UninstallKey);
            return key != null && File.Exists(InstalledExe);
        }
    }

    public static string? InstalledVersion
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(UninstallKey);
            return key?.GetValue("DisplayVersion") as string;
        }
    }

    public static bool IsRunningInstalled =>
        string.Equals(Path.GetFullPath(Environment.ProcessPath ?? ""), Path.GetFullPath(InstalledExe),
            StringComparison.OrdinalIgnoreCase);

    /// <summary>Installer-Modus, wenn die EXE "ClipSec-Setup…" heißt oder mit --install gestartet wird.</summary>
    public static bool IsSetupMode(string[] args) =>
        !args.Contains("--portable", StringComparer.OrdinalIgnoreCase) &&
        (args.Contains("--install", StringComparer.OrdinalIgnoreCase) ||
         Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? "")
             .StartsWith("ClipSec-Setup", StringComparison.OrdinalIgnoreCase));

    // ------------------------------------------------------------------ Laufende Instanz

    public static bool IsAppRunning()
    {
        try
        {
            using var m = Mutex.OpenExisting(MutexName);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Bittet eine laufende ClipSec-Instanz, sich zu beenden, und wartet darauf. Ältere Versionen
    /// (ohne Beenden-Signal) oder hängende Instanzen werden notfalls hart beendet.
    /// </summary>
    public static bool StopRunningApp(TimeSpan timeout)
    {
        if (!IsAppRunning()) return true;
        try
        {
            using var ev = EventWaitHandle.OpenExisting(ExitEventName);
            ev.Set();
            if (WaitForMutex(timeout))
            {
                // Mutex ist frei, der Prozess räumt evtl. noch auf → EXE erst danach überschreibbar.
                WaitForOtherInstancesToExit(TimeSpan.FromSeconds(5));
                return true;
            }
        }
        catch (WaitHandleCannotBeOpenedException)
        {
            // Version 1.0 kennt das Signal noch nicht.
        }

        var self = Environment.ProcessId;
        foreach (var p in Process.GetProcessesByName("ClipSec").Where(p => p.Id != self))
        {
            try
            {
                p.Kill();
                p.WaitForExit(5000);
            }
            catch { }
            finally { p.Dispose(); }
        }
        return WaitForMutex(TimeSpan.FromSeconds(5));
    }

    private static void WaitForOtherInstancesToExit(TimeSpan timeout)
    {
        var self = Environment.ProcessId;
        foreach (var p in Process.GetProcessesByName("ClipSec").Where(p => p.Id != self))
        {
            try { p.WaitForExit((int)timeout.TotalMilliseconds); } catch { }
            finally { p.Dispose(); }
        }
    }

    private static bool WaitForMutex(TimeSpan timeout)
    {
        using var mutex = new Mutex(false, MutexName);
        try
        {
            if (!mutex.WaitOne(timeout)) return false;
        }
        catch (AbandonedMutexException)
        {
            // Instanz wurde hart beendet – zählt als beendet.
        }
        mutex.ReleaseMutex();
        return true;
    }

    // ------------------------------------------------------------------ Installieren

    public static void Install(bool desktopShortcut, bool autostart)
    {
        var source = Environment.ProcessPath ?? throw new InvalidOperationException("Programmpfad unbekannt.");
        Directory.CreateDirectory(InstallDir);
        if (!string.Equals(Path.GetFullPath(source), Path.GetFullPath(InstalledExe), StringComparison.OrdinalIgnoreCase))
        {
            // Erst in Temp-Datei kopieren, dann ersetzen → keine halbe EXE bei Abbruch.
            var tmp = InstalledExe + ".new";
            File.Copy(source, tmp, overwrite: true);
            File.Move(tmp, InstalledExe, overwrite: true);
        }

        CreateShortcut(StartMenuShortcut, InstalledExe);
        if (desktopShortcut) CreateShortcut(DesktopShortcut, InstalledExe);
        else TryDelete(DesktopShortcut);

        using (var key = Registry.CurrentUser.CreateSubKey(UninstallKey))
        {
            key.SetValue("DisplayName", "ClipSec");
            key.SetValue("DisplayVersion", Version);
            key.SetValue("Publisher", "ClipSec");
            key.SetValue("DisplayIcon", InstalledExe);
            key.SetValue("InstallLocation", InstallDir);
            key.SetValue("UninstallString", $"\"{InstalledExe}\" --uninstall");
            key.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"));
            key.SetValue("EstimatedSize", (int)(new FileInfo(InstalledExe).Length / 1024), RegistryValueKind.DWord);
            key.SetValue("NoModify", 1, RegistryValueKind.DWord);
            key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
        }

        SystemIntegration.SetAutostart(autostart, InstalledExe);
    }

    public static void StartInstalled() =>
        Process.Start(new ProcessStartInfo(InstalledExe) { UseShellExecute = false, WorkingDirectory = InstallDir });

    // ------------------------------------------------------------------ Deinstallieren

    /// <summary>
    /// Entfernt Verknüpfungen, Autostart und den Eintrag in "Apps &amp; Features". Der Programmordner
    /// wird gelöscht, sobald dieser Prozess beendet ist.
    /// </summary>
    public static void Uninstall(bool deleteData)
    {
        SystemIntegration.SetAutostart(false);
        TryDelete(StartMenuShortcut);
        TryDelete(DesktopShortcut);
        Registry.CurrentUser.DeleteSubKeyTree(UninstallKey, throwOnMissingSubKey: false);

        if (deleteData && Directory.Exists(AppPaths.DataDir))
        {
            try { Directory.Delete(AppPaths.DataDir, recursive: true); } catch { }
        }

        if (Directory.Exists(InstallDir))
        {
            // Die laufende EXE kann sich nicht selbst löschen → kurz nach Prozessende per cmd entfernen.
            Process.Start(new ProcessStartInfo("cmd.exe",
                $"/c ping 127.0.0.1 -n 3 > nul & rmdir /s /q \"{InstallDir}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                WorkingDirectory = Path.GetTempPath(),
            });
        }
    }

    // ------------------------------------------------------------------ Hilfen

    private static void CreateShortcut(string path, string target)
    {
        var shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("WScript.Shell fehlt.");
        dynamic shell = Activator.CreateInstance(shellType)!;
        try
        {
            dynamic link = shell.CreateShortcut(path);
            link.TargetPath = target;
            link.WorkingDirectory = Path.GetDirectoryName(target);
            link.IconLocation = target + ",0";
            link.Description = "ClipSec – gesicherte Zwischenablage";
            link.Save();
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
