using System.IO;
using System.Text;

namespace ClipSec.Core;

internal static class AppPaths
{
    /// <summary>%LOCALAPPDATA%\ClipSec – per CLIPSEC_DATA_DIR überschreibbar (Tests, portable Nutzung).</summary>
    public static string DataDir { get; } =
        Environment.GetEnvironmentVariable("CLIPSEC_DATA_DIR") is { Length: > 0 } custom
            ? custom
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ClipSec");

    public static string VaultFile => Path.Combine(DataDir, "vault.json");
    public static string HistoryFile => Path.Combine(DataDir, "history.dat");
    public static string SettingsFile => Path.Combine(DataDir, "settings.json");

    public static void EnsureDataDir() => Directory.CreateDirectory(DataDir);

    /// <summary>Schreibt atomar: erst Temp-Datei, dann ersetzen – kein halb geschriebener Tresor bei Absturz.</summary>
    public static void WriteAllTextAtomic(string path, string content)
    {
        EnsureDataDir();
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content, Encoding.UTF8);
        File.Move(tmp, path, overwrite: true);
    }
}
