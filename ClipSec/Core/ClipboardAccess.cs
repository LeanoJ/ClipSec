using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media.Imaging;
using ClipSec.Native;

namespace ClipSec.Core;

/// <summary>Lesen und Schreiben der Windows-Zwischenablage (UI-Thread).</summary>
internal static class ClipboardAccess
{
    // Von Windows/Passwortmanagern genutzte Markierungen
    // (https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats#cloud-clipboard-and-clipboard-history-formats)
    private const string ExcludeFormat = "ExcludeClipboardContentFromMonitorProcessing";
    private const string CanIncludeFormat = "CanIncludeInClipboardHistory";
    private const string CanUploadFormat = "CanUploadToCloudClipboard";
    private const string ViewerIgnoreFormat = "Clipboard Viewer Ignore";
    private const string OwnMarkerFormat = "ClipSec.Internal";

    /// <summary>
    /// Liest den aktuellen Inhalt. Null, wenn leer, nicht unterstützt, vertraulich markiert,
    /// aus einem ausgeschlossenen Programm oder von ClipSec selbst.
    /// </summary>
    public static ClipPayload? Read(AppSettings settings)
    {
        if (settings.ExcludedApps.Count > 0 && settings.IsExcluded(GetSourceProcessName())) return null;

        var data = Retry(Clipboard.GetDataObject);
        if (data == null) return null;

        if (data.GetDataPresent(OwnMarkerFormat)) return null;
        if (settings.RespectExcludeMarkers && IsMarkedPrivate(data)) return null;

        long maxBytes = settings.MaxItemSizeMb * 1024L * 1024L;

        if (settings.CaptureFiles && data.GetDataPresent(DataFormats.FileDrop) &&
            data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
        {
            return ClipPayload.FromFiles(files);
        }

        if (data.GetDataPresent(DataFormats.UnicodeText) && data.GetData(DataFormats.UnicodeText) is string text &&
            text.Length > 0)
        {
            if (text.Length * 2L > maxBytes) return null;
            var payload = ClipPayload.FromText(text);
            if (!settings.KeepFormatting) return payload;

            var withFormat = new ClipPayload(ClipKind.Text, payload.Data)
            {
                Html = TryGetString(data, DataFormats.Html),
                Rtf = TryGetString(data, DataFormats.Rtf),
            };
            // Zu groß mit Formatierung → wenigstens den Text behalten.
            return withFormat.TotalSize <= maxBytes ? withFormat : payload;
        }

        if (settings.CaptureImages)
        {
            var png = ReadPng(data);
            if (png != null && png.Length <= maxBytes) return new ClipPayload(ClipKind.Image, png);
        }

        return null;
    }

    /// <summary>Programm, das den aktuellen Inhalt in die Zwischenablage gelegt hat (z. B. "KeePass.exe").</summary>
    public static string? GetSourceProcessName()
    {
        var hwnd = NativeMethods.GetClipboardOwner();
        if (hwnd == IntPtr.Zero) hwnd = NativeMethods.GetForegroundWindow();
        if (hwnd == IntPtr.Zero) return null;
        NativeMethods.GetWindowThreadProcessId(hwnd, out var pid);
        if (pid == 0) return null;
        try
        {
            using var p = Process.GetProcessById((int)pid);
            return p.ProcessName + ".exe";
        }
        catch
        {
            return null;
        }
    }

    private static string? TryGetString(IDataObject data, string format)
    {
        try
        {
            return data.GetDataPresent(format) && data.GetData(format) is string { Length: > 0 } s ? s : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsMarkedPrivate(IDataObject data)
    {
        if (data.GetDataPresent(ExcludeFormat) || data.GetDataPresent(ViewerIgnoreFormat)) return true;
        if (data.GetDataPresent(CanIncludeFormat) && ReadDword(data, CanIncludeFormat) == 0) return true;
        return false;
    }

    private static int? ReadDword(IDataObject data, string format)
    {
        try
        {
            if (data.GetData(format) is MemoryStream ms && ms.Length >= 4)
            {
                var buf = new byte[4];
                ms.Position = 0;
                ms.ReadExactly(buf);
                return BitConverter.ToInt32(buf);
            }
        }
        catch { }
        return null;
    }

    private static byte[]? ReadPng(IDataObject data)
    {
        try
        {
            // Viele Programme (Browser, Office, Snipping Tool) liefern direkt PNG mit Transparenz.
            if (data.GetDataPresent("PNG") && data.GetData("PNG") is MemoryStream pngStream && pngStream.Length > 0)
                return pngStream.ToArray();

            if (!data.GetDataPresent(DataFormats.Bitmap)) return null;
            var bmp = Retry(Clipboard.GetImage);
            if (bmp == null) return null;
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bmp));
            using var ms = new MemoryStream();
            encoder.Save(ms);
            return ms.ToArray();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Legt einen Eintrag in die Zwischenablage – markiert, damit weder der Windows-Verlauf
    /// noch die Cloud-Zwischenablage ihn unverschlüsselt speichern.
    /// </summary>
    /// <returns>Sequenznummer der Zwischenablage danach (für automatisches Leeren), sonst null.</returns>
    public static uint? Write(ClipPayload payload, bool plainTextOnly = false)
    {
        var obj = new DataObject();
        switch (payload.Kind)
        {
            case ClipKind.Text:
                obj.SetText(payload.Text, TextDataFormat.UnicodeText);
                if (!plainTextOnly)
                {
                    if (!string.IsNullOrEmpty(payload.Html)) obj.SetData(DataFormats.Html, payload.Html);
                    if (!string.IsNullOrEmpty(payload.Rtf)) obj.SetData(DataFormats.Rtf, payload.Rtf);
                }
                break;
            case ClipKind.Files:
                if (plainTextOnly)
                {
                    obj.SetText(string.Join(Environment.NewLine, payload.Files), TextDataFormat.UnicodeText);
                    break;
                }
                var list = new StringCollection();
                list.AddRange(payload.Files);
                obj.SetFileDropList(list);
                break;
            case ClipKind.Image:
                obj.SetData("PNG", new MemoryStream(payload.Data));
                var decoder = new PngBitmapDecoder(new MemoryStream(payload.Data),
                    BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
                obj.SetImage(decoder.Frames[0]);
                break;
        }
        obj.SetData(OwnMarkerFormat, new MemoryStream([1]));
        obj.SetData(CanIncludeFormat, new MemoryStream(BitConverter.GetBytes(0)));
        obj.SetData(CanUploadFormat, new MemoryStream(BitConverter.GetBytes(0)));

        var ok = Retry(() =>
        {
            Clipboard.SetDataObject(obj, copy: true);
            return true;
        });
        return ok ? NativeMethods.GetClipboardSequenceNumber() : null;
    }

    /// <summary>Leert die Zwischenablage, sofern seit <paramref name="sequence"/> nichts Neues kopiert wurde.</summary>
    public static bool ClearIfUnchanged(uint sequence)
    {
        if (NativeMethods.GetClipboardSequenceNumber() != sequence) return false;
        return Retry(() =>
        {
            Clipboard.Clear();
            return true;
        });
    }

    /// <summary>Andere Programme halten die Zwischenablage manchmal kurz offen → mehrfach versuchen.</summary>
    private static T? Retry<T>(Func<T?> action)
    {
        for (var i = 0; i < 8; i++)
        {
            try
            {
                return action();
            }
            catch (ExternalException) // inkl. COMException (CLIPBRD_E_CANT_OPEN)
            {
                Thread.Sleep(40);
            }
        }
        return default;
    }
}
