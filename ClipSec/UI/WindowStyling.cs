using System.Windows;
using System.Windows.Interop;
using ClipSec.Native;

namespace ClipSec.UI;

internal static class WindowStyling
{
    /// <summary>Dunkle Titelleiste passend zum Windows-Modus (Windows 10 20H1+ / 11).</summary>
    public static void ApplyTitleBarTheme(Window window)
    {
        window.SourceInitialized += (_, _) =>
        {
            var hwnd = new WindowInteropHelper(window).Handle;
            var dark = Theme.IsDark() ? 1 : 0;
            NativeMethods.DwmSetWindowAttribute(hwnd, NativeMethods.DWMWA_USE_IMMERSIVE_DARK_MODE, ref dark, sizeof(int));
        };
    }

    /// <summary>Runde Ecken + Systemschatten für rahmenlose Fenster (Windows 11; unter Windows 10 eckig).</summary>
    public static void ApplyRoundedCorners(IntPtr hwnd)
    {
        var pref = NativeMethods.DWMWCP_ROUND;
        NativeMethods.DwmSetWindowAttribute(hwnd, NativeMethods.DWMWA_WINDOW_CORNER_PREFERENCE, ref pref, sizeof(int));
    }
}
