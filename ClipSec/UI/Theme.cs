using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace ClipSec.UI;

/// <summary>Hell/Dunkel nach Windows-App-Modus. Farben werden als DynamicResource verwendet.</summary>
internal static class Theme
{
    public static bool IsDark()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        return key?.GetValue("AppsUseLightTheme") is int v && v == 0;
    }

    public static void Apply(ResourceDictionary res)
    {
        var dark = IsDark();
        // Kontraste bewusst hoch: dünne Schrift bei 100 % Skalierung wirkt sonst grau.
        Set(res, "BgBrush", dark ? "#1F1F1F" : "#F3F3F3");
        Set(res, "SurfaceBrush", dark ? "#2C2C2C" : "#FFFFFF");
        Set(res, "SurfaceHoverBrush", dark ? "#373737" : "#EEF3FE");
        Set(res, "SurfaceSelectedBrush", dark ? "#30436A" : "#DCE7FD");
        Set(res, "BorderBrush", dark ? "#474747" : "#D0D0D0");
        Set(res, "InputBrush", dark ? "#161616" : "#FFFFFF");
        Set(res, "TextBrush", dark ? "#FFFFFF" : "#111111");
        Set(res, "TextSecondaryBrush", dark ? "#CFCFCF" : "#4A4A4A");
        Set(res, "TextHintBrush", dark ? "#B4B4B4" : "#6B6B6B");
        // Wie Windows 11: im Dunkelmodus helle Akzentfläche mit dunkler Schrift.
        Set(res, "AccentBrush", dark ? "#6CA8FF" : "#2563EB");
        Set(res, "AccentHoverBrush", dark ? "#8BBBFF" : "#1D4ED8");
        Set(res, "OnAccentBrush", dark ? "#0B1220" : "#FFFFFF");
        Set(res, "DangerBrush", dark ? "#FF8A8A" : "#C81E1E");
        Set(res, "WarningBgBrush", dark ? "#3A2E12" : "#FFF4D6");
        Set(res, "WarningTextBrush", dark ? "#FFD27A" : "#6B4700");
        Set(res, "SensitiveBrush", dark ? "#FFB86B" : "#9A4A00");
        Set(res, "OverlayBrush", dark ? "#E6161616" : "#E6F3F3F3");
    }

    private static void Set(ResourceDictionary res, string key, string hex, bool asColor = false)
    {
        var color = (Color)ColorConverter.ConvertFromString(hex);
        if (asColor)
        {
            res[key] = color;
            return;
        }
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        res[key] = brush;
    }
}
