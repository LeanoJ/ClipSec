using System.Windows.Controls;

namespace ClipSec.UI;

internal static class UiHelpers
{
    public const int MinPasswordLength = 8;

    /// <summary>Wählt in einer Chip-Liste den Eintrag mit passendem Tag (oder den nächstgelegenen).</summary>
    public static void SelectChip(ListBox list, int value)
    {
        ListBoxItem? best = null;
        var bestDiff = int.MaxValue;
        foreach (ListBoxItem item in list.Items)
        {
            var diff = Math.Abs(int.Parse((string)item.Tag) - value);
            if (diff < bestDiff)
            {
                best = item;
                bestDiff = diff;
            }
        }
        list.SelectedItem = best;
    }

    public static int GetChip(ListBox list, int fallback) =>
        list.SelectedItem is ListBoxItem { Tag: string tag } && int.TryParse(tag, out var v) ? v : fallback;

    public static string? ValidatePassword(string pw, string confirm)
    {
        if (pw.Length < MinPasswordLength) return $"Das Passwort muss mindestens {MinPasswordLength} Zeichen lang sein.";
        if (pw != confirm) return "Die Passwörter stimmen nicht überein.";
        return null;
    }

    public static string? ValidatePin(string pin, string confirm)
    {
        if (pin.Length is < 4 or > 8 || !pin.All(char.IsAsciiDigit)) return "Die PIN muss aus 4–8 Ziffern bestehen.";
        if (pin != confirm) return "Die PINs stimmen nicht überein.";
        return null;
    }
}
