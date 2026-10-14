using System.Windows;
using System.Windows.Input;

namespace ClipSec.UI;

/// <summary>Fragt das Master-Passwort ab, prüft es und entsperrt bei Bedarf den Tresor.</summary>
public partial class PasswordPrompt : Window
{
    private readonly AppController _c;
    private bool _busy;

    internal PasswordPrompt(AppController controller, string title, string message)
    {
        _c = controller;
        InitializeComponent();
        WindowStyling.ApplyTitleBarTheme(this);
        TitleText.Text = title;
        MessageText.Text = message;
        Loaded += (_, _) => Box.Focus();
    }

    private async void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || Box.Password.Length == 0) return;
        _busy = true;
        OkButton.IsEnabled = Box.IsEnabled = false;
        OkButton.Content = "Prüfe …";

        var pw = Box.Password;
        var (ok, error) = _c.Lock.IsUnlocked
            ? await _c.Lock.VerifyPasswordAsync(pw)
            : await _c.Lock.UnlockWithPasswordAsync(pw);
        Box.Clear();

        if (ok)
        {
            DialogResult = true;
            return;
        }
        _busy = false;
        OkButton.IsEnabled = Box.IsEnabled = true;
        OkButton.Content = "Bestätigen";
        ErrorText.Text = error ?? "Falsches Passwort.";
        ErrorText.Visibility = Visibility.Visible;
        Box.Focus();
    }

    private void Box_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Ok_Click(sender, e);
    }
}
