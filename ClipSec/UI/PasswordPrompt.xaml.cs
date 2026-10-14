using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using ClipSec.Core;

namespace ClipSec.UI;

/// <summary>
/// Fragt das Master-Passwort (bzw. den Sicherheitsschlüssel) ab, prüft es und entsperrt bei Bedarf den Tresor.
/// Im 2-Faktor-Modus wird nach dem Passwort automatisch der Schlüssel abgefragt.
/// </summary>
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
        var mode = _c.Lock.Mode;
        MessageText.Text = mode == UnlockMode.PasswordAndKey && !_c.Lock.IsUnlocked
            ? message + " Danach wird der Sicherheitsschlüssel abgefragt."
            : message;
        KeyButton.Visibility = mode == UnlockMode.PasswordOrKey ? Visibility.Visible : Visibility.Collapsed;
        Loaded += (_, _) => Box.Focus();
    }

    private IntPtr Hwnd => new WindowInteropHelper(this).Handle;

    private async void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || Box.Password.Length == 0) return;
        var withKey = !_c.Lock.IsUnlocked && _c.Lock.Mode == UnlockMode.PasswordAndKey;
        SetBusy(true, withKey ? "Schlüssel berühren …" : "Prüfe …");

        var pw = Box.Password;
        var (ok, error) = _c.Lock.IsUnlocked
            ? await _c.Lock.VerifyPasswordAsync(pw)
            : await _c.Lock.UnlockWithPasswordAsync(pw, Hwnd);
        Box.Clear();
        Finish(ok, error ?? "Falsches Passwort.");
    }

    private async void KeyButton_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SetBusy(true, "Schlüssel berühren …");
        var (ok, error) = _c.Lock.IsUnlocked
            ? await _c.Lock.VerifyKeyAsync(Hwnd)
            : await _c.Lock.UnlockWithKeyAsync(Hwnd);
        Finish(ok, error ?? "Nicht bestätigt.");
    }

    private void Finish(bool ok, string error)
    {
        if (ok)
        {
            DialogResult = true;
            return;
        }
        SetBusy(false, "");
        Activate();
        ErrorText.Text = error;
        ErrorText.Visibility = Visibility.Visible;
        Box.Focus();
    }

    private void SetBusy(bool busy, string text)
    {
        _busy = busy;
        OkButton.IsEnabled = Box.IsEnabled = KeyButton.IsEnabled = !busy;
        OkButton.Content = busy ? text : "Bestätigen";
    }

    private void Box_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Ok_Click(sender, e);
    }
}
