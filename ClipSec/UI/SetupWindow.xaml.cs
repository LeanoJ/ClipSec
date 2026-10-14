using System.Windows;
using ClipSec.Core;

namespace ClipSec.UI;

/// <summary>Ersteinrichtung: Master-Passwort, Timer, optionale PIN.</summary>
public partial class SetupWindow : Window
{
    private readonly AppSettings _settings;

    internal SetupWindow(AppSettings settings)
    {
        _settings = settings;
        InitializeComponent();
        WindowStyling.ApplyTitleBarTheme(this);
        UiHelpers.SelectChip(TimeoutChips, settings.LockTimeoutMinutes);
        WinHistoryWarning.Visibility = SystemIntegration.IsWindowsClipboardHistoryEnabled() || SystemIntegration.IsCloudClipboardEnabled()
            ? Visibility.Visible
            : Visibility.Collapsed;
        Activated += (_, _) =>
        {
            // Nach Rückkehr aus den Windows-Einstellungen Hinweis aktualisieren.
            if (WinHistoryWarning.Visibility == Visibility.Visible &&
                !SystemIntegration.IsWindowsClipboardHistoryEnabled() && !SystemIntegration.IsCloudClipboardEnabled())
                WinHistoryWarning.Visibility = Visibility.Collapsed;
        };
        Loaded += (_, _) => PasswordBox1.Focus();
    }

    internal CryptoVault? CreatedVault { get; private set; }

    private void PinCheck_Changed(object sender, RoutedEventArgs e) =>
        PinPanel.Visibility = PinCheck.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;

    private void OpenWinSettings_Click(object sender, RoutedEventArgs e) => SystemIntegration.OpenWindowsClipboardSettings();

    private async void Create_Click(object sender, RoutedEventArgs e)
    {
        var pw = PasswordBox1.Password;
        var error = UiHelpers.ValidatePassword(pw, PasswordBox2.Password);
        var usePin = PinCheck.IsChecked == true;
        var pin = PinBox1.Password;
        if (error == null && usePin) error = UiHelpers.ValidatePin(pin, PinBox2.Password);
        if (error == null && usePin && pw == pin) error = "PIN und Passwort dürfen nicht gleich sein.";
        if (error != null)
        {
            ErrorText.Text = error;
            return;
        }

        ErrorText.Text = "";
        CreateButton.IsEnabled = false;
        CreateButton.Content = "Schlüssel werden erzeugt …";
        try
        {
            var vault = await Task.Run(() =>
            {
                var v = CryptoVault.Create(pw);
                if (usePin) v.SetPin(pin);
                return v;
            });

            _settings.LockTimeoutMinutes = UiHelpers.GetChip(TimeoutChips, 5);
            _settings.PinEnabled = usePin;
            _settings.Save();
            try { SystemIntegration.SetAutostart(AutostartCheck.IsChecked == true); } catch { }

            PasswordBox1.Clear();
            PasswordBox2.Clear();
            PinBox1.Clear();
            PinBox2.Clear();
            CreatedVault = vault;
            DialogResult = true;
        }
        catch (Exception ex)
        {
            ErrorText.Text = "Einrichtung fehlgeschlagen: " + ex.Message;
            CreateButton.IsEnabled = true;
            CreateButton.Content = "Einrichten";
        }
    }
}
