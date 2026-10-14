using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ClipSec.Core;
using Microsoft.Win32;

namespace ClipSec.UI;

public partial class SettingsWindow : Window
{
    private readonly AppController _c;
    private readonly ObservableCollection<string> _excluded;
    private readonly StackPanel[] _sections;

    internal SettingsWindow(AppController controller)
    {
        _c = controller;
        InitializeComponent();
        WindowStyling.ApplyTitleBarTheme(this);
        _sections = [SecLock, SecSensitive, SecExclude, SecHistory, SecUsage, SecPassword, SecInfo];

        var s = _c.Settings;
        // Sperre & PIN
        UiHelpers.SelectChip(TimeoutChips, s.LockTimeoutMinutes);
        LockOnWinLockCheck.IsChecked = s.LockOnWorkstationLock;
        UiHelpers.SelectChip(IdleChips, s.IdleLockMinutes);
        PinCheck.IsChecked = s.PinEnabled;
        UiHelpers.SelectChip(PinAttemptsChips, s.MaxPinAttempts);
        ForgetPinCheck.IsChecked = s.ForgetPinOnWorkstationLock;
        PinStatus.Text = _c.Vault.HasPin
            ? "Eine PIN ist gesetzt. Nur ausfüllen, wenn du sie ändern möchtest."
            : "Noch keine PIN gesetzt.";
        PinLabel.Text = _c.Vault.HasPin ? "Neue PIN (optional)" : "PIN (4–8 Ziffern)";
        // Vertraulich
        DetectSensitiveCheck.IsChecked = s.DetectSensitive;
        SensitivePasswordCheck.IsChecked = s.SensitiveRequiresPassword;
        UiHelpers.SelectChip(SensitiveRetentionChips, s.SensitiveRetentionMinutes);
        UiHelpers.SelectChip(ClearSensitiveChips, s.ClearSensitiveSeconds);
        UiHelpers.SelectChip(ClearPasteChips, s.ClearAfterPasteSeconds);
        // Ausschlüsse
        _excluded = new ObservableCollection<string>(s.ExcludedApps);
        ExcludeList.ItemsSource = _excluded;
        _excluded.CollectionChanged += (_, _) => UpdateExcludeEmpty();
        UpdateExcludeEmpty();
        RespectMarkersCheck.IsChecked = s.RespectExcludeMarkers;
        // Verlauf
        UiHelpers.SelectChip(MaxItemsChips, s.MaxItems);
        UiHelpers.SelectChip(RetentionChips, s.RetentionDays);
        UiHelpers.SelectChip(MaxSizeChips, s.MaxItemSizeMb);
        PersistCheck.IsChecked = s.PersistHistory;
        FormattingCheck.IsChecked = s.KeepFormatting;
        ImagesCheck.IsChecked = s.CaptureImages;
        FilesCheck.IsChecked = s.CaptureFiles;
        // Bedienung
        UiHelpers.SelectChip(HotkeyChips, (int)s.Hotkey);
        AutoPasteCheck.IsChecked = s.AutoPaste;
        AutostartCheck.IsChecked = SystemIntegration.IsAutostartEnabled();
        // Info
        VersionText.Text = $"Version {Installer.Version}";
        DataPathText.Text = AppPaths.DataDir;
        ProgramPathText.Text = Installer.IsRunningInstalled
            ? $"Installiert: {Installer.InstallDir}"
            : $"Nicht installiert (portabel): {Environment.ProcessPath}";
        UninstallButton.Content = Installer.IsRunningInstalled ? "ClipSec deinstallieren …" : "ClipSec installieren …";

        UpdatePinPanel();
        UpdateWarning();
        Activated += (_, _) => UpdateWarning();
        Loaded += (_, _) => NavList.SelectedIndex = 0;
    }

    /// <summary>Nach dem Schließen: Deinstallation gewünscht (true = inkl. Daten).</summary>
    internal bool? UninstallRequested { get; private set; }

    private void NavList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var index = Math.Max(0, NavList.SelectedIndex);
        for (var i = 0; i < _sections.Length; i++)
            _sections[i].Visibility = i == index ? Visibility.Visible : Visibility.Collapsed;
        ContentScroll.ScrollToTop();
        if (index == 2) LoadRunningApps();
    }

    private void UpdateWarning() =>
        WinHistoryWarning.Visibility =
            SystemIntegration.IsWindowsClipboardHistoryEnabled() || SystemIntegration.IsCloudClipboardEnabled()
                ? Visibility.Visible
                : Visibility.Collapsed;

    private void UpdatePinPanel() => PinPanel.IsEnabled = PinCheck.IsChecked == true;

    private void PinCheck_Changed(object sender, RoutedEventArgs e) => UpdatePinPanel();

    private void OpenWinSettings_Click(object sender, RoutedEventArgs e) => SystemIntegration.OpenWindowsClipboardSettings();

    // ------------------------------------------------------------------ Ausschlüsse

    private void UpdateExcludeEmpty() =>
        ExcludeEmpty.Visibility = _excluded.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

    private void AddExcluded(string? name)
    {
        var normalized = AppSettings.NormalizeAppName(name);
        if (normalized.Length == 0) return;
        if (!_excluded.Contains(normalized, StringComparer.OrdinalIgnoreCase)) _excluded.Add(normalized);
        ExcludeInput.Clear();
    }

    private void ExcludeAdd_Click(object sender, RoutedEventArgs e) => AddExcluded(ExcludeInput.Text);

    private void ExcludeInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        AddExcluded(ExcludeInput.Text);
        e.Handled = true;
    }

    private void ExcludeBrowse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Programm auswählen",
            Filter = "Programme (*.exe)|*.exe",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        };
        if (dlg.ShowDialog(this) == true) AddExcluded(dlg.FileName);
    }

    private void ExcludeRemove_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: string name }) _excluded.Remove(name);
    }

    /// <summary>Programme mit sichtbarem Fenster als Vorschläge.</summary>
    private void LoadRunningApps()
    {
        var self = Process.GetCurrentProcess().ProcessName;
        // Technische Host-Prozesse ohne eigenen Inhalt nicht vorschlagen.
        string[] hosts = ["ApplicationFrameHost", "TextInputHost", "ShellExperienceHost", "StartMenuExperienceHost"];
        var names = new List<string>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.MainWindowHandle != IntPtr.Zero && !string.IsNullOrEmpty(p.MainWindowTitle) && p.ProcessName != self &&
                    !hosts.Contains(p.ProcessName, StringComparer.OrdinalIgnoreCase))
                    names.Add(p.ProcessName + ".exe");
            }
            catch { }
            finally { p.Dispose(); }
        }
        RunningAppsChips.ItemsSource = names.Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private void RunningApps_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (RunningAppsChips.SelectedItem is string name) AddExcluded(name);
        RunningAppsChips.SelectedItem = null;
    }

    // ------------------------------------------------------------------ Info

    private void Uninstall_Click(object sender, RoutedEventArgs e)
    {
        if (!Installer.IsRunningInstalled)
        {
            // Portabel → Installer starten (beendet diese Instanz für die Installation).
            if (Environment.ProcessPath is { } exe)
                Process.Start(new ProcessStartInfo(exe, "--install") { UseShellExecute = false });
            DialogResult = false;
            return;
        }

        if (MessageBox.Show(this, "ClipSec wirklich deinstallieren?", "ClipSec deinstallieren",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        var deleteData = MessageBox.Show(this,
            "Auch den verschlüsselten Verlauf und die Einstellungen löschen?\n\n„Nein“ behält die Daten für eine spätere Neuinstallation.",
            "ClipSec deinstallieren", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;
        UninstallRequested = deleteData;
        DialogResult = false;
    }

    // ------------------------------------------------------------------ Speichern

    private void ShowSection(StackPanel section) => NavList.SelectedIndex = Array.IndexOf(_sections, section);

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        var vault = _c.Vault;
        var usePin = PinCheck.IsChecked == true;
        var newPin = PinBox1.Password;
        var newPw = NewPw1.Password;

        string? error = null;
        if (usePin && (!vault.HasPin || newPin.Length > 0))
        {
            error = UiHelpers.ValidatePin(newPin, PinBox2.Password);
            if (error != null) ShowSection(SecLock);
        }
        if (error == null && newPw.Length > 0)
        {
            error = UiHelpers.ValidatePassword(newPw, NewPw2.Password);
            if (error != null) ShowSection(SecPassword);
        }
        if (error != null)
        {
            ErrorText.Text = error;
            return;
        }
        if (!vault.IsUnlocked)
        {
            ErrorText.Text = "ClipSec wurde zwischenzeitlich gesperrt. Bitte Einstellungen erneut öffnen.";
            return;
        }

        ErrorText.Text = "";
        SaveButton.IsEnabled = false;
        SaveButton.Content = "Speichere …";
        try
        {
            if (newPw.Length > 0) await Task.Run(() => vault.ChangePassword(newPw));

            if (usePin)
            {
                if (newPin.Length > 0)
                {
                    vault.SetPin(newPin);
                    vault.ForgetPinSession();
                }
                if (!vault.PinSessionActive) await Task.Run(vault.StartPinSession);
            }
            else if (vault.HasPin)
            {
                vault.SetPin(null);
            }

            var s = _c.Settings;
            s.LockTimeoutMinutes = UiHelpers.GetChip(TimeoutChips, 5);
            s.LockOnWorkstationLock = LockOnWinLockCheck.IsChecked == true;
            s.IdleLockMinutes = UiHelpers.GetChip(IdleChips, 0);
            s.PinEnabled = usePin;
            s.MaxPinAttempts = UiHelpers.GetChip(PinAttemptsChips, 5);
            s.ForgetPinOnWorkstationLock = ForgetPinCheck.IsChecked == true;

            s.DetectSensitive = DetectSensitiveCheck.IsChecked == true;
            s.SensitiveRequiresPassword = SensitivePasswordCheck.IsChecked == true;
            s.SensitiveRetentionMinutes = UiHelpers.GetChip(SensitiveRetentionChips, 0);
            s.ClearSensitiveSeconds = UiHelpers.GetChip(ClearSensitiveChips, 30);
            s.ClearAfterPasteSeconds = UiHelpers.GetChip(ClearPasteChips, 0);

            s.ExcludedApps = _excluded.ToList();
            s.RespectExcludeMarkers = RespectMarkersCheck.IsChecked == true;

            s.MaxItems = UiHelpers.GetChip(MaxItemsChips, 50);
            s.RetentionDays = UiHelpers.GetChip(RetentionChips, 0);
            s.MaxItemSizeMb = UiHelpers.GetChip(MaxSizeChips, 8);
            s.PersistHistory = PersistCheck.IsChecked == true;
            s.KeepFormatting = FormattingCheck.IsChecked == true;
            s.CaptureImages = ImagesCheck.IsChecked == true;
            s.CaptureFiles = FilesCheck.IsChecked == true;

            s.Hotkey = (HotkeyPreset)UiHelpers.GetChip(HotkeyChips, 0);
            s.AutoPaste = AutoPasteCheck.IsChecked == true;
            try { SystemIntegration.SetAutostart(AutostartCheck.IsChecked == true); } catch { }

            _c.ApplySettings();
            DialogResult = true;
        }
        catch (Exception ex)
        {
            ErrorText.Text = "Speichern fehlgeschlagen: " + ex.Message;
            SaveButton.IsEnabled = true;
            SaveButton.Content = "Speichern";
        }
        finally
        {
            PinBox1.Clear();
            PinBox2.Clear();
            NewPw1.Clear();
            NewPw2.Clear();
        }
    }
}
