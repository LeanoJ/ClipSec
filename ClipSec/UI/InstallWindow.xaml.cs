using System.Diagnostics;
using System.IO;
using System.Windows;
using ClipSec.Core;

namespace ClipSec.UI;

public partial class InstallWindow : Window
{
    public InstallWindow()
    {
        InitializeComponent();
        WindowStyling.ApplyTitleBarTheme(this);

        var installed = Installer.IsInstalled;
        HeaderText.Text = installed ? "ClipSec aktualisieren" : "ClipSec installieren";
        Title = HeaderText.Text;
        InstallButton.Content = installed ? "Aktualisieren" : "Installieren";
        VersionText.Text = installed && Installer.InstalledVersion is { } old
            ? $"Version {old} → {Installer.Version}"
            : $"Version {Installer.Version}";
        PathText.Text = Installer.InstallDir;
        AutostartCheck.IsChecked = !installed || SystemIntegration.IsAutostartEnabled();
        RunningHint.Visibility = Installer.IsAppRunning() ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void Install_Click(object sender, RoutedEventArgs e)
    {
        InstallButton.IsEnabled = false;
        InstallButton.Content = "Bitte warten …";
        ErrorText.Visibility = Visibility.Collapsed;

        var desktop = DesktopCheck.IsChecked == true;
        var autostart = AutostartCheck.IsChecked == true;
        try
        {
            await Task.Run(() =>
            {
                if (!Installer.StopRunningApp(TimeSpan.FromSeconds(10)))
                    throw new InvalidOperationException("Die laufende ClipSec-Instanz ließ sich nicht beenden. Bitte über das Tray-Symbol beenden und erneut versuchen.");
                Installer.Install(desktop, autostart);
            });
            if (LaunchCheck.IsChecked == true) Installer.StartInstalled();
            Close();
        }
        catch (Exception ex)
        {
            ErrorText.Text = "Installation fehlgeschlagen: " + ex.Message;
            ErrorText.Visibility = Visibility.Visible;
            InstallButton.IsEnabled = true;
            InstallButton.Content = Installer.IsInstalled ? "Aktualisieren" : "Installieren";
        }
    }

    /// <summary>Startet diese EXE als normale (portable) App, ohne etwas zu installieren.</summary>
    private void Portable_Click(object sender, RoutedEventArgs e)
    {
        if (Environment.ProcessPath is { } exe)
            Process.Start(new ProcessStartInfo(exe, "--portable") { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(exe) });
        Close();
    }
}
