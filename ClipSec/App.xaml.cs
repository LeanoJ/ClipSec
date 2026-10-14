using System.Windows;
using System.Windows.Threading;
using ClipSec.Core;
using ClipSec.UI;

namespace ClipSec;

public partial class App : Application
{
    private const string ShowEventName = @"Local\ClipSec.ShowPopup";

    private Mutex? _mutex;
    private EventWaitHandle? _showEvent;
    private EventWaitHandle? _exitEvent;
    private AppController? _controller;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        Theme.Apply(Resources);
        DispatcherUnhandledException += OnUnhandledException;

        if (e.Args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase))
        {
            RunUninstall();
            return;
        }
        if (Installer.IsSetupMode(e.Args))
        {
            new InstallWindow().ShowDialog();
            Shutdown();
            return;
        }

        _mutex = new Mutex(true, Installer.MutexName, out var created);
        if (!created && e.Args.Contains("--restart"))
        {
            // Nach "Tresor zurücksetzen": warten, bis die alte Instanz beendet ist.
            try { created = _mutex.WaitOne(TimeSpan.FromSeconds(10)); }
            catch (AbandonedMutexException) { created = true; }
        }
        if (!created)
        {
            // Läuft schon → vorhandene Instanz soll ihr Fenster zeigen.
            try { EventWaitHandle.OpenExisting(ShowEventName).Set(); } catch { }
            _mutex = null;
            Shutdown();
            return;
        }

        _controller = new AppController(this);
        _showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        ThreadPool.RegisterWaitForSingleObject(_showEvent,
            (_, _) => Dispatcher.BeginInvoke(() => _controller?.ShowPopup()), null, -1, false);
        // Installer/Deinstallation bittet über dieses Ereignis um ein sauberes Beenden.
        _exitEvent = new EventWaitHandle(false, EventResetMode.AutoReset, Installer.ExitEventName);
        ThreadPool.RegisterWaitForSingleObject(_exitEvent,
            (_, _) => Dispatcher.BeginInvoke(() => _controller?.Exit()), null, -1, true);

        _controller.Start(startInTray: e.Args.Contains("--tray"));
    }

    private void RunUninstall()
    {
        if (MessageBox.Show("ClipSec wirklich deinstallieren?", "ClipSec deinstallieren",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            Shutdown();
            return;
        }
        var deleteData = MessageBox.Show(
            "Auch den verschlüsselten Verlauf und die Einstellungen löschen?\n\n" +
            "„Nein“ behält die Daten für eine spätere Neuinstallation.",
            "ClipSec deinstallieren", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

        Installer.StopRunningApp(TimeSpan.FromSeconds(10));
        Installer.Uninstall(deleteData);
        MessageBox.Show("ClipSec wurde entfernt.", "ClipSec", MessageBoxButton.OK, MessageBoxImage.Information);
        Shutdown();
    }

    public void ReleaseSingleInstance()
    {
        try { _mutex?.ReleaseMutex(); } catch { }
        _mutex?.Dispose();
        _mutex = null;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _controller?.Dispose();
        ReleaseSingleInstance();
        base.OnExit(e);
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show($"Unerwarteter Fehler:\n\n{e.Exception.Message}", "ClipSec",
            MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
