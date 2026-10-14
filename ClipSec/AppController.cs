using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using ClipSec.Core;
using ClipSec.Native;
using ClipSec.UI;
using Microsoft.Win32;

namespace ClipSec;

/// <summary>Verbindet Tresor, Verlauf, Sperre, Hotkey, Zwischenablage und Oberfläche.</summary>
internal sealed class AppController : IDisposable
{
    // Application statt App: Werkzeuge (Screenshots) dürfen kein App-Objekt erzeugen,
    // weil WPF dann App.OnStartup – also den kompletten ClipSec-Start – auslöst.
    private readonly Application _app;
    private KeyboardHook? _hook;
    private MessageWindow? _messages;
    private TrayIcon? _tray;
    private ClipWindow? _window;
    private SettingsWindow? _settingsWindow;
    private bool _capturePending;
    private readonly ClipboardClearer _clearer = new();
    private readonly System.Windows.Threading.DispatcherTimer _purgeTimer = new() { Interval = TimeSpan.FromMinutes(1) };

    public AppController(Application app) => _app = app;

    public AppSettings Settings { get; private set; } = new();
    public CryptoVault Vault { get; private set; } = null!;
    public HistoryStore History { get; private set; } = null!;
    public LockManager Lock { get; private set; } = null!;

    /// <summary>Nur für Werkzeuge (Screenshots): Zustand ohne Hotkey, Tray und Zwischenablage-Überwachung.</summary>
    internal void AttachForTooling(AppSettings settings, CryptoVault vault, HistoryStore history, LockManager lockManager)
    {
        Settings = settings;
        Vault = vault;
        History = history;
        Lock = lockManager;
    }

    /// <summary>Fenster, das vor dem Öffnen von ClipSec aktiv war – dorthin wird eingefügt.</summary>
    public IntPtr PreviousForeground { get; private set; }

    // ------------------------------------------------------------------ Start

    public void Start(bool startInTray)
    {
        AppPaths.EnsureDataDir();
        Settings = AppSettings.Load();

        if (!CryptoVault.Exists())
        {
            var setup = new SetupWindow(Settings);
            if (setup.ShowDialog() != true || setup.CreatedVault == null)
            {
                _app.Shutdown();
                return;
            }
            Vault = setup.CreatedVault;
        }
        else
        {
            try
            {
                Vault = CryptoVault.Load();
            }
            catch (Exception ex)
            {
                var answer = MessageBox.Show(
                    $"Der Tresor konnte nicht geladen werden ({ex.Message}).\n\nTresor zurücksetzen? Der gespeicherte Verlauf geht dabei verloren.",
                    "ClipSec", MessageBoxButton.YesNo, MessageBoxImage.Error);
                if (answer == MessageBoxResult.Yes) ResetAndRestart();
                else _app.Shutdown();
                return;
            }
        }

        History = new HistoryStore(Vault, Settings);
        History.Load();
        History.Purge();
        _purgeTimer.Tick += (_, _) => History.Purge();
        _purgeTimer.Start();
        Lock = new LockManager(Vault, History, Settings);
        _ = Lock.AdoptUnlockedAsync(); // nur nach Ersteinrichtung wirksam

        _messages = new MessageWindow();
        _messages.ClipboardChanged += OnClipboardChanged;
        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;

        _tray = new TrayIcon(this);
        Lock.StateChanged += _tray.Update;
        Lock.Tick += _tray.Update;

        _hook = new KeyboardHook(Settings.Hotkey);
        _hook.HotkeyPressed += ShowPopup;
        try
        {
            _hook.Install();
        }
        catch (Exception ex)
        {
            _tray.ShowBalloon("Hotkey nicht verfügbar", ex.Message + " ClipSec ist über das Tray-Symbol erreichbar.");
        }

        if (SystemIntegration.IsWindowsClipboardHistoryEnabled())
            _tray.ShowBalloon("Windows-Zwischenablageverlauf ist aktiv",
                "Windows speichert Kopien zusätzlich unverschlüsselt. Bitte in den ClipSec-Einstellungen deaktivieren.");
        else if (!startInTray)
            _tray.ShowBalloon("ClipSec läuft", $"Öffnen mit {HotkeyText(Settings.Hotkey)}.");
    }

    public static string HotkeyText(HotkeyPreset preset) => preset switch
    {
        HotkeyPreset.CtrlShiftV => "Strg+Umschalt+V",
        HotkeyPreset.CtrlAltV => "Strg+Alt+V",
        _ => "Win+V",
    };

    private void OnSessionSwitch(object? sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect)
            _app.Dispatcher.BeginInvoke(() => Lock.OnWorkstationLocked(suspend: false));
    }

    private void OnPowerModeChanged(object? sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Suspend)
            _app.Dispatcher.BeginInvoke(() => Lock.OnWorkstationLocked(suspend: true));
    }

    // ------------------------------------------------------------------ Aufnehmen

    private void OnClipboardChanged()
    {
        // Manche Programme lösen mehrere Updates hintereinander aus → kurz bündeln.
        if (_capturePending) return;
        _capturePending = true;
        _app.Dispatcher.BeginInvoke(async () =>
        {
            await Task.Delay(120);
            _capturePending = false;
            await CaptureAsync();
        });
    }

    private async Task CaptureAsync()
    {
        ClipPayload? payload;
        try
        {
            payload = ClipboardAccess.Read(Settings);
        }
        catch
        {
            return;
        }
        if (payload == null) return;

        var hash = payload.Hash();
        if (History.IsSameAsLast(hash)) return;
        History.MarkLastCaptured(hash);

        var sensitive = Settings.DetectSensitive && SensitiveDetector.Detect(payload) != null;
        if (sensitive) _clearer.ScheduleForCurrent(Settings.ClearSensitiveSeconds);

        var entry = new StoredEntry { Id = Guid.NewGuid(), CreatedUtc = DateTime.UtcNow, Sensitive = sensitive };
        entry.Blob = await Task.Run(() =>
        {
            var raw = payload.Serialize();
            try { return Vault.Seal(raw, entry.Aad()); }
            finally { CryptographicOperations.ZeroMemory(raw); }
        });
        History.AddSealed(entry, payload);
    }

    // ------------------------------------------------------------------ Popup

    public void ShowPopup()
    {
        if (_settingsWindow != null)
        {
            _settingsWindow.Activate();
            return;
        }

        _window ??= new ClipWindow(this);
        if (_window.IsVisible && _window.IsActive)
        {
            _window.HidePopup();
            return;
        }

        var fg = NativeMethods.GetForegroundWindow();
        if (fg != _window.Handle) PreviousForeground = fg;
        Lock.Touch();
        _window.ShowPopup(PreviousForeground);
    }

    public void OnPopupHidden()
    {
        if (Settings.LockTimeoutMinutes == 0) Lock.Lock();
    }

    /// <param name="plainText">Ohne Formatierung einfügen (Umschalt+Enter).</param>
    public async Task PasteAsync(ClipItem item, bool plainText = false)
    {
        if (ClipboardAccess.Write(item.Payload, plainText) is not { } sequence)
        {
            _tray?.ShowBalloon("Einfügen fehlgeschlagen", "Die Zwischenablage ist gerade durch ein anderes Programm blockiert.");
            return;
        }
        _clearer.Schedule(sequence, Settings.ClearAfterPasteSeconds, item.Sensitive ? Settings.ClearSensitiveSeconds : 0);
        History.Touch(item);
        Lock.Touch();
        _window?.HidePopup();
        if (Settings.AutoPaste) await PasteHelper.PasteIntoAsync(PreviousForeground);
    }

    /// <summary>Master-Passwort erneut abfragen (z. B. für vertrauliche Einträge). Prüft selbst.</summary>
    public bool ConfirmMasterPassword(Window? owner, string title, string message)
    {
        var prompt = new PasswordPrompt(this, title, message);
        if (owner is { IsVisible: true })
        {
            prompt.Owner = owner;
            prompt.WindowStartupLocation = WindowStartupLocation.CenterOwner;
        }
        return prompt.ShowDialog() == true;
    }

    // ------------------------------------------------------------------ Einstellungen & Verwaltung

    public void OpenSettings()
    {
        if (_settingsWindow != null)
        {
            _settingsWindow.Activate();
            return;
        }
        _window?.HidePopup();

        // Einstellungen sind sicherheitsrelevant → immer Master-Passwort (nicht PIN).
        // PasswordPrompt prüft selbst und entsperrt bei Bedarf.
        var prompt = new PasswordPrompt(this, "Einstellungen öffnen",
            "Zum Ändern der Einstellungen ist das Master-Passwort nötig.");
        if (prompt.ShowDialog() != true || !Lock.IsUnlocked) return;

        bool? uninstall;
        Lock.HoldOpen = true;
        try
        {
            _settingsWindow = new SettingsWindow(this);
            _settingsWindow.ShowDialog();
            uninstall = _settingsWindow.UninstallRequested;
        }
        finally
        {
            _settingsWindow = null;
            Lock.HoldOpen = false;
            Lock.Touch();
        }
        if (uninstall is { } deleteData) UninstallSelf(deleteData);
    }

    /// <summary>Deinstallation aus den Einstellungen heraus (diese Instanz ist die installierte).</summary>
    private void UninstallSelf(bool deleteData)
    {
        Lock.Lock();
        Dispose();
        Installer.Uninstall(deleteData);
        MessageBox.Show("ClipSec wurde entfernt.", "ClipSec", MessageBoxButton.OK, MessageBoxImage.Information);
        _app.Shutdown();
    }

    /// <summary>Von SettingsWindow nach dem Speichern aufgerufen.</summary>
    public void ApplySettings()
    {
        Settings.Save();
        if (_hook != null) _hook.Preset = Settings.Hotkey;
        History.ApplySettings();
        _tray?.Update();
    }

    public void ClearHistory()
    {
        var answer = MessageBox.Show("Gesamten Verlauf inklusive angehefteter Einträge löschen?", "ClipSec",
            MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer == MessageBoxResult.Yes) History.ClearAll();
    }

    public void ConfirmReset()
    {
        var answer = MessageBox.Show(
            "Tresor zurücksetzen?\n\nDer komplette Verlauf wird unwiderruflich gelöscht und du vergibst ein neues Master-Passwort. " +
            "Nutze das nur, wenn du dein Passwort vergessen hast.",
            "ClipSec – Tresor zurücksetzen", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer == MessageBoxResult.Yes) ResetAndRestart();
    }

    private void ResetAndRestart()
    {
        Lock?.Lock();
        CryptoVault.DeleteAll();
        Dispose();
        (_app as App)?.ReleaseSingleInstance();
        if (Environment.ProcessPath is { } exe)
            Process.Start(new ProcessStartInfo(exe, "--restart") { UseShellExecute = false });
        _app.Shutdown();
    }

    public void Exit()
    {
        Lock?.Lock();
        _app.Shutdown();
    }

    public void Dispose()
    {
        SystemEvents.SessionSwitch -= OnSessionSwitch;
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        _purgeTimer.Stop();
        try { if (History != null && File.Exists(AppPaths.VaultFile)) History.SaveNow(); } catch { }
        _hook?.Dispose();
        _hook = null;
        _messages?.Dispose();
        _messages = null;
        _tray?.Dispose();
        _tray = null;
    }
}
