using System.Windows.Threading;

namespace ClipSec.Core;

public enum LockState
{
    Locked,
    Unlocked,
}

/// <summary>
/// Sperrlogik: gleitender Inaktivitäts-Timer, PIN/Passwort-Entsperrung, Bremse gegen Durchprobieren.
/// Als "Aktivität" zählt nur die Benutzung von ClipSec selbst (Hotkey, Auswahl, Bedienung) –
/// normales Kopieren in anderen Programmen verlängert die Entsperrung nicht.
/// </summary>
public sealed class LockManager
{
    private readonly CryptoVault _vault;
    private readonly HistoryStore _history;
    private readonly AppSettings _settings;
    private readonly DispatcherTimer _timer;
    private DateTime _lastActivityUtc = DateTime.MinValue;
    private int _passwordFailures;
    private DateTime _passwordBlockedUntilUtc = DateTime.MinValue;

    public LockManager(CryptoVault vault, HistoryStore history, AppSettings settings)
    {
        _vault = vault;
        _history = history;
        _settings = settings;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => OnTick();
        _timer.Start();
    }

    public LockState State { get; private set; } = LockState.Locked;

    public bool IsUnlocked => State == LockState.Unlocked;

    /// <summary>Kann gerade per PIN entsperrt werden (Passwort wurde in dieser Sitzung schon eingegeben).</summary>
    public bool CanUsePin => _settings.PinEnabled && _vault.HasPin && _vault.PinSessionActive;

    public event Action? StateChanged;

    /// <summary>Sekündlich, für Countdown-Anzeigen.</summary>
    public event Action? Tick;

    public TimeSpan? RemainingUnlocked
    {
        get
        {
            if (!IsUnlocked || _settings.LockTimeoutMinutes <= 0) return null;
            var left = _lastActivityUtc.AddMinutes(_settings.LockTimeoutMinutes) - DateTime.UtcNow;
            return left < TimeSpan.Zero ? TimeSpan.Zero : left;
        }
    }

    public TimeSpan PasswordBlockedFor
    {
        get
        {
            var left = _passwordBlockedUntilUtc - DateTime.UtcNow;
            return left < TimeSpan.Zero ? TimeSpan.Zero : left;
        }
    }

    public int RemainingPinAttempts => _vault.RemainingPinAttempts(_settings.MaxPinAttempts);

    /// <summary>Setzt den Timer zurück (gleitende Entsperrung).</summary>
    public void Touch()
    {
        if (IsUnlocked) _lastActivityUtc = DateTime.UtcNow;
    }

    private void OnTick()
    {
        if (HoldOpen) Touch();
        if (IsUnlocked && _settings.LockTimeoutMinutes > 0 && RemainingUnlocked == TimeSpan.Zero)
            Lock();
        // Zusätzlich: PC insgesamt unbenutzt (keine Maus/Tastatur) → sperren.
        else if (IsUnlocked && !HoldOpen && _settings.IdleLockMinutes > 0 &&
                 Native.NativeMethods.GetSystemIdleTime() >= TimeSpan.FromMinutes(_settings.IdleLockMinutes))
            Lock();
        Tick?.Invoke();
    }

    public void Lock()
    {
        _vault.Lock();
        _history.ClearDecrypted();
        if (State != LockState.Locked)
        {
            State = LockState.Locked;
            StateChanged?.Invoke();
        }
        // Entschlüsselte Inhalte möglichst schnell aus dem Speicher räumen.
        GC.Collect();
        GC.WaitForPendingFinalizers();
    }

    public async Task<(bool ok, string? error)> UnlockWithPasswordAsync(string password)
    {
        if (PasswordBlockedFor > TimeSpan.Zero)
            return (false, $"Zu viele Fehlversuche. Bitte {Math.Ceiling(PasswordBlockedFor.TotalSeconds)} s warten.");

        var ok = await Task.Run(() => _vault.UnlockWithPassword(password));
        if (!ok) return (false, RegisterPasswordFailure());

        _passwordFailures = 0;
        if (_settings.PinEnabled && _vault.HasPin && !_vault.PinSessionActive)
            await Task.Run(_vault.StartPinSession);
        await FinishUnlockAsync();
        return (true, null);
    }

    /// <summary>Prüft das Passwort ohne Zustandswechsel (z. B. für Einstellungen) – mit derselben Bremse.</summary>
    public async Task<(bool ok, string? error)> VerifyPasswordAsync(string password)
    {
        if (PasswordBlockedFor > TimeSpan.Zero)
            return (false, $"Zu viele Fehlversuche. Bitte {Math.Ceiling(PasswordBlockedFor.TotalSeconds)} s warten.");
        var ok = await Task.Run(() => _vault.VerifyPassword(password));
        if (!ok) return (false, RegisterPasswordFailure());
        _passwordFailures = 0;
        return (true, null);
    }

    private string RegisterPasswordFailure()
    {
        _passwordFailures++;
        if (_passwordFailures >= 3)
        {
            var seconds = Math.Min(60, 1 << Math.Min(6, _passwordFailures - 2)); // 2, 4, 8 … 60 s
            _passwordBlockedUntilUtc = DateTime.UtcNow.AddSeconds(seconds);
        }
        return "Falsches Passwort.";
    }

    public async Task<(bool ok, string? error)> UnlockWithPinAsync(string pin)
    {
        var result = await Task.Run(() => _vault.UnlockWithPin(pin, _settings.MaxPinAttempts));
        switch (result)
        {
            case PinUnlockResult.Success:
                await FinishUnlockAsync();
                return (true, null);
            case PinUnlockResult.WrongPin:
                return (false, $"Falsche PIN. Noch {RemainingPinAttempts} Versuch(e).");
            case PinUnlockResult.Exhausted:
                StateChanged?.Invoke();
                return (false, "Zu viele Fehlversuche – bitte mit Passwort entsperren.");
            default:
                return (false, "PIN ist nicht verfügbar – bitte mit Passwort entsperren.");
        }
    }

    /// <summary>Übernimmt einen bereits entsperrten Tresor (direkt nach der Ersteinrichtung).</summary>
    public async Task AdoptUnlockedAsync()
    {
        if (!_vault.IsUnlocked) return;
        if (_settings.PinEnabled && _vault.HasPin && !_vault.PinSessionActive)
            await Task.Run(_vault.StartPinSession);
        await FinishUnlockAsync();
    }

    /// <summary>Solange true (z. B. Einstellungen offen), wird nicht automatisch gesperrt.</summary>
    public bool HoldOpen { get; set; }

    private async Task FinishUnlockAsync()
    {
        var snapshot = _history.Snapshot();
        try
        {
            var items = await Task.Run(() => _history.Decrypt(snapshot));
            if (!_vault.IsUnlocked) return; // in der Zwischenzeit wieder gesperrt (z. B. Win+L)
            _history.SetDecrypted(snapshot, items);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        State = LockState.Unlocked;
        _lastActivityUtc = DateTime.UtcNow;
        StateChanged?.Invoke();
    }

    /// <summary>Windows wurde gesperrt (Win+L) oder geht in den Ruhezustand.</summary>
    public void OnWorkstationLocked(bool suspend)
    {
        if (suspend || _settings.LockOnWorkstationLock) Lock();
        if (_settings.ForgetPinOnWorkstationLock)
        {
            _vault.ForgetPinSession();
            StateChanged?.Invoke();
        }
    }
}
