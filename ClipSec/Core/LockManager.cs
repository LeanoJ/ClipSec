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

    public LockManager(CryptoVault vault, HistoryStore history, AppSettings settings, ISecurityKeyProvider? keys = null)
    {
        _vault = vault;
        _history = history;
        _settings = settings;
        Keys = keys ?? new WebAuthnSecurityKeyProvider();
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => OnTick();
        _timer.Start();
    }

    public LockState State { get; private set; } = LockState.Locked;

    public ISecurityKeyProvider Keys { get; }

    public UnlockMode Mode => _vault.Mode;

    /// <summary>Läuft gerade eine Abfrage am Sicherheitsschlüssel (Windows-Dialog offen)?</summary>
    public bool KeyPromptActive { get; private set; }

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

    /// <summary>
    /// Entsperren mit Passwort. Im 2-Faktor-Modus folgt danach automatisch die Abfrage am
    /// Sicherheitsschlüssel (<paramref name="hwnd"/> = Fenster, über dem der Windows-Dialog erscheint).
    /// </summary>
    public async Task<(bool ok, string? error)> UnlockWithPasswordAsync(string password, IntPtr hwnd = default)
    {
        if (PasswordBlockedFor > TimeSpan.Zero)
            return (false, $"Zu viele Fehlversuche. Bitte {Math.Ceiling(PasswordBlockedFor.TotalSeconds)} s warten.");

        if (_vault.Mode == UnlockMode.PasswordAndKey)
        {
            var passwordKey = await Task.Run(() => _vault.DerivePasswordKey(password));
            try
            {
                var key = await AskKeyAsync(hwnd);
                var ok2 = await Task.Run(() => _vault.UnlockWithPasswordAndKey(passwordKey, key.CredentialId, key.Secret));
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(key.Secret);
                if (!ok2) return (false, RegisterPasswordFailure());
            }
            catch (SecurityKeyException ex)
            {
                return (false, ex.Message);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(passwordKey);
            }
        }
        else
        {
            var ok = await Task.Run(() => _vault.UnlockWithPassword(password));
            if (!ok) return (false, RegisterPasswordFailure());
        }

        _passwordFailures = 0;
        await CompleteFullUnlockAsync();
        return (true, null);
    }

    /// <summary>Entsperren nur mit Sicherheitsschlüssel (Modus „Passwort oder Schlüssel“).</summary>
    public async Task<(bool ok, string? error)> UnlockWithKeyAsync(IntPtr hwnd)
    {
        if (_vault.Mode != UnlockMode.PasswordOrKey)
            return (false, _vault.Mode == UnlockMode.PasswordAndKey
                ? "Bitte Master-Passwort eingeben – danach wird der Schlüssel abgefragt."
                : "Es ist kein Sicherheitsschlüssel eingerichtet.");
        try
        {
            var key = await AskKeyAsync(hwnd);
            var ok = await Task.Run(() => _vault.UnlockWithKey(key.CredentialId, key.Secret));
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(key.Secret);
            if (!ok) return (false, "Dieser Schlüssel passt nicht zu diesem Tresor.");
        }
        catch (SecurityKeyException ex)
        {
            return (false, ex.Message);
        }
        await CompleteFullUnlockAsync();
        return (true, null);
    }

    private async Task<KeySecret> AskKeyAsync(IntPtr hwnd)
    {
        var ids = _vault.KeyCredentialIds;
        if (ids.Count == 0) throw new SecurityKeyException("Es ist kein Sicherheitsschlüssel eingerichtet.");
        if (!Keys.IsSupported(out var reason)) throw new SecurityKeyException(reason ?? "Nicht unterstützt.");
        var salt = _vault.EnsureFidoSalt();
        var raw = _vault.FidoRawSalt ?? false;
        KeyPromptActive = true;
        try
        {
            return await Task.Run(() => Keys.GetSecret(hwnd, ids, salt, raw));
        }
        finally
        {
            KeyPromptActive = false;
        }
    }

    /// <summary>Nach Passwort- oder Schlüssel-Entsperrung: PIN-Sitzung anlegen, Verlauf entschlüsseln.</summary>
    private async Task CompleteFullUnlockAsync()
    {
        if (_settings.PinEnabled && _vault.HasPin && !_vault.PinSessionActive)
            await Task.Run(_vault.StartPinSession);
        await FinishUnlockAsync();
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

    /// <summary>Bestätigung per Sicherheitsschlüssel statt Passwort (entsperrt, Modus „Passwort oder Schlüssel“).</summary>
    public async Task<(bool ok, string? error)> VerifyKeyAsync(IntPtr hwnd)
    {
        if (_vault.Mode != UnlockMode.PasswordOrKey) return (false, "Bitte Master-Passwort verwenden.");
        try
        {
            var key = await AskKeyAsync(hwnd);
            var ok = _vault.VerifyKey(key.CredentialId, key.Secret);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(key.Secret);
            return ok ? (true, null) : (false, "Dieser Schlüssel passt nicht zu diesem Tresor.");
        }
        catch (SecurityKeyException ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>
    /// Registriert einen neuen Sicherheitsschlüssel (Tresor muss entsperrt sein).
    /// Windows fragt dabei zweimal nach dem Schlüssel: Anlegen + hmac-secret abholen.
    /// </summary>
    public async Task<(bool ok, string? error)> AddSecurityKeyAsync(IntPtr hwnd, string name)
    {
        if (!Keys.IsSupported(out var reason)) return (false, reason);
        if (!_vault.IsUnlocked) return (false, "ClipSec ist gesperrt.");
        var salt = _vault.EnsureFidoSalt();
        var existing = _vault.KeyCredentialIds;
        var raw = _vault.FidoRawSalt; // null beim ersten Schlüssel → ermitteln
        KeyPromptActive = true;
        try
        {
            var credentialId = await Task.Run(() => Keys.Register(hwnd, existing));
            var key = await Task.Run(() => Keys.GetSecret(hwnd, [credentialId], salt, raw));
            _vault.AddSecurityKey(credentialId, name, key.Secret, key.RawSalt);
            return (true, null);
        }
        catch (SecurityKeyException ex)
        {
            return (false, ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return (false, ex.Message);
        }
        finally
        {
            KeyPromptActive = false;
        }
    }

    /// <summary>Prüft, ob ein registrierter Schlüssel noch das richtige Geheimnis liefert.</summary>
    public async Task<(bool ok, string? error)> TestSecurityKeyAsync(IntPtr hwnd, byte[] credentialId)
    {
        if (!_vault.IsUnlocked) return (false, "ClipSec ist gesperrt.");
        try
        {
            var salt = _vault.EnsureFidoSalt();
            var raw = _vault.FidoRawSalt ?? false;
            KeyPromptActive = true;
            var key = await Task.Run(() => Keys.GetSecret(hwnd, [credentialId], salt, raw));
            var ok = _vault.VerifyKey(key.CredentialId, key.Secret);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(key.Secret);
            return ok ? (true, null) : (false, "Der Schlüssel liefert ein anderes Geheimnis – bitte entfernen und neu hinzufügen.");
        }
        catch (SecurityKeyException ex)
        {
            return (false, ex.Message);
        }
        finally
        {
            KeyPromptActive = false;
        }
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
        await CompleteFullUnlockAsync();
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
