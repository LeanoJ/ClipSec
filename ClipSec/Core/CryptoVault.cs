using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ClipSec.Core;

public enum PinUnlockResult
{
    Success,
    WrongPin,
    /// <summary>Zu viele Fehlversuche – PIN für diese Sitzung verworfen, Passwort nötig.</summary>
    Exhausted,
    NotAvailable,
}

/// <summary>Womit der Tresor entsperrt werden kann.</summary>
public enum UnlockMode
{
    /// <summary>Nur Master-Passwort.</summary>
    Password = 0,
    /// <summary>Master-Passwort oder ein registrierter Sicherheitsschlüssel (jeweils allein ausreichend).</summary>
    PasswordOrKey = 1,
    /// <summary>Master-Passwort und Sicherheitsschlüssel gemeinsam (2-Faktor).</summary>
    PasswordAndKey = 2,
}

public sealed record SecurityKeyInfo(byte[] CredentialId, string Name, DateTime AddedUtc);

/// <summary>
/// Schlüsselverwaltung von ClipSec.
///
/// Aufbau:
///  • Ein P-256-Schlüsselpaar pro Tresor. Neue Einträge werden mit dem öffentlichen Schlüssel versiegelt
///    (ECDH mit Wegwerf-Schlüssel + AES-256-GCM). Dadurch kann ClipSec auch im gesperrten Zustand
///    mitschreiben, ohne irgendetwas lesen zu können.
///  • Der private Schlüssel liegt auf der Platte nur verschlüsselt in "Fächern":
///      – Passwort-Fach: Schlüssel = PBKDF2-SHA256(Master-Passwort, 600 000 Iterationen)
///      – Schlüssel-Fach (je Sicherheitsschlüssel): Schlüssel = HKDF(hmac-secret des FIDO2-Schlüssels)
///      – Kombi-Fach (2-Faktor): Schlüssel = HKDF(PBKDF2(Passwort) ‖ hmac-secret)
///    Welche Fächer existieren, bestimmt die <see cref="UnlockMode"/>. Im 2-Faktor-Modus gibt es weder
///    ein reines Passwort- noch ein reines Schlüssel-Fach.
///  • "Secrets": PBKDF2(Passwort) und die hmac-secrets der Schlüssel, verschlüsselt mit dem privaten
///    Schlüssel selbst. Nur im entsperrten Zustand lesbar; erlaubt Moduswechsel und Passwortänderung,
///    ohne dass jeder Schlüssel erneut berührt werden muss.
///  • Kurz-PIN: wird nie zum Verschlüsseln auf der Platte verwendet. Nach einer Entsperrung wird der
///    private Schlüssel nur im Arbeitsspeicher mit einem PIN-Schlüssel eingepackt. Prozessende
///    (Neustart/Abmelden) oder zu viele Fehlversuche löschen diese Kopie.
/// </summary>
public sealed class CryptoVault
{
    private const int Pbkdf2Iterations = 600_000;
    private const int PinPbkdf2Iterations = 150_000;
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const byte SealVersion = 1;
    private const int PointSize = 65; // 0x04 | X(32) | Y(32)
    private const int FileVersion = 2;

    private static readonly byte[] VaultAad = Encoding.ASCII.GetBytes("clipsec-vault-v1");
    private static readonly byte[] PinBlobInfo = Encoding.ASCII.GetBytes("clipsec-pin-v1");
    private static readonly byte[] EntryInfo = Encoding.ASCII.GetBytes("clipsec-entry-v1");
    private static readonly byte[] SessionAad = Encoding.ASCII.GetBytes("clipsec-session-v1");
    private static readonly byte[] SecretsInfo = Encoding.ASCII.GetBytes("clipsec-secrets-v1");
    private static readonly byte[] KeySlotInfo = Encoding.ASCII.GetBytes("clipsec-key-v1");
    private static readonly byte[] ComboSlotInfo = Encoding.ASCII.GetBytes("clipsec-password+key-v1");
    private static readonly byte[] SlotAadPrefix = Encoding.ASCII.GetBytes("clipsec-slot-v1");

    private readonly object _sync = new();
    private VaultFile _file;

    // Nur im entsperrten Zustand gesetzt.
    private byte[]? _privateKeyPkcs8;
    private ECDiffieHellman? _privateKey;
    private SecretsData? _secrets;

    // PIN-Sitzung (nur Arbeitsspeicher).
    private byte[]? _sessionWrappedKey;
    private byte[]? _sessionSalt;
    private int _pinFailures;

    private CryptoVault(VaultFile file) => _file = file;

    public bool IsUnlocked { get { lock (_sync) return _privateKey != null; } }

    public bool HasPin => _file.PinBlob != null;

    public bool PinSessionActive { get { lock (_sync) return _sessionWrappedKey != null; } }

    public UnlockMode Mode { get { lock (_sync) return _file.Mode; } }

    /// <summary>Gibt es ein Fach, das allein mit dem Passwort aufgeht?</summary>
    public bool HasPasswordSlot { get { lock (_sync) return _file.WrappedPrivateKey.Length > 0; } }

    public IReadOnlyList<SecurityKeyInfo> SecurityKeys
    {
        get { lock (_sync) return _file.Keys.Select(k => new SecurityKeyInfo(k.CredentialId, k.Name, k.AddedUtc)).ToList(); }
    }

    public IReadOnlyList<byte[]> KeyCredentialIds { get { lock (_sync) return _file.Keys.Select(k => k.CredentialId).ToList(); } }

    /// <summary>Wie das Salt an Windows übergeben wird (bei der ersten Registrierung ermittelt).</summary>
    public bool? FidoRawSalt { get { lock (_sync) return _file.Keys.Count > 0 ? _file.FidoRawSalt : null; } }

    public static bool Exists() => File.Exists(AppPaths.VaultFile);

    // ------------------------------------------------------------------ Lebenszyklus

    public static CryptoVault Create(string password)
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var pkcs8 = ecdh.ExportPkcs8PrivateKey();
        var file = new VaultFile
        {
            Version = FileVersion,
            Iterations = Pbkdf2Iterations,
            Salt = RandomNumberGenerator.GetBytes(16),
            PublicKey = ecdh.ExportSubjectPublicKeyInfo(),
        };
        var vault = new CryptoVault(file);
        lock (vault._sync)
        {
            vault.SetUnlocked(pkcs8);
            vault._secrets = new SecretsData { PasswordKey = DerivePasswordKey(password, file.Salt, file.Iterations) };
            vault.RebuildSlotsLocked();
            vault.Save();
        }
        return vault;
    }

    public static CryptoVault Load()
    {
        var json = File.ReadAllText(AppPaths.VaultFile);
        var file = JsonSerializer.Deserialize<VaultFile>(json)
                   ?? throw new InvalidDataException("Tresor-Datei ist leer oder beschädigt.");
        file.Keys ??= [];
        if (file.PublicKey.Length == 0 || (file.WrappedPrivateKey.Length == 0 && file.Keys.Count == 0))
            throw new InvalidDataException("Tresor-Datei ist unvollständig.");
        return new CryptoVault(file);
    }

    /// <summary>Löscht Tresor und Verlauf unwiderruflich (für "Passwort vergessen").</summary>
    public static void DeleteAll()
    {
        foreach (var f in new[] { AppPaths.VaultFile, AppPaths.HistoryFile })
            if (File.Exists(f)) File.Delete(f);
    }

    private void Save() =>
        AppPaths.WriteAllTextAtomic(AppPaths.VaultFile,
            JsonSerializer.Serialize(_file, new JsonSerializerOptions { WriteIndented = true }));

    // ------------------------------------------------------------------ Entsperren / Sperren

    /// <summary>Nur Passwort (Modus Passwort bzw. Passwort-oder-Schlüssel). Langsam (PBKDF2).</summary>
    public bool UnlockWithPassword(string password)
    {
        byte[] wrapped, salt;
        int iterations;
        lock (_sync)
        {
            if (_file.WrappedPrivateKey.Length == 0) return false; // 2-Faktor: Passwort allein reicht nicht
            wrapped = _file.WrappedPrivateKey;
            salt = _file.Salt;
            iterations = _file.Iterations;
        }

        var kek = DerivePasswordKey(password, salt, iterations);
        var pkcs8 = AeadDecrypt(kek, wrapped, PasswordSlotAad());
        if (pkcs8 == null)
        {
            CryptographicOperations.ZeroMemory(kek);
            return false;
        }
        lock (_sync)
        {
            SetUnlocked(pkcs8);
            _pinFailures = 0;
            if (_secrets == null)
            {
                // Tresor aus Version 1 (ohne Secrets) → jetzt nachrüsten.
                _secrets = new SecretsData { PasswordKey = kek };
                RebuildSlotsLocked();
                Save();
            }
            else
            {
                CryptographicOperations.ZeroMemory(kek);
            }
        }
        return true;
    }

    /// <summary>PBKDF2 des Passworts (für den 2-Faktor-Weg, bevor der Schlüssel berührt wird). Langsam.</summary>
    public byte[] DerivePasswordKey(string password)
    {
        byte[] salt;
        int iterations;
        lock (_sync)
        {
            salt = _file.Salt;
            iterations = _file.Iterations;
        }
        return DerivePasswordKey(password, salt, iterations);
    }

    /// <summary>Nur Sicherheitsschlüssel (Modus Passwort-oder-Schlüssel).</summary>
    public bool UnlockWithKey(byte[] credentialId, byte[] secret) =>
        UnlockWithSlot(credentialId, SlotType.Key, () => HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, KeySize, credentialId, KeySlotInfo));

    /// <summary>Passwort und Sicherheitsschlüssel (2-Faktor-Modus).</summary>
    public bool UnlockWithPasswordAndKey(byte[] passwordKey, byte[] credentialId, byte[] secret) =>
        UnlockWithSlot(credentialId, SlotType.PasswordAndKey, () => ComboKey(passwordKey, secret, credentialId));

    private bool UnlockWithSlot(byte[] credentialId, SlotType type, Func<byte[]> deriveKey)
    {
        KeySlot? slot;
        lock (_sync) slot = _file.Keys.FirstOrDefault(k => k.Type == type && k.CredentialId.AsSpan().SequenceEqual(credentialId));
        if (slot == null || slot.Wrapped.Length == 0) return false;

        var kek = deriveKey();
        try
        {
            var pkcs8 = AeadDecrypt(kek, slot.Wrapped, SlotAad(credentialId));
            if (pkcs8 == null) return false;
            lock (_sync)
            {
                SetUnlocked(pkcs8);
                _pinFailures = 0;
            }
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>Prüft das Passwort, ohne den Zustand zu ändern. Langsam.</summary>
    public bool VerifyPassword(string password)
    {
        var kek = DerivePasswordKey(password);
        try
        {
            lock (_sync)
            {
                if (_secrets != null) return CryptographicOperations.FixedTimeEquals(kek, _secrets.PasswordKey);
                if (_file.WrappedPrivateKey.Length == 0) return false;
            }
            var pkcs8 = AeadDecrypt(kek, _file.WrappedPrivateKey, PasswordSlotAad());
            if (pkcs8 == null) return false;
            CryptographicOperations.ZeroMemory(pkcs8);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>Prüft (entsperrt) ein hmac-secret gegen den gespeicherten Wert des Schlüssels.</summary>
    public bool VerifyKey(byte[] credentialId, byte[] secret)
    {
        lock (_sync)
        {
            return _secrets != null &&
                   _secrets.Keys.TryGetValue(Convert.ToBase64String(credentialId), out var stored) &&
                   CryptographicOperations.FixedTimeEquals(stored, secret);
        }
    }

    /// <summary>Langsam (PBKDF2) – nicht auf dem UI-Thread aufrufen.</summary>
    public PinUnlockResult UnlockWithPin(string pin, int maxAttempts)
    {
        byte[]? wrapped, salt;
        lock (_sync)
        {
            wrapped = _sessionWrappedKey;
            salt = _sessionSalt;
        }
        if (wrapped == null || salt == null) return PinUnlockResult.NotAvailable;

        var key = DerivePinKey(pin, salt);
        try
        {
            var pkcs8 = AeadDecrypt(key, wrapped, SessionAad);
            lock (_sync)
            {
                if (pkcs8 == null)
                {
                    _pinFailures++;
                    if (_pinFailures >= maxAttempts)
                    {
                        ForgetPinSessionLocked();
                        return PinUnlockResult.Exhausted;
                    }
                    return PinUnlockResult.WrongPin;
                }
                _pinFailures = 0;
                SetUnlocked(pkcs8);
                return PinUnlockResult.Success;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public int RemainingPinAttempts(int maxAttempts)
    {
        lock (_sync) return Math.Max(0, maxAttempts - _pinFailures);
    }

    public void Lock()
    {
        lock (_sync)
        {
            _privateKey?.Dispose();
            _privateKey = null;
            if (_privateKeyPkcs8 != null) CryptographicOperations.ZeroMemory(_privateKeyPkcs8);
            _privateKeyPkcs8 = null;
            _secrets?.Wipe();
            _secrets = null;
        }
    }

    /// <summary>Unter _sync aufrufen.</summary>
    private void SetUnlocked(byte[] pkcs8)
    {
        _privateKey?.Dispose();
        if (_privateKeyPkcs8 != null && !ReferenceEquals(_privateKeyPkcs8, pkcs8))
            CryptographicOperations.ZeroMemory(_privateKeyPkcs8);

        var ecdh = ECDiffieHellman.Create();
        ecdh.ImportPkcs8PrivateKey(pkcs8, out _);
        _privateKey = ecdh;
        _privateKeyPkcs8 = pkcs8;

        _secrets?.Wipe();
        _secrets = null;
        if (_file.Secrets is { Length: > 0 } blob)
        {
            var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, pkcs8, KeySize, null, SecretsInfo);
            var raw = AeadDecrypt(key, blob, _file.PublicKey);
            CryptographicOperations.ZeroMemory(key);
            if (raw != null)
            {
                _secrets = JsonSerializer.Deserialize<SecretsData>(raw);
                CryptographicOperations.ZeroMemory(raw);
            }
        }
    }

    // ------------------------------------------------------------------ PIN

    /// <summary>
    /// Legt die PIN-Sitzung an (nach einer vollständigen Entsperrung). Danach kann bis Prozessende mit
    /// PIN entsperrt werden. Langsam (PBKDF2).
    /// </summary>
    public void StartPinSession()
    {
        byte[] pkcs8;
        lock (_sync)
        {
            if (_privateKeyPkcs8 == null || _file.PinBlob == null) return;
            pkcs8 = (byte[])_privateKeyPkcs8.Clone();
        }
        try
        {
            var pinKeyForBlob = HKDF.DeriveKey(HashAlgorithmName.SHA256, pkcs8, KeySize, null, PinBlobInfo);
            var pinBytes = AeadDecrypt(pinKeyForBlob, _file.PinBlob, _file.PublicKey);
            CryptographicOperations.ZeroMemory(pinKeyForBlob);
            if (pinBytes == null) return;

            var pin = Encoding.UTF8.GetString(pinBytes);
            CryptographicOperations.ZeroMemory(pinBytes);

            var salt = RandomNumberGenerator.GetBytes(16);
            var sessionKey = DerivePinKey(pin, salt);
            var wrapped = AeadEncrypt(sessionKey, pkcs8, SessionAad);
            CryptographicOperations.ZeroMemory(sessionKey);

            lock (_sync)
            {
                _sessionSalt = salt;
                _sessionWrappedKey = wrapped;
                _pinFailures = 0;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    public void ForgetPinSession()
    {
        lock (_sync) ForgetPinSessionLocked();
    }

    private void ForgetPinSessionLocked()
    {
        if (_sessionWrappedKey != null) CryptographicOperations.ZeroMemory(_sessionWrappedKey);
        _sessionWrappedKey = null;
        _sessionSalt = null;
        _pinFailures = 0;
    }

    /// <summary>Setzt oder entfernt (null) die PIN. Erfordert entsperrten Tresor.</summary>
    public void SetPin(string? pin)
    {
        lock (_sync)
        {
            if (_privateKeyPkcs8 == null) throw new InvalidOperationException("Tresor ist gesperrt.");
            if (pin == null)
            {
                _file.PinBlob = null;
                ForgetPinSessionLocked();
            }
            else
            {
                var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, _privateKeyPkcs8, KeySize, null, PinBlobInfo);
                var pinBytes = Encoding.UTF8.GetBytes(pin);
                _file.PinBlob = AeadEncrypt(key, pinBytes, _file.PublicKey);
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(pinBytes);
            }
            Save();
        }
    }

    // ------------------------------------------------------------------ Passwort & Sicherheitsschlüssel

    /// <summary>Ändert das Master-Passwort (alle Fächer werden neu verschlüsselt). Erfordert entsperrten Tresor. Langsam.</summary>
    public void ChangePassword(string newPassword)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var kek = DerivePasswordKey(newPassword, salt, Pbkdf2Iterations);
        lock (_sync)
        {
            var secrets = RequireSecrets();
            CryptographicOperations.ZeroMemory(secrets.PasswordKey);
            secrets.PasswordKey = kek;
            _file.Salt = salt;
            _file.Iterations = Pbkdf2Iterations;
            RebuildSlotsLocked();
            Save();
        }
    }

    /// <summary>Salt für hmac-secret (für alle Schlüssel dieses Tresors gleich; öffentlich).</summary>
    public byte[] EnsureFidoSalt()
    {
        lock (_sync)
        {
            if (_file.FidoSalt is not { Length: 32 })
            {
                _file.FidoSalt = RandomNumberGenerator.GetBytes(32);
                Save();
            }
            return _file.FidoSalt;
        }
    }

    /// <summary>Registriert einen Sicherheitsschlüssel. Erster Schlüssel → Modus „Passwort oder Schlüssel“.</summary>
    public void AddSecurityKey(byte[] credentialId, string name, byte[] secret, bool rawSalt)
    {
        lock (_sync)
        {
            var secrets = RequireSecrets();
            if (_file.Keys.Any(k => k.CredentialId.AsSpan().SequenceEqual(credentialId)))
                throw new InvalidOperationException("Dieser Schlüssel ist bereits registriert.");
            if (_file.Keys.Count == 0) _file.FidoRawSalt = rawSalt;
            secrets.Keys[Convert.ToBase64String(credentialId)] = secret;
            _file.Keys.Add(new KeySlot
            {
                CredentialId = credentialId,
                Name = string.IsNullOrWhiteSpace(name) ? "Sicherheitsschlüssel" : name.Trim(),
                AddedUtc = DateTime.UtcNow,
            });
            if (_file.Mode == UnlockMode.Password) _file.Mode = UnlockMode.PasswordOrKey;
            RebuildSlotsLocked();
            Save();
        }
    }

    /// <summary>Entfernt einen Schlüssel. Ohne Schlüssel gilt wieder „nur Passwort“.</summary>
    public void RemoveSecurityKey(byte[] credentialId)
    {
        lock (_sync)
        {
            var secrets = RequireSecrets();
            _file.Keys.RemoveAll(k => k.CredentialId.AsSpan().SequenceEqual(credentialId));
            if (secrets.Keys.Remove(Convert.ToBase64String(credentialId), out var old)) CryptographicOperations.ZeroMemory(old);
            if (_file.Keys.Count == 0) _file.Mode = UnlockMode.Password;
            RebuildSlotsLocked();
            Save();
        }
    }

    public void RenameSecurityKey(byte[] credentialId, string name)
    {
        lock (_sync)
        {
            var slot = _file.Keys.FirstOrDefault(k => k.CredentialId.AsSpan().SequenceEqual(credentialId));
            if (slot == null || string.IsNullOrWhiteSpace(name)) return;
            slot.Name = name.Trim();
            Save();
        }
    }

    /// <summary>Wechselt die Entsperr-Art. Erfordert entsperrten Tresor; Schlüssel müssen nicht berührt werden.</summary>
    public void SetMode(UnlockMode mode)
    {
        lock (_sync)
        {
            RequireSecrets();
            if (mode != UnlockMode.Password && _file.Keys.Count == 0)
                throw new InvalidOperationException("Dafür muss mindestens ein Sicherheitsschlüssel registriert sein.");
            if (mode == UnlockMode.Password && _file.Keys.Count > 0)
                throw new InvalidOperationException("Zuerst alle Sicherheitsschlüssel entfernen.");
            _file.Mode = mode;
            RebuildSlotsLocked();
            Save();
        }
    }

    /// <summary>Erzeugt alle Fächer passend zur Betriebsart neu. Unter _sync, entsperrt.</summary>
    private void RebuildSlotsLocked()
    {
        var secrets = RequireSecrets();
        var pkcs8 = _privateKeyPkcs8!;

        _file.WrappedPrivateKey = _file.Mode == UnlockMode.PasswordAndKey
            ? []
            : AeadEncrypt(secrets.PasswordKey, pkcs8, PasswordSlotAad());

        foreach (var slot in _file.Keys)
        {
            // Geheimnis fehlt (z. B. beschädigte Secrets) → Fach unverändert lassen statt abzustürzen.
            if (!secrets.Keys.TryGetValue(Convert.ToBase64String(slot.CredentialId), out var secret)) continue;
            byte[]? kek = _file.Mode switch
            {
                UnlockMode.PasswordOrKey => HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, KeySize, slot.CredentialId, KeySlotInfo),
                UnlockMode.PasswordAndKey => ComboKey(secrets.PasswordKey, secret, slot.CredentialId),
                _ => null,
            };
            slot.Type = _file.Mode == UnlockMode.PasswordAndKey ? SlotType.PasswordAndKey : SlotType.Key;
            slot.Wrapped = kek == null ? [] : AeadEncrypt(kek, pkcs8, SlotAad(slot.CredentialId));
            if (kek != null) CryptographicOperations.ZeroMemory(kek);
        }

        var secretsKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, pkcs8, KeySize, null, SecretsInfo);
        var json = JsonSerializer.SerializeToUtf8Bytes(secrets);
        _file.Secrets = AeadEncrypt(secretsKey, json, _file.PublicKey);
        CryptographicOperations.ZeroMemory(secretsKey);
        CryptographicOperations.ZeroMemory(json);
        _file.Version = FileVersion;
    }

    private SecretsData RequireSecrets()
    {
        if (_privateKeyPkcs8 == null) throw new InvalidOperationException("Tresor ist gesperrt.");
        return _secrets ?? throw new InvalidOperationException("Bitte einmal mit dem Master-Passwort entsperren.");
    }

    private static byte[] ComboKey(byte[] passwordKey, byte[] secret, byte[] credentialId)
    {
        var ikm = Concat(passwordKey, secret);
        try { return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, KeySize, credentialId, ComboSlotInfo); }
        finally { CryptographicOperations.ZeroMemory(ikm); }
    }

    private byte[] PasswordSlotAad() => Concat(VaultAad, _file.PublicKey);

    private static byte[] SlotAad(byte[] credentialId) => Concat(SlotAadPrefix, credentialId);

    // ------------------------------------------------------------------ Versiegeln / Öffnen

    /// <summary>Verschlüsselt mit dem öffentlichen Schlüssel – funktioniert auch im gesperrten Zustand.</summary>
    public byte[] Seal(byte[] plaintext, byte[] aad)
    {
        using var recipient = ECDiffieHellman.Create();
        recipient.ImportSubjectPublicKeyInfo(_file.PublicKey, out _);

        using var eph = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var ephPoint = ExportPoint(eph);
        var key = eph.DeriveKeyFromHash(recipient.PublicKey, HashAlgorithmName.SHA256, Concat(EntryInfo, ephPoint), null);
        try
        {
            var body = AeadEncrypt(key, plaintext, aad);
            var result = new byte[1 + PointSize + body.Length];
            result[0] = SealVersion;
            ephPoint.CopyTo(result, 1);
            body.CopyTo(result, 1 + PointSize);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Entschlüsselt einen versiegelten Eintrag. Null bei Manipulation/falschem Schlüssel.</summary>
    public byte[]? Open(byte[] sealedData, byte[] aad)
    {
        if (sealedData.Length < 1 + PointSize + NonceSize + TagSize || sealedData[0] != SealVersion)
            return null;

        var ephPoint = sealedData.AsSpan(1, PointSize).ToArray();
        var body = sealedData.AsSpan(1 + PointSize).ToArray();

        using var eph = ImportPoint(ephPoint);
        byte[] key;
        lock (_sync)
        {
            if (_privateKey == null) throw new InvalidOperationException("Tresor ist gesperrt.");
            key = _privateKey.DeriveKeyFromHash(eph.PublicKey, HashAlgorithmName.SHA256, Concat(EntryInfo, ephPoint), null);
        }
        try
        {
            return AeadDecrypt(key, body, aad);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    // ------------------------------------------------------------------ Hilfsfunktionen

    private static byte[] DerivePasswordKey(string password, byte[] salt, int iterations)
    {
        var pw = Encoding.UTF8.GetBytes(password);
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(pw, salt, iterations, HashAlgorithmName.SHA256, KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pw);
        }
    }

    private static byte[] DerivePinKey(string pin, byte[] salt) => DerivePasswordKey(pin, salt, PinPbkdf2Iterations);

    /// <summary>Format: nonce(12) | tag(16) | ciphertext</summary>
    private static byte[] AeadEncrypt(byte[] key, byte[] plaintext, byte[] aad)
    {
        var output = new byte[NonceSize + TagSize + plaintext.Length];
        var nonce = output.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, output.AsSpan(NonceSize + TagSize), output.AsSpan(NonceSize, TagSize), aad);
        return output;
    }

    private static byte[]? AeadDecrypt(byte[] key, byte[] data, byte[] aad)
    {
        if (data.Length < NonceSize + TagSize) return null;
        var plaintext = new byte[data.Length - NonceSize - TagSize];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(data.AsSpan(0, NonceSize), data.AsSpan(NonceSize + TagSize),
                data.AsSpan(NonceSize, TagSize), plaintext, aad);
            return plaintext;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            return null;
        }
    }

    private static byte[] ExportPoint(ECDiffieHellman ecdh)
    {
        var p = ecdh.ExportParameters(false);
        var point = new byte[PointSize];
        point[0] = 0x04;
        p.Q.X!.CopyTo(point, 1);
        p.Q.Y!.CopyTo(point, 33);
        return point;
    }

    private static ECDiffieHellman ImportPoint(byte[] point)
    {
        if (point.Length != PointSize || point[0] != 0x04) throw new CryptographicException("Ungültiger Punkt.");
        var p = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = point[1..33], Y = point[33..65] },
        };
        return ECDiffieHellman.Create(p);
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r, a.Length);
        return r;
    }

    // ------------------------------------------------------------------ Dateiformat

    private enum SlotType
    {
        Key = 1,
        PasswordAndKey = 2,
    }

    private sealed class KeySlot
    {
        public byte[] CredentialId { get; set; } = [];
        public string Name { get; set; } = "";
        public DateTime AddedUtc { get; set; }
        public SlotType Type { get; set; }
        public byte[] Wrapped { get; set; } = [];
    }

    private sealed class VaultFile
    {
        public int Version { get; set; }
        public int Iterations { get; set; }
        public byte[] Salt { get; set; } = [];
        public byte[] PublicKey { get; set; } = [];
        /// <summary>Passwort-Fach (leer im 2-Faktor-Modus). Name aus Version 1 beibehalten → ältere ClipSec-Versionen lesen ihn weiter.</summary>
        public byte[] WrappedPrivateKey { get; set; } = [];
        public byte[]? PinBlob { get; set; }
        // Version 2
        public UnlockMode Mode { get; set; }
        public byte[]? FidoSalt { get; set; }
        public bool FidoRawSalt { get; set; }
        public List<KeySlot> Keys { get; set; } = [];
        public byte[]? Secrets { get; set; }
    }

    private sealed class SecretsData
    {
        public byte[] PasswordKey { get; set; } = [];
        public Dictionary<string, byte[]> Keys { get; set; } = [];

        public void Wipe()
        {
            CryptographicOperations.ZeroMemory(PasswordKey);
            foreach (var v in Keys.Values) CryptographicOperations.ZeroMemory(v);
        }
    }
}
