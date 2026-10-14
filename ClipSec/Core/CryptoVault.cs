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

/// <summary>
/// Schlüsselverwaltung von ClipSec.
///
/// Aufbau:
///  • Ein P-256-Schlüsselpaar pro Tresor. Neue Einträge werden mit dem öffentlichen Schlüssel versiegelt
///    (ECDH mit Wegwerf-Schlüssel + AES-256-GCM). Dadurch kann ClipSec auch im gesperrten Zustand
///    mitschreiben, ohne irgendetwas lesen zu können.
///  • Der private Schlüssel liegt auf der Platte nur verschlüsselt mit einem Schlüssel aus
///    PBKDF2-SHA256(Master-Passwort, 600 000 Iterationen).
///  • Kurz-PIN: wird nie zum Verschlüsseln auf der Platte verwendet. Nach einer Passwort-Entsperrung
///    wird der private Schlüssel nur im Arbeitsspeicher mit einem PIN-Schlüssel eingepackt. Prozessende
///    (Neustart/Abmelden) oder zu viele Fehlversuche löschen diese Kopie → Passwort nötig.
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

    private static readonly byte[] VaultAad = Encoding.ASCII.GetBytes("clipsec-vault-v1");
    private static readonly byte[] PinBlobInfo = Encoding.ASCII.GetBytes("clipsec-pin-v1");
    private static readonly byte[] EntryInfo = Encoding.ASCII.GetBytes("clipsec-entry-v1");
    private static readonly byte[] SessionAad = Encoding.ASCII.GetBytes("clipsec-session-v1");

    private readonly object _sync = new();
    private VaultFile _file;

    // Nur im entsperrten Zustand gesetzt.
    private byte[]? _privateKeyPkcs8;
    private ECDiffieHellman? _privateKey;

    // PIN-Sitzung (nur Arbeitsspeicher).
    private byte[]? _sessionWrappedKey;
    private byte[]? _sessionSalt;
    private int _pinFailures;

    private CryptoVault(VaultFile file) => _file = file;

    public bool IsUnlocked { get { lock (_sync) return _privateKey != null; } }

    public bool HasPin => _file.PinBlob != null;

    public bool PinSessionActive { get { lock (_sync) return _sessionWrappedKey != null; } }

    public static bool Exists() => File.Exists(AppPaths.VaultFile);

    // ------------------------------------------------------------------ Lebenszyklus

    public static CryptoVault Create(string password)
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var pkcs8 = ecdh.ExportPkcs8PrivateKey();
        var file = new VaultFile
        {
            Version = 1,
            Iterations = Pbkdf2Iterations,
            PublicKey = ecdh.ExportSubjectPublicKeyInfo(),
        };
        var vault = new CryptoVault(file);
        vault.WrapWithPassword(password, pkcs8);
        vault.SetUnlocked(pkcs8);
        vault.Save();
        return vault;
    }

    public static CryptoVault Load()
    {
        var json = File.ReadAllText(AppPaths.VaultFile);
        var file = JsonSerializer.Deserialize<VaultFile>(json)
                   ?? throw new InvalidDataException("Tresor-Datei ist leer oder beschädigt.");
        if (file.PublicKey.Length == 0 || file.WrappedPrivateKey.Length == 0)
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

    /// <summary>Langsam (PBKDF2) – nicht auf dem UI-Thread aufrufen.</summary>
    public bool UnlockWithPassword(string password)
    {
        var pkcs8 = TryUnwrapWithPassword(password);
        if (pkcs8 == null) return false;
        lock (_sync)
        {
            SetUnlocked(pkcs8);
            _pinFailures = 0;
        }
        return true;
    }

    /// <summary>Prüft das Passwort, ohne den Zustand zu ändern. Langsam.</summary>
    public bool VerifyPassword(string password)
    {
        var pkcs8 = TryUnwrapWithPassword(password);
        if (pkcs8 == null) return false;
        CryptographicOperations.ZeroMemory(pkcs8);
        return true;
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
        }
    }

    private void SetUnlocked(byte[] pkcs8)
    {
        _privateKey?.Dispose();
        if (_privateKeyPkcs8 != null && !ReferenceEquals(_privateKeyPkcs8, pkcs8))
            CryptographicOperations.ZeroMemory(_privateKeyPkcs8);

        var ecdh = ECDiffieHellman.Create();
        ecdh.ImportPkcs8PrivateKey(pkcs8, out _);
        _privateKey = ecdh;
        _privateKeyPkcs8 = pkcs8;
    }

    // ------------------------------------------------------------------ PIN

    /// <summary>
    /// Legt die PIN-Sitzung an (nach Passwort-Entsperrung). Danach kann bis Prozessende mit PIN entsperrt werden.
    /// Langsam (PBKDF2).
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

    // ------------------------------------------------------------------ Passwort

    /// <summary>Ändert das Master-Passwort. Erfordert entsperrten Tresor. Langsam.</summary>
    public void ChangePassword(string newPassword)
    {
        byte[] pkcs8;
        lock (_sync)
        {
            if (_privateKeyPkcs8 == null) throw new InvalidOperationException("Tresor ist gesperrt.");
            pkcs8 = (byte[])_privateKeyPkcs8.Clone();
        }
        try
        {
            WrapWithPassword(newPassword, pkcs8);
            lock (_sync) Save();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    private void WrapWithPassword(string password, byte[] pkcs8)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var kek = DerivePasswordKey(password, salt, Pbkdf2Iterations);
        try
        {
            var wrapped = AeadEncrypt(kek, pkcs8, Concat(VaultAad, _file.PublicKey));
            _file.Salt = salt;
            _file.Iterations = Pbkdf2Iterations;
            _file.WrappedPrivateKey = wrapped;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private byte[]? TryUnwrapWithPassword(string password)
    {
        var kek = DerivePasswordKey(password, _file.Salt, _file.Iterations);
        try
        {
            return AeadDecrypt(kek, _file.WrappedPrivateKey, Concat(VaultAad, _file.PublicKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

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

    private sealed class VaultFile
    {
        public int Version { get; set; }
        public int Iterations { get; set; }
        public byte[] Salt { get; set; } = [];
        public byte[] PublicKey { get; set; } = [];
        public byte[] WrappedPrivateKey { get; set; } = [];
        public byte[]? PinBlob { get; set; }
    }
}
