using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ClipSec.Native;
using static ClipSec.Native.WebAuthnNative;

namespace ClipSec.Core;

/// <summary>Fehler beim Sicherheitsschlüssel – Nachricht ist für die Anzeige gedacht.</summary>
public sealed class SecurityKeyException(string message, bool cancelled = false) : Exception(message)
{
    public bool Cancelled { get; } = cancelled;
}

/// <summary>Ergebnis einer hmac-secret-Abfrage.</summary>
public sealed record KeySecret(byte[] CredentialId, byte[] Secret, bool RawSalt);

/// <summary>
/// Zugriff auf FIDO2-Sicherheitsschlüssel. Alle Methoden blockieren, bis der Benutzer den
/// Windows-Dialog abgeschlossen hat → nicht auf dem UI-Thread aufrufen.
/// </summary>
public interface ISecurityKeyProvider
{
    bool IsSupported(out string? reason);

    /// <summary>Registriert einen neuen Schlüssel (mit hmac-secret) und liefert die Credential-ID.</summary>
    byte[] Register(IntPtr hwnd, IReadOnlyList<byte[]> exclude);

    /// <summary>
    /// Liefert das 32-Byte-hmac-secret für <paramref name="salt"/> vom Schlüssel, den der Benutzer berührt.
    /// <paramref name="rawSalt"/> = null: erst als WebAuthn-PRF, notfalls als rohes Salt versuchen (nur bei der Registrierung).
    /// </summary>
    KeySecret GetSecret(IntPtr hwnd, IReadOnlyList<byte[]> allow, byte[] salt, bool? rawSalt);
}

/// <summary>Echte Umsetzung über die Windows-WebAuthn-API (FIDO2 hmac-secret, z. B. YubiKey 5).</summary>
public sealed class WebAuthnSecurityKeyProvider : ISecurityKeyProvider
{
    private const string RpId = "clipsec.local";
    private const string CredentialType = "public-key";
    private const uint TimeoutMs = 60_000;
    private const int NTE_USER_CANCELLED = unchecked((int)0x80090036);

    public bool IsSupported(out string? reason)
    {
        try
        {
            var version = WebAuthNGetApiVersionNumber();
            if (version < MIN_API_VERSION_FOR_HMAC)
            {
                reason = $"Diese Windows-Version ist zu alt (WebAuthn-API {version}, benötigt {MIN_API_VERSION_FOR_HMAC}+). Bitte Windows aktualisieren.";
                return false;
            }
            reason = null;
            return true;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            reason = "Windows stellt keine Schnittstelle für Sicherheitsschlüssel bereit (webauthn.dll fehlt).";
            return false;
        }
    }

    public byte[] Register(IntPtr hwnd, IReadOnlyList<byte[]> exclude)
    {
        using var u = new Unmanaged();
        var rp = new RP_ENTITY_INFORMATION { dwVersion = 1, pwszId = u.Str(RpId), pwszName = u.Str("ClipSec") };
        var userId = RandomNumberGenerator.GetBytes(16);
        var user = new USER_ENTITY_INFORMATION
        {
            dwVersion = 1,
            cbId = (uint)userId.Length,
            pbId = u.Bytes(userId),
            pwszName = u.Str("ClipSec"),
            pwszDisplayName = u.Str("ClipSec-Tresor"),
        };
        var param = new COSE_CREDENTIAL_PARAMETER { dwVersion = 1, pwszCredentialType = u.Str(CredentialType), lAlg = COSE_ES256 };
        var parameters = new COSE_CREDENTIAL_PARAMETERS { cCredentialParameters = 1, pCredentialParameters = u.Struct(param) };

        // hmac-secret aktivieren: pvExtension zeigt auf BOOL TRUE
        var hmacExtension = new EXTENSION
        {
            pwszExtensionIdentifier = u.Str("hmac-secret"),
            cbExtension = sizeof(int),
            pvExtension = u.Bytes(BitConverter.GetBytes(1)),
        };
        var prfFlag = WebAuthNGetApiVersionNumber() >= MIN_API_VERSION_FOR_PRF_FLAG;
        var options = new MAKE_CREDENTIAL_OPTIONS
        {
            // Neuere Windows-Versionen: zusätzlich PRF ausdrücklich aktivieren (bildet auf hmac-secret ab).
            dwVersion = prfFlag ? MAKE_CREDENTIAL_OPTIONS_VERSION_6 : MAKE_CREDENTIAL_OPTIONS_VERSION_4,
            bEnablePrf = prfFlag ? 1 : 0,
            dwTimeoutMilliseconds = TimeoutMs,
            CredentialList = Credentials(u, exclude),
            Extensions = new EXTENSIONS { cExtensions = 1, pExtensions = u.Struct(hmacExtension) },
            dwAuthenticatorAttachment = ATTACHMENT_CROSS_PLATFORM,
            bRequireResidentKey = 0, // nicht auffindbar → belegt keinen Speicherplatz auf dem YubiKey
            dwUserVerificationRequirement = USER_VERIFICATION_REQUIRED,
            dwAttestationConveyancePreference = ATTESTATION_NONE,
        };

        var hr = WebAuthNAuthenticatorMakeCredential(hwnd, u.Struct(rp), u.Struct(user), u.Struct(parameters),
            u.Struct(ClientData(u, "webauthn.create")), u.Struct(options), out var pAttestation);
        if (hr != 0) throw ToException(hr, registering: true);

        try
        {
            var att = Marshal.PtrToStructure<CREDENTIAL_ATTESTATION>(pAttestation);
            var credentialId = Copy(att.pbCredentialId, att.cbCredentialId);
            if (credentialId.Length == 0) throw new SecurityKeyException("Der Schlüssel hat keine Kennung geliefert.");
            if (att.dwVersion >= 2 && !HmacSecretEnabled(att.Extensions))
                throw new SecurityKeyException("Dieser Schlüssel unterstützt „hmac-secret“ nicht (nötig: FIDO2, z. B. YubiKey 5).");
            return credentialId;
        }
        finally
        {
            WebAuthNFreeCredentialAttestation(pAttestation);
        }
    }

    public KeySecret GetSecret(IntPtr hwnd, IReadOnlyList<byte[]> allow, byte[] salt, bool? rawSalt)
    {
        if (salt.Length != 32) throw new ArgumentException("Salt muss 32 Byte lang sein.", nameof(salt));
        if (rawSalt is { } raw) return GetSecretOnce(hwnd, allow, salt, raw)
            ?? throw new SecurityKeyException("Der Schlüssel hat kein hmac-secret geliefert.");

        // Registrierung: erst PRF-Variante, falls Windows dabei nichts liefert, rohes Salt (zweite Berührung).
        return GetSecretOnce(hwnd, allow, salt, raw: false)
            ?? GetSecretOnce(hwnd, allow, salt, raw: true)
            ?? throw new SecurityKeyException("Der Schlüssel hat kein hmac-secret geliefert (nötig: FIDO2, z. B. YubiKey 5).");
    }

    private static KeySecret? GetSecretOnce(IntPtr hwnd, IReadOnlyList<byte[]> allow, byte[] salt, bool raw)
    {
        using var u = new Unmanaged();
        var saltStruct = new HMAC_SECRET_SALT { cbFirst = (uint)salt.Length, pbFirst = u.Bytes(salt) };
        var values = new HMAC_SECRET_SALT_VALUES { pGlobalHmacSalt = u.Struct(saltStruct) };
        var options = new GET_ASSERTION_OPTIONS
        {
            dwVersion = GET_ASSERTION_OPTIONS_VERSION_6,
            dwTimeoutMilliseconds = TimeoutMs,
            CredentialList = Credentials(u, allow),
            dwAuthenticatorAttachment = ATTACHMENT_CROSS_PLATFORM,
            dwUserVerificationRequirement = USER_VERIFICATION_REQUIRED,
            dwFlags = raw ? HMAC_SECRET_VALUES_FLAG : 0,
            pHmacSecretSaltValues = u.Struct(values),
        };

        var hr = WebAuthNAuthenticatorGetAssertion(hwnd, RpId, u.Struct(ClientData(u, "webauthn.get")), u.Struct(options),
            out var pAssertion);
        if (hr != 0) throw ToException(hr, registering: false);

        try
        {
            var assertion = Marshal.PtrToStructure<ASSERTION>(pAssertion);
            var credentialId = Copy(assertion.Credential.pbId, assertion.Credential.cbId);
            if (assertion.dwVersion < 3 || assertion.pHmacSecret == IntPtr.Zero) return null;
            var hmac = Marshal.PtrToStructure<HMAC_SECRET_SALT>(assertion.pHmacSecret);
            var secret = Copy(hmac.pbFirst, hmac.cbFirst);
            return secret.Length == 32 ? new KeySecret(credentialId, secret, raw) : null;
        }
        finally
        {
            WebAuthNFreeAssertion(pAssertion);
        }
    }

    // ------------------------------------------------------------------ Hilfen

    private static CLIENT_DATA ClientData(Unmanaged u, string type)
    {
        // Der Inhalt wird nur gehasht und signiert; ClipSec prüft keine Signaturen, braucht nur hmac-secret.
        var challenge = Base64Url(RandomNumberGenerator.GetBytes(32));
        var json = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"{type}\",\"challenge\":\"{challenge}\",\"origin\":\"https://{RpId}\",\"crossOrigin\":false}}");
        return new CLIENT_DATA
        {
            dwVersion = 1,
            cbClientDataJSON = (uint)json.Length,
            pbClientDataJSON = u.Bytes(json),
            pwszHashAlgId = u.Str("SHA-256"),
        };
    }

    private static CREDENTIALS Credentials(Unmanaged u, IReadOnlyList<byte[]> ids)
    {
        if (ids.Count == 0) return default;
        var size = Marshal.SizeOf<CREDENTIAL>();
        var array = u.Alloc(size * ids.Count);
        for (var i = 0; i < ids.Count; i++)
        {
            var c = new CREDENTIAL
            {
                dwVersion = 1,
                cbId = (uint)ids[i].Length,
                pbId = u.Bytes(ids[i]),
                pwszCredentialType = u.Str(CredentialType),
            };
            Marshal.StructureToPtr(c, array + i * size, false);
        }
        return new CREDENTIALS { cCredentials = (uint)ids.Count, pCredentials = array };
    }

    private static bool HmacSecretEnabled(EXTENSIONS extensions)
    {
        var size = Marshal.SizeOf<EXTENSION>();
        for (var i = 0; i < extensions.cExtensions; i++)
        {
            var ext = Marshal.PtrToStructure<EXTENSION>(extensions.pExtensions + i * size);
            if (Marshal.PtrToStringUni(ext.pwszExtensionIdentifier) == "hmac-secret" &&
                ext.cbExtension >= sizeof(int) && ext.pvExtension != IntPtr.Zero)
                return Marshal.ReadInt32(ext.pvExtension) != 0;
        }
        return false;
    }

    private static SecurityKeyException ToException(int hr, bool registering)
    {
        if (hr == NTE_USER_CANCELLED) return new SecurityKeyException("Abgebrochen.", cancelled: true);
        string? name = null;
        try { name = Marshal.PtrToStringUni(WebAuthNGetErrorName(hr)); } catch { }
        return name switch
        {
            "NotAllowedError" => new SecurityKeyException("Abgebrochen oder Zeit abgelaufen.", cancelled: true),
            "InvalidStateError" when registering => new SecurityKeyException("Dieser Schlüssel ist bereits registriert."),
            "InvalidStateError" => new SecurityKeyException("Dieser Schlüssel ist für ClipSec nicht registriert."),
            "NotSupportedError" => new SecurityKeyException("Der Schlüssel unterstützt die benötigte Funktion nicht (FIDO2 mit hmac-secret)."),
            "ConstraintError" => new SecurityKeyException("Der Schlüssel erfüllt die Anforderungen nicht (FIDO2-PIN nötig)."),
            _ => new SecurityKeyException($"Sicherheitsschlüssel-Fehler: {name ?? "unbekannt"} (0x{hr:X8})."),
        };
    }

    private static byte[] Copy(IntPtr p, uint length)
    {
        if (p == IntPtr.Zero || length == 0) return [];
        var bytes = new byte[length];
        Marshal.Copy(p, bytes, 0, (int)length);
        return bytes;
    }

    private static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Sammelt unverwaltete Speicherblöcke und gibt sie gemeinsam frei (Salts werden vorher genullt).</summary>
    private sealed class Unmanaged : IDisposable
    {
        private readonly List<(IntPtr ptr, int size)> _blocks = [];

        public IntPtr Alloc(int size)
        {
            var p = Marshal.AllocHGlobal(Math.Max(size, 1));
            _blocks.Add((p, size));
            return p;
        }

        public IntPtr Bytes(byte[] data)
        {
            var p = Alloc(data.Length);
            Marshal.Copy(data, 0, p, data.Length);
            return p;
        }

        public IntPtr Str(string s)
        {
            var p = Marshal.StringToHGlobalUni(s);
            _blocks.Add((p, 0));
            return p;
        }

        public IntPtr Struct<T>(T value) where T : struct
        {
            var p = Alloc(Marshal.SizeOf<T>());
            Marshal.StructureToPtr(value, p, false);
            return p;
        }

        public void Dispose()
        {
            foreach (var (ptr, size) in _blocks)
            {
                for (var i = 0; i < size; i++) Marshal.WriteByte(ptr, i, 0);
                Marshal.FreeHGlobal(ptr);
            }
            _blocks.Clear();
        }
    }
}
