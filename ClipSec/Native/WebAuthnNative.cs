using System.Runtime.InteropServices;

namespace ClipSec.Native;

/// <summary>
/// Windows-WebAuthn-API (webauthn.dll) – Zugriff auf FIDO2-Sicherheitsschlüssel ohne Adminrechte.
/// Strukturen nach webauthn.h; Felder späterer Versionen werden über dwVersion ein-/ausgeblendet.
/// </summary>
internal static class WebAuthnNative
{
    public const uint ATTACHMENT_CROSS_PLATFORM = 2;
    public const uint USER_VERIFICATION_REQUIRED = 1;
    public const uint ATTESTATION_NONE = 1;
    public const int COSE_ES256 = -7;
    /// <summary>Salts werden unverändert als hmac-secret übergeben (statt nach WebAuthn-PRF gehasht).</summary>
    public const uint HMAC_SECRET_VALUES_FLAG = 0x00100000;

    public const uint MAKE_CREDENTIAL_OPTIONS_VERSION_4 = 4;
    public const uint MAKE_CREDENTIAL_OPTIONS_VERSION_6 = 6;
    /// <summary>Ab dieser API-Version gibt es MakeCredential-Optionen v6 (bEnablePrf).</summary>
    public const uint MIN_API_VERSION_FOR_PRF_FLAG = 6;
    public const uint GET_ASSERTION_OPTIONS_VERSION_6 = 6;

    /// <summary>Ab dieser API-Version kennt GetAssertion die hmac-secret-Salts (Optionen v6).</summary>
    public const uint MIN_API_VERSION_FOR_HMAC = 4;

    [StructLayout(LayoutKind.Sequential)]
    public struct RP_ENTITY_INFORMATION
    {
        public uint dwVersion;
        public IntPtr pwszId;
        public IntPtr pwszName;
        public IntPtr pwszIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct USER_ENTITY_INFORMATION
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        public IntPtr pwszName;
        public IntPtr pwszIcon;
        public IntPtr pwszDisplayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_DATA
    {
        public uint dwVersion;
        public uint cbClientDataJSON;
        public IntPtr pbClientDataJSON;
        public IntPtr pwszHashAlgId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct COSE_CREDENTIAL_PARAMETER
    {
        public uint dwVersion;
        public IntPtr pwszCredentialType;
        public int lAlg;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct COSE_CREDENTIAL_PARAMETERS
    {
        public uint cCredentialParameters;
        public IntPtr pCredentialParameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CREDENTIAL
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        public IntPtr pwszCredentialType;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CREDENTIALS
    {
        public uint cCredentials;
        public IntPtr pCredentials;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXTENSION
    {
        public IntPtr pwszExtensionIdentifier;
        public uint cbExtension;
        public IntPtr pvExtension;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXTENSIONS
    {
        public uint cExtensions;
        public IntPtr pExtensions;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct HMAC_SECRET_SALT
    {
        public uint cbFirst;
        public IntPtr pbFirst;
        public uint cbSecond;
        public IntPtr pbSecond;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct HMAC_SECRET_SALT_VALUES
    {
        public IntPtr pGlobalHmacSalt;
        public uint cCredWithHmacSecretSaltList;
        public IntPtr pCredWithHmacSecretSaltList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MAKE_CREDENTIAL_OPTIONS
    {
        public uint dwVersion;
        public uint dwTimeoutMilliseconds;
        public CREDENTIALS CredentialList; // Ausschlussliste (bereits registrierte Schlüssel)
        public EXTENSIONS Extensions;
        public uint dwAuthenticatorAttachment;
        public int bRequireResidentKey;
        public uint dwUserVerificationRequirement;
        public uint dwAttestationConveyancePreference;
        public uint dwFlags;
        // v2
        public IntPtr pCancellationId;
        // v3
        public IntPtr pExcludeCredentialList;
        // v4
        public uint dwEnterpriseAttestation;
        public uint dwLargeBlobSupport;
        public int bPreferResidentKey;
        // v5
        public int bBrowserInPrivateMode;
        // v6 (API-Version 6+)
        public int bEnablePrf;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct GET_ASSERTION_OPTIONS
    {
        public uint dwVersion;
        public uint dwTimeoutMilliseconds;
        public CREDENTIALS CredentialList; // erlaubte Schlüssel
        public EXTENSIONS Extensions;
        public uint dwAuthenticatorAttachment;
        public uint dwUserVerificationRequirement;
        public uint dwFlags;
        // v2
        public IntPtr pwszU2fAppId;
        public IntPtr pbU2fAppId;
        // v3
        public IntPtr pCancellationId;
        // v4
        public IntPtr pAllowCredentialList;
        // v5
        public uint dwCredLargeBlobOperation;
        public uint cbCredLargeBlob;
        public IntPtr pbCredLargeBlob;
        // v6
        public IntPtr pHmacSecretSaltValues;
        public int bBrowserInPrivateMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CREDENTIAL_ATTESTATION
    {
        public uint dwVersion;
        public IntPtr pwszFormatType;
        public uint cbAuthenticatorData;
        public IntPtr pbAuthenticatorData;
        public uint cbAttestation;
        public IntPtr pbAttestation;
        public uint dwAttestationDecodeType;
        public IntPtr pvAttestationDecode;
        public uint cbAttestationObject;
        public IntPtr pbAttestationObject;
        public uint cbCredentialId;
        public IntPtr pbCredentialId;
        // v2
        public EXTENSIONS Extensions;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ASSERTION
    {
        public uint dwVersion;
        public uint cbAuthenticatorData;
        public IntPtr pbAuthenticatorData;
        public uint cbSignature;
        public IntPtr pbSignature;
        public CREDENTIAL Credential;
        public uint cbUserId;
        public IntPtr pbUserId;
        // v2
        public EXTENSIONS Extensions;
        public uint cbCredLargeBlob;
        public IntPtr pbCredLargeBlob;
        public uint dwCredLargeBlobStatus;
        // v3
        public IntPtr pHmacSecret;
    }

    [DllImport("webauthn.dll")]
    public static extern uint WebAuthNGetApiVersionNumber();

    [DllImport("webauthn.dll")]
    public static extern int WebAuthNAuthenticatorMakeCredential(
        IntPtr hWnd, IntPtr pRpInformation, IntPtr pUserInformation, IntPtr pPubKeyCredParams,
        IntPtr pWebAuthNClientData, IntPtr pWebAuthNMakeCredentialOptions, out IntPtr ppCredentialAttestation);

    [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
    public static extern int WebAuthNAuthenticatorGetAssertion(
        IntPtr hWnd, string pwszRpId, IntPtr pWebAuthNClientData, IntPtr pWebAuthNGetAssertionOptions,
        out IntPtr ppWebAuthNAssertion);

    [DllImport("webauthn.dll")]
    public static extern void WebAuthNFreeCredentialAttestation(IntPtr pCredentialAttestation);

    [DllImport("webauthn.dll")]
    public static extern void WebAuthNFreeAssertion(IntPtr pWebAuthNAssertion);

    [DllImport("webauthn.dll")]
    public static extern IntPtr WebAuthNGetErrorName(int hr);
}
