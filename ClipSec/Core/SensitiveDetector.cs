using System.Numerics;
using System.Text.RegularExpressions;

namespace ClipSec.Core;

/// <summary>
/// Erkennt typische vertrauliche Inhalte. Liefert eine Bezeichnung (z. B. "IBAN") oder null.
/// Prüfsummen (IBAN, Luhn) halten Fehlalarme gering; im Zweifel lieber maskieren –
/// Aufdecken ist nur einen Klick entfernt.
/// </summary>
public static partial class SensitiveDetector
{
    private const int MaxScanLength = 100_000;

    public static string? Detect(ClipPayload payload) =>
        payload.Kind == ClipKind.Text ? Detect(payload.Text) : null;

    public static string? Detect(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > MaxScanLength) return null;

        if (PrivateKeyRx().IsMatch(text)) return "Privater Schlüssel";
        if (ApiKeyRx().IsMatch(text)) return "API-Schlüssel";
        if (JwtRx().IsMatch(text)) return "Token";
        if (CredentialRx().IsMatch(text)) return "Zugangsdaten";
        if (ContainsIban(text)) return "IBAN";
        if (ContainsCreditCard(text)) return "Kreditkarte";
        if (LooksLikePassword(text.Trim())) return "Passwort";
        return null;
    }

    // ------------------------------------------------------------------ Muster

    [GeneratedRegex(@"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")]
    private static partial Regex PrivateKeyRx();

    [GeneratedRegex(
        @"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}" +      // OpenAI / Anthropic
        @"|(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}" +    // Stripe
        @"|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}" +
        @"|xox[abprs]-[A-Za-z0-9\-]{10,}" +                  // Slack
        @"|AKIA[0-9A-Z]{16}" +                               // AWS
        @"|AIza[0-9A-Za-z_\-]{35}" +                         // Google
        @"|glpat-[A-Za-z0-9_\-]{20,}" +                      // GitLab
        @"|npm_[A-Za-z0-9]{36})")]
    private static partial Regex ApiKeyRx();

    [GeneratedRegex(@"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")]
    private static partial Regex JwtRx();

    [GeneratedRegex(@"(?i)\b(?:password|passwort|passwd|pwd|kennwort|secret|api[_\-]?key|access[_\-]?token|client[_\-]?secret)\s*[:=]\s*[""']?[^\s""';]{4,}")]
    private static partial Regex CredentialRx();

    [GeneratedRegex(@"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,32}")]
    private static partial Regex IbanCandidateRx();

    [GeneratedRegex(@"(?<![\d])(?:\d[ \-]?){12,18}\d(?![\d])")]
    private static partial Regex CardCandidateRx();

    [GeneratedRegex(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    private static partial Regex GuidRx();

    [GeneratedRegex(@"^[\w\-.]+\.[A-Za-z][A-Za-z0-9]{0,4}$")]
    private static partial Regex FileNameRx();

    // ------------------------------------------------------------------ IBAN

    private static bool ContainsIban(string text)
    {
        foreach (Match m in IbanCandidateRx().Matches(text))
        {
            var compact = m.Value.Replace(" ", "");
            // Kandidat kann in nachfolgende Großbuchstaben hineinlaufen → kürzere Präfixe prüfen.
            for (var len = Math.Min(34, compact.Length); len >= 15; len--)
                if (IsValidIban(compact[..len])) return true;
        }
        return false;
    }

    public static bool IsValidIban(string iban)
    {
        if (iban.Length is < 15 or > 34) return false;
        var rearranged = iban[4..] + iban[..4];
        var digits = new System.Text.StringBuilder(rearranged.Length * 2);
        foreach (var c in rearranged)
        {
            if (char.IsAsciiDigit(c)) digits.Append(c);
            else if (char.IsAsciiLetterUpper(c)) digits.Append(c - 'A' + 10);
            else return false;
        }
        return BigInteger.Parse(digits.ToString()) % 97 == 1;
    }

    // ------------------------------------------------------------------ Kreditkarte

    private static bool ContainsCreditCard(string text)
    {
        foreach (Match m in CardCandidateRx().Matches(text))
        {
            var digits = new string(m.Value.Where(char.IsAsciiDigit).ToArray());
            if (IsPlausibleCardNumber(digits)) return true;
        }
        return false;
    }

    public static bool IsPlausibleCardNumber(string digits)
    {
        var len = digits.Length;
        if (len is < 13 or > 19 || !Luhn(digits)) return false;
        int P(int n) => int.Parse(digits[..n]);
        return
            (digits[0] == '4' && len is 13 or 16 or 19) ||                                  // Visa
            (((P(2) is >= 51 and <= 55) || (P(4) is >= 2221 and <= 2720)) && len == 16) || // Mastercard
            (P(2) is 34 or 37 && len == 15) ||                                              // Amex
            ((P(4) == 6011 || P(2) == 65 || (P(3) is >= 644 and <= 649)) && len >= 16) ||   // Discover
            (P(2) == 35 && len >= 16) ||                                                    // JCB
            (P(2) is 36 or 38 or 30 && len is >= 14 and <= 16);                             // Diners
    }

    private static bool Luhn(string digits)
    {
        var sum = 0;
        var dbl = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var d = digits[i] - '0';
            if (dbl)
            {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    // ------------------------------------------------------------------ Passwort

    /// <summary>Ein einzelnes "Wort" mit gemischten Zeichenklassen, das nicht wie URL, Pfad, Datei oder GUID aussieht.</summary>
    public static bool LooksLikePassword(string s)
    {
        if (s.Length is < 8 or > 64 || s.Any(char.IsWhiteSpace)) return false;
        if (s.Contains("://") || s.StartsWith("www.", StringComparison.OrdinalIgnoreCase)) return false;
        if (s.Contains('@') && s.LastIndexOf('.') > s.IndexOf('@')) return false; // E-Mail
        if (s.Contains('\\') || s.StartsWith('/') || (s.Length > 2 && s[1] == ':')) return false; // Pfad
        if (GuidRx().IsMatch(s)) return false;
        if (s.All(c => char.IsAsciiDigit(c) || c is '.' or ',' or '-' or '+' or '/' or ':')) return false; // Zahl/Datum/Telefon

        bool lower = s.Any(char.IsLower), upper = s.Any(char.IsUpper), digit = s.Any(char.IsAsciiDigit);
        bool special = s.Any(c => !char.IsLetterOrDigit(c) && c is not '.' and not '-' and not '_');
        bool mildSpecial = s.Any(c => c is '.' or '-' or '_');
        var classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (special || mildSpecial ? 1 : 0);

        if (!(lower || upper)) return false;
        if (classes < 3) return false;
        if (!digit && !special) return false; // z. B. "System.Text.Json", "Mein-Ordner_Name"
        if (!special && FileNameRx().IsMatch(s)) return false; // z. B. "bericht_2026.pdf"
        if (special && (s.Contains("()") || s.Contains("=>") || s.EndsWith(';'))) return false; // Code-Schnipsel
        return true;
    }
}
