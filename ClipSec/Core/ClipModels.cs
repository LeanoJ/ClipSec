using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace ClipSec.Core;

public enum ClipKind : byte
{
    Text = 1,
    Image = 2,
    Files = 3,
}

/// <summary>
/// Klartext-Inhalt eines Eintrags inkl. aller Metadaten, die geheim bleiben sollen
/// (Formatierung, Name und Gruppe eines Textbausteins). Wird komplett versiegelt.
/// </summary>
public sealed class ClipPayload
{
    // Format v2: [Marker][Version][Kind] ([Tag][Länge int32][Bytes])*
    // Format v1 (Altbestand): [Kind][Daten]
    private const byte V2Marker = 0xC5;
    private const byte V2Version = 2;
    private const byte TagData = 1, TagHtml = 2, TagRtf = 3, TagTitle = 4, TagGroup = 5;

    public ClipPayload(ClipKind kind, byte[] data)
    {
        Kind = kind;
        Data = data;
    }

    public ClipKind Kind { get; }

    /// <summary>Text (UTF-8), PNG-Bild oder Dateipfade (durch \n getrennt).</summary>
    public byte[] Data { get; }

    /// <summary>"HTML Format" der Zwischenablage (inkl. CF_HTML-Kopf), falls vorhanden.</summary>
    public string? Html { get; init; }

    public string? Rtf { get; init; }

    /// <summary>Name als Textbaustein.</summary>
    public string? Title { get; init; }

    public string? Group { get; init; }

    public bool HasFormatting => !string.IsNullOrEmpty(Html) || !string.IsNullOrEmpty(Rtf);

    public static ClipPayload FromText(string text) => new(ClipKind.Text, Encoding.UTF8.GetBytes(text));

    public static ClipPayload FromFiles(IEnumerable<string> paths) =>
        new(ClipKind.Files, Encoding.UTF8.GetBytes(string.Join('\n', paths)));

    public string Text => Encoding.UTF8.GetString(Data);

    public string[] Files => Encoding.UTF8.GetString(Data).Split('\n', StringSplitOptions.RemoveEmptyEntries);

    public long TotalSize => Data.Length + (Html?.Length ?? 0) * 2L + (Rtf?.Length ?? 0) * 2L;

    public ClipPayload WithMeta(string? title, string? group) => new(Kind, Data)
    {
        Html = Html,
        Rtf = Rtf,
        Title = string.IsNullOrWhiteSpace(title) ? null : title.Trim(),
        Group = string.IsNullOrWhiteSpace(group) ? null : group.Trim(),
    };

    /// <summary>Bearbeiteter Text: Formatierung passt nicht mehr und entfällt.</summary>
    public ClipPayload WithText(string text) => new(ClipKind.Text, Encoding.UTF8.GetBytes(text))
    {
        Title = Title,
        Group = Group,
    };

    public ClipPayload WithoutFormatting() => new(Kind, Data) { Title = Title, Group = Group };

    /// <summary>Für Duplikaterkennung zählt nur der eigentliche Inhalt.</summary>
    public byte[] Hash()
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha.AppendData([(byte)Kind]);
        sha.AppendData(Data);
        return sha.GetHashAndReset();
    }

    public byte[] Serialize()
    {
        using var ms = new MemoryStream();
        ms.WriteByte(V2Marker);
        ms.WriteByte(V2Version);
        ms.WriteByte((byte)Kind);
        WriteSection(ms, TagData, Data);
        WriteSection(ms, TagHtml, Html);
        WriteSection(ms, TagRtf, Rtf);
        WriteSection(ms, TagTitle, Title);
        WriteSection(ms, TagGroup, Group);
        return ms.ToArray();
    }

    private static void WriteSection(Stream s, byte tag, string? value)
    {
        if (!string.IsNullOrEmpty(value)) WriteSection(s, tag, Encoding.UTF8.GetBytes(value));
    }

    private static void WriteSection(Stream s, byte tag, byte[] value)
    {
        s.WriteByte(tag);
        s.Write(BitConverter.GetBytes(value.Length));
        s.Write(value);
    }

    public static ClipPayload? Deserialize(byte[] raw)
    {
        if (raw.Length < 1) return null;
        if (raw[0] != V2Marker)
        {
            // v1
            if (!Enum.IsDefined(typeof(ClipKind), raw[0])) return null;
            return new ClipPayload((ClipKind)raw[0], raw[1..]);
        }

        if (raw.Length < 3 || raw[1] != V2Version || !Enum.IsDefined(typeof(ClipKind), raw[2])) return null;
        var kind = (ClipKind)raw[2];
        byte[]? data = null;
        string? html = null, rtf = null, title = null, group = null;
        var pos = 3;
        while (pos + 5 <= raw.Length)
        {
            var tag = raw[pos];
            var len = BitConverter.ToInt32(raw, pos + 1);
            pos += 5;
            if (len < 0 || len > raw.Length - pos) return null; // ohne Überlauf bei riesigen Längen
            var bytes = raw.AsSpan(pos, len);
            pos += len;
            switch (tag)
            {
                case TagData: data = bytes.ToArray(); break;
                case TagHtml: html = Encoding.UTF8.GetString(bytes); break;
                case TagRtf: rtf = Encoding.UTF8.GetString(bytes); break;
                case TagTitle: title = Encoding.UTF8.GetString(bytes); break;
                case TagGroup: group = Encoding.UTF8.GetString(bytes); break;
                // Unbekannte Tags (neuere Version) überspringen.
            }
        }
        if (data == null) return null;
        return new ClipPayload(kind, data) { Html = html, Rtf = rtf, Title = title, Group = group };
    }
}

/// <summary>Verschlüsselter Eintrag, wie er gespeichert wird.</summary>
public sealed class StoredEntry
{
    public Guid Id { get; set; }
    public DateTime CreatedUtc { get; set; }
    public bool Pinned { get; set; }

    /// <summary>
    /// Vertraulich (erkannt oder manuell markiert). Bewusst unverschlüsselt, damit die
    /// automatische Löschung auch im gesperrten Zustand funktioniert. Verrät keinen Inhalt.
    /// </summary>
    public bool Sensitive { get; set; }

    public byte[] Blob { get; set; } = [];

    public byte[] Aad() => Id.ToByteArray();
}

/// <summary>Entschlüsselter Eintrag für die Anzeige. Existiert nur im entsperrten Zustand.</summary>
public sealed class ClipItem : INotifyPropertyChanged
{
    private const string Mask = "••••••••••••";

    private bool _pinned;
    private bool _sensitive;
    private bool _revealed;
    private int _quickIndex;
    private DateTime _createdUtc;
    private ImageSource? _thumbnail;
    private string? _detectedLabel;

    public ClipItem(Guid id, DateTime createdUtc, bool pinned, bool sensitive, ClipPayload payload)
    {
        Id = id;
        _createdUtc = createdUtc;
        _pinned = pinned;
        _sensitive = sensitive;
        Payload = payload;
        Hash = payload.Hash();
        _detectedLabel = SensitiveDetector.Detect(payload);
    }

    public Guid Id { get; }
    public ClipPayload Payload { get; private set; }
    public byte[] Hash { get; private set; }

    public void SetPayload(ClipPayload payload)
    {
        Payload = payload;
        Hash = payload.Hash();
        _thumbnail = null;
        _detectedLabel = SensitiveDetector.Detect(payload);
        OnChanged(string.Empty); // alle abgeleiteten Eigenschaften neu lesen
    }

    public ClipKind Kind => Payload.Kind;
    public bool IsText => Kind == ClipKind.Text;
    public bool IsImage => Kind == ClipKind.Image;
    public bool IsFiles => Kind == ClipKind.Files;

    public bool Pinned
    {
        get => _pinned;
        set { _pinned = value; OnChanged(); }
    }

    public DateTime CreatedUtc
    {
        get => _createdUtc;
        set { _createdUtc = value; OnChanged(); OnChanged(nameof(AgeText)); }
    }

    // ------------------------------------------------------------------ Vertraulich

    public bool Sensitive
    {
        get => _sensitive;
        set { _sensitive = value; _revealed = false; OnChanged(string.Empty); }
    }

    /// <summary>Aufgedeckt (nur bis zum Schließen des Popups).</summary>
    public bool Revealed
    {
        get => _revealed;
        set { _revealed = value; OnChanged(string.Empty); }
    }

    public bool IsMasked => Sensitive && !Revealed;

    public string? SensitiveLabel => Sensitive ? (_detectedLabel ?? "Vertraulich") : null;

    public string? DetectedLabel => _detectedLabel;

    // ------------------------------------------------------------------ Anzeige

    public string? Title => Payload.Title;
    public string? Group => Payload.Group;
    public bool HasTitle => !string.IsNullOrEmpty(Title);

    /// <summary>1–9 für Strg+Zahl, sonst 0.</summary>
    public int QuickIndex
    {
        get => _quickIndex;
        set
        {
            if (_quickIndex == value) return;
            _quickIndex = value;
            OnChanged();
            OnChanged(nameof(QuickHint));
        }
    }

    public string QuickHint => QuickIndex is >= 1 and <= 9 ? $"Strg+{QuickIndex}" : "";

    public bool ShowText => !IsImage || IsMasked;
    public bool ShowImage => IsImage && !IsMasked;

    public string AgeText
    {
        get
        {
            var age = DateTime.UtcNow - CreatedUtc;
            if (age.TotalSeconds < 60) return "gerade eben";
            if (age.TotalMinutes < 60) return $"vor {(int)age.TotalMinutes} Min.";
            if (age.TotalHours < 24) return $"vor {(int)age.TotalHours} Std.";
            return CreatedUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm");
        }
    }

    public string KindLabel
    {
        get
        {
            var label = Kind switch
            {
                ClipKind.Text => "Text",
                ClipKind.Image => "Bild",
                ClipKind.Files => Payload.Files.Length == 1 ? "Datei" : $"{Payload.Files.Length} Dateien",
                _ => "",
            };
            if (Payload.HasFormatting) label += " · formatiert";
            if (!string.IsNullOrEmpty(Group)) label = Group + " · " + label;
            return label;
        }
    }

    public string PreviewText
    {
        get
        {
            if (IsMasked) return IsImage ? "Bild verborgen" : Mask;
            var raw = Kind switch
            {
                ClipKind.Text => Payload.Text,
                ClipKind.Files => string.Join(Environment.NewLine, Payload.Files.Take(6)),
                _ => "",
            };
            raw = raw.Replace("\r\n", "\n").Trim();
            if (raw.Length > 400) raw = raw[..400] + " …";
            var lines = raw.Split('\n');
            return lines.Length > 6 ? string.Join('\n', lines.Take(6)) + "\n…" : raw;
        }
    }

    /// <summary>Vollständiger Text für die große Vorschau.</summary>
    public string FullText => Kind switch
    {
        ClipKind.Text => Payload.Text,
        ClipKind.Files => string.Join(Environment.NewLine, Payload.Files),
        _ => "",
    };

    public ImageSource? Thumbnail => IsImage ? (_thumbnail ??= LoadImage(320)) : null;

    public ImageSource? LoadImage(int decodeWidth = 0)
    {
        if (Kind != ClipKind.Image) return null;
        try
        {
            var bmp = new BitmapImage();
            bmp.BeginInit();
            bmp.CacheOption = BitmapCacheOption.OnLoad;
            if (decodeWidth > 0) bmp.DecodePixelWidth = decodeWidth;
            bmp.StreamSource = new MemoryStream(Payload.Data);
            bmp.EndInit();
            bmp.Freeze();
            return bmp;
        }
        catch
        {
            return null;
        }
    }

    public void RefreshAge() => OnChanged(nameof(AgeText));

    /// <summary>Für die Suche. Verborgene vertrauliche Inhalte werden nur über Name/Art gefunden.</summary>
    public bool Matches(string query)
    {
        bool Has(string? s) => s != null && s.Contains(query, StringComparison.CurrentCultureIgnoreCase);
        if (Has(Title) || Has(Group) || Has(SensitiveLabel)) return true;
        if (IsMasked || Kind == ClipKind.Image) return false;
        return Has(Encoding.UTF8.GetString(Payload.Data));
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
