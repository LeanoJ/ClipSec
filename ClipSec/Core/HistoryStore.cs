using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows.Threading;

namespace ClipSec.Core;

/// <summary>
/// Verwaltet den Verlauf. Alle Methoden laufen auf dem UI-Thread (außer <see cref="Decrypt"/>).
/// Verschlüsselte Einträge (<see cref="StoredEntry"/>) sind immer vorhanden;
/// entschlüsselte Einträge (<see cref="Items"/>) nur, solange entsperrt ist.
/// </summary>
public sealed class HistoryStore
{
    private readonly CryptoVault _vault;
    private readonly AppSettings _settings;
    private readonly List<StoredEntry> _entries = []; // neueste zuerst
    private readonly DispatcherTimer _saveTimer;
    private byte[]? _lastCapturedHash;

    public HistoryStore(CryptoVault vault, AppSettings settings)
    {
        _vault = vault;
        _settings = settings;
        _saveTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
        _saveTimer.Tick += (_, _) =>
        {
            _saveTimer.Stop();
            SaveNow();
        };
    }

    /// <summary>Entschlüsselte Einträge (nur entsperrt). Angeheftete oben, sonst neueste zuerst.</summary>
    public ObservableCollection<ClipItem> Items { get; } = [];

    public bool IsDecrypted { get; private set; }

    public int Count => _entries.Count;

    /// <summary>Alle vergebenen Gruppen (nur entsperrt bekannt).</summary>
    public IReadOnlyList<string> Groups =>
        Items.Select(i => i.Group).OfType<string>().Distinct(StringComparer.CurrentCultureIgnoreCase)
            .Order(StringComparer.CurrentCultureIgnoreCase).ToList();

    // ------------------------------------------------------------------ Laden / Speichern

    public void Load()
    {
        _entries.Clear();
        if (!_settings.PersistHistory)
        {
            DeleteFile();
            return;
        }
        try
        {
            if (!File.Exists(AppPaths.HistoryFile)) return;
            var list = JsonSerializer.Deserialize<List<StoredEntry>>(File.ReadAllText(AppPaths.HistoryFile));
            if (list != null) _entries.AddRange(list.OrderByDescending(e => e.CreatedUtc));
        }
        catch
        {
            // Beschädigte Datei: lieber leer starten als abstürzen. Alte Datei zur Analyse sichern.
            try { File.Move(AppPaths.HistoryFile, AppPaths.HistoryFile + ".corrupt", true); } catch { }
        }
    }

    private void ScheduleSave()
    {
        if (!_settings.PersistHistory) return;
        _saveTimer.Stop();
        _saveTimer.Start();
    }

    public void SaveNow()
    {
        if (!_settings.PersistHistory) return;
        AppPaths.WriteAllTextAtomic(AppPaths.HistoryFile, JsonSerializer.Serialize(_entries));
    }

    /// <summary>Nach geänderten Einstellungen (Speichern an/aus, Höchstzahl, Aufbewahrung).</summary>
    public void ApplySettings()
    {
        Evict();
        Purge();
        if (_settings.PersistHistory) SaveNow();
        else DeleteFile();
    }

    private static void DeleteFile()
    {
        try { if (File.Exists(AppPaths.HistoryFile)) File.Delete(AppPaths.HistoryFile); } catch { }
    }

    // ------------------------------------------------------------------ Aufnehmen

    /// <summary>True, wenn der Inhalt dem zuletzt aufgenommenen entspricht (Duplikat direkt hintereinander).</summary>
    public bool IsSameAsLast(byte[] hash) => _lastCapturedHash != null && _lastCapturedHash.AsSpan().SequenceEqual(hash);

    public void MarkLastCaptured(byte[] hash) => _lastCapturedHash = hash;

    /// <summary>Fügt einen bereits versiegelten Eintrag hinzu (Versiegeln läuft im Hintergrund).</summary>
    public void AddSealed(StoredEntry entry, ClipPayload payload)
    {
        if (IsDecrypted)
        {
            // Gleicher Inhalt schon vorhanden → vorhandenen Eintrag (mit Name/Gruppe/Anheftung) nach oben holen.
            var hash = payload.Hash();
            var dup = Items.FirstOrDefault(i => i.Hash.AsSpan().SequenceEqual(hash));
            if (dup != null)
            {
                Touch(dup);
                return;
            }
            InsertItemSorted(new ClipItem(entry.Id, entry.CreatedUtc, false, entry.Sensitive, payload));
        }
        _entries.Insert(0, entry);
        Evict();
        ScheduleSave();
    }

    private void Evict()
    {
        var unpinned = _entries.Where(e => !e.Pinned).ToList();
        foreach (var old in unpinned.Skip(_settings.MaxItems))
            RemoveInternal(old.Id);
    }

    /// <summary>
    /// Automatisches Aufräumen (Aufbewahrungsdauer, vertrauliche Einträge). Funktioniert auch gesperrt,
    /// weil nur unverschlüsselte Metadaten (Zeit, Anheftung, Vertraulich-Flag) nötig sind.
    /// </summary>
    public int Purge()
    {
        var now = DateTime.UtcNow;
        var removed = 0;
        foreach (var e in _entries.Where(e => !e.Pinned).ToList())
        {
            var age = now - e.CreatedUtc;
            var expired =
                (_settings.RetentionDays > 0 && age > TimeSpan.FromDays(_settings.RetentionDays)) ||
                (e.Sensitive && _settings.SensitiveRetentionMinutes > 0 &&
                 age > TimeSpan.FromMinutes(_settings.SensitiveRetentionMinutes));
            if (!expired) continue;
            RemoveInternal(e.Id);
            removed++;
        }
        if (removed > 0) ScheduleSave();
        return removed;
    }

    // ------------------------------------------------------------------ Entsperren / Sperren

    /// <summary>Kopie der verschlüsselten Einträge (UI-Thread), zur Entschlüsselung im Hintergrund.</summary>
    public List<StoredEntry> Snapshot() => _entries.ToList();

    /// <summary>Entschlüsselt einen Snapshot (Hintergrund-Thread geeignet).</summary>
    public List<ClipItem> Decrypt(List<StoredEntry> snapshot)
    {
        var result = new List<ClipItem>(snapshot.Count);
        foreach (var e in snapshot)
        {
            byte[]? raw;
            try { raw = _vault.Open(e.Blob, e.Aad()); }
            catch (InvalidOperationException) { throw new OperationCanceledException(); } // zwischendurch gesperrt
            var payload = raw == null ? null : ClipPayload.Deserialize(raw);
            if (payload != null) result.Add(new ClipItem(e.Id, e.CreatedUtc, e.Pinned, e.Sensitive, payload));
        }
        return result;
    }

    /// <summary>Übernimmt die entschlüsselten Einträge (UI-Thread) und führt Duplikate zusammen.</summary>
    public void SetDecrypted(List<StoredEntry> snapshot, List<ClipItem> items)
    {
        Items.Clear();
        var decryptedIds = items.Select(i => i.Id).ToHashSet();
        var snapshotIds = snapshot.Select(e => e.Id).ToHashSet();

        // Im Snapshot, aber nicht entschlüsselbar → beschädigt, verwerfen.
        var changed = _entries.RemoveAll(e => snapshotIds.Contains(e.Id) && !decryptedIds.Contains(e.Id)) > 0;

        // Während der Entschlüsselung neu hinzugekommene Einträge nachziehen.
        var late = _entries.Where(e => !snapshotIds.Contains(e.Id)).ToList();
        var known = _entries.Select(e => e.Id).ToHashSet();
        var all = items.Concat(Decrypt(late)).Where(i => known.Contains(i.Id)).ToList();

        // Duplikate (z. B. im gesperrten Zustand erneut kopiert): den Eintrag mit Name/Anheftung behalten,
        // Zeitstempel vom neuesten übernehmen.
        var keep = new List<ClipItem>();
        foreach (var group in all.GroupBy(i => Convert.ToHexString(i.Hash)))
        {
            var keeper = group.OrderByDescending(i => i.Pinned || i.HasTitle).ThenByDescending(i => i.CreatedUtc).First();
            var newest = group.Max(i => i.CreatedUtc);
            if (keeper.CreatedUtc != newest)
            {
                keeper.CreatedUtc = newest;
                var entry = _entries.First(e => e.Id == keeper.Id);
                entry.CreatedUtc = newest;
            }
            foreach (var other in group.Where(i => i.Id != keeper.Id))
            {
                _entries.RemoveAll(e => e.Id == other.Id);
                changed = true;
            }
            keep.Add(keeper);
        }
        _entries.Sort((a, b) => b.CreatedUtc.CompareTo(a.CreatedUtc));
        if (changed) ScheduleSave();

        foreach (var item in keep.OrderByDescending(i => i.Pinned).ThenByDescending(i => i.CreatedUtc))
            Items.Add(item);
        IsDecrypted = true;
    }

    public void ClearDecrypted()
    {
        Items.Clear();
        IsDecrypted = false;
    }

    // ------------------------------------------------------------------ Bearbeiten (nur entsperrt)

    public void Delete(ClipItem item)
    {
        RemoveInternal(item.Id);
        ScheduleSave();
    }

    public void TogglePin(ClipItem item) => SetPinned(item, !item.Pinned);

    public void SetPinned(ClipItem item, bool pinned)
    {
        item.Pinned = pinned;
        var entry = _entries.FirstOrDefault(e => e.Id == item.Id);
        if (entry != null) entry.Pinned = pinned;
        Items.Remove(item);
        InsertItemSorted(item);
        Evict();
        ScheduleSave();
    }

    public void SetSensitive(ClipItem item, bool sensitive)
    {
        item.Sensitive = sensitive;
        var entry = _entries.FirstOrDefault(e => e.Id == item.Id);
        if (entry != null) entry.Sensitive = sensitive;
        ScheduleSave();
    }

    /// <summary>Ersetzt den Inhalt (Bearbeiten, Name/Gruppe) – wird neu versiegelt.</summary>
    public void UpdatePayload(ClipItem item, ClipPayload payload)
    {
        var entry = _entries.FirstOrDefault(e => e.Id == item.Id);
        if (entry == null) return;
        var raw = payload.Serialize();
        try { entry.Blob = _vault.Seal(raw, entry.Aad()); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(raw); }
        item.SetPayload(payload);
        ScheduleSave();
    }

    /// <summary>Als Textbaustein speichern: Name/Gruppe setzen und anheften.</summary>
    public void SetSnippet(ClipItem item, string? title, string? group)
    {
        UpdatePayload(item, item.Payload.WithMeta(title, group));
        if (!item.Pinned) SetPinned(item, true);
    }

    /// <summary>Beim Einfügen nach oben verschieben (wie bei Windows).</summary>
    public void Touch(ClipItem item)
    {
        var entry = _entries.FirstOrDefault(e => e.Id == item.Id);
        if (entry == null) return;
        entry.CreatedUtc = item.CreatedUtc = DateTime.UtcNow;
        _entries.Remove(entry);
        _entries.Insert(0, entry);
        Items.Remove(item);
        InsertItemSorted(item);
        _lastCapturedHash = item.Hash;
        ScheduleSave();
    }

    public void ClearUnpinned()
    {
        foreach (var e in _entries.Where(e => !e.Pinned).ToList()) RemoveInternal(e.Id);
        ScheduleSave();
    }

    /// <summary>Löscht alles, auch im gesperrten Zustand möglich (vernichtet nur, verrät nichts).</summary>
    public void ClearAll()
    {
        _entries.Clear();
        Items.Clear();
        _lastCapturedHash = null;
        if (_settings.PersistHistory) SaveNow();
    }

    private void RemoveInternal(Guid id)
    {
        _entries.RemoveAll(e => e.Id == id);
        var item = Items.FirstOrDefault(i => i.Id == id);
        if (item != null) Items.Remove(item);
    }

    private void InsertItemSorted(ClipItem item)
    {
        var index = 0;
        while (index < Items.Count && Compare(Items[index], item) < 0) index++;
        Items.Insert(index, item);
    }

    private static int Compare(ClipItem a, ClipItem b)
    {
        if (a.Pinned != b.Pinned) return a.Pinned ? -1 : 1;
        return b.CreatedUtc.CompareTo(a.CreatedUtc);
    }
}
