using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;
using ClipSec.Core;
using ClipSec.Native;

namespace ClipSec.UI;

public partial class ClipWindow : Window
{
    private enum Overlay { None, Preview, Edit, Snippet }

    /// <summary>Filter-Chip über der Liste.</summary>
    private sealed record FilterChip(string Label, string Kind, string? Group = null)
    {
        public string Key => Kind + ":" + Group;
    }

    private readonly AppController _c;
    private readonly ICollectionView _view;
    private readonly ContextMenu _menu;
    private bool _forcePassword;
    private bool _pinMode;
    private bool _busy;
    private bool _suppressHide;
    private bool _sensitiveConfirmed;
    private bool _refreshQueued;
    private Overlay _overlay;
    private ClipItem? _overlayItem;
    private ClipItem? _menuItem;
    private FilterChip _filter = new("Alle", "all");

    internal ClipWindow(AppController controller)
    {
        _c = controller;
        InitializeComponent();
        Handle = new WindowInteropHelper(this).EnsureHandle();
        WindowStyling.ApplyRoundedCorners(Handle);
        // Windows ersetzt beim ersten ShowWindow eines Prozesses den Modus durch den Startmodus des Aufrufers.
        // Wurde ClipSec versteckt gestartet (z. B. durch ein Skript), bliebe das erste Win+V sonst unsichtbar.
        // Dieser unsichtbare Aufruf "verbraucht" die Sonderregel.
        NativeMethods.ShowWindow(Handle, NativeMethods.SW_HIDE);

        _menu = (ContextMenu)Resources["ItemMenu"];
        _view = CollectionViewSource.GetDefaultView(_c.History.Items);
        _view.Filter = o => o is ClipItem item && PassesFilter(item);
        ItemsList.ItemsSource = _view;

        _c.Lock.StateChanged += OnLockStateChanged;
        _c.Lock.Tick += OnTick;
        _c.History.Items.CollectionChanged += (_, _) => QueueListRefresh();

        Deactivated += (_, _) => { if (!_suppressHide && !_menu.IsOpen) HidePopup(); };
        PreviewKeyDown += OnPreviewKeyDown;
        PreviewMouseDown += (_, _) => _c.Lock.Touch();
    }

    public IntPtr Handle { get; }

    // ------------------------------------------------------------------ Anzeigen / Verbergen

    public void ShowPopup(IntPtr target)
    {
        UpdateMode();
        foreach (var item in _c.History.Items) item.RefreshAge();

        var (anchor, work, scale) = PasteHelper.GetPopupAnchor(target);
        int w = (int)(Width * scale), h = (int)(Height * scale);
        int x = anchor.X;
        int y = anchor.Y + (int)(4 * scale);
        if (y + h > work.Bottom) y = anchor.Y - h - (int)(20 * scale);
        x = Math.Clamp(x, work.Left, Math.Max(work.Left, work.Right - w));
        y = Math.Clamp(y, work.Top, Math.Max(work.Top, work.Bottom - h));
        NativeMethods.SetWindowPos(Handle, IntPtr.Zero, x, y, 0, 0,
            NativeMethods.SWP_NOSIZE | NativeMethods.SWP_NOZORDER | NativeMethods.SWP_NOACTIVATE);

        Show();
        Activate();
        PasteHelper.ForceForeground(Handle);
        FocusInput();
    }

    public void HidePopup()
    {
        if (!IsVisible) return;
        _menu.IsOpen = false;
        Hide();
        CloseOverlay();
        SecretBox.Clear();
        SearchBox.Clear();
        LockError.Visibility = Visibility.Collapsed;
        _forcePassword = false;
        ResetSensitiveAccess();
        _filter = new FilterChip("Alle", "all");
        _c.OnPopupHidden();
    }

    private void FocusInput()
    {
        Dispatcher.BeginInvoke(() =>
        {
            if (!_c.Lock.IsUnlocked) SecretBox.Focus();
            else if (_overlay == Overlay.Edit) EditBox.Focus();
            else if (_overlay == Overlay.Snippet) SnippetName.Focus();
            else SearchBox.Focus();
        }, DispatcherPriority.Input);
    }

    /// <summary>Aufgedeckte Inhalte beim Schließen wieder verbergen, Passwortbestätigung verfällt.</summary>
    private void ResetSensitiveAccess()
    {
        _sensitiveConfirmed = false;
        foreach (var item in _c.History.Items.Where(i => i.Revealed)) item.Revealed = false;
    }

    // ------------------------------------------------------------------ Zustand

    private void OnLockStateChanged()
    {
        if (!_c.Lock.IsUnlocked)
        {
            _sensitiveConfirmed = false;
            CloseOverlay();
        }
        if (IsVisible) UpdateMode();
    }

    private void UpdateMode()
    {
        var unlocked = _c.Lock.IsUnlocked;
        ListPanel.Visibility = unlocked ? Visibility.Visible : Visibility.Collapsed;
        LockPanel.Visibility = unlocked ? Visibility.Collapsed : Visibility.Visible;
        ClearButton.Visibility = unlocked ? Visibility.Visible : Visibility.Collapsed;
        LockButton.Visibility = unlocked ? Visibility.Visible : Visibility.Collapsed;

        if (unlocked)
        {
            RefreshList();
            SelectFirst();
        }
        else
        {
            _pinMode = _c.Lock.CanUsePin && !_forcePassword;
            LockHint.Text = _pinMode ? "Kurz-PIN eingeben" : "Master-Passwort eingeben";
            UsePasswordLink.Visibility = _pinMode ? Visibility.Visible : Visibility.Collapsed;
            SecretBox.Clear();
            SetBusy(false);
        }
        UpdateStatus();
        if (IsVisible) FocusInput();
    }

    private void QueueListRefresh()
    {
        if (_refreshQueued) return;
        _refreshQueued = true;
        Dispatcher.BeginInvoke(() =>
        {
            _refreshQueued = false;
            UpdateFilterChips();
            UpdateQuickIndexes();
            UpdateEmptyState();
        }, DispatcherPriority.Background);
    }

    private void RefreshList()
    {
        UpdateFilterChips();
        _view.Refresh();
        UpdateQuickIndexes();
        UpdateEmptyState();
    }

    private void UpdateEmptyState()
    {
        var any = !_view.IsEmpty;
        EmptyState.Visibility = any ? Visibility.Collapsed : Visibility.Visible;
        ItemsList.Visibility = any ? Visibility.Visible : Visibility.Collapsed;
        var filtering = !string.IsNullOrWhiteSpace(SearchBox.Text) || _filter.Kind != "all";
        EmptyText.Text = filtering ? "Keine Treffer" : "Noch nichts kopiert";
        EmptySub.Text = filtering ? "" : "Alles, was du kopierst, landet hier – verschlüsselt.";
    }

    /// <summary>Strg+1…9 gilt für die ersten neun sichtbaren Einträge.</summary>
    private void UpdateQuickIndexes()
    {
        var visible = _view.Cast<ClipItem>().Take(9).ToList();
        foreach (var item in _c.History.Items)
        {
            var i = visible.IndexOf(item);
            item.QuickIndex = i >= 0 ? i + 1 : 0;
        }
    }

    private void UpdateFilterChips()
    {
        var items = _c.History.Items;
        var chips = new List<FilterChip> { new("Alle", "all") };
        if (items.Any(i => i.Pinned)) chips.Add(new("Angeheftet", "pinned"));
        chips.AddRange(_c.History.Groups.Select(g => new FilterChip(g, "group", g)));
        if (items.Any(i => i.Sensitive)) chips.Add(new("Vertraulich", "sensitive"));

        var current = chips.FirstOrDefault(c => c.Key == _filter.Key);
        if (current == null)
        {
            current = chips[0];
            _filter = current;
            _view.Refresh();
        }
        var same = FilterChips.ItemsSource is List<FilterChip> old && old.Select(c => c.Key).SequenceEqual(chips.Select(c => c.Key));
        if (!same) FilterChips.ItemsSource = chips;
        FilterChips.SelectedItem = ((List<FilterChip>)FilterChips.ItemsSource!).First(c => c.Key == current.Key);
        FilterChips.Visibility = chips.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
    }

    private bool PassesFilter(ClipItem item)
    {
        var ok = _filter.Kind switch
        {
            "pinned" => item.Pinned,
            "group" => string.Equals(item.Group, _filter.Group, StringComparison.CurrentCultureIgnoreCase),
            "sensitive" => item.Sensitive,
            _ => true,
        };
        var q = SearchBox.Text.Trim();
        return ok && (q.Length == 0 || item.Matches(q));
    }

    private void OnTick()
    {
        if (!IsVisible) return;
        UpdateStatus();
        if (!_c.Lock.IsUnlocked && !_pinMode && !_busy)
        {
            var blocked = _c.Lock.PasswordBlockedFor;
            if (blocked > TimeSpan.Zero) ShowError($"Zu viele Fehlversuche. Bitte {Math.Ceiling(blocked.TotalSeconds)} s warten.");
            UnlockButton.IsEnabled = blocked == TimeSpan.Zero;
        }
    }

    private void UpdateStatus()
    {
        var hotkey = AppController.HotkeyText(_c.Settings.Hotkey);
        if (!_c.Lock.IsUnlocked)
        {
            StatusText.Text = _c.Lock.CanUsePin
                ? $"{_c.History.Count} Einträge verschlüsselt · PIN gültig bis Neustart/Abmeldung"
                : $"{_c.History.Count} Einträge verschlüsselt · {hotkey}";
        }
        else if (_c.Lock.RemainingUnlocked is { } left)
        {
            StatusText.Text = $"Sperrt nach {left:m\\:ss} ohne Nutzung · Rechtsklick für Aktionen";
        }
        else
        {
            StatusText.Text = "Sperrt beim Schließen · Rechtsklick für Aktionen";
        }
    }

    // ------------------------------------------------------------------ Entsperren

    private async void TryUnlock()
    {
        if (_busy) return;
        var secret = SecretBox.Password;
        if (secret.Length == 0) return;

        SetBusy(true);
        var (ok, error) = _pinMode
            ? await _c.Lock.UnlockWithPinAsync(secret)
            : await _c.Lock.UnlockWithPasswordAsync(secret);
        SecretBox.Clear();
        SetBusy(false);

        if (ok)
        {
            _forcePassword = false;
            LockError.Visibility = Visibility.Collapsed;
            return; // StateChanged schaltet auf die Liste um
        }

        if (_pinMode && !_c.Lock.CanUsePin)
        {
            _forcePassword = true;
            UpdateMode();
        }
        ShowError(error ?? "Entsperren fehlgeschlagen.");
        SecretBox.Focus();
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        SecretBox.IsEnabled = !busy;
        UnlockButton.IsEnabled = !busy;
        UnlockButton.Content = busy ? "Prüfe …" : "Entsperren";
    }

    private void ShowError(string text)
    {
        LockError.Text = text;
        LockError.Visibility = Visibility.Visible;
    }

    private void SecretBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            TryUnlock();
            e.Handled = true;
        }
    }

    private void UnlockButton_Click(object sender, RoutedEventArgs e) => TryUnlock();

    private void UsePasswordLink_Click(object sender, RoutedEventArgs e)
    {
        _forcePassword = true;
        LockError.Visibility = Visibility.Collapsed;
        UpdateMode();
    }

    // ------------------------------------------------------------------ Vertrauliche Einträge

    /// <summary>
    /// Zugriff auf vertraulichen Inhalt (Aufdecken, Einfügen, Vorschau, Bearbeiten). Wenn eingestellt,
    /// ist dafür erneut das Master-Passwort nötig – gültig, bis das Popup geschlossen wird.
    /// </summary>
    private bool EnsureSensitiveAccess(ClipItem item)
    {
        if (!item.Sensitive || !_c.Settings.SensitiveRequiresPassword || _sensitiveConfirmed) return true;
        _suppressHide = true;
        try
        {
            _sensitiveConfirmed = _c.ConfirmMasterPassword(this, "Vertraulicher Eintrag",
                $"Dieser Eintrag ist als vertraulich markiert ({item.SensitiveLabel}). Bitte Master-Passwort bestätigen.");
        }
        finally
        {
            _suppressHide = false;
        }
        Activate();
        return _sensitiveConfirmed;
    }

    private void ToggleReveal(ClipItem item)
    {
        if (item.Revealed) item.Revealed = false;
        else if (EnsureSensitiveAccess(item)) item.Revealed = true;
    }

    // ------------------------------------------------------------------ Aktionen

    private ClipItem? Selected => ItemsList.SelectedItem as ClipItem;

    private void SelectFirst()
    {
        if (_view.IsEmpty) return;
        ItemsList.SelectedIndex = 0;
        ItemsList.ScrollIntoView(ItemsList.SelectedItem);
    }

    private void Select(ClipItem item)
    {
        ItemsList.SelectedItem = item;
        ItemsList.ScrollIntoView(item);
    }

    private void MoveSelection(int delta)
    {
        var count = ItemsList.Items.Count;
        if (count == 0) return;
        var index = Math.Clamp(ItemsList.SelectedIndex + delta, 0, count - 1);
        ItemsList.SelectedIndex = index;
        ItemsList.ScrollIntoView(ItemsList.SelectedItem);
    }

    private async void Paste(ClipItem? item, bool plainText = false)
    {
        if (item == null || !EnsureSensitiveAccess(item)) return;
        await _c.PasteAsync(item, plainText);
    }

    private void Delete(ClipItem? item)
    {
        if (item == null) return;
        var index = ItemsList.SelectedIndex;
        _c.History.Delete(item);
        if (ItemsList.Items.Count > 0) ItemsList.SelectedIndex = Math.Clamp(index, 0, ItemsList.Items.Count - 1);
    }

    private void TogglePin(ClipItem item)
    {
        _c.History.TogglePin(item);
        RefreshList();
        Select(item);
    }

    private void ToggleSensitive(ClipItem item)
    {
        if (item.Sensitive && !EnsureSensitiveAccess(item)) return;
        _c.History.SetSensitive(item, !item.Sensitive);
        RefreshList();
        Select(item);
    }

    // ------------------------------------------------------------------ Einblendungen

    private void ShowOverlay(Overlay overlay, ClipItem item)
    {
        CloseOverlay();
        _overlay = overlay;
        _overlayItem = item;
        var panel = overlay switch
        {
            Overlay.Preview => PreviewPanel,
            Overlay.Edit => EditPanel,
            _ => SnippetPanel,
        };
        panel.Visibility = Visibility.Visible;
        FocusInput();
    }

    private void CloseOverlay()
    {
        if (_overlay == Overlay.None) return;
        PreviewPanel.Visibility = EditPanel.Visibility = SnippetPanel.Visibility = Visibility.Collapsed;
        PreviewText.Clear();
        PreviewImage.Source = null;
        EditBox.Clear();
        var item = _overlayItem;
        _overlay = Overlay.None;
        _overlayItem = null;
        if (IsVisible && _c.Lock.IsUnlocked)
        {
            if (item != null && _c.History.Items.Contains(item)) Select(item);
            FocusInput();
        }
    }

    private void OpenPreview(ClipItem? item)
    {
        if (item == null || !EnsureSensitiveAccess(item)) return;
        PreviewTitle.Text = item.HasTitle ? item.Title : $"{item.KindLabel} · {item.AgeText}";
        if (item.IsImage)
        {
            PreviewImage.Source = item.LoadImage();
            PreviewImageHost.Visibility = Visibility.Visible;
            PreviewText.Visibility = Visibility.Collapsed;
        }
        else
        {
            PreviewText.Text = item.FullText;
            PreviewImageHost.Visibility = Visibility.Collapsed;
            PreviewText.Visibility = Visibility.Visible;
        }
        ShowOverlay(Overlay.Preview, item);
    }

    private void OpenEditor(ClipItem? item)
    {
        if (item is not { IsText: true } || !EnsureSensitiveAccess(item)) return;
        ShowOverlay(Overlay.Edit, item);
        EditBox.Text = item.Payload.Text;
        EditBox.CaretIndex = EditBox.Text.Length;
    }

    private void OpenSnippet(ClipItem? item)
    {
        if (item == null) return;
        ShowOverlay(Overlay.Snippet, item);
        SnippetName.Text = item.Title ?? "";
        SnippetGroup.Text = item.Group ?? "";
        SnippetGroupChips.ItemsSource = _c.History.Groups;
        SnippetGroupChips.Visibility = _c.History.Groups.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        SnippetName.SelectAll();
    }

    private void SaveEdit(bool paste)
    {
        if (_overlayItem is not { } item) return;
        var text = EditBox.Text;
        if (text.Length > 0 && text != item.Payload.Text)
            _c.History.UpdatePayload(item, item.Payload.WithText(text));
        CloseOverlay();
        if (paste) Paste(item);
    }

    private void SaveSnippet()
    {
        if (_overlayItem is not { } item) return;
        _c.History.SetSnippet(item, SnippetName.Text, SnippetGroup.Text);
        CloseOverlay();
        RefreshList();
        Select(item);
    }

    private void CloseOverlay_Click(object sender, RoutedEventArgs e) => CloseOverlay();

    private void PreviewPaste_Click(object sender, RoutedEventArgs e) => Paste(_overlayItem);

    private void EditSave_Click(object sender, RoutedEventArgs e) => SaveEdit(paste: false);

    private void EditSavePaste_Click(object sender, RoutedEventArgs e) => SaveEdit(paste: true);

    private void EditBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.Control)
        {
            SaveEdit(paste: true);
            e.Handled = true;
        }
    }

    private void SnippetSave_Click(object sender, RoutedEventArgs e) => SaveSnippet();

    private void SnippetBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            SaveSnippet();
            e.Handled = true;
        }
    }

    private void SnippetGroupChips_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SnippetGroupChips.SelectedItem is string group) SnippetGroup.Text = group;
    }

    // ------------------------------------------------------------------ Liste & Tastatur

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _view.Refresh();
        UpdateQuickIndexes();
        UpdateEmptyState();
        SelectFirst();
    }

    private void FilterChips_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FilterChips.SelectedItem is not FilterChip chip || chip.Key == _filter.Key) return;
        _filter = chip;
        _view.Refresh();
        UpdateQuickIndexes();
        UpdateEmptyState();
        SelectFirst();
        FocusInput();
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        _c.Lock.Touch();

        if (e.Key == Key.Escape)
        {
            if (_overlay != Overlay.None) CloseOverlay();
            else HidePopup();
            e.Handled = true;
            return;
        }
        if (!_c.Lock.IsUnlocked || ListPanel.Visibility != Visibility.Visible) return;

        if (_overlay == Overlay.Preview)
        {
            if (e.Key is Key.Space or Key.Back) { CloseOverlay(); e.Handled = true; }
            else if (e.Key == Key.Enter) { Paste(_overlayItem, Keyboard.Modifiers == ModifierKeys.Shift); e.Handled = true; }
            return;
        }
        if (_overlay != Overlay.None) return; // Bearbeiten/Textbaustein: Tasten gehören den Eingabefeldern

        var key = e.Key == Key.System ? e.SystemKey : e.Key;
        var mods = Keyboard.Modifiers;
        var inSearch = SearchBox.IsKeyboardFocusWithin;
        var searchEmpty = SearchBox.Text.Length == 0;

        if (mods == ModifierKeys.Control && QuickNumber(key) is int n)
        {
            Paste(_view.Cast<ClipItem>().ElementAtOrDefault(n - 1));
            e.Handled = true;
            return;
        }

        switch (key)
        {
            case Key.Down: MoveSelection(1); e.Handled = true; break;
            case Key.Up: MoveSelection(-1); e.Handled = true; break;
            case Key.PageDown: MoveSelection(5); e.Handled = true; break;
            case Key.PageUp: MoveSelection(-5); e.Handled = true; break;
            case Key.Enter:
                Paste(Selected, plainText: mods == ModifierKeys.Shift);
                e.Handled = true;
                break;
            case Key.Space when mods == ModifierKeys.None && (!inSearch || searchEmpty):
                OpenPreview(Selected);
                e.Handled = true;
                break;
            case Key.F2:
                OpenEditor(Selected);
                e.Handled = true;
                break;
            case Key.Delete when !inSearch || searchEmpty:
                Delete(Selected);
                e.Handled = true;
                break;
        }
    }

    private static int? QuickNumber(Key key) => key switch
    {
        >= Key.D1 and <= Key.D9 => key - Key.D0,
        >= Key.NumPad1 and <= Key.NumPad9 => key - Key.NumPad0,
        _ => null,
    };

    private void ItemsList_KeyDown(object sender, KeyEventArgs e)
    {
        // Tippen in der Liste → Suche
        if (e.Key is >= Key.A and <= Key.Z && Keyboard.Modifiers is ModifierKeys.None or ModifierKeys.Shift)
            SearchBox.Focus();
    }

    private void Item_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (sender is ListBoxItem { DataContext: ClipItem item }) Paste(item);
    }

    private void RevealButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: ClipItem item }) ToggleReveal(item);
        e.Handled = true;
    }

    private void PinButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: ClipItem item }) TogglePin(item);
        e.Handled = true;
    }

    private void MoreButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: ClipItem } button) return;
        _menu.PlacementTarget = button;
        _menu.Placement = PlacementMode.Bottom;
        _menu.IsOpen = true;
        e.Handled = true;
    }

    // ------------------------------------------------------------------ Kontextmenü

    private MenuItem MenuEntry(string name) => _menu.Items.OfType<MenuItem>().First(m => m.Name == name);

    private void ItemMenu_Opened(object sender, RoutedEventArgs e)
    {
        _menuItem = (_menu.PlacementTarget as FrameworkElement)?.DataContext as ClipItem;
        if (_menuItem is not { } item)
        {
            _menu.IsOpen = false;
            return;
        }
        Select(item);
        MenuEntry("MenuPastePlain").Visibility =
            (item.IsText && item.Payload.HasFormatting) || item.IsFiles ? Visibility.Visible : Visibility.Collapsed;
        MenuEntry("MenuEdit").Visibility = item.IsText ? Visibility.Visible : Visibility.Collapsed;
        MenuEntry("MenuSnippet").Header = item.HasTitle ? "Textbaustein bearbeiten …" : "Als Textbaustein …";
        var pin = MenuEntry("MenuPin");
        pin.Header = item.Pinned ? "Lösen" : "Anheften";
        pin.Tag = item.Pinned ? "" : "";
        var sensitive = MenuEntry("MenuSensitive");
        sensitive.Header = item.Sensitive ? "Vertraulich-Markierung entfernen" : "Als vertraulich markieren";
        sensitive.Tag = item.Sensitive ? "" : "";
    }

    private void MenuPaste_Click(object sender, RoutedEventArgs e) => Paste(_menuItem);
    private void MenuPastePlain_Click(object sender, RoutedEventArgs e) => Paste(_menuItem, plainText: true);
    private void MenuPreview_Click(object sender, RoutedEventArgs e) => OpenPreview(_menuItem);
    private void MenuEdit_Click(object sender, RoutedEventArgs e) => OpenEditor(_menuItem);
    private void MenuSnippet_Click(object sender, RoutedEventArgs e) => OpenSnippet(_menuItem);
    private void MenuDelete_Click(object sender, RoutedEventArgs e) => Delete(_menuItem);

    private void MenuPin_Click(object sender, RoutedEventArgs e)
    {
        if (_menuItem != null) TogglePin(_menuItem);
    }

    private void MenuSensitive_Click(object sender, RoutedEventArgs e)
    {
        if (_menuItem != null) ToggleSensitive(_menuItem);
    }

    // ------------------------------------------------------------------ Kopfzeile

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        _suppressHide = true;
        var answer = MessageBox.Show(this, "Alle nicht angehefteten Einträge löschen?", "ClipSec",
            MessageBoxButton.YesNo, MessageBoxImage.Question);
        _suppressHide = false;
        if (answer == MessageBoxResult.Yes) _c.History.ClearUnpinned();
        Activate();
        FocusInput();
    }

    private void LockButton_Click(object sender, RoutedEventArgs e) => _c.Lock.Lock();

    private void SettingsButton_Click(object sender, RoutedEventArgs e) => _c.OpenSettings();

    private void CloseButton_Click(object sender, RoutedEventArgs e) => HidePopup();

    protected override void OnClosing(CancelEventArgs e)
    {
        // Alt+F4 soll nur verbergen, nicht das Fenster zerstören.
        e.Cancel = true;
        HidePopup();
    }
}
