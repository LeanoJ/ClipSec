using System.IO;
using System.Reflection;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using ClipSec;
using ClipSec.Core;
using ClipSec.UI;

namespace ClipSec.Screenshots;

/// <summary>
/// Baut die echten ClipSec-Fenster mit Beispieldaten auf (unsichtbar außerhalb des Bildschirms)
/// und speichert sie in doppelter Auflösung nach website/assets/img/screenshots.
/// Es werden keine echten Daten verwendet: eigener Temp-Datenordner, erfundene Einträge.
/// </summary>
internal static class Program
{
    private const BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Instance;
    private const double Scale = 2.0;
    private static string _out = "";

    [STAThread]
    private static int Main()
    {
        var dataDir = Path.Combine(Path.GetTempPath(), "clipsec-screenshots-" + Guid.NewGuid().ToString("N"));
        Environment.SetEnvironmentVariable("CLIPSEC_DATA_DIR", dataDir); // vor dem ersten Zugriff auf AppPaths!

        var root = FindRepoRoot();
        _out = Path.Combine(root, "website", "assets", "img", "screenshots");
        Directory.CreateDirectory(_out);

        // WICHTIG: kein ClipSec.App erzeugen! WPF ruft dann App.OnStartup auf, sobald der Dispatcher läuft –
        // das wäre ein kompletter ClipSec-Start (Hotkey, Tray, Signal an eine laufende Instanz …).
        // Stattdessen eine neutrale Application mit den ClipSec-Designs.
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        app.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri("pack://application:,,,/ClipSec;component/UI/Styles.xaml"),
        });
        app.Resources["BoolToVis"] = new BooleanToVisibilityConverter();
        Theme.Apply(app.Resources);

        var rc = 0;
        Dispatcher.CurrentDispatcher.InvokeAsync(async () =>
        {
            try
            {
                await RunAsync(app);
                ExportIcons(root);
            }
            catch (Exception ex)
            {
                File.WriteAllText(Path.Combine(_out, "_error.txt"), ex.ToString());
                rc = 1;
            }
            finally
            {
                try { Directory.Delete(dataDir, true); } catch { }
                Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        });
        Dispatcher.Run();
        return rc;
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "ClipSec.sln"))) dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("ClipSec.sln nicht gefunden.");
    }

    // ------------------------------------------------------------------ Szenen

    private static async Task RunAsync(Application app)
    {
        var settings = new AppSettings
        {
            PinEnabled = true,
            ExcludedApps = ["KeePass.exe", "Banking.exe"],
            ClearSensitiveSeconds = 30,
            SensitiveRetentionMinutes = 120,
            IdleLockMinutes = 10,
            RetentionDays = 30,
        };
        var vault = CryptoVault.Create("beispiel-passwort");
        vault.SetPin("4711");
        var history = new HistoryStore(vault, settings);
        var lockMgr = new LockManager(vault, history, settings);
        var ctrl = new AppController(app);
        ctrl.AttachForTooling(settings, vault, history, lockMgr);

        Seed(vault, history);

        var win = new ClipWindow(ctrl);
        Call(win, "UpdateMode");
        Save(Render(win, rounded: true), "popup-locked.png");

        var (ok, error) = await lockMgr.UnlockWithPasswordAsync("beispiel-passwort");
        if (!ok) throw new InvalidOperationException(error);
        Call(win, "UpdateMode");
        Save(Render(win, rounded: true), "popup-list.png");

        // Vertraulich-Filter: maskiert und aufgedeckt
        var chips = (ListBox)win.FindName("FilterChips");
        chips.SelectedIndex = chips.Items.Count - 1;
        Save(Render(win, rounded: true), "popup-sensitive.png");
        var iban = history.Items.First(i => i.SensitiveLabel == "IBAN");
        iban.Revealed = true;
        Save(Render(win, rounded: true), "popup-sensitive-revealed.png");
        iban.Revealed = false;
        chips.SelectedIndex = 0;

        // Kontextmenü am formatierten Eintrag
        var formatted = history.Items.First(i => i.Payload.HasFormatting);
        Save(RenderWithMenu(win, formatted), "popup-menu.png");

        var code = history.Items.First(i => i.IsText && i.Payload.Text.StartsWith("function"));
        Call(win, "OpenPreview", code);
        Save(Render(win, rounded: true), "popup-preview.png");
        Call(win, "CloseOverlay");

        var meeting = history.Items.First(i => i.IsText && i.Payload.Text.StartsWith("Treffen"));
        Call(win, "OpenEditor", meeting);
        Save(Render(win, rounded: true), "popup-edit.png");
        Call(win, "CloseOverlay");

        var address = history.Items.First(i => i.IsText && i.Payload.Text.StartsWith("Musterstraße"));
        Call(win, "OpenSnippet", address);
        ((TextBox)win.FindName("SnippetName")).Text = "Adresse privat";
        ((TextBox)win.FindName("SnippetGroup")).Text = "Privat";
        Save(Render(win, rounded: true), "popup-snippet.png");
        Call(win, "CloseOverlay");

        // Gesperrt mit PIN (Passwort wurde in dieser "Sitzung" schon eingegeben)
        lockMgr.Lock();
        Call(win, "UpdateMode");
        Save(Render(win, rounded: true), "popup-pin.png");

        // Einstellungen
        var sw = new SettingsWindow(ctrl);
        var nav = (ListBox)sw.FindName("NavList");
        string[] names = ["settings-lock.png", "settings-sensitive.png", "settings-exclude.png", "settings-history.png", "settings-usage.png"];
        for (var i = 0; i < names.Length; i++)
        {
            nav.SelectedIndex = i;
            if (i == 2)
            {
                // Keine echten laufenden Programme zeigen
                ((ListBox)sw.FindName("RunningAppsChips")).ItemsSource =
                    new[] { "chrome.exe", "EXCEL.EXE", "Outlook.exe", "Teams.exe", "WINWORD.EXE" };
            }
            if (i == 4) ((FrameworkElement)sw.FindName("WinHistoryWarning")).Visibility = Visibility.Collapsed;
            Save(Render(sw), names[i]);
        }

        // Einrichtung
        var setup = new SetupWindow(new AppSettings());
        ((CheckBox)setup.FindName("PinCheck")).IsChecked = true;
        ((FrameworkElement)setup.FindName("WinHistoryWarning")).Visibility = Visibility.Collapsed;
        Save(Render(setup, height: 700), "setup.png");

        // Installer (Pfad ohne Benutzernamen)
        var install = new InstallWindow { SizeToContent = SizeToContent.Manual, Height = 480 };
        // Immer die Erstinstallation zeigen – unabhängig davon, ob ClipSec auf diesem Rechner installiert ist.
        ((TextBlock)install.FindName("HeaderText")).Text = "ClipSec installieren";
        ((TextBlock)install.FindName("VersionText")).Text = $"Version {Installer.Version}";
        ((Button)install.FindName("InstallButton")).Content = "Installieren";
        ((TextBlock)install.FindName("PathText")).Text = @"%LOCALAPPDATA%\Programs\ClipSec";
        ((FrameworkElement)install.FindName("RunningHint")).Visibility = Visibility.Collapsed;
        Save(Render(install), "install.png");
    }

    private static void Seed(CryptoVault vault, HistoryStore history)
    {
        void Add(ClipPayload p, int minutesAgo, bool pinned = false)
        {
            var e = new StoredEntry
            {
                Id = Guid.NewGuid(),
                CreatedUtc = DateTime.UtcNow.AddMinutes(-minutesAgo),
                Pinned = pinned,
                Sensitive = SensitiveDetector.Detect(p) != null,
            };
            e.Blob = vault.Seal(p.Serialize(), e.Aad());
            history.AddSealed(e, p);
        }

        Add(ClipPayload.FromText("Viele Grüße\nMax Mustermann").WithMeta("Signatur", "Mails"), 2880, pinned: true);
        Add(ClipPayload.FromText("Musterstraße 12\n12345 Musterstadt"), 1500);
        Add(new ClipPayload(ClipKind.Image, SampleImage()), 95);
        Add(ClipPayload.FromFiles([@"C:\Users\Max\Documents\Vertrag_2026.pdf", @"C:\Users\Max\Documents\Angebot.xlsx"]), 64);
        Add(ClipPayload.FromText("Tr0ub4dor&3x!"), 41);
        Add(ClipPayload.FromText("DE89 3704 0044 0532 0130 00"), 30);
        Add(new ClipPayload(ClipKind.Text, Encoding.UTF8.GetBytes("Angebot Q4 – Zusammenfassung für das Team"))
        {
            Html = "Version:0.9\r\nStartHTML:0\r\n<b>Angebot Q4</b> – Zusammenfassung für das Team",
        }, 12);
        Add(ClipPayload.FromText("function greet(name) {\n  return `Hallo ${name}!`;\n}\n\nconsole.log(greet(\"ClipSec\"));"), 4);
        Add(ClipPayload.FromText("Treffen morgen um 10:30 im Besprechungsraum 2 – bitte Unterlagen mitbringen."), 0);
    }

    private static byte[] SampleImage()
    {
        var dv = new DrawingVisual();
        using (var dc = dv.RenderOpen())
        {
            dc.DrawRectangle(new LinearGradientBrush(Color.FromRgb(37, 99, 235), Color.FromRgb(147, 51, 234), 30), null, new Rect(0, 0, 480, 220));
            dc.DrawEllipse(new SolidColorBrush(Color.FromArgb(220, 255, 214, 102)), null, new Point(360, 80), 46, 46);
            var hills = new StreamGeometry();
            using (var g = hills.Open())
            {
                g.BeginFigure(new Point(0, 220), true, true);
                g.LineTo(new Point(0, 160), true, false);
                g.QuadraticBezierTo(new Point(120, 90), new Point(240, 160), true, false);
                g.QuadraticBezierTo(new Point(360, 120), new Point(480, 170), true, false);
                g.LineTo(new Point(480, 220), true, false);
            }
            dc.DrawGeometry(new SolidColorBrush(Color.FromArgb(200, 15, 23, 42)), null, hills);
        }
        var bmp = new RenderTargetBitmap(480, 220, 96, 96, PixelFormats.Pbgra32);
        bmp.Render(dv);
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(bmp));
        using var ms = new MemoryStream();
        enc.Save(ms);
        return ms.ToArray();
    }

    // ------------------------------------------------------------------ Rendern

    private static readonly HashSet<Window> Shown = [];

    /// <summary>
    /// Zeigt das Fenster unsichtbar außerhalb des Bildschirms an (ohne Fokus) und liefert die Größe
    /// des Inhaltsbereichs – ohne Windows-Rahmen und Titelleiste.
    /// </summary>
    private static Size Layout(Window w, double? height = null)
    {
        if (Shown.Add(w))
        {
            if (w is ClipWindow)
                typeof(ClipWindow).GetField("_suppressHide", Private)!.SetValue(w, true); // verbirgt sich sonst bei Fokusverlust
            w.ShowActivated = false;
            w.WindowStartupLocation = WindowStartupLocation.Manual;
            w.Left = -20000; // nicht -32000: das ist Windows' Position für minimierte Fenster
            w.Top = -20000;
            if (height is { } h && w.SizeToContent == SizeToContent.Manual) w.Height = h + 39;
            TextOptions.SetTextFormattingMode(w, TextFormattingMode.Ideal); // für skalierte Darstellung im Web
            w.Show();
        }
        Pump();
        w.UpdateLayout();
        var content = (FrameworkElement)w.Content;
        if (content.ActualWidth <= 0)
            throw new InvalidOperationException($"{w.GetType().Name} wurde nicht angezeigt (IsVisible={w.IsVisible}).");
        return new Size(content.ActualWidth, content.ActualHeight);
    }

    private static void Pump()
    {
        for (var i = 0; i < 3; i++)
            Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
    }

    private static object? Call(object target, string method, params object[] args) =>
        target.GetType().GetMethod(method, Private)!.Invoke(target, args);

    /// <summary>
    /// Pinsel mit festem Ausschnitt in Layout-Koordinaten. Ohne Viewbox richtet sich ein VisualBrush nach den
    /// gezeichneten Inhalten – Innenabstände ohne Hintergrund (z. B. oberer Rand) würden abgeschnitten.
    /// </summary>
    private static VisualBrush BrushOf(Visual v, Size size) => new(v)
    {
        Stretch = Stretch.None,
        ViewboxUnits = BrushMappingMode.Absolute,
        Viewbox = new Rect(size),
        ViewportUnits = BrushMappingMode.Absolute,
        Viewport = new Rect(size),
    };

    private static BitmapSource Render(Window w, bool rounded = false, double? height = null)
    {
        var size = Layout(w, height);
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            if (rounded) dc.PushClip(new RectangleGeometry(new Rect(size), 8, 8));
            // Der Fensterhintergrund gehört zum Fenster, nicht zum Inhalt → mitzeichnen.
            dc.DrawRectangle(w.Background, null, new Rect(size));
            dc.DrawRectangle(BrushOf((Visual)w.Content, size), null, new Rect(size));
            if (rounded) dc.Pop();
        }
        return ToBitmap(visual, size);
    }

    /// <summary>Popup + Kontextmenü als ein Bild (das Menü wird nicht wirklich geöffnet).</summary>
    private static BitmapSource RenderWithMenu(ClipWindow win, ClipItem item)
    {
        Layout(win);
        var root = (FrameworkElement)win.Content;
        var list = (ListBox)win.FindName("ItemsList");
        list.ScrollIntoView(item);
        var winSize = Layout(win);
        var container = (FrameworkElement)list.ItemContainerGenerator.ContainerFromItem(item);
        var menu = (ContextMenu)win.Resources["ItemMenu"];
        menu.PlacementTarget = container;
        Call(win, "ItemMenu_Opened", menu, new RoutedEventArgs());
        winSize = Layout(win);

        TextElement.SetFontFamily(menu, (FontFamily)Application.Current.Resources["UiFont"]);
        TextOptions.SetTextFormattingMode(menu, TextFormattingMode.Ideal);
        menu.ApplyTemplate();
        menu.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
        menu.Arrange(new Rect(menu.DesiredSize));
        menu.UpdateLayout();

        var anchor = container.TransformToAncestor(root).Transform(new Point(container.ActualWidth - 40, 34));
        var menuPos = new Point(Math.Min(anchor.X, winSize.Width - menu.ActualWidth + 60), anchor.Y);
        var total = new Size(Math.Max(winSize.Width, menuPos.X + menu.ActualWidth + 12),
            Math.Max(winSize.Height, menuPos.Y + menu.ActualHeight + 12));

        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.PushClip(new RectangleGeometry(new Rect(winSize), 8, 8));
            dc.DrawRectangle(BrushOf(root, winSize), null, new Rect(winSize));
            dc.Pop();
            // weicher Schatten unter dem Menü
            for (var i = 6; i >= 1; i--)
            {
                var r = new Rect(menuPos.X - i + 2, menuPos.Y - i + 4, menu.ActualWidth + 2 * i - 4, menu.ActualHeight + 2 * i - 4);
                dc.DrawRoundedRectangle(new SolidColorBrush(Color.FromArgb(14, 0, 0, 0)), null, r, 8 + i, 8 + i);
            }
            var menuSize = new Size(menu.ActualWidth, menu.ActualHeight);
            var menuBrush = BrushOf(menu, menuSize);
            menuBrush.Viewport = new Rect(menuPos, menuSize);
            dc.DrawRectangle(menuBrush, null, new Rect(menuPos, menuSize));
        }
        return ToBitmap(visual, total);
    }
    private static BitmapSource ToBitmap(Visual visual, Size size)
    {
        var bmp = new RenderTargetBitmap((int)Math.Ceiling(size.Width * Scale), (int)Math.Ceiling(size.Height * Scale),
            96 * Scale, 96 * Scale, PixelFormats.Pbgra32);
        bmp.Render(visual);
        bmp.Freeze();
        return bmp;
    }

    private static void Save(BitmapSource bmp, string name)
    {
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(bmp));
        using var fs = File.Create(Path.Combine(_out, name));
        enc.Save(fs);
    }

    /// <summary>Icon als PNG/ICO für Webseite (Favicon, Logo, Unraid-Vorlage).</summary>
    private static void ExportIcons(string root)
    {
        var ico = Path.Combine(root, "ClipSec", "Assets", "clipsec.ico");
        var imgDir = Path.Combine(root, "website", "assets", "img");
        File.Copy(ico, Path.Combine(root, "website", "favicon.ico"), overwrite: true);
        var decoder = new IconBitmapDecoder(new Uri(ico), BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
        foreach (var frame in decoder.Frames.Where(f => f.PixelWidth is 32 or 64 or 256))
        {
            var enc = new PngBitmapEncoder();
            enc.Frames.Add(BitmapFrame.Create(frame));
            using var fs = File.Create(Path.Combine(imgDir, $"icon-{frame.PixelWidth}.png"));
            enc.Save(fs);
        }
    }
}
