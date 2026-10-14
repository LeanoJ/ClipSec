using System.Drawing;
using System.Windows;
using ClipSec.Core;
using Forms = System.Windows.Forms;

namespace ClipSec.UI;

internal sealed class TrayIcon : IDisposable
{
    private readonly AppController _controller;
    private readonly Forms.NotifyIcon _icon;
    private readonly Forms.ToolStripMenuItem _lockItem;
    private string _lastText = "";

    public TrayIcon(AppController controller)
    {
        _controller = controller;

        var stream = Application.GetResourceStream(new Uri("pack://application:,,,/ClipSec;component/Assets/clipsec.ico"))!.Stream;
        _icon = new Forms.NotifyIcon
        {
            Icon = new Icon(stream, Forms.SystemInformation.SmallIconSize),
            Visible = true,
        };

        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Öffnen", null, (_, _) => _controller.ShowPopup());
        _lockItem = new Forms.ToolStripMenuItem("Jetzt sperren", null, (_, _) => _controller.Lock.Lock());
        menu.Items.Add(_lockItem);
        menu.Items.Add("Einstellungen …", null, (_, _) => _controller.OpenSettings());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Verlauf löschen …", null, (_, _) => _controller.ClearHistory());
        menu.Items.Add("Passwort vergessen – Tresor zurücksetzen …", null, (_, _) => _controller.ConfirmReset());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Beenden", null, (_, _) => _controller.Exit());
        _icon.ContextMenuStrip = menu;

        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == Forms.MouseButtons.Left) _controller.ShowPopup();
        };
        Update();
    }

    public void Update()
    {
        var lm = _controller.Lock;
        string text;
        if (!lm.IsUnlocked)
            text = "ClipSec – gesperrt";
        else if (lm.RemainingUnlocked is { } left)
            text = $"ClipSec – entsperrt (sperrt in {left:m\\:ss})";
        else
            text = "ClipSec – entsperrt";

        _lockItem.Enabled = lm.IsUnlocked;
        if (text != _lastText)
        {
            _icon.Text = text; // max. 63 Zeichen
            _lastText = text;
        }
    }

    public void ShowBalloon(string title, string text) =>
        _icon.ShowBalloonTip(5000, title, text, Forms.ToolTipIcon.Info);

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
