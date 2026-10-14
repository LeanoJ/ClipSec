using System.Windows.Interop;
using static ClipSec.Native.NativeMethods;

namespace ClipSec.Native;

/// <summary>Unsichtbares Nachrichtenfenster, das Änderungen der Zwischenablage empfängt.</summary>
internal sealed class MessageWindow : IDisposable
{
    private readonly HwndSource _source;

    public event Action? ClipboardChanged;

    public MessageWindow()
    {
        var p = new HwndSourceParameters("ClipSecMessageWindow")
        {
            Width = 0,
            Height = 0,
            WindowStyle = 0,
            ParentWindow = new IntPtr(-3), // HWND_MESSAGE
        };
        _source = new HwndSource(p);
        _source.AddHook(WndProc);
        AddClipboardFormatListener(_source.Handle);
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_CLIPBOARDUPDATE)
        {
            ClipboardChanged?.Invoke();
            handled = true;
        }
        return IntPtr.Zero;
    }

    public void Dispose()
    {
        RemoveClipboardFormatListener(_source.Handle);
        _source.RemoveHook(WndProc);
        _source.Dispose();
    }
}
