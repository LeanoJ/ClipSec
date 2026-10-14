using System.Runtime.InteropServices;
using static ClipSec.Native.NativeMethods;

namespace ClipSec.Native;

internal static class PasteHelper
{
    private const ushort VK_CONTROL = 0x11;
    private const ushort VK_SHIFT = 0x10;
    private const ushort VK_MENU = 0x12;
    private const ushort VK_LWIN = 0x5B;
    private const ushort VK_RWIN = 0x5C;
    private const ushort VK_V = 0x56;

    /// <summary>Holt ein Fenster zuverlässig in den Vordergrund (umgeht die Foreground-Lock-Sperre).</summary>
    public static void ForceForeground(IntPtr hwnd)
    {
        var fg = GetForegroundWindow();
        if (fg == hwnd) return;
        var fgThread = GetWindowThreadProcessId(fg, out _);
        var myThread = GetCurrentThreadId();
        var attached = fgThread != 0 && fgThread != myThread && AttachThreadInput(myThread, fgThread, true);
        try
        {
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
        }
        finally
        {
            if (attached) AttachThreadInput(myThread, fgThread, false);
        }
    }

    /// <summary>Aktiviert das Zielfenster und sendet Strg+V.</summary>
    public static async Task PasteIntoAsync(IntPtr target)
    {
        if (target == IntPtr.Zero || !IsWindow(target)) return;
        ForceForeground(target);
        await Task.Delay(60);

        var inputs = new List<INPUT>();
        // Noch gehaltene Modifier lösen, sonst wird z. B. Win+Strg+V daraus.
        foreach (var vk in new[] { VK_LWIN, VK_RWIN, VK_SHIFT, VK_MENU })
            if ((GetAsyncKeyState(vk) & 0x8000) != 0) inputs.Add(KeyboardHook.KeyInput(vk, true));

        inputs.Add(KeyboardHook.KeyInput(VK_CONTROL, false));
        inputs.Add(KeyboardHook.KeyInput(VK_V, false));
        inputs.Add(KeyboardHook.KeyInput(VK_V, true));
        inputs.Add(KeyboardHook.KeyInput(VK_CONTROL, true));
        SendInput((uint)inputs.Count, inputs.ToArray(), Marshal.SizeOf<INPUT>());
    }

    /// <summary>
    /// Position für das Popup: Text-Cursor (Caret) des Zielfensters, sonst Mauszeiger. In physischen Pixeln.
    /// </summary>
    public static (POINT anchor, RECT workArea, double scale) GetPopupAnchor(IntPtr target)
    {
        POINT anchor;
        var gui = new GUITHREADINFO { cbSize = Marshal.SizeOf<GUITHREADINFO>() };
        var thread = target != IntPtr.Zero ? GetWindowThreadProcessId(target, out _) : 0;
        if (thread != 0 && GetGUIThreadInfo(thread, ref gui) && gui.hwndCaret != IntPtr.Zero &&
            (gui.rcCaret.Right > gui.rcCaret.Left || gui.rcCaret.Bottom > gui.rcCaret.Top))
        {
            anchor = new POINT { X = gui.rcCaret.Left, Y = gui.rcCaret.Bottom };
            ClientToScreen(gui.hwndCaret, ref anchor);
        }
        else
        {
            GetCursorPos(out anchor);
        }

        var mon = MonitorFromPoint(anchor, MONITOR_DEFAULTTONEAREST);
        var mi = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
        GetMonitorInfo(mon, ref mi);
        var scale = GetDpiForMonitor(mon, 0, out var dpiX, out _) == 0 ? dpiX / 96.0 : 1.0;
        return (anchor, mi.rcWork, scale);
    }
}
