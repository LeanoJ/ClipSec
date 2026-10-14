using System.Runtime.InteropServices;
using ClipSec.Core;
using static ClipSec.Native.NativeMethods;

namespace ClipSec.Native;

/// <summary>
/// Globaler Low-Level-Tastatur-Hook. Fängt den eingestellten Hotkey (Standard Win+V) ab,
/// bevor Windows ihn an den eingebauten Zwischenablage-Verlauf weitergibt.
/// Muss auf einem Thread mit Message-Loop (UI-Thread) installiert werden.
/// </summary>
internal sealed class KeyboardHook : IDisposable
{
    private const int VK_V = 0x56;
    private const int VK_LWIN = 0x5B;
    private const int VK_RWIN = 0x5C;
    private const int VK_SHIFT = 0x10;
    private const int VK_CONTROL = 0x11;
    private const int VK_MENU = 0x12;
    /// <summary>Nicht belegter Key, verhindert, dass beim Loslassen von Win das Startmenü aufgeht.</summary>
    private const ushort VK_MASK = 0xE8;
    private static readonly IntPtr OwnInjectionMarker = new(0x434C5053); // "CLPS"

    private readonly LowLevelKeyboardProc _proc; // Referenz halten, sonst sammelt der GC den Delegate ein
    private IntPtr _hook;
    private bool _swallowedKeyDown;

    public HotkeyPreset Preset { get; set; }

    public event Action? HotkeyPressed;

    public KeyboardHook(HotkeyPreset preset)
    {
        Preset = preset;
        _proc = HookProc;
    }

    public void Install()
    {
        if (_hook != IntPtr.Zero) return;
        _hook = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, GetModuleHandle(null), 0);
        if (_hook == IntPtr.Zero)
            throw new InvalidOperationException($"Tastatur-Hook konnte nicht installiert werden (Fehler {Marshal.GetLastWin32Error()}).");
    }

    public void Dispose()
    {
        if (_hook != IntPtr.Zero)
        {
            UnhookWindowsHookEx(_hook);
            _hook = IntPtr.Zero;
        }
    }

    private IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0)
        {
            var info = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
            var msg = wParam.ToInt32();
            var isDown = msg is WM_KEYDOWN or WM_SYSKEYDOWN;
            var isUp = msg is WM_KEYUP or WM_SYSKEYUP;
            var injected = (info.flags & LLKHF_INJECTED) != 0;

            if (info.vkCode == VK_V && !injected)
            {
                if (isDown && ModifiersMatch())
                {
                    _swallowedKeyDown = true;
                    if (Preset == HotkeyPreset.WinV) SendMaskKey();
                    // Asynchron, damit der Hook sofort zurückkehrt (sonst Timeout durch Windows).
                    System.Windows.Application.Current?.Dispatcher.BeginInvoke(() => HotkeyPressed?.Invoke());
                    return 1;
                }
                if (isUp && _swallowedKeyDown)
                {
                    _swallowedKeyDown = false;
                    return 1;
                }
            }
        }
        return CallNextHookEx(_hook, nCode, wParam, lParam);
    }

    private bool ModifiersMatch()
    {
        bool win = IsDown(VK_LWIN) || IsDown(VK_RWIN);
        bool ctrl = IsDown(VK_CONTROL);
        bool shift = IsDown(VK_SHIFT);
        bool alt = IsDown(VK_MENU);
        return Preset switch
        {
            HotkeyPreset.WinV => win && !ctrl && !shift && !alt,
            HotkeyPreset.CtrlShiftV => ctrl && shift && !win && !alt,
            HotkeyPreset.CtrlAltV => ctrl && alt && !win && !shift,
            _ => false,
        };
    }

    private static bool IsDown(int vk) => (GetAsyncKeyState(vk) & 0x8000) != 0;

    private static void SendMaskKey()
    {
        var inputs = new[]
        {
            KeyInput(VK_MASK, false),
            KeyInput(VK_MASK, true),
        };
        SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>());
    }

    internal static INPUT KeyInput(ushort vk, bool up) => new()
    {
        type = INPUT_KEYBOARD,
        U = new InputUnion
        {
            ki = new KEYBDINPUT
            {
                wVk = vk,
                dwFlags = up ? KEYEVENTF_KEYUP : 0,
                dwExtraInfo = OwnInjectionMarker,
            },
        },
    };
}
