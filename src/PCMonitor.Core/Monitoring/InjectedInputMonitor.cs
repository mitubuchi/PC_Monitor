using System.ComponentModel;
using System.Runtime.InteropServices;

namespace PCMonitor.Core.Monitoring;

/// <summary>1 秒ぶんの入力の件数。キーの中身は持たない（持つ欄が無い）。</summary>
public sealed record InputSecond(DateTime SecondUtc, int Keys, int InjectedKeys, int Mouse, int InjectedMouse)
{
    public int Injected => InjectedKeys + InjectedMouse;
}

/// <summary>合成入力を見張った結果（設計書 §16.2 G）。入力のあった秒だけを持つ。</summary>
public sealed record InputObservation(DateTime StartedUtc, DateTime? StoppedUtc, IReadOnlyList<InputSecond> Seconds)
{
    public int InjectedKeys => Seconds.Sum(s => s.InjectedKeys);
    public int InjectedMouse => Seconds.Sum(s => s.InjectedMouse);
    public int Injected => InjectedKeys + InjectedMouse;
    public int Physical => Seconds.Sum(s => s.Keys + s.Mouse) - Injected;
    public int PeakInjectedPerSecond => Seconds.Count == 0 ? 0 : Seconds.Max(s => s.Injected);

    public string Period =>
        $"{StartedUtc.ToLocalTime():HH:mm:ss}〜{(StoppedUtc ?? DateTime.UtcNow).ToLocalTime():HH:mm:ss}"
        + $"（{(int)((StoppedUtc ?? DateTime.UtcNow) - StartedUtc).TotalSeconds} 秒）";
}

/// <summary>
/// 合成入力（<c>SendInput</c> などで作られたマウスやキーの入力）が来ているかを見張る（設計書 §16.2 G）。
///
/// 低レベル フック（<c>WH_KEYBOARD_LL</c>・<c>WH_MOUSE_LL</c>）を仕掛けるので、**PCMonitor 自身が
/// キーロガーと同じ形になる。** そのため次を守る。
/// - 受け取った構造体から読むのは <c>flags</c> の位置の 4 バイトだけ。仮想キー コード・スキャン コード・
///   マウスの位置には触らない（読む処理そのものが無い）
/// - 残すのは 1 秒ごとの件数だけ
/// - ボタンで始めてボタンで止める。常駐しない。管理者は要らない
///
/// 入力を作ったプロセスは、フックからは分からない。リモートデスクトップ経由の入力には印が付かない見込み。
/// </summary>
public sealed class InjectedInputMonitor : IDisposable
{
    // 1 時間ぶん見張れば十分。それより長いと古い秒から捨てる
    private const int MaxSeconds = 3600;

    // KBDLLHOOKSTRUCT は vkCode・scanCode・flags の順、MSLLHOOKSTRUCT は pt（8 バイト）・mouseData・flags の順
    private const int KeyboardFlagsOffset = 8;
    private const int MouseFlagsOffset = 12;

    private const uint LLKHF_INJECTED = 0x10;
    private const uint LLKHF_LOWER_IL_INJECTED = 0x02;
    private const uint LLMHF_INJECTED = 0x01;
    private const uint LLMHF_LOWER_IL_INJECTED = 0x02;

    private readonly object _gate = new();
    private readonly List<InputSecond> _seconds = new();
    private Thread? _thread;
    private uint _threadId;
    private DateTime? _startedUtc;
    private DateTime? _stoppedUtc;

    // フックの関数は、ネイティブ側から呼ばれている間ずっと生きていなければならない
    private HookProc? _keyboardProc;
    private HookProc? _mouseProc;

    public bool IsRunning => _thread is not null;
    public DateTime? StartedUtc => _startedUtc;

    /// <summary>件数が変わったとき（フックのスレッドから、1 秒に 1 回まで）。</summary>
    public event Action? Changed;

    public void Start()
    {
        if (_thread is not null) return;
        lock (_gate) _seconds.Clear();
        _startedUtc = DateTime.UtcNow;
        _stoppedUtc = null;

        Exception? failure = null;
        using var ready = new ManualResetEventSlim();
        _thread = new Thread(() => Pump(ready, ref failure)) { IsBackground = true, Name = "PCMonitor input watch" };
        _thread.Start();
        ready.Wait();
        if (failure is not null)
        {
            _thread.Join();
            _thread = null;
            throw failure;
        }
    }

    public void Stop()
    {
        if (_thread is not { } thread) return;
        PostThreadMessageW(_threadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero);
        thread.Join(TimeSpan.FromSeconds(5));
        _thread = null;
        _stoppedUtc = DateTime.UtcNow;
    }

    /// <summary>いままでの結果。見張りを一度も始めていなければ null。</summary>
    public InputObservation? Observation()
    {
        if (_startedUtc is not { } started) return null;
        lock (_gate) return new InputObservation(started, _stoppedUtc, _seconds.ToList());
    }

    public void Dispose() => Stop();

    // フックは、仕掛けたスレッドがメッセージを回している間だけ呼ばれる
    private void Pump(ManualResetEventSlim ready, ref Exception? failure)
    {
        _threadId = GetCurrentThreadId();
        _keyboardProc = (code, message, data) => OnInput(code, message, data, keyboard: true);
        _mouseProc = (code, message, data) => OnInput(code, message, data, keyboard: false);
        var module = GetModuleHandleW(null);
        var keyboard = SetWindowsHookExW(WH_KEYBOARD_LL, _keyboardProc, module, 0);
        var mouse = keyboard == IntPtr.Zero ? IntPtr.Zero : SetWindowsHookExW(WH_MOUSE_LL, _mouseProc, module, 0);
        if (keyboard == IntPtr.Zero || mouse == IntPtr.Zero)
        {
            failure = new Win32Exception(Marshal.GetLastWin32Error(), "低レベル フックを仕掛けられなかった");
            if (keyboard != IntPtr.Zero) UnhookWindowsHookEx(keyboard);
            ready.Set();
            return;
        }

        // メッセージ キューを作ってから知らせる（作る前に WM_QUIT を送られると取りこぼす）
        PeekMessageW(out _, IntPtr.Zero, 0, 0, PM_NOREMOVE);
        ready.Set();
        try
        {
            while (GetMessageW(out var msg, IntPtr.Zero, 0, 0) > 0)
            {
                TranslateMessage(ref msg);
                DispatchMessageW(ref msg);
            }
        }
        finally
        {
            UnhookWindowsHookEx(mouse);
            UnhookWindowsHookEx(keyboard);
        }
    }

    private IntPtr OnInput(int code, IntPtr message, IntPtr data, bool keyboard)
    {
        if (code >= 0)
        {
            // flags だけを読む。ほかの欄（キーの値・位置）には触らない
            var flags = (uint)Marshal.ReadInt32(data, keyboard ? KeyboardFlagsOffset : MouseFlagsOffset);
            var injected = keyboard
                ? (flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED)) != 0
                : (flags & (LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED)) != 0;
            Count(keyboard, injected);
        }
        // ほかのフックと、入力そのものは止めない
        return CallNextHookEx(IntPtr.Zero, code, message, data);
    }

    private void Count(bool keyboard, bool injected)
    {
        var now = DateTime.UtcNow;
        var second = new DateTime(now.Ticks - now.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
        var newSecond = false;
        lock (_gate)
        {
            var last = _seconds.Count > 0 ? _seconds[^1] : null;
            if (last is null || last.SecondUtc != second)
            {
                if (_seconds.Count >= MaxSeconds) _seconds.RemoveAt(0);
                last = new InputSecond(second, 0, 0, 0, 0);
                _seconds.Add(last);
                newSecond = true;
            }
            _seconds[^1] = keyboard
                ? last with { Keys = last.Keys + 1, InjectedKeys = last.InjectedKeys + (injected ? 1 : 0) }
                : last with { Mouse = last.Mouse + 1, InjectedMouse = last.InjectedMouse + (injected ? 1 : 0) };
        }
        if (newSecond) Changed?.Invoke();
    }

    // ---- P/Invoke ----

    private const int WH_KEYBOARD_LL = 13;
    private const int WH_MOUSE_LL = 14;
    private const uint WM_QUIT = 0x0012;
    private const uint PM_NOREMOVE = 0x0000;

    private delegate IntPtr HookProc(int code, IntPtr message, IntPtr data);

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
        public uint lPrivate;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookExW(int hook, HookProc proc, IntPtr module, uint threadId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hook);

    [DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr message, IntPtr data);

    [DllImport("user32.dll")]
    private static extern int GetMessageW(out MSG msg, IntPtr window, uint min, uint max);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PeekMessageW(out MSG msg, IntPtr window, uint min, uint max, uint remove);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TranslateMessage(ref MSG msg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessageW(ref MSG msg);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostThreadMessageW(uint threadId, uint message, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? name);
}
