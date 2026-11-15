using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Win32;

// 検知を実測するための、無害な検証プログラム（設計書 §12）。
// 「未署名で、自動起動に登録し、ポートを待ち受け、ウィンドウを出さない」をわざと行う。
// キー入力の取得は行わない。終了時に自分の登録を消す。
//
//   PCMonitor.Probe.exe [--run-key] [--listen <ポート>] [--seconds <秒>]
//                       [--ready-file <パス>] [--stop-file <パス>]
//
//   --run-key     HKCU の Run キーに自分を登録する
//   --listen      0.0.0.0 の指定ポートを待ち受ける（接続は受けても何もしない）
//   --seconds     この秒数が過ぎたら終わる（既定 120）
//   --spawn-shell cmd.exe を子プロセスとして起動し、終わるまで待たせておく（何も実行させない）。
//                 この EXE を WINWORD.EXE などの名前に写して使うと、「文書を開くアプリが
//                 シェルを起動している」形になる
//   --alloc-exec  --spawn-shell で起動した子の cmd.exe の中に、書き込みも実行もできる領域を
//                 64 KB だけ確保する。**確保するだけ**で、何も書き込まず、何も実行させない
//                 （中身はゼロのまま。子は終了時に一緒に片付ける）。
//                 「ファイルの裏付けが無い実行可能な領域」の検知を確かめるためのもの
//   --key-apis    キーロガーが使う API を、**何も取得しない形で**呼ぶ（ETW で呼び出しが見えるかの確認用）。
//                 中身は KeyApis クラスの説明を参照
//   --hidden-desktop  画面に出ない別のデスクトップ（PCMonitorProbeDesktop）を作り、そこに見えないウィンドウを
//                 1 つ置いて待つ（何も起動しない）。終わるときに片付ける（設計書 §16.5）
//   --inject-input <回数>  マウスを 1 ピクセル動かして戻すのと、F24（ふつうのキーボードに無いキー）の押して離すを、
//                 合成入力として 0.2 秒おきにこの回数だけ送る（既定 5）。どこにも何も起きない入力にしてある
//   --ready-file  準備ができたら、このファイルを作る
//   --stop-file   このファイルができたら終わる
//
// 「署名済みのプロセスに読み込まれた未署名の DLL」は、この EXE ではなく
//   dotnet PCMonitor.Probe.dll …
// で確かめる（署名済みの dotnet.exe が、未署名の PCMonitor.Probe.dll を読み込む）。

const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
const string RunValueName = "PCMonitorProbe";

string? Option(string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

var registerRunKey = args.Contains("--run-key");
var port = int.TryParse(Option("--listen"), out var parsedPort) ? parsedPort : 0;
var seconds = int.TryParse(Option("--seconds"), out var parsedSeconds) ? parsedSeconds : 120;
var readyFile = Option("--ready-file");
var stopFile = Option("--stop-file");
var spawnShell = args.Contains("--spawn-shell");

TcpListener? listener = null;
HiddenDesktop? desktop = null;
Process? shell = null;
var registered = false;
try
{
    if (spawnShell)
    {
        // 入力を閉じないまま持っておくと、cmd.exe は何もせずに待ち続ける
        shell = Process.Start(new ProcessStartInfo("cmd.exe", "/q /k")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
        });

        if (shell is not null && args.Contains("--alloc-exec"))
        {
            // MEM_COMMIT | MEM_RESERVE、PAGE_EXECUTE_READWRITE。書き込みも、スレッドの作成もしない
            Native.VirtualAllocEx(shell.Handle, IntPtr.Zero, 64 * 1024, 0x3000, 0x40);
        }
    }

    if (registerRunKey)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath);
        key.SetValue(RunValueName, $"\"{Environment.ProcessPath}\"");
        registered = true;
    }

    if (port > 0)
    {
        listener = new TcpListener(IPAddress.Any, port);
        listener.Start();
    }

    var keyApis = args.Contains("--key-apis");
    if (keyApis) KeyApis.InstallAndRemove();

    if (args.Contains("--hidden-desktop")) desktop = HiddenDesktop.Create("PCMonitorProbeDesktop");

    if (args.Contains("--inject-input"))
    {
        var times = int.TryParse(Option("--inject-input"), out var parsedTimes) ? parsedTimes : 5;
        var sent = InjectedInput.Send(times);
        Console.Error.WriteLine($"合成入力を送った: {sent} 件（{times} 回 × マウス 2・キー 2）");
    }

    if (readyFile is not null) File.WriteAllText(readyFile, Environment.ProcessId.ToString());

    var watch = Stopwatch.StartNew();
    while (watch.Elapsed < TimeSpan.FromSeconds(seconds))
    {
        if (stopFile is not null && File.Exists(stopFile)) break;
        if (keyApis)
        {
            KeyApis.PollUnusedKey();
            Thread.Sleep(20);
        }
        else
        {
            Thread.Sleep(200);
        }
    }
}
finally
{
    if (shell is not null)
    {
        try { if (!shell.HasExited) shell.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { }
        shell.Dispose();
    }
    listener?.Stop();
    desktop?.Dispose();
    if (registered)
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
        key?.DeleteValue(RunValueName, throwOnMissingValue: false);
    }
}

/// <summary>
/// キーロガーが使う 4 つの API を呼ぶ。**キー入力は 1 つも受け取らない。**
///
///   - SetWindowsHookEx(WH_KEYBOARD_LL): 設置して、すぐに外す。このスレッドはメッセージを
///     処理しないので、フックの関数は一度も呼ばれない（呼ばれても、次へ渡すだけ）
///   - RegisterRawInputDevices(キーボード): 登録して、すぐに取り消す。ウィンドウを持たないので、
///     入力は届かない
///   - GetAsyncKeyState: F24（ふつうのキーボードに無いキー）だけを問い合わせ、結果は捨てる
///   - SetWinEventHook: 前面のウィンドウが変わった通知を登録して、すぐに外す（キーとは無関係。
///     同じ監査の仕組みに載っているので、番号の対応を確かめるために呼ぶ）
/// </summary>
internal static class KeyApis
{
    private const int WH_KEYBOARD_LL = 13;
    private const int VK_F24 = 0x87;
    private const uint RIDEV_REMOVE = 0x1;
    private const uint EVENT_SYSTEM_FOREGROUND = 0x3;

    private delegate IntPtr HookProc(int code, IntPtr wParam, IntPtr lParam);
    private delegate void WinEventProc(IntPtr hook, uint eventId, IntPtr window, int objectId, int childId, uint thread, uint time);

    // 関数への参照を保っておく（外すまでの間に回収されないように）
    private static readonly HookProc PassThrough = (code, wParam, lParam) => CallNextHookEx(IntPtr.Zero, code, wParam, lParam);
    private static readonly WinEventProc Ignore = (_, _, _, _, _, _, _) => { };

    public static void InstallAndRemove()
    {
        var hook = SetWindowsHookExW(WH_KEYBOARD_LL, PassThrough, GetModuleHandleW(null), 0);
        if (hook != IntPtr.Zero) UnhookWindowsHookEx(hook);

        var size = (uint)System.Runtime.InteropServices.Marshal.SizeOf<RAWINPUTDEVICE>();
        var keyboard = new RAWINPUTDEVICE { UsagePage = 1, Usage = 6 };
        if (RegisterRawInputDevices(new[] { keyboard }, 1, size))
        {
            keyboard.Flags = RIDEV_REMOVE;
            RegisterRawInputDevices(new[] { keyboard }, 1, size);
        }

        var winEvent = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, IntPtr.Zero, Ignore, 0, 0, 0);
        if (winEvent != IntPtr.Zero) UnhookWinEvent(winEvent);
    }

    public static void PollUnusedKey() => GetAsyncKeyState(VK_F24);

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct RAWINPUTDEVICE
    {
        public ushort UsagePage;
        public ushort Usage;
        public uint Flags;
        public IntPtr Target;
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookExW(int hookId, HookProc proc, IntPtr module, uint threadId);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hook);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr wParam, IntPtr lParam);

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool RegisterRawInputDevices(RAWINPUTDEVICE[] devices, uint count, uint size);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int virtualKey);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern IntPtr SetWinEventHook(uint eventMin, uint eventMax, IntPtr module, WinEventProc proc, uint processId, uint threadId, uint flags);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool UnhookWinEvent(IntPtr hook);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? name);
}

internal static class Native
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, nuint size, uint allocationType, uint protect);
}

/// <summary>
/// 画面に出ない別のデスクトップを作り、見えないウィンドウを 1 つ置く（設計書 §16.2 F の確認用）。
/// ウィンドウは何もしない。終わるときに壊して、デスクトップを閉じる。
/// </summary>
internal sealed class HiddenDesktop : IDisposable
{
    // READOBJECTS・CREATEWINDOW・ENUMERATE・WRITEOBJECTS
    private const uint DesktopAccess = 0x0001 | 0x0002 | 0x0040 | 0x0080;
    private const uint WM_APP_QUIT = 0x8001;

    private readonly IntPtr _desktop;
    private readonly Thread _thread;
    private IntPtr _window;
    private uint _threadId;

    private HiddenDesktop(IntPtr desktop)
    {
        _desktop = desktop;
        using var ready = new ManualResetEventSlim();
        // ウィンドウを持つ前のスレッドでないと、別のデスクトップへ移れない
        _thread = new Thread(() =>
        {
            _threadId = GetCurrentThreadId();
            if (SetThreadDesktop(_desktop))
                _window = CreateWindowExW(0, "STATIC", "PCMonitor Probe", 0, 0, 0, 100, 100,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            Console.Error.WriteLine(_window != IntPtr.Zero
                ? "別のデスクトップにウィンドウを置いた"
                : $"ウィンドウを置けなかった（エラー {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}）");
            // メッセージ キューを作ってから知らせる
            PeekMessageW(out _, IntPtr.Zero, 0, 0, 0);
            ready.Set();
            while (GetMessageW(out var msg, IntPtr.Zero, 0, 0) > 0)
            {
                if (msg.message == WM_APP_QUIT) break;
            }
            if (_window != IntPtr.Zero) DestroyWindow(_window);
        }) { IsBackground = true };
        _thread.Start();
        ready.Wait();
    }

    public static HiddenDesktop? Create(string name)
    {
        var desktop = CreateDesktopW(name, IntPtr.Zero, IntPtr.Zero, 0, DesktopAccess, IntPtr.Zero);
        if (desktop == IntPtr.Zero)
        {
            Console.Error.WriteLine($"デスクトップを作れなかった（エラー {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}）");
            return null;
        }
        Console.Error.WriteLine($"デスクトップ {name} を作った");
        return new HiddenDesktop(desktop);
    }

    public void Dispose()
    {
        PostThreadMessageW(_threadId, WM_APP_QUIT, IntPtr.Zero, IntPtr.Zero);
        _thread.Join(TimeSpan.FromSeconds(5));
        CloseDesktop(_desktop);
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
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

    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateDesktopW(string name, IntPtr device, IntPtr mode, uint flags, uint access, IntPtr attributes);

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseDesktop(IntPtr desktop);

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetThreadDesktop(IntPtr desktop);

    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowExW(uint exStyle, string className, string windowName, uint style,
        int x, int y, int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool DestroyWindow(IntPtr window);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern int GetMessageW(out MSG msg, IntPtr window, uint min, uint max);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool PeekMessageW(out MSG msg, IntPtr window, uint min, uint max, uint remove);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool PostThreadMessageW(uint threadId, uint message, IntPtr wParam, IntPtr lParam);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();
}

/// <summary>
/// 合成入力を送る（設計書 §16.2 G の確認用）。マウスは 1 ピクセル動かしてすぐ戻す、キーは F24 の押して離すだけなので、
/// 前面のアプリには何も起きない。
/// </summary>
internal static class InjectedInput
{
    private const uint INPUT_MOUSE = 0;
    private const uint INPUT_KEYBOARD = 1;
    private const uint MOUSEEVENTF_MOVE = 0x0001;
    private const uint KEYEVENTF_KEYUP = 0x0002;
    private const ushort VK_F24 = 0x87;

    public static int Send(int times)
    {
        var sent = 0;
        var size = System.Runtime.InteropServices.Marshal.SizeOf<INPUT>();
        for (var i = 0; i < times; i++)
        {
            var inputs = new[]
            {
                // 0 ピクセルの移動は、Windows がフックに渡す前に捨てる（2026-11-15 に確認）。1 ピクセル動かしてすぐ戻す
                new INPUT { Type = INPUT_MOUSE, Union = new InputUnion { Mouse = new MOUSEINPUT { Dx = 1, Flags = MOUSEEVENTF_MOVE } } },
                new INPUT { Type = INPUT_MOUSE, Union = new InputUnion { Mouse = new MOUSEINPUT { Dx = -1, Flags = MOUSEEVENTF_MOVE } } },
                new INPUT { Type = INPUT_KEYBOARD, Union = new InputUnion { Keyboard = new KEYBDINPUT { VirtualKey = VK_F24 } } },
                new INPUT { Type = INPUT_KEYBOARD, Union = new InputUnion { Keyboard = new KEYBDINPUT { VirtualKey = VK_F24, Flags = KEYEVENTF_KEYUP } } },
            };
            sent += (int)SendInput((uint)inputs.Length, inputs, size);
            Thread.Sleep(200);
        }
        return sent;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct INPUT
    {
        public uint Type;
        public InputUnion Union;
    }

    // INPUT の共用部分は、いちばん大きい MOUSEINPUT に合わせる
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Explicit)]
    private struct InputUnion
    {
        [System.Runtime.InteropServices.FieldOffset(0)] public MOUSEINPUT Mouse;
        [System.Runtime.InteropServices.FieldOffset(0)] public KEYBDINPUT Keyboard;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct MOUSEINPUT
    {
        public int Dx;
        public int Dy;
        public uint MouseData;
        public uint Flags;
        public uint Time;
        public IntPtr ExtraInfo;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort VirtualKey;
        public ushort ScanCode;
        public uint Flags;
        public uint Time;
        public IntPtr ExtraInfo;
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint count, INPUT[] inputs, int size);
}
