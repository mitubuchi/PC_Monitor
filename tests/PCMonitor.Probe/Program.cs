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
