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

    if (readyFile is not null) File.WriteAllText(readyFile, Environment.ProcessId.ToString());

    var watch = Stopwatch.StartNew();
    while (watch.Elapsed < TimeSpan.FromSeconds(seconds))
    {
        if (stopFile is not null && File.Exists(stopFile)) break;
        Thread.Sleep(200);
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
