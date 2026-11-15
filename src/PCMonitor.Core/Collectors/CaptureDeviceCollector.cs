using Microsoft.Win32;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Collectors;

/// <summary>
/// アプリごとの、カメラとマイクを最後に使った時刻を読む（設計書 §16.2 E）。通常の権限で読める。
///
/// <code>
/// HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\
///   ├─ &lt;パッケージ名&gt;\              ストア アプリ
///   └─ NonPackaged\&lt;パス&gt;\          ふつうのアプリ。パスの \ が # に置き換わっている
///        ├─ LastUsedTimeStart      FILETIME
///        └─ LastUsedTimeStop       FILETIME（0 なら、いま使っている見込み。ただし異常終了でも 0 のまま残るので、
///                                  アプリが動いているかを合わせて見る）
/// </code>
///
/// 画面の取り込みは、ここには記録されない（設計書 §16.6）。
/// </summary>
public sealed class CaptureDeviceCollector
{
    private const string ConsentStore = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    public void Collect(ScanFacts facts, CancellationToken cancel)
    {
        Read(facts, CaptureDevice.Camera, "webcam", cancel);
        Read(facts, CaptureDevice.Microphone, "microphone", cancel);
    }

    private static void Read(ScanFacts facts, CaptureDevice device, string capability, CancellationToken cancel)
    {
        using var root = Registry.CurrentUser.OpenSubKey($@"{ConsentStore}\{capability}");
        if (root is null) return;

        foreach (var name in root.GetSubKeyNames())
        {
            cancel.ThrowIfCancellationRequested();
            using var key = root.OpenSubKey(name);
            if (key is null) continue;

            if (name.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var app in key.GetSubKeyNames())
                {
                    using var appKey = key.OpenSubKey(app);
                    if (appKey is not null) Add(facts, device, app, ToPath(app), appKey);
                }
            }
            else
            {
                Add(facts, device, name, null, key);
            }
        }
    }

    /// <summary>使った記録のあるものだけ残す。許可を聞かれただけで使っていないアプリは、時刻を持たない。</summary>
    private static void Add(ScanFacts facts, CaptureDevice device, string app, string? path, RegistryKey key)
    {
        var start = FromFileTime(key.GetValue("LastUsedTimeStart"));
        if (start is null) return;
        var usage = new DeviceUsage(device, app, path, start, FromFileTime(key.GetValue("LastUsedTimeStop")));
        facts.DeviceUsages.Add(usage.Unclosed ? usage with { Running = IsRunning(facts.Processes, path) } : usage);
    }

    /// <summary>
    /// そのアプリがいま動いているか。分からなければ null（ストア アプリ、プロセスの一覧を取れなかった）。
    /// 実行ファイルを確かめられなかったプロセス（管理者として動いているものなど）は、名前が同じなら動いているとみなす。
    /// 「動いていない」と言い切るのは、見逃す側に倒れる判断なので、言えるときだけにする。
    /// </summary>
    internal static bool? IsRunning(IReadOnlyList<ProcessFact> processes, string? path)
    {
        if (path is null || processes.Count == 0) return null;
        var name = System.IO.Path.GetFileNameWithoutExtension(path);
        return processes.Any(p => p.Path is not null
            ? string.Equals(p.Path, path, StringComparison.OrdinalIgnoreCase)
            : string.Equals(System.IO.Path.GetFileNameWithoutExtension(p.Name), name, StringComparison.OrdinalIgnoreCase)
              || string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary><c>C:#Users#u#app.exe</c> → <c>C:\Users\u\app.exe</c>。</summary>
    internal static string ToPath(string name) => name.Replace('#', '\\');

    internal static DateTime? FromFileTime(object? value)
    {
        var ticks = value switch
        {
            long l => l,
            int i => i,
            byte[] { Length: 8 } bytes => BitConverter.ToInt64(bytes),
            _ => 0L,
        };
        return ticks > 0 ? DateTime.FromFileTimeUtc(ticks) : null;
    }
}
