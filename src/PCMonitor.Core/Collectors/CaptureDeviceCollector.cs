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
///        └─ LastUsedTimeStop       FILETIME（0 なら、いま使っている見込み）
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
        facts.DeviceUsages.Add(new DeviceUsage(device, app, path, start, FromFileTime(key.GetValue("LastUsedTimeStop"))));
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
