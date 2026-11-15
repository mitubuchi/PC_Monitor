using System.Globalization;
using Microsoft.Win32;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Collectors;

/// <summary>
/// インストール済みのプログラム（Uninstall キー）を集める（設計書 §16.2 A）。
/// 遠隔操作ソフトの「いつ入ったか」を知るのに使う。判断はしない。
/// </summary>
public sealed class InstalledProgramCollector
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string UninstallPath32 = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    public void Collect(ScanFacts facts, CancellationToken cancel)
    {
        Read(facts, Registry.LocalMachine, "HKLM", UninstallPath, cancel);
        Read(facts, Registry.LocalMachine, "HKLM", UninstallPath32, cancel);
        Read(facts, Registry.CurrentUser, "HKCU", UninstallPath, cancel);
    }

    private static void Read(ScanFacts facts, RegistryKey hive, string hiveName, string path, CancellationToken cancel)
    {
        using var root = hive.OpenSubKey(path);
        if (root is null) return;

        foreach (var name in root.GetSubKeyNames())
        {
            cancel.ThrowIfCancellationRequested();
            using var key = root.OpenSubKey(name);
            if (key?.GetValue("DisplayName") is not string displayName || string.IsNullOrWhiteSpace(displayName)) continue;

            facts.InstalledPrograms.Add(new InstalledProgram(
                displayName.Trim(),
                (key.GetValue("Publisher") as string)?.Trim(),
                ParseInstallDate(key.GetValue("InstallDate") as string),
                (key.GetValue("InstallLocation") as string)?.Trim().Trim('"'),
                ExecutableFromIcon(key.GetValue("DisplayIcon") as string),
                $@"{hiveName}\{path}\{name}"));
        }
    }

    /// <summary><c>InstallDate</c> は <c>yyyyMMdd</c> の文字列（その PC の日付）。読めなければ null。</summary>
    internal static DateTime? ParseInstallDate(string? text) =>
        DateTime.TryParseExact(text?.Trim(), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var date)
            ? date.ToUniversalTime()
            : null;

    /// <summary>
    /// <c>DisplayIcon</c>（<c>"C:\…\app.exe",0</c> の形）から EXE のパスを取り出す。
    /// 実在する EXE を指しているときだけ返す（アイコン専用の .ico や、アンインストーラーを指すことも多い）。
    /// </summary>
    internal static string? ExecutableFromIcon(string? icon)
    {
        if (string.IsNullOrWhiteSpace(icon)) return null;
        var text = icon.Trim();
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            text = end > 0 ? text[1..end] : text.Trim('"');
        }
        else
        {
            var comma = text.LastIndexOf(',');
            if (comma > 0 && int.TryParse(text[(comma + 1)..].Trim(), out _)) text = text[..comma];
        }

        text = Environment.ExpandEnvironmentVariables(text.Trim());
        if (!text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        try
        {
            return File.Exists(text) ? Path.GetFullPath(text) : null;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }
}
