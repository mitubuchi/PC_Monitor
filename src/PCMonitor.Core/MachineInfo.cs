using System.Runtime.InteropServices;
using Microsoft.Win32;
using PCMonitor.Core.Model;
using PCMonitor.Core.Monitoring;

namespace PCMonitor.Core;

/// <summary>
/// 点検している PC の条件（Windows の版、CPU の種類、権限）と、そこで使えない機能。
///
/// 別の PC で使われることを前提にする。結果を見る人が「この PC ではどこまで見られたのか」を
/// 取り違えないよう、使えない機能や確かめていない条件は、スキャンの注意書きに必ず出す。
/// </summary>
public sealed record MachineInfo(
    string WindowsName,
    string DisplayVersion,
    int Build,
    string OsArchitecture,
    string ProcessArchitecture,
    bool Elevated,
    string Runtime)
{
    /// <summary>動作を確かめた Windows（2026-11-13、Windows 11 25H2）。</summary>
    public const int VerifiedBuild = 26200;

    public string Describe() =>
        $"{WindowsName} {DisplayVersion}（ビルド {Build}）、{OsArchitecture}、{(Elevated ? "管理者" : "通常")}の権限、{Runtime}";

    public static MachineInfo Detect()
    {
        var build = Environment.OSVersion.Version.Build;
        string displayVersion = "";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            displayVersion = key?.GetValue("DisplayVersion") as string ?? key?.GetValue("ReleaseId") as string ?? "";
            if (key?.GetValue("CurrentBuild") is string text && int.TryParse(text, out var registryBuild)) build = registryBuild;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // 版の表示が欠けるだけで、点検には差し支えない
        }

        return new MachineInfo(
            // レジストリの ProductName は Windows 11 でも「Windows 10」のままなので、ビルド番号で分ける
            build >= 22000 ? "Windows 11" : "Windows 10",
            displayVersion,
            build,
            RuntimeInformation.OSArchitecture.ToString(),
            RuntimeInformation.ProcessArchitecture.ToString(),
            Scanner.IsElevated(),
            RuntimeInformation.FrameworkDescription);
    }

    /// <summary>この PC で使えない機能や、確かめていない条件。スキャンの注意書きに出す。</summary>
    public IEnumerable<ScanNote> Caveats()
    {
        if (RuntimeInformation.OSArchitecture == Architecture.Arm64)
            yield return new ScanNote("この PC",
                "ARM64 の PC では動作を確かめていない（x64 のアプリとして動いている）。ほかのプロセスの DLL やメモリの割り当てが、"
                + "x64 の PC と違って見えることがある");

        if (Build < 22000)
            yield return new ScanNote("この PC",
                $"Windows 10 では動作を確かめていない（確かめたのは Windows 11 25H2、ビルド {VerifiedBuild}）。"
                + "点検の仕組みは Windows 10 にもあるが、採点は Windows 11 で調整している");
        else if (Build < VerifiedBuild)
            yield return new ScanNote("この PC",
                $"確かめた Windows（ビルド {VerifiedBuild}）より古い。キー入力 API の監視は、Windows の版でイベントの形が変わりうる");

        var (supported, reason) = KeyApiMonitor.CheckSupport();
        if (!supported)
            yield return new ScanNote("キー入力 API の監視", "この Windows では使えない: " + reason);
    }
}
