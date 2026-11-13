using PCMonitor.Core.Model;

namespace PCMonitor.Core.Scoring;

/// <summary>
/// 親子関係の異常（設計書 §11）。見るのは 2 つ。
///
///   1. 文書を開くアプリが、シェルやスクリプト実行系を起動している（マクロや細工した文書の典型）
///   2. システムのプロセスの親が、決まった相手ではない（正規のプロセスを起動して中身を
///      差し替える手口では、親が services.exe にならない）
///
/// 親の番号は、親が終わったあと別のプロセスに使い回される。起動時刻が分かるときは、
/// 親のほうが先に起動していることを確かめる。
/// </summary>
public static class ParentRules
{
    /// <param name="Name">親であるはずのプロセス。</param>
    /// <param name="AlwaysRunning">
    /// 親が Windows の動いている間ずっと居るか。居るなら番号は使い回されないので、
    /// 起動時刻が分からなくても（管理者でなくても）食い違いを異常と言える。
    /// </param>
    private sealed record Expected(string Name, bool AlwaysRunning);

    // 2026-11-13 に実機で確かめた（svchost 89 個すべての親が services.exe、ほかも下のとおり）
    private static readonly Dictionary<string, Expected> ExpectedParents = new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost.exe"] = new("services.exe", true),
        ["spoolsv.exe"] = new("services.exe", true),
        ["services.exe"] = new("wininit.exe", true),
        ["lsass.exe"] = new("wininit.exe", true),
        ["taskhostw.exe"] = new("svchost.exe", false),
        ["RuntimeBroker.exe"] = new("svchost.exe", false),
        ["sihost.exe"] = new("svchost.exe", false),
    };

    // ブラウザーは入れない。拡張機能のネイティブ メッセージングが cmd.exe 経由で起動するのは正規の動き
    private static readonly HashSet<string> DocumentApps = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
        "mspub.exe", "visio.exe", "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "hh.exe", "wordpad.exe",
    };

    private static readonly HashSet<string> Shells = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    };

    /// <summary>異常があれば、その説明を返す。</summary>
    public static string? Check(ProcessFact process, IReadOnlyDictionary<int, ProcessFact> processes)
    {
        processes.TryGetValue(process.ParentPid, out var parent);

        var timesKnown = parent?.StartedUtc is not null && process.StartedUtc is not null;
        // 親のほうが後から起動している。番号が使い回されただけで、本当の親はもう居ない
        if (timesKnown && parent!.StartedUtc > process.StartedUtc) parent = null;

        if (ExpectedParents.TryGetValue(process.Name, out var expected))
        {
            if (parent is null)
                return expected.AlwaysRunning
                    ? $"{process.Name}（PID {process.Pid}）の親が見つからない（{expected.Name} のはず）"
                    : null;
            if (parent.Name.Equals(expected.Name, StringComparison.OrdinalIgnoreCase)) return null;
            if (!expected.AlwaysRunning && !timesKnown) return null;
            return $"{process.Name}（PID {process.Pid}）の親が {expected.Name} ではなく {parent.Name}（PID {parent.Pid}）";
        }

        if (parent is not null && timesKnown && Shells.Contains(process.Name) && DocumentApps.Contains(parent.Name))
            return $"文書を開くアプリ {parent.Name}（PID {parent.Pid}）が {process.Name}（PID {process.Pid}）を起動している";

        return null;
    }
}
