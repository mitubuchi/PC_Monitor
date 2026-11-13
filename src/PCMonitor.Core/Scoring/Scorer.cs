using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using PCMonitor.Core.Collectors;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Scoring;

/// <summary>点数と境界（設計書 §6）。初期値で、実機で試しながら調整する。</summary>
public sealed class ScoringRules
{
    public int SignatureInvalid { get; init; } = 50;
    public int SystemNameWrongLocation { get; init; } = 40;
    public int ViaScriptHost { get; init; } = 40;
    public int SignatureNone { get; init; } = 30;
    public int UnusualPersistence { get; init; } = 30;
    public int UserWritableLocation { get; init; } = 20;
    public int ListeningNonLoopback { get; init; } = 20;
    public int HiddenOrDoubleExtension { get; init; } = 15;
    public int Autostart { get; init; } = 10;
    public int OutboundConnection { get; init; } = 10;
    public int NoVisibleWindow { get; init; } = 10;
    public int RecentlyCreated { get; init; } = 10;

    // 第 2 段階
    public int UnusualParent { get; init; } = 30;
    public int ModuleInSignedProcess { get; init; } = 10;

    /// <summary>
    /// DLL としてだけ出てきたファイルの「署名が無い」。実行ファイルより低く数える。
    /// 署名済みの本体に未署名の DLL を同梱する製品は多く、同じ +30 だと 1 つの製品で数十件が「中」になる。
    /// </summary>
    public int SignatureNoneModule { get; init; } = 10;
    public int ModuleAcrossPublishers { get; init; } = 15;
    public int WritableExecutableMemory { get; init; } = 30;
    public int ExecutableMappedData { get; init; } = 30;

    /// <summary>発行元の違うプログラムが、この数以上その DLL を読み込んでいたら「広く入り込んでいる」とする。</summary>
    public int ModulePublisherThreshold { get; init; } = 3;

    public int RecentDays { get; init; } = 7;

    public int HighFrom { get; init; } = 60;
    public int MediumFrom { get; init; } = 30;
    public int LowFrom { get; init; } = 10;

    public RiskLevel LevelOf(int score) =>
        score >= HighFrom ? RiskLevel.High
        : score >= MediumFrom ? RiskLevel.Medium
        : score >= LowFrom ? RiskLevel.Low
        : RiskLevel.Info;
}

/// <summary>
/// 集めた事実を実行ファイルごとに 1 件にまとめ、兆候を付けて危険度を決める。
/// ここはファイルにもレジストリにも触らない（事実は引数でもらう）ので、規則だけを試せる。
/// </summary>
public sealed class Scorer
{
    private static readonly HashSet<string> SystemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "explorer.exe",
        "smss.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe",
        "rundll32.exe", "dwm.exe", "ctfmon.exe", "sihost.exe", "RuntimeBroker.exe", "fontdrvhost.exe",
        "userinit.exe", "cmd.exe", "powershell.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    };

    private static readonly Regex DoubleExtension = new(
        @"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|bmp|mp3|mp4|avi|mov|zip|rar|7z|csv|html?)\.(exe|scr|com|pif|bat|cmd|vbs|js|lnk)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly ScoringRules _rules;
    private readonly string _systemRoot;
    private readonly string _systemTemp;
    private readonly string _nativeImages;

    public Scorer(ScoringRules rules, string systemRoot)
    {
        _rules = rules;
        _systemRoot = systemRoot.TrimEnd('\\') + '\\';
        _systemTemp = _systemRoot + @"Temp\";
        _nativeImages = _systemRoot + @"assembly\NativeImages_";
    }

    public List<Finding> Score(ScanFacts facts, Func<string, FileFacts> files, DateTime nowUtc, int scannerSession)
    {
        var findings = new Dictionary<string, Finding>(StringComparer.Ordinal);

        foreach (var entry in facts.Persistence)
        {
            var finding = entry.Command.TargetPath is { } target
                ? ForFile(findings, target)
                : ForCommand(findings, entry);
            finding.Persistence.Add(entry);
        }

        var byPid = new Dictionary<int, Finding>();
        foreach (var process in facts.Processes)
        {
            var finding = process.Path is { } path
                ? ForFile(findings, path)
                : ForName(findings, "proc:" + process.Name.ToLowerInvariant(), process.Name);
            finding.Processes.Add(process);
            byPid[process.Pid] = finding;
        }

        var processes = new Dictionary<int, ProcessFact>();
        foreach (var process in facts.Processes) processes[process.Pid] = process;

        // 署名済みのプロセスに載っている、署名の有効でない DLL を候補にする。
        // 本体が未署名のアプリは、DLL も未署名なのがふつうで、本体のほうがもう挙がっている
        foreach (var (pid, modules) in facts.Modules)
        {
            if (!byPid.TryGetValue(pid, out var host) || host.Path is null) continue;
            var hostSignature = files(host.Path).Signature;
            if (!hostSignature.IsValid) continue;
            var publisher = hostSignature.Status == SignatureStatus.ValidMicrosoft ? "Microsoft" : hostSignature.Publisher;

            foreach (var module in modules)
            {
                if (FileKey(module) == host.Key) continue;
                var file = files(module);
                if (file.Signature.Status is not (SignatureStatus.None or SignatureStatus.Invalid)) continue;
                // .NET Framework が、その PC の上で作る実行用の写し（NGEN）。署名の付けようがなく、
                // 管理者でなければ書けない場所にある。書き換えられる状態になっていたら挙げる
                if (!file.UserWritable && module.StartsWith(_nativeImages, StringComparison.OrdinalIgnoreCase)) continue;
                ForFile(findings, module).LoadedBy.Add(new ModuleHost(pid, processes[pid].Name, publisher));
            }
        }

        foreach (var endpoint in facts.Endpoints)
        {
            if (!byPid.TryGetValue(endpoint.Pid, out var finding))
            {
                finding = endpoint.Pid is 0 or 4
                    ? ForName(findings, "proc:system", "System（カーネル）")
                    : ForName(findings, $"pid:{endpoint.Pid}", $"PID {endpoint.Pid}（終了済み）");
            }
            finding.Endpoints.Add(endpoint);
        }

        foreach (var finding in findings.Values)
        {
            if (finding.Path is not null) AddFileIndicators(finding, files(finding.Path), nowUtc);
            AddPersistenceIndicators(finding);
            AddProcessIndicators(finding, scannerSession);
            AddParentIndicators(finding, processes);
            AddModuleIndicators(finding);
            AddMemoryIndicators(finding, facts);
            AddNetworkIndicators(finding);

            finding.Score = finding.Indicators.Sum(i => i.Points);
            finding.Level = _rules.LevelOf(finding.Score);
        }

        return findings.Values
            .OrderByDescending(f => f.Score)
            .ThenBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    // ---- まとめる単位 ----

    public static string FileKey(string path) => "file:" + NormalizePath(path).ToLowerInvariant();

    private static string NormalizePath(string path)
    {
        try { return Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return path;
        }
    }

    private static Finding ForFile(Dictionary<string, Finding> findings, string path)
    {
        var full = NormalizePath(path);
        var key = "file:" + full.ToLowerInvariant();
        if (!findings.TryGetValue(key, out var finding))
        {
            var name = full[(full.LastIndexOfAny(new[] { '\\', '/' }) + 1)..];
            finding = new Finding { Key = key, Name = name.Length == 0 ? full : name, Path = full };
            findings[key] = finding;
        }
        return finding;
    }

    /// <summary>ファイルにたどり着かない登録（その場に書かれた命令、解決できなかったもの）。</summary>
    private static Finding ForCommand(Dictionary<string, Finding> findings, PersistenceEntry entry)
    {
        var key = $"cmd:{entry.Location}|{entry.Name}".ToLowerInvariant();
        if (!findings.TryGetValue(key, out var finding))
        {
            finding = new Finding
            {
                Key = key,
                Name = entry.Name,
                // 許可リストはパスとハッシュの組で持つ。ファイルが無いので、命令の文字列のハッシュで代える
                Sha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(entry.Command.Raw))),
            };
            findings[key] = finding;
        }
        return finding;
    }

    private static Finding ForName(Dictionary<string, Finding> findings, string key, string name)
    {
        if (!findings.TryGetValue(key, out var finding))
        {
            finding = new Finding { Key = key, Name = name };
            findings[key] = finding;
        }
        return finding;
    }

    // ---- 兆候 ----

    private void AddFileIndicators(Finding finding, FileFacts file, DateTime nowUtc)
    {
        var path = finding.Path!;
        finding.Sha256 = file.Sha256;
        finding.Signature = file.Signature;
        finding.FileCreatedUtc = file.CreatedUtc;

        if (!file.Exists)
        {
            if (finding.Persistence.Count > 0)
                Add(finding, IndicatorKind.MissingFile, 0, "ファイル無し", "登録は残っているが、ファイルが無い");
            else
                Add(finding, IndicatorKind.MissingFile, 0, "ファイル無し", "動いているが、実行ファイルがもう無い（または読めない）");
            return;
        }

        var isScript = CommandLineResolver.ImplicitScriptHost(path) is not null;
        switch (file.Signature.Status)
        {
            case SignatureStatus.Invalid:
                Add(finding, IndicatorKind.SignatureInvalid, _rules.SignatureInvalid, "署名無効",
                    $"署名はあるが検証に失敗した: {file.Signature.Detail ?? "理由不明"}");
                break;
            case SignatureStatus.None when !isScript:
                // スクリプトはふつう署名を持たない。スクリプトであること自体は「スクリプト経由」で数える
                var moduleOnly = finding.LoadedBy.Count > 0 && finding.Persistence.Count == 0 && finding.Processes.Count == 0;
                if (moduleOnly)
                    Add(finding, IndicatorKind.SignatureNone, _rules.SignatureNoneModule, "未署名",
                        "署名が無い（DLL としてだけ出てきたので、実行ファイルより低く数えている）");
                else
                    Add(finding, IndicatorKind.SignatureNone, _rules.SignatureNone, "未署名", "署名が無い");
                break;
        }

        if (SystemProcessNames.Contains(finding.Name) && !IsUnderSystemRoot(path))
            Add(finding, IndicatorKind.SystemNameWrongLocation, _rules.SystemNameWrongLocation, "偽装名",
                $"システムのプロセス名「{finding.Name}」を名乗っているが、置き場所が Windows のフォルダーではない");

        if (file.UserWritable)
            Add(finding, IndicatorKind.UserWritableLocation, _rules.UserWritableLocation, "書込可",
                $"管理者でなくても書き換えられる場所にある: {Path.GetDirectoryName(path)}");

        if (file.Hidden)
            Add(finding, IndicatorKind.HiddenOrDoubleExtension, _rules.HiddenOrDoubleExtension, "隠し",
                "隠し属性が付いている");
        else if (DoubleExtension.IsMatch(finding.Name))
            Add(finding, IndicatorKind.HiddenOrDoubleExtension, _rules.HiddenOrDoubleExtension, "二重拡張子",
                "拡張子が二重になっている（文書に見せかけた実行ファイルの形）");

        // 署名が有効なファイルは数えない。Windows Update や各アプリの更新のたびに、
        // 正規のファイルが数百件まとめて「新しい」になり、ほかの兆候が埋もれるため
        if (!file.Signature.IsValid
            && file.CreatedUtc is { } created && created <= nowUtc && nowUtc - created <= TimeSpan.FromDays(_rules.RecentDays))
            Add(finding, IndicatorKind.RecentlyCreated, _rules.RecentlyCreated, "新しい",
                $"ファイルの作成日時が {_rules.RecentDays} 日以内（{created.ToLocalTime():yyyy-MM-dd HH:mm}）");
    }

    private void AddPersistenceIndicators(Finding finding)
    {
        // ファイルが無い登録は何も起動できない。点は付けず、情報として挙げるだけにする
        if (finding.Indicators.Any(i => i.Kind == IndicatorKind.MissingFile)) return;

        var active = finding.Persistence.Where(e => e.AutoStarts).ToList();

        if (active.Count > 0)
            Add(finding, IndicatorKind.Autostart, _rules.Autostart, "常駐",
                "自動起動に登録されている: " + Summarize(active.Select(Describe)));

        var unusual = active.Where(e => e.IsUnusual).ToList();
        if (unusual.Count > 0)
            Add(finding, IndicatorKind.UnusualPersistence, _rules.UnusualPersistence, "特殊な常駐",
                "ふつうは使われない常駐箇所に登録されている: " + Summarize(unusual.Select(Describe)));

        // 対象のファイルまでたどれて、その署名が有効なら数えない
        // （Windows 自身のタスクにも rundll32 経由のものがあり、それを軒並み挙げても役に立たない）
        var targetIsScript = finding.Path is not null && CommandLineResolver.ImplicitScriptHost(finding.Path) is not null;
        var viaHost = active
            .Where(e => e.Command.ScriptHost is not null
                        && (!e.Command.HasFileTarget || !finding.Signature.IsValid))
            .ToList();
        if (viaHost.Count > 0)
        {
            var first = viaHost[0].Command;
            var how = first.Encoded ? "エンコードされた命令を実行する"
                : first.Inline ? "その場に書かれた命令（または外部の URL）を実行する"
                : targetIsScript ? "スクリプトを実行する"
                : "署名を確かめられないファイルを読み込む";
            Add(finding, IndicatorKind.ViaScriptHost, _rules.ViaScriptHost, "スクリプト経由",
                $"自動起動が {first.ScriptHost} を経由して{how}: {Shorten(first.Raw, 200)}");
        }

        foreach (var entry in finding.Persistence.Where(e => e.Command.UnresolvedReason is not null))
            Add(finding, IndicatorKind.Unresolved, 0, "解決できず",
                $"{Describe(entry)} の実行ファイルを解決できなかった（{entry.Command.UnresolvedReason}）: {Shorten(entry.Command.Raw, 200)}");
    }

    private void AddProcessIndicators(Finding finding, int scannerSession)
    {
        // セッション 0（サービス）のウィンドウは、こちらからは元々見えない。同じセッションのものだけを見る
        var sameSession = finding.Processes.Where(p => p.SessionId == scannerSession).ToList();
        if (sameSession.Count > 0 && !sameSession.Any(p => p.HasVisibleWindow))
            Add(finding, IndicatorKind.NoVisibleWindow, _rules.NoVisibleWindow, "窓なし",
                $"ウィンドウを表示しないまま動いている（PID {Summarize(sameSession.Select(p => p.Pid.ToString()))}）");
    }

    private void AddParentIndicators(Finding finding, IReadOnlyDictionary<int, ProcessFact> processes)
    {
        var anomalies = finding.Processes
            .Select(p => ParentRules.Check(p, processes))
            .Where(a => a is not null)
            .Select(a => a!)
            .ToList();
        if (anomalies.Count > 0)
            Add(finding, IndicatorKind.UnusualParent, _rules.UnusualParent, "親子異常",
                "親子関係が不自然: " + Summarize(anomalies));
    }

    private void AddModuleIndicators(Finding finding)
    {
        if (finding.LoadedBy.Count == 0) return;

        var hosts = finding.LoadedBy
            .GroupBy(h => h.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Select(g => $"{g.Key}（PID {Summarize(g.Select(h => h.Pid.ToString()), 2)}）");
        Add(finding, IndicatorKind.ModuleInSignedProcess, _rules.ModuleInSignedProcess, "読込",
            "署名済みのプロセスに読み込まれている: " + Summarize(hosts));

        var publishers = finding.LoadedBy
            .Select(h => h.Publisher ?? "（発行元不明）")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (publishers.Count >= _rules.ModulePublisherThreshold)
            Add(finding, IndicatorKind.ModuleAcrossPublishers, _rules.ModuleAcrossPublishers, "広く読込",
                $"発行元の違う {publishers.Count} 社のプログラムに読み込まれている（{Summarize(publishers)}）。"
                + "キーボード フックのように、ほかのプロセスへ入り込む DLL はこの形になる");
    }

    /// <summary>
    /// ファイルの裏付けが無い実行可能な領域（設計書 §11.3）。JIT を持つプロセスは正規に作るので見ない。
    /// JIT を持たないプロセスでも、書き込みのできない小さな領域（ウィンドウ処理の中継コードなど）は
    /// 正規に作られる。点を付けるのは、書き込みも実行もできる領域と、ファイルを写しただけなのに
    /// 実行できる領域。
    /// </summary>
    private void AddMemoryIndicators(Finding finding, ScanFacts facts)
    {
        var writable = new List<string>();
        var mapped = new List<string>();
        var readOnly = new List<string>();

        foreach (var process in finding.Processes)
        {
            if (!facts.ExecutableRegions.TryGetValue(process.Pid, out var regions)) continue;
            if (facts.JitEngines.ContainsKey(process.Pid)) continue;

            var privateWritable = regions.Where(r => r.Private && r.Writable).ToList();
            var privateReadOnly = regions.Where(r => r.Private && !r.Writable).ToList();
            var mappedRegions = regions.Where(r => !r.Private).ToList();

            if (privateWritable.Count > 0) writable.Add(DescribeRegions(process.Pid, privateWritable));
            if (privateReadOnly.Count > 0) readOnly.Add(DescribeRegions(process.Pid, privateReadOnly));
            if (mappedRegions.Count > 0)
                mapped.Add(DescribeRegions(process.Pid, mappedRegions) + "、写しているのは "
                           + Summarize(mappedRegions.Select(r => r.MappedFile ?? "ページ ファイル（名前の無い共有メモリ）").Distinct()));
        }

        if (writable.Count > 0)
            Add(finding, IndicatorKind.WritableExecutableMemory, _rules.WritableExecutableMemory, "書込実行メモリ",
                "ファイルの裏付けが無く、書き込みも実行もできる領域がある（実行時にコードを作る仕組みを持たないプロセス）: "
                + Summarize(writable));

        if (mapped.Count > 0)
            Add(finding, IndicatorKind.ExecutableMappedData, _rules.ExecutableMappedData, "写しを実行",
                "実行イメージではなく、ファイルを写しただけの領域が実行できるようになっている: " + Summarize(mapped));

        if (readOnly.Count > 0)
            Add(finding, IndicatorKind.ExecutableMemoryNote, 0, "実行領域",
                "ファイルの裏付けが無い実行可能な領域がある（書き込みはできない）: " + Summarize(readOnly)
                + "。ウィンドウ処理の中継コードなど、正規にも作られる");
    }

    private static string DescribeRegions(int pid, List<ExecutableRegion> regions) =>
        $"PID {pid} に {regions.Count} 個・計 {Math.Max(1, regions.Sum(r => r.Size) / 1024)} KB（0x{regions[0].Address:X} から）";

    private void AddNetworkIndicators(Finding finding)
    {
        var listening = finding.Endpoints
            .Where(e => e.Protocol == "TCP" && e.IsListening && !NetworkCollector.IsLoopback(e.LocalAddress))
            .ToList();
        if (listening.Count > 0)
            Add(finding, IndicatorKind.ListeningNonLoopback, _rules.ListeningNonLoopback, "待受",
                "ループバック以外でポートを待ち受けている: "
                + Summarize(listening.Select(e => FormatEndpoint(e.LocalAddress, e.LocalPort)).Distinct()));

        // 待ち受けているポートで受けた接続は、外向きではない
        var listeningPorts = finding.Endpoints.Where(e => e.IsListening).Select(e => e.LocalPort).ToHashSet();
        var outbound = finding.Endpoints
            .Where(e => e.Protocol == "TCP" && e.IsEstablished && e.RemoteAddress is not null
                        && !NetworkCollector.IsLoopback(e.RemoteAddress) && !listeningPorts.Contains(e.LocalPort))
            .ToList();
        if (outbound.Count > 0)
            Add(finding, IndicatorKind.OutboundConnection, _rules.OutboundConnection, "外向き",
                "外向きの接続を持っている: "
                + Summarize(outbound.Select(e => FormatEndpoint(e.RemoteAddress!, e.RemotePort)).Distinct()));
    }

    private bool IsUnderSystemRoot(string path) =>
        path.StartsWith(_systemRoot, StringComparison.OrdinalIgnoreCase)
        && !path.StartsWith(_systemTemp, StringComparison.OrdinalIgnoreCase);

    private static void Add(Finding finding, IndicatorKind kind, int points, string label, string evidence) =>
        finding.Indicators.Add(new Indicator(kind, points, label, evidence));

    private static string Describe(PersistenceEntry entry) =>
        $"{entry.KindDisplay}「{entry.Name}」（{entry.Location}）";

    private static string FormatEndpoint(string address, int port) =>
        address.Contains(':') ? $"[{address}]:{port}" : $"{address}:{port}";

    private static string Summarize(IEnumerable<string> items, int max = 3)
    {
        var list = items.ToList();
        return list.Count <= max
            ? string.Join("、", list)
            : string.Join("、", list.Take(max)) + $" ほか {list.Count - max} 件";
    }

    private static string Shorten(string text, int max) =>
        text.Length <= max ? text : text[..max] + "…";
}
