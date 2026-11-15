using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using PCMonitor.Core.Collectors;
using PCMonitor.Core.Model;
using PCMonitor.Core.Remote;

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
    public int KeyInputCapture { get; init; } = 30;
    public int KeyStatePolling { get; init; } = 15;

    // 第 3 段階（設計書 §16.3）
    public int RemoteToolImpersonation { get; init; } = 40;
    public int RemoteToolRecentlyInstalled { get; init; } = 20;
    public int CaptureDeviceUnsigned { get; init; } = 30;

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

        // 見張っている間に呼ばれたキー入力の API。呼んだプロセスはもう終わっているかもしれないので、
        // 受け取ったときに確かめた実行ファイルで突き合わせる
        foreach (var call in facts.KeyApiCalls)
        {
            Finding caller;
            if (call.Path is { } callerPath)
                caller = ForFile(findings, callerPath);
            else if (byPid.TryGetValue(call.Pid, out var running)
                     && processes[call.Pid].StartedUtc is { } started && started <= call.TimeUtc)
                caller = running;
            else
                caller = ForName(findings, $"pid:{call.Pid}", $"PID {call.Pid}（終了済み）");
            caller.KeyApiCalls.Add(call);
        }

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

        AttachRemoteTools(findings, facts);

        // カメラ・マイクを使った、ふつうのアプリ。ストア アプリはストアの署名で配られるので候補にしない
        foreach (var usage in facts.DeviceUsages)
            if (usage.Path is { } usagePath) ForFile(findings, usagePath).DeviceUsages.Add(usage);

        foreach (var finding in findings.Values)
        {
            if (finding.Path is not null) AddFileIndicators(finding, files(finding.Path), nowUtc);
            AddRemoteToolIndicators(finding, nowUtc);
            AddDeviceIndicators(finding);
            AddPersistenceIndicators(finding);
            AddProcessIndicators(finding, scannerSession);
            AddParentIndicators(finding, processes);
            AddModuleIndicators(finding);
            AddMemoryIndicators(finding, facts);
            AddKeyApiIndicators(finding);
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

    /// <summary>
    /// 遠隔操作ソフトの照合表と突き合わせる（設計書 §16.2 A）。実行ファイル名で当てたうえで、
    /// インストールの記録（Uninstall キー）を同じ製品の候補にまとめる。動いていない・常駐していない
    /// 遠隔操作ソフトも、インストールの記録から 1 件として出す（点が 0 でも一覧に載る）。
    /// </summary>
    private static void AttachRemoteTools(Dictionary<string, Finding> findings, ScanFacts facts)
    {
        foreach (var finding in findings.Values)
        {
            if (RemoteToolCatalog.MatchFileName(finding.Name) is { } entry)
                finding.RemoteTool = new RemoteToolMatch(entry.Product, "実行ファイル名", entry.Signers, entry.SignersVerified);
        }

        foreach (var program in facts.InstalledPrograms)
        {
            var byExe = program.ExecutablePath is { } exe ? RemoteToolCatalog.MatchFileName(Path.GetFileName(exe)) : null;
            var entry = RemoteToolCatalog.MatchInstalled(program.DisplayName) ?? byExe;
            if (entry is null) continue;

            // アイコンが同じ製品の EXE を指していれば、その実行ファイルの候補にまとめる。
            // そうでなければ、すでに挙がっている同じ製品の候補に、それも無ければ製品名の候補にまとめる
            Finding target;
            if (byExe == entry)
            {
                target = ForFile(findings, program.ExecutablePath!);
                target.RemoteTool ??= new RemoteToolMatch(entry.Product, "実行ファイル名", entry.Signers, entry.SignersVerified);
            }
            else
            {
                target = findings.Values.FirstOrDefault(f => f.RemoteTool?.Product == entry.Product)
                         ?? ForName(findings, "remote:" + entry.Product.ToLowerInvariant(), entry.Product);
                target.RemoteTool ??= new RemoteToolMatch(entry.Product, "インストールの記録", entry.Signers, entry.SignersVerified);
            }
            target.Installations.Add(program);
        }
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
            else if (finding.Processes.Count > 0)
                Add(finding, IndicatorKind.MissingFile, 0, "ファイル無し", "動いているが、実行ファイルがもう無い（または読めない）");
            else
                Add(finding, IndicatorKind.MissingFile, 0, "ファイル無し", "記録に残っているが、ファイルがもう無い（または読めない）");
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

    /// <summary>
    /// 遠隔操作ソフトの兆候（設計書 §16.3）。入っていること自体は異常ではないので、照合に当たっただけでは
    /// 点を付けない。常駐・通信・書き込める場所は、既存の兆候をそのまま使い、ここでは重ねない。
    /// </summary>
    private void AddRemoteToolIndicators(Finding finding, DateTime nowUtc)
    {
        if (finding.RemoteTool is not { } tool) return;

        var state = new List<string>();
        if (finding.Processes.Count > 0) state.Add("動作中");
        if (finding.Persistence.Any(e => e.AutoStarts)) state.Add("自動起動");
        if (finding.Installations.Count > 0) state.Add("インストール済み");
        Add(finding, IndicatorKind.RemoteTool, 0, "遠隔",
            $"遠隔操作ソフト「{tool.Product}」（{tool.MatchedBy}で照合、{(state.Count == 0 ? "状態不明" : string.Join("・", state))}）。"
            + "入っていること自体は異常ではない。入れた覚えがあるか、いま使っているかを確かめる");

        // なりすまし。名前で当てたもので、ファイルの署名を確かめられたときだけ見る
        var signature = finding.Signature;
        var entry = RemoteToolCatalog.Entries.First(e => e.Product == tool.Product);
        if (finding.Path is not null && signature.Status != SignatureStatus.Unknown && !RemoteToolCatalog.SignerMatches(entry, signature))
        {
            var expected = string.Join("・", tool.ExpectedSigners);
            if (!signature.IsValid)
                Add(finding, IndicatorKind.RemoteToolImpersonation, _rules.RemoteToolImpersonation, "なりすまし",
                    $"名前は遠隔操作ソフト「{tool.Product}」だが、署名が{(signature.Status == SignatureStatus.None ? "無い" : "有効でない")}"
                    + $"（本物は「{expected}」の署名付きの見込み）");
            else if (tool.SignersVerified)
                Add(finding, IndicatorKind.RemoteToolImpersonation, _rules.RemoteToolImpersonation, "なりすまし",
                    $"名前は遠隔操作ソフト「{tool.Product}」だが、署名者「{signature.Publisher}」が照合表（{expected}）と違う");
            else
                Add(finding, IndicatorKind.RemoteToolSignerUnverified, 0, "署名者違い",
                    $"署名者「{signature.Publisher}」が、照合表の候補（{expected}）と違う。照合表の署名者は配布物で確かめていないので、点は付けない");
        }

        // 入れたばかり。電話で入れさせた直後の状態がこれに当たる。署名が有効でも数える
        var installed = finding.Installations.Select(i => i.InstallDate).Where(d => d is not null).Max();
        string? recent = null;
        if (IsRecent(installed, nowUtc))
            recent = $"遠隔操作ソフトが、インストールされて {_rules.RecentDays} 日以内（{installed!.Value.ToLocalTime():yyyy-MM-dd}）";
        else if (IsRecent(finding.FileCreatedUtc, nowUtc))
            recent = $"遠隔操作ソフトの実行ファイルが、作られて {_rules.RecentDays} 日以内（{finding.FileCreatedUtc!.Value.ToLocalTime():yyyy-MM-dd HH:mm}）。"
                     + "インストールせずに、ダウンロードしたものをそのまま動かしている形もこれに当たる";
        if (recent is not null)
        {
            // 未署名なら「新しい」+10 も付いている。同じ事実を二重に数えない
            finding.Indicators.RemoveAll(i => i.Kind == IndicatorKind.RecentlyCreated);
            Add(finding, IndicatorKind.RemoteToolRecentlyInstalled, _rules.RemoteToolRecentlyInstalled, "入れたばかり", recent);
        }
    }

    /// <summary>カメラ・マイクの使用（設計書 §16.2 E）。書き込める場所は、ファイルの兆候としてすでに付いている。</summary>
    private void AddDeviceIndicators(Finding finding)
    {
        if (finding.DeviceUsages.Count == 0) return;

        var uses = string.Join("、", finding.DeviceUsages
            .OrderByDescending(u => u.LastStartUtc)
            .Select(u => $"{u.DeviceDisplay}（{(u.InUse ? "いま使用中の見込み" : $"最後は {u.LastStartUtc!.Value.ToLocalTime():yyyy-MM-dd HH:mm}")}）"));
        Add(finding, IndicatorKind.CaptureDeviceUse, 0, "カメラ/マイク", $"使った記録がある: {uses}");

        // 署名を確かめられなかった（ファイルが無い）ものには付けない
        if (finding.Signature.Status is SignatureStatus.None or SignatureStatus.Invalid)
            Add(finding, IndicatorKind.CaptureDeviceUnsigned, _rules.CaptureDeviceUnsigned, "未署名で撮影・録音",
                $"署名が{(finding.Signature.Status == SignatureStatus.None ? "無い" : "有効でない")}プログラムが、"
                + string.Join("と", finding.DeviceUsages.Select(u => u.DeviceDisplay).Distinct()) + "を使った");
    }

    private bool IsRecent(DateTime? utc, DateTime nowUtc) =>
        utc is { } value && value <= nowUtc && nowUtc - value <= TimeSpan.FromDays(_rules.RecentDays);

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

    /// <summary>
    /// キー入力に関わる API の呼び出し（設計書 §11.5）。使った API の数だけ点を重ねることはしない。
    /// フックと生入力の両方を使う正規のソフトもあり、重ねるとそれだけで「高」になるため。
    /// </summary>
    private void AddKeyApiIndicators(Finding finding)
    {
        if (finding.KeyApiCalls.Count == 0) return;

        var capture = finding.KeyApiCalls.Where(c => c.Weight == Monitoring.KeyApiWeight.Capture).ToList();
        var polling = finding.KeyApiCalls.Where(c => c.Weight == Monitoring.KeyApiWeight.Polling).ToList();
        var notes = finding.KeyApiCalls.Where(c => c.Weight == Monitoring.KeyApiWeight.Note).ToList();

        if (capture.Count > 0)
            Add(finding, IndicatorKind.KeyInputCapture, _rules.KeyInputCapture, "キー入力API",
                "見張っている間に、ほかのアプリへのキー入力まで受け取れる形の API を呼んだ: "
                + Summarize(DescribeCalls(capture.Concat(polling))));
        else if (polling.Count > 0)
            Add(finding, IndicatorKind.KeyStatePolling, _rules.KeyStatePolling, "キー状態",
                "見張っている間に、キーの状態を横から問い合わせた: " + Summarize(DescribeCalls(polling)));

        if (notes.Count > 0)
            Add(finding, IndicatorKind.KeyApiNote, 0, "キー入力API(自分用)",
                "見張っている間に、自分に向けたキー入力の API を呼んだ（正規のアプリもふつうに行う）: "
                + Summarize(DescribeCalls(notes)));
    }

    private static IEnumerable<string> DescribeCalls(IEnumerable<Monitoring.KeyApiCall> calls) =>
        calls.GroupBy(c => c.Description)
            .Select(g => $"{g.Key}（{g.Count()} 回、{g.Min(c => c.TimeUtc).ToLocalTime():HH:mm:ss} から、PID {Summarize(g.Select(c => c.Pid.ToString()).Distinct(), 2)}）");

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
