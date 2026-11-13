using System.Text;
using PCMonitor.Core;
using PCMonitor.Core.Collectors;
using PCMonitor.Core.Model;
using PCMonitor.Core.Monitoring;
using PCMonitor.Core.Reports;
using PCMonitor.Core.Signing;

// 画面なしで点検を走らせる。検知の実測と、あとで足す定期実行のための入口。
//
//   pcmonitor-cli [--min-level info|low|medium|high] [--verbose] [--find <文字列>]
//             [--json <パス>] [--csv <パス>] [--data-dir <フォルダー>] [--no-save]
//   pcmonitor-cli --verify <ファイル>      署名の検証結果だけを表示する

Console.OutputEncoding = new UTF8Encoding(false);

string? Option(string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

bool Flag(string name) => args.Contains(name);

if (Flag("--help") || Flag("-h"))
{
    Console.WriteLine("pcmonitor-cli [--min-level info|low|medium|high] [--verbose] [--find <文字列>]");
    Console.WriteLine("          [--json <パス>] [--csv <パス>] [--data-dir <フォルダー>] [--no-save]");
    Console.WriteLine("pcmonitor-cli --verify <ファイル>");
    return 0;
}

if (Option("--verify") is { } verifyPath)
{
    var signature = new SignatureVerifier().Verify(verifyPath);
    Console.WriteLine($"{signature.Display}{(signature.FromCatalog ? "［カタログ署名］" : "")} {signature.Detail}");
    return 0;
}

if (Flag("--check-env"))
{
    // この PC の条件と、使えない機能を並べる（別の PC で使い始めるときの確認用）
    var machine = MachineInfo.Detect();
    Console.WriteLine("この PC: " + machine.Describe());
    var (supported, reason) = KeyApiMonitor.CheckSupport();
    Console.WriteLine("キー入力 API の監視: " + (supported
        ? (machine.Elevated ? "使える" : "この Windows では使えるが、管理者として起動する必要がある")
        : "使えない（" + reason + "）"));
    foreach (var caveat in machine.Caveats().Where(c => c.Area != "キー入力 API の監視"))
        Console.WriteLine($"※ {caveat.Area}: {caveat.Message}");
    return 0;
}

if (Option("--read-etl") is { } etlPath && Flag("--list"))
{
    // 記録済みの .etl から、キー入力 API の呼び出しを読んで並べる（読み取りの確認用）
    foreach (var call in KeyApiMonitor.ReadFile(etlPath))
        Console.WriteLine($"{call.TimeUtc.ToLocalTime():HH:mm:ss.fff}  PID {call.Pid}  [{call.Weight}]  {call.Description}\n      {call.Path ?? "（実行ファイル不明）"}");
    return 0;
}

if (Flag("--memory-map"))
{
    // 採点の調整用。実行できるのに実行イメージではない領域を、プロセスごとに並べる
    var facts = new ScanFacts();
    new ProcessCollector().Collect(facts, CancellationToken.None);
    new MemoryMapCollector().Collect(facts, CancellationToken.None);
    Console.WriteLine($"プロセス {facts.Processes.Count} 個のうち、割り当てを見られたのは {facts.Modules.Count} 個。"
                      + $"該当する領域があるのは {facts.ExecutableRegions.Count} 個。");
    Console.WriteLine("PID\t名前\t私有(個)\t私有(KB)\t書込可(個)\t写し(個)\t写しのファイル\tJIT の手がかり");
    foreach (var process in facts.Processes.Where(p => facts.ExecutableRegions.ContainsKey(p.Pid)).OrderBy(p => p.Name))
    {
        var regions = facts.ExecutableRegions[process.Pid];
        var privateRegions = regions.Where(r => r.Private).ToList();
        var mapped = regions.Where(r => !r.Private).ToList();
        var jit = JitEngines.Find(process.Path, facts.Modules.GetValueOrDefault(process.Pid) ?? new List<string>());
        Console.WriteLine(string.Join('\t',
            process.Pid, process.Name,
            privateRegions.Select(r => r.AllocationBase).Distinct().Count(),
            privateRegions.Sum(r => r.Size) / 1024,
            privateRegions.Count(r => r.Writable),
            mapped.Count,
            string.Join(",", mapped.Select(r => Path.GetFileName(r.MappedFile ?? "(ページ ファイル)")).Distinct()),
            jit ?? "—"));
    }
    return 0;
}

var minLevel = (Option("--min-level") ?? "low").ToLowerInvariant() switch
{
    "info" => RiskLevel.Info,
    "medium" => RiskLevel.Medium,
    "high" => RiskLevel.High,
    _ => RiskLevel.Low,
};
var verbose = Flag("--verbose");
var find = Option("--find");

var scanner = new Scanner(new ScanOptions
{
    DataDirectory = Option("--data-dir"),
    SaveAsLast = !Flag("--no-save"),
});

// キー入力 API の監視（設計書 §11.5）
//   --monitor-keys <秒>   その秒数だけ見張ってから点検する（管理者のみ）
//   --read-etl <パス>     記録済みの .etl から読んだ呼び出しを、見張りの結果として点検に渡す
KeyApiObservation? keyApi = null;
if (int.TryParse(Option("--monitor-keys"), out var monitorSeconds) && monitorSeconds > 0)
{
    using var monitor = new KeyApiMonitor();
    try
    {
        monitor.Start();
    }
    catch (UnauthorizedAccessException ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 2;
    }
    Console.Error.WriteLine($"キー入力 API を {monitorSeconds} 秒見張ります…");
    Thread.Sleep(TimeSpan.FromSeconds(monitorSeconds));
    monitor.Stop();
    keyApi = monitor.Observation();
}
else if (Option("--read-etl") is { } replayPath)
{
    var calls = KeyApiMonitor.ReadFile(replayPath);
    if (calls.Count > 0)
        keyApi = new KeyApiObservation(calls.Min(c => c.TimeUtc), calls.Max(c => c.TimeUtc), calls);
}

var result = scanner.Scan(new Progress(), CancellationToken.None, keyApi);

Console.WriteLine();
Console.WriteLine($"点検 {result.StartedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  所要 {result.Elapsed.TotalSeconds:F1} 秒  "
                  + $"権限: {(result.Elevated ? "管理者" : "通常")}");
Console.WriteLine("件数: " + string.Join("  ", new[] { RiskLevel.High, RiskLevel.Medium, RiskLevel.Low, RiskLevel.Info }
    .Select(level => $"{Label(level)} {result.Findings.Count(f => f.Level == level && !f.IsAllowed)}"))
    + $"  許可済み {result.Findings.Count(f => f.IsAllowed)}"
    + (result.HasPrevious ? $"  新規 {result.Findings.Count(f => f.IsNew)}" : "  （前回の結果なし）"));
Console.WriteLine();

foreach (var finding in result.Findings)
{
    var matched = find is not null
        && (finding.Name.Contains(find, StringComparison.OrdinalIgnoreCase)
            || (finding.Path?.Contains(find, StringComparison.OrdinalIgnoreCase) ?? false));
    if (find is not null ? !matched : (finding.Level < minLevel || finding.IsAllowed)) continue;

    Console.WriteLine($"[{finding.LevelDisplay} {finding.Score,3}] {finding.Name}  署名: {finding.Signature.Display}"
                      + $"  {finding.IndicatorSummary}{(finding.IsNew ? "  ★新規" : "")}{(finding.IsAllowed ? "  （許可済み）" : "")}");
    if (!verbose && !matched) continue;

    if (finding.Path is not null) Console.WriteLine($"      パス: {finding.Path}");
    if (finding.Sha256 is not null) Console.WriteLine($"      SHA-256: {finding.Sha256}");
    foreach (var indicator in finding.Indicators)
        Console.WriteLine($"      ・{(indicator.Points > 0 ? $"+{indicator.Points} " : "")}{indicator.Evidence}");
}

if (keyApi is not null)
{
    // 見張っている間に拾った呼び出しを、候補になったかどうかにかかわらず、すべて並べる
    Console.WriteLine();
    Console.WriteLine($"--- 見張っている間に拾った、キー入力に関わる API の呼び出し（{keyApi.Calls.Count} 件）");
    foreach (var group in keyApi.Calls.GroupBy(c => (c.Path, c.Pid, c.Weight, c.Description)))
    {
        var first = group.Min(c => c.TimeUtc).ToLocalTime();
        Console.WriteLine($"  {first:HH:mm:ss.fff}  x{group.Count()}  [{group.Key.Weight}]  PID {group.Key.Pid}  {group.Key.Path ?? "（実行ファイル不明）"}");
        Console.WriteLine($"      {group.Key.Description}");
    }
}

Console.WriteLine();
foreach (var note in result.Notes)
    Console.WriteLine($"※ {note.Area}: {note.Message}");
Console.WriteLine("※ 「何も出なかった」は「安全」を意味しない。");

if (Option("--json") is { } jsonPath) ReportWriter.WriteJson(jsonPath, result);
if (Option("--csv") is { } csvPath) ReportWriter.WriteCsv(csvPath, result.Findings);
return 0;

static string Label(RiskLevel level) => level switch
{
    RiskLevel.High => "高",
    RiskLevel.Medium => "中",
    RiskLevel.Low => "低",
    _ => "情報",
};

// Progress<T> は呼び出し元のコンテキストへ戻そうとする。コンソールではその場で書けば足りる
internal sealed class Progress : IProgress<string>
{
    public void Report(string value) => Console.Error.WriteLine(value);
}
