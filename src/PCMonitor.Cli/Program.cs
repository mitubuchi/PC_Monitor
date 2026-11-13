using System.Text;
using PCMonitor.Core;
using PCMonitor.Core.Model;
using PCMonitor.Core.Reports;
using PCMonitor.Core.Signing;

// 画面なしで点検を走らせる。検知の実測と、あとで足す定期実行のための入口。
//
//   pcmonitor [--min-level info|low|medium|high] [--verbose] [--find <文字列>]
//             [--json <パス>] [--csv <パス>] [--data-dir <フォルダー>] [--no-save]
//   pcmonitor --verify <ファイル>      署名の検証結果だけを表示する

Console.OutputEncoding = new UTF8Encoding(false);

string? Option(string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

bool Flag(string name) => args.Contains(name);

if (Flag("--help") || Flag("-h"))
{
    Console.WriteLine("pcmonitor [--min-level info|low|medium|high] [--verbose] [--find <文字列>]");
    Console.WriteLine("          [--json <パス>] [--csv <パス>] [--data-dir <フォルダー>] [--no-save]");
    Console.WriteLine("pcmonitor --verify <ファイル>");
    return 0;
}

if (Option("--verify") is { } verifyPath)
{
    var signature = new SignatureVerifier().Verify(verifyPath);
    Console.WriteLine($"{signature.Display}{(signature.FromCatalog ? "［カタログ署名］" : "")} {signature.Detail}");
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

var result = scanner.Scan(new Progress(), CancellationToken.None);

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
