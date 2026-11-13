using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Principal;
using PCMonitor.Core.Allowlist;
using PCMonitor.Core.Collectors;
using PCMonitor.Core.Model;
using PCMonitor.Core.Reports;
using PCMonitor.Core.Scoring;
using PCMonitor.Core.Signing;

namespace PCMonitor.Core;

public sealed class ScanOptions
{
    /// <summary>保存先。null なら %LOCALAPPDATA%\PCMonitor。</summary>
    public string? DataDirectory { get; init; }

    /// <summary>結果を「前回の結果」として保存するか。</summary>
    public bool SaveAsLast { get; init; } = true;

    public ScoringRules Rules { get; init; } = new();
}

/// <summary>1 回の点検。集める → ファイルを確かめる → 採点 → 許可リスト → 前回との差分。</summary>
public sealed class Scanner
{
    private readonly ScanOptions _options;
    private readonly DataPaths _paths;

    public Scanner(ScanOptions? options = null)
    {
        _options = options ?? new ScanOptions();
        _paths = new DataPaths(_options.DataDirectory);
    }

    public DataPaths Paths => _paths;

    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>途中で止められたら <see cref="OperationCanceledException"/> を投げる。</summary>
    public ScanResult Scan(IProgress<string>? progress = null, CancellationToken cancel = default)
    {
        var started = DateTime.UtcNow;
        var watch = Stopwatch.StartNew();
        var elevated = IsElevated();
        var probe = new SystemPathProbe();
        var facts = new ScanFacts();

        progress?.Report("常駐箇所を点検中…");
        new PersistenceCollector(probe).Collect(facts, cancel);

        progress?.Report("プロセスを点検中…");
        RunCollector(facts, "プロセス", () => new ProcessCollector().Collect(facts, cancel));

        progress?.Report("通信を点検中…");
        RunCollector(facts, "通信", () => new NetworkCollector().Collect(facts, cancel));

        progress?.Report("読み込まれている DLL とメモリの割り当てを点検中…");
        RunCollector(facts, "読み込み DLL とメモリ", () => new MemoryMapCollector().Collect(facts, cancel));

        var inspector = new FileInspector(new CachingSignatureVerifier(new SignatureVerifier()));
        var files = InspectFiles(facts, inspector, progress, cancel);
        InspectModules(facts, files, inspector, progress, cancel);

        progress?.Report("採点中…");
        var scorer = new Scorer(_options.Rules, probe.SystemRoot);
        var findings = scorer.Score(
            facts,
            path => files.TryGetValue(Scorer.FileKey(path), out var file) ? file : FileFacts.Missing(path),
            DateTime.UtcNow,
            ProcessCollector.CurrentSessionId());

        new AllowlistStore(_paths.Allowlist).Apply(findings);

        var hasPrevious = ScanDiff.MarkNew(findings, JsonFiles.Read<LastScan>(_paths.LastScan));
        cancel.ThrowIfCancellationRequested();
        if (_options.SaveAsLast)
        {
            try
            {
                JsonFiles.Write(_paths.LastScan, ScanDiff.Snapshot(started, findings));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                facts.Notes.Add(new ScanNote("保存", $"前回の結果として保存できなかった: {ex.Message}"));
            }
        }

        if (!elevated)
            facts.Notes.Insert(0, new ScanNote("権限",
                "通常の権限で点検した。ほかの利用者とシステムのプロセス、一部のタスク、WMI イベント購読は管理者でないと見られない", true));

        progress?.Report("完了");
        return new ScanResult
        {
            StartedUtc = started,
            Elapsed = watch.Elapsed,
            Elevated = elevated,
            Findings = findings,
            Notes = facts.Notes,
            HasPrevious = hasPrevious,
        };
    }

    private static void RunCollector(ScanFacts facts, string area, Action collect)
    {
        try
        {
            collect();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            facts.Notes.Add(new ScanNote(area, $"点検できなかった: {ex.Message}"));
        }
    }

    /// <summary>出てきたファイルを 1 つずつ確かめる（ハッシュと署名）。いちばん時間がかかるので並べて走らせる。</summary>
    private static Dictionary<string, FileFacts> InspectFiles(ScanFacts facts, FileInspector inspector, IProgress<string>? progress, CancellationToken cancel)
    {
        var paths = facts.Persistence.Select(e => e.Command.TargetPath)
            .Concat(facts.Processes.Select(p => p.Path))
            .Where(p => p is not null)
            .Select(p => p!)
            .GroupBy(Scorer.FileKey, StringComparer.Ordinal)
            .Select(g => (Key: g.Key, Path: g.First()))
            .ToList();

        var results = new ConcurrentDictionary<string, FileFacts>(StringComparer.Ordinal);
        var done = 0;

        Parallel.ForEach(paths, Parallelism(cancel), item =>
        {
            results[item.Key] = inspector.Inspect(item.Path);
            var count = Interlocked.Increment(ref done);
            if (count % 25 == 0 || count == paths.Count)
                progress?.Report($"ファイルを点検中…（{count} / {paths.Count}）");
        });

        return new Dictionary<string, FileFacts>(results, StringComparer.Ordinal);
    }

    /// <summary>
    /// 読み込まれている DLL の署名を確かめる。署名が有効でなかったものだけ、
    /// ハッシュや書き込めるかどうかまで調べる（候補になりうるのはそれだけなので）。
    /// </summary>
    private static void InspectModules(ScanFacts facts, Dictionary<string, FileFacts> files, FileInspector inspector,
        IProgress<string>? progress, CancellationToken cancel)
    {
        var paths = facts.Modules.Values.SelectMany(m => m)
            .GroupBy(Scorer.FileKey, StringComparer.Ordinal)
            .Where(g => !files.ContainsKey(g.Key))
            .Select(g => (Key: g.Key, Path: g.First()))
            .ToList();

        var results = new ConcurrentDictionary<string, FileFacts>(StringComparer.Ordinal);
        var done = 0;

        Parallel.ForEach(paths, Parallelism(cancel), item =>
        {
            var signature = inspector.VerifySignature(item.Path);
            results[item.Key] = signature.Status is SignatureStatus.None or SignatureStatus.Invalid
                ? inspector.Inspect(item.Path)
                : new FileFacts(item.Path, signature.Status != SignatureStatus.Unknown, null, false, null, signature, false);
            var count = Interlocked.Increment(ref done);
            if (count % 100 == 0 || count == paths.Count)
                progress?.Report($"読み込まれている DLL の署名を点検中…（{count} / {paths.Count}）");
        });

        foreach (var (key, file) in results) files[key] = file;
    }

    private static ParallelOptions Parallelism(CancellationToken cancel) => new()
    {
        CancellationToken = cancel,
        MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount / 2, 1, 6),
    };
}
