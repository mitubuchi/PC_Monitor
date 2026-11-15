using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Principal;
using PCMonitor.Core.Allowlist;
using PCMonitor.Core.Collectors;
using PCMonitor.Core.Model;
using PCMonitor.Core.Monitoring;
using PCMonitor.Core.Remote;
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
    /// <param name="keyApi">キー入力 API を見張っていたなら、その結果。見張っていなければ null。</param>
    public ScanResult Scan(IProgress<string>? progress = null, CancellationToken cancel = default, KeyApiObservation? keyApi = null)
    {
        var started = DateTime.UtcNow;
        var watch = Stopwatch.StartNew();
        var elevated = IsElevated();
        var probe = new SystemPathProbe();
        var facts = new ScanFacts();
        var machine = MachineInfo.Detect();
        var session = ProcessCollector.CurrentSessionId();

        progress?.Report("常駐箇所を点検中…");
        new PersistenceCollector(probe).Collect(facts, cancel);

        progress?.Report("プロセスを点検中…");
        RunCollector(facts, "プロセス", () => new ProcessCollector().Collect(facts, cancel));

        progress?.Report("通信を点検中…");
        RunCollector(facts, "通信", () => new NetworkCollector().Collect(facts, cancel));

        progress?.Report("読み込まれている DLL とメモリの割り当てを点検中…");
        RunCollector(facts, "読み込み DLL とメモリ", () => new MemoryMapCollector().Collect(facts, cancel));

        // 第 3 段階（設計書 §16）。標準の遠隔機能はプロセスの一覧を使う（クイック アシストが動いているか）
        progress?.Report("遠隔操作の手段を点検中…");
        RunCollector(facts, "インストール済みのプログラム", () => new InstalledProgramCollector().Collect(facts, cancel));
        var remote = new RemoteAccessCollector();
        RunCollector(facts, "標準の遠隔機能", () => remote.CollectFeatures(facts, machine.IsHomeEdition, cancel));
        RunCollector(facts, "セッション", () => remote.CollectSessions(facts, cancel));
        RunCollector(facts, "遠隔接続の履歴", () => new RemoteHistoryCollector().Collect(facts, elevated, cancel));
        RunCollector(facts, "カメラ・マイク", () => new CaptureDeviceCollector().Collect(facts, cancel));

        if (keyApi is not null)
        {
            facts.KeyApiCalls.AddRange(keyApi.Calls);
            facts.Notes.Add(new ScanNote("キー入力 API の監視", keyApi.Describe()));
        }
        else
        {
            facts.Notes.Add(new ScanNote("キー入力 API の監視",
                "見張っていない。フックの設置やキーボードの生入力の登録は、管理者として起動して見張りを始めた間のものしか分からない",
                NeedsAdmin: !elevated));
        }

        var inspector = new FileInspector(new CachingSignatureVerifier(new SignatureVerifier()));
        var files = InspectFiles(facts, inspector, progress, cancel);
        InspectModules(facts, files, inspector, progress, cancel);

        progress?.Report("採点中…");
        var scorer = new Scorer(_options.Rules, probe.SystemRoot);
        var findings = scorer.Score(
            facts,
            path => files.TryGetValue(Scorer.FileKey(path), out var file) ? file : FileFacts.Missing(path),
            DateTime.UtcNow,
            session);

        new AllowlistStore(_paths.Allowlist).Apply(findings);
        // 許可リストを当てたあとに作る。許可済みかどうかを帯にも書くため
        var currentState = CurrentStateBuilder.Build(facts, findings, session);

        var hasPrevious = ScanDiff.MarkNew(findings, JsonFiles.Read<LastScan>(_paths.LastScan));
        cancel.ThrowIfCancellationRequested();
        if (_options.SaveAsLast)
        {
            try
            {
                JsonFiles.Write(_paths.LastScan, ScanDiff.Snapshot(started, findings) with { Elevated = elevated, KeyApi = keyApi });
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                facts.Notes.Add(new ScanNote("保存", $"前回の結果として保存できなかった: {ex.Message}"));
            }
        }

        if (!elevated)
            facts.Notes.Insert(0, new ScanNote("権限",
                "通常の権限で点検した。ほかの利用者とシステムのプロセス、一部のタスク、WMI イベント購読は管理者でないと見られない", true));

        // この PC の条件と、ここでは使えない機能・確かめていない条件を先頭に出す
        var caveats = machine.Caveats().ToList();
        facts.Notes.InsertRange(0, caveats);
        facts.Notes.Insert(0, new ScanNote("この PC", machine.Describe()));

        progress?.Report("完了");
        return new ScanResult
        {
            StartedUtc = started,
            Elapsed = watch.Elapsed,
            Elevated = elevated,
            Findings = findings,
            Notes = facts.Notes,
            HasPrevious = hasPrevious,
            Machine = machine,
            CurrentState = currentState,
            RemoteLogons = facts.RemoteLogons,
            DeviceUsages = facts.DeviceUsages,
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
            .Concat(facts.KeyApiCalls.Select(c => c.Path))
            // インストール済みのプログラムは、遠隔操作ソフトの EXE を指しているものだけ確かめる（全部だと遅い）
            .Concat(facts.DeviceUsages.Select(u => u.Path))
            .Concat(facts.InstalledPrograms.Select(p => p.ExecutablePath)
                .Where(exe => exe is not null && RemoteToolCatalog.MatchFileName(Path.GetFileName(exe)) is not null))
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
