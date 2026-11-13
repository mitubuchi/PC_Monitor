using PCMonitor.Core.Allowlist;
using PCMonitor.Core.Model;
using PCMonitor.Core.Monitoring;
using PCMonitor.Core.Reports;
using PCMonitor.Core.Scoring;

namespace PCMonitor.Core.Tests;

public class ScorerTests
{
    private const int Session = 1;
    private static readonly DateTime Now = new(2026, 11, 13, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime Old = Now.AddYears(-1);

    private static readonly SignatureInfo Microsoft = new(SignatureStatus.ValidMicrosoft, "Microsoft Windows");
    private static readonly SignatureInfo Vendor = new(SignatureStatus.ValidOther, "Example Inc.");
    private static readonly SignatureInfo Unsigned = new(SignatureStatus.None);

    private readonly Dictionary<string, FileFacts> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly ScanFacts _facts = new();

    private void File(string path, SignatureInfo signature, bool writable = false, DateTime? created = null, bool hidden = false) =>
        _files[path] = new FileFacts(path, true, created ?? Old, hidden, "AA", signature, writable);

    private void RunKey(string name, ResolvedCommand command, PersistenceKind kind = PersistenceKind.RunKey, bool autoStarts = true) =>
        _facts.Persistence.Add(new PersistenceEntry(kind, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", name, command, autoStarts));

    private void Process(int pid, string path, bool window = false, int session = Session, int parent = 1, DateTime? started = null) =>
        _facts.Processes.Add(new ProcessFact(pid, parent, Path.GetFileName(path), path, null, window, session, started));

    private List<Finding> Score() =>
        new Scorer(new ScoringRules(), @"C:\Windows").Score(
            _facts, path => _files.TryGetValue(path, out var file) ? file : FileFacts.Missing(path), Now, Session);

    private static ResolvedCommand Direct(string path) => new($"\"{path}\"", path, path);

    private static int Points(Finding finding, IndicatorKind kind) =>
        finding.Indicators.Where(i => i.Kind == kind).Sum(i => i.Points);

    [Fact]
    public void 常駐_プロセス_通信に出た同じファイルは_1_件にまとまり_高になる()
    {
        const string path = @"C:\Users\u\AppData\Roaming\updater.exe";
        File(path, Unsigned, writable: true);
        RunKey("Updater", Direct(path));
        Process(100, path.ToUpperInvariant());
        _facts.Endpoints.Add(new EndpointFact("TCP", "0.0.0.0", 4444, null, 0, "LISTEN", 100));

        var finding = Assert.Single(Score());
        Assert.Equal(FindingSources.Persistence | FindingSources.Process | FindingSources.Network, finding.Sources);
        Assert.Equal(30 + 20 + 10 + 10 + 20, finding.Score);
        Assert.Equal(RiskLevel.High, finding.Level);
        Assert.All(finding.Indicators, i => Assert.False(string.IsNullOrWhiteSpace(i.Evidence)));
    }

    [Fact]
    public void 単独で高になる兆候は無い()
    {
        var rules = new ScoringRules();
        var points = new[]
        {
            rules.SignatureInvalid, rules.SystemNameWrongLocation, rules.ViaScriptHost, rules.SignatureNone,
            rules.UnusualPersistence, rules.UserWritableLocation, rules.ListeningNonLoopback,
            rules.HiddenOrDoubleExtension, rules.Autostart, rules.OutboundConnection,
            rules.NoVisibleWindow, rules.RecentlyCreated,
            rules.UnusualParent, rules.ModuleInSignedProcess, rules.ModuleAcrossPublishers, rules.SignatureNoneModule,
            rules.WritableExecutableMemory, rules.ExecutableMappedData,
            rules.KeyInputCapture, rules.KeyStatePolling,
        };
        Assert.All(points, p => Assert.True(p < rules.HighFrom));
    }

    [Fact]
    public void 署名済みの自動起動だけなら_低に留まる()
    {
        const string path = @"C:\Windows\System32\spoolsv.exe";
        File(path, Microsoft, created: Now.AddDays(-1));
        RunKey("Spooler", Direct(path), PersistenceKind.Service);

        var finding = Assert.Single(Score());
        Assert.Equal(10, finding.Score);
        Assert.Equal(RiskLevel.Low, finding.Level);
    }

    [Fact]
    public void 作成日時が新しくても_署名が有効なら数えない()
    {
        File(@"C:\Program Files\App\signed.exe", Vendor, created: Now.AddDays(-1));
        File(@"C:\Program Files\App\unsigned.exe", Unsigned, created: Now.AddDays(-1));
        Process(1, @"C:\Program Files\App\signed.exe", window: true);
        Process(2, @"C:\Program Files\App\unsigned.exe", window: true);

        var findings = Score();
        Assert.Equal(0, Points(findings.Single(f => f.Name == "signed.exe"), IndicatorKind.RecentlyCreated));
        Assert.Equal(10, Points(findings.Single(f => f.Name == "unsigned.exe"), IndicatorKind.RecentlyCreated));
    }

    [Fact]
    public void システムのプロセス名を別の場所で名乗ると挙がる()
    {
        File(@"C:\Users\u\AppData\Local\svchost.exe", Unsigned, writable: true);
        File(@"C:\Windows\System32\svchost.exe", Microsoft);
        Process(1, @"C:\Users\u\AppData\Local\svchost.exe");
        Process(2, @"C:\Windows\System32\svchost.exe", session: 0);

        var findings = Score();
        Assert.Equal(40, Points(findings.Single(f => f.Path!.Contains("AppData")), IndicatorKind.SystemNameWrongLocation));
        Assert.Equal(0, Points(findings.Single(f => f.Path!.Contains("System32")), IndicatorKind.SystemNameWrongLocation));
    }

    [Fact]
    public void ファイルが無い登録は_点を付けず情報にする()
    {
        RunKey("Gone", Direct(@"C:\Gone\gone.exe"));

        var finding = Assert.Single(Score());
        Assert.Equal(0, finding.Score);
        Assert.Equal(RiskLevel.Info, finding.Level);
        Assert.Contains(finding.Indicators, i => i.Kind == IndicatorKind.MissingFile);
    }

    [Fact]
    public void rundll32_経由でも_対象の署名が有効なら数えない()
    {
        const string signed = @"C:\Windows\System32\sysmain.dll";
        const string unsigned = @"C:\ProgramData\x\payload.dll";
        File(signed, Microsoft);
        File(unsigned, Unsigned);
        RunKey("A", new ResolvedCommand("rundll32 sysmain.dll,Entry", @"C:\Windows\System32\rundll32.exe", signed, "rundll32"));
        RunKey("B", new ResolvedCommand("rundll32 payload.dll,Entry", @"C:\Windows\System32\rundll32.exe", unsigned, "rundll32"));

        var findings = Score();
        Assert.Equal(0, Points(findings.Single(f => f.Path == signed), IndicatorKind.ViaScriptHost));
        Assert.Equal(40, Points(findings.Single(f => f.Path == unsigned), IndicatorKind.ViaScriptHost));
        Assert.Equal(RiskLevel.High, findings.Single(f => f.Path == unsigned).Level);
    }

    [Fact]
    public void その場に書かれた命令の自動起動は_ファイル無しの_1_件として中になる()
    {
        RunKey("Loader", new ResolvedCommand("powershell -enc SQBFAFgA",
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", null, "powershell", Inline: true, Encoded: true));

        var finding = Assert.Single(Score());
        Assert.Null(finding.Path);
        Assert.NotNull(finding.Sha256);
        Assert.Equal(40 + 10, finding.Score);
        Assert.Equal(RiskLevel.Medium, finding.Level);
    }

    [Fact]
    public void 署名の無いスクリプトは_未署名ではなくスクリプト経由として数える()
    {
        const string script = @"C:\Scripts\job.ps1";
        File(script, Unsigned);
        RunKey("Job", new ResolvedCommand("powershell -File job.ps1", "powershell.exe", script, "powershell"), PersistenceKind.ScheduledTask);

        var finding = Assert.Single(Score());
        Assert.Equal(0, Points(finding, IndicatorKind.SignatureNone));
        Assert.Equal(40, Points(finding, IndicatorKind.ViaScriptHost));
    }

    [Fact]
    public void 無効にされた登録は_自動起動として数えない()
    {
        const string path = @"C:\Program Files\App\app.exe";
        File(path, Vendor);
        RunKey("App", Direct(path), autoStarts: false);

        var finding = Assert.Single(Score());
        Assert.Equal(0, finding.Score);
        Assert.Single(finding.Persistence);
    }

    [Fact]
    public void ふつう使われない常駐箇所は_それだけで挙がる()
    {
        const string path = @"C:\Program Files\Tool\dbg.exe";
        File(path, Vendor);
        RunKey("notepad.exe", Direct(path), PersistenceKind.Ifeo);

        var finding = Assert.Single(Score());
        Assert.Equal(30 + 10, finding.Score);
    }

    [Fact]
    public void ウィンドウの有無は_同じセッションのプロセスだけで見る()
    {
        File(@"C:\Program Files\Svc\svc.exe", Vendor);
        File(@"C:\Program Files\Tray\tray.exe", Vendor);
        File(@"C:\Program Files\Gui\gui.exe", Vendor);
        Process(1, @"C:\Program Files\Svc\svc.exe", session: 0);
        Process(2, @"C:\Program Files\Tray\tray.exe");
        Process(3, @"C:\Program Files\Gui\gui.exe");
        Process(4, @"C:\Program Files\Gui\gui.exe", window: true);

        var findings = Score();
        Assert.Equal(0, findings.Single(f => f.Name == "svc.exe").Score);
        Assert.Equal(10, findings.Single(f => f.Name == "tray.exe").Score);
        Assert.Equal(0, findings.Single(f => f.Name == "gui.exe").Score);
    }

    [Fact]
    public void 通信は_ループバックと_待ち受けポートで受けた接続を数えない()
    {
        const string path = @"C:\Program Files\Srv\srv.exe";
        File(path, Vendor);
        Process(7, path, window: true);
        _facts.Endpoints.Add(new EndpointFact("TCP", "127.0.0.1", 5000, null, 0, "LISTEN", 7));
        _facts.Endpoints.Add(new EndpointFact("TCP", "::1", 5000, null, 0, "LISTEN", 7));
        _facts.Endpoints.Add(new EndpointFact("TCP", "192.168.0.2", 5000, "192.168.0.9", 51000, "ESTABLISHED", 7));
        _facts.Endpoints.Add(new EndpointFact("TCP", "127.0.0.1", 52000, "127.0.0.1", 9000, "ESTABLISHED", 7));
        _facts.Endpoints.Add(new EndpointFact("UDP", "0.0.0.0", 5353, null, 0, "BOUND", 7));

        Assert.Equal(0, Assert.Single(Score()).Score);

        _facts.Endpoints.Add(new EndpointFact("TCP", "192.168.0.2", 53000, "203.0.113.5", 443, "ESTABLISHED", 7));
        _facts.Endpoints.Add(new EndpointFact("TCP", "::", 8080, null, 0, "LISTEN", 7));
        Assert.Equal(10 + 20, Assert.Single(Score()).Score);
    }

    // ---- 第 2 段階: 読み込み DLL ----

    [Fact]
    public void 署名済みのプロセスに載った未署名の_DLL_は_低く数えて挙げる()
    {
        const string host = @"C:\Program Files\App\app.exe";
        const string dll = @"C:\Program Files\App\plugin.dll";
        File(host, Vendor);
        File(dll, Unsigned);
        File(@"C:\Program Files\App\signed.dll", Vendor);
        Process(10, host, window: true);
        _facts.Modules[10] = new List<string> { host, dll, @"C:\Program Files\App\signed.dll" };

        var findings = Score();
        Assert.DoesNotContain(findings, f => f.Name == "signed.dll");
        var finding = findings.Single(f => f.Name == "plugin.dll");
        Assert.Equal(FindingSources.Module, finding.Sources);
        Assert.Equal(10 + 10, finding.Score);
        Assert.Equal(RiskLevel.Low, finding.Level);
    }

    [Fact]
    public void 本体が未署名なら_その_DLL_は挙げない()
    {
        const string host = @"C:\Tools\tool.exe";
        File(host, Unsigned);
        File(@"C:\Tools\tool.dll", Unsigned);
        Process(10, host, window: true);
        _facts.Modules[10] = new List<string> { host, @"C:\Tools\tool.dll" };

        Assert.Equal("tool.exe", Assert.Single(Score()).Name);
    }

    [Fact]
    public void 発行元の違うプログラムに広く入り込んだ_DLL_は_書き込める場所にあれば高になる()
    {
        const string dll = @"C:\Users\u\AppData\Roaming\hook.dll";
        File(dll, Unsigned, writable: true, created: Now.AddDays(-1));
        File(@"C:\Windows\explorer.exe", Microsoft);
        File(@"C:\Program Files\A\a.exe", Vendor);
        File(@"C:\Program Files\B\b.exe", new SignatureInfo(SignatureStatus.ValidOther, "Other Co."));
        Process(1, @"C:\Windows\explorer.exe", window: true);
        Process(2, @"C:\Program Files\A\a.exe", window: true);
        Process(3, @"C:\Program Files\B\b.exe", window: true);
        foreach (var pid in new[] { 1, 2, 3 }) _facts.Modules[pid] = new List<string> { dll };

        var finding = Score().Single(f => f.Name == "hook.dll");
        Assert.Equal(15, Points(finding, IndicatorKind.ModuleAcrossPublishers));
        Assert.Equal(10 + 20 + 10 + 10 + 15, finding.Score);
        Assert.Equal(RiskLevel.High, finding.Level);
    }

    [Fact]
    public void 同じ発行元の中だけで使われる_DLL_は_広く入り込んだとは数えない()
    {
        const string dll = @"C:\Program Files\Git\usr\bin\msys-2.0.dll";
        File(dll, Unsigned);
        foreach (var (pid, name) in new[] { (1, "git.exe"), (2, "bash.exe"), (3, "sh.exe") })
        {
            File($@"C:\Program Files\Git\bin\{name}", Vendor);
            Process(pid, $@"C:\Program Files\Git\bin\{name}", window: true);
            _facts.Modules[pid] = new List<string> { dll };
        }

        var finding = Score().Single(f => f.Name == "msys-2.0.dll");
        Assert.Equal(0, Points(finding, IndicatorKind.ModuleAcrossPublishers));
        Assert.Equal(3, finding.LoadedBy.Count);
    }

    [Fact]
    public void NET_Framework_がその場で作った写しは_書き換えられない限り挙げない()
    {
        const string host = @"C:\Program Files\App\app.exe";
        const string locked = @"C:\Windows\assembly\NativeImages_v4.0.30319_64\System\abc\System.ni.dll";
        const string open = @"C:\Windows\assembly\NativeImages_v4.0.30319_64\Evil\abc\Evil.ni.dll";
        File(host, Vendor);
        File(locked, Unsigned);
        File(open, Unsigned, writable: true);
        Process(10, host, window: true);
        _facts.Modules[10] = new List<string> { locked, open };

        var findings = Score();
        Assert.DoesNotContain(findings, f => f.Name == "System.ni.dll");
        Assert.Contains(findings, f => f.Name == "Evil.ni.dll");
    }

    // ---- 第 2 段階: 親子関係 ----

    [Fact]
    public void 文書を開くアプリがシェルを起動していると挙がる()
    {
        File(@"C:\Program Files\Office\WINWORD.EXE", Microsoft);
        File(@"C:\Windows\System32\cmd.exe", Microsoft);
        Process(100, @"C:\Program Files\Office\WINWORD.EXE", window: true, started: Now.AddMinutes(-10));
        Process(200, @"C:\Windows\System32\cmd.exe", window: true, parent: 100, started: Now.AddMinutes(-1));

        var finding = Score().Single(f => f.Name == "cmd.exe");
        Assert.Equal(30, Points(finding, IndicatorKind.UnusualParent));
    }

    [Fact]
    public void 親の番号が使い回されているときは_親子とみなさない()
    {
        File(@"C:\Program Files\Office\WINWORD.EXE", Microsoft);
        File(@"C:\Windows\System32\cmd.exe", Microsoft);
        // cmd のほうが先に起動している。番号 100 は、あとから Word に付いただけ
        Process(100, @"C:\Program Files\Office\WINWORD.EXE", window: true, started: Now.AddMinutes(-1));
        Process(200, @"C:\Windows\System32\cmd.exe", window: true, parent: 100, started: Now.AddMinutes(-10));

        Assert.All(Score(), f => Assert.Equal(0, Points(f, IndicatorKind.UnusualParent)));
    }

    [Fact]
    public void ブラウザーが_cmd_を起動するのは挙げない()
    {
        File(@"C:\Program Files\Google\Chrome\chrome.exe", Vendor);
        File(@"C:\Windows\System32\cmd.exe", Microsoft);
        Process(100, @"C:\Program Files\Google\Chrome\chrome.exe", window: true, started: Now.AddMinutes(-10));
        Process(200, @"C:\Windows\System32\cmd.exe", window: true, parent: 100, started: Now.AddMinutes(-1));

        Assert.All(Score(), f => Assert.Equal(0, Points(f, IndicatorKind.UnusualParent)));
    }

    [Fact]
    public void svchost_の親が_services_でなければ_起動時刻が分からなくても挙がる()
    {
        File(@"C:\Windows\System32\svchost.exe", Microsoft);
        File(@"C:\Windows\System32\services.exe", Microsoft);
        File(@"C:\Users\u\AppData\Local\loader.exe", Unsigned, writable: true);
        Process(600, @"C:\Windows\System32\services.exe", session: 0);
        Process(700, @"C:\Windows\System32\svchost.exe", session: 0, parent: 600);
        Process(800, @"C:\Users\u\AppData\Local\loader.exe", window: true);
        Process(900, @"C:\Windows\System32\svchost.exe", parent: 800);
        Process(901, @"C:\Windows\System32\svchost.exe", parent: 4242);

        var finding = Score().Single(f => f.Name == "svchost.exe");
        var indicator = Assert.Single(finding.Indicators, i => i.Kind == IndicatorKind.UnusualParent);
        Assert.Contains("PID 900", indicator.Evidence);
        Assert.Contains("loader.exe", indicator.Evidence);
        Assert.Contains("PID 901", indicator.Evidence);
        Assert.DoesNotContain("PID 700", indicator.Evidence);
    }

    [Fact]
    public void 親が入れ替わりうるプロセスは_起動時刻が分からなければ挙げない()
    {
        File(@"C:\Windows\System32\RuntimeBroker.exe", Microsoft);
        File(@"C:\Program Files\App\app.exe", Vendor);
        Process(10, @"C:\Program Files\App\app.exe", window: true);
        Process(20, @"C:\Windows\System32\RuntimeBroker.exe", window: true, parent: 10);
        Assert.All(Score(), f => Assert.Equal(0, Points(f, IndicatorKind.UnusualParent)));

        _facts.Processes.Clear();
        Process(10, @"C:\Program Files\App\app.exe", window: true, started: Now.AddMinutes(-10));
        Process(20, @"C:\Windows\System32\RuntimeBroker.exe", window: true, parent: 10, started: Now.AddMinutes(-1));
        Assert.Equal(30, Points(Score().Single(f => f.Name == "RuntimeBroker.exe"), IndicatorKind.UnusualParent));
    }

    // ---- 第 2 段階: メモリ ----

    private static ExecutableRegion Region(bool writable, bool isPrivate = true, string? file = null, long size = 65536) =>
        new(0x1A2B0000, 0x1A2B0000, size, writable, isPrivate, file);

    [Fact]
    public void JIT_を持たないプロセスの_書き込みも実行もできる領域は挙がる()
    {
        File(@"C:\Windows\System32\notepad.exe", Microsoft);
        Process(10, @"C:\Windows\System32\notepad.exe", window: true);
        _facts.ExecutableRegions[10] = new List<ExecutableRegion> { Region(writable: true) };

        var finding = Assert.Single(Score());
        var indicator = Assert.Single(finding.Indicators);
        Assert.Equal(IndicatorKind.WritableExecutableMemory, indicator.Kind);
        Assert.Equal(30, indicator.Points);
        Assert.Contains("PID 10", indicator.Evidence);
        Assert.Contains("64 KB", indicator.Evidence);
    }

    [Fact]
    public void JIT_を持つプロセスの領域は_兆候にしない()
    {
        File(@"C:\Program Files\App\app.exe", Vendor);
        Process(10, @"C:\Program Files\App\app.exe", window: true);
        _facts.ExecutableRegions[10] = new List<ExecutableRegion> { Region(writable: true), Region(writable: false, isPrivate: false) };
        _facts.JitEngines[10] = ".NET";

        Assert.Empty(Assert.Single(Score()).Indicators);
    }

    [Fact]
    public void 書き込みのできない領域は_点を付けず情報にする()
    {
        File(@"C:\Windows\explorer.exe", Microsoft);
        Process(10, @"C:\Windows\explorer.exe", window: true);
        _facts.ExecutableRegions[10] = new List<ExecutableRegion> { Region(writable: false, size: 4096), Region(writable: false, size: 4096) };

        var finding = Assert.Single(Score());
        Assert.Equal(0, finding.Score);
        Assert.Equal(IndicatorKind.ExecutableMemoryNote, Assert.Single(finding.Indicators).Kind);
    }

    [Fact]
    public void ファイルを写しただけの領域が実行できると挙がる()
    {
        File(@"C:\Windows\System32\notepad.exe", Microsoft);
        Process(10, @"C:\Windows\System32\notepad.exe", window: true);
        _facts.ExecutableRegions[10] = new List<ExecutableRegion>
        {
            Region(writable: false, isPrivate: false, file: @"C:\Users\u\AppData\payload.bin"),
        };

        var indicator = Assert.Single(Assert.Single(Score()).Indicators);
        Assert.Equal(IndicatorKind.ExecutableMappedData, indicator.Kind);
        Assert.Equal(30, indicator.Points);
        Assert.Contains("payload.bin", indicator.Evidence);
    }

    [Fact]
    public void EXE_が公開しているシンボルを_ファイルから読める()
    {
        var kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        Assert.True(PCMonitor.Core.Collectors.PeExports.ContainsAny(kernel32, "CreateFileW"));
        Assert.False(PCMonitor.Core.Collectors.PeExports.ContainsAny(kernel32, "napi_create_function"));
        Assert.False(PCMonitor.Core.Collectors.PeExports.ContainsAny(Path.Combine(Environment.SystemDirectory, "no-such-file.dll"), "x"));
    }

    // ---- 第 2 段階: キー入力 API の監視 ----

    private static KeyApiCall Call(string? path, KeyApiWeight weight, string description = "呼び出し", int pid = 50) =>
        new(Now.AddMinutes(-1), pid, 1, path, weight, description);

    [Theory]
    [InlineData(13, null, KeyApiWeight.Capture)]
    [InlineData(13, "NULL", KeyApiWeight.Capture)]
    [InlineData(2, @"C:\Users\u\AppData\hook.dll", KeyApiWeight.Capture)]
    [InlineData(2, "NULL", KeyApiWeight.Note)]
    [InlineData(0, null, KeyApiWeight.Capture)]
    public void キーボードのフックは_ほかのアプリに届く形かどうかで重さが変わる(int filterType, string? library, KeyApiWeight expected)
    {
        Assert.Equal(expected, KeyApiClassifier.Hook(filterType, library)!.Value.Weight);
    }

    [Theory]
    [InlineData(3)]   // WH_GETMESSAGE
    [InlineData(5)]   // WH_CBT
    [InlineData(14)]  // WH_MOUSE_LL
    public void キー入力に関わらないフックは拾わない(int filterType)
    {
        Assert.Null(KeyApiClassifier.Hook(filterType, @"C:\x.dll"));
    }

    [Fact]
    public void 生入力は_キーボードを前面でなくても受け取る形だけを重く見る()
    {
        const uint image = 0x1000000;
        // 2026-11-13 に実機で流れてきた値: UsagePage 1、Usage 6、Flags 0（登録）と 1（取り消し）
        Assert.Equal(KeyApiWeight.Note, KeyApiClassifier.RawInput(1, 6, 0x0, true, image)!.Value.Weight);
        Assert.Null(KeyApiClassifier.RawInput(1, 6, 0x1, true, image));

        Assert.Equal(KeyApiWeight.Capture, KeyApiClassifier.RawInput(1, 6, 0x100, true, image)!.Value.Weight);
        Assert.Equal(KeyApiWeight.Capture, KeyApiClassifier.RawInput(1, 0, 0x120, true, image)!.Value.Weight);

        // マウス、失敗した登録は対象外
        Assert.Null(KeyApiClassifier.RawInput(1, 2, 0x100, true, image));
        Assert.Null(KeyApiClassifier.RawInput(1, 6, 0x100, false, image));

        // 登録したスレッドが、ファイルの裏付けが無いメモリから始まっていれば重く見る
        var fromNowhere = KeyApiClassifier.RawInput(1, 6, 0x0, true, 0x20000)!.Value;
        Assert.Equal(KeyApiWeight.Capture, fromNowhere.Weight);
        Assert.Contains("ファイルの裏付けが無い", fromNowhere.Description);
    }

    [Fact]
    public void キー入力を受け取れる形の_API_は_使った数だけ重ねずに_1_つの兆候にする()
    {
        const string path = @"C:\Program Files\Tool\tool.exe";
        File(path, Vendor);
        Process(50, path, window: true);
        _facts.KeyApiCalls.Add(Call(path, KeyApiWeight.Capture, "フック"));
        _facts.KeyApiCalls.Add(Call(path, KeyApiWeight.Capture, "生入力"));
        _facts.KeyApiCalls.Add(Call(path, KeyApiWeight.Polling, "問い合わせ"));

        var finding = Assert.Single(Score());
        Assert.Equal(30, finding.Score);
        var indicator = Assert.Single(finding.Indicators);
        Assert.Equal(IndicatorKind.KeyInputCapture, indicator.Kind);
        Assert.Contains("フック", indicator.Evidence);
        Assert.Contains("生入力", indicator.Evidence);
        Assert.True(finding.Sources.HasFlag(FindingSources.KeyApi));
    }

    [Fact]
    public void 未署名で常駐するものがキー入力を受け取っていれば_高になる()
    {
        const string path = @"C:\Users\u\AppData\Roaming\helper.exe";
        File(path, Unsigned, writable: true);
        RunKey("Helper", Direct(path));
        Process(50, path);
        _facts.KeyApiCalls.Add(Call(path, KeyApiWeight.Capture));

        var finding = Assert.Single(Score());
        Assert.Equal(30 + 20 + 10 + 10 + 30, finding.Score);
        Assert.Equal(RiskLevel.High, finding.Level);
    }

    [Fact]
    public void 問い合わせだけなら低く数え_自分用の_API_は点を付けない()
    {
        File(@"C:\Program Files\A\a.exe", Vendor);
        File(@"C:\Program Files\B\b.exe", Vendor);
        _facts.KeyApiCalls.Add(Call(@"C:\Program Files\A\a.exe", KeyApiWeight.Polling));
        _facts.KeyApiCalls.Add(Call(@"C:\Program Files\B\b.exe", KeyApiWeight.Note));

        var findings = Score();
        Assert.Equal(15, findings.Single(f => f.Name == "a.exe").Score);
        var b = findings.Single(f => f.Name == "b.exe");
        Assert.Equal(0, b.Score);
        Assert.Equal(IndicatorKind.KeyApiNote, Assert.Single(b.Indicators).Kind);
    }

    [Fact]
    public void 呼んだプロセスが終わっていても_実行ファイルで突き合わせる()
    {
        const string path = @"C:\Users\u\AppData\Local\gone.exe";
        File(path, Unsigned, writable: true);
        _facts.KeyApiCalls.Add(Call(path, KeyApiWeight.Capture, pid: 999));
        _facts.KeyApiCalls.Add(Call(null, KeyApiWeight.Capture, pid: 888));

        var findings = Score();
        Assert.Equal(30 + 20 + 30, findings.Single(f => f.Path == path).Score);
        // 実行ファイルが分からなければ、番号だけの項目として残す（隠さない）
        Assert.Contains(findings, f => f.Key == "pid:888" && f.Score == 30);
    }

    [Fact]
    public void 番号が使い回されたプロセスには_付けない()
    {
        const string path = @"C:\Program Files\App\app.exe";
        File(path, Vendor);
        // 呼び出しのあとに起動したプロセスが、同じ番号を持っている
        Process(50, path, window: true, started: Now);
        _facts.KeyApiCalls.Add(Call(null, KeyApiWeight.Capture, pid: 50));

        var findings = Score();
        Assert.Equal(0, findings.Single(f => f.Path == path).Score);
        Assert.Contains(findings, f => f.Key == "pid:50");
    }

    [Fact]
    public void 許可リストは_ハッシュが変わると外れて_変わったことを挙げる()
    {
        var directory = Path.Combine(Path.GetTempPath(), "pcmonitor-tests-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new AllowlistStore(Path.Combine(directory, "allowlist.json"));
            var finding = new Finding { Key = @"file:c:\x\a.exe", Name = "a.exe", Path = @"C:\x\a.exe", Sha256 = "AA", Score = 40 };
            Assert.True(store.Add(finding));
            Assert.False(store.Add(new Finding { Key = "file:nohash", Name = "n" }));

            // 読み直しても残っている。同じハッシュなら許可、変われば外れる
            var reloaded = new AllowlistStore(Path.Combine(directory, "allowlist.json"));
            var same = new Finding { Key = finding.Key, Name = "a.exe", Sha256 = "aa", Score = 40 };
            var changed = new Finding { Key = finding.Key, Name = "a.exe", Sha256 = "BB", Score = 40 };
            reloaded.Apply(new[] { same });
            reloaded.Apply(new[] { changed });

            Assert.True(same.IsAllowed);
            Assert.False(changed.IsAllowed);
            Assert.Contains(changed.Indicators, i => i.Kind == IndicatorKind.AllowedButChanged && i.Points == 0);
            Assert.Equal(40, changed.Score);

            // BOM 無しで保存されている
            var bytes = System.IO.File.ReadAllBytes(Path.Combine(directory, "allowlist.json"));
            Assert.NotEqual(0xEF, bytes[0]);
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void 差分は_前回に無かった項目だけに印を付け_初回は付けない()
    {
        var findings = new[]
        {
            new Finding { Key = "file:a", Name = "a" },
            new Finding { Key = "file:b", Name = "b" },
        };

        Assert.False(ScanDiff.MarkNew(findings, null));
        Assert.All(findings, f => Assert.False(f.IsNew));

        var previous = new LastScan(Now, new List<LastScanItem> { new("file:a", null, 0) });
        Assert.True(ScanDiff.MarkNew(findings, previous));
        Assert.False(findings[0].IsNew);
        Assert.True(findings[1].IsNew);
    }

    [Fact]
    public void CSV_は区切り文字と式の形を無害にする()
    {
        var path = Path.Combine(Path.GetTempPath(), "pcmonitor-tests-" + Guid.NewGuid().ToString("N") + ".csv");
        try
        {
            ReportWriter.WriteCsv(path, new[]
            {
                new Finding { Key = "k", Name = "=cmd|' /c calc'!A1", Path = @"C:\a,b\""x"".exe" },
            });
            var lines = System.IO.File.ReadAllLines(path);
            Assert.Equal(2, lines.Length);
            Assert.Contains("'=cmd|' /c calc'!A1", lines[1]);
            Assert.Contains(@"""C:\a,b\""""x"""".exe""", lines[1]);
        }
        finally
        {
            System.IO.File.Delete(path);
        }
    }
}
