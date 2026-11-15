using PCMonitor.Core.Collectors;
using PCMonitor.Core.Model;
using PCMonitor.Core.Remote;
using PCMonitor.Core.Scoring;

namespace PCMonitor.Core.Tests;

/// <summary>第 3 段階の手順 1（設計書 §16.2 A・B・C、§16.3、§16.4）。</summary>
public class RemoteTests
{
    private const int Session = 1;
    private static readonly DateTime Now = new(2026, 11, 15, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime Old = Now.AddYears(-1);

    private static readonly SignatureInfo AnyDeskSigned = new(SignatureStatus.ValidOther, "AnyDesk Software GmbH");
    private static readonly SignatureInfo OtherVendor = new(SignatureStatus.ValidOther, "Example Inc.");
    private static readonly SignatureInfo Unsigned = new(SignatureStatus.None);

    private readonly Dictionary<string, FileFacts> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly ScanFacts _facts = new();

    private void File(string path, SignatureInfo signature, bool writable = false, DateTime? created = null) =>
        _files[path] = new FileFacts(path, true, created ?? Old, false, "AA", signature, writable);

    private void Process(int pid, string path, bool window = true) =>
        _facts.Processes.Add(new ProcessFact(pid, 1, Path.GetFileName(path), path, null, window, Session));

    private void RunKey(string name, string path) =>
        _facts.Persistence.Add(new PersistenceEntry(PersistenceKind.RunKey, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            name, new ResolvedCommand($"\"{path}\"", path, path)));

    private void Outbound(int pid) =>
        _facts.Endpoints.Add(new EndpointFact("TCP", "192.168.1.10", 50000, "203.0.113.5", 443, "ESTABLISHED", pid));

    private List<Finding> Score() =>
        new Scorer(new ScoringRules(), @"C:\Windows").Score(
            _facts, path => _files.TryGetValue(path, out var file) ? file : FileFacts.Missing(path), Now, Session);

    private static int Points(Finding finding, IndicatorKind kind) =>
        finding.Indicators.Where(i => i.Kind == kind).Sum(i => i.Points);

    // ---- 照合表 ----

    [Theory]
    [InlineData("AnyDesk.exe", "AnyDesk")]
    [InlineData("anydesk (1).exe", "AnyDesk")]
    [InlineData("TeamViewerQS_x64.exe", "TeamViewer")]
    [InlineData("rustdesk-1.3.2-x86_64.exe", "RustDesk")]
    public void 実行ファイル名で照合する(string fileName, string product) =>
        Assert.Equal(product, RemoteToolCatalog.MatchFileName(fileName)?.Product);

    [Theory]
    [InlineData("notepad.exe")]
    [InlineData("AnyDesk.dll")]
    [InlineData("myanydesk.exe")]
    public void 照合表に無い名前は当たらない(string fileName) =>
        Assert.Null(RemoteToolCatalog.MatchFileName(fileName));

    [Fact]
    public void 表示名に_Remote_と入っているだけでは当たらない() =>
        // この PC に実際にある名前（2026-11-15）。「Remote」で引くと SDK の部品が挙がる
        Assert.Null(RemoteToolCatalog.MatchInstalled("Windows SDK DirectX x64 Remote"));

    [Fact]
    public void まだ署名者を確かめた製品は無い() =>
        // 確かめたら、この試験を書き換え、確かめた日と版を設計書 §16 に書き戻す
        Assert.All(RemoteToolCatalog.Entries, e => Assert.False(e.SignersVerified));

    // ---- 採点（§16.3） ----

    [Fact]
    public void 署名が有効な遠隔操作ソフトは_点が_0_でも_遠隔として出る()
    {
        const string path = @"C:\Program Files (x86)\AnyDesk\AnyDesk.exe";
        File(path, AnyDeskSigned);
        Process(10, path);

        var finding = Assert.Single(Score());
        Assert.Equal(0, finding.Score);
        Assert.Equal(RiskLevel.Info, finding.Level);
        Assert.True(finding.Sources.HasFlag(FindingSources.Remote));
        Assert.Equal("AnyDesk", finding.RemoteTool!.Product);
        Assert.Contains(finding.Indicators, i => i.Kind == IndicatorKind.RemoteTool);
    }

    [Fact]
    public void 名前が遠隔操作ソフトで署名が無いと_なりすましになる()
    {
        // Probe を AnyDesk.exe に写して動かしたときの形（§16.5）
        const string path = @"C:\Users\u\Downloads\AnyDesk.exe";
        File(path, Unsigned, writable: true);
        Process(10, path);

        var finding = Assert.Single(Score());
        Assert.Equal(40, Points(finding, IndicatorKind.RemoteToolImpersonation));
        Assert.Equal(40 + 30 + 20, finding.Score);
        Assert.Equal(RiskLevel.High, finding.Level);
    }

    [Fact]
    public void 署名者が違っても_照合表が未確認なら点を付けない()
    {
        const string path = @"C:\Program Files\AnyDesk\AnyDesk.exe";
        File(path, OtherVendor);
        Process(10, path);

        var finding = Assert.Single(Score());
        Assert.Equal(0, Points(finding, IndicatorKind.RemoteToolImpersonation));
        Assert.Contains(finding.Indicators, i => i.Kind == IndicatorKind.RemoteToolSignerUnverified);
    }

    [Fact]
    public void 入れたばかりで_自動起動し_外と通信していると_40_点の中になる()
    {
        // 電話で入れさせた直後の状態（§16.3 の例）
        const string path = @"C:\Program Files (x86)\AnyDesk\AnyDesk.exe";
        File(path, AnyDeskSigned);
        Process(10, path);
        RunKey("AnyDesk", path);
        Outbound(10);
        _facts.InstalledPrograms.Add(new InstalledProgram("AnyDesk", "AnyDesk Software GmbH", Now.AddDays(-1),
            @"C:\Program Files (x86)\AnyDesk", path, @"HKLM\…\Uninstall\AnyDesk"));

        var finding = Assert.Single(Score());
        Assert.Equal(20, Points(finding, IndicatorKind.RemoteToolRecentlyInstalled));
        Assert.Equal(10, Points(finding, IndicatorKind.Autostart));
        Assert.Equal(10, Points(finding, IndicatorKind.OutboundConnection));
        Assert.Equal(40, finding.Score);
        Assert.Equal(RiskLevel.Medium, finding.Level);
        Assert.Single(finding.Installations);
    }

    [Fact]
    public void インストールせずにダウンロードから動かすと_40_点の中になる()
    {
        // ウィンドウは出ている（遠隔操作ソフトは画面を出して番号を伝えさせる）
        const string path = @"C:\Users\u\Downloads\AnyDesk.exe";
        File(path, AnyDeskSigned, writable: true, created: Now.AddHours(-2));
        Process(10, path);

        var finding = Assert.Single(Score());
        Assert.Equal(20, Points(finding, IndicatorKind.UserWritableLocation));
        Assert.Equal(20, Points(finding, IndicatorKind.RemoteToolRecentlyInstalled));
        Assert.Equal(40, finding.Score);
    }

    [Fact]
    public void 未署名で新しくても_新しさを二重に数えない()
    {
        const string path = @"C:\Users\u\Downloads\AnyDesk.exe";
        File(path, Unsigned, writable: true, created: Now.AddHours(-2));
        Process(10, path);

        var finding = Assert.Single(Score());
        Assert.Equal(0, Points(finding, IndicatorKind.RecentlyCreated));
        Assert.Equal(20, Points(finding, IndicatorKind.RemoteToolRecentlyInstalled));
    }

    [Fact]
    public void 動いていない遠隔操作ソフトも_インストールの記録から_1_件出る()
    {
        _facts.InstalledPrograms.Add(new InstalledProgram("TeamViewer", "TeamViewer Germany GmbH", Old, null, null, @"HKLM\…\TeamViewer"));

        var finding = Assert.Single(Score());
        Assert.Equal("TeamViewer", finding.Name);
        Assert.Null(finding.Path);
        Assert.Equal("インストールの記録", finding.RemoteTool!.MatchedBy);
        Assert.Equal(0, finding.Score);
    }

    [Fact]
    public void インストールの記録は_動いている同じ製品の候補にまとまる()
    {
        const string path = @"C:\Program Files\TeamViewer\TeamViewer.exe";
        File(path, new SignatureInfo(SignatureStatus.ValidOther, "TeamViewer Germany GmbH"));
        Process(10, path);
        // アイコンが別の EXE（アンインストーラー）を指していても、製品名でまとめる
        _facts.InstalledPrograms.Add(new InstalledProgram("TeamViewer", "TeamViewer", Old, null, null, @"HKLM\…\TeamViewer"));

        var finding = Assert.Single(Score());
        Assert.Equal(path, finding.Path);
        Assert.Single(finding.Installations);
    }

    [Fact]
    public void 単独で高になる兆候は無い_第_3_段階()
    {
        var rules = new ScoringRules();
        Assert.True(rules.RemoteToolImpersonation < rules.HighFrom);
        Assert.True(rules.RemoteToolRecentlyInstalled < rules.HighFrom);
    }

    // ---- いまの状態（§16.4） ----

    private List<StatusLine> State()
    {
        var findings = Score();
        return CurrentStateBuilder.Build(_facts, findings, Session);
    }

    private void HomeFeatures() =>
        _facts.RemoteFeatures.Add(new RemoteFeature("リモートデスクトップ（受け付け）", false, "受け付けない", "Home"));

    private void Sessions(params SessionFact[] sessions) => _facts.Sessions.AddRange(sessions);

    private static SessionFact Console1 => new(Session, "Console", "使用中", @"PC\u", null, null, true);

    [Fact]
    public void 何も無ければ_どの行も_なし_と出て_空にならない()
    {
        HomeFeatures();
        Sessions(Console1);

        var state = State();
        Assert.All(state, line => Assert.False(string.IsNullOrWhiteSpace(line.Text)));
        Assert.DoesNotContain(state, line => line.Level == StatusLevel.Warning);
        Assert.Equal("なし（この画面は手元のもの）", state.Single(l => l.Label == "リモート セッション").Text);
        Assert.Equal("なし", state.Single(l => l.Label == "ほかのログイン中の利用者").Text);
    }

    [Fact]
    public void この画面がリモート経由なら_接続元つきで警告する()
    {
        _facts.CurrentSessionIsRemote = true;
        Sessions(new SessionFact(Session, "RDP-Tcp#3", "使用中", @"PC\u", "LAPTOP", "192.168.1.20", true));

        var line = State().Single(l => l.Label == "リモート セッション");
        Assert.Equal(StatusLevel.Warning, line.Level);
        Assert.Contains("192.168.1.20", line.Text);
        Assert.Contains("LAPTOP", line.Text);
    }

    [Fact]
    public void 遠隔操作ソフトが動いて外と通信していれば_許可済みでも警告する()
    {
        const string path = @"C:\Program Files (x86)\AnyDesk\AnyDesk.exe";
        File(path, AnyDeskSigned);
        Process(10, path);
        Outbound(10);
        var findings = Score();
        findings.Single().IsAllowed = true;

        var line = CurrentStateBuilder.Build(_facts, findings, Session).Single(l => l.Label == "遠隔操作ソフト");
        Assert.Equal(StatusLevel.Warning, line.Level);
        Assert.Contains("外部と通信中", line.Text);
        Assert.Contains("許可済み", line.Text);
        Assert.NotNull(line.Detail);
    }

    [Fact]
    public void 入っているだけで動いていなければ_注意に留める()
    {
        _facts.InstalledPrograms.Add(new InstalledProgram("AnyDesk", null, Old, null, null, @"HKLM\…\AnyDesk"));

        var line = State().Single(l => l.Label == "遠隔操作ソフト");
        Assert.Equal(StatusLevel.Notice, line.Level);
        Assert.Contains("動いていない", line.Text);
    }

    [Fact]
    public void 有効な標準の遠隔機能は_注意として名前を出す()
    {
        _facts.RemoteFeatures.Add(new RemoteFeature("リモートデスクトップ（受け付け）", true, "受け付ける", "fDenyTSConnections が 0"));
        _facts.RemoteFeatures.Add(new RemoteFeature("OpenSSH サーバー", false, "入っていない", "サービス sshd が無い"));

        var line = State().Single(l => l.Label == "Windows の遠隔機能");
        Assert.Equal(StatusLevel.Notice, line.Level);
        Assert.Contains("リモートデスクトップ", line.Text);
        Assert.DoesNotContain("OpenSSH", line.Text);
    }

    [Fact]
    public void ほかの利用者がログインしていれば出す()
    {
        Sessions(Console1, new SessionFact(2, "", "切断（ログインしたまま）", @"PC\other", null, null, false));

        var line = State().Single(l => l.Label == "ほかのログイン中の利用者");
        Assert.Equal(StatusLevel.Notice, line.Level);
        Assert.Contains(@"PC\other", line.Text);
    }

    // ---- 集める側の小さな解析 ----

    [Theory]
    [InlineData("20261114", 2026, 11, 14)]
    [InlineData(" 20250101 ", 2025, 1, 1)]
    public void InstallDate_を読む(string text, int y, int m, int d) =>
        Assert.Equal(new DateTime(y, m, d), InstalledProgramCollector.ParseInstallDate(text)!.Value.ToLocalTime());

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("2026/11/14")]
    public void 読めない_InstallDate_は_null(string? text) =>
        Assert.Null(InstalledProgramCollector.ParseInstallDate(text));

    [Fact]
    public void アイコンの指定から実在する_EXE_を取り出す()
    {
        var exe = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        Assert.Equal(exe, InstalledProgramCollector.ExecutableFromIcon($"\"{exe}\",0"), ignoreCase: true);
        Assert.Equal(exe, InstalledProgramCollector.ExecutableFromIcon($"{exe},0"), ignoreCase: true);
        Assert.Null(InstalledProgramCollector.ExecutableFromIcon(@"C:\nowhere\app.exe,0"));
        Assert.Null(InstalledProgramCollector.ExecutableFromIcon(@"C:\Windows\app.ico"));
    }
}
