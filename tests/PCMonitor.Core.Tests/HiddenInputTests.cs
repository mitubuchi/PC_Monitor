using PCMonitor.Core.Collectors;
using PCMonitor.Core.Model;
using PCMonitor.Core.Monitoring;
using PCMonitor.Core.Remote;
using PCMonitor.Core.Scoring;

namespace PCMonitor.Core.Tests;

/// <summary>第 3 段階の手順 3（設計書 §16.2 F・G）。</summary>
public class HiddenInputTests
{
    private const int Session = 1;
    private static readonly DateTime Now = new(2026, 11, 15, 0, 0, 0, DateTimeKind.Utc);

    private readonly Dictionary<string, FileFacts> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly ScanFacts _facts = new();

    private void Process(int pid, string path, SignatureInfo signature)
    {
        _files[path] = new FileFacts(path, true, Now.AddYears(-1), false, "AA", signature, false);
        _facts.Processes.Add(new ProcessFact(pid, 1, Path.GetFileName(path), path, null, true, Session));
    }

    private List<Finding> Score() =>
        new Scorer(new ScoringRules(), @"C:\Windows").Score(
            _facts, path => _files.TryGetValue(path, out var file) ? file : FileFacts.Missing(path), Now, Session);

    private StatusLine Line(string label) =>
        CurrentStateBuilder.Build(_facts, Score(), Session).Single(l => l.Label == label);

    private static readonly SignatureInfo Vendor = new(SignatureStatus.ValidOther, "Example Inc.");

    // ---- F. 隠しデスクトップ ----

    [Fact]
    public void 見慣れたデスクトップだけなら_何も無いと出る()
    {
        // この PC の通常の権限での一覧（2026-11-15）
        _facts.Desktops.Add(new DesktopFact("Default", true, Array.Empty<int>()));

        var line = Line("隠しデスクトップ");
        Assert.Equal(StatusLevel.Normal, line.Level);
        Assert.Equal("見慣れないものは無い", line.Text);
    }

    [Theory]
    [InlineData("Default", true)]
    [InlineData("winlogon", true)]
    [InlineData("Disconnect", true)]
    [InlineData("Screen-saver", true)]
    [InlineData("PCMonitorProbeDesktop", false)]
    public void 見慣れた名前(string name, bool familiar) =>
        Assert.Equal(familiar, DesktopCollector.FamiliarNames.Contains(name));

    [Fact]
    public void 見慣れないデスクトップにウィンドウを持つプロセスに_30_点()
    {
        Process(10, @"C:\Program Files\Vendor\tool.exe", Vendor);
        _facts.Desktops.Add(new DesktopFact("Default", true, Array.Empty<int>()));
        _facts.Desktops.Add(new DesktopFact("hvnc", false, new[] { 10 }));

        var finding = Assert.Single(Score());
        Assert.Equal(30, finding.Indicators.Single(i => i.Kind == IndicatorKind.HiddenDesktopWindow).Points);
        Assert.Contains("hvnc", finding.Indicators.Single(i => i.Kind == IndicatorKind.HiddenDesktopWindow).Evidence);

        var line = Line("隠しデスクトップ");
        Assert.Equal(StatusLevel.Warning, line.Level);
        Assert.Contains("hvnc（ウィンドウを持つもの: tool.exe）", line.Text);
    }

    [Fact]
    public void ウィンドウの無い見慣れないデスクトップは_注意に留める()
    {
        _facts.Desktops.Add(new DesktopFact("KeePassSecureDesktop", false, Array.Empty<int>()));

        Assert.Empty(Score());
        var line = Line("隠しデスクトップ");
        Assert.Equal(StatusLevel.Notice, line.Level);
        Assert.Contains("ウィンドウは無い", line.Text);
    }

    [Fact]
    public void 中を見られなかったデスクトップは_そう書く()
    {
        _facts.Desktops.Add(new DesktopFact("locked", false, Array.Empty<int>(), "開けなかった（エラー 5）"));

        Assert.Contains("中を見られなかった", Line("隠しデスクトップ").Text);
    }

    // ---- G. 合成入力 ----

    private static InputObservation Observation(params InputSecond[] seconds) =>
        new(Now.AddSeconds(-30), Now, seconds);

    [Fact]
    public void 見張っていなければ_そう出す()
    {
        var line = Line("合成入力");
        Assert.Equal(StatusLevel.Normal, line.Level);
        Assert.Equal("見張っていない", line.Text);
    }

    [Fact]
    public void 合成入力が無ければ_無かったと出す()
    {
        _facts.Input = Observation(new InputSecond(Now.AddSeconds(-5), 4, 0, 30, 0));

        var line = Line("合成入力");
        Assert.Equal(StatusLevel.Normal, line.Level);
        Assert.Contains("合成入力は無かった", line.Text);
    }

    [Fact]
    public void 合成入力だけなら_注意に留める()
    {
        // スクリーン キーボードや AutoHotkey も作る。合成入力だけでは警告しない
        _facts.Input = Observation(
            new InputSecond(Now.AddSeconds(-5), 6, 6, 4, 4),
            new InputSecond(Now.AddSeconds(-4), 4, 4, 0, 0));

        var line = Line("合成入力");
        Assert.Equal(StatusLevel.Notice, line.Level);
        Assert.Contains("14 件（キー 10・マウス 4、多い 1 秒で 10 件）", line.Text);
    }

    [Fact]
    public void 遠隔操作ソフトが動いているときに来ていれば_警告する()
    {
        Process(10, @"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", new SignatureInfo(SignatureStatus.ValidOther, "AnyDesk Software GmbH"));
        _facts.Input = Observation(new InputSecond(Now.AddSeconds(-5), 2, 2, 0, 0));

        var line = Line("合成入力");
        Assert.Equal(StatusLevel.Warning, line.Level);
        Assert.Contains("AnyDesk", line.Text);
        Assert.NotNull(line.Detail);
    }

    [Fact]
    public void 件数の合計()
    {
        var observation = Observation(
            new InputSecond(Now.AddSeconds(-2), 10, 3, 50, 0),
            new InputSecond(Now.AddSeconds(-1), 5, 0, 20, 7));
        Assert.Equal(3, observation.InjectedKeys);
        Assert.Equal(7, observation.InjectedMouse);
        Assert.Equal(85 - 10, observation.Physical);
        Assert.Equal(7, observation.PeakInjectedPerSecond);
    }

    [Fact]
    public void 結果の型は件数しか持たない()
    {
        // キーの中身（仮想キー コード・スキャン コード）を持つ欄を足していないことを、型で確かめる
        var names = typeof(InputSecond).GetProperties().Select(p => p.Name).ToHashSet();
        Assert.Equal(new HashSet<string> { "SecondUtc", "Keys", "InjectedKeys", "Mouse", "InjectedMouse", "Injected" }, names);
    }

    [Fact]
    public void 単独で高になる兆候は無い_手順_3() =>
        Assert.True(new ScoringRules().HiddenDesktopWindow < new ScoringRules().HighFrom);
}
