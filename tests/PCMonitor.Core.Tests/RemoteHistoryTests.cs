using PCMonitor.Core.Collectors;
using PCMonitor.Core.Model;
using PCMonitor.Core.Remote;
using PCMonitor.Core.Scoring;

namespace PCMonitor.Core.Tests;

/// <summary>第 3 段階の手順 2（設計書 §16.2 D・E）。</summary>
public class RemoteHistoryTests
{
    private const int Session = 1;
    private static readonly DateTime Now = new(2026, 11, 15, 0, 0, 0, DateTimeKind.Utc);

    private readonly Dictionary<string, FileFacts> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly ScanFacts _facts = new();

    private void File(string path, SignatureInfo signature, bool writable = false) =>
        _files[path] = new FileFacts(path, true, Now.AddYears(-1), false, "AA", signature, writable);

    private List<Finding> Score() =>
        new Scorer(new ScoringRules(), @"C:\Windows").Score(
            _facts, path => _files.TryGetValue(path, out var file) ? file : FileFacts.Missing(path), Now, Session);

    private StatusLine Line(string label) =>
        CurrentStateBuilder.Build(_facts, Score(), Session).Single(l => l.Label == label);

    private static int Points(Finding finding, IndicatorKind kind) =>
        finding.Indicators.Where(i => i.Kind == kind).Sum(i => i.Points);

    // ---- イベントの読み取り ----

    // この PC の LocalSessionManager 21 の形（2026-11-15）。手元のログオンは Address が訳されて「ローカル」になる
    private const string LocalLogon = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><EventID>21</EventID><Computer>Kuro</Computer></System>
          <UserData>
            <EventXML xmlns="Event_NS">
              <User>Kuro\keiji</User><SessionID>4</SessionID><Address>ローカル</Address>
            </EventXML>
          </UserData>
        </Event>
        """;

    private const string RemoteAuth = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><EventID>1149</EventID></System>
          <UserData>
            <EventXML xmlns="Event_NS"><Param1>alice</Param1><Param2>PC</Param2><Param3>203.0.113.7</Param3></EventXML>
          </UserData>
        </Event>
        """;

    private const string SecurityLogon = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><EventID>4624</EventID><Computer>PC</Computer></System>
          <EventData>
            <Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">PC</Data>
            <Data Name="LogonType">10</Data><Data Name="IpAddress">198.51.100.2</Data>
          </EventData>
        </Event>
        """;

    [Fact]
    public void UserData_の要素を名前で読む()
    {
        var fields = RemoteHistoryCollector.Fields(LocalLogon);
        Assert.Equal(@"Kuro\keiji", fields["User"]);
        Assert.Equal("4", fields["SessionID"]);
        Assert.Equal("ローカル", fields["Address"]);
        // System の中身は混ぜない
        Assert.False(fields.ContainsKey("Computer"));
    }

    [Fact]
    public void EventData_の_Data_を_Name_で読む()
    {
        var fields = RemoteHistoryCollector.Fields(SecurityLogon);
        Assert.Equal("10", fields["LogonType"]);
        Assert.Equal("198.51.100.2", fields["IpAddress"]);
        Assert.False(fields.ContainsKey("Computer"));
    }

    [Fact]
    public void Param_の形も読む() =>
        Assert.Equal("203.0.113.7", RemoteHistoryCollector.Fields(RemoteAuth)["Param3"]);

    [Theory]
    [InlineData("192.168.1.20", true)]
    [InlineData("fe80::1", true)]
    [InlineData("LOCAL", false)]
    [InlineData("ローカル", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void 接続元が_IP_アドレスのときだけ遠隔とする(string? address, bool remote) =>
        Assert.Equal(remote, RemoteHistoryCollector.IsIpAddress(address));

    // ---- 遠隔接続の履歴の帯（D） ----

    [Fact]
    public void 記録が無くても_入られていないとは書かない()
    {
        _facts.UnreadLogs.Add("Security（管理者なら見られる）");

        var line = Line("遠隔接続の履歴（30 日）");
        Assert.Equal(StatusLevel.Normal, line.Level);
        Assert.Contains("見られた記録の中には無い", line.Text);
        Assert.Contains("Security", line.Text);
        Assert.Contains("意味しない", line.Detail);
    }

    [Fact]
    public void 記録があれば_接続元ごとにまとめて注意する()
    {
        _facts.RemoteLogons.Add(new RemoteLogon(Now.AddDays(-2), "ログオン", @"PC\alice", "203.0.113.7", 3, "LocalSessionManager 21"));
        _facts.RemoteLogons.Add(new RemoteLogon(Now.AddDays(-1), "再接続", @"PC\alice", "203.0.113.7", 3, "LocalSessionManager 25"));
        _facts.RemoteLogons.Add(new RemoteLogon(Now.AddHours(-3), "認証成功", @"PC\bob", "198.51.100.2", null, "RemoteConnectionManager 1149"));

        var line = Line("遠隔接続の履歴（30 日）");
        Assert.Equal(StatusLevel.Notice, line.Level);
        Assert.Contains("3 件", line.Text);
        Assert.Contains("203.0.113.7（2 件", line.Text);
        // 新しい接続元が先
        Assert.True(line.Text.IndexOf("198.51.100.2", StringComparison.Ordinal) < line.Text.IndexOf("203.0.113.7", StringComparison.Ordinal));
    }

    // ---- カメラ・マイク（E） ----

    private void Usage(CaptureDevice device, string? path, DateTime start, DateTime? stop, string app = "app") =>
        _facts.DeviceUsages.Add(new DeviceUsage(device, path ?? app, path, start, stop));

    [Fact]
    public void 止めた記録が無ければ使用中とみなす()
    {
        Assert.True(new DeviceUsage(CaptureDevice.Camera, "a", null, Now, null).InUse);
        Assert.True(new DeviceUsage(CaptureDevice.Camera, "a", null, Now, Now.AddHours(-1)).InUse);
        Assert.False(new DeviceUsage(CaptureDevice.Camera, "a", null, Now, Now.AddMinutes(5)).InUse);
    }

    [Fact]
    public void 署名の無いプログラムがマイクを使っていたら_30_点()
    {
        const string path = @"C:\Users\u\AppData\Local\rec.exe";
        File(path, new SignatureInfo(SignatureStatus.None), writable: true);
        Usage(CaptureDevice.Microphone, path, Now.AddDays(-3), Now.AddDays(-3).AddMinutes(10));

        var finding = Assert.Single(Score());
        Assert.Equal(30, Points(finding, IndicatorKind.CaptureDeviceUnsigned));
        Assert.True(finding.Sources.HasFlag(FindingSources.Device));
        // 未署名 30・書き込める場所 20・撮影録音 30
        Assert.Equal(80, finding.Score);
    }

    [Fact]
    public void 署名のあるアプリが使っただけなら点を付けず_記録だけ出す()
    {
        const string path = @"C:\Program Files\Meet\meet.exe";
        File(path, new SignatureInfo(SignatureStatus.ValidOther, "Example Inc."));
        Usage(CaptureDevice.Camera, path, Now.AddDays(-1), Now.AddDays(-1).AddHours(1));

        var finding = Assert.Single(Score());
        Assert.Equal(0, finding.Score);
        Assert.Contains(finding.Indicators, i => i.Kind == IndicatorKind.CaptureDeviceUse);
    }

    [Fact]
    public void ファイルの無い記録には_署名の点を付けない()
    {
        Usage(CaptureDevice.Camera, @"C:\Gone\old.exe", Now.AddDays(-100), Now.AddDays(-100));

        var finding = Assert.Single(Score());
        Assert.Equal(0, finding.Score);
        Assert.Contains(finding.Indicators, i => i.Evidence.Contains("記録に残っている"));
    }

    [Fact]
    public void ストア_アプリの記録は候補にしない()
    {
        Usage(CaptureDevice.Camera, null, Now.AddDays(-1), Now.AddDays(-1), "Microsoft.WindowsCamera_8wekyb3d8bbwe");
        Assert.Empty(Score());
    }

    [Fact]
    public void いま使っているアプリを帯に出す()
    {
        const string path = @"C:\Program Files\Meet\meet.exe";
        File(path, new SignatureInfo(SignatureStatus.ValidOther, "Example Inc."));
        Usage(CaptureDevice.Camera, path, Now.AddMinutes(-5), null);

        var line = Line("カメラ・マイク");
        Assert.Equal(StatusLevel.Notice, line.Level);
        Assert.Contains("meet.exe（カメラ）", line.Text);
    }

    [Fact]
    public void 署名の無いプログラムがいま使っていたら警告する()
    {
        const string path = @"C:\Users\u\AppData\Local\rec.exe";
        File(path, new SignatureInfo(SignatureStatus.None), writable: true);
        Usage(CaptureDevice.Microphone, path, Now.AddMinutes(-5), null);

        var line = Line("カメラ・マイク");
        Assert.Equal(StatusLevel.Warning, line.Level);
        Assert.Contains("署名なし", line.Text);
        Assert.NotNull(line.Detail);
    }

    [Fact]
    public void 記録が無ければ_使った記録も無いと出す()
    {
        var line = Line("カメラ・マイク");
        Assert.Equal(StatusLevel.Normal, line.Level);
        Assert.Contains("使った記録も無い", line.Text);
    }

    [Fact]
    public void 単独で高になる兆候は無い_手順_2() =>
        Assert.True(new ScoringRules().CaptureDeviceUnsigned < new ScoringRules().HighFrom);

    // ---- レジストリの値の読み方 ----

    [Fact]
    public void NonPackaged_の名前をパスに戻す() =>
        Assert.Equal(@"C:\Users\u\AppData\Roaming\Zoom\bin\Zoom.exe",
            CaptureDeviceCollector.ToPath(@"C:#Users#u#AppData#Roaming#Zoom#bin#Zoom.exe"));

    [Fact]
    public void FILETIME_の_0_は時刻なしとする()
    {
        Assert.Null(CaptureDeviceCollector.FromFileTime(0L));
        Assert.Null(CaptureDeviceCollector.FromFileTime(null));
        // この PC にある値（Zoom のカメラ、2026-06-11 ごろ）
        var time = CaptureDeviceCollector.FromFileTime(134256312546424379L);
        Assert.Equal(new DateTime(2026, 6, 11), time!.Value.Date);
    }
}
