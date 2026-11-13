using PCMonitor.Core.Model;
using ReactiveUI;

namespace PCMonitor.Wpf.ViewModels;

/// <summary>一覧の 1 行。Finding を画面向けの文字列にして持つ。</summary>
public sealed class FindingRow : ReactiveObject
{
    private bool _isAllowed;

    public FindingRow(Finding finding)
    {
        Finding = finding;
        _isAllowed = finding.IsAllowed;

        Evidence = finding.Indicators
            .Select(i => i.Points > 0 ? $"+{i.Points}　{i.Evidence}" : $"情報　{i.Evidence}")
            .ToList();

        Registrations = finding.Persistence
            .Select(e => $"{e.KindDisplay}「{e.Name}」　{e.Location}"
                         + (e.Note is null ? "" : $"　［{e.Note}］")
                         + $"\n　　{e.Command.Raw}")
            .ToList();

        Processes = finding.Processes
            .Select(p => $"PID {p.Pid}（親 {p.ParentPid}、セッション {p.SessionId}）"
                         + (p.HasVisibleWindow ? "　ウィンドウあり" : "")
                         + (string.IsNullOrWhiteSpace(p.CommandLine) ? "" : $"\n　　{p.CommandLine}"))
            .ToList();

        Endpoints = finding.Endpoints
            .Select(e => $"{e.Display}（PID {e.Pid}）")
            .Distinct()
            .ToList();

        LoadedBy = finding.LoadedBy
            .GroupBy(h => (h.ProcessName, h.Publisher))
            .Select(g => $"{g.Key.ProcessName}（{g.Key.Publisher ?? "発行元不明"}）　PID {string.Join("、", g.Select(h => h.Pid))}")
            .ToList();
    }

    public Finding Finding { get; }

    public string Name => Finding.Name;
    public int Score => Finding.Score;
    public RiskLevel Level => Finding.Level;
    public string LevelDisplay => Finding.LevelDisplay;
    public string SignatureDisplay => Finding.Signature.Display;
    public string Summary => Finding.IndicatorSummary;
    public string NewMark => Finding.IsNew ? "新規" : "";

    public string PathDisplay => Finding.Path ?? "（ファイルにたどり着かない登録）";
    public string Sha256Display => Finding.Sha256 ?? "（取得できず）";
    public string CreatedDisplay => Finding.FileCreatedUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "—";

    public string SignerDisplay
    {
        get
        {
            var signature = Finding.Signature;
            var text = signature.Display;
            if (signature.FromCatalog) text += "　［カタログ署名］";
            if (!string.IsNullOrEmpty(signature.Detail)) text += $"　{signature.Detail}";
            return text;
        }
    }

    public bool HasFile => Finding.Path is not null;
    public bool CanAllow => !string.IsNullOrEmpty(Finding.Sha256);

    public IReadOnlyList<string> Evidence { get; }
    public IReadOnlyList<string> Registrations { get; }
    public IReadOnlyList<string> Processes { get; }
    public IReadOnlyList<string> Endpoints { get; }
    public IReadOnlyList<string> LoadedBy { get; }

    public bool HasLoadedBy => LoadedBy.Count > 0;
    public bool HasRegistrations => Registrations.Count > 0;
    public bool HasProcesses => Processes.Count > 0;
    public bool HasEndpoints => Endpoints.Count > 0;

    public bool IsAllowed
    {
        get => _isAllowed;
        set => this.RaiseAndSetIfChanged(ref _isAllowed, value);
    }

    public bool Matches(string text) =>
        Name.Contains(text, StringComparison.OrdinalIgnoreCase)
        || (Finding.Path?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false)
        || Summary.Contains(text, StringComparison.OrdinalIgnoreCase)
        || (Finding.Signature.Publisher?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false)
        || (Finding.Sha256?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false);
}
