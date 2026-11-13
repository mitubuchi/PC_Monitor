using System.ComponentModel;
using System.Diagnostics;
using System.Reactive;
using System.Reactive.Linq;
using System.Windows;
using PCMonitor.Core;
using PCMonitor.Core.Allowlist;
using PCMonitor.Core.Model;
using PCMonitor.Core.Reports;
using ReactiveUI;

namespace PCMonitor.Wpf.ViewModels;

public sealed class MainViewModel : ReactiveObject
{
    private readonly Scanner _scanner = new();
    private List<FindingRow> _all = new();
    private ScanResult? _result;
    private CancellationTokenSource? _cancel;

    private bool _isScanning;
    private string _progress = "［スキャン］を押すと点検を始めます。";
    private string _summary = "";
    private bool _showAllowed;
    private int _kindFilter;
    private int _levelFilter;
    private string _searchText = "";
    private IReadOnlyList<FindingRow> _rows = Array.Empty<FindingRow>();
    private FindingRow? _selected;
    private IReadOnlyList<ScanNote> _notes = Array.Empty<ScanNote>();

    public MainViewModel()
    {
        IsElevated = Scanner.IsElevated();

        var idle = this.WhenAnyValue(x => x.IsScanning, scanning => !scanning);
        var scanning = this.WhenAnyValue(x => x.IsScanning);
        var hasResult = this.WhenAnyValue(x => x.Rows, x => x.IsScanning, (rows, busy) => _result is not null && !busy);
        var hasFile = this.WhenAnyValue(x => x.Selected, row => row is { HasFile: true });
        var hasHash = this.WhenAnyValue(x => x.Selected, row => row is { CanAllow: true });

        ScanCommand = ReactiveCommand.CreateFromTask(ScanAsync, idle);
        CancelCommand = ReactiveCommand.Create(() => _cancel?.Cancel(), scanning);
        RestartAsAdminCommand = ReactiveCommand.Create(RestartAsAdmin, idle.Select(ok => ok && !IsElevated));
        OpenLocationCommand = ReactiveCommand.Create(OpenLocation, hasFile);
        CopyHashCommand = ReactiveCommand.Create(CopyHash, hasHash);
        ToggleAllowCommand = ReactiveCommand.Create(ToggleAllow, hasHash);
        ExportCsvCommand = ReactiveCommand.Create(ExportCsv, hasResult);
        ExportJsonCommand = ReactiveCommand.Create(ExportJson, hasResult);

        foreach (var command in new IHandleObservableErrors[]
                 {
                     ScanCommand, CancelCommand, RestartAsAdminCommand, OpenLocationCommand,
                     CopyHashCommand, ToggleAllowCommand, ExportCsvCommand, ExportJsonCommand,
                 })
        {
            command.ThrownExceptions.Subscribe(ex => ShowError(ex.Message));
        }

        this.WhenAnyValue(x => x.ShowAllowed, x => x.KindFilter, x => x.LevelFilter)
            .Skip(1)
            .Subscribe(_ => ApplyFilter());
        this.WhenAnyValue(x => x.SearchText)
            .Skip(1)
            .Throttle(TimeSpan.FromMilliseconds(250), RxSchedulers.MainThreadScheduler)
            .Subscribe(_ => ApplyFilter());
    }

    /// <summary>保存先を選ばせる。画面側が差し込む（既定のファイル名、フィルター → パス）。</summary>
    public Func<string, string, string?>? PickSavePath { get; set; }

    public bool IsElevated { get; }
    public string Title => "PCMonitor — 常駐と通信の点検" + (IsElevated ? "（管理者）" : "");
    public string DataDirectory => _scanner.Paths.Directory;

    public ReactiveCommand<Unit, Unit> ScanCommand { get; }
    public ReactiveCommand<Unit, Unit> CancelCommand { get; }
    public ReactiveCommand<Unit, Unit> RestartAsAdminCommand { get; }
    public ReactiveCommand<Unit, Unit> OpenLocationCommand { get; }
    public ReactiveCommand<Unit, Unit> CopyHashCommand { get; }
    public ReactiveCommand<Unit, Unit> ToggleAllowCommand { get; }
    public ReactiveCommand<Unit, Unit> ExportCsvCommand { get; }
    public ReactiveCommand<Unit, Unit> ExportJsonCommand { get; }

    public bool IsScanning
    {
        get => _isScanning;
        private set => this.RaiseAndSetIfChanged(ref _isScanning, value);
    }

    public string Progress
    {
        get => _progress;
        private set => this.RaiseAndSetIfChanged(ref _progress, value);
    }

    public string Summary
    {
        get => _summary;
        private set => this.RaiseAndSetIfChanged(ref _summary, value);
    }

    public bool ShowAllowed
    {
        get => _showAllowed;
        set => this.RaiseAndSetIfChanged(ref _showAllowed, value);
    }

    /// <summary>0: すべて、1: 常駐、2: プロセス、3: 通信</summary>
    public int KindFilter
    {
        get => _kindFilter;
        set => this.RaiseAndSetIfChanged(ref _kindFilter, value);
    }

    /// <summary>0: すべて、1: 低以上、2: 中以上、3: 高のみ</summary>
    public int LevelFilter
    {
        get => _levelFilter;
        set => this.RaiseAndSetIfChanged(ref _levelFilter, value);
    }

    public string SearchText
    {
        get => _searchText;
        set => this.RaiseAndSetIfChanged(ref _searchText, value);
    }

    public IReadOnlyList<FindingRow> Rows
    {
        get => _rows;
        private set => this.RaiseAndSetIfChanged(ref _rows, value);
    }

    public FindingRow? Selected
    {
        get => _selected;
        set => this.RaiseAndSetIfChanged(ref _selected, value);
    }

    public IReadOnlyList<ScanNote> Notes
    {
        get => _notes;
        private set => this.RaiseAndSetIfChanged(ref _notes, value);
    }

    // ---- スキャン ----

    private async Task ScanAsync()
    {
        _cancel = new CancellationTokenSource();
        IsScanning = true;
        try
        {
            // Progress<T> は作ったスレッド（画面）へ戻して知らせる
            var progress = new Progress<string>(text => Progress = text);
            var token = _cancel.Token;
            var result = await Task.Run(() => _scanner.Scan(progress, token), token);

            _result = result;
            _all = result.Findings.Select(f => new FindingRow(f)).ToList();
            Notes = result.Notes;
            Summarize();
            ApplyFilter();
            Progress = $"点検が終わりました（{result.StartedUtc.ToLocalTime():HH:mm:ss}、{result.Elapsed.TotalSeconds:F1} 秒）。";
        }
        catch (OperationCanceledException)
        {
            Progress = "点検を中止しました。前の結果はそのまま残しています。";
        }
        finally
        {
            IsScanning = false;
            _cancel.Dispose();
            _cancel = null;
        }
    }

    private void Summarize()
    {
        if (_result is null) return;
        int Count(RiskLevel level) => _all.Count(r => r.Level == level && !r.IsAllowed);

        Summary = $"高 {Count(RiskLevel.High)}　中 {Count(RiskLevel.Medium)}　低 {Count(RiskLevel.Low)}　情報 {Count(RiskLevel.Info)}"
                  + $"　｜　許可済み {_all.Count(r => r.IsAllowed)}"
                  + (_result.HasPrevious
                      ? $"　｜　前回から増えた項目 {_result.Findings.Count(f => f.IsNew)}"
                      : "　｜　前回の結果なし（次回から差分が出ます）")
                  + $"　｜　{(_result.Elevated ? "管理者の権限" : "通常の権限")}で点検";
    }

    private void ApplyFilter()
    {
        IEnumerable<FindingRow> rows = _all;

        if (!ShowAllowed) rows = rows.Where(r => !r.IsAllowed);

        var source = KindFilter switch
        {
            1 => FindingSources.Persistence,
            2 => FindingSources.Process,
            3 => FindingSources.Network,
            _ => FindingSources.None,
        };
        if (source != FindingSources.None) rows = rows.Where(r => r.Finding.Sources.HasFlag(source));

        var minimum = LevelFilter switch
        {
            1 => RiskLevel.Low,
            2 => RiskLevel.Medium,
            3 => RiskLevel.High,
            _ => RiskLevel.Info,
        };
        rows = rows.Where(r => r.Level >= minimum);

        var text = SearchText.Trim();
        if (text.Length > 0) rows = rows.Where(r => r.Matches(text));

        var keep = Selected;
        var list = rows.ToList();
        Rows = list;
        Selected = keep is not null && list.Contains(keep) ? keep : null;
    }

    // ---- 選んだ項目への操作（壊す操作は置かない） ----

    private void OpenLocation()
    {
        if (Selected?.Finding.Path is not { } path) return;
        // エクスプローラーで、そのファイルを選んだ状態で開く。ファイル自体は実行しない
        Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = false });
    }

    private void CopyHash()
    {
        if (Selected?.Finding.Sha256 is { } hash) Clipboard.SetText(hash);
    }

    private void ToggleAllow()
    {
        if (Selected is not { } row) return;

        var store = new AllowlistStore(_scanner.Paths.Allowlist);
        if (row.IsAllowed)
        {
            store.Remove(row.Finding);
        }
        else if (!store.Add(row.Finding))
        {
            ShowError("ハッシュを取れなかった項目は、許可リストに入れられません（中身が変わっても気づけなくなるため）。");
            return;
        }

        row.IsAllowed = row.Finding.IsAllowed;
        Summarize();
        ApplyFilter();
    }

    // ---- 書き出し ----

    private void ExportCsv()
    {
        var path = PickSavePath?.Invoke($"pcmonitor-{DateTime.Now:yyyyMMdd-HHmmss}.csv", "CSV (*.csv)|*.csv");
        if (path is null) return;
        // いま一覧に出ている行（絞り込んだ結果）を書き出す
        ReportWriter.WriteCsv(path, Rows.Select(r => r.Finding));
        Progress = $"CSV を書き出しました: {path}";
    }

    private void ExportJson()
    {
        if (_result is null) return;
        var path = PickSavePath?.Invoke($"pcmonitor-{DateTime.Now:yyyyMMdd-HHmmss}.json", "JSON (*.json)|*.json");
        if (path is null) return;
        // 絞り込みにかかわらず、点検の結果すべてを書き出す
        ReportWriter.WriteJson(path, _result);
        Progress = $"JSON を書き出しました: {path}";
    }

    // ---- 権限 ----

    private void RestartAsAdmin()
    {
        if (Environment.ProcessPath is not { } exe) return;
        try
        {
            Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas" });
        }
        catch (Win32Exception)
        {
            // 昇格の確認で「いいえ」を選んだ。いまのまま続ける
            return;
        }
        Application.Current.Shutdown();
    }

    private static void ShowError(string message) =>
        MessageBox.Show(message, "PCMonitor", MessageBoxButton.OK, MessageBoxImage.Warning);
}
