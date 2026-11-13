using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using PCMonitor.Core.Collectors;

namespace PCMonitor.Core.Monitoring;

/// <summary>
/// キー入力に関わる API の呼び出しを見張る（設計書 §11.5）。
///
/// Microsoft-Windows-Win32k の監査イベント（キーワード AuditApiCalls）を受け取る。
/// ほかの点検と違い、「その瞬間を写す」のではなく「見張っている間に起きたこと」しか分からない。
/// すでに設置されているフックは出てこない。セッションを始められるのは管理者だけ。
///
/// 受け取るのは「誰が、どの API を、どういう形で呼んだか」で、キー入力そのものは流れてこない。
/// </summary>
public sealed class KeyApiMonitor : IDisposable
{
    public static readonly Guid Win32kProvider = new("8c416c79-d49b-4f01-a467-e56d3aa8234c");
    private const ulong AuditApiCalls = 0x400;
    private const string SessionName = "PCMonitorKeyApi";
    private const int MaxCalls = 5000;

    private readonly object _gate = new();
    private readonly List<KeyApiCall> _calls = new();
    private TraceEventSession? _session;
    private Task? _pump;
    private DevicePaths? _devices;

    private static readonly Lazy<(bool Supported, string Reason)> Support = new(DetectSupport);

    /// <summary>
    /// この Windows で、キー入力 API の監視が使えるか。権限は見ない（管理者かどうかは別に確かめる）。
    ///
    /// 見るのは、Win32k のプロバイダーが、監査のイベント（1001・1002）を定義しているか。
    /// 定義はプロバイダーごとに Windows に登録されていて、管理者でなくても読める。
    /// 2026-11-13 に Windows 11 25H2 で確かめた形が前提で、古い Windows には無いことがある。
    /// </summary>
    public static (bool Supported, string Reason) CheckSupport() => Support.Value;

    private static (bool, string) DetectSupport()
    {
        string? manifest;
        try
        {
            manifest = RegisteredTraceEventParser.GetManifestForRegisteredProvider(Win32kProvider);
        }
        catch (Exception ex)
        {
            return (false, $"Win32k のイベントの定義を読めなかった（{ex.GetType().Name}: {ex.Message}）");
        }
        if (string.IsNullOrEmpty(manifest))
            return (false, "Win32k のイベントの定義が、この Windows に登録されていない");

        var hook = HasAuditEvent(manifest, 1002);
        var rawInput = HasAuditEvent(manifest, 1001);
        if (hook && rawInput) return (true, "");
        return (false, hook || rawInput
            ? "Win32k の監査のイベントが一部しか定義されていない（フックの設置か、生入力の登録のどちらかを見られない）"
            : "Win32k の監査のイベント（AuditApiCalls）が定義されていない。古い Windows では、この仕組みが無い");
    }

    /// <summary>マニフェストに、その番号の監査のイベントがあるか。属性の並びは決め打ちしない。</summary>
    internal static bool HasAuditEvent(string manifest, int id)
    {
        foreach (System.Text.RegularExpressions.Match match in
                 System.Text.RegularExpressions.Regex.Matches(manifest, @"<event\s[^>]*>", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
        {
            var element = match.Value;
            if (element.Contains($"value=\"{id}\"", StringComparison.OrdinalIgnoreCase)
                && element.Contains("AuditApiCalls", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public bool IsRunning => _session is not null;
    public DateTime? StartedUtc { get; private set; }
    public DateTime? StoppedUtc { get; private set; }

    /// <summary>受け取るたびに知らせる（受け取りのスレッドから呼ばれる）。</summary>
    public event Action<KeyApiCall>? CallObserved;

    public int Count
    {
        get { lock (_gate) return _calls.Count; }
    }

    public IReadOnlyList<KeyApiCall> Snapshot()
    {
        lock (_gate) return _calls.ToList();
    }

    /// <summary>スキャンに渡す形。一度も見張っていなければ null。</summary>
    public KeyApiObservation? Observation() =>
        StartedUtc is { } started ? new KeyApiObservation(started, StoppedUtc, Snapshot()) : null;

    /// <summary>見張りを始める。管理者でなければ <see cref="UnauthorizedAccessException"/>。</summary>
    public void Start()
    {
        if (IsRunning) return;
        if (!Scanner.IsElevated())
            throw new UnauthorizedAccessException("キー入力 API の監視は、管理者として起動したときだけ始められます。");
        var (supported, reason) = CheckSupport();
        if (!supported)
            throw new PlatformNotSupportedException("この Windows では、キー入力 API の監視を使えません。\n" + reason);

        // 前回、片付ける前に落ちていたら、同じ名前のセッションが残っている
        TraceEventSession.GetActiveSession(SessionName)?.Stop(true);

        _devices = DevicePaths.Create();
        var session = new TraceEventSession(SessionName) { StopOnDispose = true };
        try
        {
            session.EnableProvider(Win32kProvider, TraceEventLevel.Informational, AuditApiCalls);
            session.Source.Dynamic.All += OnEvent;
        }
        catch
        {
            session.Dispose();
            throw;
        }

        lock (_gate) _calls.Clear();
        _session = session;
        StartedUtc = DateTime.UtcNow;
        StoppedUtc = null;
        // Process() は、セッションが止まるまで戻らない
        _pump = Task.Run(() => session.Source.Process());
    }

    public void Stop()
    {
        var session = _session;
        if (session is null) return;
        _session = null;
        StoppedUtc = DateTime.UtcNow;
        try
        {
            session.Stop(true);
            _pump?.Wait(TimeSpan.FromSeconds(5));
        }
        catch (Exception ex) when (ex is AggregateException or InvalidOperationException or System.Runtime.InteropServices.COMException)
        {
            // 止めるときの失敗で、集めたものまで失わない
        }
        finally
        {
            session.Dispose();
            _pump = null;
        }
    }

    public void Dispose() => Stop();

    /// <summary>
    /// 記録済みのファイル（.etl）から読む。管理者でなくても読めるので、読み取りの確認に使う。
    /// 記録のときのプロセスはもう居ないので、実行ファイルは分かる範囲でしか付かない。
    /// </summary>
    public static IReadOnlyList<KeyApiCall> ReadFile(string etlPath)
    {
        var devices = DevicePaths.Create();
        var calls = new List<KeyApiCall>();
        using var source = new ETWTraceEventSource(etlPath);
        source.Dynamic.All += data =>
        {
            if (ToCall(data, devices, resolveLiveProcess: false) is { } call) calls.Add(call);
        };
        source.Process();

        // 実行ファイルが分からなかった呼び出しに、同じプロセスのほかの呼び出しで分かったものを当てる
        var known = calls.Where(c => c.Path is not null)
            .GroupBy(c => c.Pid)
            .ToDictionary(g => g.Key, g => g.First().Path);
        return calls.Select(c => c.Path is null && known.TryGetValue(c.Pid, out var path) ? c with { Path = path } : c).ToList();
    }

    private void OnEvent(TraceEvent data)
    {
        if (_devices is null || ToCall(data, _devices, resolveLiveProcess: true) is not { } call) return;
        lock (_gate)
        {
            // 同じ呼び出しを延々と繰り返すプロセスに、覚えておく枠を使い切らせない
            if (_calls.Count >= MaxCalls) _calls.RemoveAt(0);
            _calls.Add(call);
        }
        CallObserved?.Invoke(call);
    }

    private static KeyApiCall? ToCall(TraceEvent data, DevicePaths devices, bool resolveLiveProcess)
    {
        if (data.ProviderGuid != Win32kProvider) return null;
        try
        {
            var pid = data.ProcessID;
            (KeyApiWeight Weight, string Description)? classified;
            string? fallbackPath = null;

            switch ((int)data.ID)
            {
                case 1002: // SetWindowsHookEx
                    classified = KeyApiClassifier.Hook(
                        (int)Number(data, "FilterType"),
                        data.PayloadByName("pstrLib") as string);
                    break;

                case 1001: // RegisterRawInputDevices
                    var module = data.PayloadByName("ThreadStartAddressMappedModuleName") as string;
                    var queried = Number(data, "ThreadStartAddressQueryResult") == 0;
                    classified = KeyApiClassifier.RawInput(
                        (int)Number(data, "UsagePage"),
                        (int)Number(data, "Usage"),
                        (uint)Number(data, "Flags"),
                        Number(data, "ReturnValue") != 0,
                        queried ? (uint?)Number(data, "ThreadStartAddressVadRegionType") : null);
                    if (Number(data, "ProcessId") is > 0 and var owner) pid = (int)owner;
                    // 記録を読み直すときは、プロセスがもう居ない。スレッドが EXE から始まっていれば、それを本体とみなす
                    if (!string.IsNullOrEmpty(module) && module.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        fallbackPath = devices.ToDrivePath(module);
                    break;

                case 1003: // GetAsyncKeyState（前面でないプロセスから）
                    classified = KeyApiClassifier.Polling(
                        Number(data, "MsSinceLastKeyEvent"),
                        Number(data, "BackgroundCallCount"));
                    if (Number(data, "PID") is > 0 and var caller) pid = (int)caller;
                    break;

                default:
                    // 1000（SetWinEventHook）は、キー入力とは関係が無い
                    return null;
            }

            if (classified is not { } result) return null;

            // プロセスはすぐ終わるかもしれない。受け取ったその場で、実行ファイルを確かめておく
            var path = (resolveLiveProcess ? ProcessCollector.TryGetImagePath(pid) : null) ?? fallbackPath;
            return new KeyApiCall(data.TimeStamp.ToUniversalTime(), pid, data.ThreadID, path, result.Weight, result.Description);
        }
        catch (Exception ex) when (ex is InvalidCastException or FormatException or OverflowException or ArgumentException)
        {
            // 版が変わって項目の形が違っていても、見張り全体は止めない
            return null;
        }
    }

    private static long Number(TraceEvent data, string name) =>
        data.PayloadByName(name) is { } value ? Convert.ToInt64(value) : 0;
}
