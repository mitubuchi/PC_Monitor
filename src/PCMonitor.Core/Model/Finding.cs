using System.Text.Json.Serialization;

namespace PCMonitor.Core.Model;

public enum RiskLevel
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

[Flags]
public enum FindingSources
{
    None = 0,
    Persistence = 1,
    Process = 2,
    Network = 4,
    Module = 8,
    KeyApi = 16,
    /// <summary>遠隔操作ソフトとして照合表に当たった（設計書 §16）。</summary>
    Remote = 32,
}

public enum IndicatorKind
{
    SignatureInvalid,
    SystemNameWrongLocation,
    ViaScriptHost,
    SignatureNone,
    UnusualPersistence,
    UserWritableLocation,
    ListeningNonLoopback,
    HiddenOrDoubleExtension,
    Autostart,
    OutboundConnection,
    NoVisibleWindow,
    RecentlyCreated,

    // 第 2 段階
    UnusualParent,
    ModuleInSignedProcess,
    ModuleAcrossPublishers,
    WritableExecutableMemory,
    ExecutableMappedData,
    KeyInputCapture,
    KeyStatePolling,

    // 第 3 段階（設計書 §16.3）
    RemoteToolImpersonation,
    RemoteToolRecentlyInstalled,

    // ここから下は点を付けない「情報」
    MissingFile,
    Unresolved,
    AllowedButChanged,
    ExecutableMemoryNote,
    KeyApiNote,
    RemoteTool,
    RemoteToolSignerUnverified,
}

/// <summary>兆候。点だけでなく、人が確かめられる根拠の文を必ず持つ（設計書 §7）。</summary>
public sealed record Indicator(IndicatorKind Kind, int Points, string Label, string Evidence);

/// <summary>1 件の候補。同じ実行ファイルは常駐・プロセス・通信をまたいで 1 件にまとめる。</summary>
public sealed class Finding
{
    /// <summary>まとめる単位。ファイルなら <c>file:</c>＋小文字のパス。</summary>
    public required string Key { get; init; }
    public required string Name { get; init; }

    /// <summary>実行ファイルのパス。その場に書かれた命令の登録など、ファイルが無いものは null。</summary>
    public string? Path { get; init; }

    /// <summary>ファイルの SHA-256。ファイルが無い登録では、コマンドラインの文字列のハッシュ。</summary>
    public string? Sha256 { get; set; }
    public SignatureInfo Signature { get; set; } = SignatureInfo.Unknown;
    public DateTime? FileCreatedUtc { get; set; }

    public List<Indicator> Indicators { get; } = new();
    public int Score { get; set; }
    public RiskLevel Level { get; set; }

    public List<PersistenceEntry> Persistence { get; } = new();
    public List<ProcessFact> Processes { get; } = new();
    public List<EndpointFact> Endpoints { get; } = new();

    /// <summary>この DLL を読み込んでいる、署名済みのプロセス。</summary>
    public List<ModuleHost> LoadedBy { get; } = new();

    /// <summary>見張っている間に、このプログラムが呼んだキー入力に関わる API。</summary>
    public List<Monitoring.KeyApiCall> KeyApiCalls { get; } = new();

    /// <summary>遠隔操作ソフトの照合表に当たったなら、その結果（設計書 §16.2 A）。</summary>
    public Remote.RemoteToolMatch? RemoteTool { get; set; }

    /// <summary>このプログラムのインストールの記録（Uninstall キー）。</summary>
    public List<InstalledProgram> Installations { get; } = new();

    /// <summary>許可リストに、同じパスと同じハッシュで登録されている。</summary>
    public bool IsAllowed { get; set; }

    /// <summary>前回の結果に無かった。</summary>
    public bool IsNew { get; set; }

    [JsonIgnore]
    public FindingSources Sources =>
        (Persistence.Count > 0 ? FindingSources.Persistence : FindingSources.None)
        | (Processes.Count > 0 ? FindingSources.Process : FindingSources.None)
        | (Endpoints.Count > 0 ? FindingSources.Network : FindingSources.None)
        | (LoadedBy.Count > 0 ? FindingSources.Module : FindingSources.None)
        | (KeyApiCalls.Count > 0 ? FindingSources.KeyApi : FindingSources.None)
        | (RemoteTool is not null ? FindingSources.Remote : FindingSources.None);

    [JsonIgnore]
    public string LevelDisplay => Level switch
    {
        RiskLevel.High => "高",
        RiskLevel.Medium => "中",
        RiskLevel.Low => "低",
        _ => "情報",
    };

    [JsonIgnore]
    public string IndicatorSummary => string.Join(" ", Indicators.Select(i => i.Label));
}

public sealed class ScanResult
{
    public DateTime StartedUtc { get; init; }
    public TimeSpan Elapsed { get; init; }
    public bool Elevated { get; init; }
    public bool Cancelled { get; init; }
    public List<Finding> Findings { get; init; } = new();
    public List<ScanNote> Notes { get; init; } = new();

    /// <summary>前回の結果があり、差分を付けられたか。</summary>
    public bool HasPrevious { get; init; }

    /// <summary>点検した PC の条件。書き出した結果を別の PC で見るときに、どこまで見られたかが分かるように残す。</summary>
    public MachineInfo? Machine { get; init; }

    /// <summary>
    /// 「いまの状態」の帯（設計書 §16.4）。遠隔操作は「いま起きているか」が大事なので、
    /// 危険度順の一覧に混ぜずに別に持つ。
    /// </summary>
    public List<StatusLine> CurrentState { get; init; } = new();
}

public enum StatusLevel
{
    /// <summary>何も無い、または問題の無い状態。</summary>
    Normal,
    /// <summary>有効になっている・入っている。それ自体は異常ではないが、覚えがあるかを確かめる。</summary>
    Notice,
    /// <summary>いま遠隔から操作されている・つながっている見込みがある。</summary>
    Warning,
}

/// <summary>「いまの状態」の 1 行。何も無くても「なし」と書いて出す（空にしない）。</summary>
public sealed record StatusLine(string Label, string Text, StatusLevel Level, string? Detail = null);
