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

    // ここから下は点を付けない「情報」
    MissingFile,
    Unresolved,
    AllowedButChanged,
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

    /// <summary>許可リストに、同じパスと同じハッシュで登録されている。</summary>
    public bool IsAllowed { get; set; }

    /// <summary>前回の結果に無かった。</summary>
    public bool IsNew { get; set; }

    [JsonIgnore]
    public FindingSources Sources =>
        (Persistence.Count > 0 ? FindingSources.Persistence : FindingSources.None)
        | (Processes.Count > 0 ? FindingSources.Process : FindingSources.None)
        | (Endpoints.Count > 0 ? FindingSources.Network : FindingSources.None)
        | (LoadedBy.Count > 0 ? FindingSources.Module : FindingSources.None);

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
}
