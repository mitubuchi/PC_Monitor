namespace PCMonitor.Core.Model;

// 収集した「事実」。ここでは判断しない（採点は Scoring が行う）。

/// <summary>署名の検証結果（設計書 §5.4 の 4 通り＋検証できず）。</summary>
public enum SignatureStatus
{
    /// <summary>ファイルが無い・読めないなどで検証できなかった。</summary>
    Unknown,
    ValidMicrosoft,
    ValidOther,
    /// <summary>署名はあるが検証に失敗した（改ざん・期限切れ・信頼されない発行元）。</summary>
    Invalid,
    None,
}

public sealed record SignatureInfo(SignatureStatus Status, string? Publisher = null, bool FromCatalog = false, string? Detail = null)
{
    public static readonly SignatureInfo Unknown = new(SignatureStatus.Unknown);

    public bool IsValid => Status is SignatureStatus.ValidMicrosoft or SignatureStatus.ValidOther;

    public string Display => Status switch
    {
        SignatureStatus.ValidMicrosoft => "有効（Microsoft）",
        SignatureStatus.ValidOther => $"有効（{Publisher ?? "発行元不明"}）",
        SignatureStatus.Invalid => "無効",
        SignatureStatus.None => "無し",
        _ => "検証できず",
    };
}

/// <summary>ファイルそのものについて分かったこと。</summary>
public sealed record FileFacts(
    string Path,
    bool Exists,
    DateTime? CreatedUtc,
    bool Hidden,
    string? Sha256,
    SignatureInfo Signature,
    bool UserWritable,
    string? Error = null)
{
    public static FileFacts Missing(string path) =>
        new(path, false, null, false, null, SignatureInfo.Unknown, false);
}

public enum PersistenceKind
{
    RunKey,
    StartupFolder,
    Service,
    Driver,
    ScheduledTask,
    WmiSubscription,
    Winlogon,
    AppInitDll,
    Ifeo,
}

/// <summary>
/// 登録されたコマンドラインを解いた結果。
/// 「実際に動くファイル」が <see cref="TargetPath"/>。たどれなければ <see cref="UnresolvedReason"/> に理由が入る。
/// </summary>
public sealed record ResolvedCommand(
    string Raw,
    string? HostPath,
    string? TargetPath,
    string? ScriptHost = null,
    bool Inline = false,
    bool Encoded = false,
    string? UnresolvedReason = null)
{
    /// <summary>ファイルではなく、その場に書かれた命令や URL を実行する登録か。</summary>
    public bool HasFileTarget => TargetPath is not null;
}

public sealed record PersistenceEntry(
    PersistenceKind Kind,
    string Location,
    string Name,
    ResolvedCommand Command,
    bool AutoStarts = true,
    string? Note = null)
{
    public string KindDisplay => Kind switch
    {
        PersistenceKind.RunKey => "Run キー",
        PersistenceKind.StartupFolder => "スタートアップ",
        PersistenceKind.Service => "サービス",
        PersistenceKind.Driver => "ドライバー",
        PersistenceKind.ScheduledTask => "タスク",
        PersistenceKind.WmiSubscription => "WMI イベント購読",
        PersistenceKind.Winlogon => "Winlogon",
        PersistenceKind.AppInitDll => "AppInit_DLLs",
        PersistenceKind.Ifeo => "IFEO",
        _ => Kind.ToString(),
    };

    /// <summary>ふつうは使われない常駐箇所か（値が入っているだけで確認に値する）。</summary>
    public bool IsUnusual => Kind is PersistenceKind.WmiSubscription or PersistenceKind.Winlogon
        or PersistenceKind.AppInitDll or PersistenceKind.Ifeo;
}

public sealed record ProcessFact(
    int Pid,
    int ParentPid,
    string Name,
    string? Path,
    string? CommandLine,
    bool HasVisibleWindow,
    int SessionId,
    DateTime? StartedUtc = null);

/// <summary>
/// 実行できるのに、実行イメージではない領域。
/// <see cref="Private"/> が true ならファイルの裏付けが無い。false ならファイルを写しただけの領域で、
/// <see cref="MappedFile"/> がそのファイル（ページ ファイルを写したものなら null）。
/// </summary>
public sealed record ExecutableRegion(long Address, long AllocationBase, long Size, bool Writable, bool Private, string? MappedFile);

/// <summary>ある DLL を読み込んでいるプロセス。</summary>
public sealed record ModuleHost(int Pid, string ProcessName, string? Publisher);

public sealed record EndpointFact(
    string Protocol,
    string LocalAddress,
    int LocalPort,
    string? RemoteAddress,
    int RemotePort,
    string State,
    int Pid)
{
    public bool IsListening => State == "LISTEN";
    public bool IsEstablished => State == "ESTABLISHED";

    public string Display => RemoteAddress is null
        ? $"{Protocol} {Format(LocalAddress, LocalPort)} {(IsListening ? "待ち受け" : "バインド")}"
        : $"{Protocol} {Format(LocalAddress, LocalPort)} → {Format(RemoteAddress, RemotePort)}";

    private static string Format(string address, int port) =>
        address.Contains(':') ? $"[{address}]:{port}" : $"{address}:{port}";
}

/// <summary>
/// インストール済みのプログラム（Uninstall キーの 1 件。設計書 §16.2 A）。
/// <see cref="ExecutablePath"/> は、表示用のアイコンが実在する EXE を指していたときだけ入る。
/// </summary>
public sealed record InstalledProgram(
    string DisplayName,
    string? Publisher,
    DateTime? InstallDate,
    string? InstallLocation,
    string? ExecutablePath,
    string RegistryKey);

/// <summary>Windows 標準の遠隔機能の状態（設計書 §16.2 B）。</summary>
/// <param name="Enabled">遠隔から使える状態か。読めなかった・判断できないなら null。</param>
public sealed record RemoteFeature(string Name, bool? Enabled, string State, string Evidence);

/// <summary>ログオンのセッション 1 つ（設計書 §16.2 C）。</summary>
public sealed record SessionFact(
    int SessionId,
    string WinStation,
    string State,
    string? User,
    string? ClientName,
    string? ClientAddress,
    bool IsCurrent)
{
    /// <summary>リモートデスクトップのセッションか（ウィンドウ ステーションの名前が RDP-Tcp#… になる）。</summary>
    public bool IsRemote => WinStation.StartsWith("RDP-", StringComparison.OrdinalIgnoreCase);
}

/// <summary>点検できなかった項目。全体は止めず、画面に出す（設計書 §8）。</summary>
public sealed record ScanNote(string Area, string Message, bool NeedsAdmin = false);

/// <summary>収集した事実のまとまり。</summary>
public sealed class ScanFacts
{
    public List<PersistenceEntry> Persistence { get; } = new();
    public List<ProcessFact> Processes { get; } = new();
    public List<EndpointFact> Endpoints { get; } = new();

    /// <summary>プロセス ID → そのプロセスに実行イメージとして載っているファイル（EXE 自身も含む）。</summary>
    public Dictionary<int, List<string>> Modules { get; } = new();

    /// <summary>プロセス ID → 実行できるのに、実行イメージではない領域。無いプロセスは載らない。</summary>
    public Dictionary<int, List<ExecutableRegion>> ExecutableRegions { get; } = new();

    /// <summary>
    /// プロセス ID → 実行時にコードを作る仕組み（JIT）の名前。該当する領域を持つプロセスについてだけ調べる。
    /// JIT を持つプロセスは、ファイルの裏付けが無い実行可能な領域を正規に作る。
    /// </summary>
    public Dictionary<int, string> JitEngines { get; } = new();

    /// <summary>見張っている間に起きた、キー入力に関わる API の呼び出し（設計書 §11.5）。見張っていなければ空。</summary>
    public List<Monitoring.KeyApiCall> KeyApiCalls { get; } = new();

    // 第 3 段階（設計書 §16）
    public List<InstalledProgram> InstalledPrograms { get; } = new();
    public List<RemoteFeature> RemoteFeatures { get; } = new();
    public List<SessionFact> Sessions { get; } = new();

    /// <summary>点検している画面そのものがリモート経由か（<c>SM_REMOTESESSION</c>）。</summary>
    public bool CurrentSessionIsRemote { get; set; }

    public List<ScanNote> Notes { get; } = new();
}
