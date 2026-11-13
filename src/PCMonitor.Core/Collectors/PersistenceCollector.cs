using System.Management;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Collectors;

/// <summary>
/// 常駐箇所を読む（設計書 §5.1）。事実を集めるだけで、判断はしない。
/// 箇所ごとに失敗を受け止め、全体は止めない。
/// </summary>
public sealed class PersistenceCollector
{
    private const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\";
    private const string RunPath32 = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\";
    private const string StartupApproved = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\";
    private const string WindowsNt = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\";
    private const string WindowsNt32 = @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\";

    private static readonly Regex WmiNameReference = new(@"Name\s*=\s*""((?:[^""\\]|\\.)*)""", RegexOptions.Compiled);

    private readonly IPathProbe _probe;
    private readonly CommandLineResolver _resolver;

    public PersistenceCollector(IPathProbe probe)
    {
        _probe = probe;
        _resolver = new CommandLineResolver(probe);
    }

    public void Collect(ScanFacts facts, CancellationToken cancel)
    {
        Step(facts, "Run キー", () => CollectRunKeys(facts), cancel);
        Step(facts, "スタートアップ フォルダー", () => CollectStartupFolders(facts), cancel);
        Step(facts, "サービス", () => CollectServices(facts, cancel), cancel);
        Step(facts, "タスク スケジューラ", () => CollectTasks(facts, cancel), cancel);
        Step(facts, "WMI イベント購読", () => CollectWmiSubscriptions(facts), cancel);
        Step(facts, "Winlogon", () => CollectWinlogon(facts), cancel);
        Step(facts, "AppInit_DLLs", () => CollectAppInit(facts), cancel);
        Step(facts, "IFEO", () => CollectIfeo(facts), cancel);
    }

    private static void Step(ScanFacts facts, string area, Action action, CancellationToken cancel)
    {
        cancel.ThrowIfCancellationRequested();
        try
        {
            action();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            var denied = ex is UnauthorizedAccessException or System.Security.SecurityException
                || (ex is ManagementException me && me.ErrorCode == ManagementStatus.AccessDenied);
            facts.Notes.Add(new ScanNote(area,
                denied ? "権限が足りず点検できなかった（管理者なら見られる）" : $"点検できなかった: {ex.Message}",
                denied));
        }
    }

    // ---- Run / RunOnce ----

    private void CollectRunKeys(ScanFacts facts)
    {
        var hives = new[] { (RegistryHive.LocalMachine, "HKLM"), (RegistryHive.CurrentUser, "HKCU") };
        var keys = new[]
        {
            (RunPath + "Run", "Run"),
            (RunPath + "RunOnce", (string?)null),
            (RunPath + @"Policies\Explorer\Run", null),
            (RunPath32 + "Run", "Run32"),
            (RunPath32 + "RunOnce", null),
        };

        foreach (var (hive, hiveName) in hives)
        {
            using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            foreach (var (path, approvedName) in keys)
            {
                using var key = TryOpen(root, path);
                if (key is null) continue;
                using var approved = approvedName is null ? null : TryOpen(root, StartupApproved + approvedName);

                foreach (var name in key.GetValueNames())
                {
                    if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string command
                        || string.IsNullOrWhiteSpace(command))
                        continue;
                    var disabled = IsStartupDisabled(approved, name);
                    facts.Persistence.Add(new PersistenceEntry(
                        PersistenceKind.RunKey,
                        $@"{hiveName}\{path}",
                        name.Length == 0 ? "(既定)" : name,
                        _resolver.Resolve(command),
                        AutoStarts: !disabled,
                        Note: disabled ? "スタートアップの設定で無効にされている" : null));
                }
            }
        }
    }

    /// <summary>タスク マネージャーの「スタートアップ」で無効にされた項目か（先頭バイトが奇数）。</summary>
    private static bool IsStartupDisabled(RegistryKey? approved, string name) =>
        approved?.GetValue(name) is byte[] { Length: > 0 } state && (state[0] & 1) == 1;

    // ---- スタートアップ フォルダー ----

    private void CollectStartupFolders(ScanFacts facts)
    {
        var folders = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), RegistryHive.CurrentUser),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), RegistryHive.LocalMachine),
        };

        foreach (var (folder, hive) in folders)
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;
            using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var approved = TryOpen(root, StartupApproved + "StartupFolder");

            foreach (var file in Directory.EnumerateFiles(folder))
            {
                var fileName = Path.GetFileName(file);
                if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;

                ResolvedCommand command;
                if (Path.GetExtension(file).Equals(".lnk", StringComparison.OrdinalIgnoreCase))
                {
                    var (target, arguments) = ReadShortcut(file);
                    command = string.IsNullOrWhiteSpace(target)
                        ? new ResolvedCommand(file, null, null, UnresolvedReason: "ショートカットのリンク先を読めない")
                        : _resolver.Resolve($"\"{target}\" {arguments}".TrimEnd()) with { Raw = $"{target} {arguments}".TrimEnd() };
                }
                else
                {
                    command = _resolver.Resolve($"\"{file}\"");
                }

                var disabled = IsStartupDisabled(approved, fileName);
                facts.Persistence.Add(new PersistenceEntry(
                    PersistenceKind.StartupFolder, folder, fileName, command,
                    AutoStarts: !disabled,
                    Note: disabled ? "スタートアップの設定で無効にされている" : null));
            }
        }
    }

    private static (string? Target, string? Arguments) ReadShortcut(string path)
    {
        var type = Type.GetTypeFromProgID("WScript.Shell");
        if (type is null) return (null, null);
        object? shell = null;
        object? shortcut = null;
        try
        {
            shell = Activator.CreateInstance(type);
            if (shell is null) return (null, null);
            dynamic dynamicShell = shell;
            shortcut = dynamicShell.CreateShortcut(path);
            dynamic dynamicShortcut = shortcut!;
            return ((string?)dynamicShortcut.TargetPath, (string?)dynamicShortcut.Arguments);
        }
        catch (Exception ex) when (ex is COMException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException)
        {
            return (null, null);
        }
        finally
        {
            if (shortcut is not null) Marshal.FinalReleaseComObject(shortcut);
            if (shell is not null) Marshal.FinalReleaseComObject(shell);
        }
    }

    // ---- サービスとドライバー ----

    private void CollectServices(ScanFacts facts, CancellationToken cancel)
    {
        const string servicesPath = @"SYSTEM\CurrentControlSet\Services";
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var services = root.OpenSubKey(servicesPath)
            ?? throw new InvalidOperationException("サービスのキーを開けない");

        var unreadable = 0;
        foreach (var name in services.GetSubKeyNames())
        {
            cancel.ThrowIfCancellationRequested();
            RegistryKey? service;
            try { service = services.OpenSubKey(name); }
            catch (System.Security.SecurityException) { unreadable++; continue; }
            if (service is null) continue;

            using (service)
            {
                if (service.GetValue("Type") is not int type) continue;
                var isWin32 = (type & 0x30) != 0;
                var isDriver = !isWin32 && (type & 0x0F) != 0;
                if (!isWin32 && !isDriver) continue;
                // 利用者ごとに複製されたサービス（名前_xxxxx）は、ひな型のほうで見る
                if ((type & 0x80) != 0) continue;

                var start = service.GetValue("Start") as int? ?? 3;
                var imagePath = service.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;

                if (string.IsNullOrWhiteSpace(imagePath))
                {
                    if (!isDriver) continue;
                    // ImagePath の無いドライバーは既定の場所。カーネルに組み込まれたものは実体が無いので挙げない
                    imagePath = $@"\SystemRoot\System32\drivers\{name}.sys";
                    if (!_probe.FileExists(_resolver.NormalizePrefix(imagePath))) continue;
                }

                var command = ResolveServiceImage(service, imagePath, isWin32);

                facts.Persistence.Add(new PersistenceEntry(
                    isDriver ? PersistenceKind.Driver : PersistenceKind.Service,
                    $@"HKLM\{servicesPath}\{name}",
                    name,
                    command,
                    AutoStarts: start <= 2,
                    Note: start switch
                    {
                        0 => "開始: ブート時",
                        1 => "開始: システム起動時",
                        2 => "開始: 自動",
                        3 => "開始: 手動",
                        4 => "開始: 無効",
                        _ => null,
                    }));
            }
        }

        if (unreadable > 0)
            facts.Notes.Add(new ScanNote("サービス", $"{unreadable} 件のサービスを読めなかった（管理者なら見られる）", true));
    }

    /// <summary>サービスの実体を解く。svchost 経由なら、読み込まれる ServiceDll が実体。</summary>
    private ResolvedCommand ResolveServiceImage(RegistryKey service, string imagePath, bool isWin32)
    {
        var command = _resolver.Resolve(imagePath);
        if (isWin32 && command.HostPath is not null
            && Path.GetFileName(command.HostPath).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            var dll = ReadServiceDll(service);
            if (dll is not null)
                return new ResolvedCommand(imagePath, command.HostPath, _resolver.NormalizePrefix(_probe.Expand(dll)));
        }
        return command;
    }

    private static string? ReadServiceDll(RegistryKey service)
    {
        try
        {
            using var parameters = service.OpenSubKey("Parameters");
            return (parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames)
                    ?? service.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames)) as string;
        }
        catch (System.Security.SecurityException)
        {
            return null;
        }
    }

    // ---- タスク スケジューラ ----

    private void CollectTasks(ScanFacts facts, CancellationToken cancel)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service")
            ?? throw new InvalidOperationException("タスク スケジューラに接続できない");
        var service = Activator.CreateInstance(type)
            ?? throw new InvalidOperationException("タスク スケジューラに接続できない");
        try
        {
            dynamic scheduler = service;
            scheduler.Connect();
            var skipped = 0;
            WalkTaskFolder(scheduler.GetFolder(@"\"), facts, ref skipped, cancel);
            if (skipped > 0)
                facts.Notes.Add(new ScanNote("タスク スケジューラ", $"{skipped} 件のタスクまたはフォルダーを読めなかった（管理者なら見られる）", true));
        }
        finally
        {
            Marshal.FinalReleaseComObject(service);
        }
    }

    private void WalkTaskFolder(dynamic folder, ScanFacts facts, ref int skipped, CancellationToken cancel)
    {
        cancel.ThrowIfCancellationRequested();

        // 1 = 隠しタスクも含める
        foreach (dynamic task in folder.GetTasks(1))
        {
            try
            {
                string path = task.Path;
                string name = task.Name;
                bool enabled = task.Enabled;
                foreach (dynamic action in task.Definition.Actions)
                {
                    ResolvedCommand? command = ResolveTaskAction(action);
                    if (command is null) continue;
                    facts.Persistence.Add(new PersistenceEntry(
                        PersistenceKind.ScheduledTask,
                        "タスク スケジューラ " + path,
                        name,
                        command,
                        AutoStarts: enabled,
                        Note: enabled ? null : "タスクは無効"));
                }
            }
            catch (Exception ex) when (ex is COMException or UnauthorizedAccessException
                                           or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException)
            {
                skipped++;
            }
        }

        dynamic subfolders;
        try
        {
            subfolders = folder.GetFolders(0);
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException)
        {
            skipped++;
            return;
        }
        foreach (dynamic subfolder in subfolders)
            WalkTaskFolder(subfolder, facts, ref skipped, cancel);
    }

    private ResolvedCommand? ResolveTaskAction(dynamic action)
    {
        var actionType = (int)action.Type;
        switch (actionType)
        {
            case 0: // 実行
            {
                string path = action.Path ?? "";
                string arguments = action.Arguments ?? "";
                if (string.IsNullOrWhiteSpace(path)) return null;
                // Path にはスペースを含む実行ファイルが引用符なしで入ることがある
                var quoted = !path.Contains('"') && path.Contains(' ') && _probe.FileExists(_probe.Expand(path))
                    ? $"\"{path}\""
                    : path;
                var raw = (path + " " + arguments).Trim();
                return _resolver.Resolve((quoted + " " + arguments).Trim()) with { Raw = raw };
            }
            case 5: // COM ハンドラー
            {
                string classId = action.ClassId ?? "";
                var raw = $"COM ハンドラー {classId}";
                var server = ResolveComClass(classId);
                return server is null
                    ? new ResolvedCommand(raw, null, null,
                        UnresolvedReason: "COM クラスの実体が登録されていない（パッケージ化されたアプリのものは、ここからは見えない）")
                    : server with { Raw = raw };
            }
            default:
                // メール送信・メッセージ表示は、いまの Windows では動かない
                return null;
        }
    }

    /// <summary>COM クラスの実体をたどる。DLL か EXE、またはサービスが受け持つ形（AppID の LocalService）。</summary>
    private ResolvedCommand? ResolveComClass(string classId)
    {
        if (string.IsNullOrWhiteSpace(classId)) return null;
        using var root = RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Registry64);
        foreach (var server in new[] { "InprocServer32", "LocalServer32" })
        {
            using var key = TryOpen(root, $@"CLSID\{classId}\{server}");
            if (key?.GetValue(null, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string value
                && !string.IsNullOrWhiteSpace(value))
                return _resolver.Resolve(value);
        }

        using var clsid = TryOpen(root, $@"CLSID\{classId}");
        if (clsid?.GetValue("AppID") is not string appId) return null;
        using var app = TryOpen(root, $@"AppID\{appId}");
        if (app?.GetValue("LocalService") is not string serviceName || string.IsNullOrWhiteSpace(serviceName)) return null;

        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var service = TryOpen(machine, $@"SYSTEM\CurrentControlSet\Services\{serviceName}");
        return service?.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string imagePath
               && !string.IsNullOrWhiteSpace(imagePath)
            ? ResolveServiceImage(service, imagePath, isWin32: true)
            : null;
    }

    // ---- WMI イベント購読 ----

    private void CollectWmiSubscriptions(ScanFacts facts)
    {
        var scope = new ManagementScope(@"\\.\root\subscription");
        scope.Connect();

        // フィルター名 → 条件、コンシューマー名 → 結び付いたフィルター名
        var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var filter in Query(scope, "SELECT Name, Query FROM __EventFilter"))
            filters[filter["Name"] as string ?? ""] = filter["Query"] as string ?? "";

        var bindings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var binding in Query(scope, "SELECT Filter, Consumer FROM __FilterToConsumerBinding"))
        {
            var consumer = ReferencedName(binding["Consumer"] as string);
            var filter = ReferencedName(binding["Filter"] as string);
            if (consumer is not null && filter is not null) bindings[consumer] = filter;
        }

        foreach (var consumer in Query(scope, "SELECT * FROM CommandLineEventConsumer"))
        {
            var name = consumer["Name"] as string ?? "";
            var command = consumer["CommandLineTemplate"] as string ?? consumer["ExecutablePath"] as string ?? "";
            AddWmi(facts, "CommandLineEventConsumer", name, _resolver.Resolve(command), filters, bindings);
        }

        foreach (var consumer in Query(scope, "SELECT * FROM ActiveScriptEventConsumer"))
        {
            var name = consumer["Name"] as string ?? "";
            var file = consumer["ScriptFileName"] as string;
            var text = consumer["ScriptText"] as string ?? "";
            var command = string.IsNullOrWhiteSpace(file)
                ? new ResolvedCommand(Shorten(text, 400), null, null, "ActiveScript", Inline: true)
                : new ResolvedCommand(file, null, _probe.Expand(file), "ActiveScript");
            AddWmi(facts, "ActiveScriptEventConsumer", name, command, filters, bindings);
        }
    }

    private static void AddWmi(ScanFacts facts, string className, string name, ResolvedCommand command,
        Dictionary<string, string> filters, Dictionary<string, string> bindings)
    {
        var bound = bindings.TryGetValue(name, out var filterName);
        var condition = bound && filters.TryGetValue(filterName!, out var query) ? query : null;
        facts.Persistence.Add(new PersistenceEntry(
            PersistenceKind.WmiSubscription,
            $@"root\subscription の {className}",
            name,
            command,
            AutoStarts: bound,
            Note: bound ? $"条件: {condition ?? filterName}" : "フィルターに結び付いていない"));
    }

    private static List<ManagementBaseObject> Query(ManagementScope scope, string query)
    {
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query));
        using var results = searcher.Get();
        return results.Cast<ManagementBaseObject>().ToList();
    }

    private static string? ReferencedName(string? reference)
    {
        if (reference is null) return null;
        var match = WmiNameReference.Match(reference);
        return match.Success ? match.Groups[1].Value.Replace("\\\"", "\"").Replace(@"\\", @"\") : null;
    }

    // ---- Winlogon ----

    private void CollectWinlogon(ScanFacts facts)
    {
        var explorer = Path.Combine(_probe.SystemRoot, "explorer.exe");
        var userinit = Path.Combine(_probe.SystemRoot, "System32", "userinit.exe");

        using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        using (var key = TryOpen(root, WindowsNt + "Winlogon"))
        {
            AddWinlogonValue(facts, key, $@"HKLM\{WindowsNt}Winlogon", "Shell", explorer);
            AddWinlogonValue(facts, key, $@"HKLM\{WindowsNt}Winlogon", "Userinit", userinit);
        }

        // HKCU 側の Shell は、既定では値が無い
        using (var root = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
        using (var key = TryOpen(root, WindowsNt + "Winlogon"))
        {
            AddWinlogonValue(facts, key, $@"HKCU\{WindowsNt}Winlogon", "Shell", expected: null);
        }
    }

    private void AddWinlogonValue(ScanFacts facts, RegistryKey? key, string location, string valueName, string? expected)
    {
        if (key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string value) return;

        foreach (var item in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var command = _resolver.Resolve(item);
            if (expected is not null && command.TargetPath is not null
                && string.Equals(Path.GetFullPath(command.TargetPath), expected, StringComparison.OrdinalIgnoreCase)
                && command.ScriptHost is null)
                continue; // 既定値のまま

            facts.Persistence.Add(new PersistenceEntry(
                PersistenceKind.Winlogon, location, valueName, command,
                Note: "既定値から変わっている"));
        }
    }

    // ---- AppInit_DLLs ----

    private void CollectAppInit(ScanFacts facts)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        foreach (var path in new[] { WindowsNt + "Windows", WindowsNt32 + "Windows" })
        {
            using var key = TryOpen(root, path);
            if (key?.GetValue("AppInit_DLLs", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string value
                || string.IsNullOrWhiteSpace(value))
                continue;

            var loads = key.GetValue("LoadAppInit_DLLs") is int flag && flag != 0;
            foreach (var dll in value.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                facts.Persistence.Add(new PersistenceEntry(
                    PersistenceKind.AppInitDll, $@"HKLM\{path}", "AppInit_DLLs",
                    _resolver.Resolve(dll),
                    AutoStarts: loads,
                    Note: loads ? "すべての GUI プロセスに読み込まれる" : "読み込みは無効（LoadAppInit_DLLs = 0）"));
            }
        }
    }

    // ---- IFEO ----

    private void CollectIfeo(ScanFacts facts)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        foreach (var path in new[] { WindowsNt + "Image File Execution Options", WindowsNt32 + "Image File Execution Options" })
        {
            using var options = TryOpen(root, path);
            if (options is null) continue;

            foreach (var image in options.GetSubKeyNames())
            {
                using var key = TryOpen(options, image);
                if (key?.GetValue("Debugger", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string debugger
                    || string.IsNullOrWhiteSpace(debugger))
                    continue;

                facts.Persistence.Add(new PersistenceEntry(
                    PersistenceKind.Ifeo, $@"HKLM\{path}\{image}", image,
                    _resolver.Resolve(debugger),
                    Note: $"{image} を起動すると、代わりにこれが動く"));
            }
        }
    }

    // ---- 道具 ----

    private static RegistryKey? TryOpen(RegistryKey root, string path)
    {
        try { return root.OpenSubKey(path); }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    private static string Shorten(string text, int max) =>
        text.Length <= max ? text : text[..max] + "…";
}
