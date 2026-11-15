using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Collectors;

/// <summary>
/// Windows 標準の遠隔機能の状態（設計書 §16.2 B）と、いまのセッション（C）を集める。
/// どちらも通常の権限で読める。判断はしない（有効かどうかを事実として残すだけ）。
/// </summary>
public sealed class RemoteAccessCollector
{
    private const string TerminalServer = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string TerminalServicesPolicy = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

    // ユーザーごとの、入っているストア アプリの一覧
    private const string AppxRepository =
        @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    /// <param name="isHomeEdition">Home 版か。Home 版はリモートデスクトップを受け付ける機能を持たない。</param>
    public void CollectFeatures(ScanFacts facts, bool isHomeEdition, CancellationToken cancel)
    {
        cancel.ThrowIfCancellationRequested();
        var services = ReadServices(facts, "TermService", "WinRM", "sshd");

        facts.RemoteFeatures.Add(RemoteDesktop(isHomeEdition, services.GetValueOrDefault("TermService")));
        facts.RemoteFeatures.Add(RemoteAssistance());
        facts.RemoteFeatures.Add(ServiceFeature("WinRM（PowerShell のリモート実行）", "WinRM", services.GetValueOrDefault("WinRM")));
        facts.RemoteFeatures.Add(ServiceFeature("OpenSSH サーバー", "sshd", services.GetValueOrDefault("sshd")));
        facts.RemoteFeatures.Add(QuickAssist(facts));
    }

    public void CollectSessions(ScanFacts facts, CancellationToken cancel)
    {
        cancel.ThrowIfCancellationRequested();
        facts.CurrentSessionIsRemote = GetSystemMetrics(SM_REMOTESESSION) != 0;

        var current = ProcessCollector.CurrentSessionId();
        if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out var buffer, out var count))
        {
            facts.Notes.Add(new ScanNote("セッション", $"セッションの一覧を取れなかった（エラー {Marshal.GetLastWin32Error()}）"));
            return;
        }

        try
        {
            var size = Marshal.SizeOf<WTS_SESSION_INFOW>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WTS_SESSION_INFOW>(buffer + i * size);
                var id = (int)info.SessionId;
                var user = QueryString(id, WTS_INFO_CLASS.WTSUserName);
                var domain = QueryString(id, WTS_INFO_CLASS.WTSDomainName);
                facts.Sessions.Add(new SessionFact(
                    id,
                    info.pWinStationName ?? "",
                    StateName(info.State),
                    string.IsNullOrEmpty(user) ? null : string.IsNullOrEmpty(domain) ? user : $@"{domain}\{user}",
                    NullIfEmpty(QueryString(id, WTS_INFO_CLASS.WTSClientName)),
                    ClientAddress(id),
                    id == current));
            }
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    // ---- B. 標準の遠隔機能 ----

    private static RemoteFeature RemoteDesktop(bool isHomeEdition, ServiceState? service)
    {
        var (deny, where) = ReadDword(TerminalServicesPolicy, "fDenyTSConnections") is { } policy
            ? (policy, "グループ ポリシー")
            : (ReadDword(TerminalServer, "fDenyTSConnections"), "設定");
        var serviceText = service is null ? "" : $"、サービス TermService は {service.Describe()}";

        if (isHomeEdition)
            return new RemoteFeature("リモートデスクトップ（受け付け）", false, "受け付けない（Home 版には受け付ける機能が無い）",
                $"Windows の版が Home{serviceText}");
        return deny switch
        {
            0 => new RemoteFeature("リモートデスクトップ（受け付け）", true, "受け付ける",
                $@"{where}の fDenyTSConnections が 0{serviceText}"),
            null => new RemoteFeature("リモートデスクトップ（受け付け）", null, "読めなかった",
                $@"HKLM\{TerminalServer} の fDenyTSConnections が読めなかった"),
            _ => new RemoteFeature("リモートデスクトップ（受け付け）", false, "受け付けない",
                $@"{where}の fDenyTSConnections が {deny}{serviceText}"),
        };
    }

    private static RemoteFeature RemoteAssistance()
    {
        var (allow, where) = ReadDword(TerminalServicesPolicy, "fAllowToGetHelp") is { } policy
            ? (policy, "グループ ポリシー")
            : (ReadDword(TerminalServer, "fAllowToGetHelp"), "設定");
        return allow switch
        {
            1 => new RemoteFeature("リモート アシスタンス", true, "招待を受け付ける", $"{where}の fAllowToGetHelp が 1"),
            0 => new RemoteFeature("リモート アシスタンス", false, "受け付けない", $"{where}の fAllowToGetHelp が 0"),
            // 値が無いときに Windows がどう扱うかは確かめていない。推測で埋めない
            null => new RemoteFeature("リモート アシスタンス", null, "設定の値が無い（既定のまま）",
                @"HKLM\" + TerminalServer + " に fAllowToGetHelp が無い"),
            _ => new RemoteFeature("リモート アシスタンス", null, $"不明な値（{allow}）", $"{where}の fAllowToGetHelp が {allow}"),
        };
    }

    private static RemoteFeature ServiceFeature(string display, string serviceName, ServiceState? service)
    {
        if (service is null)
            return new RemoteFeature(display, false, "入っていない", $"サービス {serviceName} が無い");
        // 止まっているが無効ではないサービスは、遠隔から使えるかをここでは決められない
        var enabled = service.Running ? true : service.Disabled ? false : (bool?)null;
        var state = service.Running ? "動作中" : service.Disabled ? "無効" : "止まっている（起動できる状態）";
        return new RemoteFeature(display, enabled, state, $"サービス {serviceName} は {service.Describe()}");
    }

    /// <summary>クイック アシスト。いまはストア アプリ版で、旧版（System32 の quickassist.exe）もありうる。</summary>
    private static RemoteFeature QuickAssist(ScanFacts facts)
    {
        string? package = null;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(AppxRepository);
            package = key?.GetSubKeyNames().FirstOrDefault(n => n.StartsWith("MicrosoftCorporationII.QuickAssist_", StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // 入っているかが分からないだけ。下で「旧版」も見る
        }

        var legacy = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "quickassist.exe");
        var hasLegacy = File.Exists(legacy);
        var running = facts.Processes.Any(p => p.Name.Equals("QuickAssist.exe", StringComparison.OrdinalIgnoreCase));

        if (package is null && !hasLegacy)
            return new RemoteFeature("クイック アシスト", false, running ? "動作中（入っている場所は不明）" : "入っていない",
                "ストア アプリ版も、System32 の旧版も見つからなかった");

        var where = package is not null ? $"ストア アプリ {package}" : legacy;
        return new RemoteFeature("クイック アシスト", running, running ? "動作中" : "入っている（動いていない）", where);
    }

    private sealed record ServiceState(string State, string StartMode)
    {
        public bool Running => State.Equals("Running", StringComparison.OrdinalIgnoreCase);
        public bool Disabled => StartMode.Equals("Disabled", StringComparison.OrdinalIgnoreCase);
        public string Describe() => $"{State}（起動: {StartMode}）";
    }

    private static Dictionary<string, ServiceState> ReadServices(ScanFacts facts, params string[] names)
    {
        var result = new Dictionary<string, ServiceState>(StringComparer.OrdinalIgnoreCase);
        var filter = string.Join(" OR ", names.Select(n => $"Name='{n}'"));
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT Name, State, StartMode FROM Win32_Service WHERE {filter}");
            using var services = searcher.Get();
            foreach (var service in services)
            {
                using (service)
                {
                    if (service["Name"] is string name)
                        result[name] = new ServiceState(service["State"] as string ?? "?", service["StartMode"] as string ?? "?");
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException)
        {
            facts.Notes.Add(new ScanNote("標準の遠隔機能", $"サービスの状態を取れなかった: {ex.Message}"));
        }
        return result;
    }

    private static int? ReadDword(string path, string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            return key?.GetValue(name) is int value ? value : null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    // ---- C. セッション ----

    private static string StateName(WTS_CONNECTSTATE_CLASS state) => state switch
    {
        WTS_CONNECTSTATE_CLASS.WTSActive => "使用中",
        WTS_CONNECTSTATE_CLASS.WTSConnected => "接続済み",
        WTS_CONNECTSTATE_CLASS.WTSConnectQuery => "接続処理中",
        WTS_CONNECTSTATE_CLASS.WTSShadow => "シャドウ（画面の共有）",
        WTS_CONNECTSTATE_CLASS.WTSDisconnected => "切断（ログインしたまま）",
        WTS_CONNECTSTATE_CLASS.WTSIdle => "待機",
        WTS_CONNECTSTATE_CLASS.WTSListen => "待ち受け",
        WTS_CONNECTSTATE_CLASS.WTSReset => "リセット",
        WTS_CONNECTSTATE_CLASS.WTSDown => "停止",
        WTS_CONNECTSTATE_CLASS.WTSInit => "初期化中",
        _ => state.ToString(),
    };

    private static string? QueryString(int session, WTS_INFO_CLASS info)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, (uint)session, info, out var buffer, out _)) return null;
        try
        {
            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    /// <summary>リモートのセッションの接続元。手元のセッションでは null。</summary>
    private static string? ClientAddress(int session)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, (uint)session, WTS_INFO_CLASS.WTSClientAddress, out var buffer, out _)) return null;
        try
        {
            var address = Marshal.PtrToStructure<WTS_CLIENT_ADDRESS>(buffer);
            // Address の並びは、IPv4 なら 2 バイト目から 4 バイト、IPv6 なら 2 バイト目から 16 バイト
            return address.AddressFamily switch
            {
                AF_INET => new IPAddress(address.Address.AsSpan(2, 4)).ToString(),
                AF_INET6 => new IPAddress(address.Address.AsSpan(2, 16)).ToString(),
                _ => null,
            };
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static string? NullIfEmpty(string? text) => string.IsNullOrWhiteSpace(text) ? null : text;

    // ---- P/Invoke ----

    private const int SM_REMOTESESSION = 0x1000;
    private const uint AF_INET = 2;
    private const uint AF_INET6 = 23;

    private enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive, WTSConnected, WTSConnectQuery, WTSShadow, WTSDisconnected,
        WTSIdle, WTSListen, WTSReset, WTSDown, WTSInit,
    }

    private enum WTS_INFO_CLASS
    {
        WTSUserName = 5,
        WTSWinStationName = 6,
        WTSDomainName = 7,
        WTSClientName = 10,
        WTSClientAddress = 14,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WTS_SESSION_INFOW
    {
        public uint SessionId;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_CLIENT_ADDRESS
    {
        public uint AddressFamily;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)] public byte[] Address;
    }

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSEnumerateSessionsW(IntPtr server, uint reserved, uint version, out IntPtr sessions, out int count);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, uint sessionId, WTS_INFO_CLASS info, out IntPtr buffer, out uint bytes);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}
