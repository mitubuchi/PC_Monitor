using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Xml.Linq;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Collectors;

/// <summary>
/// 遠隔からのログオン・接続の記録を、Windows のイベント ログから読む（設計書 §16.2 D）。
///
/// | ログ | 番号 | 権限 |
/// |---|---|---|
/// | TerminalServices-LocalSessionManager/Operational | 21 ログオン・24 切断・25 再接続 | 通常（2026-11-15 に確認） |
/// | TerminalServices-RemoteConnectionManager/Operational | 1149 認証成功 | 通常（Home 版では空） |
/// | Security | 4624 でログオンの種類が 10（RemoteInteractive） | 管理者 |
///
/// 遠隔操作ソフト自身の接続記録は、製品と版ごとに置き場所と書式が違い、まだ確かめていないので読まない。
/// </summary>
public sealed class RemoteHistoryCollector
{
    public const int DefaultDays = 30;

    // 1 つのログから読む上限。古い PC でログが大きくても、点検が止まらないようにする
    private const int MaxPerLog = 500;

    private const string LocalSessionManager = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
    private const string RemoteConnectionManager = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

    private readonly int _days;

    public RemoteHistoryCollector(int days = DefaultDays) => _days = days;

    public void Collect(ScanFacts facts, bool elevated, CancellationToken cancel)
    {
        var since = $"TimeCreated[timediff(@SystemTime) <= {(long)TimeSpan.FromDays(_days).TotalMilliseconds}]";

        Read(facts, LocalSessionManager, $"*[System[(EventID=21 or EventID=24 or EventID=25) and {since}]]",
            "LocalSessionManager", cancel, (id, data, time) =>
            {
                // 手元のログオンでは Address に「LOCAL」が入る。Windows の言語で訳されて
                // 「ローカル」になる（この PC で確認）ので、IP アドレスとして読めるものだけを遠隔とする
                var address = data.GetValueOrDefault("Address");
                if (!IsIpAddress(address)) return null;
                var what = id switch { 21 => "ログオン", 24 => "切断", 25 => "再接続", _ => id.ToString() };
                return new RemoteLogon(time, what, data.GetValueOrDefault("User"), address,
                    int.TryParse(data.GetValueOrDefault("SessionID"), out var session) ? session : null,
                    $"LocalSessionManager {id}");
            });

        Read(facts, RemoteConnectionManager, $"*[System[EventID=1149 and {since}]]",
            "RemoteConnectionManager", cancel, (id, data, time) =>
            {
                var user = data.GetValueOrDefault("Param1");
                var domain = data.GetValueOrDefault("Param2");
                return new RemoteLogon(time, "認証成功",
                    string.IsNullOrEmpty(domain) ? user : $@"{domain}\{user}",
                    NullIfEmpty(data.GetValueOrDefault("Param3")), null, $"RemoteConnectionManager {id}");
            });

        if (!elevated)
        {
            facts.UnreadLogs.Add("Security（管理者なら見られる）");
            return;
        }
        Read(facts, "Security", $"*[System[EventID=4624 and {since}] and EventData[Data[@Name='LogonType']='10']]",
            "Security", cancel, (id, data, time) =>
            {
                var user = data.GetValueOrDefault("TargetUserName");
                var domain = data.GetValueOrDefault("TargetDomainName");
                var address = data.GetValueOrDefault("IpAddress");
                return new RemoteLogon(time, "ログオン（リモートデスクトップ）",
                    string.IsNullOrEmpty(domain) ? user : $@"{domain}\{user}",
                    address is null or "-" ? null : address, null, $"Security {id}");
            });
    }

    private void Read(ScanFacts facts, string log, string xpath, string display, CancellationToken cancel,
        Func<int, IReadOnlyDictionary<string, string>, DateTime, RemoteLogon?> convert)
    {
        try
        {
            // 新しい順に読み、上限で切る
            using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true });
            for (var count = 0; count < MaxPerLog; count++)
            {
                cancel.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null) break;
                if (record.TimeCreated is not { } time) continue;
                var logon = convert(record.Id, Fields(record.ToXml()), time.ToUniversalTime());
                if (logon is not null) facts.RemoteLogons.Add(logon);
            }
        }
        catch (EventLogNotFoundException)
        {
            // そのログが無い（機能が入っていない版）。読むものが無いだけで、異常ではない
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or EventLogException)
        {
            facts.UnreadLogs.Add(display);
            facts.Notes.Add(new ScanNote("遠隔接続の履歴", $"{display} のログを読めなかった: {ex.Message}",
                ex is UnauthorizedAccessException));
        }
    }

    /// <summary>
    /// イベントの中身を「名前 → 値」にする。EventData は <c>Data Name="…"</c> の形、
    /// UserData は要素名が名前になる形なので、両方を同じに扱う。
    /// </summary>
    internal static IReadOnlyDictionary<string, string> Fields(string xml)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var root = XElement.Parse(xml);
        foreach (var element in root.Descendants())
        {
            if (element.HasElements) continue;
            var parent = element.Parent?.Name.LocalName;
            if (parent is not ("EventData" or "EventXML") && element.Parent?.Parent?.Name.LocalName != "UserData") continue;
            var name = element.Name.LocalName == "Data" ? (string?)element.Attribute("Name") : element.Name.LocalName;
            if (!string.IsNullOrEmpty(name)) result[name] = element.Value.Trim();
        }
        return result;
    }

    internal static bool IsIpAddress(string? text) =>
        !string.IsNullOrWhiteSpace(text) && IPAddress.TryParse(text.Trim(), out _);

    private static string? NullIfEmpty(string? text) => string.IsNullOrWhiteSpace(text) ? null : text;
}
