using PCMonitor.Core.Collectors;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Remote;

/// <summary>
/// 「いまの状態」の帯を組み立てる（設計書 §16.4）。集めた事実と採点の結果から作るだけで、
/// どこにも触らない（規則だけを試せる）。
///
/// 何も無い行も「なし」と書いて出す。空にすると、点検していないのか何も無かったのかが区別できない。
/// </summary>
public static class CurrentStateBuilder
{
    /// <summary>心当たりが無いときの次の一歩。止める操作は置かず、文で示す（設計書 §16.4）。</summary>
    public const string NextStep =
        "心当たりが無ければ、まずネットワーク（LAN ケーブル・Wi-Fi）を切る。そのうえでアンインストールし、"
        + "銀行や会社の管理者に連絡する。電話で言われて入れた場合は、その電話の相手には連絡しない";

    public static List<StatusLine> Build(ScanFacts facts, IReadOnlyList<Finding> findings, int scannerSession)
    {
        return new List<StatusLine>
        {
            Session(facts, scannerSession),
            RemoteTools(findings),
            Features(facts),
            History(facts),
            Devices(facts, findings),
            OtherUsers(facts),
        };
    }

    private static StatusLine Session(ScanFacts facts, int scannerSession)
    {
        var current = facts.Sessions.FirstOrDefault(s => s.SessionId == scannerSession);
        if (facts.CurrentSessionIsRemote || current?.IsRemote == true)
        {
            var from = current is null ? "" : Describe(current.ClientName, current.ClientAddress);
            return new StatusLine("リモート セッション",
                $"この画面はリモートデスクトップ経由{(from.Length > 0 ? $"（接続元 {from}）" : "（接続元は取れなかった）")}",
                StatusLevel.Warning,
                "自分で接続しているのでなければ、" + NextStep);
        }

        var others = facts.Sessions.Where(s => s.IsRemote && s.SessionId != scannerSession && s.User is not null).ToList();
        if (others.Count > 0)
            return new StatusLine("リモート セッション",
                "ほかにリモートデスクトップのセッションがある: "
                + string.Join("、", others.Select(s => $"{s.User}（{s.State}{AppendFrom(s)}）")),
                StatusLevel.Warning);

        return new StatusLine("リモート セッション", "なし（この画面は手元のもの）", StatusLevel.Normal);
    }

    private static StatusLine RemoteTools(IReadOnlyList<Finding> findings)
    {
        var tools = findings.Where(f => f.RemoteTool is not null).ToList();
        if (tools.Count == 0)
            return new StatusLine("遠隔操作ソフト", "照合表に当たるものは無い（照合表に無い製品は分からない）", StatusLevel.Normal);

        var running = tools.Where(f => f.Processes.Count > 0).ToList();
        if (running.Count == 0)
            return new StatusLine("遠隔操作ソフト",
                $"入っているが動いていない: {Products(tools)}",
                StatusLevel.Notice);

        var talking = running.Where(IsTalkingOutside).ToList();
        var parts = running.Select(f =>
            $"{f.RemoteTool!.Product} が動作中{(IsTalkingOutside(f) ? "・外部と通信中 ⚠" : "")}{(f.IsAllowed ? "（許可済み）" : "")}");
        var idle = tools.Except(running).ToList();
        var text = string.Join("、", parts) + (idle.Count > 0 ? $"。ほかに入っているもの: {Products(idle)}" : "");

        // 許可リストに入れていても、動いて外とつながっているなら出す。電話で入れさせる手口では、
        // 正規の遠隔操作ソフトを本人が許可済みにしていることがありうる
        return talking.Count > 0
            ? new StatusLine("遠隔操作ソフト", text, StatusLevel.Warning, "いま使っている覚えが無ければ、" + NextStep)
            : new StatusLine("遠隔操作ソフト", text, StatusLevel.Notice);
    }

    private static StatusLine Features(ScanFacts facts)
    {
        if (facts.RemoteFeatures.Count == 0)
            return new StatusLine("Windows の遠隔機能", "点検できなかった", StatusLevel.Notice);

        var on = facts.RemoteFeatures.Where(f => f.Enabled == true).ToList();
        var text = string.Join("、", facts.RemoteFeatures.Select(f => $"{f.Name}: {f.State}"));
        return new StatusLine("Windows の遠隔機能",
            on.Count == 0 ? "有効なものは無い" : "有効: " + string.Join("、", on.Select(f => f.Name)),
            on.Count == 0 ? StatusLevel.Normal : StatusLevel.Notice,
            text);
    }

    /// <summary>遠隔接続の履歴（§16.2 D）。「記録が無い」は「入られていない」ではないことを必ず添える。</summary>
    private static StatusLine History(ScanFacts facts)
    {
        const string label = "遠隔接続の履歴（30 日）";
        const string caveat = "記録が無いことは、入られていないことを意味しない（管理者の権限を取られていれば、記録は消せる）。"
                              + "遠隔操作ソフト自身の接続記録は読んでいない";
        var unread = facts.UnreadLogs.Count > 0 ? $"。見られなかったログ: {string.Join("、", facts.UnreadLogs)}" : "";

        if (facts.RemoteLogons.Count == 0)
            return new StatusLine(label, "見られた記録の中には無い" + unread, StatusLevel.Normal, caveat);

        var byAddress = facts.RemoteLogons
            .GroupBy(l => l.Address ?? "接続元不明")
            .OrderByDescending(g => g.Max(l => l.TimeUtc))
            .Select(g => $"{g.Key}（{g.Count()} 件、最後は {g.Max(l => l.TimeUtc).ToLocalTime():MM-dd HH:mm}）")
            .ToList();
        var latest = facts.RemoteLogons
            .OrderByDescending(l => l.TimeUtc)
            .Take(5)
            .Select(l => $"{l.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm} {l.What} {l.User ?? "利用者不明"} {l.Address ?? ""}（{l.Source}）".TrimEnd());
        return new StatusLine(label,
            $"リモートデスクトップの記録が {facts.RemoteLogons.Count} 件。接続元: {string.Join("、", byAddress.Take(3))}"
            + (byAddress.Count > 3 ? $" ほか {byAddress.Count - 3} か所" : "") + unread,
            StatusLevel.Notice,
            "新しい順: " + string.Join(" ／ ", latest) + "。自分の接続でなければ、" + NextStep);
    }

    /// <summary>カメラ・マイク（§16.2 E）。いま使っているアプリを出す。署名の無いものが使っていれば警告する。</summary>
    private static StatusLine Devices(ScanFacts facts, IReadOnlyList<Finding> findings)
    {
        const string label = "カメラ・マイク";
        if (facts.DeviceUsages.Count == 0)
            return new StatusLine(label, "使用中のアプリなし（使った記録も無い）", StatusLevel.Normal,
                "画面の取り込みは、この記録には残らない");

        bool Unsigned(DeviceUsage usage) =>
            usage.Path is not null
            && findings.FirstOrDefault(f => f.DeviceUsages.Contains(usage))?.Signature.Status is SignatureStatus.None or SignatureStatus.Invalid;

        var last = facts.DeviceUsages.OrderByDescending(u => u.LastStartUtc).First();
        var lastText = $"最後に使ったのは {last.AppDisplay}（{last.DeviceDisplay}、{last.LastStartUtc!.Value.ToLocalTime():yyyy-MM-dd HH:mm}）。"
                       + "画面の取り込みは、この記録には残らない";
        var inUse = facts.DeviceUsages.Where(u => u.InUse).ToList();
        var unsignedUsers = facts.DeviceUsages.Where(Unsigned).Select(u => u.AppDisplay).Distinct().ToList();

        if (inUse.Count == 0)
            return unsignedUsers.Count > 0
                ? new StatusLine(label, $"使用中のアプリなし。ただし署名の無いプログラムが使った記録がある: {string.Join("、", unsignedUsers)}",
                    StatusLevel.Notice, lastText)
                : new StatusLine(label, "使用中のアプリなし", StatusLevel.Normal, lastText);

        var text = "使用中: " + string.Join("、", inUse
            .GroupBy(u => u.AppDisplay)
            .Select(g => $"{g.Key}（{string.Join("・", g.Select(u => u.DeviceDisplay).Distinct())}{(g.Any(Unsigned) ? "、署名なし ⚠" : "")}）"));
        return inUse.Any(Unsigned)
            ? new StatusLine(label, text, StatusLevel.Warning, "使っている覚えが無ければ、" + NextStep)
            : new StatusLine(label, text, StatusLevel.Notice, lastText);
    }

    private static StatusLine OtherUsers(ScanFacts facts)
    {
        var current = facts.Sessions.FirstOrDefault(s => s.IsCurrent);
        var others = facts.Sessions
            .Where(s => !s.IsCurrent && s.User is not null && s.SessionId != 0)
            .Where(s => !string.Equals(s.User, current?.User, StringComparison.OrdinalIgnoreCase) || s.IsRemote)
            .ToList();
        if (facts.Sessions.Count == 0)
            return new StatusLine("ほかのログイン中の利用者", "セッションの一覧を取れなかった", StatusLevel.Notice);
        if (others.Count == 0)
            return new StatusLine("ほかのログイン中の利用者", "なし", StatusLevel.Normal);
        return new StatusLine("ほかのログイン中の利用者",
            string.Join("、", others.Select(s => $"{s.User}（{s.State}{AppendFrom(s)}）")),
            StatusLevel.Notice);
    }

    /// <summary>ループバック以外の相手との確立した接続か、ループバック以外での待ち受けがある。</summary>
    internal static bool IsTalkingOutside(Finding finding) =>
        finding.Endpoints.Any(e => e.Protocol == "TCP"
                                   && ((e.IsEstablished && e.RemoteAddress is not null && !NetworkCollector.IsLoopback(e.RemoteAddress))
                                       || (e.IsListening && !NetworkCollector.IsLoopback(e.LocalAddress))));

    private static string Products(IEnumerable<Finding> findings) =>
        string.Join("、", findings.Select(f => f.RemoteTool!.Product + (f.IsAllowed ? "（許可済み）" : "")).Distinct());

    private static string AppendFrom(SessionFact session)
    {
        var from = Describe(session.ClientName, session.ClientAddress);
        return from.Length > 0 ? $"、接続元 {from}" : "";
    }

    private static string Describe(string? name, string? address) =>
        (name, address) switch
        {
            (not null, not null) => $"{name}／{address}",
            (not null, null) => name,
            (null, not null) => address,
            _ => "",
        };
}
