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
        "まずネットワーク（LAN ケーブル・Wi-Fi）を切る。そのうえでアンインストールし、"
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
            Desktops(facts, findings),
            Input(facts, findings),
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

    /// <summary>隠しデスクトップ（§16.2 F）。見慣れないものは名前を出し、ウィンドウを持つプログラムも添える。</summary>
    private static StatusLine Desktops(ScanFacts facts, IReadOnlyList<Finding> findings)
    {
        const string label = "隠しデスクトップ";
        const string scope = "見えるのは、自分の画面（WinSta0）の中のデスクトップだけ";
        if (facts.Desktops.Count == 0)
            return new StatusLine(label, "点検できなかった", StatusLevel.Notice, scope);

        var unfamiliar = facts.Desktops.Where(d => !d.Familiar).ToList();
        if (unfamiliar.Count == 0)
            return new StatusLine(label, "見慣れないものは無い", StatusLevel.Normal,
                $"{scope}。あったもの: {string.Join("、", facts.Desktops.Select(d => d.Name))}");

        string Owners(DesktopFact desktop)
        {
            if (desktop.Error is not null) return $"中を見られなかった: {desktop.Error}";
            if (desktop.WindowOwners.Count == 0) return "ウィンドウは無い";
            var names = desktop.WindowOwners.Select(pid =>
                findings.FirstOrDefault(f => f.Processes.Any(p => p.Pid == pid))?.Name ?? $"PID {pid}");
            return "ウィンドウを持つもの: " + string.Join("、", names.Distinct());
        }

        var withWindows = unfamiliar.Any(d => d.WindowOwners.Count > 0);
        return new StatusLine(label,
            "見慣れないデスクトップがある: " + string.Join("、", unfamiliar.Select(d => $"{d.Name}（{Owners(d)}）")),
            withWindows ? StatusLevel.Warning : StatusLevel.Notice,
            withWindows
                ? "パスワード管理ソフトの安全な入力画面や、仮想デスクトップの道具も作る。覚えが無ければ、" + NextStep
                : scope + "。パスワード管理ソフトの安全な入力画面や、仮想デスクトップの道具も作る");
    }

    /// <summary>
    /// 合成入力（§16.2 G）。合成入力だけでは警告しない（スクリーン キーボードや AutoHotkey なども作る）。
    /// 遠隔操作ソフトが動いているときに来ていれば警告する。
    /// </summary>
    private static StatusLine Input(ScanFacts facts, IReadOnlyList<Finding> findings)
    {
        const string label = "合成入力";
        if (facts.Input is not { } input)
            return new StatusLine(label, "見張っていない", StatusLevel.Normal,
                "［合成入力の見張りを開始］で始め、［停止］で止める。キーの中身は読まず、件数だけを数える");

        var period = $"見張っていた {input.Period}";
        if (input.Injected == 0)
            return new StatusLine(label, $"{period} に、合成入力は無かった", StatusLevel.Normal,
                "リモートデスクトップ経由の入力には印が付かないので、ここには数えられない（「リモート セッション」の行で分かる）");

        var text = $"{period} に {input.Injected} 件（キー {input.InjectedKeys}・マウス {input.InjectedMouse}、"
                   + $"多い 1 秒で {input.PeakInjectedPerSecond} 件）";
        var tools = findings.Where(f => f.RemoteTool is not null && f.Processes.Count > 0).Select(f => f.RemoteTool!.Product).Distinct().ToList();
        return tools.Count > 0
            ? new StatusLine(label, $"{text}。遠隔操作ソフト（{string.Join("、", tools)}）が動いている ⚠", StatusLevel.Warning,
                "自分で操作していないのにマウスやキーが動いていたなら、" + NextStep)
            : new StatusLine(label, text, StatusLevel.Notice,
                "作ったプロセスは分からない。スクリーン キーボード、AutoHotkey、マウスやゲーム機器のユーティリティなども作る");
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
