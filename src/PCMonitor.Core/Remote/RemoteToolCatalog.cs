using System.Text.RegularExpressions;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Remote;

/// <summary>
/// 遠隔操作ソフト 1 製品ぶんの照合の材料（設計書 §16.2 A）。
/// </summary>
/// <param name="Product">画面に出す製品名。</param>
/// <param name="FileNames">実行ファイル名（小文字で比べる）。末尾が <c>*</c> なら前方一致。</param>
/// <param name="Signers">署名者として期待する名前の一部（どれかを含めば一致）。</param>
/// <param name="SignersVerified">
/// <see cref="Signers"/> を配布物の署名で確かめたか。確かめていない製品は、署名が有効なのに署名者が違っても
/// 「なりすまし」の点を付けず、情報として出すだけにする（社名の変更や買収で、署名者は変わりうる）。
/// </param>
/// <param name="InstalledNames">Uninstall キーの表示名に含まれる文字列。</param>
public sealed record RemoteToolEntry(
    string Product,
    string[] FileNames,
    string[] Signers,
    bool SignersVerified,
    string[] InstalledNames);

/// <summary>照合の結果。</summary>
/// <param name="MatchedBy">何で当たったか（「実行ファイル名」「インストールの記録」）。</param>
public sealed record RemoteToolMatch(string Product, string MatchedBy, string[] ExpectedSigners, bool SignersVerified);

/// <summary>
/// 遠隔操作ソフトの照合表。<b>実行ファイル名と署名者の組</b>で持つ。名前だけで照合すると、
/// 名前を真似たものと区別できない。
///
/// ⚠ ここに載せた名前と署名者は、記憶をもとにした候補である（2026-11-15）。この PC には
/// どの製品も入っておらず、配布物の署名を確かめていない。確かめたら <c>SignersVerified</c> を
/// true にし、確かめた日と版を設計書 §16 に書き戻す。
/// </summary>
public static class RemoteToolCatalog
{
    public static IReadOnlyList<RemoteToolEntry> Entries { get; } = new RemoteToolEntry[]
    {
        new("AnyDesk", new[] { "anydesk.exe" },
            new[] { "AnyDesk Software", "philandro Software" }, false, new[] { "AnyDesk" }),
        new("TeamViewer", new[] { "teamviewer.exe", "teamviewer_service.exe", "teamviewerqs*", "tv_w32.exe", "tv_x64.exe" },
            new[] { "TeamViewer" }, false, new[] { "TeamViewer" }),
        new("ScreenConnect（ConnectWise Control）", new[] { "screenconnect.clientservice.exe", "screenconnect.windowsclient.exe", "screenconnect*" },
            new[] { "ConnectWise" }, false, new[] { "ScreenConnect", "ConnectWise Control" }),
        new("Splashtop", new[] { "srservice.exe", "srmanager.exe", "srserver.exe", "srapp.exe", "strwinclt.exe" },
            new[] { "Splashtop" }, false, new[] { "Splashtop" }),
        new("RustDesk", new[] { "rustdesk.exe", "rustdesk*" },
            new[] { "Purslane" }, false, new[] { "RustDesk" }),
        new("Chrome リモート デスクトップ", new[] { "remoting_host.exe", "remoting_desktop.exe", "remoting_start_host.exe" },
            // 2026-11-15 に確認: Chrome Remote Desktop Host 157.0.8103.41 の exe 13 個すべてが「Google LLC」
            new[] { "Google" }, true, new[] { "Chrome Remote Desktop" }),
        new("RealVNC", new[] { "vncserver.exe", "vncviewer.exe", "vncagent.exe" },
            new[] { "RealVNC" }, false, new[] { "RealVNC", "VNC Server", "VNC Viewer" }),
        new("TightVNC", new[] { "tvnserver.exe", "tvnviewer.exe" },
            new[] { "GlavSoft" }, false, new[] { "TightVNC" }),
        new("UltraVNC", new[] { "winvnc.exe", "uvnc_service.exe" },
            new[] { "uvnc" }, false, new[] { "UltraVNC" }),
        new("Atera", new[] { "ateraagent.exe" },
            new[] { "Atera" }, false, new[] { "AteraAgent", "Atera Agent" }),
        new("NinjaOne", new[] { "ninjarmmagent.exe", "ninjarmmagentpatcher.exe" },
            new[] { "NinjaRMM", "NinjaOne" }, false, new[] { "NinjaRMMAgent", "NinjaOne" }),
        new("LogMeIn", new[] { "logmein.exe", "lmiguardiansvc.exe", "logmeinsystray.exe", "lmi_rescue*" },
            new[] { "LogMeIn", "GoTo" }, false, new[] { "LogMeIn" }),
        new("Zoho Assist", new[] { "za_connect.exe", "zohoassist*", "zaservice.exe" },
            new[] { "Zoho" }, false, new[] { "Zoho Assist" }),
        new("Supremo", new[] { "supremo.exe", "supremoservice.exe", "supremohelper.exe" },
            new[] { "Nanosystems" }, false, new[] { "Supremo" }),
        new("AeroAdmin", new[] { "aeroadmin.exe", "aeroadmin*" },
            new[] { "AeroAdmin" }, false, new[] { "AeroAdmin" }),
    };

    // ブラウザーは、同じ名前のファイルを落とし直すと「AnyDesk (1).exe」のように番号を付ける
    private static readonly Regex DownloadCopySuffix = new(@"\s*\(\d+\)(?=\.[^.]+$)", RegexOptions.Compiled);

    /// <summary>実行ファイル名で照合する。当たらなければ null。</summary>
    public static RemoteToolEntry? MatchFileName(string fileName)
    {
        var name = DownloadCopySuffix.Replace(fileName.Trim(), "").ToLowerInvariant();
        if (!name.EndsWith(".exe", StringComparison.Ordinal)) return null;

        foreach (var entry in Entries)
        {
            foreach (var pattern in entry.FileNames)
            {
                var hit = pattern.EndsWith('*')
                    ? name.StartsWith(pattern[..^1], StringComparison.Ordinal)
                    : name == pattern;
                if (hit) return entry;
            }
        }
        return null;
    }

    /// <summary>Uninstall キーの表示名で照合する。当たらなければ null。</summary>
    public static RemoteToolEntry? MatchInstalled(string displayName) =>
        Entries.FirstOrDefault(e => e.InstalledNames.Any(n => displayName.Contains(n, StringComparison.OrdinalIgnoreCase)));

    /// <summary>
    /// 署名が照合表の署名者と合っているか。
    /// true: 合っている。false: 合っていない（署名が無い・無効を含む）。
    /// </summary>
    public static bool SignerMatches(RemoteToolEntry entry, SignatureInfo signature) =>
        signature.IsValid
        && signature.Publisher is { } publisher
        && entry.Signers.Any(s => publisher.Contains(s, StringComparison.OrdinalIgnoreCase));
}
