using System.Text;
using System.Text.RegularExpressions;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Collectors;

/// <summary>ファイルの有無と PATH の検索。テストで差し替えられるように分けてある。</summary>
public interface IPathProbe
{
    string SystemRoot { get; }
    string Expand(string text);
    bool FileExists(string path);

    /// <summary>フォルダーの付いていない名前を、System32 と PATH から探す。</summary>
    string? SearchPath(string name);
}

public sealed class SystemPathProbe : IPathProbe
{
    private static readonly string[] ExecutableExtensions = { ".exe", ".com", ".bat", ".cmd" };
    private readonly string[] _directories;

    public SystemPathProbe()
    {
        SystemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var dirs = new List<string>
        {
            Environment.SystemDirectory,
            SystemRoot,
        };
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!dirs.Contains(dir, StringComparer.OrdinalIgnoreCase)) dirs.Add(dir);
        }
        _directories = dirs.ToArray();
    }

    public string SystemRoot { get; }

    public string Expand(string text) => Environment.ExpandEnvironmentVariables(text);

    public bool FileExists(string path)
    {
        try { return File.Exists(path); }
        catch { return false; }
    }

    public string? SearchPath(string name)
    {
        if (name.Length == 0 || name.IndexOfAny(Path.GetInvalidPathChars()) >= 0) return null;
        var candidates = Path.HasExtension(name)
            ? new[] { name }
            : ExecutableExtensions.Select(ext => name + ext).ToArray();
        foreach (var dir in _directories)
        {
            foreach (var candidate in candidates)
            {
                string full;
                try { full = Path.Combine(dir, candidate); }
                catch { continue; }
                if (FileExists(full)) return full;
            }
        }
        return null;
    }
}

/// <summary>
/// 登録されたコマンドラインから「実際に動くファイル」をたどる（設計書 §5.1）。
/// 引用符の有無、環境変数、rundll32 や powershell のような間接起動を解く。
/// たどれなかったものは理由を付けて返す（隠さない）。
/// </summary>
public sealed class CommandLineResolver
{
    private const int MaxDepth = 4;
    private static readonly char[] Whitespace = { ' ', '\t' };

    private static readonly Regex KnownExtensionPath = new(
        @"^(.+?\.(?:exe|dll|sys|com|scr|bat|cmd|ps1|vbs|js|hta|msi|cpl|ocx))(?:\s|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CmdSwitch = new(
        @"(?:^|\s)/[ck]\s*(.*)$",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex StartCommand = new(
        @"^start(?:\s+""[^""]*"")?(?:\s+/d\s+(?:""[^""]*""|\S+)|\s+/\w+)*\s+(.*)$",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex Ps1InCommand = new(
        @"([A-Za-z]:\\[^'""|;&<>*?]+?\.ps1)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] PowerShellValueParameters =
    {
        "executionpolicy", "windowstyle", "version", "inputformat", "outputformat",
        "configurationname", "workingdirectory", "psconsolefile", "settingsfile",
        "custompipename", "encodedarguments",
    };

    private readonly IPathProbe _probe;

    public CommandLineResolver(IPathProbe probe) => _probe = probe;

    public ResolvedCommand Resolve(string raw) => Resolve(raw, raw, 0);

    /// <summary>拡張子から、暗黙に使われるスクリプト実行系の名前を返す。</summary>
    public static string? ImplicitScriptHost(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".bat" or ".cmd" => "cmd",
        ".vbs" or ".vbe" or ".js" or ".jse" or ".wsf" or ".wsh" => "wscript",
        ".hta" => "mshta",
        ".ps1" => "powershell",
        _ => null,
    };

    private ResolvedCommand Resolve(string original, string text, int depth)
    {
        if (depth > MaxDepth)
            return new ResolvedCommand(original, null, null, UnresolvedReason: "間接起動の入れ子が深すぎる");

        var expanded = NormalizePrefix(_probe.Expand(text.Trim()));
        if (expanded.Length == 0)
            return new ResolvedCommand(original, null, null, UnresolvedReason: "コマンドが空");

        if (!TrySplitExecutable(expanded, out var exe, out var args))
            return new ResolvedCommand(original, null, null, UnresolvedReason: "実行ファイルを特定できない");

        var name = SafeFileNameWithoutExtension(exe).ToLowerInvariant();
        return name switch
        {
            "rundll32" => Rundll32(original, exe, args),
            "regsvr32" => Regsvr32(original, exe, args),
            "mshta" => Mshta(original, exe, args),
            "powershell" or "pwsh" => PowerShell(original, exe, name, args),
            "cmd" => Cmd(original, exe, args, depth),
            "wscript" or "cscript" => WindowsScriptHost(original, exe, name, args),
            "conhost" => Conhost(original, exe, args, depth),
            _ => new ResolvedCommand(original, exe, exe, ImplicitScriptHost(exe)),
        };
    }

    // ---- 実行ファイルの切り出し ----

    private bool TrySplitExecutable(string expanded, out string exe, out string args)
    {
        exe = "";
        args = "";

        if (expanded[0] == '"')
        {
            // ""C:\x\y.exe"" のように引用符が二重に付いた登録もある（タスク スケジューラは受け付ける）
            var begin = 0;
            while (begin < expanded.Length && expanded[begin] == '"') begin++;
            var end = expanded.IndexOf('"', begin);
            var quoted = end < 0 ? expanded[begin..] : expanded[begin..end];
            var after = end < 0 ? expanded.Length : end;
            while (after < expanded.Length && expanded[after] == '"') after++;
            args = expanded[after..].TrimStart();
            quoted = NormalizePrefix(quoted.Trim());
            if (quoted.Length == 0) return false;
            var located = Locate(quoted);
            if (located is null && !IsRooted(quoted)) return false;
            exe = located ?? quoted;
            return true;
        }

        // 引用符が無いときは CreateProcess と同じく、空白の位置ごとに「そこまでがファイルか」を試す
        for (var i = 1; i <= expanded.Length; i++)
        {
            if (i < expanded.Length && !char.IsWhiteSpace(expanded[i])) continue;
            var located = Locate(expanded[..i]);
            if (located is null) continue;
            exe = located;
            args = expanded[i..].TrimStart();
            return true;
        }

        // どれも存在しない。パスの形をしていれば、拡張子までを推定のパスとして返す
        // （「登録は残っているが、ファイルが無い」として挙げるため）
        if (!IsRooted(expanded)) return false;
        var match = KnownExtensionPath.Match(expanded);
        exe = match.Success ? match.Groups[1].Value : FirstToken(expanded);
        args = expanded[exe.Length..].TrimStart();
        return exe.Length > 0;
    }

    private string? Locate(string candidate)
    {
        if (IsRooted(candidate))
        {
            if (_probe.FileExists(candidate)) return candidate;
            if (!HasExtension(candidate) && _probe.FileExists(candidate + ".exe")) return candidate + ".exe";
            return null;
        }
        // フォルダーの付いていない名前だけ PATH から探す
        if (candidate.IndexOfAny(new[] { '\\', '/', ' ' }) >= 0) return null;
        return _probe.SearchPath(candidate);
    }

    /// <summary>間接起動の対象ファイルを探す。絶対パスなら、無くてもそのまま返す。</summary>
    private string? LocateTarget(string name, string defaultExtension)
    {
        name = NormalizePrefix(_probe.Expand(name.Trim().Trim('"')));
        if (name.Length == 0) return null;
        if (IsRooted(name))
        {
            if (!_probe.FileExists(name) && !HasExtension(name) && _probe.FileExists(name + defaultExtension))
                return name + defaultExtension;
            return name;
        }
        if (name.IndexOfAny(Path.GetInvalidPathChars()) >= 0) return null;
        return _probe.SearchPath(name) ?? (HasExtension(name) ? null : _probe.SearchPath(name + defaultExtension));
    }

    // ---- 間接起動 ----

    private ResolvedCommand Rundll32(string original, string host, string args)
    {
        var rest = args.TrimStart();
        while (rest.StartsWith('/') || rest.StartsWith('-'))
        {
            // -sta {CLSID} のように、DLL ではなく COM のクラスを起動する形
            if (rest.StartsWith("-sta", StringComparison.OrdinalIgnoreCase)
                || rest.StartsWith("-localserver", StringComparison.OrdinalIgnoreCase))
                return new ResolvedCommand(original, host, null, "rundll32",
                    UnresolvedReason: "rundll32 が COM のクラスを起動している（DLL を特定できない）");
            var space = rest.IndexOfAny(Whitespace);
            rest = space < 0 ? "" : rest[(space + 1)..].TrimStart();
        }
        if (rest.Length == 0) return new ResolvedCommand(original, host, host);

        string dll;
        if (rest[0] == '"')
        {
            var end = rest.IndexOf('"', 1);
            dll = end < 0 ? rest[1..] : rest[1..end];
        }
        else
        {
            var comma = rest.IndexOf(',');
            dll = comma >= 0 ? rest[..comma] : FirstToken(rest);
        }
        dll = dll.Trim();

        if (LooksLikeScriptOrUrl(dll))
            return new ResolvedCommand(original, host, null, "rundll32", Inline: true);

        var target = LocateTarget(dll, ".dll");
        return target is null
            ? new ResolvedCommand(original, host, null, "rundll32", UnresolvedReason: $"rundll32 の対象「{dll}」が見つからない")
            : new ResolvedCommand(original, host, target, "rundll32");
    }

    private ResolvedCommand Regsvr32(string original, string host, string args)
    {
        var tokens = Tokenize(args);
        if (tokens.Count == 0) return new ResolvedCommand(original, host, host);

        // /i:http://… scrobj.dll の形は、外から取ってきたスクリプトを実行する
        var remote = tokens.Any(t => (t.StartsWith("/i:", StringComparison.OrdinalIgnoreCase)
                                      || t.StartsWith("-i:", StringComparison.OrdinalIgnoreCase))
                                     && t.Contains("://"));
        if (remote) return new ResolvedCommand(original, host, null, "regsvr32", Inline: true);

        var dll = tokens.LastOrDefault(t => !t.StartsWith('/') && !t.StartsWith('-'));
        if (dll is null)
            return new ResolvedCommand(original, host, null, "regsvr32", UnresolvedReason: "regsvr32 の対象が無い");

        var target = LocateTarget(dll, ".dll");
        return target is null
            ? new ResolvedCommand(original, host, null, "regsvr32", UnresolvedReason: $"regsvr32 の対象「{dll}」が見つからない")
            : new ResolvedCommand(original, host, target, "regsvr32");
    }

    private ResolvedCommand Mshta(string original, string host, string args)
    {
        var trimmed = args.Trim();
        if (trimmed.Length == 0) return new ResolvedCommand(original, host, host);
        if (LooksLikeScriptOrUrl(trimmed.TrimStart('"')))
            return new ResolvedCommand(original, host, null, "mshta", Inline: true);

        var target = LocateTarget(Tokenize(trimmed)[0], ".hta");
        return target is null
            ? new ResolvedCommand(original, host, null, "mshta", UnresolvedReason: "mshta の対象が見つからない")
            : new ResolvedCommand(original, host, target, "mshta");
    }

    private ResolvedCommand PowerShell(string original, string host, string hostName, string args)
    {
        var tokens = Tokenize(args);
        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            if (token.Length > 1 && (token[0] == '-' || token[0] == '/'))
            {
                var parameter = token[1..].ToLowerInvariant();
                var colon = parameter.IndexOf(':');
                if (colon > 0) parameter = parameter[..colon];

                // -e / -ec / -enc … は EncodedCommand（-ex… は ExecutionPolicy なので除く）
                if (parameter is "e" or "ec" || (parameter.Length >= 2 && "encodedcommand".StartsWith(parameter)))
                    return new ResolvedCommand(original, host, null, hostName, Inline: true, Encoded: true);

                if ("file".StartsWith(parameter))
                    return PowerShellFile(original, host, hostName, tokens.ElementAtOrDefault(i + 1));

                if (parameter is "c" || (parameter.Length >= 2 && "command".StartsWith(parameter)))
                    return PowerShellCommand(original, host, hostName, string.Join(' ', tokens.Skip(i + 1)));

                if (parameter is "ep" or "wd" or "ea"
                    || PowerShellValueParameters.Any(p => p.StartsWith(parameter)))
                    i++;
                continue;
            }

            // 最初の位置引数。.ps1 ならファイル、そうでなければその場の命令
            return token.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)
                ? PowerShellFile(original, host, hostName, token)
                : PowerShellCommand(original, host, hostName, string.Join(' ', tokens.Skip(i)));
        }

        // 引数が無ければ、対話シェルを開くだけ
        return new ResolvedCommand(original, host, host);
    }

    private ResolvedCommand PowerShellFile(string original, string host, string hostName, string? script)
    {
        var target = script is null ? null : LocateTarget(script, ".ps1");
        return target is null
            ? new ResolvedCommand(original, host, null, hostName, UnresolvedReason: $"{hostName} のスクリプトが見つからない")
            : new ResolvedCommand(original, host, target, hostName);
    }

    private ResolvedCommand PowerShellCommand(string original, string host, string hostName, string command)
    {
        // & 'C:\x\y.ps1' のように、スクリプトを呼んでいるだけならそのファイルを対象にする
        var match = Ps1InCommand.Match(_probe.Expand(command));
        return match.Success
            ? new ResolvedCommand(original, host, match.Groups[1].Value, hostName)
            : new ResolvedCommand(original, host, null, hostName, Inline: true);
    }

    private ResolvedCommand Cmd(string original, string host, string args, int depth)
    {
        var match = CmdSwitch.Match(args);
        if (!match.Success) return new ResolvedCommand(original, host, host);

        var inner = match.Groups[1].Value.Trim();
        // cmd /c ""C:\a b\x.exe" 引数" の、外側の引用符を 1 段はがす
        if (inner.StartsWith("\"\"", StringComparison.Ordinal))
        {
            inner = inner[1..];
            if (inner.EndsWith('"')) inner = inner[..^1];
        }

        var start = StartCommand.Match(inner);
        if (start.Success) inner = start.Groups[1].Value.Trim();

        if (inner.Length == 0)
            return new ResolvedCommand(original, host, null, "cmd", Inline: true);

        var resolved = Resolve(original, inner, depth + 1);
        if (resolved.HasFileTarget || resolved.Inline)
            return resolved with { HostPath = host, ScriptHost = resolved.ScriptHost ?? "cmd" };

        // echo や if のような組み込み命令。その場に書かれた命令として扱う
        return new ResolvedCommand(original, host, null, "cmd", Inline: true);
    }

    private ResolvedCommand WindowsScriptHost(string original, string host, string hostName, string args)
    {
        var script = Tokenize(args).FirstOrDefault(t => !t.StartsWith("//", StringComparison.Ordinal));
        if (script is null) return new ResolvedCommand(original, host, host);

        var target = LocateTarget(script, ".vbs");
        return target is null
            ? new ResolvedCommand(original, host, null, hostName, UnresolvedReason: $"{hostName} のスクリプト「{script}」が見つからない")
            : new ResolvedCommand(original, host, target, hostName);
    }

    private ResolvedCommand Conhost(string original, string host, string args, int depth)
    {
        // conhost --headless <コマンド> は、ウィンドウを出さずに別のコマンドを起動する
        var rest = args.TrimStart();
        while (rest.StartsWith("--", StringComparison.Ordinal))
        {
            var space = rest.IndexOfAny(Whitespace);
            rest = space < 0 ? "" : rest[(space + 1)..].TrimStart();
        }
        if (rest.Length == 0 || rest.Length == args.TrimStart().Length)
            return new ResolvedCommand(original, host, host);

        var resolved = Resolve(original, rest, depth + 1);
        return resolved with { HostPath = host };
    }

    // ---- 文字列の道具 ----

    /// <summary>NT 形式の接頭辞や、サービスの ImagePath に出る相対表記を、ふつうのパスに直す。</summary>
    internal string NormalizePrefix(string path)
    {
        if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path[4..];
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            return _probe.SystemRoot + path[11..];
        if (path.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(@"syswow64\", StringComparison.OrdinalIgnoreCase))
            return _probe.SystemRoot + @"\" + path;
        return path;
    }

    private static bool LooksLikeScriptOrUrl(string text) =>
        text.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase)
        || text.StartsWith("vbscript:", StringComparison.OrdinalIgnoreCase)
        || text.StartsWith("about:", StringComparison.OrdinalIgnoreCase)
        || text.Contains("://");

    private static bool IsRooted(string path)
    {
        // C:\… か \\server\share\… だけを絶対パスとみなす
        if (path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/'))
            return true;
        return path.StartsWith(@"\\", StringComparison.Ordinal) && path.Length > 2;
    }

    private static bool HasExtension(string path)
    {
        var name = path[(path.LastIndexOfAny(new[] { '\\', '/' }) + 1)..];
        return name.Contains('.');
    }

    private static string SafeFileNameWithoutExtension(string path)
    {
        var name = path[(path.LastIndexOfAny(new[] { '\\', '/' }) + 1)..];
        var dot = name.LastIndexOf('.');
        return dot > 0 ? name[..dot] : name;
    }

    private static string FirstToken(string text)
    {
        var space = text.IndexOfAny(Whitespace);
        return space < 0 ? text : text[..space];
    }

    /// <summary>空白で区切る。二重引用符で囲まれた部分は 1 つにまとめ、引用符は外す。</summary>
    internal static List<string> Tokenize(string text)
    {
        var tokens = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;
        var hasToken = false;
        foreach (var c in text)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
                hasToken = true;
            }
            else if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (hasToken) tokens.Add(current.ToString());
                current.Clear();
                hasToken = false;
            }
            else
            {
                current.Append(c);
                hasToken = true;
            }
        }
        if (hasToken) tokens.Add(current.ToString());
        return tokens;
    }
}
