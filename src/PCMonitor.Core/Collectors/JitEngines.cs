namespace PCMonitor.Core.Collectors;

/// <summary>
/// 実行時にコードを作る仕組み（JIT）を持つプロセスかどうかを見分ける（設計書 §11.3）。
///
/// JIT は、ファイルの裏付けが無い実行可能な領域を正規に作る。それをインジェクションと
/// 区別できないので、JIT を持つプロセスでは「領域がある」こと自体を兆候にしない。
/// </summary>
public static class JitEngines
{
    private static readonly Dictionary<string, string> ByModule = new(StringComparer.OrdinalIgnoreCase)
    {
        ["clr.dll"] = ".NET Framework",
        ["mscorwks.dll"] = ".NET Framework",
        ["coreclr.dll"] = ".NET",
        ["clrjit.dll"] = ".NET",
        ["jvm.dll"] = "Java",
        ["chrome.dll"] = "V8（Chrome）",
        ["msedge.dll"] = "V8（Edge / WebView2）",
        ["libcef.dll"] = "V8（CEF）",
        ["node.dll"] = "V8（Node.js）",
        ["libnode.dll"] = "V8（Node.js）",
        ["v8.dll"] = "V8",
        ["jscript9.dll"] = "Chakra",
        ["chakra.dll"] = "Chakra",
        ["chakracore.dll"] = "Chakra",
        ["xul.dll"] = "SpiderMonkey（Firefox）",
        ["qt5qml.dll"] = "Qt QML",
        ["qt6qml.dll"] = "Qt QML",
        ["luajit.dll"] = "LuaJIT",
    };

    // JIT を DLL に分けず、本体の EXE に内蔵しているもの。DLL の名前では見分けられないので、
    // EXE が外に公開しているシンボルで見分ける。
    //   - Node.js・Electron・Bun・Deno は、ネイティブ アドオン向けに N-API（napi_*）を EXE から公開している
    //   - .NET の単一ファイル アプリは、デバッガー向けに DotNetRuntimeInfo を公開している
    private static readonly (string Symbol, string Engine)[] ByExport =
    {
        ("napi_create_function", "JavaScript エンジン（EXE に内蔵）"),
        ("DotNetRuntimeInfo", ".NET（EXE に内蔵）"),
    };

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string?> ExportCache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>JIT の手がかりがあれば、その名前を返す。</summary>
    public static string? Find(string? executablePath, IEnumerable<string> modules)
    {
        foreach (var module in modules)
        {
            var name = module[(module.LastIndexOfAny(new[] { '\\', '/' }) + 1)..];
            if (ByModule.TryGetValue(name, out var engine)) return engine;
        }
        return executablePath is null ? null : ExportCache.GetOrAdd(executablePath, FindByExport);
    }

    private static string? FindByExport(string path)
    {
        foreach (var (symbol, engine) in ByExport)
        {
            if (PeExports.ContainsAny(path, symbol)) return engine;
        }
        return null;
    }
}
