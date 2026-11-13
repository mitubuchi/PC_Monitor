using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Reports;

/// <summary>JSON の読み書き。UTF-8、BOM 無し（設計書 §10）。</summary>
public static class JsonFiles
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        // 日本語を \uXXXX にしない（人が読むファイルなので）
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() },
    };

    private static readonly UTF8Encoding Utf8NoBom = new(false);

    public static T? Read<T>(string path) where T : class
    {
        try
        {
            if (!File.Exists(path)) return null;
            return JsonSerializer.Deserialize<T>(File.ReadAllText(path, Encoding.UTF8), Options);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            // 壊れた保存ファイルで起動できなくなるより、無かったことにして続ける
            return null;
        }
    }

    public static void Write<T>(string path, T value)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

        // 書いている途中で落ちても元のファイルを壊さないよう、別名で書いてから置き換える
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(value, Options), Utf8NoBom);
        File.Move(temporary, path, overwrite: true);
    }
}

/// <summary>保存するファイルの置き場所（設計書 §10）。</summary>
public sealed class DataPaths
{
    public DataPaths(string? directory = null)
    {
        Directory = directory
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PCMonitor");
    }

    public string Directory { get; }
    public string Allowlist => Path.Combine(Directory, "allowlist.json");
    public string LastScan => Path.Combine(Directory, "last-scan.json");
}

/// <summary>前回の結果。差分に要るぶんだけを持つ。</summary>
public sealed record LastScan(DateTime ScannedUtc, List<LastScanItem> Items);

public sealed record LastScanItem(string Key, string? Sha256, int Score);

public static class ScanDiff
{
    /// <summary>前回に無かった項目に印を付ける。前回が無ければ（初回は）何も付けない。</summary>
    public static bool MarkNew(IEnumerable<Finding> findings, LastScan? previous)
    {
        if (previous is null) return false;
        var known = previous.Items.Select(i => i.Key).ToHashSet(StringComparer.Ordinal);
        foreach (var finding in findings)
            finding.IsNew = !known.Contains(finding.Key);
        return true;
    }

    public static LastScan Snapshot(DateTime scannedUtc, IEnumerable<Finding> findings) =>
        new(scannedUtc, findings.Select(f => new LastScanItem(f.Key, f.Sha256, f.Score)).ToList());
}

/// <summary>結果の書き出し（CSV と JSON）。</summary>
public static class ReportWriter
{
    public static void WriteJson(string path, ScanResult result) => JsonFiles.Write(path, result);

    public static void WriteCsv(string path, IEnumerable<Finding> findings)
    {
        var builder = new StringBuilder();
        builder.AppendLine("危険度,点,名前,パス,署名,兆候,根拠,SHA-256,作成日時,新規,許可済み");
        foreach (var f in findings)
        {
            builder.AppendJoin(',', new[]
            {
                f.LevelDisplay,
                f.Score.ToString(),
                f.Name,
                f.Path ?? "",
                f.Signature.Display,
                f.IndicatorSummary,
                string.Join(" / ", f.Indicators.Select(i => i.Evidence)),
                f.Sha256 ?? "",
                f.FileCreatedUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                f.IsNew ? "新規" : "",
                f.IsAllowed ? "許可済み" : "",
            }.Select(Escape));
            builder.AppendLine();
        }
        // CSV は Excel で開くことが多い。BOM が無いと日本語が化けるので、こちらは BOM を付ける
        File.WriteAllText(path, builder.ToString(), new UTF8Encoding(true));
    }

    private static string Escape(string value)
    {
        // 先頭が = + - @ のセルは、Excel が式として実行してしまう。文字として読ませる
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@') value = "'" + value;
        return value.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0
            ? "\"" + value.Replace("\"", "\"\"") + "\""
            : value;
    }
}
