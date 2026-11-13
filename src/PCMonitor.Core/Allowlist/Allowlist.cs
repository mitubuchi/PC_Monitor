using PCMonitor.Core.Model;
using PCMonitor.Core.Reports;

namespace PCMonitor.Core.Allowlist;

public sealed record AllowEntry(string Key, string Name, string? Path, string Sha256, DateTime AddedUtc);

/// <summary>
/// 許可リスト（設計書 §10）。パスとハッシュの組で持つ。
/// パスだけで許可すると、同じ場所のファイルを差し替えられても気づけないため。
/// </summary>
public sealed class AllowlistStore
{
    private readonly string _path;
    private readonly Dictionary<string, AllowEntry> _entries = new(StringComparer.Ordinal);

    public AllowlistStore(string path)
    {
        _path = path;
        foreach (var entry in JsonFiles.Read<List<AllowEntry>>(path) ?? new List<AllowEntry>())
            _entries[entry.Key] = entry;
    }

    public IReadOnlyCollection<AllowEntry> Entries => _entries.Values;

    /// <summary>ハッシュを取れなかったものは許可できない（中身が変わっても気づけなくなる）。</summary>
    public bool Add(Finding finding)
    {
        if (string.IsNullOrEmpty(finding.Sha256)) return false;
        _entries[finding.Key] = new AllowEntry(finding.Key, finding.Name, finding.Path, finding.Sha256, DateTime.UtcNow);
        finding.IsAllowed = true;
        finding.Indicators.RemoveAll(i => i.Kind == IndicatorKind.AllowedButChanged);
        Save();
        return true;
    }

    public bool Remove(Finding finding)
    {
        if (!_entries.Remove(finding.Key)) return false;
        finding.IsAllowed = false;
        Save();
        return true;
    }

    /// <summary>
    /// 許可の印を付ける。ハッシュが変わっていたら許可は外し、変わったことを情報として挙げる
    /// （更新でも変わるので、危険度は上げない）。
    /// </summary>
    public void Apply(IEnumerable<Finding> findings)
    {
        foreach (var finding in findings)
        {
            if (!_entries.TryGetValue(finding.Key, out var entry)) continue;

            if (string.Equals(entry.Sha256, finding.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                finding.IsAllowed = true;
            }
            else
            {
                finding.IsAllowed = false;
                finding.Indicators.Add(new Indicator(IndicatorKind.AllowedButChanged, 0, "許可後に変更",
                    $"許可済みだったが、中身が変わった（許可した日: {entry.AddedUtc.ToLocalTime():yyyy-MM-dd}）。更新でも変わる"));
            }
        }
    }

    private void Save() => JsonFiles.Write(_path, _entries.Values.OrderBy(e => e.Key, StringComparer.Ordinal).ToList());
}
