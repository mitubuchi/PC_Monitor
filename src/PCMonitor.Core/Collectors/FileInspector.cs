using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using PCMonitor.Core.Model;
using PCMonitor.Core.Signing;

namespace PCMonitor.Core.Collectors;

public interface IFileInspector
{
    FileFacts Inspect(string path);
}

/// <summary>ファイルそのものの事実（有無・作成日時・ハッシュ・署名・書き込めるか）を集める。</summary>
public sealed class FileInspector : IFileInspector
{
    private const FileSystemRights WriteRights = FileSystemRights.WriteData | FileSystemRights.AppendData;

    private readonly ISignatureVerifier _verifier;
    private readonly HashSet<SecurityIdentifier> _ordinarySids;
    private readonly string _profilesRoot;
    private readonly string _windowsTemp;

    public FileInspector(ISignatureVerifier verifier)
    {
        _verifier = verifier;

        // 管理者でない利用者が持つ SID。昇格して動かしていても、Administrators は数えない
        _ordinarySids = new HashSet<SecurityIdentifier>
        {
            new(WellKnownSidType.BuiltinUsersSid, null),
            new(WellKnownSidType.AuthenticatedUserSid, null),
            new(WellKnownSidType.WorldSid, null),
            new(WellKnownSidType.InteractiveSid, null),
        };
        using (var identity = WindowsIdentity.GetCurrent())
        {
            if (identity.User is not null) _ordinarySids.Add(identity.User);
        }

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _profilesRoot = EnsureTrailingSeparator(Path.GetDirectoryName(profile) ?? @"C:\Users");
        _windowsTemp = EnsureTrailingSeparator(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
    }

    public FileFacts Inspect(string path)
    {
        FileInfo info;
        try
        {
            info = new FileInfo(path);
            if (!info.Exists) return FileFacts.Missing(path);
        }
        catch (Exception ex) when (IsFileError(ex))
        {
            return FileFacts.Missing(path) with { Error = ex.Message };
        }

        string? error = null;
        DateTime? created = null;
        var hidden = false;
        try
        {
            created = info.CreationTimeUtc;
            hidden = info.Attributes.HasFlag(FileAttributes.Hidden);
        }
        catch (Exception ex) when (IsFileError(ex))
        {
            error = ex.Message;
        }

        string? sha256 = null;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
            sha256 = Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception ex) when (IsFileError(ex))
        {
            error = ex.Message;
        }

        return new FileFacts(path, true, created, hidden, sha256, _verifier.Verify(path), IsUserWritable(info), error);
    }

    /// <summary>
    /// 管理者でない利用者が書き換えられるファイルか。
    /// フォルダーの名前ではなく、ファイルのアクセス許可を実際に読んで決める
    /// （ProgramData の下でも、Defender のように守られた場所は書き込めない）。
    /// </summary>
    private bool IsUserWritable(FileInfo info)
    {
        // ほかの利用者のプロファイルは、その利用者なら書ける
        if (info.FullName.StartsWith(_profilesRoot, StringComparison.OrdinalIgnoreCase)
            || info.FullName.StartsWith(_windowsTemp, StringComparison.OrdinalIgnoreCase))
            return true;

        try
        {
            var rules = info.GetAccessControl(AccessControlSections.Access)
                .GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                if ((rule.FileSystemRights & WriteRights) == 0) continue;
                if (rule.IdentityReference is SecurityIdentifier sid && _ordinarySids.Contains(sid)) return true;
            }
        }
        catch (Exception ex) when (IsFileError(ex) || ex is InvalidOperationException or IdentityNotMappedException)
        {
            // 許可を読めない場所（WindowsApps など）は、利用者が書ける場所ではない
        }
        return false;
    }

    private static bool IsFileError(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or ArgumentException or NotSupportedException;

    private static string EnsureTrailingSeparator(string path) =>
        path.EndsWith('\\') ? path : path + '\\';
}
