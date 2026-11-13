using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Xml;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Signing;

/// <summary>
/// MSIX（ストア アプリ）の中のファイルを確かめる。
///
/// パッケージの中の実行ファイルは、埋め込み署名もカタログ署名も持たないことが多い。
/// 署名はパッケージ全体に 1 つ（AppxSignature.p7x）で、各ファイルのハッシュは
/// AppxBlockMap.xml に載っている。そこで 3 段で確かめる。
///
///   1. AppxSignature.p7x の署名が有効か（WinVerifyTrust）
///   2. p7x が保証している AppxBlockMap.xml のハッシュ（AXBM）が、実際のファイルと合うか
///   3. 対象のファイルの中身が、AppxBlockMap.xml に載ったブロックごとのハッシュと合うか
///
/// 1 つでも欠ければ「署名あり」とはしない。
/// </summary>
internal sealed class AppxPackageVerifier
{
    private const string SignatureFile = "AppxSignature.p7x";
    private const string BlockMapFile = "AppxBlockMap.xml";
    private const int BlockSize = 64 * 1024;
    private const int MaxDepth = 12;

    private readonly Func<string, SignatureInfo> _verifyEmbedded;
    private readonly ConcurrentDictionary<string, Lazy<Package?>> _packages = new(StringComparer.OrdinalIgnoreCase);

    public AppxPackageVerifier(Func<string, SignatureInfo> verifyEmbedded) => _verifyEmbedded = verifyEmbedded;

    /// <summary>パッケージの中のファイルでなければ null。</summary>
    public SignatureInfo? TryVerify(string path)
    {
        var root = FindPackageRoot(path);
        if (root is null) return null;

        var package = _packages.GetOrAdd(root, r => new Lazy<Package?>(() => LoadPackage(r))).Value;
        if (package is null) return null;
        if (!package.Signature.IsValid) return package.Signature;

        var relative = Path.GetRelativePath(root, path);
        if (!package.Files.TryGetValue(relative, out var expected))
            return null; // パッケージの記録に無いファイル。あとから置かれたものなので、署名なしのまま

        return MatchesBlocks(path, expected, package.HashName)
            ? package.Signature
            : new SignatureInfo(SignatureStatus.Invalid, package.Signature.Publisher,
                Detail: "ファイルの中身が、パッケージの記録（AppxBlockMap.xml）と合わない");
    }

    private static string? FindPackageRoot(string path)
    {
        var directory = Path.GetDirectoryName(path);
        for (var depth = 0; depth < MaxDepth && !string.IsNullOrEmpty(directory); depth++)
        {
            if (File.Exists(Path.Combine(directory, SignatureFile)) && File.Exists(Path.Combine(directory, BlockMapFile)))
                return directory;
            directory = Path.GetDirectoryName(directory);
        }
        return null;
    }

    private Package? LoadPackage(string root)
    {
        try
        {
            var signature = _verifyEmbedded(Path.Combine(root, SignatureFile));
            if (signature.Status is SignatureStatus.None or SignatureStatus.Unknown) return null;
            if (!signature.IsValid) return new Package(signature, "", EmptyFiles);

            var blockMap = File.ReadAllBytes(Path.Combine(root, BlockMapFile));
            var signed = ReadSignedBlockMapHash(File.ReadAllBytes(Path.Combine(root, SignatureFile)));
            if (signed is null || !signed.AsSpan().SequenceEqual(SHA256.HashData(blockMap)))
                return new Package(new SignatureInfo(SignatureStatus.Invalid, signature.Publisher,
                    Detail: "AppxBlockMap.xml が、パッケージの署名と合わない"), "", EmptyFiles);

            var (hashName, files) = ParseBlockMap(blockMap);
            return new Package(signature with { Detail = "MSIX パッケージの署名" }, hashName, files);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or XmlException or FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// p7x の署名対象は「APPX」に続けて、AXPC・AXCD・AXCT・AXBM・AXCI の各 4 文字＋ SHA-256（32 バイト）。
    /// このうち AXBM が AppxBlockMap.xml のハッシュ。
    /// </summary>
    private static byte[]? ReadSignedBlockMapHash(byte[] p7x)
    {
        var start = p7x.AsSpan().IndexOf("APPXAXPC"u8);
        if (start < 0) return null;
        var content = p7x.AsSpan(start);
        var marker = content.IndexOf("AXBM"u8);
        if (marker < 0 || marker > 4 + 36 * 4 || content.Length < marker + 4 + 32) return null;
        return content.Slice(marker + 4, 32).ToArray();
    }

    private static (string HashName, Dictionary<string, string[]> Files) ParseBlockMap(byte[] xml)
    {
        var files = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        var hashName = "SHA256";
        string? currentFile = null;
        var blocks = new List<string>();

        using var reader = XmlReader.Create(new MemoryStream(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });
        while (reader.Read())
        {
            if (reader.NodeType == XmlNodeType.Element)
            {
                switch (reader.LocalName)
                {
                    case "BlockMap":
                        var method = reader.GetAttribute("HashMethod") ?? "";
                        hashName = method.EndsWith("sha384", StringComparison.OrdinalIgnoreCase) ? "SHA384"
                            : method.EndsWith("sha512", StringComparison.OrdinalIgnoreCase) ? "SHA512"
                            : "SHA256";
                        break;
                    case "File":
                        currentFile = reader.GetAttribute("Name");
                        blocks.Clear();
                        if (reader.IsEmptyElement && currentFile is not null)
                        {
                            files[currentFile] = Array.Empty<string>();
                            currentFile = null;
                        }
                        break;
                    case "Block":
                        if (reader.GetAttribute("Hash") is { } hash) blocks.Add(hash);
                        break;
                }
            }
            else if (reader.NodeType == XmlNodeType.EndElement && reader.LocalName == "File" && currentFile is not null)
            {
                files[currentFile] = blocks.ToArray();
                currentFile = null;
            }
        }
        return (hashName, files);
    }

    /// <summary>ファイルを 64 KB ごとに区切り、ブロックごとのハッシュを記録と比べる。</summary>
    private static bool MatchesBlocks(string path, string[] expected, string hashName)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, BlockSize, FileOptions.SequentialScan);
            var buffer = new byte[BlockSize];
            var index = 0;
            while (true)
            {
                var read = stream.ReadAtLeast(buffer, BlockSize, throwOnEndOfStream: false);
                if (read == 0) break;
                if (index >= expected.Length) return false;
                var actual = hashName switch
                {
                    "SHA384" => SHA384.HashData(buffer.AsSpan(0, read)),
                    "SHA512" => SHA512.HashData(buffer.AsSpan(0, read)),
                    _ => SHA256.HashData(buffer.AsSpan(0, read)),
                };
                if (!actual.AsSpan().SequenceEqual(Convert.FromBase64String(expected[index]))) return false;
                index++;
            }
            return index == expected.Length;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
            return false;
        }
    }

    private static readonly Dictionary<string, string[]> EmptyFiles = new();

    private sealed record Package(SignatureInfo Signature, string HashName, Dictionary<string, string[]> Files);
}
