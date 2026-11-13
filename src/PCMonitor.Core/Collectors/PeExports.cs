using System.Buffers.Binary;

namespace PCMonitor.Core.Collectors;

/// <summary>
/// 実行ファイルが公開しているシンボル（エクスポート）の名前を、ディスク上のファイルから読む。
/// 動いているプロセスのメモリは読まない。
/// </summary>
public static class PeExports
{
    private const int MaxExportBytes = 64 * 1024 * 1024;

    /// <summary>エクスポートの名前の中に、どれかの文字列が含まれるか。読めなければ false。</summary>
    public static bool ContainsAny(string path, params string[] needles)
    {
        try
        {
            var exports = ReadExportDirectory(path);
            if (exports is null) return false;
            foreach (var needle in needles)
            {
                if (exports.AsSpan().IndexOf(System.Text.Encoding.ASCII.GetBytes(needle)) >= 0) return true;
            }
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>エクスポート ディレクトリの中身（名前の文字列を含む）を、そのまま返す。</summary>
    private static byte[]? ReadExportDirectory(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        var dos = new byte[0x40];
        if (!TryRead(stream, 0, dos) || dos[0] != 'M' || dos[1] != 'Z') return null;
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(dos.AsSpan(0x3C));

        // 署名（4）＋ COFF ヘッダー（20）
        var coff = new byte[24];
        if (peOffset <= 0 || !TryRead(stream, peOffset, coff)
            || coff[0] != 'P' || coff[1] != 'E' || coff[2] != 0 || coff[3] != 0)
            return null;
        var sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(coff.AsSpan(6));
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(coff.AsSpan(20));

        var optional = new byte[optionalSize];
        var optionalOffset = peOffset + 24;
        if (optionalSize < 2 || !TryRead(stream, optionalOffset, optional)) return null;

        // データ ディレクトリの先頭がエクスポート。位置は 32 ビットと 64 ビットで違う
        var directoryOffset = BinaryPrimitives.ReadUInt16LittleEndian(optional) switch
        {
            0x10b => 96,
            0x20b => 112,
            _ => -1,
        };
        if (directoryOffset < 0 || optional.Length < directoryOffset + 8) return null;
        var exportRva = BinaryPrimitives.ReadUInt32LittleEndian(optional.AsSpan(directoryOffset));
        var exportSize = BinaryPrimitives.ReadUInt32LittleEndian(optional.AsSpan(directoryOffset + 4));
        if (exportRva == 0 || exportSize == 0 || exportSize > MaxExportBytes) return null;

        // セクションの表から、メモリ上の位置（RVA）をファイル上の位置に直す
        var sections = new byte[sectionCount * 40];
        if (!TryRead(stream, optionalOffset + optionalSize, sections)) return null;
        for (var i = 0; i < sectionCount; i++)
        {
            var section = sections.AsSpan(i * 40, 40);
            var virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(section[8..]);
            var virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(section[12..]);
            var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(section[16..]);
            var rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(section[20..]);
            var span = Math.Max(virtualSize, rawSize);
            if (exportRva < virtualAddress || exportRva >= virtualAddress + span) continue;

            var offset = rawOffset + (exportRva - virtualAddress);
            var available = (long)rawOffset + rawSize - offset;
            if (available <= 0) return null;
            var buffer = new byte[Math.Min(exportSize, available)];
            return TryRead(stream, offset, buffer) ? buffer : null;
        }
        return null;
    }

    private static bool TryRead(FileStream stream, long offset, byte[] buffer)
    {
        if (offset < 0 || offset + buffer.Length > stream.Length) return false;
        stream.Position = offset;
        stream.ReadExactly(buffer);
        return true;
    }
}
