using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Collectors;

/// <summary>動いているプロセスを集める（設計書 §5.2）。</summary>
public sealed class ProcessCollector
{
    public void Collect(ScanFacts facts, CancellationToken cancel)
    {
        cancel.ThrowIfCancellationRequested();

        var windowOwners = VisibleWindowOwners();
        var commandLines = ReadCommandLines(facts);
        var inaccessible = 0;

        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == InvalidHandleValue)
        {
            facts.Notes.Add(new ScanNote("プロセス", "プロセスの一覧を取れなかった"));
            return;
        }

        try
        {
            var entry = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snapshot, ref entry)) return;
            do
            {
                cancel.ThrowIfCancellationRequested();
                var pid = (int)entry.th32ProcessID;
                // 0 は Idle、4 は System（カーネル）。実行ファイルを持たない
                if (pid is 0 or 4) continue;
                // 点検している自分自身は候補にしない
                if (pid == Environment.ProcessId) continue;

                var (path, started) = QueryImagePath(pid);
                if (path is null && !IsKernelPseudoProcess(entry.szExeFile)) inaccessible++;

                ProcessIdToSessionId((uint)pid, out var session);
                commandLines.TryGetValue(pid, out var commandLine);
                facts.Processes.Add(new ProcessFact(
                    pid,
                    (int)entry.th32ParentProcessID,
                    entry.szExeFile,
                    path,
                    commandLine,
                    windowOwners.Contains(pid),
                    (int)session,
                    started));
            }
            while (Process32NextW(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        if (inaccessible > 0)
            facts.Notes.Add(new ScanNote("プロセス",
                $"{inaccessible} 個のプロセスの実行ファイルを確かめられなかった（管理者なら見られる）", true));
    }

    /// <summary>Registry や Memory Compression のように、実行ファイルを持たないカーネルの仮のプロセス。</summary>
    private static bool IsKernelPseudoProcess(string name) =>
        name is "Registry" or "Memory Compression" or "Secure System" or "vmmem" or "vmmemWSL" or "[System Process]";

    public static int CurrentSessionId()
    {
        ProcessIdToSessionId((uint)Environment.ProcessId, out var session);
        return (int)session;
    }

    /// <summary>
    /// 実行ファイルのパスと起動時刻。起動時刻は、親プロセスの番号が使い回されていないかを
    /// 確かめるのに使う（親が終わったあと、同じ番号が別のプロセスに付くことがある）。
    /// </summary>
    private static (string? Path, DateTime? StartedUtc) QueryImagePath(int pid)
    {
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (handle == IntPtr.Zero) return (null, null);
        try
        {
            var buffer = new StringBuilder(1024);
            var size = (uint)buffer.Capacity;
            var path = QueryFullProcessImageNameW(handle, 0, buffer, ref size) ? buffer.ToString(0, (int)size) : null;
            DateTime? started = GetProcessTimes(handle, out var creation, out _, out _, out _) && creation > 0
                ? DateTime.FromFileTimeUtc(creation)
                : null;
            return (path, started);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static HashSet<int> VisibleWindowOwners()
    {
        var owners = new HashSet<int>();
        EnumWindows((window, _) =>
        {
            if (IsWindowVisible(window))
            {
                GetWindowThreadProcessId(window, out var pid);
                owners.Add((int)pid);
            }
            return true;
        }, IntPtr.Zero);
        return owners;
    }

    private static Dictionary<int, string> ReadCommandLines(ScanFacts facts)
    {
        var result = new Dictionary<int, string>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, CommandLine FROM Win32_Process");
            using var processes = searcher.Get();
            foreach (var process in processes)
            {
                using (process)
                {
                    if (process["CommandLine"] is string commandLine && process["ProcessId"] is uint pid)
                        result[(int)pid] = commandLine;
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException)
        {
            facts.Notes.Add(new ScanNote("プロセス", $"コマンドラインを取れなかった: {ex.Message}"));
        }
        return result;
    }

    // ---- P/Invoke ----

    private static readonly IntPtr InvalidHandleValue = new(-1);
    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    private delegate bool EnumWindowsProc(IntPtr window, IntPtr parameter);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(IntPtr snapshot, ref PROCESSENTRY32W entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(IntPtr snapshot, ref PROCESSENTRY32W entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder name, ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr window);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
}
