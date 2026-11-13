using System.Runtime.InteropServices;
using System.Text;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Collectors;

/// <summary>
/// 各プロセスのアドレス空間を端から歩いて、2 つを集める（設計書 §11.2、§11.3）。
///
///   1. 実行イメージとして載っているファイル（読み込まれている DLL）
///   2. 実行できるのに、実行イメージではない領域（ファイルの裏付けが無い実行可能な領域）
///
/// プロセスが自分で持っている DLL の一覧（PEB）は読まない。そこは本人が書き換えられるので、
/// 名前を偽ったり、一覧から外したりできる。カーネルが覚えている割り当ての情報だけを使う。
/// 要るのは PROCESS_QUERY_INFORMATION だけで、ほかのプロセスのメモリの中身は読まない。
/// </summary>
public sealed class MemoryMapCollector
{
    public void Collect(ScanFacts facts, CancellationToken cancel)
    {
        var devices = DevicePaths.Create();
        var denied = 0;

        foreach (var process in facts.Processes)
        {
            cancel.ThrowIfCancellationRequested();
            var handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, (uint)process.Pid);
            if (handle == IntPtr.Zero)
            {
                denied++;
                continue;
            }
            try
            {
                var (modules, regions) = Walk(handle, devices);
                facts.Modules[process.Pid] = modules;
                if (regions.Count > 0)
                {
                    facts.ExecutableRegions[process.Pid] = regions;
                    if (JitEngines.Find(process.Path, modules) is { } engine)
                        facts.JitEngines[process.Pid] = engine;
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        if (denied > 0)
            facts.Notes.Add(new ScanNote("読み込み DLL とメモリ",
                $"{denied} 個のプロセスは、読み込んでいる DLL とメモリの割り当てを確かめられなかった（管理者なら見られる範囲が広がる）", true));
    }

    private static (List<string> Modules, List<ExecutableRegion> Regions) Walk(IntPtr process, DevicePaths devices)
    {
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var regions = new List<ExecutableRegion>();
        var name = new StringBuilder(1024);
        var size = (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
        long address = 0;

        while (VirtualQueryEx(process, (IntPtr)address, out var region, size) != 0)
        {
            if (region.Type == MEM_IMAGE)
            {
                // イメージの先頭の領域だけを見る（1 つのイメージは、節ごとに複数の領域に分かれている）
                if (region.State != MEM_FREE && region.BaseAddress == region.AllocationBase)
                {
                    var length = K32GetMappedFileNameW(process, region.BaseAddress, name, (uint)name.Capacity);
                    if (length > 0) files.Add(devices.ToDrivePath(name.ToString(0, (int)length)));
                }
            }
            else if (region.State == MEM_COMMIT && IsExecutable(region.Protect))
            {
                // 実行できるのに、実行イメージではない。ファイルを写しただけの領域（MEM_MAPPED）なら、
                // どのファイルかを聞いておく
                string? mappedFile = null;
                if (region.Type == MEM_MAPPED)
                {
                    var length = K32GetMappedFileNameW(process, region.BaseAddress, name, (uint)name.Capacity);
                    if (length > 0) mappedFile = devices.ToDrivePath(name.ToString(0, (int)length));
                }
                regions.Add(new ExecutableRegion(
                    region.BaseAddress.ToInt64(),
                    region.AllocationBase.ToInt64(),
                    (long)region.RegionSize,
                    IsWritable(region.Protect),
                    region.Type == MEM_PRIVATE,
                    mappedFile));
            }

            var next = region.BaseAddress.ToInt64() + (long)region.RegionSize;
            if (next <= address) break;
            address = next;
        }
        return (files.ToList(), regions);
    }

    private static bool IsExecutable(uint protect) =>
        (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

    private static bool IsWritable(uint protect) =>
        (protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_FREE = 0x10000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint MEM_MAPPED = 0x40000;
    private const uint MEM_IMAGE = 0x1000000;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public nuint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nuint VirtualQueryEx(IntPtr process, IntPtr address, out MEMORY_BASIC_INFORMATION buffer, nuint length);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint K32GetMappedFileNameW(IntPtr process, IntPtr address, StringBuilder fileName, uint size);
}
