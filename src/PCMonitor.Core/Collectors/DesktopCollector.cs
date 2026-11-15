using System.Runtime.InteropServices;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Collectors;

/// <summary>
/// 自分のウィンドウ ステーション（WinSta0）の中のデスクトップを並べる（設計書 §16.2 F）。
/// 画面に出ない別のデスクトップを作り、そこでブラウザーなどを動かす遠隔操作の手口（hidden VNC）を見るため。
///
/// この PC（2026-11-15、通常の権限）で列挙できたのは <c>Default</c> だけ。<c>Winlogon</c> などは
/// 守られていて、通常の権限では列挙に出てこない。ほかのウィンドウ ステーションやセッションの中は見えない。
/// </summary>
public sealed class DesktopCollector
{
    /// <summary>Windows が自分で作るデスクトップの名前。</summary>
    public static readonly IReadOnlySet<string> FamiliarNames =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Default", "Winlogon", "Disconnect", "Screen-saver" };

    public void Collect(ScanFacts facts, CancellationToken cancel)
    {
        cancel.ThrowIfCancellationRequested();

        // 自分のプロセスのウィンドウ ステーションではなく、名前で開く。サンドボックスなどから起動されて
        // 別のウィンドウ ステーションに乗っていても、利用者の画面のほうを見るため
        var station = OpenWindowStationW("WinSta0", false, WINSTA_ENUMDESKTOPS);
        if (station == IntPtr.Zero)
        {
            facts.Notes.Add(new ScanNote("隠しデスクトップ", $"WinSta0 を開けなかった（エラー {Marshal.GetLastWin32Error()}）"));
            return;
        }

        try
        {
            var names = new List<string>();
            if (!EnumDesktopsW(station, (name, _) => { names.Add(name); return true; }, IntPtr.Zero))
            {
                facts.Notes.Add(new ScanNote("隠しデスクトップ", $"デスクトップの一覧を取れなかった（エラー {Marshal.GetLastWin32Error()}）"));
                return;
            }

            foreach (var name in names)
            {
                var familiar = FamiliarNames.Contains(name);
                // 見慣れたものの中までは見ない（Default のウィンドウは数百ある。プロセスの点検で見ている）
                if (familiar)
                {
                    facts.Desktops.Add(new DesktopFact(name, true, Array.Empty<int>()));
                    continue;
                }
                var (owners, error) = WindowOwners(name);
                facts.Desktops.Add(new DesktopFact(name, false, owners, error));
            }
        }
        finally
        {
            CloseWindowStation(station);
        }
    }

    private static (IReadOnlyList<int> Owners, string? Error) WindowOwners(string desktopName)
    {
        // 名前で開くデスクトップは、呼び出したスレッドのウィンドウ ステーションの中から探される
        var desktop = OpenDesktopW(desktopName, 0, false, DESKTOP_READOBJECTS | DESKTOP_ENUMERATE);
        if (desktop == IntPtr.Zero) return (Array.Empty<int>(), $"開けなかった（エラー {Marshal.GetLastWin32Error()}）");
        try
        {
            var owners = new HashSet<int>();
            EnumDesktopWindows(desktop, (window, _) =>
            {
                GetWindowThreadProcessId(window, out var pid);
                if (pid != 0) owners.Add((int)pid);
                return true;
            }, IntPtr.Zero);
            return (owners.OrderBy(p => p).ToList(), null);
        }
        finally
        {
            CloseDesktop(desktop);
        }
    }

    // ---- P/Invoke ----

    private const uint WINSTA_ENUMDESKTOPS = 0x0001;
    private const uint DESKTOP_READOBJECTS = 0x0001;
    private const uint DESKTOP_ENUMERATE = 0x0040;

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    private delegate bool EnumNameProc(string name, IntPtr parameter);

    private delegate bool EnumWindowsProc(IntPtr window, IntPtr parameter);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenWindowStationW(string name, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint access);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseWindowStation(IntPtr station);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDesktopsW(IntPtr station, EnumNameProc callback, IntPtr parameter);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenDesktopW(string name, uint flags, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint access);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseDesktop(IntPtr desktop);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDesktopWindows(IntPtr desktop, EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
}
