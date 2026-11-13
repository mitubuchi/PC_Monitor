using System.Runtime.InteropServices;
using System.Text;

namespace PCMonitor.Core.Collectors;

/// <summary>
/// カーネルが返すファイル名（\Device\HarddiskVolume3\…）を、ドライブ文字のパス（C:\…）に直す。
/// メモリの割り当てに聞いたファイル名も、ETW のイベントに入っているファイル名も、この形で来る。
/// </summary>
public sealed class DevicePaths
{
    private const string Network = @"\Device\Mup\";
    private readonly List<(string Device, string Drive)> _devices;

    private DevicePaths(List<(string, string)> devices) => _devices = devices;

    public static DevicePaths Create()
    {
        var result = new List<(string, string)>();
        var buffer = new StringBuilder(512);
        foreach (var root in Environment.GetLogicalDrives())
        {
            var drive = root.TrimEnd('\\');
            if (QueryDosDeviceW(drive, buffer, (uint)buffer.Capacity) > 0)
                result.Add((buffer.ToString(), drive));
        }
        return new DevicePaths(result);
    }

    /// <summary>直せないものは、そのまま返す。</summary>
    public string ToDrivePath(string devicePath)
    {
        foreach (var (device, drive) in _devices)
        {
            if (devicePath.Length > device.Length && devicePath[device.Length] == '\\'
                && devicePath.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                return drive + devicePath[device.Length..];
        }
        return devicePath.StartsWith(Network, StringComparison.OrdinalIgnoreCase)
            ? @"\\" + devicePath[Network.Length..]
            : devicePath;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string deviceName, StringBuilder targetPath, uint max);
}
