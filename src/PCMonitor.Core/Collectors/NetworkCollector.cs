using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Collectors;

/// <summary>
/// TCP と UDP の待ち受け・接続を、プロセス ID 付きで集める（設計書 §5.3）。
/// スナップショットなので、点検した瞬間に張っていない接続は見えない。
/// </summary>
public sealed class NetworkCollector
{
    public void Collect(ScanFacts facts, CancellationToken cancel)
    {
        cancel.ThrowIfCancellationRequested();
        ReadTable(facts, "TCP (IPv4)", AddressFamily.InterNetwork, tcp: true);
        ReadTable(facts, "TCP (IPv6)", AddressFamily.InterNetworkV6, tcp: true);
        ReadTable(facts, "UDP (IPv4)", AddressFamily.InterNetwork, tcp: false);
        ReadTable(facts, "UDP (IPv6)", AddressFamily.InterNetworkV6, tcp: false);
    }

    private static void ReadTable(ScanFacts facts, string area, AddressFamily family, bool tcp)
    {
        var buffer = IntPtr.Zero;
        try
        {
            var size = 0;
            uint result;
            // 取っている間に表が伸びることがあるので、足りなければ取り直す
            for (var attempt = 0; ; attempt++)
            {
                result = tcp
                    ? GetExtendedTcpTable(buffer, ref size, false, (int)family, TCP_TABLE_OWNER_PID_ALL, 0)
                    : GetExtendedUdpTable(buffer, ref size, false, (int)family, UDP_TABLE_OWNER_PID, 0);
                if (result != ERROR_INSUFFICIENT_BUFFER || attempt >= 4) break;
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                size += 4096;
                buffer = Marshal.AllocHGlobal(size);
            }
            if (result != 0)
            {
                facts.Notes.Add(new ScanNote("通信", $"{area} の一覧を取れなかった（エラー {result}）"));
                return;
            }
            if (buffer == IntPtr.Zero) return;

            var count = Marshal.ReadInt32(buffer);
            var row = buffer + 4;
            var v6 = family == AddressFamily.InterNetworkV6;
            for (var i = 0; i < count; i++)
            {
                facts.Endpoints.Add((tcp, v6) switch
                {
                    (true, false) => ReadTcp4(row),
                    (true, true) => ReadTcp6(row),
                    (false, false) => ReadUdp4(row),
                    (false, true) => ReadUdp6(row),
                });
                row += (tcp, v6) switch
                {
                    (true, false) => 24,
                    (true, true) => 56,
                    (false, false) => 12,
                    (false, true) => 28,
                };
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }

    // MIB_TCPROW_OWNER_PID { state, localAddr, localPort, remoteAddr, remotePort, pid }
    private static EndpointFact ReadTcp4(IntPtr row)
    {
        var state = Marshal.ReadInt32(row);
        var listening = state == MIB_TCP_STATE_LISTEN;
        return new EndpointFact("TCP",
            Address4(row + 4), Port(row + 8),
            listening ? null : Address4(row + 12), listening ? 0 : Port(row + 16),
            StateName(state), Marshal.ReadInt32(row + 20));
    }

    // MIB_TCP6ROW_OWNER_PID { localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid }
    private static EndpointFact ReadTcp6(IntPtr row)
    {
        var state = Marshal.ReadInt32(row + 48);
        var listening = state == MIB_TCP_STATE_LISTEN;
        return new EndpointFact("TCP",
            Address6(row), Port(row + 20),
            listening ? null : Address6(row + 24), listening ? 0 : Port(row + 44),
            StateName(state), Marshal.ReadInt32(row + 52));
    }

    // MIB_UDPROW_OWNER_PID { localAddr, localPort, pid }
    private static EndpointFact ReadUdp4(IntPtr row) =>
        new("UDP", Address4(row), Port(row + 4), null, 0, "BOUND", Marshal.ReadInt32(row + 8));

    // MIB_UDP6ROW_OWNER_PID { localAddr[16], localScope, localPort, pid }
    private static EndpointFact ReadUdp6(IntPtr row) =>
        new("UDP", Address6(row), Port(row + 20), null, 0, "BOUND", Marshal.ReadInt32(row + 24));

    private static string Address4(IntPtr pointer)
    {
        var bytes = new byte[4];
        Marshal.Copy(pointer, bytes, 0, 4);
        return new IPAddress(bytes).ToString();
    }

    private static string Address6(IntPtr pointer)
    {
        var bytes = new byte[16];
        Marshal.Copy(pointer, bytes, 0, 16);
        var address = new IPAddress(bytes);
        return (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
    }

    /// <summary>ポートはネットワーク バイト順で、下位 16 ビットに入っている。</summary>
    private static int Port(IntPtr pointer) =>
        (Marshal.ReadByte(pointer) << 8) | Marshal.ReadByte(pointer + 1);

    private static string StateName(int state) => state switch
    {
        MIB_TCP_STATE_LISTEN => "LISTEN",
        5 => "ESTABLISHED",
        1 => "CLOSED",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        6 or 7 => "FIN_WAIT",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        _ => "OTHER",
    };

    public static bool IsLoopback(string address) =>
        IPAddress.TryParse(address, out var parsed) && IPAddress.IsLoopback(parsed);

    private const uint ERROR_INSUFFICIENT_BUFFER = 122;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;
    private const int MIB_TCP_STATE_LISTEN = 2;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool sort, int family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool sort, int family, int tableClass, uint reserved);
}
