using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using PCMonitor.Core.Model;

namespace PCMonitor.Core.Signing;

public interface ISignatureVerifier
{
    SignatureInfo Verify(string path);
}

/// <summary>
/// WinVerifyTrust による署名の検証（設計書 §5.4）。
/// 埋め込み署名が無ければ、カタログ署名を必ず確かめる。Windows 付属のファイルの多くは
/// カタログ署名だけなので、これを省くと System32 の中身が軒並み「無し」になる。
///
/// 失効の確認はしない（ネットワークに出ない）。数百のファイルを点検するたびに
/// 発行元へ問い合わせることになるため。
/// </summary>
public sealed class SignatureVerifier : ISignatureVerifier
{
    private const uint TrustENoSignature = 0x800B0100;
    private const uint TrustESubjectFormUnknown = 0x800B0003;
    private const uint TrustEProviderUnknown = 0x800B0001;

    private static readonly string[] CatalogHashAlgorithms = { "SHA256", "SHA1" };

    private readonly AppxPackageVerifier _packages = new(VerifyEmbedded);

    public SignatureInfo Verify(string path)
    {
        try
        {
            if (!File.Exists(path)) return SignatureInfo.Unknown with { Detail = "ファイルが無い" };

            var embedded = VerifyEmbedded(path);
            if (embedded.IsValid) return embedded;

            // 埋め込み署名が有効でなければ、カタログ署名、次に MSIX パッケージの署名を確かめる。
            // 「無い」ときだけでなく「無効」のときも確かめる。ネットワークに出ないので、
            // 証明書のつながりを手元だけでは組めない正規のファイルがある
            // （Windows 付属の WebView2 がそうだった）。中身が書き換えられていれば、
            // カタログにもパッケージの記録にも合わないので、ここで有効になることはない
            var other = VerifyCatalog(path) ?? _packages.TryVerify(path);
            if (other is { IsValid: true }) return other;
            return embedded.Status != SignatureStatus.None ? embedded : other ?? embedded;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            return SignatureInfo.Unknown with { Detail = ex.Message };
        }
    }

    private static SignatureInfo VerifyEmbedded(string path)
    {
        var pathPtr = Marshal.StringToCoTaskMemUni(path);
        var fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = pathPtr,
            };
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
            return RunWinVerifyTrust(WTD_CHOICE_FILE, fileInfoPtr, fromCatalog: false);
        }
        finally
        {
            Marshal.FreeCoTaskMem(fileInfoPtr);
            Marshal.FreeCoTaskMem(pathPtr);
        }
    }

    /// <summary>カタログに載っていなければ null。</summary>
    private static SignatureInfo? VerifyCatalog(string path)
    {
        using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        foreach (var algorithm in CatalogHashAlgorithms)
        {
            var driverAction = DriverActionVerify;
            if (!CryptCATAdminAcquireContext2(out var catAdmin, ref driverAction, algorithm, IntPtr.Zero, 0))
                continue;
            try
            {
                uint hashSize = 0;
                CryptCATAdminCalcHashFromFileHandle2(catAdmin, file, ref hashSize, null, 0);
                if (hashSize == 0) continue;
                var hash = new byte[hashSize];
                if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, file, ref hashSize, hash, 0))
                    continue;

                var previous = IntPtr.Zero;
                var catInfoHandle = CryptCATAdminEnumCatalogFromHash(catAdmin, hash, hashSize, 0, ref previous);
                if (catInfoHandle == IntPtr.Zero) continue;
                try
                {
                    var catalogInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                    if (!CryptCATCatalogInfoFromContext(catInfoHandle, ref catalogInfo, 0))
                        continue;

                    return VerifyCatalogMember(path, file, catalogInfo.wszCatalogFile, hash, catAdmin);
                }
                finally
                {
                    CryptCATAdminReleaseCatalogContext(catAdmin, catInfoHandle, 0);
                }
            }
            finally
            {
                CryptCATAdminReleaseContext(catAdmin, 0);
            }
        }
        return null;
    }

    private static SignatureInfo VerifyCatalogMember(string path, SafeFileHandle file, string catalogPath, byte[] hash, IntPtr catAdmin)
    {
        var memberTag = Convert.ToHexString(hash);
        var catalogPathPtr = Marshal.StringToCoTaskMemUni(catalogPath);
        var memberTagPtr = Marshal.StringToCoTaskMemUni(memberTag);
        var memberPathPtr = Marshal.StringToCoTaskMemUni(path);
        var hashPtr = Marshal.AllocCoTaskMem(hash.Length);
        var infoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
        try
        {
            Marshal.Copy(hash, 0, hashPtr, hash.Length);
            var info = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = catalogPathPtr,
                pcwszMemberTag = memberTagPtr,
                pcwszMemberFilePath = memberPathPtr,
                hMemberFile = file.DangerousGetHandle(),
                pbCalculatedFileHash = hashPtr,
                cbCalculatedFileHash = (uint)hash.Length,
                hCatAdmin = catAdmin,
            };
            Marshal.StructureToPtr(info, infoPtr, false);
            return RunWinVerifyTrust(WTD_CHOICE_CATALOG, infoPtr, fromCatalog: true);
        }
        finally
        {
            Marshal.FreeCoTaskMem(infoPtr);
            Marshal.FreeCoTaskMem(hashPtr);
            Marshal.FreeCoTaskMem(memberPathPtr);
            Marshal.FreeCoTaskMem(memberTagPtr);
            Marshal.FreeCoTaskMem(catalogPathPtr);
        }
    }

    private static SignatureInfo RunWinVerifyTrust(uint unionChoice, IntPtr unionData, bool fromCatalog)
    {
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pUnion = unionData,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
        };
        var action = WintrustActionGenericVerifyV2;
        var result = unchecked((uint)WinVerifyTrust(InvalidHandleValue, ref action, ref data));
        try
        {
            if (result is TrustENoSignature or TrustESubjectFormUnknown or TrustEProviderUnknown)
                return new SignatureInfo(SignatureStatus.None);

            var (publisher, organization) = ReadSigner(data.hWVTStateData);
            if (result != 0)
                return new SignatureInfo(SignatureStatus.Invalid, publisher, fromCatalog, DescribeError(result));

            var isMicrosoft = string.Equals(organization, "Microsoft Corporation", StringComparison.OrdinalIgnoreCase);
            return new SignatureInfo(
                isMicrosoft ? SignatureStatus.ValidMicrosoft : SignatureStatus.ValidOther,
                publisher ?? organization,
                fromCatalog);
        }
        finally
        {
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(InvalidHandleValue, ref action, ref data);
        }
    }

    /// <summary>署名者の証明書から、表示名と組織名（O=）を読む。</summary>
    private static (string? Publisher, string? Organization) ReadSigner(IntPtr stateData)
    {
        if (stateData == IntPtr.Zero) return (null, null);
        var providerData = WTHelperProvDataFromStateData(stateData);
        if (providerData == IntPtr.Zero) return (null, null);
        var signer = WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
        if (signer == IntPtr.Zero) return (null, null);
        var providerCert = WTHelperGetProvCertFromChain(signer, 0);
        if (providerCert == IntPtr.Zero) return (null, null);

        // CRYPT_PROVIDER_CERT は { DWORD cbStruct; PCCERT_CONTEXT pCert; … }。ポインターの境界に揃う
        var certContext = Marshal.ReadIntPtr(providerCert, IntPtr.Size);
        if (certContext == IntPtr.Zero) return (null, null);

        return (GetCertName(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, null),
                GetCertName(certContext, CERT_NAME_ATTR_TYPE, OidOrganizationName));
    }

    private static string? GetCertName(IntPtr certContext, uint type, string? oid)
    {
        var oidPtr = oid is null ? IntPtr.Zero : Marshal.StringToCoTaskMemAnsi(oid);
        try
        {
            var length = CertGetNameStringW(certContext, type, 0, oidPtr, null, 0);
            if (length <= 1) return null;
            var buffer = new StringBuilder((int)length);
            CertGetNameStringW(certContext, type, 0, oidPtr, buffer, length);
            var name = buffer.ToString();
            return name.Length == 0 ? null : name;
        }
        finally
        {
            if (oidPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(oidPtr);
        }
    }

    private static string DescribeError(uint code) => code switch
    {
        0x80096010 => "ファイルの中身が署名と合わない（改ざんの疑い）",
        0x800B0101 => "証明書の期限が切れている",
        0x800B010C => "証明書が失効している",
        0x800B0109 => "信頼されていない発行元にたどり着く",
        0x800B010A => "証明書のつながりを確かめられない",
        0x800B0111 => "発行元が明示的に信頼を外されている",
        0x800B0004 => "署名が信頼されていない",
        _ => $"検証に失敗（0x{code:X8}）",
    };

    // ---- P/Invoke ----

    private static readonly IntPtr InvalidHandleValue = new(-1);
    private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly Guid DriverActionVerify = new("F750E6C3-38EE-11d1-85E5-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    private const uint WTD_DISABLE_MD2_MD4 = 0x2000;

    private const uint CERT_NAME_ATTR_TYPE = 3;
    private const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;
    private const string OidOrganizationName = "2.5.4.10";

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, uint idxSigner, [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner, uint idxCounterSigner);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, uint idxCert);

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, ref Guid pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("crypt32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern uint CertGetNameStringW(IntPtr pCertContext, uint dwType, uint dwFlags, IntPtr pvTypePara, StringBuilder? pszNameString, uint cchNameString);
}

/// <summary>同じファイルを何度も検証しないための覚え書き。1 回のスキャンの間だけ使う。</summary>
public sealed class CachingSignatureVerifier : ISignatureVerifier
{
    private readonly ISignatureVerifier _inner;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, SignatureInfo> _cache = new(StringComparer.OrdinalIgnoreCase);

    public CachingSignatureVerifier(ISignatureVerifier inner) => _inner = inner;

    public SignatureInfo Verify(string path) => _cache.GetOrAdd(path, _inner.Verify);
}
