namespace PCMonitor.Core.Monitoring;

/// <summary>キー入力に関わる API の呼び出しを、どのくらい重く見るか。</summary>
public enum KeyApiWeight
{
    /// <summary>正規のアプリも自分のためにふつうに行う形。点を付けず、事実として載せる。</summary>
    Note,
    /// <summary>キーの状態の問い合わせ。出る条件をまだ確かめていないので、低く数える。</summary>
    Polling,
    /// <summary>ほかのアプリに向けたキー入力まで受け取れる形。</summary>
    Capture,
}

/// <summary>
/// 見張っている間に起きた、キー入力に関わる API の呼び出し 1 回（設計書 §11.5）。
/// キー入力そのものは含まない。「誰が、どの API を、どういう形で呼んだか」だけ。
/// </summary>
public sealed record KeyApiCall(
    DateTime TimeUtc,
    int Pid,
    int Tid,
    string? Path,
    KeyApiWeight Weight,
    string Description);

/// <summary>見張っていた時間と、その間に拾った呼び出し。スキャンに渡す。</summary>
public sealed record KeyApiObservation(DateTime StartedUtc, DateTime? StoppedUtc, IReadOnlyList<KeyApiCall> Calls)
{
    public string Describe()
    {
        var from = StartedUtc.ToLocalTime();
        var to = (StoppedUtc ?? DateTime.UtcNow).ToLocalTime();
        var state = StoppedUtc is null ? "見張りを続けている" : "見張りは止めてある";
        return $"{from:HH:mm:ss} から {to:HH:mm:ss} まで（{(to - from).TotalMinutes:F1} 分間）見張り、{Calls.Count} 件の呼び出しを拾った。{state}。"
               + "見張りを始める前から設置されていたフックは、ここには出てこない";
    }
}

/// <summary>
/// Win32k の監査イベントの値から、呼び出しの意味を決める。
/// ETW にもファイルにも触らないので、規則だけを試せる。
/// </summary>
public static class KeyApiClassifier
{
    private const int WH_JOURNALRECORD = 0;
    private const int WH_KEYBOARD = 2;
    private const int WH_KEYBOARD_LL = 13;

    private const uint RIDEV_REMOVE = 0x1;
    private const uint RIDEV_PAGEONLY = 0x20;
    private const uint RIDEV_INPUTSINK = 0x100;
    private const uint RIDEV_EXINPUTSINK = 0x1000;

    private const uint MEM_IMAGE = 0x1000000;

    /// <summary>SetWindowsHookEx（ID 1002）。キー入力に関わらない種類のフックは null。</summary>
    public static (KeyApiWeight Weight, string Description)? Hook(int filterType, string? library)
    {
        var hasLibrary = !string.IsNullOrWhiteSpace(library) && library != "NULL";
        return filterType switch
        {
            WH_KEYBOARD_LL => (KeyApiWeight.Capture,
                "低レベルのキーボード フック（WH_KEYBOARD_LL）を設置した。すべてのアプリへのキー入力が、このプロセスを通る"),
            // DLL を伴うキーボード フックは、ほかのプロセスに入り込んで働く。
            // DLL の無いものは、自分のスレッドだけに向けたもの（メニューやダイアログの処理でふつうに使う）
            WH_KEYBOARD when hasLibrary => (KeyApiWeight.Capture,
                $"キーボード フック（WH_KEYBOARD）を、ほかのプロセスに入り込む DLL 付きで設置した: {library}"),
            WH_KEYBOARD => (KeyApiWeight.Note,
                "自分のスレッドに向けたキーボード フック（WH_KEYBOARD）を設置した"),
            WH_JOURNALRECORD => (KeyApiWeight.Capture,
                "入力を記録するフック（WH_JOURNALRECORD）を設置した"),
            _ => null,
        };
    }

    /// <summary>RegisterRawInputDevices（ID 1001）。キーボード以外と、登録の取り消しは null。</summary>
    public static (KeyApiWeight Weight, string Description)? RawInput(
        int usagePage, int usage, uint flags, bool succeeded, uint? threadStartRegionType)
    {
        // 汎用デスクトップ（1）のキーボード（6）とキーパッド（7）。PAGEONLY なら、ページ 1 のすべて
        var keyboard = usagePage == 1 && (usage is 6 or 7 || (flags & RIDEV_PAGEONLY) != 0);
        if (!keyboard || !succeeded || (flags & RIDEV_REMOVE) != 0) return null;

        var fromNowhere = threadStartRegionType is { } type && type != MEM_IMAGE
            ? "。登録したスレッドは、ファイルの裏付けが無いメモリから始まっている"
            : "";

        return (flags & (RIDEV_INPUTSINK | RIDEV_EXINPUTSINK)) != 0
            ? (KeyApiWeight.Capture,
                "キーボードの生入力を、前面に居ないときも受け取る形で登録した（RIDEV_INPUTSINK）" + fromNowhere)
            : (fromNowhere.Length > 0 ? KeyApiWeight.Capture : KeyApiWeight.Note,
                "キーボードの生入力を登録した（自分が前面のときだけ受け取る形）" + fromNowhere);
    }

    /// <summary>GetAsyncKeyState の、前面でないプロセスからの問い合わせ（ID 1003）。</summary>
    public static (KeyApiWeight Weight, string Description) Polling(long msSinceLastKeyEvent, long backgroundCallCount) =>
        (KeyApiWeight.Polling,
            $"前面に居ない状態で、キーの状態を問い合わせた（GetAsyncKeyState。回数 {backgroundCallCount}、最後のキー操作から {msSinceLastKeyEvent} ミリ秒）");
}
