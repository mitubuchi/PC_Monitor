using System.Windows;
using System.Windows.Threading;
using ReactiveUI.Builder;

namespace PCMonitor.Wpf;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // ReactiveUI 20 以降は明示的な初期化が必須。WhenAnyValue などを最初に触る前に
        // 済ませる必要があるため、StartupUri は使わず MainWindow の生成もここで行う。
        // （SubPi.Wpf・DeviceMap と同じ初期化手順・同じバージョンに揃えてある）
        RxAppBuilder
            .CreateReactiveUIBuilder()
            .WithCoreServices()
            .WithWpf()
            .Build();

        DispatcherUnhandledException += OnUnhandledException;

        var window = new MainWindow();
        MainWindow = window;
        window.Show();
    }

    private static void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // 点検ツールが黙って落ちると「何も出なかった」と区別が付かない。必ず見せる
        MessageBox.Show(e.Exception.ToString(), "PCMonitor — 予期しないエラー", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
