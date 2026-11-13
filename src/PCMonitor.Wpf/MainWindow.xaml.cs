using System.Windows;
using Microsoft.Win32;
using PCMonitor.Wpf.ViewModels;

namespace PCMonitor.Wpf;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        var viewModel = new MainViewModel { PickSavePath = PickSavePath };
        DataContext = viewModel;
        // 閉じるときに、キー入力 API の監視のセッションを止める
        Closed += (_, _) => viewModel.Dispose();
    }

    private string? PickSavePath(string fileName, string filter)
    {
        var dialog = new SaveFileDialog
        {
            FileName = fileName,
            Filter = filter,
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };
        return dialog.ShowDialog(this) == true ? dialog.FileName : null;
    }
}
