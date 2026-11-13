using System.Windows;
using Microsoft.Win32;
using PCMonitor.Wpf.ViewModels;

namespace PCMonitor.Wpf;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel { PickSavePath = PickSavePath };
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
