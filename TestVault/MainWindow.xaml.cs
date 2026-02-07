#nullable enable

using System;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Serilog;
using TestVault.Core;
using TestVault.Core.Security;
using TestVault.UI.Views;
using TestVault.UI.ViewModels;

namespace TestVault
{
    public partial class MainWindow : Window
    {
        private AppBootstrapper? _bootstrapper;
        private DashboardView? _dashboardView;
        private TestCaseBrowserView? _testCaseBrowserView;
        private TestRunView? _testRunView;

        public MainWindow()
        {
            InitializeComponent();
        }

        public void Initialize(AppBootstrapper bootstrapper)
        {
            _bootstrapper = bootstrapper;

            // Set up dashboard view
            _dashboardView = new DashboardView();
            var dashboardVm = new DashboardViewModel(bootstrapper.Database);
            _dashboardView.DataContext = dashboardVm;
            DashboardContent.Content = _dashboardView;

            // Set up test case browser
            _testCaseBrowserView = new TestCaseBrowserView();
            var browserVm = new TestCaseBrowserViewModel(bootstrapper.Database);
            _testCaseBrowserView.DataContext = browserVm;
            TestCasesContent.Content = _testCaseBrowserView;

            // Set up test run view
            _testRunView = new TestRunView();
            var runVm = new TestRunViewModel(bootstrapper.Database);
            _testRunView.DataContext = runVm;
            TestRunsContent.Content = _testRunView;

            // Wire up SharePoint events
            bootstrapper.SharePoint.OnStatusUpdate += status =>
                Dispatcher.Invoke(() => StatusText.Text = status);
            bootstrapper.SharePoint.OnAuthenticationRequired += () =>
                Dispatcher.Invoke(() => ShowLoginPanel());
        }

        public void ShowLoginPanel()
        {
            LoginPanel.Visibility = Visibility.Visible;
            DashboardPanel.Visibility = Visibility.Collapsed;

            if (_bootstrapper?.Config?.SharePointSiteUrl != null)
            {
                _ = InitializeWebViewAsync(_bootstrapper.Config.SharePointSiteUrl);
            }
        }

        public void ShowDashboardPanel()
        {
            LoginPanel.Visibility = Visibility.Collapsed;
            DashboardPanel.Visibility = Visibility.Visible;
            StatusText.Text = "Ready";
        }

        private async Task InitializeWebViewAsync(string url)
        {
            try
            {
                await LoginWebView.EnsureCoreWebView2Async();
                LoginWebView.CoreWebView2.Navigate(url);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to initialize WebView2");
                StatusText.Text = "WebView2 initialization failed";
            }
        }

        private async void LoginWebView_NavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
        {
            if (_bootstrapper?.SharePoint == null || _bootstrapper.Config == null)
                return;

            try
            {
                var currentUrl = LoginWebView.CoreWebView2.Source;
                var siteUri = new Uri(_bootstrapper.Config.SharePointSiteUrl);

                if (currentUrl.Contains(siteUri.Host, StringComparison.OrdinalIgnoreCase)
                    && !currentUrl.Contains("login", StringComparison.OrdinalIgnoreCase)
                    && !currentUrl.Contains("oauth", StringComparison.OrdinalIgnoreCase))
                {
                    StatusText.Text = "Capturing session...";
                    await _bootstrapper.SharePoint.CaptureSessionFromWebView(LoginWebView.CoreWebView2);
                    Log.Information("Session captured successfully after login");
                    ShowDashboardPanel();
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error during navigation completion");
                StatusText.Text = "Login error - please try again";
            }
        }

        private async void SyncNow_Click(object sender, RoutedEventArgs e)
        {
            if (_bootstrapper?.SharePoint == null) return;

            try
            {
                SyncProgress.Visibility = Visibility.Visible;
                SyncButton.IsEnabled = false;
                StatusText.Text = "Syncing...";

                var library = _bootstrapper.Config?.DocumentLibraryName ?? "Documents";
                var files = await _bootstrapper.SharePoint.ListExcelFilesAsync(library);
                StatusText.Text = $"Found {files.Count} Excel files. Downloading...";

                var parser = new Core.Services.SecureExcelParser(_bootstrapper.Database);
                foreach (var file in files)
                {
                    var (localPath, hash) = await _bootstrapper.SharePoint.DownloadFileAsync(file);
                    var result = await parser.ParseAndImportAsync(localPath, file.ServerRelativePath, hash);
                    StatusText.Text = $"Imported {result.FileName}: {result.TestCasesParsed} cases";
                }

                StatusText.Text = $"Sync complete. {files.Count} files processed.";
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Sync failed");
                StatusText.Text = "Sync failed: " + ex.Message;
            }
            finally
            {
                SyncProgress.Visibility = Visibility.Collapsed;
                SyncButton.IsEnabled = true;
            }
        }

        private void Settings_Click(object sender, RoutedEventArgs e)
        {
            if (_bootstrapper == null) return;
            var dialog = new SettingsDialog(_bootstrapper);
            dialog.Owner = this;
            dialog.ShowDialog();
        }

        private async void EmergencyPurge_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "This will permanently delete ALL local data including:\n\n" +
                "- Encrypted database\n" +
                "- Stored credentials\n" +
                "- Temporary files\n" +
                "- Log files\n\n" +
                "This action CANNOT be undone. Continue?",
                "Emergency Purge - TestVault",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes && _bootstrapper != null)
            {
                StatusText.Text = "Purging all data...";
                await _bootstrapper.EmergencyPurgeAsync();
                MessageBox.Show("All data has been securely deleted.", "Purge Complete",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                Application.Current.Shutdown();
            }
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void LoginAgain_Click(object sender, RoutedEventArgs e)
        {
            ShowLoginPanel();
        }
    }
}
