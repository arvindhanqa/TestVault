#nullable enable

using System;
using System.Windows;
using Serilog;
using TestVault.Core;

namespace TestVault
{
    public partial class App : Application
    {
        private AppBootstrapper? _bootstrapper;

        protected override async void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Show splash
            var splash = new Window
            {
                Title = "TestVault",
                Width = 400,
                Height = 200,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                WindowStyle = WindowStyle.None,
                ResizeMode = ResizeMode.NoResize,
                Content = new System.Windows.Controls.TextBlock
                {
                    Text = "TestVault\nLoading...",
                    FontSize = 24,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center,
                    TextAlignment = System.Windows.TextAlignment.Center
                }
            };
            splash.Show();

            try
            {
                _bootstrapper = new AppBootstrapper();
                var result = await _bootstrapper.InitializeAsync();

                splash.Close();

                if (!result.Success)
                {
                    MessageBox.Show(
                        $"Startup failed: {result.Error}",
                        "TestVault - Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                    Shutdown();
                    return;
                }

                if (!result.IntegrityPassed)
                {
                    MessageBox.Show(
                        "Security integrity checks detected warnings.\n" +
                        "The application will continue, but some security features may be compromised.",
                        "TestVault - Security Warning",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }

                var mainWindow = new MainWindow();
                mainWindow.Initialize(_bootstrapper);

                if (result.SessionRestored)
                {
                    mainWindow.ShowDashboardPanel();
                }
                else
                {
                    mainWindow.ShowLoginPanel();
                }

                MainWindow = mainWindow;
                mainWindow.Show();
            }
            catch (Exception ex)
            {
                splash.Close();
                Log.Fatal(ex, "Fatal error during startup");
                MessageBox.Show(
                    $"Fatal startup error: {ex.Message}",
                    "TestVault - Fatal Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                Shutdown();
            }
        }

        protected override async void OnExit(ExitEventArgs e)
        {
            try
            {
                if (_bootstrapper != null)
                {
                    await _bootstrapper.ShutdownAsync();
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error during shutdown");
            }
            finally
            {
                base.OnExit(e);
            }
        }
    }
}
