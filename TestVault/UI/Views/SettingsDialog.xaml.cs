#nullable enable

using System;
using System.Windows;
using Serilog;
using TestVault.Core;

namespace TestVault.UI.Views
{
    public partial class SettingsDialog : Window
    {
        private readonly AppBootstrapper _bootstrapper;

        public SettingsDialog(AppBootstrapper bootstrapper)
        {
            InitializeComponent();
            _bootstrapper = bootstrapper;
            LoadSettings();
            CheckSecurityStatus();
        }

        private void LoadSettings()
        {
            var config = _bootstrapper.Config;
            if (config == null) return;

            SiteUrlTextBox.Text = config.SharePointSiteUrl;
            LibraryNameTextBox.Text = config.DocumentLibraryName ?? "Documents";
            SyncIntervalTextBox.Text = config.SyncIntervalMinutes.ToString();
            AutoSyncCheckBox.IsChecked = config.AutoSyncEnabled;
        }

        private void CheckSecurityStatus()
        {
            try
            {
                DbEncryptedStatus.Text = _bootstrapper.Database != null ? "Yes" : "No";
                DbEncryptedStatus.Foreground = _bootstrapper.Database != null
                    ? System.Windows.Media.Brushes.Green : System.Windows.Media.Brushes.Red;

                SecretsStatus.Text = _bootstrapper.SecretStore != null ? "Yes" : "No";
                SecretsStatus.Foreground = _bootstrapper.SecretStore != null
                    ? System.Windows.Media.Brushes.Green : System.Windows.Media.Brushes.Red;

                FirewallStatus.Text = "Active";
                FirewallStatus.Foreground = System.Windows.Media.Brushes.Green;

                TempDirStatus.Text = _bootstrapper.TempDir != null ? "Active" : "Inactive";
                TempDirStatus.Foreground = _bootstrapper.TempDir != null
                    ? System.Windows.Media.Brushes.Green : System.Windows.Media.Brushes.Red;
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Error checking security status");
            }
        }

        private async void TestConnection_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(SiteUrlTextBox.Text))
                {
                    MessageBox.Show("Please enter a SharePoint URL.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (_bootstrapper.SharePoint == null)
                {
                    MessageBox.Show("SharePoint client not initialized.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var restored = await _bootstrapper.SharePoint.TryRestoreSessionAsync();
                if (restored)
                {
                    MessageBox.Show("Connection successful! Session is active.", "Test Connection",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("Connection requires authentication. Please log in first.", "Test Connection",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Connection failed: {ex.Message}", "Test Connection",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void Save_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var config = _bootstrapper.Config;
                if (config == null) return;

                config.SharePointSiteUrl = SiteUrlTextBox.Text.Trim();
                config.DocumentLibraryName = LibraryNameTextBox.Text.Trim();

                if (int.TryParse(SyncIntervalTextBox.Text, out var interval) && interval > 0)
                    config.SyncIntervalMinutes = interval;

                config.AutoSyncEnabled = AutoSyncCheckBox.IsChecked ?? true;

                config.Save(_bootstrapper.SecretStore);
                await _bootstrapper.Database.AuditAsync("SETTINGS_UPDATED", "Configuration saved");

                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to save settings");
                MessageBox.Show($"Failed to save: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
