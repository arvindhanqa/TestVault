#nullable enable

using System;
using System.IO;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Threading.Tasks;
using Serilog;
using TestVault.Core.Data;
using TestVault.Core.Security;
using TestVault.Core.SharePoint;

namespace TestVault.Core;

/// <summary>
/// Represents the result of the application startup sequence.
/// </summary>
public sealed class StartupResult
{
    /// <summary>
    /// True when the entire startup sequence completed without fatal errors.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// True when all integrity checks passed.
    /// </summary>
    public bool IntegrityPassed { get; init; }

    /// <summary>
    /// True when the database was created/opened and verified successfully.
    /// </summary>
    public bool DatabaseReady { get; init; }

    /// <summary>
    /// True when a previous authenticated session was restored.
    /// </summary>
    public bool SessionRestored { get; init; }

    /// <summary>
    /// Contains the error message if startup failed; null on success.
    /// </summary>
    public string? Error { get; init; }
}

/// <summary>
/// Application configuration persisted as an encrypted JSON blob in the <see cref="SecretStore"/>.
/// </summary>
public sealed class AppConfig
{
    private const string ConfigKey = "app_config";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    /// <summary>
    /// The full SharePoint site URL (e.g. "https://contoso.sharepoint.com/sites/QA").
    /// This property is required for the application to function.
    /// </summary>
    public string SharePointSiteUrl { get; set; } = string.Empty;

    /// <summary>
    /// The display name of the SharePoint document library to sync from.
    /// If null, the user will be prompted to select one.
    /// </summary>
    public string? DocumentLibraryName { get; set; }

    /// <summary>
    /// Interval in minutes between automatic synchronization cycles.
    /// </summary>
    public int SyncIntervalMinutes { get; set; } = 30;

    /// <summary>
    /// Maximum file size in megabytes that the application will download.
    /// </summary>
    public int MaxFileSizeMb { get; set; } = 100;

    /// <summary>
    /// Whether automatic background synchronization is enabled.
    /// </summary>
    public bool AutoSyncEnabled { get; set; } = true;

    /// <summary>
    /// Attempts to load the application configuration from the <see cref="SecretStore"/>.
    /// If no configuration exists, returns a new default instance.
    /// </summary>
    /// <param name="secretStore">The DPAPI-backed secret store to read from.</param>
    /// <returns>The loaded or default <see cref="AppConfig"/> instance.</returns>
    public static AppConfig LoadOrCreate(SecretStore secretStore)
    {
        ArgumentNullException.ThrowIfNull(secretStore);

        try
        {
            string? json = secretStore.RetrieveSecret(ConfigKey);

            if (json is not null)
            {
                var config = JsonSerializer.Deserialize<AppConfig>(json, JsonOptions);
                if (config is not null)
                {
                    Log.Information("Application configuration loaded from SecretStore");
                    return config;
                }
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to load application configuration from SecretStore; using defaults");
        }

        Log.Information("No existing application configuration found; returning defaults");
        return new AppConfig();
    }

    /// <summary>
    /// Serializes this configuration to JSON and stores it encrypted in the <see cref="SecretStore"/>.
    /// </summary>
    /// <param name="secretStore">The DPAPI-backed secret store to write to.</param>
    public void Save(SecretStore secretStore)
    {
        ArgumentNullException.ThrowIfNull(secretStore);

        string json = JsonSerializer.Serialize(this, JsonOptions);
        secretStore.StoreSecret(ConfigKey, json);

        Log.Information("Application configuration saved to SecretStore");
    }
}

/// <summary>
/// Orchestrates the secure startup and shutdown of the TestVault application.
/// Initializes all core subsystems in the correct order: logging, integrity checks,
/// network guard, secret store, configuration, database, temp directory, and SharePoint client.
/// Implements <see cref="IDisposable"/> for deterministic cleanup of all managed resources.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AppBootstrapper : IDisposable
{
    private static readonly string LogDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TestVault",
        "logs");

    private static readonly string DbFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TestVault", "data", "testvault.db");

    private AppConfig? _config;
    private SecretStore? _secretStore;
    private SecureTempDirectory? _tempDir;
    private TestVaultDbContext? _database;
    private SecureSharePointClient? _sharePoint;

    private bool _initialized;
    private bool _disposed;

    /// <summary>
    /// Gets the application configuration. Throws if the bootstrapper has not been initialized.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when accessed before <see cref="InitializeAsync"/> completes.</exception>
    public AppConfig Config => _config
        ?? throw new InvalidOperationException(
            "AppBootstrapper has not been initialized. Call InitializeAsync() first.");

    /// <summary>
    /// Gets the DPAPI-backed secret store. Throws if the bootstrapper has not been initialized.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when accessed before <see cref="InitializeAsync"/> completes.</exception>
    public SecretStore SecretStore => _secretStore
        ?? throw new InvalidOperationException(
            "AppBootstrapper has not been initialized. Call InitializeAsync() first.");

    /// <summary>
    /// Gets the secure temporary directory. Throws if the bootstrapper has not been initialized.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when accessed before <see cref="InitializeAsync"/> completes.</exception>
    public SecureTempDirectory TempDir => _tempDir
        ?? throw new InvalidOperationException(
            "AppBootstrapper has not been initialized. Call InitializeAsync() first.");

    /// <summary>
    /// Gets the Entity Framework database context. Throws if the bootstrapper has not been initialized.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when accessed before <see cref="InitializeAsync"/> completes.</exception>
    public TestVaultDbContext Database => _database
        ?? throw new InvalidOperationException(
            "AppBootstrapper has not been initialized. Call InitializeAsync() first.");

    /// <summary>
    /// Gets the SharePoint client. Throws if the bootstrapper has not been initialized.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when accessed before <see cref="InitializeAsync"/> completes.</exception>
    public SecureSharePointClient SharePoint => _sharePoint
        ?? throw new InvalidOperationException(
            "AppBootstrapper has not been initialized. Call InitializeAsync() first.");

    /// <summary>
    /// Executes the full application startup sequence in order:
    /// <list type="number">
    ///   <item>Initialize secure logging</item>
    ///   <item>Run integrity checks</item>
    ///   <item>Initialize network guard with the SharePoint domain</item>
    ///   <item>Create the DPAPI secret store</item>
    ///   <item>Load or create application configuration</item>
    ///   <item>Create and verify the encrypted database</item>
    ///   <item>Create the secure temporary directory</item>
    ///   <item>Create the SharePoint client</item>
    ///   <item>Attempt to restore a previous authenticated session</item>
    ///   <item>Record an APP_START audit entry</item>
    /// </list>
    /// </summary>
    /// <returns>A <see cref="StartupResult"/> describing the outcome of initialization.</returns>
    public async Task<StartupResult> InitializeAsync()
    {
        bool integrityPassed = false;
        bool databaseReady = false;
        bool sessionRestored = false;

        try
        {
            // Step 1: Initialize secure logging
            SecureLogger.Initialize();
            Log.Information("Application startup initiated");

            // Step 2: Run integrity checks
            var integrityResult = await IntegrityChecker.RunAllChecksAsync().ConfigureAwait(false);
            integrityPassed = integrityResult.AllPassed;

            if (!integrityPassed)
            {
                Log.Warning("Integrity checks reported failures — continuing with caution");
            }

            // Step 3: Initialize network guard
            // Create a temporary secret store and load config to get the SharePoint URL,
            // then extract the domain from the URL for NetworkGuard
            _secretStore = new SecretStore();
            _config = AppConfig.LoadOrCreate(_secretStore);

            if (!string.IsNullOrWhiteSpace(_config.SharePointSiteUrl))
            {
                var siteUri = new Uri(_config.SharePointSiteUrl);
                string domain = siteUri.Host;
                NetworkGuard.Initialize(domain);
                Log.Information("NetworkGuard initialized with domain {Domain}", domain);
            }
            else
            {
                Log.Warning("SharePoint site URL is not configured; NetworkGuard not initialized");
            }

            // Steps 4 & 5 already done above (SecretStore + AppConfig)

            // Step 6: Create and verify the encrypted database
            _database = new TestVaultDbContext();
            await _database.Database.EnsureCreatedAsync().ConfigureAwait(false);
            await _database.VerifyIntegrityAsync().ConfigureAwait(false);
            databaseReady = true;
            Log.Information("Database created/verified successfully");

            // Step 7: Create the secure temporary directory
            _tempDir = new SecureTempDirectory();

            // Step 8: Create the SharePoint client
            if (!string.IsNullOrWhiteSpace(_config.SharePointSiteUrl))
            {
                _sharePoint = new SecureSharePointClient(
                    _config.SharePointSiteUrl,
                    _secretStore,
                    _tempDir);

                // Step 9: Attempt to restore a previous authenticated session
                sessionRestored = await _sharePoint.TryRestoreSessionAsync().ConfigureAwait(false);
            }
            else
            {
                Log.Warning("SharePoint client not created — site URL is not configured");
            }

            // Step 10: Record APP_START audit entry
            await _database.AuditAsync("APP_START").ConfigureAwait(false);

            _initialized = true;

            Log.Information(
                "Application startup completed — Integrity: {IntegrityPassed}, " +
                "Database: {DatabaseReady}, Session: {SessionRestored}",
                integrityPassed,
                databaseReady,
                sessionRestored);

            return new StartupResult
            {
                Success = true,
                IntegrityPassed = integrityPassed,
                DatabaseReady = databaseReady,
                SessionRestored = sessionRestored,
                Error = null
            };
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Application startup failed");

            return new StartupResult
            {
                Success = false,
                IntegrityPassed = integrityPassed,
                DatabaseReady = databaseReady,
                SessionRestored = sessionRestored,
                Error = ex.Message
            };
        }
    }

    /// <summary>
    /// Performs a graceful application shutdown: records an audit entry, disposes all
    /// managed resources, and flushes the log pipeline.
    /// </summary>
    public async Task ShutdownAsync()
    {
        Log.Information("Application shutdown initiated");

        try
        {
            // Record shutdown audit entry
            if (_database is not null)
            {
                await _database.AuditAsync("APP_SHUTDOWN").ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to record APP_SHUTDOWN audit entry");
        }

        // Dispose all resources in reverse initialization order
        try
        {
            _sharePoint?.Dispose();
            _sharePoint = null;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Error disposing SharePoint client during shutdown");
        }

        try
        {
            _tempDir?.Dispose();
            _tempDir = null;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Error disposing SecureTempDirectory during shutdown");
        }

        try
        {
            if (_database is not null)
            {
                await _database.DisposeAsync().ConfigureAwait(false);
                _database = null;
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Error disposing database context during shutdown");
        }

        try
        {
            _secretStore?.Dispose();
            _secretStore = null;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Error disposing SecretStore during shutdown");
        }

        _config = null;
        _initialized = false;

        Log.Information("Application shutdown completed");

        // Flush and close the Serilog pipeline
        await Log.CloseAndFlushAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Emergency purge: securely destroys the temporary directory, all stored secrets,
    /// the database file, and the log directory. Intended for panic/security-incident scenarios
    /// where all local data must be irrecoverably removed.
    /// </summary>
    public async Task EmergencyPurgeAsync()
    {
        Log.Warning("EMERGENCY PURGE initiated — destroying all local data");

        // Dispose and wipe the secure temporary directory
        try
        {
            _tempDir?.Dispose();
            _tempDir = null;
            Log.Information("Secure temp directory disposed during emergency purge");
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to dispose secure temp directory during emergency purge");
        }

        // Purge all secrets from the DPAPI store
        try
        {
            if (_secretStore is not null)
            {
                _secretStore.PurgeAll();
                _secretStore.Dispose();
                _secretStore = null;
            }
            Log.Information("Secret store purged during emergency purge");
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to purge secret store during emergency purge");
        }

        // Securely delete the database file
        try
        {
            // Dispose the database context first so the file handle is released
            if (_database is not null)
            {
                await _database.DisposeAsync().ConfigureAwait(false);
                _database = null;
            }

            SecretStore.SecureFileDelete(DbFilePath);
            Log.Information("Database file securely deleted during emergency purge: {DbPath}", DbFilePath);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to securely delete database file during emergency purge");
        }

        // Wipe the log directory
        try
        {
            if (Directory.Exists(LogDirectory))
            {
                foreach (string file in Directory.GetFiles(LogDirectory, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        SecretStore.SecureFileDelete(file);
                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex, "Failed to securely delete log file: {FilePath}", file);
                    }
                }

                try
                {
                    Directory.Delete(LogDirectory, recursive: true);
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "Failed to remove log directory during emergency purge");
                }

                Log.Information("Log directory wiped during emergency purge");
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to wipe log directory during emergency purge");
        }

        // Dispose remaining resources
        _sharePoint?.Dispose();
        _sharePoint = null;
        _config = null;
        _initialized = false;

        Log.Warning("EMERGENCY PURGE completed");

        await Log.CloseAndFlushAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Disposes all managed resources held by the bootstrapper.
    /// For a graceful shutdown, prefer <see cref="ShutdownAsync"/> which also records
    /// an audit entry and flushes logs.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        _sharePoint?.Dispose();
        _sharePoint = null;

        _tempDir?.Dispose();
        _tempDir = null;

        _database?.Dispose();
        _database = null;

        _secretStore?.Dispose();
        _secretStore = null;

        _config = null;
        _initialized = false;

        Log.Debug("AppBootstrapper disposed");
    }
}
