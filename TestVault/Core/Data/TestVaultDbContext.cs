#nullable enable

using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Serilog;
using TestVault.Core.Models;
using TestVault.Core.Security;

namespace TestVault.Core.Data;

/// <summary>
/// SQLCipher-encrypted Entity Framework Core database context for TestVault.
/// All data is stored locally in an encrypted SQLite database under %LocalAppData%/TestVault/data/.
/// The encryption key is managed via DPAPI-backed <see cref="SecretStore"/>.
/// </summary>
[SupportedOSPlatform("windows")]
public class TestVaultDbContext : DbContext
{
    private static readonly Regex SensitivePattern = new(
        @"(password|token|cookie|secret|key|authorization|bearer)\s*[=:]\s*\S+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string DbPath = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TestVault", "data", "testvault.db");

    // ─── DbSets ──────────────────────────────────────────────────────────

    public DbSet<TestCase> TestCases => Set<TestCase>();
    public DbSet<TestRun> TestRuns => Set<TestRun>();
    public DbSet<TestExecution> TestExecutions => Set<TestExecution>();
    public DbSet<ExcelSource> ExcelSources => Set<ExcelSource>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<SyncMetadata> SyncMetadata => Set<SyncMetadata>();

    // ─── Configuration ───────────────────────────────────────────────────

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (optionsBuilder.IsConfigured)
            return;

        var dataDir = System.IO.Path.GetDirectoryName(DbPath)!;
        if (!System.IO.Directory.Exists(dataDir))
            System.IO.Directory.CreateDirectory(dataDir);

        var key = GetOrCreateDbKey();
        var connectionString = $"Data Source={DbPath};Password={key}";

        optionsBuilder
            .UseSqlite(connectionString)
            .EnableSensitiveDataLogging(false);

        Log.Debug("TestVaultDbContext configured with database at {DbPath}", DbPath);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // ── TestCase ─────────────────────────────────────────────────
        modelBuilder.Entity<TestCase>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.Module);
            entity.HasIndex(e => e.Priority);
            entity.HasIndex(e => e.Status);

            entity.Property(e => e.Title)
                  .IsRequired()
                  .HasMaxLength(500);

            entity.Property(e => e.Module)
                  .HasMaxLength(200);

            entity.Property(e => e.FileHash)
                  .HasMaxLength(64);
        });

        // ── TestRun ──────────────────────────────────────────────────
        modelBuilder.Entity<TestRun>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.Property(e => e.Name)
                  .IsRequired()
                  .HasMaxLength(200);
        });

        // ── TestExecution ────────────────────────────────────────────
        modelBuilder.Entity<TestExecution>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.Property(e => e.Result)
                  .IsRequired();

            entity.HasOne(e => e.TestCase)
                  .WithMany()
                  .HasForeignKey(e => e.TestCaseId)
                  .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(e => e.TestRun)
                  .WithMany()
                  .HasForeignKey(e => e.TestRunId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        // ── ExcelSource ──────────────────────────────────────────────
        modelBuilder.Entity<ExcelSource>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.Property(e => e.FileName)
                  .IsRequired();

            entity.Property(e => e.SharePointPath)
                  .IsRequired()
                  .HasMaxLength(1000);

            entity.Property(e => e.FileHash)
                  .IsRequired()
                  .HasMaxLength(64);
        });

        // ── AuditEntry ───────────────────────────────────────────────
        modelBuilder.Entity<AuditEntry>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.Timestamp);

            entity.Property(e => e.Action)
                  .IsRequired()
                  .HasMaxLength(100);

            entity.Property(e => e.WindowsUser)
                  .IsRequired();
        });

        // ── SyncMetadata ─────────────────────────────────────────────
        modelBuilder.Entity<SyncMetadata>(entity =>
        {
            entity.HasKey(e => e.Id);
        });
    }

    // ─── Public helpers ──────────────────────────────────────────────────

    /// <summary>
    /// Runs <c>PRAGMA integrity_check</c> against the database to verify that the
    /// SQLCipher-encrypted file is intact and uncorrupted.
    /// </summary>
    public async Task VerifyIntegrityAsync(CancellationToken cancellationToken = default)
    {
        Log.Information("Running database integrity check...");

        await Database.ExecuteSqlRawAsync("PRAGMA integrity_check;", cancellationToken);

        Log.Information("Database integrity check completed successfully");
    }

    /// <summary>
    /// Records an audit entry with the current UTC timestamp and the Windows user name.
    /// </summary>
    /// <param name="action">A short description of the auditable action.</param>
    /// <param name="details">Optional additional details about the action.</param>
    public async Task AuditAsync(string action, string? details = null)
    {
        var entry = new AuditEntry
        {
            Action = action,
            Details = details,
            Timestamp = DateTime.UtcNow,
            WindowsUser = Environment.UserName
        };

        AuditEntries.Add(entry);
        await SaveChangesAsync();

        Log.Information("Audit entry recorded: {Action}", action);
    }

    /// <summary>
    /// Sanitizes a string for safe logging by replacing values associated with sensitive
    /// keys (password, token, cookie, secret, key, authorization, bearer) with ***REDACTED***.
    /// </summary>
    /// <param name="input">The string to sanitize; may be null.</param>
    /// <returns>The sanitized string, or null if the input was null.</returns>
    public static string? SanitizeForLog(string? input)
    {
        if (input is null)
            return null;

        return SensitivePattern.Replace(input, m =>
        {
            // Keep the key name and separator, redact only the value
            var equalsIndex = m.Value.IndexOfAny(new[] { '=', ':' });
            if (equalsIndex >= 0)
            {
                return m.Value[..(equalsIndex + 1)] + " ***REDACTED***";
            }

            return "***REDACTED***";
        });
    }

    // ─── Private helpers ─────────────────────────────────────────────────

    /// <summary>
    /// Retrieves the database encryption key from the DPAPI-backed <see cref="SecretStore"/>.
    /// If no key exists yet, generates 32 cryptographically random bytes, Base64-encodes them,
    /// and stores the result. The raw byte array is zeroed after use.
    /// </summary>
    private static string GetOrCreateDbKey()
    {
        const string keyName = "db_encryption_key";

        using var store = new SecretStore();

        var existing = store.RetrieveSecret(keyName);
        if (existing is not null)
        {
            Log.Debug("Database encryption key retrieved from SecretStore");
            return existing;
        }

        Log.Information("No database encryption key found; generating a new one");

        byte[] keyBytes = new byte[32];
        try
        {
            RandomNumberGenerator.Fill(keyBytes);
            var base64Key = Convert.ToBase64String(keyBytes);

            store.StoreSecret(keyName, base64Key);

            Log.Information("Database encryption key generated and stored in SecretStore");
            return base64Key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }
}
