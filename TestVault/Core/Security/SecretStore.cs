using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Serilog;

namespace TestVault.Core.Security;

/// <summary>
/// Represents cookie data for secure storage and retrieval.
/// </summary>
public record CookieData(
    string Name,
    string Value,
    string Domain,
    string Path,
    DateTime Expires,
    bool IsSecure,
    bool IsHttpOnly);

/// <summary>
/// DPAPI-based secret storage for Windows. Encrypts secrets using the current user's
/// credentials and stores them as individual files under %LocalAppData%/TestVault/secrets/.
/// All files and directories are ACL-locked to the current Windows user only.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SecretStore : IDisposable
{
    private static readonly byte[] EntropySalt =
        Encoding.UTF8.GetBytes("TestVault-v1-2025-entropy-salt");

    private static readonly Regex InvalidKeyPattern =
        new(@"[\\/:*?""<>|\x00-\x1F]", RegexOptions.Compiled);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    private readonly string _secretsDirectory;
    private bool _disposed;

    public SecretStore()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _secretsDirectory = Path.Combine(localAppData, "TestVault", "secrets");

        EnsureSecureDirectory(_secretsDirectory);

        Log.Debug("SecretStore initialized with storage at {SecretsDirectory}", _secretsDirectory);
    }

    /// <summary>
    /// Stores a secret value encrypted with DPAPI under the given key name.
    /// </summary>
    /// <param name="key">A valid key name (no path characters).</param>
    /// <param name="value">The plaintext secret value to encrypt and store.</param>
    /// <exception cref="ArgumentException">Thrown when the key contains invalid characters.</exception>
    /// <exception cref="ArgumentNullException">Thrown when key or value is null.</exception>
    public void StoreSecret(string key, string value)
    {
        ThrowIfDisposed();
        ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);

        byte[] plaintextBytes = Array.Empty<byte>();
        try
        {
            plaintextBytes = Encoding.UTF8.GetBytes(value);
            byte[] encryptedBytes = ProtectedData.Protect(
                plaintextBytes,
                EntropySalt,
                DataProtectionScope.CurrentUser);

            var filePath = GetSecretFilePath(key);
            File.WriteAllBytes(filePath, encryptedBytes);
            SetFileAclCurrentUserOnly(filePath);

            Log.Information("Secret stored successfully for key {SecretKey}", key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }
    }

    /// <summary>
    /// Retrieves and decrypts a secret stored under the given key name.
    /// </summary>
    /// <param name="key">The key name of the secret to retrieve.</param>
    /// <returns>The decrypted secret value, or null if the key does not exist.</returns>
    public string? RetrieveSecret(string key)
    {
        ThrowIfDisposed();
        ValidateKey(key);

        var filePath = GetSecretFilePath(key);

        if (!File.Exists(filePath))
        {
            Log.Debug("No secret found for key {SecretKey}", key);
            return null;
        }

        byte[] plaintextBytes = Array.Empty<byte>();
        try
        {
            byte[] encryptedBytes = File.ReadAllBytes(filePath);
            plaintextBytes = ProtectedData.Unprotect(
                encryptedBytes,
                EntropySalt,
                DataProtectionScope.CurrentUser);

            string result = Encoding.UTF8.GetString(plaintextBytes);

            Log.Information("Secret retrieved successfully for key {SecretKey}", key);
            return result;
        }
        catch (CryptographicException ex)
        {
            Log.Error(ex, "Failed to decrypt secret for key {SecretKey}", key);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }
    }

    /// <summary>
    /// Securely deletes the secret stored under the given key name.
    /// </summary>
    /// <param name="key">The key name of the secret to delete.</param>
    public void DeleteSecret(string key)
    {
        ThrowIfDisposed();
        ValidateKey(key);

        var filePath = GetSecretFilePath(key);

        if (!File.Exists(filePath))
        {
            Log.Debug("No secret to delete for key {SecretKey}", key);
            return;
        }

        SecureFileDelete(filePath);
        Log.Information("Secret securely deleted for key {SecretKey}", key);
    }

    /// <summary>
    /// Securely deletes all stored secrets and removes the secrets directory.
    /// </summary>
    public void PurgeAll()
    {
        ThrowIfDisposed();

        if (!Directory.Exists(_secretsDirectory))
        {
            Log.Debug("Secrets directory does not exist; nothing to purge");
            return;
        }

        var files = Directory.GetFiles(_secretsDirectory);
        int count = files.Length;

        foreach (var file in files)
        {
            SecureFileDelete(file);
        }

        try
        {
            Directory.Delete(_secretsDirectory, recursive: true);
        }
        catch (IOException ex)
        {
            Log.Warning(ex, "Could not remove secrets directory after purge");
        }

        Log.Information("Purged all secrets ({SecretCount} files removed)", count);
    }

    /// <summary>
    /// Serializes cookie data to JSON, then encrypts and stores it under a domain-based key.
    /// </summary>
    /// <param name="domain">The domain the cookies belong to.</param>
    /// <param name="cookies">The collection of cookie data records to store.</param>
    public void StoreCookies(string domain, IEnumerable<CookieData> cookies)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(cookies);

        var cookieList = cookies.ToList();
        string json = JsonSerializer.Serialize(cookieList, JsonOptions);

        var key = BuildCookieKey(domain);
        StoreSecret(key, json);

        Log.Information(
            "Stored {CookieCount} cookies for domain {Domain}",
            cookieList.Count,
            domain);
    }

    /// <summary>
    /// Retrieves and deserializes cookies stored for the given domain.
    /// </summary>
    /// <param name="domain">The domain to retrieve cookies for.</param>
    /// <returns>The list of cookie data records, or null if none are stored.</returns>
    public IReadOnlyList<CookieData>? RetrieveCookies(string domain)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(domain);

        var key = BuildCookieKey(domain);
        string? json = RetrieveSecret(key);

        if (json is null)
        {
            Log.Debug("No cookies found for domain {Domain}", domain);
            return null;
        }

        var cookies = JsonSerializer.Deserialize<List<CookieData>>(json, JsonOptions);

        Log.Information(
            "Retrieved {CookieCount} cookies for domain {Domain}",
            cookies?.Count ?? 0,
            domain);

        return cookies?.AsReadOnly();
    }

    /// <summary>
    /// Performs a secure 3-pass overwrite of a file before deletion.
    /// Pass 1: all zeros. Pass 2: all 0xFF bytes. Pass 3: cryptographically random bytes.
    /// </summary>
    /// <param name="filePath">The absolute path of the file to securely delete.</param>
    public static void SecureFileDelete(string filePath)
    {
        ArgumentNullException.ThrowIfNull(filePath);

        if (!File.Exists(filePath))
        {
            Log.Debug("File does not exist for secure deletion: {FilePath}", filePath);
            return;
        }

        try
        {
            var fileInfo = new FileInfo(filePath);
            long length = fileInfo.Length;

            if (length > 0)
            {
                byte[] buffer = new byte[length];

                try
                {
                    // Pass 1: overwrite with zeros
                    Array.Clear(buffer);
                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
                    {
                        fs.Write(buffer, 0, buffer.Length);
                        fs.Flush(flushToDisk: true);
                    }

                    // Pass 2: overwrite with 0xFF
                    Array.Fill(buffer, (byte)0xFF);
                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
                    {
                        fs.Write(buffer, 0, buffer.Length);
                        fs.Flush(flushToDisk: true);
                    }

                    // Pass 3: overwrite with random bytes
                    RandomNumberGenerator.Fill(buffer);
                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
                    {
                        fs.Write(buffer, 0, buffer.Length);
                        fs.Flush(flushToDisk: true);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(buffer);
                }
            }

            File.Delete(filePath);
            Log.Debug("File securely deleted: {FilePath}", filePath);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to securely delete file: {FilePath}", filePath);
            throw;
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        Log.Debug("SecretStore disposed");
    }

    // ─── Private helpers ─────────────────────────────────────────────────

    private string GetSecretFilePath(string key)
    {
        return Path.Combine(_secretsDirectory, $"{key}.secret");
    }

    private static string BuildCookieKey(string domain)
    {
        // Replace dots with underscores so the domain is a valid key name
        return $"cookies_{domain.Replace('.', '_').Replace(':', '_')}";
    }

    private static void ValidateKey(string key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (string.IsNullOrWhiteSpace(key))
            throw new ArgumentException("Key must not be empty or whitespace.", nameof(key));

        if (InvalidKeyPattern.IsMatch(key))
            throw new ArgumentException(
                $"Key '{key}' contains invalid path characters. " +
                "Keys must not contain \\ / : * ? \" < > | or control characters.",
                nameof(key));
    }

    private static void EnsureSecureDirectory(string directoryPath)
    {
        if (Directory.Exists(directoryPath))
            return;

        var dirInfo = Directory.CreateDirectory(directoryPath);
        SetDirectoryAclCurrentUserOnly(dirInfo);

        Log.Information("Created secure secrets directory at {DirectoryPath}", directoryPath);
    }

    private static void SetDirectoryAclCurrentUserOnly(DirectoryInfo dirInfo)
    {
        try
        {
            var currentUser = WindowsIdentity.GetCurrent();
            var userSid = currentUser.User
                ?? throw new InvalidOperationException("Could not determine current user SID.");

            var dirSecurity = new DirectorySecurity();

            // Remove inheritance from parent directories
            dirSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            // Add full control for the current user only
            dirSecurity.AddAccessRule(new FileSystemAccessRule(
                userSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            dirInfo.SetAccessControl(dirSecurity);
            Log.Debug("Directory ACL set to current user only: {DirectoryPath}", dirInfo.FullName);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to set directory ACL for {DirectoryPath}", dirInfo.FullName);
        }
    }

    private static void SetFileAclCurrentUserOnly(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            var currentUser = WindowsIdentity.GetCurrent();
            var userSid = currentUser.User
                ?? throw new InvalidOperationException("Could not determine current user SID.");

            var fileSecurity = new FileSecurity();

            // Remove inheritance from parent directories
            fileSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            // Add full control for the current user only
            fileSecurity.AddAccessRule(new FileSystemAccessRule(
                userSid,
                FileSystemRights.FullControl,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));

            fileInfo.SetAccessControl(fileSecurity);
            Log.Debug("File ACL set to current user only: {FilePath}", filePath);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to set file ACL for {FilePath}", filePath);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
