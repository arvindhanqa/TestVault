#nullable enable

using System;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Serilog;

namespace TestVault.Core.Security;

/// <summary>
/// An isolated temporary directory that auto-wipes on exit. Each session receives a
/// cryptographically random subdirectory under %LocalAppData%/TestVault/temp/, ACL-locked
/// to the current Windows user only. All files are securely deleted when the session ends,
/// whether via normal disposal, process exit, or unhandled exception.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SecureTempDirectory : IDisposable
{
    private static readonly string BasePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TestVault",
        "temp");

    private static readonly TimeSpan OrphanedDirMaxAge = TimeSpan.FromHours(1);

    private readonly string _sessionDirectory;
    private bool _disposed;

    public SecureTempDirectory()
    {
        CleanupOrphanedDirs();

        // Generate 8 random bytes (16 hex characters) for the session directory name
        byte[] randomBytes = new byte[8];
        RandomNumberGenerator.Fill(randomBytes);
        string sessionName = Convert.ToHexString(randomBytes).ToLowerInvariant();

        _sessionDirectory = Path.Combine(BasePath, sessionName);

        EnsureSecureDirectory(_sessionDirectory);

        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

        Log.Information(
            "SecureTempDirectory session created at {SessionDirectory}",
            _sessionDirectory);
    }

    /// <summary>
    /// Gets the full path to the session-specific temporary directory.
    /// </summary>
    public string SessionDirectory => _sessionDirectory;

    /// <summary>
    /// Returns a sanitized file path within the session directory for the given original file name.
    /// </summary>
    /// <param name="originalFileName">The original file name to sanitize and map into the session directory.</param>
    /// <returns>The full sanitized path within the session directory.</returns>
    /// <exception cref="ArgumentException">Thrown when the original file name is null or whitespace.</exception>
    public string GetTempFilePath(string originalFileName)
    {
        ThrowIfDisposed();

        string sanitized = SanitizeFileName(originalFileName);
        return Path.Combine(_sessionDirectory, sanitized);
    }

    /// <summary>
    /// Writes the given byte array to a temporary file within the session directory.
    /// </summary>
    /// <param name="originalFileName">The original file name (will be sanitized).</param>
    /// <param name="data">The byte array to write.</param>
    /// <returns>The full path to the written temporary file.</returns>
    public async Task<string> WriteTempFileAsync(string originalFileName, byte[] data)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(data);

        string filePath = GetTempFilePath(originalFileName);

        await File.WriteAllBytesAsync(filePath, data).ConfigureAwait(false);
        SetFileAclCurrentUserOnly(filePath);

        Log.Debug("Wrote temp file ({ByteCount} bytes): {FilePath}", data.Length, filePath);
        return filePath;
    }

    /// <summary>
    /// Writes the given stream to a temporary file within the session directory.
    /// </summary>
    /// <param name="originalFileName">The original file name (will be sanitized).</param>
    /// <param name="stream">The stream whose contents will be written.</param>
    /// <returns>The full path to the written temporary file.</returns>
    public async Task<string> WriteTempFileAsync(string originalFileName, Stream stream)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(stream);

        string filePath = GetTempFilePath(originalFileName);

        await using (var fileStream = new FileStream(
            filePath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 81920,
            useAsync: true))
        {
            await stream.CopyToAsync(fileStream).ConfigureAwait(false);
            await fileStream.FlushAsync().ConfigureAwait(false);
        }

        SetFileAclCurrentUserOnly(filePath);

        Log.Debug("Wrote temp file from stream: {FilePath}", filePath);
        return filePath;
    }

    /// <summary>
    /// Computes the SHA-256 hash of the file at the specified path and returns it as a lowercase hex string.
    /// </summary>
    /// <param name="filePath">The absolute path to the file to hash.</param>
    /// <returns>The SHA-256 hash as a lowercase hex string.</returns>
    public static async Task<string> ComputeFileHashAsync(string filePath)
    {
        ArgumentNullException.ThrowIfNull(filePath);

        if (!File.Exists(filePath))
            throw new FileNotFoundException("File not found for hashing.", filePath);

        using var sha256 = SHA256.Create();

        await using var fileStream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 81920,
            useAsync: true);

        byte[] hashBytes = await sha256.ComputeHashAsync(fileStream).ConfigureAwait(false);
        string hashHex = Convert.ToHexString(hashBytes).ToLowerInvariant();

        Log.Debug("Computed SHA-256 hash for {FilePath}: {Hash}", filePath, hashHex);
        return hashHex;
    }

    /// <summary>
    /// Securely deletes a file, but only if it resides within the current session directory.
    /// This prevents accidental or malicious deletion of files outside the temp sandbox.
    /// </summary>
    /// <param name="filePath">The absolute path to the file to delete.</param>
    /// <exception cref="UnauthorizedAccessException">
    /// Thrown when the file path is not within the session directory.
    /// </exception>
    public void SecureDeleteFile(string filePath)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(filePath);

        string fullPath = Path.GetFullPath(filePath);
        string fullSessionDir = Path.GetFullPath(_sessionDirectory);

        if (!fullPath.StartsWith(fullSessionDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(fullPath, fullSessionDir, StringComparison.OrdinalIgnoreCase))
        {
            Log.Warning(
                "Attempted to delete file outside session directory. File: {FilePath}, Session: {SessionDir}",
                filePath,
                _sessionDirectory);
            throw new UnauthorizedAccessException(
                $"Cannot delete file outside the session directory. File: {filePath}");
        }

        SecretStore.SecureFileDelete(fullPath);
        Log.Debug("Securely deleted file within session: {FilePath}", fullPath);
    }

    /// <summary>
    /// Sanitizes a file name by stripping invalid path characters, replacing directory
    /// traversal sequences, and limiting the total length to 200 characters.
    /// </summary>
    /// <param name="fileName">The original file name to sanitize.</param>
    /// <returns>The sanitized file name.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the file name is null, whitespace, or empty after sanitization.
    /// </exception>
    public static string SanitizeFileName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
            throw new ArgumentException("File name must not be null or whitespace.", nameof(fileName));

        // Take only the file name portion if a path was provided
        string name = Path.GetFileName(fileName);

        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("File name is empty after extracting file name component.", nameof(fileName));

        // Strip invalid file name characters
        char[] invalidChars = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(name.Length);

        foreach (char c in name)
        {
            if (Array.IndexOf(invalidChars, c) < 0)
                sb.Append(c);
        }

        // Replace directory traversal sequences
        string sanitized = sb.ToString().Replace("..", "_");

        // Limit to 200 characters
        if (sanitized.Length > 200)
            sanitized = sanitized[..200];

        if (string.IsNullOrWhiteSpace(sanitized))
            throw new ArgumentException(
                "File name is empty after sanitization. Original: " + fileName,
                nameof(fileName));

        return sanitized;
    }

    /// <summary>
    /// Cleans up orphaned session directories that are older than the maximum age threshold.
    /// Called automatically during construction of a new session.
    /// </summary>
    public static void CleanupOrphanedDirs()
    {
        try
        {
            if (!Directory.Exists(BasePath))
                return;

            var directories = Directory.GetDirectories(BasePath);

            foreach (string dir in directories)
            {
                try
                {
                    var dirInfo = new DirectoryInfo(dir);
                    TimeSpan age = DateTime.UtcNow - dirInfo.CreationTimeUtc;

                    if (age > OrphanedDirMaxAge)
                    {
                        Log.Information(
                            "Cleaning up orphaned temp directory (age: {Age}): {Directory}",
                            age,
                            dir);

                        // Securely delete all files in the orphaned directory
                        foreach (string file in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                        {
                            try
                            {
                                SecretStore.SecureFileDelete(file);
                            }
                            catch (Exception ex)
                            {
                                Log.Warning(ex, "Failed to securely delete orphaned file: {FilePath}", file);
                            }
                        }

                        Directory.Delete(dir, recursive: true);
                        Log.Debug("Removed orphaned directory: {Directory}", dir);
                    }
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "Failed to clean up orphaned directory: {Directory}", dir);
                }
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to enumerate orphaned temp directories under {BasePath}", BasePath);
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;
        AppDomain.CurrentDomain.UnhandledException -= OnUnhandledException;

        Cleanup();

        Log.Debug("SecureTempDirectory disposed");
    }

    // ─── Private helpers ─────────────────────────────────────────────────

    private void Cleanup()
    {
        try
        {
            if (!Directory.Exists(_sessionDirectory))
            {
                Log.Debug("Session directory already removed: {SessionDirectory}", _sessionDirectory);
                return;
            }

            // Securely delete every file in the session directory tree
            string[] files = Directory.GetFiles(_sessionDirectory, "*", SearchOption.AllDirectories);

            foreach (string file in files)
            {
                try
                {
                    SecretStore.SecureFileDelete(file);
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "Failed to securely delete temp file during cleanup: {FilePath}", file);
                }
            }

            // Remove the session directory itself
            Directory.Delete(_sessionDirectory, recursive: true);
            Log.Information("Session directory cleaned up: {SessionDirectory}", _sessionDirectory);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to clean up session directory: {SessionDirectory}", _sessionDirectory);
        }
    }

    private void OnProcessExit(object? sender, EventArgs e)
    {
        Log.Debug("Process exit detected; cleaning up SecureTempDirectory");
        Dispose();
    }

    private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        Log.Warning("Unhandled exception detected; cleaning up SecureTempDirectory");
        Dispose();
    }

    private static void EnsureSecureDirectory(string directoryPath)
    {
        if (!Directory.Exists(BasePath))
        {
            Directory.CreateDirectory(BasePath);
        }

        var dirInfo = Directory.CreateDirectory(directoryPath);
        SetDirectoryAclCurrentUserOnly(dirInfo);

        Log.Debug("Created secure temp directory at {DirectoryPath}", directoryPath);
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
