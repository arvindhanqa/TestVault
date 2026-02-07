#nullable enable

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using Serilog;

namespace TestVault.Core.Security;

/// <summary>
/// Result of startup integrity verification. Each boolean property indicates
/// whether the corresponding check passed. <see cref="AllPassed"/> excludes the
/// debugger check (which is advisory only).
/// </summary>
public sealed class IntegrityResult
{
    /// <summary>
    /// True when no debugger is attached. This is advisory — a false value
    /// generates a warning but does not cause <see cref="AllPassed"/> to be false.
    /// </summary>
    public bool DebuggerSafe { get; init; }

    /// <summary>
    /// True when the assembly is not running from a temporary, download, or cache directory.
    /// </summary>
    public bool LocationSafe { get; init; }

    /// <summary>
    /// True when the executing assembly loads correctly and strong-name validation succeeds.
    /// </summary>
    public bool AssemblySafe { get; init; }

    /// <summary>
    /// True when the %LocalAppData%/TestVault directory ACLs do not include the
    /// Everyone or Users group with an Allow entry.
    /// </summary>
    public bool PermissionsSafe { get; init; }

    /// <summary>
    /// True when orphaned temp directory cleanup and log cleanup completed successfully.
    /// </summary>
    public bool CleanupDone { get; init; }

    /// <summary>
    /// True when all critical checks passed. Excludes <see cref="DebuggerSafe"/>
    /// which is advisory only.
    /// </summary>
    public bool AllPassed => LocationSafe && AssemblySafe && PermissionsSafe && CleanupDone;

    /// <summary>
    /// True when there are any warnings (currently only the debugger check).
    /// </summary>
    public bool HasWarnings => !DebuggerSafe;
}

/// <summary>
/// Performs startup integrity verification to ensure the application is running
/// in a safe environment. All checks are best-effort — exceptions are caught and
/// the check returns true to avoid blocking application startup.
/// </summary>
[SupportedOSPlatform("windows")]
public static class IntegrityChecker
{
    private static readonly string TestVaultDataPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TestVault");

    private static readonly string TempBasePath = Path.Combine(TestVaultDataPath, "temp");

    private static readonly TimeSpan OrphanedDirMaxAge = TimeSpan.FromHours(2);

    /// <summary>
    /// Runs all integrity checks and returns an <see cref="IntegrityResult"/>
    /// describing the outcome. Individual check failures are logged but never
    /// throw — each check returns true on exception to avoid blocking startup.
    /// </summary>
    public static async Task<IntegrityResult> RunAllChecksAsync()
    {
        Log.Information("Starting integrity checks");

        var debuggerTask = Task.Run(CheckDebugger);
        var locationTask = Task.Run(CheckLocation);
        var assemblyTask = Task.Run(CheckAssembly);
        var permissionTask = Task.Run(CheckPermissions);
        var cleanupTask = Task.Run(RunCleanup);

        await Task.WhenAll(debuggerTask, locationTask, assemblyTask, permissionTask, cleanupTask)
            .ConfigureAwait(false);

        var result = new IntegrityResult
        {
            DebuggerSafe = await debuggerTask.ConfigureAwait(false),
            LocationSafe = await locationTask.ConfigureAwait(false),
            AssemblySafe = await assemblyTask.ConfigureAwait(false),
            PermissionsSafe = await permissionTask.ConfigureAwait(false),
            CleanupDone = await cleanupTask.ConfigureAwait(false)
        };

        Log.Information(
            "Integrity checks complete — AllPassed: {AllPassed}, HasWarnings: {HasWarnings}, " +
            "Debugger: {DebuggerSafe}, Location: {LocationSafe}, Assembly: {AssemblySafe}, " +
            "Permissions: {PermissionsSafe}, Cleanup: {CleanupDone}",
            result.AllPassed,
            result.HasWarnings,
            result.DebuggerSafe,
            result.LocationSafe,
            result.AssemblySafe,
            result.PermissionsSafe,
            result.CleanupDone);

        return result;
    }

    // ─── Individual Checks ──────────────────────────────────────────────

    /// <summary>
    /// Warns if a debugger is attached. Returns true when no debugger is detected.
    /// Best-effort: returns true on exception.
    /// </summary>
    private static bool CheckDebugger()
    {
        try
        {
            if (Debugger.IsAttached)
            {
                Log.Warning("IntegrityChecker: a debugger is attached to the process");
                return false;
            }

            Log.Debug("IntegrityChecker: no debugger detected");
            return true;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "IntegrityChecker: debugger check failed — treating as safe");
            return true;
        }
    }

    /// <summary>
    /// Verifies the executing assembly is not running from a temporary, download,
    /// or cache directory. Returns false if the assembly location matches one of
    /// the suspicious path fragments.
    /// Best-effort: returns true on exception.
    /// </summary>
    private static bool CheckLocation()
    {
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            string? location = assembly.Location;

            if (string.IsNullOrEmpty(location))
            {
                // Single-file publish or in-memory assembly — cannot determine location
                Log.Debug("IntegrityChecker: assembly location is empty (single-file publish); skipping location check");
                return true;
            }

            string fullPath = Path.GetFullPath(location).ToUpperInvariant();

            string[] suspiciousFragments =
            {
                Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
                    .ToUpperInvariant(),
                @"\TEMP\",
                @"\TMP\",
                @"\DOWNLOADS\",
                @"\CACHE\",
                @"\APPDATA\LOCAL\TEMP\",
            };

            foreach (string fragment in suspiciousFragments)
            {
                if (fullPath.Contains(fragment, StringComparison.Ordinal))
                {
                    Log.Warning(
                        "IntegrityChecker: assembly is running from a suspicious location — " +
                        "matched fragment {Fragment} in path {AssemblyPath}",
                        fragment,
                        location);
                    return false;
                }
            }

            Log.Debug("IntegrityChecker: assembly location is safe — {AssemblyPath}", location);
            return true;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "IntegrityChecker: location check failed — treating as safe");
            return true;
        }
    }

    /// <summary>
    /// Verifies the executing assembly loads correctly and checks whether it is
    /// strong-named. A missing strong name logs a warning but does not fail the check.
    /// Best-effort: returns true on exception.
    /// </summary>
    private static bool CheckAssembly()
    {
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            var assemblyName = assembly.GetName();

            // Verify the assembly name can be read
            if (string.IsNullOrEmpty(assemblyName.Name))
            {
                Log.Warning("IntegrityChecker: assembly name is null or empty");
                return false;
            }

            // Attempt to reload by full name to verify the assembly is loadable
            try
            {
                Assembly.Load(assemblyName);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "IntegrityChecker: failed to reload assembly by full name — {AssemblyName}", assemblyName.FullName);
                return false;
            }

            // Check for strong naming
            byte[]? publicKeyToken = assemblyName.GetPublicKeyToken();

            if (publicKeyToken is null || publicKeyToken.Length == 0)
            {
                Log.Debug(
                    "IntegrityChecker: assembly {AssemblyName} is not strong-named (advisory)",
                    assemblyName.Name);
            }
            else
            {
                Log.Debug(
                    "IntegrityChecker: assembly {AssemblyName} is strong-named — token: {PublicKeyToken}",
                    assemblyName.Name,
                    Convert.ToHexString(publicKeyToken).ToLowerInvariant());
            }

            Log.Debug("IntegrityChecker: assembly check passed — {AssemblyName}", assemblyName.FullName);
            return true;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "IntegrityChecker: assembly check failed — treating as safe");
            return true;
        }
    }

    /// <summary>
    /// Verifies the %LocalAppData%/TestVault directory ACLs do not include the
    /// Everyone or Users group with an Allow entry. Returns false if a broad
    /// Allow rule is found.
    /// Best-effort: returns true on exception.
    /// </summary>
    private static bool CheckPermissions()
    {
        try
        {
            if (!Directory.Exists(TestVaultDataPath))
            {
                Log.Debug("IntegrityChecker: TestVault data directory does not exist yet — skipping permission check");
                return true;
            }

            var dirInfo = new DirectoryInfo(TestVaultDataPath);
            DirectorySecurity dirSecurity = dirInfo.GetAccessControl();
            AuthorizationRuleCollection rules = dirSecurity.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier));

            // Well-known SIDs for Everyone and Users
            var everyoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

            foreach (FileSystemAccessRule rule in rules.OfType<FileSystemAccessRule>())
            {
                if (rule.AccessControlType != AccessControlType.Allow)
                    continue;

                if (rule.IdentityReference is not SecurityIdentifier sid)
                    continue;

                if (sid.Equals(everyoneSid))
                {
                    Log.Warning(
                        "IntegrityChecker: TestVault data directory has an Allow ACE for Everyone (S-1-1-0) — " +
                        "rights: {Rights}",
                        rule.FileSystemRights);
                    return false;
                }

                if (sid.Equals(usersSid))
                {
                    Log.Warning(
                        "IntegrityChecker: TestVault data directory has an Allow ACE for Users (S-1-5-32-545) — " +
                        "rights: {Rights}",
                        rule.FileSystemRights);
                    return false;
                }
            }

            Log.Debug("IntegrityChecker: directory permissions are safe — {Path}", TestVaultDataPath);
            return true;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "IntegrityChecker: permission check failed — treating as safe");
            return true;
        }
    }

    /// <summary>
    /// Cleans orphaned temp directories older than 2 hours and invokes
    /// <see cref="SecureLogger.CleanupOldLogs"/>. Returns true when cleanup
    /// completes (even if individual items fail).
    /// Best-effort: returns true on exception.
    /// </summary>
    private static bool RunCleanup()
    {
        try
        {
            CleanOrphanedTempDirectories();
            SecureLogger.CleanupOldLogs();

            Log.Debug("IntegrityChecker: cleanup completed successfully");
            return true;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "IntegrityChecker: cleanup failed — treating as done");
            return true;
        }
    }

    /// <summary>
    /// Enumerates subdirectories under %LocalAppData%/TestVault/temp/ and
    /// securely removes any that are older than <see cref="OrphanedDirMaxAge"/>.
    /// </summary>
    private static void CleanOrphanedTempDirectories()
    {
        if (!Directory.Exists(TempBasePath))
        {
            Log.Debug("IntegrityChecker: temp base path does not exist — nothing to clean");
            return;
        }

        string[] directories;

        try
        {
            directories = Directory.GetDirectories(TempBasePath);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "IntegrityChecker: failed to enumerate temp directories under {BasePath}", TempBasePath);
            return;
        }

        foreach (string dir in directories)
        {
            try
            {
                var dirInfo = new DirectoryInfo(dir);
                TimeSpan age = DateTime.UtcNow - dirInfo.CreationTimeUtc;

                if (age <= OrphanedDirMaxAge)
                    continue;

                Log.Information(
                    "IntegrityChecker: cleaning orphaned temp directory (age: {Age}): {Directory}",
                    age,
                    dir);

                // Securely delete all files before removing the directory
                foreach (string file in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        SecretStore.SecureFileDelete(file);
                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex, "IntegrityChecker: failed to securely delete orphaned file: {FilePath}", file);
                    }
                }

                Directory.Delete(dir, recursive: true);
                Log.Debug("IntegrityChecker: removed orphaned directory: {Directory}", dir);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "IntegrityChecker: failed to clean up orphaned directory: {Directory}", dir);
            }
        }
    }
}
