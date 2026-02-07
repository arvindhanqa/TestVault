#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Serilog;
using Serilog.Configuration;
using Serilog.Core;
using Serilog.Events;

namespace TestVault.Core.Security;

/// <summary>
/// Serilog-based secure logging system with automatic PII scrubbing.
/// All string properties in log events are inspected and sensitive values
/// (tokens, passwords, emails, JWTs, base64 blobs, etc.) are replaced
/// with ***REDACTED*** before the event reaches any sink.
/// </summary>
[SupportedOSPlatform("windows")]
public static class SecureLogger
{
    private const string RedactedPlaceholder = "***REDACTED***";

    private static readonly string LogDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TestVault",
        "logs");

    /// <summary>
    /// Initializes the global Serilog <see cref="Log.Logger"/> with a rolling file sink,
    /// PII scrubbing enricher, and sensible minimum levels.
    /// </summary>
    public static void Initialize()
    {
        Directory.CreateDirectory(LogDirectory);

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
            .Enrich.With<PiiScrubberEnricher>()
            .WriteTo.File(
                path: Path.Combine(LogDirectory, "testvault-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7,
                fileSizeLimitBytes: 10 * 1024 * 1024,
                rollOnFileSizeLimit: true,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
            .CreateLogger();

        Log.Information("SecureLogger initialized — log directory: {LogDirectory}", LogDirectory);
    }

    /// <summary>
    /// Removes log files older than <paramref name="daysToKeep"/> days by securely
    /// overwriting them via <see cref="SecretStore.SecureFileDelete"/> before deletion.
    /// </summary>
    /// <param name="daysToKeep">Number of days of logs to retain. Defaults to 7.</param>
    public static void CleanupOldLogs(int daysToKeep = 7)
    {
        if (!Directory.Exists(LogDirectory))
        {
            Log.Debug("Log directory does not exist; nothing to clean up");
            return;
        }

        var cutoff = DateTime.UtcNow.AddDays(-daysToKeep);
        var logFiles = Directory.GetFiles(LogDirectory, "testvault-*.log");

        foreach (var file in logFiles)
        {
            try
            {
                var lastWrite = File.GetLastWriteTimeUtc(file);
                if (lastWrite < cutoff)
                {
                    Log.Debug("Securely deleting expired log file: {FilePath}", file);
                    SecretStore.SecureFileDelete(file);
                }
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to clean up log file: {FilePath}", file);
            }
        }
    }

    // ─── PII Scrubber Enricher ──────────────────────────────────────────

    /// <summary>
    /// A Serilog enricher that walks every <see cref="ScalarValue"/> property in a
    /// <see cref="LogEvent"/> and replaces sensitive patterns with a redacted placeholder.
    /// </summary>
    internal sealed class PiiScrubberEnricher : ILogEventEnricher
    {
        // Bearer tokens: "Bearer <token>"
        private static readonly Regex BearerTokenPattern = new(
            @"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Key=value patterns for cookie / token / session values
        private static readonly Regex KeyValueSecretPattern = new(
            @"(?i)(cookie|token|session|sess_id|auth)[\s]*[=:][\s]*[^\s;,""']+",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Authorization and Set-Cookie header values
        private static readonly Regex AuthHeaderPattern = new(
            @"(?i)(Authorization|Set-Cookie)[\s]*:[\s]*[^\r\n]+",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Password / secret / key / apikey key=value pairs
        private static readonly Regex PasswordSecretPattern = new(
            @"(?i)(password|secret|key|apikey|api_key|api-key)[\s]*[=:][\s]*[^\s;,""']+",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Email addresses (RFC-5322 simplified)
        private static readonly Regex EmailPattern = new(
            @"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
            RegexOptions.Compiled);

        // Base64 strings longer than 40 characters
        private static readonly Regex Base64Pattern = new(
            @"[A-Za-z0-9+/]{40,}={0,2}",
            RegexOptions.Compiled);

        // JWT tokens (three base64url segments starting with eyJ)
        private static readonly Regex JwtPattern = new(
            @"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-]+",
            RegexOptions.Compiled);

        public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
        {
            if (logEvent is null)
                return;

            // Scrub the message template rendered properties
            var propertyKeys = logEvent.Properties.Keys.ToList();
            foreach (var key in propertyKeys)
            {
                var scrubbed = ScrubValue(logEvent.Properties[key]);
                if (!ReferenceEquals(scrubbed, logEvent.Properties[key]))
                {
                    logEvent.AddOrUpdateProperty(new LogEventProperty(key, scrubbed));
                }
            }
        }

        private static LogEventPropertyValue ScrubValue(LogEventPropertyValue value)
        {
            switch (value)
            {
                case ScalarValue scalar when scalar.Value is string text:
                    var scrubbed = ScrubString(text);
                    return ReferenceEquals(scrubbed, text)
                        ? value
                        : new ScalarValue(scrubbed);

                case SequenceValue sequence:
                    var elements = sequence.Elements;
                    var newElements = new LogEventPropertyValue[elements.Count];
                    bool changed = false;
                    for (int i = 0; i < elements.Count; i++)
                    {
                        newElements[i] = ScrubValue(elements[i]);
                        if (!ReferenceEquals(newElements[i], elements[i]))
                            changed = true;
                    }
                    return changed ? new SequenceValue(newElements) : value;

                case StructureValue structure:
                    var props = structure.Properties;
                    var newProps = new LogEventProperty[props.Count];
                    bool structChanged = false;
                    for (int i = 0; i < props.Count; i++)
                    {
                        var scrubVal = ScrubValue(props[i].Value);
                        if (!ReferenceEquals(scrubVal, props[i].Value))
                        {
                            newProps[i] = new LogEventProperty(props[i].Name, scrubVal);
                            structChanged = true;
                        }
                        else
                        {
                            newProps[i] = props[i];
                        }
                    }
                    return structChanged
                        ? new StructureValue(newProps, structure.TypeTag)
                        : value;

                case DictionaryValue dict:
                    var dictElements = dict.Elements;
                    var newDictElements = new List<KeyValuePair<ScalarValue, LogEventPropertyValue>>(dictElements.Count);
                    bool dictChanged = false;
                    foreach (var kvp in dictElements)
                    {
                        var scrubKey = ScrubValue(kvp.Key);
                        var scrubVal = ScrubValue(kvp.Value);
                        if (!ReferenceEquals(scrubKey, kvp.Key) || !ReferenceEquals(scrubVal, kvp.Value))
                        {
                            dictChanged = true;
                            newDictElements.Add(new KeyValuePair<ScalarValue, LogEventPropertyValue>(
                                (ScalarValue)scrubKey, scrubVal));
                        }
                        else
                        {
                            newDictElements.Add(kvp);
                        }
                    }
                    return dictChanged ? new DictionaryValue(newDictElements) : value;

                default:
                    return value;
            }
        }

        /// <summary>
        /// Applies all PII regex patterns to the input string and replaces
        /// matches with the redacted placeholder.
        /// </summary>
        private static string ScrubString(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            // Order matters: JWT before generic base64, Bearer before key-value
            string result = JwtPattern.Replace(input, RedactedPlaceholder);
            result = BearerTokenPattern.Replace(result, RedactedPlaceholder);
            result = AuthHeaderPattern.Replace(result, RedactedPlaceholder);
            result = PasswordSecretPattern.Replace(result, RedactedPlaceholder);
            result = KeyValueSecretPattern.Replace(result, RedactedPlaceholder);
            result = EmailPattern.Replace(result, RedactedPlaceholder);
            result = Base64Pattern.Replace(result, RedactedPlaceholder);

            // Return original reference if nothing changed to allow cheap equality check
            return string.Equals(result, input, StringComparison.Ordinal) ? input : result;
        }
    }
}
