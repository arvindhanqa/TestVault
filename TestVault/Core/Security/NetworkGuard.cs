#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Serilog;

namespace TestVault.Core.Security;

/// <summary>
/// Exception thrown when a network request violates the security policy,
/// such as attempting to connect to a non-whitelisted domain.
/// </summary>
public sealed class NetworkSecurityException : SecurityException
{
    public NetworkSecurityException(string message)
        : base(message) { }

    public NetworkSecurityException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// Network firewall that restricts all outbound HTTP traffic to whitelisted domains only.
/// Enforces strict TLS settings, certificate validation, and domain filtering.
/// Must be initialized once at application startup via <see cref="Initialize"/>.
/// </summary>
[SupportedOSPlatform("windows")]
public static class NetworkGuard
{
    private static readonly object InitLock = new();
    private static volatile bool _initialized;
    private static string _sharePointDomain = string.Empty;
    private static readonly List<string> AllowedDomainSuffixes = new();

    private const string GenericUserAgent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan OverallTimeout = TimeSpan.FromMinutes(5);
    private const int MaxConnectionsPerServer = 4;

    /// <summary>
    /// Initializes the network guard with the target SharePoint domain.
    /// Configures TLS settings and certificate validation globally.
    /// Must be called exactly once at application startup.
    /// </summary>
    /// <param name="sharePointDomain">
    /// The SharePoint site domain (e.g. "contoso.sharepoint.com").
    /// </param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="sharePointDomain"/> is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">Thrown when called more than once.</exception>
    public static void Initialize(string sharePointDomain)
    {
        if (string.IsNullOrWhiteSpace(sharePointDomain))
            throw new ArgumentException("SharePoint domain must not be null or empty.", nameof(sharePointDomain));

        lock (InitLock)
        {
            if (_initialized)
                throw new InvalidOperationException("NetworkGuard has already been initialized.");

            _sharePointDomain = sharePointDomain.Trim().ToLowerInvariant();

            // Build the whitelist of allowed domain suffixes
            AllowedDomainSuffixes.Clear();
            AllowedDomainSuffixes.Add(_sharePointDomain);
            AllowedDomainSuffixes.Add(".sharepoint.com");
            AllowedDomainSuffixes.Add(".microsoft.com");
            AllowedDomainSuffixes.Add(".microsoftonline.com");
            AllowedDomainSuffixes.Add(".live.com");

            // Enforce TLS 1.2 and TLS 1.3 only — disable SSL3, TLS 1.0, TLS 1.1
#pragma warning disable SYSLIB0039 // SecurityProtocolType members are obsolete
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
#pragma warning restore SYSLIB0039

            // Reject any certificate with SSL policy errors — no exceptions
            ServicePointManager.ServerCertificateValidationCallback = ValidateServerCertificate;

            _initialized = true;

            Log.Information(
                "NetworkGuard initialized — SharePoint domain: {SharePointDomain}, " +
                "allowed suffixes: {AllowedSuffixes}, TLS 1.2+1.3 enforced",
                _sharePointDomain,
                AllowedDomainSuffixes);
        }
    }

    /// <summary>
    /// Creates a secure <see cref="HttpClient"/> configured with domain filtering,
    /// strict TLS, connection limits, and a generic User-Agent header.
    /// </summary>
    /// <param name="cookieContainer">
    /// Optional <see cref="CookieContainer"/> for session cookie management.
    /// A new container is created if none is provided.
    /// </param>
    /// <returns>A fully configured <see cref="HttpClient"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if <see cref="Initialize"/> has not been called.
    /// </exception>
    public static HttpClient CreateSecureClient(CookieContainer? cookieContainer = null)
    {
        EnsureInitialized();

        var socketHandler = new SocketsHttpHandler
        {
            CookieContainer = cookieContainer ?? new CookieContainer(),
            UseCookies = true,
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 10,
            ConnectTimeout = ConnectTimeout,
            MaxConnectionsPerServer = MaxConnectionsPerServer,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = ValidateServerCertificate
            },
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10)
        };

        var domainFilter = new DomainFilterHandler(socketHandler);

        var client = new HttpClient(domainFilter, disposeHandler: true)
        {
            Timeout = OverallTimeout
        };

        client.DefaultRequestHeaders.UserAgent.ParseAdd(GenericUserAgent);

        Log.Debug("Created secure HttpClient with domain filtering and TLS enforcement");

        return client;
    }

    /// <summary>
    /// Determines whether the given host is permitted by the whitelist.
    /// </summary>
    /// <param name="host">The hostname to check.</param>
    /// <returns><c>true</c> if the host matches a whitelisted domain; otherwise <c>false</c>.</returns>
    internal static bool IsHostAllowed(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return false;

        var normalizedHost = host.Trim().ToLowerInvariant();

        // Exact match against the SharePoint domain
        if (normalizedHost == _sharePointDomain)
            return true;

        // Suffix match against each allowed wildcard domain
        foreach (var suffix in AllowedDomainSuffixes)
        {
            if (suffix.StartsWith('.'))
            {
                // Wildcard suffix: host must end with the suffix or match the suffix without the leading dot
                if (normalizedHost.EndsWith(suffix, StringComparison.Ordinal) ||
                    normalizedHost == suffix.TrimStart('.'))
                    return true;
            }
            else
            {
                // Exact domain match
                if (normalizedHost == suffix)
                    return true;
            }
        }

        return false;
    }

    // ─── Private helpers ─────────────────────────────────────────────────

    private static bool ValidateServerCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors != SslPolicyErrors.None)
        {
            Log.Warning(
                "Certificate validation failed with errors: {SslPolicyErrors}",
                sslPolicyErrors);
            return false;
        }

        return true;
    }

    private static void EnsureInitialized()
    {
        if (!_initialized)
            throw new InvalidOperationException(
                "NetworkGuard has not been initialized. Call NetworkGuard.Initialize() at application startup.");
    }

    // ─── DomainFilterHandler ─────────────────────────────────────────────

    /// <summary>
    /// A <see cref="DelegatingHandler"/> that intercepts every outbound HTTP request
    /// and verifies the target host against the configured whitelist.
    /// Blocks and logs any attempt to reach a non-whitelisted domain.
    /// </summary>
    private sealed class DomainFilterHandler : DelegatingHandler
    {
        public DomainFilterHandler(HttpMessageHandler innerHandler)
            : base(innerHandler) { }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var host = request.RequestUri?.Host;

            if (host is null || !IsHostAllowed(host))
            {
                var blockedDomain = host ?? "<unknown>";

                // Log only the domain — never the full URL path for privacy/security
                Log.Warning(
                    "NetworkGuard blocked outbound request to non-whitelisted domain: {BlockedDomain}",
                    blockedDomain);

                throw new NetworkSecurityException(
                    $"Outbound HTTP request blocked: the domain '{blockedDomain}' is not in the allowed whitelist. " +
                    "Only connections to configured SharePoint and Microsoft authentication domains are permitted.");
            }

            Log.Debug("NetworkGuard permitted request to {AllowedDomain}", host);

            return base.SendAsync(request, cancellationToken);
        }
    }
}
