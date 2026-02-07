#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Web.WebView2.Core;
using Serilog;
using TestVault.Core.Security;

namespace TestVault.Core.SharePoint;

/// <summary>
/// Represents a file discovered on a SharePoint document library.
/// </summary>
public record SharePointFile(
    string FileName,
    string ServerRelativePath,
    long FileSize,
    DateTime LastModified);

// ─── SharePoint REST API JSON response models ────────────────────────────

/// <summary>
/// Envelope for SharePoint REST API responses that return a collection of results.
/// </summary>
internal sealed class SharePointListResponse<T>
{
    [JsonPropertyName("d")]
    public SharePointResultSet<T>? D { get; set; }
}

/// <summary>
/// The "d" wrapper containing "results" array in SharePoint REST responses.
/// </summary>
internal sealed class SharePointResultSet<T>
{
    [JsonPropertyName("results")]
    public List<T>? Results { get; set; }
}

/// <summary>
/// Represents a single file entry returned by the SharePoint REST Files endpoint.
/// </summary>
internal sealed class SharePointFileEntry
{
    [JsonPropertyName("Name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("ServerRelativeUrl")]
    public string ServerRelativeUrl { get; set; } = string.Empty;

    [JsonPropertyName("Length")]
    public string Length { get; set; } = "0";

    [JsonPropertyName("TimeLastModified")]
    public string TimeLastModified { get; set; } = string.Empty;
}

/// <summary>
/// Represents the "d" wrapper for a single-value response such as _api/web/title.
/// </summary>
internal sealed class SharePointTitleResponse
{
    [JsonPropertyName("d")]
    public SharePointTitleValue? D { get; set; }
}

/// <summary>
/// Contains the Title property returned by _api/web/title.
/// </summary>
internal sealed class SharePointTitleValue
{
    [JsonPropertyName("Title")]
    public string Title { get; set; } = string.Empty;
}

/// <summary>
/// WebView2 cookie-harvesting SharePoint client. Authenticates by capturing session cookies
/// from a WebView2 browser control, encrypts them via <see cref="SecretStore"/>, and uses
/// <see cref="NetworkGuard"/> to enforce domain-whitelisted HTTPS connections.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SecureSharePointClient : IDisposable
{
    /// <summary>
    /// Maximum allowed file size for download (100 MB).
    /// </summary>
    private const long MaxFileSize = 100L * 1024 * 1024;

    /// <summary>
    /// File extensions permitted for listing and download.
    /// </summary>
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".xlsx",
        ".xls"
    };

    /// <summary>
    /// Domains from which cookies are harvested during WebView2 authentication.
    /// </summary>
    private static readonly string[] CookieDomains = new[]
    {
        ".sharepoint.com",
        ".microsoftonline.com"
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly string _siteUrl;
    private readonly SecretStore _secretStore;
    private readonly SecureTempDirectory _secureTempDirectory;

    private HttpClient? _httpClient;
    private CookieContainer? _cookieContainer;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of <see cref="SecureSharePointClient"/>.
    /// </summary>
    /// <param name="siteUrl">
    /// The full SharePoint site URL (e.g. "https://contoso.sharepoint.com/sites/QA").
    /// </param>
    /// <param name="secretStore">
    /// DPAPI-backed secret store used to persist encrypted session cookies.
    /// </param>
    /// <param name="secureTempDirectory">
    /// Isolated temporary directory for downloaded files; auto-wipes on disposal.
    /// </param>
    public SecureSharePointClient(
        string siteUrl,
        SecretStore secretStore,
        SecureTempDirectory secureTempDirectory)
    {
        if (string.IsNullOrWhiteSpace(siteUrl))
            throw new ArgumentException("Site URL must not be null or empty.", nameof(siteUrl));

        _siteUrl = siteUrl.TrimEnd('/');
        _secretStore = secretStore ?? throw new ArgumentNullException(nameof(secretStore));
        _secureTempDirectory = secureTempDirectory ?? throw new ArgumentNullException(nameof(secureTempDirectory));

        Log.Information("SecureSharePointClient created for site {SiteUrl}", _siteUrl);
    }

    // ─── Events ──────────────────────────────────────────────────────────

    /// <summary>
    /// Raised to report human-readable status messages (e.g. "Downloading file...").
    /// </summary>
    public Action<string>? OnStatusUpdate { get; set; }

    /// <summary>
    /// Raised when the client determines that authentication is required
    /// (e.g. stored session has expired or a 401/403 was received).
    /// </summary>
    public Action? OnAuthenticationRequired { get; set; }

    /// <summary>
    /// Raised after session cookies have been successfully captured from WebView2.
    /// </summary>
    public Action? OnAuthenticationComplete { get; set; }

    // ─── Properties ──────────────────────────────────────────────────────

    /// <summary>
    /// Indicates whether the client currently holds a valid authenticated session.
    /// </summary>
    public bool IsAuthenticated { get; private set; }

    // ─── Session restore ─────────────────────────────────────────────────

    /// <summary>
    /// Attempts to restore a previous session by loading encrypted cookies from
    /// <see cref="SecretStore"/> and verifying them against the SharePoint REST API.
    /// </summary>
    /// <returns><c>true</c> if the session was restored and verified; otherwise <c>false</c>.</returns>
    public async Task<bool> TryRestoreSessionAsync()
    {
        ThrowIfDisposed();
        OnStatusUpdate?.Invoke("Attempting to restore previous session...");

        try
        {
            var cookieContainer = new CookieContainer();
            bool hasCookies = false;

            foreach (string domain in CookieDomains)
            {
                var cookies = _secretStore.RetrieveCookies(domain);
                if (cookies is null || cookies.Count == 0)
                    continue;

                foreach (var cookie in cookies)
                {
                    try
                    {
                        cookieContainer.Add(new Cookie(
                            cookie.Name,
                            cookie.Value,
                            cookie.Path,
                            cookie.Domain)
                        {
                            Secure = cookie.IsSecure,
                            HttpOnly = cookie.IsHttpOnly,
                            Expires = cookie.Expires
                        });
                        hasCookies = true;
                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex, "Skipped invalid cookie {CookieName} for domain {Domain}",
                            cookie.Name, cookie.Domain);
                    }
                }
            }

            if (!hasCookies)
            {
                Log.Information("No stored cookies found; session restore skipped");
                OnStatusUpdate?.Invoke("No stored session found.");
                return false;
            }

            // Build a temporary client with the restored cookies
            _cookieContainer = cookieContainer;
            _httpClient?.Dispose();
            _httpClient = NetworkGuard.CreateSecureClient(_cookieContainer);

            // Verify the session by calling _api/web/title
            string testUrl = $"{_siteUrl}/_api/web/title";
            var response = await AuthenticatedGetAsync(testUrl).ConfigureAwait(false);

            if (response is null || !response.IsSuccessStatusCode)
            {
                Log.Information("Session restore verification failed; stored cookies are no longer valid");
                OnStatusUpdate?.Invoke("Stored session expired. Please sign in again.");
                _httpClient?.Dispose();
                _httpClient = null;
                _cookieContainer = null;
                return false;
            }

            IsAuthenticated = true;
            OnStatusUpdate?.Invoke("Session restored successfully.");
            Log.Information("Session restored and verified for {SiteUrl}", _siteUrl);
            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to restore session for {SiteUrl}", _siteUrl);
            OnStatusUpdate?.Invoke("Session restore failed.");
            return false;
        }
    }

    // ─── WebView2 cookie capture ─────────────────────────────────────────

    /// <summary>
    /// Captures authentication cookies from a <see cref="CoreWebView2"/> browser control
    /// that has completed the SharePoint/Microsoft login flow. Cookies for SharePoint and
    /// microsoftonline.com domains are extracted, encrypted, and persisted via <see cref="SecretStore"/>.
    /// An authenticated <see cref="HttpClient"/> is built from the captured cookies.
    /// </summary>
    /// <param name="webView">The WebView2 core instance that has completed authentication.</param>
    public async Task CaptureSessionFromWebView(CoreWebView2 webView)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(webView);

        OnStatusUpdate?.Invoke("Capturing session cookies from browser...");

        try
        {
            var cookieManager = webView.CookieManager;
            var cookieContainer = new CookieContainer();

            foreach (string domain in CookieDomains)
            {
                string cookieUri = domain.StartsWith('.')
                    ? $"https://{domain.TrimStart('.')}"
                    : $"https://{domain}";

                var webViewCookies = await cookieManager.GetCookiesAsync(cookieUri).ConfigureAwait(false);
                var cookieDataList = new List<CookieData>();

                foreach (var wvCookie in webViewCookies)
                {
                    var cookieData = new CookieData(
                        Name: wvCookie.Name,
                        Value: wvCookie.Value,
                        Domain: wvCookie.Domain,
                        Path: wvCookie.Path,
                        Expires: wvCookie.Expires,
                        IsSecure: wvCookie.IsSecure,
                        IsHttpOnly: wvCookie.IsHttpOnly);

                    cookieDataList.Add(cookieData);

                    try
                    {
                        cookieContainer.Add(new Cookie(
                            wvCookie.Name,
                            wvCookie.Value,
                            wvCookie.Path,
                            wvCookie.Domain)
                        {
                            Secure = wvCookie.IsSecure,
                            HttpOnly = wvCookie.IsHttpOnly,
                            Expires = wvCookie.Expires
                        });
                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex, "Skipped invalid WebView2 cookie {CookieName}", wvCookie.Name);
                    }
                }

                if (cookieDataList.Count > 0)
                {
                    _secretStore.StoreCookies(domain, cookieDataList);
                    Log.Information(
                        "Stored {CookieCount} cookies for domain {Domain}",
                        cookieDataList.Count,
                        domain);
                }
            }

            // Also capture cookies that match the specific site URL
            var siteCookies = await cookieManager.GetCookiesAsync(_siteUrl).ConfigureAwait(false);
            foreach (var wvCookie in siteCookies)
            {
                try
                {
                    cookieContainer.Add(new Cookie(
                        wvCookie.Name,
                        wvCookie.Value,
                        wvCookie.Path,
                        wvCookie.Domain)
                    {
                        Secure = wvCookie.IsSecure,
                        HttpOnly = wvCookie.IsHttpOnly,
                        Expires = wvCookie.Expires
                    });
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "Skipped invalid site cookie {CookieName}", wvCookie.Name);
                }
            }

            // Build the authenticated HttpClient
            _cookieContainer = cookieContainer;
            _httpClient?.Dispose();
            _httpClient = NetworkGuard.CreateSecureClient(_cookieContainer);

            IsAuthenticated = true;
            OnStatusUpdate?.Invoke("Authentication successful.");
            OnAuthenticationComplete?.Invoke();

            Log.Information("Session captured from WebView2 for {SiteUrl}", _siteUrl);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to capture session from WebView2 for {SiteUrl}", _siteUrl);
            OnStatusUpdate?.Invoke("Failed to capture session cookies.");
            throw;
        }
    }

    // ─── File listing ────────────────────────────────────────────────────

    /// <summary>
    /// Lists Excel files (.xlsx, .xls) in the specified SharePoint document library.
    /// Only files matching <see cref="AllowedExtensions"/> and smaller than <see cref="MaxFileSize"/>
    /// are returned.
    /// </summary>
    /// <param name="libraryName">
    /// The display name of the SharePoint document library (e.g. "Test Cases").
    /// </param>
    /// <returns>A list of <see cref="SharePointFile"/> records for qualifying Excel files.</returns>
    public async Task<List<SharePointFile>> ListExcelFilesAsync(string libraryName)
    {
        ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(libraryName))
            throw new ArgumentException("Library name must not be null or empty.", nameof(libraryName));

        OnStatusUpdate?.Invoke($"Listing Excel files in '{libraryName}'...");

        string encodedLibrary = Uri.EscapeDataString(libraryName);
        string url = $"{_siteUrl}/_api/web/lists/getbytitle('{encodedLibrary}')/items" +
                     "?$select=FileLeafRef,FileRef,File_x0020_Size,Modified" +
                     "&$filter=substringof('.xlsx',FileLeafRef) or substringof('.xls',FileLeafRef)" +
                     "&$top=5000";

        var response = await AuthenticatedGetAsync(url).ConfigureAwait(false);

        if (response is null || !response.IsSuccessStatusCode)
        {
            Log.Warning(
                "Failed to list files from library {Library}. Status: {StatusCode}",
                libraryName,
                response?.StatusCode);
            OnStatusUpdate?.Invoke($"Failed to list files from '{libraryName}'.");
            return new List<SharePointFile>();
        }

        string json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        var parsed = JsonSerializer.Deserialize<SharePointListItemResponse>(json, JsonOptions);
        var items = parsed?.D?.Results;

        if (items is null || items.Count == 0)
        {
            Log.Information("No files found in library {Library}", libraryName);
            OnStatusUpdate?.Invoke($"No Excel files found in '{libraryName}'.");
            return new List<SharePointFile>();
        }

        var result = new List<SharePointFile>();

        foreach (var item in items)
        {
            string fileName = item.FileLeafRef;
            string extension = Path.GetExtension(fileName);

            // Enforce the allowed extensions whitelist
            if (!AllowedExtensions.Contains(extension))
            {
                Log.Debug("Skipping file with disallowed extension: {FileName}", fileName);
                continue;
            }

            long fileSize = long.TryParse(item.FileSizeText, out long parsed_size) ? parsed_size : 0;

            // Enforce maximum file size
            if (fileSize > MaxFileSize)
            {
                Log.Warning(
                    "Skipping file exceeding max size ({FileSize} bytes): {FileName}",
                    fileSize,
                    fileName);
                continue;
            }

            DateTime lastModified = DateTime.TryParse(item.Modified, out DateTime parsedDate)
                ? parsedDate
                : DateTime.MinValue;

            result.Add(new SharePointFile(
                FileName: fileName,
                ServerRelativePath: item.FileRef,
                FileSize: fileSize,
                LastModified: lastModified));
        }

        Log.Information(
            "Found {FileCount} qualifying Excel files in library {Library}",
            result.Count,
            libraryName);
        OnStatusUpdate?.Invoke($"Found {result.Count} Excel file(s) in '{libraryName}'.");

        return result;
    }

    // ─── File download ───────────────────────────────────────────────────

    /// <summary>
    /// Downloads a SharePoint file to the secure temporary directory and computes
    /// its SHA-256 hash. The file size is verified against <see cref="MaxFileSize"/>
    /// before download begins.
    /// </summary>
    /// <param name="file">The <see cref="SharePointFile"/> to download.</param>
    /// <returns>
    /// A tuple containing the local file path and its SHA-256 hash (lowercase hex).
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the file exceeds the maximum allowed size.
    /// </exception>
    public async Task<(string LocalPath, string Hash)> DownloadFileAsync(SharePointFile file)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(file);

        if (file.FileSize > MaxFileSize)
        {
            throw new InvalidOperationException(
                $"File '{file.FileName}' ({file.FileSize:N0} bytes) exceeds the maximum allowed size of {MaxFileSize:N0} bytes.");
        }

        OnStatusUpdate?.Invoke($"Downloading '{file.FileName}'...");

        string encodedPath = Uri.EscapeDataString(file.ServerRelativePath);
        string url = $"{_siteUrl}/_api/web/GetFileByServerRelativePath(decodedurl='{encodedPath}')/$value";

        var response = await AuthenticatedGetAsync(url).ConfigureAwait(false);

        if (response is null || !response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Failed to download file '{file.FileName}'. " +
                $"Status: {response?.StatusCode.ToString() ?? "no response"}");
        }

        // Verify content length if the server provides it
        long? contentLength = response.Content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > MaxFileSize)
        {
            throw new InvalidOperationException(
                $"File '{file.FileName}' content length ({contentLength.Value:N0} bytes) " +
                $"exceeds the maximum allowed size of {MaxFileSize:N0} bytes.");
        }

        // Stream the response into the secure temp directory
        await using var contentStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        string localPath = await _secureTempDirectory.WriteTempFileAsync(file.FileName, contentStream)
            .ConfigureAwait(false);

        // Verify actual downloaded size
        var fileInfo = new FileInfo(localPath);
        if (fileInfo.Length > MaxFileSize)
        {
            _secureTempDirectory.SecureDeleteFile(localPath);
            throw new InvalidOperationException(
                $"Downloaded file '{file.FileName}' ({fileInfo.Length:N0} bytes) " +
                $"exceeds the maximum allowed size of {MaxFileSize:N0} bytes.");
        }

        // Compute SHA-256 hash
        string hash = await SecureTempDirectory.ComputeFileHashAsync(localPath).ConfigureAwait(false);

        Log.Information(
            "Downloaded {FileName} ({FileSize} bytes) to {LocalPath} with hash {Hash}",
            file.FileName,
            fileInfo.Length,
            localPath,
            hash);
        OnStatusUpdate?.Invoke($"Downloaded '{file.FileName}' ({fileInfo.Length:N0} bytes).");

        return (localPath, hash);
    }

    // ─── Authenticated HTTP ──────────────────────────────────────────────

    /// <summary>
    /// Sends an authenticated GET request. If a 401 or 403 response is received,
    /// <see cref="IsAuthenticated"/> is set to <c>false</c> and
    /// <see cref="OnAuthenticationRequired"/> is raised.
    /// </summary>
    /// <param name="url">The absolute URL to request.</param>
    /// <returns>
    /// The <see cref="HttpResponseMessage"/>, or <c>null</c> if no client is available.
    /// </returns>
    private async Task<HttpResponseMessage?> AuthenticatedGetAsync(string url)
    {
        if (_httpClient is null)
        {
            Log.Warning("AuthenticatedGetAsync called without an active HttpClient");
            IsAuthenticated = false;
            OnAuthenticationRequired?.Invoke();
            return null;
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Add("odata-version", "3.0");

            var response = await _httpClient.SendAsync(request).ConfigureAwait(false);

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                Log.Warning(
                    "Received {StatusCode} from {Url}; marking session as unauthenticated",
                    response.StatusCode,
                    url);

                IsAuthenticated = false;
                OnAuthenticationRequired?.Invoke();
                return response;
            }

            return response;
        }
        catch (HttpRequestException ex)
        {
            Log.Error(ex, "HTTP request failed for {Url}", url);
            throw;
        }
    }

    // ─── IDisposable ─────────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        _httpClient?.Dispose();
        _httpClient = null;
        _cookieContainer = null;

        Log.Debug("SecureSharePointClient disposed");
    }

    // ─── Private helpers ─────────────────────────────────────────────────

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

// ─── SharePoint list item JSON response models ──────────────────────────

/// <summary>
/// Envelope for SharePoint REST API list-item responses.
/// </summary>
internal sealed class SharePointListItemResponse
{
    [JsonPropertyName("d")]
    public SharePointListItemResultSet? D { get; set; }
}

/// <summary>
/// The "d" wrapper containing "results" array for list-item queries.
/// </summary>
internal sealed class SharePointListItemResultSet
{
    [JsonPropertyName("results")]
    public List<SharePointListItem>? Results { get; set; }
}

/// <summary>
/// Represents a single list item returned by the SharePoint REST Items endpoint,
/// projected to include file metadata.
/// </summary>
internal sealed class SharePointListItem
{
    [JsonPropertyName("FileLeafRef")]
    public string FileLeafRef { get; set; } = string.Empty;

    [JsonPropertyName("FileRef")]
    public string FileRef { get; set; } = string.Empty;

    [JsonPropertyName("File_x0020_Size")]
    public string FileSizeText { get; set; } = "0";

    [JsonPropertyName("Modified")]
    public string Modified { get; set; } = string.Empty;
}
