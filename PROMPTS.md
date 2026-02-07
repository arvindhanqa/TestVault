# TestVault — Claude Code Build Prompts

## How to Use This File

1. Open terminal on your PC
2. Run each prompt in order inside Claude Code
3. After each prompt, review the output and commit

```bash
# After each prompt succeeds:
git add .
git commit -m "the commit message shown after each prompt"
```

---

## PROMPT 0: Project Setup

> Copy-paste this into your regular terminal (NOT Claude Code yet)

```bash
mkdir TestVault && cd TestVault
git init
dotnet new wpf -n TestVault --framework net8.0
cd TestVault
```

Now add these NuGet packages:

```bash
dotnet add package Microsoft.Web.WebView2
dotnet add package EPPlus
dotnet add package Microsoft.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
dotnet add package SQLitePCLRaw.bundle_e_sqlcipher
dotnet add package Microsoft.AspNetCore.DataProtection
dotnet add package CommunityToolkit.Mvvm
dotnet add package LiveChartsCore.SkiaSharpView.WPF
dotnet add package Serilog
dotnet add package Serilog.Sinks.File
```

```bash
mkdir -p Core/Security Core/Data Core/SharePoint Core/Models Core/Services UI/Views UI/ViewModels UI/Converters Resources
git add .
git commit -m "chore: initial WPF project with NuGet packages"
```

Now start Claude Code:

```bash
claude
```

---

## PROMPT 1: Secret Store

```
Create Core/Security/SecretStore.cs

A DPAPI-based secret storage class for Windows. Requirements:

- Uses System.Security.Cryptography.ProtectedData with DataProtectionScope.CurrentUser
- Additional entropy salt unique to our app: "TestVault-v1-2025-entropy-salt"
- Stores encrypted secrets as files in %LocalAppData%/TestVault/secrets/
- Sets directory and file ACLs to current Windows user only (remove inheritance, add FullControl for current user only)
- Methods: StoreSecret(key, value), RetrieveSecret(key) -> string?, DeleteSecret(key), PurgeAll()
- StoreCookies(domain, cookies) and RetrieveCookies(domain) that serialize CookieData records to JSON then encrypt
- SecureFileDelete static method: 3-pass overwrite (zeros, 0xFF, random bytes) before File.Delete
- CryptographicOperations.ZeroMemory on all plaintext byte arrays in finally blocks
- IDisposable pattern
- Serilog logging (NEVER log secret values, only key names)
- Input validation on key names (no path chars)
- Create a CookieData record: Name, Value, Domain, Path, Expires(DateTime), IsSecure, IsHttpOnly

Run dotnet build after creating the file and fix any errors.
```

**Commit:** `git commit -m "feat: DPAPI secret store with secure file deletion"`

---

## PROMPT 2: Network Guard

```
Create Core/Security/NetworkGuard.cs

A network firewall class that restricts all outbound HTTP to whitelisted domains only. Requirements:

- Static class with Initialize(sharePointDomain) method — call once at startup
- Enforces TLS 1.2 and 1.3 ONLY via ServicePointManager.SecurityProtocol (disable SSL3, TLS 1.0, TLS 1.1)
- Certificate validation callback that rejects ALL SslPolicyErrors (no exceptions)
- CreateSecureClient(CookieContainer?) -> HttpClient factory method using SocketsHttpHandler
- Uses a DomainFilterHandler (DelegatingHandler) that checks every request's host against whitelist
- Allowed hosts: the configured SharePoint domain, *.sharepoint.com, *.microsoft.com, *.microsoftonline.com, *.live.com (for SSO redirects)
- Any request to non-whitelisted domain throws SecurityException with clear message
- User-Agent set to a generic browser string (no app fingerprinting)
- Connection timeouts: 30s connect, 5min overall, 4 max connections per server
- Log all blocked connection attempts (domain only, never the full URL path)
- Custom SecurityException class

Run dotnet build after creating the file and fix any errors.
```

**Commit:** `git commit -m "feat: network guard with domain whitelist firewall"`

---

## PROMPT 3: Memory Guard

```
Create Core/Security/MemoryGuard.cs

Memory protection utilities to prevent sensitive data from persisting in RAM. Requirements:

- Static class MemoryGuard with:
  - UseSecret<T>(byte[] secretBytes, Func<string, T> action): pins the array via GCHandle.Alloc Pinned, converts to string, runs action, zeros bytes in finally, frees handle
  - SecureZero(byte[]): uses CryptographicOperations.ZeroMemory with NoInlining + NoOptimization attributes, Volatile.Read to prevent dead-store elimination
  - SecureZero(char[]): same pattern for char arrays
  - CreatePinnedBuffer(int size) -> PinnedBuffer

- PinnedBuffer sealed class implementing IDisposable:
  - Allocates byte array pinned via GCHandle
  - Exposes Buffer, Span, Length properties
  - Dispose zeros the buffer and frees handle
  - ThrowIf disposed pattern

Run dotnet build after creating the file and fix any errors.
```

**Commit:** `git commit -m "feat: memory protection utilities"`

---

## PROMPT 4: Secure Logger

```
Create Core/Security/SecureLogger.cs

A Serilog-based logging system with automatic PII scrubbing. Requirements:

- Static class SecureLogger with Initialize() method
- Logs to %LocalAppData%/TestVault/logs/testvault-{Date}.log
- Rolling daily, 7-day retention, 10MB max per file
- MinimumLevel.Information, override EF Core to Warning
- PiiScrubberEnricher (implements ILogEventEnricher) that regex-scrubs ALL string properties:
  - Bearer tokens
  - Cookie/token/session values (key=value patterns)
  - Authorization/Set-Cookie headers
  - Password/secret/key/apikey values
  - Email addresses
  - Base64 strings > 40 chars
  - JWT tokens (eyJ pattern)
  - Replace all matches with "***REDACTED***"
- CleanupOldLogs(daysToKeep=7) method that calls SecretStore.SecureFileDelete on expired logs
- Use compiled Regex with IgnoreCase where appropriate

Run dotnet build after creating the file and fix any errors.
```

**Commit:** `git commit -m "feat: PII-scrubbing secure logger"`

---

## PROMPT 5: Secure Temp Directory

```
Create Core/Security/SecureTempDirectory.cs

An isolated temp directory that auto-wipes on exit. Requirements:

- Sealed class implementing IDisposable
- Base path: %LocalAppData%/TestVault/temp/
- Each session gets a random subdirectory (8 random hex bytes via RandomNumberGenerator)
- ACL locked to current Windows user only
- Methods:
  - GetTempFilePath(originalFileName) -> sanitized path
  - WriteTempFileAsync(originalFileName, byte[]) -> path
  - WriteTempFileAsync(originalFileName, Stream) -> path
  - ComputeFileHashAsync(filePath) -> SHA-256 hex string (static)
  - SecureDeleteFile(filePath) — only deletes if within session dir
- Private Cleanup() method: SecureFileDelete every file, then Directory.Delete
- Register Cleanup on AppDomain.ProcessExit AND UnhandledException
- CleanupOrphanedDirs: on startup, delete any session dirs older than 1 hour
- SanitizeFileName: strip invalid chars, replace ".." with "_", limit to 200 chars

Run dotnet build after creating the file and fix any errors.
```

**Commit:** `git commit -m "feat: secure temp directory with auto-wipe"`

---

## PROMPT 6: Data Models

```
Create Core/Models/Models.cs

Entity models for the test management system. All in namespace TestVault.Core.Models:

- TestCase: Id, Title(required,max500), Description, Module(max200,indexed), Priority(indexed), Status(indexed), Preconditions, Steps, ExpectedResult, Assignee, Tags, RequirementId, ExcelSourceId(int), ExcelRowNumber(int), ImportedAt, LastSyncedAt, FileHash
- TestRun: Id, Name(required,max200), Description, Environment, BuildVersion, CreatedAt, CompletedAt?, CreatedBy
- TestExecution: Id, TestCaseId(FK->TestCase), TestRunId(FK->TestRun), Result(required: Pass/Fail/Blocked/Skipped), Notes, DefectId, ExecutedAt, ExecutedBy, DurationSeconds
- ExcelSource: Id, FileName(required), SharePointPath(required,max1000), FileHash(required,max64), FileSize(long), LastModifiedOnServer, LastSyncedAt, TotalTestCases
- AuditEntry: Id, Action(required,max100), Details, Timestamp(indexed), WindowsUser(required)
- SyncMetadata: Id, LastFullSync, LastIncrementalSync, FilesTracked, TotalTestCases

Run dotnet build after creating the file and fix any errors.
```

**Commit:** `git commit -m "feat: data models for test management"`

---

## PROMPT 7: Encrypted Database

```
Create Core/Data/TestVaultDbContext.cs

A SQLCipher-encrypted EF Core database context. Requirements:

- DbSets for all 6 models from Core/Models/Models.cs
- Database file: %LocalAppData%/TestVault/data/testvault.db
- OnConfiguring: connection string includes Password= from GetOrCreateDbKey()
- GetOrCreateDbKey (private static): checks SecretStore for "db_encryption_key", if missing generates 32 random bytes via RandomNumberGenerator, Base64 encodes, stores via SecretStore, zeros the byte array
- EnableSensitiveDataLogging(false) always
- OnModelCreating: configure all entity keys, indexes on Module/Priority/Status/Timestamp, required fields, max lengths, FK relationships
- VerifyIntegrityAsync(): runs PRAGMA integrity_check
- AuditAsync(action, details?): adds AuditEntry with UTC timestamp and Environment.UserName
- SanitizeForLog(string?): regex replaces password/token/cookie/secret/key/authorization/bearer values with ***REDACTED***

Run dotnet build after creating the file and fix any errors.
```

**Commit:** `git commit -m "feat: SQLCipher encrypted database context"`

---

## PROMPT 8: Integrity Checker

```
Create Core/Security/IntegrityChecker.cs

Startup integrity verification. Requirements:

- Static class with RunAllChecksAsync() -> IntegrityResult
- Checks:
  1. DebuggerCheck: !Debugger.IsAttached (warn, don't fail)
  2. LocationCheck: verify assembly isn't running from temp/download/cache directories
  3. AssemblyCheck: verify assembly loads correctly, check for strong naming
  4. PermissionCheck: verify %LocalAppData%/TestVault ACLs don't include Everyone or Users group with Allow
  5. CleanupDone: clean orphaned temp dirs > 2 hours old, call SecureLogger.CleanupOldLogs()
- IntegrityResult class: bool properties for each check, AllPassed (excludes DebuggerCheck), HasWarnings
- All checks are best-effort — catch exceptions and return true to avoid blocking

Run dotnet build after creating the file and fix any errors.
```

**Commit:** `git commit -m "feat: startup integrity checker"`

---

## PROMPT 9: SharePoint Client

```
Create Core/SharePoint/SecureSharePointClient.cs

WebView2 cookie-harvesting SharePoint client. Requirements:

- Constructor takes siteUrl, SecretStore, SecureTempDirectory
- Events: OnStatusUpdate(string), OnAuthenticationRequired(), OnAuthenticationComplete()
- TryRestoreSessionAsync(): load cookies from SecretStore, test with GET _api/web/title, return bool
- CaptureSessionFromWebView(CoreWebView2): extract cookies from CookieManager for SharePoint + microsoftonline.com, encrypt via SecretStore.StoreCookies, build HttpClient via NetworkGuard.CreateSecureClient
- ListExcelFilesAsync(libraryName): SharePoint REST API _api/web/lists/getbytitle, filter for .xlsx/.xls, enforce AllowedExtensions whitelist and MaxFileSize (100MB), return List<SharePointFile>
- DownloadFileAsync(SharePointFile) -> (LocalPath, Hash): download via _api/web/GetFileByServerRelativePath/$value, verify size, save to SecureTempDirectory, compute SHA-256 hash
- AuthenticatedGetAsync: handles 401/403 by setting IsAuthenticated=false and raising OnAuthenticationRequired
- SharePointFile record: FileName, ServerRelativePath, FileSize, LastModified
- SharePoint JSON response models with System.Text.Json attributes
- IDisposable, dispose HttpClient

Run dotnet build after creating the file and fix any errors.
```

**Commit:** `git commit -m "feat: SharePoint client with cookie harvesting"`

---

## PROMPT 10: Excel Parser

```
Create Core/Services/SecureExcelParser.cs

Secure in-memory Excel parser. Requirements:

- Constructor takes TestVaultDbContext, sets EPPlus LicenseContext.NonCommercial
- Event: OnProgress(string)
- ParseAndImportAsync(filePath, sharePointPath, fileHash) -> ParseResult:
  - Verify file hash matches (detect TOCTOU tampering)
  - Open with EPPlus in-memory
  - For each worksheet, auto-detect column mapping from header row
  - Column detection: match headers containing keywords like title/name/summary, description, module/area/component, priority/severity, status, precondition/setup, step/action, expected/result, assign/owner/tester, tag/label, requirement/req/story/ticket
  - Upsert test cases: match by ExcelSourceId + ExcelRowNumber
  - Batch SaveChanges every 100 rows
  - SafeGetCellValue: trim, truncate to 10000 chars, strip control characters (keep newline/tab)
  - MaxRowsPerFile = 50000
  - Audit the import action
- Track ExcelSource in DB (get or create by SharePointPath)
- ParseResult: FileName, Success, TestCasesParsed, TestCasesUpdated, RowsSkipped, Error

Run dotnet build after creating the file and fix any errors.
```

**Commit:** `git commit -m "feat: secure Excel parser with auto column detection"`

---

## PROMPT 11: App Bootstrapper

```
Create Core/AppBootstrapper.cs

Orchestrates secure startup and shutdown. Requirements:

- Sealed class, IDisposable
- Properties: Config(AppConfig), SecretStore, TempDir, Database, SharePoint — all throw if not initialized
- InitializeAsync() -> StartupResult:
  1. SecureLogger.Initialize()
  2. IntegrityChecker.RunAllChecksAsync()
  3. NetworkGuard.Initialize(domain from config URL)
  4. new SecretStore()
  5. new TestVaultDbContext() + EnsureCreatedAsync + VerifyIntegrityAsync
  6. new SecureTempDirectory()
  7. new SecureSharePointClient(url, store, temp)
  8. TryRestoreSessionAsync()
  9. AuditAsync("APP_START")
- ShutdownAsync(): audit "APP_SHUTDOWN", Dispose, Log.CloseAndFlushAsync
- EmergencyPurgeAsync(): dispose temp, PurgeAll secrets, SecureFileDelete DB file, wipe log dir
- AppConfig class: SharePointSiteUrl(required), DocumentLibraryName?, SyncIntervalMinutes=30, MaxFileSizeMb=100, AutoSyncEnabled=true
  - LoadOrCreate(SecretStore): load encrypted JSON or return default
  - Save(SecretStore): serialize and encrypt
- StartupResult: Success, IntegrityPassed, DatabaseReady, SessionRestored, Error

Run dotnet build after creating the file and fix any errors.
```

**Commit:** `git commit -m "feat: app bootstrapper with secure startup sequence"`

---

## PROMPT 12: WPF Main Window + Login

```
Now build the WPF UI. Create:

1. MainWindow.xaml + MainWindow.xaml.cs — The app shell with:
   - A Grid with two panels: LoginPanel (WebView2) and DashboardPanel
   - WebView2 control that navigates to the SharePoint URL
   - On NavigationCompleted, detect successful login (URL contains the SharePoint site path), call SharePoint.CaptureSessionFromWebView, then hide login panel and show dashboard
   - Status bar at the bottom showing sync status and security indicator (🔒)
   - Menu bar: File > Settings, File > Emergency Purge (with confirmation dialog), File > Exit
   - A "Log In Again" button that shows the WebView2 panel

2. App.xaml.cs — Override OnStartup:
   - Show a splash/loading screen
   - Run AppBootstrapper.InitializeAsync()
   - If integrity check failed, show warning MessageBox
   - If session restored, go straight to dashboard
   - Otherwise show login panel

Make sure the app handles shutdown gracefully — override OnExit to call ShutdownAsync.

Run dotnet build and fix any errors.
```

**Commit:** `git commit -m "feat: main window with WebView2 SSO login flow"`

---

## PROMPT 13: Test Case Browser View

```
Create UI/Views/TestCaseBrowserView.xaml (UserControl) and its ViewModel:

1. TestCaseBrowserViewModel (using CommunityToolkit.Mvvm):
   - ObservableCollection<TestCase> for the DataGrid
   - SearchText property that filters across Title, Module, Description, Tags
   - SelectedModule, SelectedPriority, SelectedStatus filter ComboBoxes
   - LoadTestCasesCommand that queries the encrypted DB
   - ExportToExcelCommand that exports filtered view back to .xlsx
   - Pagination: PageSize=50, NextPage/PreviousPage commands
   - TestCase count summary text

2. TestCaseBrowserView.xaml:
   - Toolbar row: SearchBox (TextBox with placeholder), Module ComboBox, Priority ComboBox, Status ComboBox, Clear Filters button
   - DataGrid with columns: ID, Title, Module, Priority, Status, Assignee, Requirement, Source File
   - Priority column with color coding (P1=Red, P2=Orange, P3=Yellow, P4=Green)
   - Status column with color coding
   - Row double-click to open detail panel
   - Footer: showing "X of Y test cases" and pagination controls

Run dotnet build and fix any errors.
```

**Commit:** `git commit -m "feat: test case browser with filtering and search"`

---

## PROMPT 14: Dashboard View

```
Create UI/Views/DashboardView.xaml (UserControl) and its ViewModel:

1. DashboardViewModel:
   - Loads stats from encrypted DB on initialization
   - Properties for chart data series using LiveChartsCore types:
     a. Test cases by Module (bar chart)
     b. Test cases by Priority (pie chart)  
     c. Test cases by Status (pie chart)
     d. Test executions pass/fail trend over time (line chart)
     e. Coverage summary: total cases, executed, pass rate percentage
   - RefreshCommand to reload all stats
   - Last sync time display

2. DashboardView.xaml:
   - Top row: 4 summary cards (Total Cases, Executed, Pass Rate %, Last Sync)
   - 2x2 grid of charts using LiveChartsCore CartesianChart and PieChart
   - Refresh button
   - Clean, professional styling

Use LiveChartsCore.SkiaSharpView.WPF controls (CartesianChart, PieChart).
Use ISeries, PieSeries<T>, ColumnSeries<T>, LineSeries<T>.

Run dotnet build and fix any errors.
```

**Commit:** `git commit -m "feat: dashboard with coverage and trend charts"`

---

## PROMPT 15: Test Run Manager

```
Create UI/Views/TestRunView.xaml (UserControl) and its ViewModel:

1. TestRunViewModel:
   - Create new test run (name, environment, build version)
   - Select test cases to include (from browser or by module/priority filter)
   - Execute: mark each case as Pass/Fail/Blocked/Skipped with notes
   - Track defect IDs for failed cases
   - Complete run with summary
   - View history of past runs with results

2. TestRunView.xaml:
   - Split view: left panel lists runs, right panel shows execution details
   - New Run button → dialog to name it and select test cases
   - Execution view: DataGrid with Pass/Fail/Blocked/Skip buttons per row
   - Notes column for each execution
   - Progress bar showing completion
   - Summary panel when run is complete

Run dotnet build and fix any errors.
```

**Commit:** `git commit -m "feat: test run manager with execution tracking"`

---

## PROMPT 16: Settings + Final Polish

```
Create a Settings dialog and polish the app:

1. UI/Views/SettingsDialog.xaml:
   - SharePoint Site URL text field
   - Document Library name
   - Sync interval (minutes)
   - Auto-sync toggle
   - "Test Connection" button that tries to reach the SharePoint API
   - Save/Cancel buttons
   - Display current security status (DB encrypted ✓, secrets protected ✓, etc.)

2. Wire up navigation in MainWindow:
   - TabControl or sidebar for Dashboard / Test Cases / Test Runs views
   - Sync button in toolbar that triggers manual SharePoint sync
   - Sync progress indicator

3. Add app icon and window title "TestVault 🛡️"

4. Handle all edge cases:
   - No internet → show cached data with "offline" indicator
   - Session expired mid-sync → show login panel
   - Corrupt Excel file → skip with error in audit log
   - Empty SharePoint library → helpful message

Run dotnet build and fix all errors. Make sure the app launches with dotnet run.
```

**Commit:** `git commit -m "feat: settings dialog and navigation polish"`

---

## DONE! 🎉

After all prompts, tag your first release:

```bash
git tag v0.1.0
git log --oneline
```

Your commit history should look like:

```
feat: settings dialog and navigation polish
feat: test run manager with execution tracking
feat: dashboard with coverage and trend charts
feat: test case browser with filtering and search
feat: main window with WebView2 SSO login flow
feat: app bootstrapper with secure startup sequence
feat: secure Excel parser with auto column detection
feat: SharePoint client with cookie harvesting
feat: startup integrity checker
feat: SQLCipher encrypted database context
feat: data models for test management
feat: secure temp directory with auto-wipe
feat: PII-scrubbing secure logger
feat: memory protection utilities
feat: network guard with domain whitelist firewall
feat: DPAPI secret store with secure file deletion
chore: initial WPF project with NuGet packages
```
