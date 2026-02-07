#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using OfficeOpenXml;
using Serilog;
using TestVault.Core.Data;
using TestVault.Core.Models;
using TestVault.Core.Security;

namespace TestVault.Core.Services;

/// <summary>
/// Secure in-memory Excel parser that imports test cases from .xlsx files into the database.
/// Performs TOCTOU hash verification, auto-detects column mappings, upserts test cases,
/// and batches database writes for performance.
/// </summary>
public sealed class SecureExcelParser
{
    private const int MaxRowsPerFile = 50_000;
    private const int MaxCellLength = 10_000;
    private const int BatchSize = 100;

    private static bool _licenseContextSet;
    private static readonly object _licenseContextLock = new();

    private readonly TestVaultDbContext _db;

    /// <summary>
    /// Raised to report progress messages during parsing and import.
    /// </summary>
    public event Action<string>? OnProgress;

    public SecureExcelParser(TestVaultDbContext db)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));

        lock (_licenseContextLock)
        {
            if (!_licenseContextSet)
            {
                ExcelPackage.LicenseContext = LicenseContext.NonCommercial;
                _licenseContextSet = true;
                Log.Debug("EPPlus LicenseContext set to NonCommercial");
            }
        }
    }

    /// <summary>
    /// Parses and imports test cases from the specified Excel file into the database.
    /// Verifies the file hash before processing to detect TOCTOU tampering.
    /// </summary>
    /// <param name="filePath">Absolute path to the Excel file on disk.</param>
    /// <param name="sharePointPath">The SharePoint server-relative path for this file.</param>
    /// <param name="fileHash">The expected SHA-256 hash of the file (lowercase hex).</param>
    /// <returns>A <see cref="ParseResult"/> describing the outcome of the import.</returns>
    public async Task<ParseResult> ParseAndImportAsync(string filePath, string sharePointPath, string fileHash)
    {
        ArgumentNullException.ThrowIfNull(filePath);
        ArgumentNullException.ThrowIfNull(sharePointPath);
        ArgumentNullException.ThrowIfNull(fileHash);

        string fileName = Path.GetFileName(filePath);

        try
        {
            // ── TOCTOU hash verification ────────────────────────────────
            ReportProgress($"Verifying file integrity: {fileName}");
            string currentHash = await SecureTempDirectory.ComputeFileHashAsync(filePath).ConfigureAwait(false);

            if (!string.Equals(currentHash, fileHash, StringComparison.OrdinalIgnoreCase))
            {
                string message = $"File hash mismatch (TOCTOU detected). Expected: {fileHash}, Actual: {currentHash}";
                Log.Warning("TOCTOU hash mismatch for {FileName}. Expected {Expected}, got {Actual}",
                    fileName, fileHash, currentHash);
                await _db.AuditAsync("IMPORT_HASH_MISMATCH", $"File: {fileName}, Expected: {fileHash}, Actual: {currentHash}")
                    .ConfigureAwait(false);
                return new ParseResult(fileName, Success: false, 0, 0, 0, Error: message);
            }

            // ── Get or create ExcelSource ───────────────────────────────
            ExcelSource source = await GetOrCreateExcelSourceAsync(fileName, sharePointPath, fileHash, filePath)
                .ConfigureAwait(false);

            // ── Open workbook with EPPlus ────────────────────────────────
            ReportProgress($"Opening workbook: {fileName}");
            var fileInfo = new FileInfo(filePath);

            using var package = new ExcelPackage(fileInfo);

            int totalParsed = 0;
            int totalUpdated = 0;
            int totalSkipped = 0;

            foreach (var worksheet in package.Workbook.Worksheets)
            {
                if (worksheet.Dimension == null)
                {
                    Log.Debug("Skipping empty worksheet: {WorksheetName}", worksheet.Name);
                    ReportProgress($"Skipping empty worksheet: {worksheet.Name}");
                    continue;
                }

                ReportProgress($"Processing worksheet: {worksheet.Name}");

                // ── Auto-detect column mapping from header row ──────────
                var columnMap = DetectColumnMapping(worksheet);

                if (columnMap.TitleColumn < 0)
                {
                    Log.Warning("No title/name column found in worksheet {WorksheetName}; skipping",
                        worksheet.Name);
                    ReportProgress($"No title column found in worksheet '{worksheet.Name}'; skipping");
                    continue;
                }

                int startRow = 2; // Data starts after header row
                int endRow = Math.Min(worksheet.Dimension.End.Row, MaxRowsPerFile + 1);
                int pendingChanges = 0;

                for (int row = startRow; row <= endRow; row++)
                {
                    string? title = SafeGetCellValue(worksheet, row, columnMap.TitleColumn);

                    if (string.IsNullOrWhiteSpace(title))
                    {
                        totalSkipped++;
                        continue;
                    }

                    // ── Upsert: match by ExcelSourceId + ExcelRowNumber ─
                    var existingCase = await _db.TestCases
                        .FirstOrDefaultAsync(tc => tc.ExcelSourceId == source.Id && tc.ExcelRowNumber == row)
                        .ConfigureAwait(false);

                    bool isUpdate = existingCase != null;
                    var testCase = existingCase ?? new TestCase();

                    testCase.Title = Truncate(title, 500);
                    testCase.Description = SafeGetCellValue(worksheet, row, columnMap.DescriptionColumn);
                    testCase.Module = Truncate(SafeGetCellValue(worksheet, row, columnMap.ModuleColumn), 200);
                    testCase.Priority = SafeGetCellValue(worksheet, row, columnMap.PriorityColumn);
                    testCase.Status = SafeGetCellValue(worksheet, row, columnMap.StatusColumn);
                    testCase.Preconditions = SafeGetCellValue(worksheet, row, columnMap.PreconditionsColumn);
                    testCase.Steps = SafeGetCellValue(worksheet, row, columnMap.StepsColumn);
                    testCase.ExpectedResult = SafeGetCellValue(worksheet, row, columnMap.ExpectedResultColumn);
                    testCase.Assignee = SafeGetCellValue(worksheet, row, columnMap.AssigneeColumn);
                    testCase.Tags = SafeGetCellValue(worksheet, row, columnMap.TagsColumn);
                    testCase.RequirementId = SafeGetCellValue(worksheet, row, columnMap.RequirementIdColumn);
                    testCase.ExcelSourceId = source.Id;
                    testCase.ExcelRowNumber = row;
                    testCase.LastSyncedAt = DateTime.UtcNow;
                    testCase.FileHash = fileHash;

                    if (isUpdate)
                    {
                        totalUpdated++;
                    }
                    else
                    {
                        testCase.ImportedAt = DateTime.UtcNow;
                        _db.TestCases.Add(testCase);
                    }

                    totalParsed++;
                    pendingChanges++;

                    // ── Batch SaveChanges every BatchSize rows ───────────
                    if (pendingChanges >= BatchSize)
                    {
                        await _db.SaveChangesAsync().ConfigureAwait(false);
                        pendingChanges = 0;
                        ReportProgress($"Processed {totalParsed} rows from worksheet '{worksheet.Name}'...");
                    }
                }

                // Save any remaining changes for this worksheet
                if (pendingChanges > 0)
                {
                    await _db.SaveChangesAsync().ConfigureAwait(false);
                }

                ReportProgress($"Completed worksheet '{worksheet.Name}': {totalParsed} parsed, {totalUpdated} updated, {totalSkipped} skipped");
            }

            // ── Update ExcelSource totals ────────────────────────────────
            source.TotalTestCases = totalParsed;
            source.LastSyncedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync().ConfigureAwait(false);

            // ── Audit the import ─────────────────────────────────────────
            await _db.AuditAsync("EXCEL_IMPORT",
                $"File: {fileName}, Parsed: {totalParsed}, Updated: {totalUpdated}, Skipped: {totalSkipped}")
                .ConfigureAwait(false);

            Log.Information(
                "Excel import complete for {FileName}. Parsed: {Parsed}, Updated: {Updated}, Skipped: {Skipped}",
                fileName, totalParsed, totalUpdated, totalSkipped);

            ReportProgress($"Import complete: {totalParsed} test cases parsed, {totalUpdated} updated, {totalSkipped} rows skipped");

            return new ParseResult(fileName, Success: true, totalParsed, totalUpdated, totalSkipped, Error: null);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to parse and import Excel file: {FileName}", fileName);
            ReportProgress($"Error importing {fileName}: {ex.Message}");

            await _db.AuditAsync("EXCEL_IMPORT_ERROR", $"File: {fileName}, Error: {ex.Message}")
                .ConfigureAwait(false);

            return new ParseResult(fileName, Success: false, 0, 0, 0, Error: ex.Message);
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    private async Task<ExcelSource> GetOrCreateExcelSourceAsync(
        string fileName, string sharePointPath, string fileHash, string filePath)
    {
        var source = await _db.ExcelSources
            .FirstOrDefaultAsync(s => s.SharePointPath == sharePointPath)
            .ConfigureAwait(false);

        if (source == null)
        {
            source = new ExcelSource
            {
                FileName = fileName,
                SharePointPath = sharePointPath,
                FileHash = fileHash,
                FileSize = new FileInfo(filePath).Length,
                LastSyncedAt = DateTime.UtcNow
            };
            _db.ExcelSources.Add(source);
            await _db.SaveChangesAsync().ConfigureAwait(false);
            Log.Information("Created new ExcelSource for {SharePointPath} (Id: {Id})", sharePointPath, source.Id);
        }
        else
        {
            source.FileName = fileName;
            source.FileHash = fileHash;
            source.FileSize = new FileInfo(filePath).Length;
            source.LastSyncedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync().ConfigureAwait(false);
            Log.Debug("Updated existing ExcelSource for {SharePointPath} (Id: {Id})", sharePointPath, source.Id);
        }

        return source;
    }

    /// <summary>
    /// Auto-detects column indices from the header row (row 1) by matching
    /// cell text against known keywords for each test case field.
    /// </summary>
    private static ColumnMapping DetectColumnMapping(ExcelWorksheet worksheet)
    {
        var map = new ColumnMapping();
        int lastCol = worksheet.Dimension?.End.Column ?? 0;

        for (int col = 1; col <= lastCol; col++)
        {
            string? header = worksheet.Cells[1, col].Text?.Trim();
            if (string.IsNullOrWhiteSpace(header))
                continue;

            string headerLower = header.ToLowerInvariant();

            if (map.TitleColumn < 0 && ContainsAny(headerLower, "title", "name", "summary"))
            {
                map.TitleColumn = col;
            }
            else if (map.DescriptionColumn < 0 && ContainsAny(headerLower, "description"))
            {
                map.DescriptionColumn = col;
            }
            else if (map.ModuleColumn < 0 && ContainsAny(headerLower, "module", "area", "component"))
            {
                map.ModuleColumn = col;
            }
            else if (map.PriorityColumn < 0 && ContainsAny(headerLower, "priority", "severity"))
            {
                map.PriorityColumn = col;
            }
            else if (map.StatusColumn < 0 && ContainsAny(headerLower, "status"))
            {
                map.StatusColumn = col;
            }
            else if (map.PreconditionsColumn < 0 && ContainsAny(headerLower, "precondition", "setup"))
            {
                map.PreconditionsColumn = col;
            }
            else if (map.StepsColumn < 0 && ContainsAny(headerLower, "step", "action"))
            {
                map.StepsColumn = col;
            }
            else if (map.ExpectedResultColumn < 0 && ContainsAny(headerLower, "expected", "result"))
            {
                map.ExpectedResultColumn = col;
            }
            else if (map.AssigneeColumn < 0 && ContainsAny(headerLower, "assign", "owner", "tester"))
            {
                map.AssigneeColumn = col;
            }
            else if (map.TagsColumn < 0 && ContainsAny(headerLower, "tag", "label"))
            {
                map.TagsColumn = col;
            }
            else if (map.RequirementIdColumn < 0 && ContainsAny(headerLower, "requirement", "req", "story", "ticket"))
            {
                map.RequirementIdColumn = col;
            }
        }

        Log.Debug(
            "Column mapping detected - Title: {Title}, Description: {Desc}, Module: {Module}, " +
            "Priority: {Priority}, Status: {Status}, Preconditions: {Precond}, Steps: {Steps}, " +
            "Expected: {Expected}, Assignee: {Assignee}, Tags: {Tags}, Requirement: {Req}",
            map.TitleColumn, map.DescriptionColumn, map.ModuleColumn,
            map.PriorityColumn, map.StatusColumn, map.PreconditionsColumn,
            map.StepsColumn, map.ExpectedResultColumn, map.AssigneeColumn,
            map.TagsColumn, map.RequirementIdColumn);

        return map;
    }

    /// <summary>
    /// Safely retrieves a cell value: trims whitespace, truncates to <see cref="MaxCellLength"/> characters,
    /// and strips control characters (preserving newline and tab).
    /// Returns null if the cell is empty or the column index is invalid.
    /// </summary>
    private static string? SafeGetCellValue(ExcelWorksheet worksheet, int row, int column)
    {
        if (column < 0)
            return null;

        string? raw = worksheet.Cells[row, column].Text;
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        string trimmed = raw.Trim();

        // Truncate to max length
        if (trimmed.Length > MaxCellLength)
            trimmed = trimmed[..MaxCellLength];

        // Strip control characters but keep newline (\n, \r) and tab (\t)
        trimmed = StripControlCharacters(trimmed);

        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    /// <summary>
    /// Removes control characters (U+0000..U+001F, U+007F..U+009F) from the input,
    /// except for tab (U+0009), line feed (U+000A), and carriage return (U+000D).
    /// </summary>
    private static string StripControlCharacters(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        return Regex.Replace(input, @"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]", string.Empty);
    }

    private static string? Truncate(string? value, int maxLength)
    {
        if (value == null)
            return null;

        return value.Length <= maxLength ? value : value[..maxLength];
    }

    private static bool ContainsAny(string text, params string[] keywords)
    {
        foreach (string keyword in keywords)
        {
            if (text.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private void ReportProgress(string message)
    {
        OnProgress?.Invoke(message);
        Log.Debug("ExcelParser progress: {Message}", message);
    }

    // ── Inner types ─────────────────────────────────────────────────────────

    /// <summary>
    /// Tracks detected column indices for each test case field.
    /// A value of -1 indicates the column was not found.
    /// </summary>
    private sealed class ColumnMapping
    {
        public int TitleColumn { get; set; } = -1;
        public int DescriptionColumn { get; set; } = -1;
        public int ModuleColumn { get; set; } = -1;
        public int PriorityColumn { get; set; } = -1;
        public int StatusColumn { get; set; } = -1;
        public int PreconditionsColumn { get; set; } = -1;
        public int StepsColumn { get; set; } = -1;
        public int ExpectedResultColumn { get; set; } = -1;
        public int AssigneeColumn { get; set; } = -1;
        public int TagsColumn { get; set; } = -1;
        public int RequirementIdColumn { get; set; } = -1;
    }
}

/// <summary>
/// Describes the outcome of an Excel import operation.
/// </summary>
public sealed record ParseResult(
    string FileName,
    bool Success,
    int TestCasesParsed,
    int TestCasesUpdated,
    int RowsSkipped,
    string? Error
);
