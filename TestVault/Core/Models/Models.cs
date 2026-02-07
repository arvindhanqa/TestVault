#nullable enable

using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TestVault.Core.Models
{
    [Microsoft.EntityFrameworkCore.Index(nameof(Module))]
    [Microsoft.EntityFrameworkCore.Index(nameof(Priority))]
    [Microsoft.EntityFrameworkCore.Index(nameof(Status))]
    public class TestCase
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(500)]
        public string Title { get; set; } = string.Empty;

        public string? Description { get; set; }

        [MaxLength(200)]
        public string? Module { get; set; }

        public string? Priority { get; set; }

        public string? Status { get; set; }

        public string? Preconditions { get; set; }

        public string? Steps { get; set; }

        public string? ExpectedResult { get; set; }

        public string? Assignee { get; set; }

        public string? Tags { get; set; }

        public string? RequirementId { get; set; }

        public int ExcelSourceId { get; set; }

        public int ExcelRowNumber { get; set; }

        public DateTime ImportedAt { get; set; }

        public DateTime LastSyncedAt { get; set; }

        public string? FileHash { get; set; }
    }

    public class TestRun
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(200)]
        public string Name { get; set; } = string.Empty;

        public string? Description { get; set; }

        public string? Environment { get; set; }

        public string? BuildVersion { get; set; }

        public DateTime CreatedAt { get; set; }

        public DateTime? CompletedAt { get; set; }

        public string? CreatedBy { get; set; }
    }

    public class TestExecution
    {
        [Key]
        public int Id { get; set; }

        public int TestCaseId { get; set; }

        [ForeignKey(nameof(TestCaseId))]
        public TestCase TestCase { get; set; } = null!;

        public int TestRunId { get; set; }

        [ForeignKey(nameof(TestRunId))]
        public TestRun TestRun { get; set; } = null!;

        [Required]
        public string Result { get; set; } = string.Empty;

        public string? Notes { get; set; }

        public string? DefectId { get; set; }

        public DateTime ExecutedAt { get; set; }

        public string? ExecutedBy { get; set; }

        public int? DurationSeconds { get; set; }
    }

    public class ExcelSource
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string FileName { get; set; } = string.Empty;

        [Required]
        [MaxLength(1000)]
        public string SharePointPath { get; set; } = string.Empty;

        [Required]
        [MaxLength(64)]
        public string FileHash { get; set; } = string.Empty;

        public long FileSize { get; set; }

        public DateTime? LastModifiedOnServer { get; set; }

        public DateTime LastSyncedAt { get; set; }

        public int TotalTestCases { get; set; }
    }

    [Microsoft.EntityFrameworkCore.Index(nameof(Timestamp))]
    public class AuditEntry
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Action { get; set; } = string.Empty;

        public string? Details { get; set; }

        public DateTime Timestamp { get; set; }

        [Required]
        public string WindowsUser { get; set; } = string.Empty;
    }

    public class SyncMetadata
    {
        [Key]
        public int Id { get; set; }

        public DateTime? LastFullSync { get; set; }

        public DateTime? LastIncrementalSync { get; set; }

        public int FilesTracked { get; set; }

        public int TotalTestCases { get; set; }
    }
}
