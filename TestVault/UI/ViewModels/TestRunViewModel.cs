#nullable enable

using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.EntityFrameworkCore;
using TestVault.Core.Data;
using TestVault.Core.Models;

namespace TestVault.UI.ViewModels;

public partial class TestRunViewModel : ObservableObject
{
    private readonly TestVaultDbContext _db;

    [ObservableProperty]
    private ObservableCollection<TestRun> _testRuns = new();

    [ObservableProperty]
    private TestRun? _selectedRun;

    [ObservableProperty]
    private ObservableCollection<TestExecution> _executions = new();

    [ObservableProperty]
    private string _newRunName = string.Empty;

    [ObservableProperty]
    private string _newRunEnvironment = string.Empty;

    [ObservableProperty]
    private string _newRunBuildVersion = string.Empty;

    [ObservableProperty]
    private string _summaryText = string.Empty;

    [ObservableProperty]
    private double _completionProgress;

    [ObservableProperty]
    private bool _isCreatingRun;

    [ObservableProperty]
    private ObservableCollection<TestCase> _availableTestCases = new();

    [ObservableProperty]
    private ObservableCollection<TestCase> _selectedTestCases = new();

    public TestRunViewModel(TestVaultDbContext db)
    {
        _db = db;
        _ = LoadRunsAsync();
    }

    [RelayCommand]
    private async Task LoadRunsAsync()
    {
        var runs = await _db.TestRuns
            .OrderByDescending(r => r.CreatedAt)
            .ToListAsync();
        TestRuns = new ObservableCollection<TestRun>(runs);
    }

    [RelayCommand]
    private void StartCreateRun()
    {
        IsCreatingRun = true;
        NewRunName = $"Test Run {DateTime.Now:yyyy-MM-dd HH:mm}";
        NewRunEnvironment = string.Empty;
        NewRunBuildVersion = string.Empty;
        _ = LoadAvailableTestCasesAsync();
    }

    private async Task LoadAvailableTestCasesAsync()
    {
        var cases = await _db.TestCases.OrderBy(tc => tc.Module).ThenBy(tc => tc.Title).ToListAsync();
        AvailableTestCases = new ObservableCollection<TestCase>(cases);
        SelectedTestCases = new ObservableCollection<TestCase>();
    }

    [RelayCommand]
    private async Task CreateRunAsync()
    {
        if (string.IsNullOrWhiteSpace(NewRunName)) return;

        var run = new TestRun
        {
            Name = NewRunName,
            Environment = NewRunEnvironment,
            BuildVersion = NewRunBuildVersion,
            CreatedAt = DateTime.UtcNow,
            CreatedBy = System.Environment.UserName
        };

        _db.TestRuns.Add(run);
        await _db.SaveChangesAsync();

        // Create executions for selected test cases
        var casesToAdd = SelectedTestCases.Any() ? SelectedTestCases : AvailableTestCases;
        foreach (var tc in casesToAdd)
        {
            _db.TestExecutions.Add(new TestExecution
            {
                TestCaseId = tc.Id,
                TestRunId = run.Id,
                Result = "Skipped",
                ExecutedAt = DateTime.UtcNow,
                ExecutedBy = System.Environment.UserName
            });
        }

        await _db.SaveChangesAsync();
        await _db.AuditAsync("TEST_RUN_CREATED", $"Run: {run.Name}, Cases: {casesToAdd.Count()}");

        IsCreatingRun = false;
        await LoadRunsAsync();
        SelectedRun = TestRuns.FirstOrDefault(r => r.Id == run.Id);
    }

    [RelayCommand]
    private void CancelCreateRun()
    {
        IsCreatingRun = false;
    }

    [RelayCommand]
    private async Task MarkResultAsync(string parameter)
    {
        // parameter format: "executionId:result"
        var parts = parameter.Split(':');
        if (parts.Length != 2) return;
        if (!int.TryParse(parts[0], out var executionId)) return;
        var result = parts[1];

        var execution = await _db.TestExecutions.FindAsync(executionId);
        if (execution == null) return;

        execution.Result = result;
        execution.ExecutedAt = DateTime.UtcNow;
        execution.ExecutedBy = System.Environment.UserName;
        await _db.SaveChangesAsync();

        // Reload executions
        if (SelectedRun != null)
            await LoadExecutionsAsync();
    }

    [RelayCommand]
    private async Task CompleteRunAsync()
    {
        if (SelectedRun == null) return;

        SelectedRun.CompletedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        await _db.AuditAsync("TEST_RUN_COMPLETED", $"Run: {SelectedRun.Name}");
        await LoadRunsAsync();
    }

    private async Task LoadExecutionsAsync()
    {
        if (SelectedRun == null)
        {
            Executions = new ObservableCollection<TestExecution>();
            SummaryText = string.Empty;
            CompletionProgress = 0;
            return;
        }

        var execs = await _db.TestExecutions
            .Include(e => e.TestCase)
            .Where(e => e.TestRunId == SelectedRun.Id)
            .OrderBy(e => e.TestCase!.Module)
            .ThenBy(e => e.TestCase!.Title)
            .ToListAsync();

        Executions = new ObservableCollection<TestExecution>(execs);

        var total = execs.Count;
        var completed = execs.Count(e => e.Result != "Skipped");
        var passed = execs.Count(e => e.Result == "Pass");
        var failed = execs.Count(e => e.Result == "Fail");
        var blocked = execs.Count(e => e.Result == "Blocked");

        CompletionProgress = total > 0 ? (double)completed / total * 100 : 0;
        SummaryText = $"Total: {total} | Pass: {passed} | Fail: {failed} | Blocked: {blocked} | Remaining: {total - completed}";
    }

    partial void OnSelectedRunChanged(TestRun? value) => _ = LoadExecutionsAsync();
}
