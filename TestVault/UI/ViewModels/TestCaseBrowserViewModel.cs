#nullable enable

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.EntityFrameworkCore;
using OfficeOpenXml;
using TestVault.Core.Data;
using TestVault.Core.Models;

namespace TestVault.UI.ViewModels;

public partial class TestCaseBrowserViewModel : ObservableObject
{
    private readonly TestVaultDbContext _db;

    [ObservableProperty]
    private ObservableCollection<TestCase> _testCases = new();

    [ObservableProperty]
    private string _searchText = string.Empty;

    [ObservableProperty]
    private string? _selectedModule;

    [ObservableProperty]
    private string? _selectedPriority;

    [ObservableProperty]
    private string? _selectedStatus;

    [ObservableProperty]
    private ObservableCollection<string> _modules = new();

    [ObservableProperty]
    private ObservableCollection<string> _priorities = new();

    [ObservableProperty]
    private ObservableCollection<string> _statuses = new();

    [ObservableProperty]
    private string _summaryText = "0 of 0 test cases";

    [ObservableProperty]
    private int _currentPage = 1;

    [ObservableProperty]
    private int _totalPages = 1;

    private int _totalCount;
    private const int PageSize = 50;

    public TestCaseBrowserViewModel(TestVaultDbContext db)
    {
        _db = db;
        _ = LoadTestCasesAsync();
    }

    [RelayCommand]
    private async Task LoadTestCasesAsync()
    {
        var query = _db.TestCases.AsQueryable();

        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var search = SearchText.Trim().ToLower();
            query = query.Where(tc =>
                (tc.Title != null && tc.Title.ToLower().Contains(search)) ||
                (tc.Module != null && tc.Module.ToLower().Contains(search)) ||
                (tc.Description != null && tc.Description.ToLower().Contains(search)) ||
                (tc.Tags != null && tc.Tags.ToLower().Contains(search)));
        }

        if (!string.IsNullOrWhiteSpace(SelectedModule))
            query = query.Where(tc => tc.Module == SelectedModule);

        if (!string.IsNullOrWhiteSpace(SelectedPriority))
            query = query.Where(tc => tc.Priority == SelectedPriority);

        if (!string.IsNullOrWhiteSpace(SelectedStatus))
            query = query.Where(tc => tc.Status == SelectedStatus);

        _totalCount = await query.CountAsync();
        TotalPages = Math.Max(1, (int)Math.Ceiling(_totalCount / (double)PageSize));
        CurrentPage = Math.Clamp(CurrentPage, 1, TotalPages);

        var items = await query
            .OrderBy(tc => tc.Id)
            .Skip((CurrentPage - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync();

        TestCases = new ObservableCollection<TestCase>(items);
        SummaryText = $"{TestCases.Count} of {_totalCount} test cases (Page {CurrentPage}/{TotalPages})";

        // Load filter options
        Modules = new ObservableCollection<string>(
            await _db.TestCases.Where(tc => tc.Module != null).Select(tc => tc.Module!).Distinct().OrderBy(m => m).ToListAsync());
        Priorities = new ObservableCollection<string>(
            await _db.TestCases.Where(tc => tc.Priority != null).Select(tc => tc.Priority!).Distinct().OrderBy(p => p).ToListAsync());
        Statuses = new ObservableCollection<string>(
            await _db.TestCases.Where(tc => tc.Status != null).Select(tc => tc.Status!).Distinct().OrderBy(s => s).ToListAsync());
    }

    [RelayCommand]
    private async Task NextPageAsync()
    {
        if (CurrentPage < TotalPages)
        {
            CurrentPage++;
            await LoadTestCasesAsync();
        }
    }

    [RelayCommand]
    private async Task PreviousPageAsync()
    {
        if (CurrentPage > 1)
        {
            CurrentPage--;
            await LoadTestCasesAsync();
        }
    }

    [RelayCommand]
    private async Task ClearFiltersAsync()
    {
        SearchText = string.Empty;
        SelectedModule = null;
        SelectedPriority = null;
        SelectedStatus = null;
        CurrentPage = 1;
        await LoadTestCasesAsync();
    }

    [RelayCommand]
    private async Task ExportToExcelAsync()
    {
        ExcelPackage.LicenseContext = LicenseContext.NonCommercial;

        var query = _db.TestCases.AsQueryable();
        if (!string.IsNullOrWhiteSpace(SelectedModule))
            query = query.Where(tc => tc.Module == SelectedModule);
        if (!string.IsNullOrWhiteSpace(SelectedPriority))
            query = query.Where(tc => tc.Priority == SelectedPriority);
        if (!string.IsNullOrWhiteSpace(SelectedStatus))
            query = query.Where(tc => tc.Status == SelectedStatus);

        var items = await query.ToListAsync();

        using var package = new ExcelPackage();
        var ws = package.Workbook.Worksheets.Add("Test Cases");

        // Headers
        ws.Cells[1, 1].Value = "ID";
        ws.Cells[1, 2].Value = "Title";
        ws.Cells[1, 3].Value = "Module";
        ws.Cells[1, 4].Value = "Priority";
        ws.Cells[1, 5].Value = "Status";
        ws.Cells[1, 6].Value = "Assignee";
        ws.Cells[1, 7].Value = "Description";
        ws.Cells[1, 8].Value = "Steps";
        ws.Cells[1, 9].Value = "Expected Result";
        ws.Cells[1, 10].Value = "Tags";
        ws.Cells[1, 11].Value = "Requirement";

        for (int i = 0; i < items.Count; i++)
        {
            var tc = items[i];
            ws.Cells[i + 2, 1].Value = tc.Id;
            ws.Cells[i + 2, 2].Value = tc.Title;
            ws.Cells[i + 2, 3].Value = tc.Module;
            ws.Cells[i + 2, 4].Value = tc.Priority;
            ws.Cells[i + 2, 5].Value = tc.Status;
            ws.Cells[i + 2, 6].Value = tc.Assignee;
            ws.Cells[i + 2, 7].Value = tc.Description;
            ws.Cells[i + 2, 8].Value = tc.Steps;
            ws.Cells[i + 2, 9].Value = tc.ExpectedResult;
            ws.Cells[i + 2, 10].Value = tc.Tags;
            ws.Cells[i + 2, 11].Value = tc.RequirementId;
        }

        var exportPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            $"TestVault_Export_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx");
        await package.SaveAsAsync(new FileInfo(exportPath));
    }

    partial void OnSearchTextChanged(string value) => _ = LoadTestCasesAsync();
    partial void OnSelectedModuleChanged(string? value) => _ = LoadTestCasesAsync();
    partial void OnSelectedPriorityChanged(string? value) => _ = LoadTestCasesAsync();
    partial void OnSelectedStatusChanged(string? value) => _ = LoadTestCasesAsync();
}
