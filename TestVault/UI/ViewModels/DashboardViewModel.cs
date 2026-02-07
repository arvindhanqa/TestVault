#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using Microsoft.EntityFrameworkCore;
using SkiaSharp;
using TestVault.Core.Data;

namespace TestVault.UI.ViewModels;

/// <summary>
/// ViewModel for the Dashboard view. Provides summary statistics and chart data
/// sourced from the local encrypted TestVault database.
/// </summary>
public partial class DashboardViewModel : ObservableObject
{
    private readonly TestVaultDbContext _db;

    // ─── Chart series ────────────────────────────────────────────────────

    [ObservableProperty]
    private ISeries[] _moduleSeries = Array.Empty<ISeries>();

    [ObservableProperty]
    private ISeries[] _prioritySeries = Array.Empty<ISeries>();

    [ObservableProperty]
    private ISeries[] _statusSeries = Array.Empty<ISeries>();

    [ObservableProperty]
    private ISeries[] _trendSeries = Array.Empty<ISeries>();

    // ─── Axes ────────────────────────────────────────────────────────────

    [ObservableProperty]
    private Axis[] _xAxes = new[] { new Axis { Name = "Date" } };

    [ObservableProperty]
    private Axis[] _yAxes = new[] { new Axis { Name = "Executions" } };

    // ─── Summary properties ──────────────────────────────────────────────

    [ObservableProperty]
    private int _totalCases;

    [ObservableProperty]
    private int _executedCases;

    [ObservableProperty]
    private double _passRate;

    [ObservableProperty]
    private string _lastSyncTime = "Never";

    // ─── Constructor ─────────────────────────────────────────────────────

    public DashboardViewModel(TestVaultDbContext db)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
    }

    // ─── Commands ────────────────────────────────────────────────────────

    [RelayCommand]
    private async Task RefreshAsync()
    {
        await LoadStatsAsync();
    }

    // ─── Private helpers ─────────────────────────────────────────────────

    private async Task LoadStatsAsync()
    {
        // ── Summary stats ────────────────────────────────────────────

        TotalCases = await _db.TestCases.CountAsync();

        var executedCaseIds = await _db.TestExecutions
            .Select(e => e.TestCaseId)
            .Distinct()
            .CountAsync();
        ExecutedCases = executedCaseIds;

        var totalExecutions = await _db.TestExecutions.CountAsync();
        var passedExecutions = await _db.TestExecutions
            .CountAsync(e => e.Result == "Pass" || e.Result == "Passed");

        PassRate = totalExecutions > 0
            ? Math.Round((double)passedExecutions / totalExecutions * 100.0, 1)
            : 0.0;

        var syncMeta = await _db.SyncMetadata.FirstOrDefaultAsync();
        if (syncMeta?.LastFullSync is not null)
        {
            LastSyncTime = syncMeta.LastFullSync.Value.ToLocalTime().ToString("g");
        }
        else
        {
            LastSyncTime = "Never";
        }

        // ── Module bar chart ─────────────────────────────────────────

        var moduleCounts = await _db.TestCases
            .GroupBy(tc => tc.Module ?? "(No Module)")
            .Select(g => new { Module = g.Key, Count = g.Count() })
            .OrderByDescending(x => x.Count)
            .Take(10)
            .ToListAsync();

        ModuleSeries = new ISeries[]
        {
            new ColumnSeries<double>
            {
                Name = "Test Cases",
                Values = moduleCounts.Select(m => (double)m.Count).ToArray(),
                Fill = new SolidColorPaint(SKColors.SteelBlue)
            }
        };

        XAxes = new Axis[]
        {
            new Axis
            {
                Name = "Module",
                Labels = moduleCounts.Select(m => m.Module).ToArray(),
                LabelsRotation = 30
            }
        };

        YAxes = new Axis[]
        {
            new Axis { Name = "Count", MinLimit = 0 }
        };

        // ── Priority pie chart ───────────────────────────────────────

        var priorityCounts = await _db.TestCases
            .GroupBy(tc => tc.Priority ?? "(Unset)")
            .Select(g => new { Priority = g.Key, Count = g.Count() })
            .ToListAsync();

        var priorityColors = new Dictionary<string, SKColor>(StringComparer.OrdinalIgnoreCase)
        {
            ["Critical"] = SKColors.Red,
            ["High"] = SKColors.OrangeRed,
            ["Medium"] = SKColors.Gold,
            ["Low"] = SKColors.LimeGreen,
            ["(Unset)"] = SKColors.Gray
        };

        PrioritySeries = priorityCounts.Select(p =>
        {
            var color = priorityColors.GetValueOrDefault(p.Priority, SKColors.SlateGray);
            return (ISeries)new PieSeries<double>
            {
                Name = p.Priority,
                Values = new[] { (double)p.Count },
                Fill = new SolidColorPaint(color)
            };
        }).ToArray();

        // ── Status pie chart ─────────────────────────────────────────

        var statusCounts = await _db.TestCases
            .GroupBy(tc => tc.Status ?? "(Unset)")
            .Select(g => new { Status = g.Key, Count = g.Count() })
            .ToListAsync();

        var statusColors = new Dictionary<string, SKColor>(StringComparer.OrdinalIgnoreCase)
        {
            ["Active"] = SKColors.DodgerBlue,
            ["Draft"] = SKColors.LightGray,
            ["Approved"] = SKColors.MediumSeaGreen,
            ["Deprecated"] = SKColors.IndianRed,
            ["(Unset)"] = SKColors.Gray
        };

        StatusSeries = statusCounts.Select(s =>
        {
            var color = statusColors.GetValueOrDefault(s.Status, SKColors.SlateGray);
            return (ISeries)new PieSeries<double>
            {
                Name = s.Status,
                Values = new[] { (double)s.Count },
                Fill = new SolidColorPaint(color)
            };
        }).ToArray();

        // ── Trend line chart (executions per day, last 30 days) ──────

        var since = DateTime.UtcNow.AddDays(-30);

        var dailyExecutions = await _db.TestExecutions
            .Where(e => e.ExecutedAt >= since)
            .GroupBy(e => e.ExecutedAt.Date)
            .Select(g => new { Date = g.Key, Count = g.Count() })
            .OrderBy(x => x.Date)
            .ToListAsync();

        // Fill in missing days with zero so the line is continuous.
        var filled = new List<double>();
        var labels = new List<string>();
        var current = since.Date;
        var today = DateTime.UtcNow.Date;

        while (current <= today)
        {
            var match = dailyExecutions.FirstOrDefault(d => d.Date == current);
            filled.Add(match?.Count ?? 0);
            labels.Add(current.ToString("MM/dd"));
            current = current.AddDays(1);
        }

        TrendSeries = new ISeries[]
        {
            new LineSeries<double>
            {
                Name = "Executions",
                Values = filled.ToArray(),
                Fill = new SolidColorPaint(SKColors.DodgerBlue.WithAlpha(40)),
                Stroke = new SolidColorPaint(SKColors.DodgerBlue) { StrokeThickness = 2 },
                GeometrySize = 4
            }
        };
    }
}
