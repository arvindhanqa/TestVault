#nullable enable

using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using LiveChartsCore.SkiaSharpView.WPF;
using TestVault.UI.ViewModels;

namespace TestVault.UI.Views
{
    public partial class DashboardView : UserControl
    {
        public DashboardView()
        {
            InitializeComponent();
            Loaded += DashboardView_Loaded;
        }

        private void DashboardView_Loaded(object sender, RoutedEventArgs e)
        {
            // Create LiveCharts controls in code-behind to avoid XAML assembly resolution issues
            var moduleChart = new CartesianChart();
            moduleChart.SetBinding(CartesianChart.SeriesProperty, new Binding("ModuleSeries"));
            moduleChart.SetBinding(CartesianChart.XAxesProperty, new Binding("XAxes"));
            moduleChart.SetBinding(CartesianChart.YAxesProperty, new Binding("YAxes"));
            ModuleChartHost.Content = moduleChart;

            var priorityChart = new PieChart();
            priorityChart.SetBinding(PieChart.SeriesProperty, new Binding("PrioritySeries"));
            PriorityChartHost.Content = priorityChart;

            var statusChart = new PieChart();
            statusChart.SetBinding(PieChart.SeriesProperty, new Binding("StatusSeries"));
            StatusChartHost.Content = statusChart;

            var trendChart = new CartesianChart();
            trendChart.SetBinding(CartesianChart.SeriesProperty, new Binding("TrendSeries"));
            TrendChartHost.Content = trendChart;

            // Trigger initial load
            if (DataContext is DashboardViewModel vm)
            {
                vm.RefreshCommand.Execute(null);
            }
        }
    }
}
