using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace ProcessWatchdog
{
    public partial class MainWindow : Window
    {
        private DispatcherTimer timer;
        [DllImport("ntdll.dll")]
        private static extern int NtSetInformationProcess(IntPtr h, int c, ref int i, int l);

        public MainWindow()
        {
            InitializeComponent();
            timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            timer.Tick += (s, e) => UpdateList();
            timer.Start();
            UpdateList();
        }

        private void UpdateList()
        {
            var items = new List<ProcessInfo>();
            foreach (var p in Process.GetProcesses())
            {
                string status = "ОК";
                Brush color = Brushes.LightGreen;
                string path = "Защищено";
                try { 
                    path = p.MainModule.FileName; 
                    // Проверка на вирусы-маскировщики
                    if ((p.ProcessName.ToLower() == "svchost" || p.ProcessName.ToLower() == "lsass") && !path.ToLower().Contains("system32")) {
                        status = "ВНИМАНИЕ: ФЕЙК!"; color = Brushes.Red;
                    }
                } catch { }
                items.Add(new ProcessInfo { Id = p.Id, Name = p.ProcessName, Path = path, Status = status, StatusColor = color });
            }
            ProcessList.ItemsSource = items.OrderBy(x => x.Name).ToList();
        }

        private void BtnDisableCritical_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessList.SelectedItem is ProcessInfo selected) {
                try {
                    int disabled = 0;
                    NtSetInformationProcess(Process.GetProcessById(selected.Id).Handle, 29, ref disabled, sizeof(int));
                    MessageBox.Show("Защита снята!");
                } catch { MessageBox.Show("Нужны права админа!"); }
            }
        }

        private void BtnKill_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessList.SelectedItem is ProcessInfo selected)
                try { Process.GetProcessById(selected.Id).Kill(); } catch { }
        }
    }

    public class ProcessInfo
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public string Status { get; set; }
        public Brush StatusColor { get; set; }
    }
}