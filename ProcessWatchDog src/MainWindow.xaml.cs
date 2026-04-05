using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Management;
using System.Windows;
using Microsoft.Win32;

namespace ProcessWatchdog
{
    public partial class MainWindow : Window
    {
        public class ProcessInfo
        {
            public string? Name { get; set; }
            public int Id { get; set; }
            public string? Status { get; set; }
            public string? Path { get; set; }
            public string? Color { get; set; }
        }

        public ObservableCollection<ProcessInfo> Processes { get; set; } = new ObservableCollection<ProcessInfo>();
        private List<string> Exclusions = new List<string>();

        public MainWindow()
        {
            InitializeComponent();
            ProcessList.ItemsSource = Processes;
            RefreshProcesses();
        }

        private void RefreshProcesses()
        {
            if (ProcessList == null) return;
            Processes.Clear();
            Process[] allProcesses = Process.GetProcesses();

            foreach (var p in allProcesses)
            {
                try
                {
                    string path = GetProcessPath(p.Id);
                    string pName = p.ProcessName.ToLower();
                    bool isSystemDir = path.ToLower().Contains(@"c:\windows\system32") || path.ToLower().Contains(@"c:\windows\syswow64");

                    if (Exclusions.Contains(path)) {
                        if (HideSystemCb.IsChecked == true) continue;
                        AddProcessToList(p, "EXCLUDED", path, "#888888");
                        continue;
                    }

                    string[] criticals = { "svchost", "lsass", "wininit", "services", "csrss", "smss" };
                    bool isCritical = Array.Exists(criticals, c => c == pName);

                    if (isCritical)
                    {
                        if (HideSystemCb.IsChecked == true && (isSystemDir || path == "System Protected")) continue;

                        if (path == "System Protected" || path == "Unknown" || isSystemDir)
                            AddProcessToList(p, "SYSTEM", path, "#44AAFF");
                        else
                            AddProcessToList(p, "SUSPICIOUS", path, "#FF4444");
                    }
                    else
                    {
                        AddProcessToList(p, "OK", path, "#00FF00");
                    }
                }
                catch { }
            }
        }

        private void AddProcessToList(Process p, string status, string path, string color)
        {
            Processes.Add(new ProcessInfo { Name = p.ProcessName, Id = p.Id, Status = status, Path = path, Color = color });
        }

        private string GetProcessPath(int pid)
        {
            try {
                using (var searcher = new ManagementObjectSearcher("SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " + pid))
                using (var objects = searcher.Get())
                    foreach (ManagementBaseObject obj in objects)
                        return obj["ExecutablePath"]?.ToString() ?? "Unknown";
            }
            catch { return "System Protected"; }
            return "Unknown";
        }

        private void KillProcess_Click(object sender, RoutedEventArgs e)
        {
            var selected = (ProcessInfo)ProcessList.SelectedItem;
            if (selected == null) return;

            try {
                Process.GetProcessById(selected.Id).Kill();
                RefreshProcesses();
            }
            catch (Exception ex) { MessageBox.Show("Ошибка: " + ex.Message); }
        }

        private void AddManualExclusion_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Filter = "Программы (*.exe)|*.exe|Все файлы (*.*)|*.*";
            if (dlg.ShowDialog() == true) {
                Exclusions.Add(dlg.FileName);
                RefreshProcesses();
            }
        }

        private void CheckUpdates_Click(object sender, RoutedEventArgs e)
        {
            string url = "https://github.com/p1shenak/Process-Watchdog/releases"; 
            try {
                Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
            }
            catch { MessageBox.Show("Не удалось открыть браузер. Ссылка: " + url); }
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => RefreshProcesses();
        private void HideSystemCb_Checked(object sender, RoutedEventArgs e) => RefreshProcesses();
        private void HideSystemCb_Unchecked(object sender, RoutedEventArgs e) => RefreshProcesses();
    }
}