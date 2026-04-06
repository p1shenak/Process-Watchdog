using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Management;
using System.Windows;
using Microsoft.Win32;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows.Threading; // Для таймера
using System.Linq;
using System.Runtime.InteropServices; // Для Freeze/Resume

namespace ProcessWatchdog
{
    public partial class MainWindow : Window
    {
        private string CurrentAppVersion = "1.7"; 
        private DispatcherTimer _refreshTimer = new DispatcherTimer();
        private List<ProcessInfo> _fullList = new List<ProcessInfo>();

        // Импорт функций Windows для заморозки процессов
        [DllImport("kernel32.dll")] static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll")] static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr hHandle);

        public class ProcessInfo
        {
            public string Name { get; set; } = "";
            public int Id { get; set; }
            public string Status { get; set; } = "";
            public string Path { get; set; } = "";
            public string Color { get; set; } = "";
        }

        public ObservableCollection<ProcessInfo> Processes { get; set; } = new ObservableCollection<ProcessInfo>();
        private List<string> Exclusions = new List<string>();

        public MainWindow()
        {
            InitializeComponent();
            ProcessList.ItemsSource = Processes;
            
            _refreshTimer.Interval = TimeSpan.FromSeconds(5);
            _refreshTimer.Tick += (s, e) => RefreshProcesses();
            
            RefreshProcesses();
        }

        private void RefreshProcesses()
        {
            _fullList.Clear();
            Process[] allProcesses = Process.GetProcesses();

            foreach (var p in allProcesses)
            {
                try {
                    string path = GetProcessPath(p.Id);
                    string lowPath = path.ToLower();
                    string pName = p.ProcessName.ToLower();
                    bool isSystemDir = lowPath.Contains(@"c:\windows\system32") || lowPath.Contains(@"c:\windows\syswow64");

                    string status = "OK";
                    string color = "#00FF00";

                    if (Exclusions.Contains(path)) {
                        if (HideSystemCb.IsChecked == true) continue;
                        status = "EXCLUDED"; color = "#888888";
                    }
                    else if (new[] { "svchost", "lsass", "wininit", "services", "csrss", "smss" }.Contains(pName)) {
                        if (HideSystemCb.IsChecked == true && (isSystemDir || path == "System Protected")) continue;
                        if (path == "System Protected" || path == "Unknown" || isSystemDir) { status = "SYSTEM"; color = "#44AAFF"; }
                        else { status = "SUSPICIOUS"; color = "#FF4444"; }
                    }

                    _fullList.Add(new ProcessInfo { Name = p.ProcessName, Id = p.Id, Status = status, Path = path, Color = color });
                } catch { }
            }
            ApplyFilter();
            StatusLabel.Text = $"Обновлено в {DateTime.Now:HH:mm:ss} | Всего: {_fullList.Count}";
        }

        // Фильтрация (Поиск)
        private void ApplyFilter()
        {
            var filter = SearchBox.Text.ToLower();
            var filtered = _fullList.Where(p => p.Name.ToLower().Contains(filter)).ToList();
            Processes.Clear();
            foreach (var p in filtered) Processes.Add(p);
        }

        private void SearchBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) => ApplyFilter();

        private void AutoRefresh_Toggle(object sender, RoutedEventArgs e)
        {
            if (AutoRefreshCb.IsChecked == true) _refreshTimer.Start();
            else _refreshTimer.Stop();
        }

        // --- НОВЫЕ ФУНКЦИИ КОНТЕКСТНОГО МЕНЮ ---

        private void CheckVirusTotal_Click(object sender, RoutedEventArgs e)
        {
            var s = (ProcessInfo)ProcessList.SelectedItem;
            if (s == null) return;
            string url = $"https://www.virustotal.com/gui/search/{s.Name}";
            Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
        }

        private void SuspendProcess_Click(object sender, RoutedEventArgs e)
        {
            var s = (ProcessInfo)ProcessList.SelectedItem;
            if (s == null) return;
            foreach (ProcessThread th in Process.GetProcessById(s.Id).Threads) {
                var h = OpenThread(2, false, (uint)th.Id);
                if (h != IntPtr.Zero) { SuspendThread(h); CloseHandle(h); }
            }
            MessageBox.Show("Процесс заморожен.");
        }

        private void ResumeProcess_Click(object sender, RoutedEventArgs e)
        {
            var s = (ProcessInfo)ProcessList.SelectedItem;
            if (s == null) return;
            foreach (ProcessThread th in Process.GetProcessById(s.Id).Threads) {
                var h = OpenThread(2, false, (uint)th.Id);
                if (h != IntPtr.Zero) { ResumeThread(h); CloseHandle(h); }
            }
            MessageBox.Show("Процесс разморожен.");
        }

        // --- БАЗОВЫЕ МЕТОДЫ (ОБНОВЛЕНИЕ, ПУТЬ И Т.Д.) ---
        private async void CheckUpdates_Click(object sender, RoutedEventArgs e)
        {
            string versionUrl = "https://raw.githubusercontent.com/p1shenak/Process-Watchdog/refs/heads/main/version.txt";
            try {
                using (HttpClient client = new HttpClient()) {
                    client.DefaultRequestHeaders.Add("User-Agent", "Updater");
                    string latest = (await client.GetStringAsync(versionUrl)).Trim();
                    if (latest != CurrentAppVersion) {
                        if (MessageBox.Show($"Версия {latest} доступна! Скачать?", "Обновление", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                            Process.Start(new ProcessStartInfo { FileName = "https://github.com/p1shenak/Process-Watchdog/releases", UseShellExecute = true });
                    }
                    else MessageBox.Show($"У вас актуальная v{CurrentAppVersion}");
                }
            } catch { MessageBox.Show("Ошибка связи с GitHub"); }
        }

        private string GetProcessPath(int pid)
        {
            try {
                using (var s = new ManagementObjectSearcher("SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " + pid))
                using (var o = s.Get()) foreach (ManagementBaseObject obj in o) return obj["ExecutablePath"]?.ToString() ?? "Unknown";
            } catch { return "System Protected"; }
            return "Unknown";
        }

        private void KillProcess_Click(object sender, RoutedEventArgs e) {
            var s = (ProcessInfo)ProcessList.SelectedItem;
            if (s != null) try { Process.GetProcessById(s.Id).Kill(); RefreshProcesses(); } catch (Exception ex) { MessageBox.Show(ex.Message); }
        }

        private void OpenFileLocation_Click(object sender, RoutedEventArgs e) {
            var s = (ProcessInfo)ProcessList.SelectedItem;
            if (s != null && s.Path != "Unknown" && s.Path != "System Protected")
                Process.Start("explorer.exe", $"/select, \"{s.Path}\"");
        }

        private void AddSelectedToExclusions_Click(object sender, RoutedEventArgs e) {
            var s = (ProcessInfo)ProcessList.SelectedItem;
            if (s != null && !string.IsNullOrEmpty(s.Path)) { Exclusions.Add(s.Path); RefreshProcesses(); }
        }

        private void AddManualExclusion_Click(object sender, RoutedEventArgs e) {
            var dlg = new OpenFileDialog { Filter = "Exe|*.exe" };
            if (dlg.ShowDialog() == true) { Exclusions.Add(dlg.FileName); RefreshProcesses(); }
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => RefreshProcesses();
    }
}