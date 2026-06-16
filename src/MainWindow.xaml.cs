using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Management;
using System.Windows;
using System.Runtime.InteropServices;
using System.IO;
using Microsoft.Win32;

namespace ProcessWatchdog
{
    public partial class MainWindow : Window
    {
        // Импорт для снятия BSOD-защиты
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSetInformationProcess(IntPtr hProcess, int processInfoClass, ref int processInformation, int processInformationLength);

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
        private string currentVersion = "1.8";

        public MainWindow()
        {
            InitializeComponent();
            ProcessList.ItemsSource = Processes;
            RefreshProcesses();
            UpdateLocalVersionFile();
        }

        private void UpdateLocalVersionFile()
        {
            try { File.WriteAllText("version.txt", currentVersion); } catch { }
        }

        private void RefreshProcesses()
        {
            if (ProcessList == null) return;
            Processes.Clear();
            foreach (var p in Process.GetProcesses())
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
                    if (Array.Exists(criticals, c => c == pName))
                    {
                        if (HideSystemCb.IsChecked == true && (isSystemDir || path == "System Protected")) continue;
                        AddProcessToList(p, "SYSTEM", path, isSystemDir ? "#44AAFF" : "#FF4444");
                    }
                    else
                    {
                        AddProcessToList(p, "OK", path, "#00FF00");
                    }
                }
                catch { }
            }
            StatusLabel.Text = $"Обновлено в {DateTime.Now.ToLongTimeString()} | Всего: {Processes.Count}";
        }

        private void AddProcessToList(Process p, string status, string path, string color)
        {
            Processes.Add(new ProcessInfo { Name = p.ProcessName, Id = p.Id, Status = status, Path = path, Color = color });
        }

        private void RemoveCritical_Click(object sender, RoutedEventArgs e)
        {
            var selected = (ProcessInfo)ProcessList.SelectedItem;
            if (selected == null) return;

            try {
                using (Process proc = Process.GetProcessById(selected.Id)) {
                    int isCritical = 0;
                    int result = NtSetInformationProcess(proc.Handle, 29, ref isCritical, sizeof(int));
                    if (result == 0) MessageBox.Show("Критический флаг снят. Теперь процесс можно безопасно завершить.", "v1.8");
                    else MessageBox.Show("Ошибка! Запустите программу от имени Администратора.");
                }
            }
            catch (Exception ex) { MessageBox.Show("Ошибка: " + ex.Message); }
        }

        private void CheckUpdates_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists("version.txt")) {
                string fileVer = File.ReadAllText("version.txt").Trim();
                if (fileVer == currentVersion) MessageBox.Show($"У вас установлена последняя версия {currentVersion}", "Обновления");
                else MessageBox.Show($"Доступна новая версия: {fileVer}", "Обновления");
            }
            else MessageBox.Show("Файл версии не найден. Текущая версия: " + currentVersion);
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
            try { Process.GetProcessById(selected.Id).Kill(); RefreshProcesses(); }
            catch (Exception ex) { MessageBox.Show("Ошибка: " + ex.Message); }
        }

        private void AddManualExclusion_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog { Filter = "Программы (*.exe)|*.exe|Все файлы (*.*)|*.*" };
            if (dlg.ShowDialog() == true) { Exclusions.Add(dlg.FileName); RefreshProcesses(); }
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => RefreshProcesses();
        private void HideSystemCb_Checked(object sender, RoutedEventArgs e) => RefreshProcesses();
        private void HideSystemCb_Unchecked(object sender, RoutedEventArgs e) => RefreshProcesses();
    }
}