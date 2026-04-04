# 🛡️ Process Watchdog

A specialized Windows process monitoring tool designed to detect hidden threats, identify spoofing, and manage critical system tasks.

## 🚀 Key Features

* **X-Ray Scanner (Anti-Spoofing):** Automatically highlights processes that disguise themselves as system tasks (e.g., `svchost.exe` or `lsass.exe`) if they are launched outside the `System32` directory.
* **BSOD Protection Bypass:** Allows you to remove the "critical" flag from system processes. Now you can terminate a system process without triggering a "Blue Screen of Death".
* **Rootkit Detector:** Scans for PIDs (Process IDs) that are hidden from the standard Windows Task Manager.
* **Dark Mode UI:** A clean, eye-friendly dark interface with clear color-coded status indicators.

## 🛠️ How to Use

1.  Download the archive from the **Releases** section.
2.  Extract and run `ProcessWatchdog.exe` **as Administrator** (required for accessing system handles and WinAPI).
3.  **Red Status:** Suspicious process, requires immediate attention.
4.  **Blue Status:** Verified system process.

## 🏗️ Technologies

* **Language:** C#
* **Platform:** .NET 8.0 (WPF)
* **APIs:** Low-level `ntdll.dll` and `kernel32.dll` calls for deep system analysis.

## ⚠️ Disclaimer
This tool is created for educational and system security analysis purposes. Use caution when terminating system processes!

---
*Developed by p1shenak.*
