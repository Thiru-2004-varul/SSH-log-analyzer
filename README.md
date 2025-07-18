# Suspicious SSH Login Analyzer 🚨

This tool analyzes SSH logs to detect failed login attempts, helping identify possible brute-force attacks.

## 📦 Features

- Supports both `/var/log/auth.log` and `journalctl`
- Detects failed , accepted or both SSH login attempts
- Groups attempts by IP and username (optional)
- Outputs results in JSON or CSV
- Color-coded terminal messages using Colorama

## 🧪 Requirements

- Python 3
- colorama

Install with:

```bash
pip install colorama
