# FreeUtilities Cleanup Assistant

This repository provides PowerShell utilities. `CleanupAssistant.ps1` scans common folders for rarely used files, checks for duplicate files, and leverages the OpenAI API to recommend whether a file should be deleted, archived, or kept. Files marked for archive are moved to a user supplied OneDrive folder. Configuration folders for applications marked for removal are copied to OneDrive with a short README describing how to restore them.

## Requirements
* Windows 10 or 11
* PowerShell 5 or later
* Internet access for OpenAI API requests

## Usage
1. Obtain an OpenAI API key.
2. Ensure you have a local OneDrive sync folder.
3. Run the script from an elevated PowerShell prompt:

```powershell
powershell -ExecutionPolicy Bypass -File .\CleanupAssistant.ps1
```

You will be prompted to enter your OpenAI API key and the path to your OneDrive folder. The script will then scan `Documents`, `Downloads`, and `Desktop` for files not accessed in 90 days. For each candidate file the OpenAI API is called to suggest **DELETE**, **ARCHIVE**, or **KEEP**. Archived files are moved to `Archive` under the OneDrive folder. Any installed programs that appear unused for six months are suggested for removal with their configuration copied to OneDrive.

After the run, review the OneDrive folder for exported application settings and README files with instructions on restoring them.
