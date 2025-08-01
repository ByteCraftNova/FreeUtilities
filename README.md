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

When run, you are prompted for your OpenAI API key and the path to your OneDrive folder.  The assistant scans `Documents`, `Downloads`, and `Desktop` for files not accessed in 90 days.  Each file is evaluated with the OpenAI API and you can confirm whether to delete, archive, or keep it.  Duplicates are displayed so you can remove extras.  Archived files are moved to an `Archive` directory under your OneDrive folder.  Programs that appear unused for six months are flagged and you can choose to export their configuration to OneDrive before uninstalling them manually.

After the run, review the OneDrive folder for exported application settings and README files with instructions on restoring them.

## SpywareScan

`SpywareScan.ps1` examines running processes, services, startup entries, and firewall configuration for signs of spyware. It also walks through inbound firewall rules and offers to disable any open ports that do not appear necessary. For each open port it explains the potential risk and prompts you to confirm before the rule is disabled.

Run it from an elevated PowerShell prompt:

```powershell
powershell -ExecutionPolicy Bypass -File .\SpywareScan.ps1
```
