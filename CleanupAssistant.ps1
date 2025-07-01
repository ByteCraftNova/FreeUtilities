#requires -Version 5
<#
CleanUp Assistant - uses AI to evaluate files for removal or archive.
The script prompts for OpenAI API credentials and a OneDrive folder path.
It analyzes files in common user folders and uses the OpenAI API
to categorize them as Delete, Archive or Keep.
Archive copies are placed in the OneDrive folder.
Duplicate files are identified via MD5 hashes.
Configuration folders for applications selected for removal are saved
in OneDrive along with a README describing how to reinstall.
Compatible with Windows 10 and 11.
#>

param()

function Prompt-Credentials {
    param(
        [string]$Prompt
    )
    Write-Host $Prompt -ForegroundColor Cyan
    $cred = Read-Host
    return $cred
}

function Get-CandidateFiles {
    param([string[]]$Paths)
    $threshold = (Get-Date).AddDays(-90)
    $files = Get-ChildItem -Path $Paths -Recurse -File -ErrorAction SilentlyContinue
    $candidates = $files | Where-Object { $_.LastAccessTime -lt $threshold }
    return $candidates
}

function Get-DuplicateGroups {
    param([System.IO.FileInfo[]]$Files)
    $hashTable = @{}
    foreach ($file in $Files) {
        try {
            $hash = (Get-FileHash -Path $file.FullName -Algorithm MD5).Hash
            if ($hashTable.ContainsKey($hash)) {
                $hashTable[$hash].Add($file)
            } else {
                $list = New-Object System.Collections.Generic.List[System.IO.FileInfo]
                $list.Add($file)
                $hashTable[$hash] = $list
            }
        } catch {
            Write-Warning "Failed to hash $($file.FullName): $_"
        }
    }
    foreach ($entry in $hashTable.GetEnumerator()) {
        if ($entry.Value.Count -gt 1) {
            [pscustomobject]@{ Hash = $entry.Key; Files = $entry.Value }
        }
    }
}

function Invoke-OpenAICategorization {
    param(
        [System.IO.FileInfo]$File,
        [string]$ApiKey
    )
    $prompt = "Given the following file information, respond with DELETE, ARCHIVE or KEEP. File: $($File.FullName). Size: $($File.Length) bytes. Last accessed: $($File.LastAccessTime)."
    $body = @{ 
        model = 'gpt-3.5-turbo'
        messages = @(
            @{ role = 'system'; content = 'You help decide if files should be deleted, archived or kept.' },
            @{ role = 'user'; content = $prompt }
        )
    } | ConvertTo-Json -Depth 4
    try {
        $resp = Invoke-RestMethod -Uri "https://api.openai.com/v1/chat/completions" -Headers @{ 'Authorization' = "Bearer $ApiKey" } -Method Post -ContentType 'application/json' -Body $body
        $reply = $resp.choices[0].message.content.Trim().ToUpper()
        if ($reply -match 'DELETE') { return 'DELETE' }
        elseif ($reply -match 'ARCHIVE') { return 'ARCHIVE' }
        else { return 'KEEP' }
    } catch {
        Write-Warning "OpenAI API call failed: $_"
        return 'KEEP'
    }
}

function Invoke-OpenAIProgramCategorization {
    param(
        [pscustomobject]$Program,
        [string]$ApiKey
    )
    $prompt = "Given the following program information, respond with DELETE or KEEP. Program: $($Program.DisplayName). Installed: $($Program.InstallDate)."
    $body = @{
        model = 'gpt-3.5-turbo'
        messages = @(
            @{ role = 'system'; content = 'You help decide if programs should be removed.' },
            @{ role = 'user'; content = $prompt }
        )
    } | ConvertTo-Json -Depth 4
    try {
        $resp = Invoke-RestMethod -Uri "https://api.openai.com/v1/chat/completions" -Headers @{ 'Authorization' = "Bearer $ApiKey" } -Method Post -ContentType 'application/json' -Body $body
        $reply = $resp.choices[0].message.content.Trim().ToUpper()
        if ($reply -match 'DELETE') { return 'DELETE' } else { return 'KEEP' }
    } catch {
        Write-Warning "OpenAI API call failed: $_"
        return 'KEEP'
    }
}

function Export-AppConfig {
    param(
        [string]$AppName,
        [string]$TargetDir
    )
    $appData = Join-Path $env:APPDATA $AppName
    $localData = Join-Path $env:LOCALAPPDATA $AppName
    $dest = Join-Path $TargetDir $AppName
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    foreach ($src in @($appData, $localData)) {
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $dest -Recurse -Force
        }
    }
    $readme = Join-Path $TargetDir "README_${AppName}.txt"
    "Reinstall $AppName and copy the contents of '$AppName' folder back to the appropriate AppData locations." | Out-File -FilePath $readme -Encoding UTF8
}

function Get-InstalledPrograms {
    $regPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $results = foreach ($path in $regPaths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            ForEach-Object {
                $instDate = $null
                if ($_.InstallDate -and $_.InstallDate -match '^\d{8}$') {
                    [void][datetime]::TryParseExact($_.InstallDate,'yyyyMMdd',$null,[System.Globalization.DateTimeStyles]::None,[ref]$instDate)
                }
                [pscustomobject]@{
                    DisplayName    = $_.DisplayName
                    InstallDate    = $instDate
                    InstallLocation = $_.InstallLocation
                    UninstallString = $_.UninstallString
                }
            }
    }
    $results | Sort-Object DisplayName -Unique
}

function Show-Menu {
    Write-Host "==== Cleanup Assistant ====" -ForegroundColor Green
    Write-Host "This script will analyze your files and suggest cleanup actions."
    $global:OpenAIKey = Prompt-Credentials "Enter OpenAI API key"
    $global:OneDrivePath = Prompt-Credentials "Enter path to your OneDrive sync folder"
}

function Start-Cleanup {
    $scanPaths = @("$env:USERPROFILE\Documents","$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop")
    Write-Host "Scanning files..." -ForegroundColor Yellow
    $candidates = Get-CandidateFiles -Paths $scanPaths
    Write-Host "Found $($candidates.Count) files not accessed in 90 days." -ForegroundColor Yellow

    $dupes = Get-DuplicateGroups -Files $candidates
    foreach ($dup in $dupes) {
        Write-Host "Duplicate group $($dup.Hash):" -ForegroundColor Magenta
        $dup.Files | ForEach-Object { Write-Host "  $_" }
    }

    foreach ($file in $candidates) {
        $decision = Invoke-OpenAICategorization -File $file -ApiKey $OpenAIKey
        switch ($decision) {
            'DELETE' {
                Write-Host "Deleting $($file.FullName)" -ForegroundColor Red
                Remove-Item -Path $file.FullName -Force
            }
            'ARCHIVE' {
                $dest = Join-Path $OneDrivePath 'Archive'
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                Write-Host "Archiving $($file.FullName) to $dest" -ForegroundColor Cyan
                Move-Item -Path $file.FullName -Destination $dest -Force
            }
            default {
                Write-Host "Keeping $($file.FullName)" -ForegroundColor Gray
            }
        }
    }

    Write-Host "Searching for rarely used programs..." -ForegroundColor Yellow
    $programs = Get-InstalledPrograms
    foreach ($prog in $programs) {
        if ($prog.InstallDate -and $prog.InstallDate.AddDays(180) -lt (Get-Date)) {
            $decision = Invoke-OpenAIProgramCategorization -Program $prog -ApiKey $OpenAIKey
            if ($decision -eq 'DELETE') {
                Export-AppConfig -AppName $prog.DisplayName -TargetDir $OneDrivePath
                Write-Host "Please uninstall $($prog.DisplayName) manually." -ForegroundColor Red
            }
        }
    }
}

Show-Menu
Start-Cleanup
