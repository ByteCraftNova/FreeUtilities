param(
    [switch]$QuickScan
)

# Ensure script is run with administrator privileges
$currentID = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentID)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Determine a directory for logs. $PSScriptRoot may be null when the script is
# executed in certain contexts (e.g., dot-sourced). Fall back to the current
# directory if it is not defined.
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$logPath = Join-Path -Path $scriptRoot -ChildPath "SpywareScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create the log file to avoid Add-Content errors if it does not exist.
New-Item -ItemType File -Path $logPath -Force | Out-Null

function Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$timestamp $Message"
    Write-Output $line
    Add-Content -Path $logPath -Value $line
}

Log "Spyware scan started."

function LogSystemInfo {
    Log "Machine Name: $env:COMPUTERNAME"
    Log "User Domain : $env:USERDOMAIN"
    Log "User Name   : $env:USERNAME"
    Log "OS Version  : $([Environment]::OSVersion.VersionString)"
}

function CheckDefender {
    try {
        $status = Get-MpComputerStatus
        Log "Windows Defender real-time protection: $($status.RealTimeProtectionEnabled)"
        Log "Antispyware signatures last updated: $($status.AntispywareSignatureLastUpdated)"
        if ($QuickScan) {
            Log "Running Windows Defender quick scan..."
            Start-MpScan -ScanType QuickScan | Out-Null
        } else {
            Log "Running Windows Defender full scan..."
            Start-MpScan -ScanType FullScan | Out-Null
        }
        Log "Windows Defender scan completed."
    } catch {
        Log "Unable to invoke Windows Defender: $_"
    }
}

function CheckDefenderHistory {
    try {
        $detections = Get-MpThreatDetection
        foreach ($det in $detections) {
            Log "PAST THREAT: $($det.ThreatName) Action:$($det.Action) Dtl:$($det.Resources)"
        }
    } catch {
        Log "Could not retrieve Defender threat history: $_"
    }
}

function CheckProcesses {
    Log "Checking running processes for unsigned executables and unusual paths..."
    Get-Process | ForEach-Object {
        if ($_.Path) {
            $sig = Get-AuthenticodeSignature -FilePath $_.Path
            if ($sig.Status -ne 'Valid') {
                Log "WARNING: Unsigned or invalid signature for process $($_.Name) path $($_.Path)"
            }
            if ($_.Path -match "AppData" -or $_.Path -match "Temp") {
                Log "NOTICE: Process $($_.Name) running from user directory $($_.Path)"
            }
        }
    }
}

function CheckScheduledTasks {
    Log "Inspecting scheduled tasks outside Microsoft path..."
    Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft\\*'} | ForEach-Object {
        try {
            $_.Actions | ForEach-Object {
                $action = $_.Execute
                if ($action -match 'powershell' -or $action -match 'cmd.exe' -or $action -match '\.ps1' -or $action -match '\.vbs') {
                    Log "Task $($_.TaskName) invokes command: $action"
                }
            }
        } catch {
            Log "Could not inspect task $($_.TaskName): $_"
        }
    }
}

function CheckRunKeys {
    Log "Inspecting Run registry keys..."
    $runKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Get-ItemProperty -Path $key | ForEach-Object {
                foreach ($property in $_.PSObject.Properties) {
                    if ($property.Name -notmatch '^PS') {
                        Log "Run key [$key] $($property.Name) = $($property.Value)"
                    }
                }
            }
        }
    }
}

function CheckStartupFolder {
    Log "Listing startup folder entries..."
    $paths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem $p | ForEach-Object {
                Log "Startup item: $($_.FullName)"
            }
        }
    }
}

function CheckServices {
    Log "Inspecting non-Microsoft services..."
    Get-Service | ForEach-Object {
        try {
            $path = (Get-WmiObject -Class Win32_Service -Filter "Name='$(($_.Name))'").PathName
            if ($path -and $path -notmatch 'Microsoft' -and $path -notmatch 'Windows\\System32') {
                $sig = $null
                if (Test-Path $path) { $sig = Get-AuthenticodeSignature -FilePath $path }
                $sigStatus = if ($sig) { $sig.Status } else { 'Unknown' }
                Log "Service $($_.Name) path $path signature $sigStatus"
            }
        } catch {
            Log "Could not inspect service $($_.Name): $_"
        }
    }
}

function CheckHostsFile {
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsFile) {
        Log "Listing hosts file entries..."
        Get-Content $hostsFile | Where-Object {$_ -notmatch '^#' -and $_ -ne ''} | ForEach-Object {
            Log "Hosts entry: $_"
        }
    }
}

function CheckNetworkConnections {
    Log "Listing established TCP connections..."
    Get-NetTCPConnection -State Established | ForEach-Object {
        Log "Connection: $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"
    }
    Log "Listing listening TCP ports..."
    Get-NetTCPConnection -State Listen | ForEach-Object {
        Log "Listening on: $($_.LocalAddress):$($_.LocalPort)"
    }
}

function CheckFirewallRules {
    Log "Listing enabled firewall rules that allow traffic..."
    Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Action -eq 'Allow'} | ForEach-Object {
        Log "Firewall rule allowing traffic: $($_.DisplayName)"
    }
}

function CheckEventLogs {
    Log "Recent security events (process creation)..."
    $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688;StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        $message = $event.Properties[5].Value
        Log "Process created: $message"
    }
}

# Begin scan
LogSystemInfo
CheckDefender
CheckDefenderHistory
CheckProcesses
CheckScheduledTasks
CheckRunKeys
CheckStartupFolder
CheckServices
CheckHostsFile
CheckNetworkConnections
CheckFirewallRules
CheckEventLogs

Log "Spyware scan completed. Results saved to $logPath"
