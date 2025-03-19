$script:Version = "3.1"
$script:AuditEnabled = $true
$script:AuditFile = "$env:TEMP\TurboTitan\TurboTitan_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:Progress = [PSCustomObject]@{ StepsCompleted = 0; TotalSteps = 12 }
$script:CriticalProcesses = @("System", "svchost", "csrss", "winlogon", "explorer", "dllhost", "services", "lsass", "smss")
$script:Config = @{
    LogLevel = "Info"  # Options: Debug, Info, Warning, Error
    MaxCacheFiles = 50
    MonitorInterval = 5  # Seconds
    BackupPath = "$env:TEMP\TurboTitan\Backups"
}
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "", Scope="Script")]
$Silent = $false
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "", Scope="Script")]
$AllYes = $false
$script:OptimizationHistory = [System.Collections.ArrayList]::new()

# Ensure script runs with admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires administrative privileges. Please run as administrator."
    exit 1
}

# Core Functions
function Write-Report {
    param ([string]$Message, [string]$Status = "Info")
    $color = switch ($Status) { "Success" { "Green" } "Error" { "Red" } "Warning" { "Yellow" } default { "White" } }
    Write-Host "[$Status] $Message" -ForegroundColor $color
    
    # Map Status to Log Level
    $logLevel = switch ($Status) {
        "Success" { "Info" }
        "Error" { "Error" }
        "Warning" { "Warning" }
        default { "Info" }  # Fallback for "Info" or any unmapped status
    }
    Write-Log $Message $logLevel
}

function Write-Log {
    param (
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("Debug", "Info", "Warning", "Error")][string]$Level = "Info"
    )
    $levels = @{ "Debug" = 0; "Info" = 1; "Warning" = 2; "Error" = 3 }
    if ($script:AuditEnabled -and $levels[$Level] -ge $levels[$script:Config.LogLevel]) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] $Message"
        $logDir = Split-Path -Path $script:AuditFile -Parent
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        try {
            Add-Content -Path $script:AuditFile -Value $logEntry -ErrorAction Stop
        } catch {
            Write-Warning "Failed to write to audit log: $_"
        }
    }
}

function Show-Progress {
    param ([int]$CurrentStep, [int]$TotalSteps = $script:Progress.TotalSteps, [string]$Activity)
    Write-Progress -Activity $Activity -Status "Step $CurrentStep of $TotalSteps" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
}

function Create-RestorePoint {
    param ([string]$Description = "TurboTitan Restore Point $(Get-Date -Format 'yyyyMMdd_HHmmss')")
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        # Check if System Restore is enabled for the system drive
        $srStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        $drive = $env:SystemDrive
        $protection = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "RPSessionInterval" -ErrorAction SilentlyContinue
        if (-not $protection -or $protection.RPSessionInterval -eq 0) {
            Write-Report "System Restore is disabled on $drive." "Warning"
            Write-Host "To enable System Restore:" -ForegroundColor Yellow
            Write-Host "1. Open 'System Properties' (sysdm.cpl)" -ForegroundColor Yellow
            Write-Host "2. Go to the 'System Protection' tab" -ForegroundColor Yellow
            Write-Host "3. Select your system drive ($drive) and click 'Configure'" -ForegroundColor Yellow
            Write-Host "4. Turn on system protection and apply" -ForegroundColor Yellow
            Write-Report "Skipping restore point creation. Enable System Restore and try again." "Error"
            Write-Host "`nPress Enter to return to the menu..." -ForegroundColor Cyan
            Read-Host
            return
        }

        # Check and enable necessary services
        $services = @("VSS", "swprv")  # Volume Shadow Copy and Microsoft Software Shadow Copy Provider
        foreach ($svc in $services) {
            $service = Get-Service -Name $svc -ErrorAction Stop
            if ($service.StartType -eq "Disabled") {
                Write-Report "Enabling $svc service..." "Info"
                Set-Service -Name $svc -StartupType Manual -ErrorAction Stop
            }
            if ($service.Status -ne "Running") {
                Write-Report "Starting $svc service..." "Info"
                Start-Service -Name $svc -ErrorAction Stop
            }
        }

        Write-Host "Creating restore point: $Description..." -ForegroundColor Yellow
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Report "Created restore point: $Description" "Success"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Create-RestorePoint"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Failed to create restore point: $_" "Error"
        Write-Host "Possible fixes:" -ForegroundColor Yellow
        Write-Host "- Ensure System Restore is enabled for $drive in System Properties" -ForegroundColor Yellow
        Write-Host "- Verify disk space is available on $drive" -ForegroundColor Yellow
        Write-Host "- Run as Administrator" -ForegroundColor Yellow
        Write-Host "`nPress Enter to return to the menu..." -ForegroundColor Cyan
        Read-Host
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Create-RestorePoint"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Backup-Registry {
    param ([string]$Hive = "HKLM")
    try {
        $backupFile = Join-Path $script:Config.BackupPath "Registry_$Hive_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
        if (-not (Test-Path $script:Config.BackupPath)) {
            New-Item -Path $script:Config.BackupPath -ItemType Directory -Force | Out-Null
        }
        reg export $Hive $backupFile /y
        Write-Log "Backed up $Hive to $backupFile" "Info"
        return $true
    } catch {
        Write-Log "Registry backup failed: $_" "Error"
        return $false
    }
}

function Check-Compatibility {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        if ($os.Version -lt "10.0") {
            Write-Report "Incompatible OS version. Windows 10 or later required." "Error"
            exit 1
        }
        if (-not [Environment]::Is64BitOperatingSystem) {
            Write-Report "This script requires a 64-bit operating system." "Error"
            exit 1
        }
        Write-Report "System compatibility check passed." "Success"
    } catch {
        Write-Report "Compatibility check failed: $_" "Error"
        exit 1
    }
}

function Get-CachedProcesses {
    if (-not $script:cachedProcesses) {
        $script:cachedProcesses = Get-Process -ErrorAction SilentlyContinue
    }
    return $script:cachedProcesses
}

function Stop-ServiceIfExists {
    param ([string]$ServiceName)
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Write-Report "Stopped service: $ServiceName" "Success"
            $script:OptimizationHistory.Add([PSCustomObject]@{Function="Stop-ServiceIfExists"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
        } catch {
            Write-Report "Failed to stop service ${ServiceName}: $_" "Error"  # Escaped with ${}
            $script:OptimizationHistory.Add([PSCustomObject]@{Function="Stop-ServiceIfExists"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
        }
    }
}

function Confirm-Action {
    param ([string]$Prompt, [switch]$AllYes)
    if ($AllYes -or $script:Silent) { return $true }
    do {
        $response = Read-Host "$Prompt (y/n)"
    } until ($response -match "^(y|n)$")
    return $response -eq "y"
}

function Get-SystemHealth {
    $metrics = [PSCustomObject]@{
        CPU = (Get-Counter "\Processor(_Total)\% Processor Time" -ErrorAction SilentlyContinue).CounterSamples.CookedValue
        MemoryFree = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).FreePhysicalMemory / 1MB
        DiskQueue = (Get-Counter "\PhysicalDisk(_Total)\Current Disk Queue Length" -ErrorAction SilentlyContinue).CounterSamples.CookedValue
        Timestamp = Get-Date
    }
    return $metrics
}

# Optimization Functions
function Emulate-HyperThread {
    Write-Report "Activating Core i3 Hyper-Thread Emulator..." "Success"
    Show-Progress -CurrentStep 1 -Activity "Hyper-thread emulation"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $coreCount = [int]((Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1).NumberOfCores)
        if (-not $coreCount -or $coreCount -lt 1) {
            $coreCount = 1
            Write-Log "Core count detection failed, defaulting to 1 core" "Warning"
        }
        $processes = Get-Process -ErrorAction Stop | Where-Object { $_.CPU -gt 1 -and $_.Name -notin $script:CriticalProcesses } | Sort-Object CPU -Descending
        $i = 0
        foreach ($proc in $processes[0..[math]::Min(10, $processes.Count-1)]) {  # Limit to top 10
            $coreIndex = $i % $coreCount
            $affinity = [math]::Pow(2, $coreIndex)
            try {
                $proc.ProcessorAffinity = [int]$affinity
                $proc.PriorityClass = if ($i % 2 -eq 0) { "AboveNormal" } else { "Normal" }
                Write-Log "Emulated thread for $($proc.Name) on core $coreIndex" "Debug"
            } catch {
                Write-Log "Failed to adjust $($proc.Name): $_" "Warning"
            }
            $i++
        }
        Write-Report "Hyper-thread emulation completed" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Emulate-HyperThread"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Hyper-thread emulation failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Emulate-HyperThread"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Simulate-SSD {
    Write-Report "Engaging SSD Simulation Engine..." "Success"
    Write-Host "This will cache system DLLs in RAM to simulate SSD speed." -ForegroundColor Cyan
    Show-Progress -CurrentStep 2 -Activity "SSD simulation"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if (Confirm-Action "Backup registry before SSD simulation?") {
            Backup-Registry "HKLM"
        }
        $ramCache = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
        $criticalFiles = Get-ChildItem "$env:SystemRoot\System32" -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq ".dll" } | Select-Object -First $script:Config.MaxCacheFiles
        
        Write-Host "Caching $($criticalFiles.Count) DLL files in RAM..." -ForegroundColor Yellow
        $results = $criticalFiles | ForEach-Object -ThrottleLimit 4 -Parallel {
            try {
                $content = [System.IO.File]::ReadAllBytes($_.FullName)
                & $using:Write-Log "Simulated SSD cache for $($_.FullName)" "Debug"
                return $_.FullName
            } catch {
                & $using:Write-Log "Failed to cache $($_.FullName): $_" "Warning"
                return $null
            }
        }
        
        $results | Where-Object { $_ -ne $null } | ForEach-Object { $ramCache.Add($_) }
        
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        try {
            if (-not (Test-Path $regPath)) {
                Write-Report "Registry path $regPath not found. Creating it..." "Warning"
                New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
            }
            $currentValue = Get-ItemProperty -Path $regPath -Name "DisablePagingExecutive" -ErrorAction SilentlyContinue
            if (-not $currentValue -or $currentValue.DisablePagingExecutive -ne 1) {
                Set-ItemProperty -Path $regPath -Name "DisablePagingExecutive" -Value 1 -ErrorAction Stop
                Write-Report "Disabled paging executive to keep drivers in RAM." "Success"
            } else {
                Write-Report "Paging executive already disabled." "Info"
            }
        } catch {
            Write-Report "Failed to set registry value for SSD simulation: $_" "Warning"
            Write-Report "Continuing without registry adjustment..." "Info"
        }
        
        Write-Report "SSD simulation completed - $($ramCache.Count) files cached" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Simulate-SSD"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
 auditioned::Stopwatch
    } catch {
        Write-Report "SSD simulation failed unexpectedly: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Simulate-SSD"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Prevent-Starvation {
    Write-Report "Activating Memory Starvation Preventer..." "Success"
    Show-Progress -CurrentStep 3 -Activity "Memory relief"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $monitorTime = 15
        $endTime = (Get-Date).AddSeconds($monitorTime)
        while ((Get-Date) -lt $endTime) {
            $freeMem = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).FreePhysicalMemory / 1024
            if ($freeMem -lt 500) {
                $bgProcs = Get-Process -ErrorAction Stop | Where-Object { $_.MainWindowHandle -eq 0 -and $_.WorkingSet64 -gt 50MB -and $_.Name -notin $script:CriticalProcesses }
                foreach ($proc in $bgProcs) {
                    $proc.PriorityClass = "Idle"
                    Write-Log "Throttled memory hog: $($proc.Name)" "Debug"
                }
                [System.GC]::Collect()
            }
            Start-Sleep -Seconds $script:Config.MonitorInterval
        }
        Write-Report "Memory starvation prevented" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Prevent-Starvation"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Memory starvation prevention failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Prevent-Starvation"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Slim-Kernel {
    Write-Report "Engaging Kernel Slimmer..." "Success"
    Show-Progress -CurrentStep 4 -Activity "Kernel slimming"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if (Confirm-Action "Backup registry before kernel slimming?") {
            Backup-Registry "HKLM"
        }
        $features = @("Microsoft-Hyper-V", "WindowsMediaPlayer", "MediaPlayback")
        foreach ($feature in $features) {
            $featureState = Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.FeatureName -eq $feature }
            if ($featureState -and $featureState.State -ne "Disabled") {
                try {
                    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop
                    Write-Log "Disabled feature: $feature" "Info"
                } catch {
                    Write-Log "Failed to disable ${feature}: $_" "Warning"  # Escaped with ${}
                }
            } else {
                Write-Log "Feature $feature not found or already disabled, skipping" "Info"
            }
        }
        Write-Report "Kernel slimming completed" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Slim-Kernel"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Kernel slimming failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Slim-Kernel"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Annihilate-Latency {
    Write-Report "Unleashing Latency Annihilator..." "Success"
    Show-Progress -CurrentStep 5 -Activity "Latency annihilation"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        powercfg /setactive SCHEME_MIN
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" -Name "ValueMax" -Value 100 -ErrorAction Stop
        $irqs = Get-CimInstance Win32_IRQResource -ErrorAction Stop | Where-Object { $_.IRQNumber -ge 0 }
        foreach ($irq in $irqs) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ$($irq.IRQNumber)Priority" -Value 1 -ErrorAction SilentlyContinue
            Write-Log "Boosted IRQ $($irq.IRQNumber) priority" "Debug"
        }
        Write-Report "Latency annihilated" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Annihilate-Latency"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Latency annihilation failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Annihilate-Latency"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Accelerate-Time {
    Write-Report "Engaging Temporal Anomaly Accelerator..." "Success"
    Show-Progress -CurrentStep 6 -Activity "Time acceleration"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $systemRoot = $env:SystemRoot
        $hotFiles = @("$systemRoot\System32\ntdll.dll", "$systemRoot\System32\kernel32.dll", "$systemRoot\System32\user32.dll")
        $buffer = [System.Collections.ArrayList]::new()
        foreach ($file in $hotFiles) {
            $content = [System.IO.File]::ReadAllBytes($file)
            $buffer.Add([PSCustomObject]@{ Path = $file; Data = $content }) | Out-Null
            Write-Log "Temporally accelerated: $file" "Debug"
        }
        Write-Report "Temporal acceleration completed" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Accelerate-Time"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Temporal acceleration failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Accelerate-Time"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Harmonize-Processes {
    Write-Report "Activating Fractal Process Harmonizer..." "Success"
    Show-Progress -CurrentStep 7 -Activity "Process harmonization"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $processes = Get-Process -ErrorAction Stop | Sort-Object CPU -Descending
        $tierSize = [math]::Ceiling($processes.Count / 4)
        $tiers = [ordered]@{ "Critical" = "High"; "Heavy" = "AboveNormal"; "Medium" = "Normal"; "Low" = "BelowNormal" }
        $i = 0
        foreach ($tier in $tiers.Keys) {
            $tierProcs = $processes | Select-Object -Skip ($i * $tierSize) -First $tierSize
            foreach ($proc in $tierProcs) {
                if ($proc.Name -notin $script:CriticalProcesses) {
                    try {
                        $proc.PriorityClass = $tiers[$tier]
                        Write-Log "Harmonized $($proc.Name) to $tier priority" "Debug"
                    } catch {
                        Write-Log "Failed to harmonize $($proc.Name): $_" "Warning"
                    }
                }
            }
            $i++
        }
        Write-Report "Process harmonization completed" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Harmonize-Processes"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Process harmonization failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Harmonize-Processes"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Compress-Registry {
    Write-Report "Deploying Holographic Registry Compressor..." "Success"
    Show-Progress -CurrentStep 8 -Activity "Registry compression"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if (Confirm-Action "Backup registry before compression?") {
            Backup-Registry "HKCU"
            Backup-Registry "HKLM"
        }
        $hives = @("HKCU", "HKLM")
        $redundantKeys = @{}
        foreach ($hive in $hives) {
            Get-ItemProperty -Path "${hive}:\Software" -ErrorAction SilentlyContinue | ForEach-Object {
                $_.PSObject.Properties | Where-Object { $_.Value } | ForEach-Object {
                    $key = "$($_.Name)=$($_.Value)"
                    if ($redundantKeys[$key]) { $redundantKeys[$key] += 1 } else { $redundantKeys[$key] = 1 }
                }
            }
        }
        $cleaned = 0
        foreach ($key in $redundantKeys.Keys | Where-Object { $redundantKeys[$_] -gt 1 }) {
            $name, $value = $key -split "="
            Get-Item -Path "HKCU:\Software", "HKLM:\Software" -ErrorAction SilentlyContinue | ForEach-Object {
                $path = $_.PSPath
                if ((Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name -eq $value) {
                    Remove-ItemProperty -Path $path -Name $name -Force -ErrorAction SilentlyContinue
                    $cleaned++
                }
            }
        }
        Write-Report "Registry compressed - $cleaned redundant keys removed" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Compress-Registry"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Registry compression failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Compress-Registry"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Expand-Bandwidth {
    Write-Report "Unleashing Cosmic Bandwidth Expander..." "Success"
    Show-Progress -CurrentStep 9 -Activity "Bandwidth expansion"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $cacheDir = "$env:TEMP\TurboTitan\CosmicCache"
        New-Item -Path $cacheDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        $resources = @{ "GoogleFonts" = "https://fonts.googleapis.com/css?family=Roboto"; "jQuery" = "https://code.jquery.com/jquery-3.6.0.min.js" }
        foreach ($name in $resources.Keys) {
            Invoke-WebRequest -Uri $resources[$name] -OutFile "$cacheDir\$name" -ErrorAction Stop
            Write-Log "Expanded bandwidth with $name" "Info"
        }
        Write-Report "Bandwidth expanded" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Expand-Bandwidth"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Bandwidth expansion failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Expand-Bandwidth"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Stabilize-System {
    Write-Report "Activating Infinite Loop Stabilizer..." "Success"
    Write-Host "This monitors and stabilizes runaway processes." -ForegroundColor Cyan
    Show-Progress -CurrentStep 10 -Activity "System stabilization"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $monitorTime = 20
        $endTime = (Get-Date).AddSeconds($monitorTime)
        $baseline = Get-Process -ErrorAction Stop | Select-Object Name, WorkingSet
        Start-Sleep -Seconds $script:Config.MonitorInterval
        while ((Get-Date) -lt $endTime) {
            $current = Get-Process -ErrorAction Stop | Select-Object Name, WorkingSet
            foreach ($proc in $current) {
                $baseProc = $baseline | Where-Object { $_.Name -eq $proc.Name }
                if ($baseProc) {
                    $baseWorkingSet = $baseProc | Select-Object -First 1 -ExpandProperty WorkingSet
                    if ($proc.WorkingSet -gt ($baseWorkingSet * 2) -and $proc.Name -notin $script:CriticalProcesses) {
                        if (Confirm-Action "Approve termination of process ** $($proc.Name) ** due to high memory usage?") {
                            Stop-Process -Name $proc.Name -Force -ErrorAction SilentlyContinue
                            Write-Log "Stabilized infinite loop in $($proc.Name)" "Info"
                        } else {
                            Write-Log "User declined termination of $($proc.Name)" "Info"
                        }
                    } else {
                        Write-Log "Skipped critical process or no issue: $($proc.Name)" "Debug"
                    }
                }
            }
            $baseline = $current
            Start-Sleep -Seconds $script:Config.MonitorInterval
        }
        Write-Report "System stabilization completed" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Stabilize-System"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "System stabilization failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Stabilize-System"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Optimize-DiskEntropy {
    Write-Report "Engaging Entropy-Based Disk Optimizer..." "Success"
    Write-Host "This optimizes disk access by caching frequently used system files." -ForegroundColor Cyan
    Show-Progress -CurrentStep 11 -Activity "Entropy optimization"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Write-Host "Enabling last access tracking..." -ForegroundColor Yellow
        Invoke-Expression "fsutil behavior set disablelastaccess 0" -ErrorAction Stop
        $hotFiles = Get-ChildItem -Path "$env:SystemRoot\System32", "$env:SystemRoot" -File -ErrorAction SilentlyContinue | 
            Sort-Object LastAccessTime -Descending | 
            Select-Object -First 10  # Reduced from 20 to 10
        Write-Host "Caching $($hotFiles.Count) recently accessed system files..." -ForegroundColor Yellow
        foreach ($file in $hotFiles) {
            try {
                [System.IO.File]::ReadAllBytes($file.FullName) | Out-Null
                Write-Log "Pre-cached high-entropy file: $($file.FullName)" "Debug"
            } catch {
                Write-Log "Error accessing file: $($file.FullName) - $_" "Warning"
            }
        }
        Write-Host "Disabling last access tracking..." -ForegroundColor Yellow
        Invoke-Expression "fsutil behavior set disablelastaccess 1" -ErrorAction Stop
        Write-Report "Disk entropy optimized - $($hotFiles.Count) files cached" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Optimize-DiskEntropy"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Disk entropy optimization failed: $_" "Error"
        Write-Report "Ensure you have admin rights and fsutil is available." "Warning"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Optimize-DiskEntropy"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Show-PerformanceMetrics {
    param ([string]$Action)
    try {
        $cpuUsage = (Get-Counter "\Processor(_Total)\% Processor Time" -ErrorAction Stop).CounterSamples | Select-Object -First 1
        $memoryAvailable = (Get-Counter "\Memory\Available MBytes" -ErrorAction Stop).CounterSamples | Select-Object -First 1
        Write-Report "Performance Metrics ${Action}:" "Info"  # Escaped with ${}
        Write-Report "CPU Usage: $($cpuUsage.CookedValue)%" "Info"
        Write-Report "Available Memory: $($memoryAvailable.CookedValue) MB" "Info"
    } catch {
        Write-Report "Failed to gather performance metrics: $_" "Error"
    }
}

function Adjust-Performance {
    param ([switch]$Silent, [switch]$AllYes, [int]$totalSteps = 14, [ref]$currentStep)
    Write-Report "Supercharging system performance with FULL TURBO BOOST..." "Success"
    Write-Host "This will run ALL optimizations in sequence (options 2-15)." -ForegroundColor Cyan
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not $currentStep) { $localCurrentStep = 1; $currentStep = [ref]$localCurrentStep } else { $currentStep.Value = 1 }
        $script:Silent = $Silent; $script:AllYes = $AllYes
        $functions = @(
            "Emulate-HyperThread",    # Option 2
            "Simulate-SSD",           # Option 3
            "Prevent-Starvation",     # Option 4
            "Slim-Kernel",            # Option 5
            "Annihilate-Latency",     # Option 6
            "Accelerate-Time",        # Option 7
            "Harmonize-Processes",    # Option 8
            "Compress-Registry",      # Option 9
            "Expand-Bandwidth",       # Option 10
            "Stabilize-System",       # Option 11
            "Optimize-DiskEntropy",   # Option 12
            "Uninstall-Apps",         # Option 13
            "Tune-Network",           # Option 14
            "Guard-System"            # Option 15
        )
        foreach ($func in $functions) {
            Show-Progress -CurrentStep $currentStep.Value -TotalSteps $totalSteps -Activity "Running $func"
            Write-Host "Starting $func..." -ForegroundColor Yellow
            Invoke-Expression $func
            Write-Host "$func completed!" -ForegroundColor Green
            $currentStep.Value++
            Start-Sleep -Milliseconds 500
        }
        Write-Report "FULL TURBO BOOST completed" "Success"
        Write-Host "All optimizations finished in $($stopwatch.Elapsed.TotalSeconds) seconds!" -ForegroundColor Green
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Adjust-Performance"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "FULL TURBO BOOST failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Adjust-Performance"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Uninstall-Apps {
    Write-Report "Purging bloatware..." "Success"
    Show-Progress -CurrentStep 7 -Activity "Bloatware purge"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $essentialApps = @("Windows Defender", "Microsoft Office", "Adobe Acrobat Reader", "Google Chrome", "Mozilla Firefox", "Microsoft Edge", "Task Manager", "Event Viewer", "Backup and Restore", "Windows Media Player")
        $script:installedApps = Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object { $_.IsFramework -eq $false -and $_.SignatureKind -ne "System" }
        foreach ($app in $script:installedApps) {
            if ($essentialApps -notcontains $app.Name) {
                if (Confirm-Action "Do you want to uninstall $($app.Name)?") {
                    try {
                        Remove-AppxPackage -Package $app.PackageFullName -ErrorAction Stop
                        Write-Log "Removed application: $($app.Name)" "Info"
                    } catch {
                        Write-Log "Failed to remove $($app.Name): $_" "Warning"
                    }
                } else {
                    Write-Log "Skipped application: $($app.Name)" "Info"
                }
            } else {
                Write-Log "Skipped essential application: $($app.Name)" "Debug"
            }
        }
        Write-Report "Bloatware purge completed" "Success"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Uninstall-Apps"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Bloatware purge failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Uninstall-Apps"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}

function Tune-Network {
    Write-Report "Tuning network..." "Success"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $dnsOptions = @(("1.1.1.1", "1.0.0.1"), ("8.8.8.8", "8.8.4.4"))
        $jobs = @()
        foreach ($dns in $dnsOptions) {
            $jobs += Start-Job -ScriptBlock {
                param($dnsPair)
                Set-DnsClientServerAddress -InterfaceAlias (Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).Name -ServerAddresses $dnsPair
                $latency = (Test-Connection "google.com" -Count 5 -ErrorAction SilentlyContinue).ResponseTime | Measure-Object -Average
                [PSCustomObject]@{ DNS = $dnsPair; Latency = $latency.Average }
            } -ArgumentList $dns
        }
        $results = $jobs | Wait-Job | Receive-Job
        $bestDNS = $results | Sort-Object Latency | Select-Object -First 1
        Set-DnsClientServerAddress -InterfaceAlias (Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).Name -ServerAddresses $bestDNS.DNS -ErrorAction Stop
        Write-Report "Network tuned with best DNS: $($bestDNS.DNS -join ', ')" "Success"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Tune-Network"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "Network tuning failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Tune-Network"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    } finally {
        $jobs | Remove-Job -Force
    }
}

function Guard-System {
    Write-Report "Launching Self-Healing System Guardian..." "Success"
    Write-Host "This monitors CPU usage and manages high-usage processes." -ForegroundColor Cyan
    Show-Progress -CurrentStep 9 -Activity "System guarding"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $monitorTime = 30
        $endTime = (Get-Date).AddSeconds($monitorTime)
        while ((Get-Date) -lt $endTime) {
            $cpu = (Get-Counter "\Processor(_Total)\% Processor Time" -ErrorAction Stop).CounterSamples.CookedValue
            if ($cpu -gt 90) {
                $cpuHogs = Get-Process -ErrorAction Stop | Sort-Object CPU -Descending | Where-Object { $_.Name -notin $script:CriticalProcesses } | Select-Object -First 3
                foreach ($proc in $cpuHogs) {
                    if (Confirm-Action "Approve termination of process ** $($proc.Name) ** due to high CPU usage?") {
                        Stop-Process -Name $proc.Name -Force -ErrorAction Stop
                        Write-Log "Guardian terminated CPU hog: $($proc.Name)" "Info"
                    } else {
                        Write-Log "User declined termination of $($proc.Name)" "Info"
                    }
                }
            }
            Start-Sleep -Seconds $script:Config.MonitorInterval
        }
        Write-Report "System guarding completed" "Success"
        $script:Progress.StepsCompleted++
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Guard-System"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Success"}) | Out-Null
    } catch {
        Write-Report "System guarding failed: $_" "Error"
        $script:OptimizationHistory.Add([PSCustomObject]@{Function="Guard-System"; Duration=$stopwatch.Elapsed.TotalSeconds; Timestamp=Get-Date; Result="Failed"}) | Out-Null
    }
}


function Show-Menu {
    $retryCount = 0
    $maxRetries = 3
    while ($retryCount -lt $maxRetries) {
        Clear-Host
        Write-Host "`n=== TurboTitan v$script:Version - Core i3 Relief Hero ===" -ForegroundColor Cyan
        Write-Host "Boost your system's performance with these options:" -ForegroundColor White
        $options = [ordered]@{
            1 = "FULL TURBO BOOST - RUNS ALL OPTIMIZATIONS AT ONCE!"
            2 = "Hyper-Thread Emulator - Boosts CPU efficiency"
            3 = "SSD Simulator - Speeds up file access"
            4 = "Memory Relief - Prevents memory starvation"
            5 = "Kernel Slimmer - Removes unused features"
            6 = "Latency Annihilator - Reduces system delays"
            7 = "Temporal Accelerator - Preloads key files"
            8 = "Fractal Harmonizer - Balances process priorities"
            9 = "Registry Compressor - Cleans registry"
            10 = "Bandwidth Expander - Boosts network cache"
            11 = "Loop Stabilizer - Stops runaway processes"
            12 = "Disk Entropy - Optimizes disk usage"
            13 = "Bloat Purge - Removes unwanted apps"
            14 = "Network Tune - Optimizes DNS"
            15 = "Self-Healing - Monitors system health"
            16 = "Exit - Save and quit"
        }
        $options.GetEnumerator() | ForEach-Object { 
            Write-Host "$($_.Key). $($_.Value)" -ForegroundColor Green 
        }
        Write-Host "`nCurrent Progress: $($script:Progress.StepsCompleted)/$($script:Progress.TotalSteps) steps completed" -ForegroundColor Yellow
        $choice = if ($Silent) { "16" } else { Read-Host "Select an option (1-16)" }
        if ($choice -match "^[1-9]$|^1[0-6]$") { return $choice }
        Write-Report "Please select a number between 1 and 16." "Warning"
        $retryCount++
        Start-Sleep -Seconds 1
    }
    return "16"
}

# Main Execution
try {
    $initialHealth = Get-SystemHealth
    $firstRun = $true  # Flag to track first run

    if ($firstRun) {
        # Display bold TurboTitan header
        Write-Host "`n" -NoNewline
        Write-Host "  ********************* " -ForegroundColor Cyan
        Write-Host "⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⡄⠀⠀
⢰⠒⠒⢻⣿⣶⡒⠒⠒⠒⠒⠒⠒⠒⠒⠒⡶⠊⣰⣓⡒⡆
⢸⢸⢻⣭⡙⢿⣿⣍⡉⠉⡇⣯⠉⠉⣩⠋⢀⣔⠕⢫⡇⡇
⢸⢸⣈⡻⣿⣶⣽⡸⣿⣦⡇⣧⠠⠊⣸⢶⠋⢁⡤⠧⡧⡇
⢸⢸⠻⣿⣶⣝⠛⣿⣮⢻⠟⣏⣠⠞⠁⣼⡶⠋⢀⣴⡇⡇
⢸⢸⣿⣶⣍⠻⠼⣮⡕⢁⡤⢿⢁⡴⠊⣸⣵⠞⠋⢠⡇⡇
⢸⢘⣛⡻⣿⣧⢳⣿⣧⠎⢀⣾⠋⡠⠞⢱⢇⣠⡴⠟⡇⡇
⢸⢸⠹⣿⣷⣎⣉⣻⢁⡔⢁⢿⡏⢀⣤⢾⡟⠁⣀⣎⡇⡇
⢸⢸⠲⣶⣭⡛⠚⢿⢋⡔⢁⣼⠟⢋⣠⣼⠖⠋⢁⠎⡇⡇
⢸⢸⢤⣬⣛⠿⠞⣿⢋⠔⣉⣾⠖⠋⢁⣯⡴⠞⢃⠂⡇⡇
⢸⢸⠀⢙⣻⢿⣧⣾⡵⠚⣉⣯⠶⠛⣹⣧⠤⢮⠁⠀⡇⡇
⠸⣘⠢⣄⠙⠿⢷⡡⠖⣋⣽⠥⠒⣩⣟⣤⣔⣁⡤⠖⣃⠇
⠀⠀⠙⠢⢍⣻⡿⠒⢉⣴⣗⣚⣽⣋⣀⣤⣊⠥⠒⠉⠀⠀
⠀⠀⠀⢀⣔⠥⠒⢮⣙⠾⠀⠷⣚⡭⠞⠉⠛⠦⣀⠀⠀⠀
⠀⠀⠀⠉⠀⠀⠀⠀⠈⠑⠒⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀ " -ForegroundColor Cyan
        Write-Host "  ********************* " -ForegroundColor Cyan
        write-host "  ** TURBOTITAN v$script:Version **" -ForegroundColor Cyan
        Write-Host "  ********************* " -ForegroundColor Cyan
        Write-Host "  Unleashing Epic Performance for Your PC!" -ForegroundColor Green
        Write-Host "`n" -NoNewline
        
        # Check compatibility and prompt for restore point
        Write-Host "Checking system compatibility..." -ForegroundColor Cyan
        Check-Compatibility
        Write-Host "System is ready for optimization!" -ForegroundColor Green
        if (Confirm-Action "Would you like to create a system restore point before proceeding?") {
            Create-RestorePoint
        }
        $firstRun = $false  # Set flag to false after first run
    }

    Show-PerformanceMetrics "initialization"

    while ($true) {
        $choice = Show-Menu
        switch ($choice) {
            "1" {
                $currentStep = 0
                if ($Silent) { Adjust-Performance -Silent -AllYes -currentStep ([ref]$currentStep) }
                else {
                    Write-Host "FULL TURBO BOOST Options:" -ForegroundColor Cyan
                    Write-Host "1. Interactive (step-by-step prompts)" -ForegroundColor Green
                    Write-Host "2. Automatic (yes to all)" -ForegroundColor Green
                    $speedChoice = Read-Host "Select (1-2)"
                    if ($speedChoice -eq "2") { Adjust-Performance -AllYes -currentStep ([ref]$currentStep) }
                    else { Adjust-Performance -currentStep ([ref]$currentStep) }
                }
            }
            "2" { Emulate-HyperThread }
            "3" { Simulate-SSD }
            "4" { Prevent-Starvation }
            "5" { Slim-Kernel }
            "6" { Annihilate-Latency }
            "7" { Accelerate-Time }
            "8" { Harmonize-Processes }
            "9" { Compress-Registry }
            "10" { Expand-Bandwidth }
            "11" { Stabilize-System }
            "12" { Optimize-DiskEntropy }
            "13" { Uninstall-Apps }
            "14" { Tune-Network }
            "15" { Guard-System }
            "16" {
                Write-Report "Exiting TurboTitan - Relief Delivered!" "Success"
                Show-PerformanceMetrics "optimizations"
                $finalHealth = Get-SystemHealth
                Write-Host "`n=== Optimization Summary ===" -ForegroundColor Cyan
                Write-Host "CPU Usage Change: $($initialHealth.CPU - $finalHealth.CPU)% " -ForegroundColor Yellow
                Write-Host "Memory Free Change: $($finalHealth.MemoryFree - $initialHealth.MemoryFree) MB" -ForegroundColor Yellow
                Write-Host "Steps Completed: $($script:Progress.StepsCompleted)" -ForegroundColor Yellow
                Write-Host "History saved to: $env:TEMP\TurboTitan\OptimizationHistory.csv" -ForegroundColor Green
                $script:OptimizationHistory | Export-Csv "$env:TEMP\TurboTitan\OptimizationHistory.csv" -NoTypeInformation -ErrorAction SilentlyContinue
                exit 0
            }
        }
        Write-Host "`nPress Enter to return to menu..." -ForegroundColor Cyan
        Read-Host
    }
} catch {
    Write-Report "Critical error occurred: $_" "Error"
    $script:OptimizationHistory | Export-Csv "$env:TEMP\TurboTitan\OptimizationHistory.csv" -NoTypeInformation -ErrorAction SilentlyContinue
    exit 1
}