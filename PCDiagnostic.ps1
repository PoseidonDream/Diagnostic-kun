<#
.SYNOPSIS
    Diagnostic-kun: checks the hardware and software of a Windows 10/11 PC and
    writes a report of anything that looks wrong.

.DESCRIPTION
    Runs a set of read-only checks (it changes nothing on the PC) and rates each
    one OK, Info, Warning or Critical. Results are saved as an HTML report and a
    JSON file. Run as Administrator for complete results; without admin rights
    some checks (disk health counters, BitLocker, TPM, Secure Boot, DISM) are
    skipped and marked as such.

.PARAMETER OutputDir
    Folder for the reports. Defaults to a "Reports" folder next to this script.

.PARAMETER Days
    How many days of event logs to look through. Default 7.

.PARAMETER Quick
    Skips the slower checks (DISM component store check, network tests).

.PARAMETER NoOpen
    Do not open the HTML report when finished.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\PCDiagnostic.ps1
    powershell -ExecutionPolicy Bypass -File .\PCDiagnostic.ps1 -Days 30 -Quick
#>
[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path $PSScriptRoot 'Reports'),
    [ValidateRange(1, 365)][int]$Days = 7,
    [switch]$Quick,
    [switch]$NoOpen
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Thresholds - adjust here to make the tool stricter or more lenient.
# ---------------------------------------------------------------------------
$T = @{
    DiskFreeWarnPct     = 15     # volume free space below this % -> Warning
    DiskFreeCritPct     = 5      # volume free space below this % -> Critical
    DiskFreeCritGB      = 2      # or below this many GB -> Critical
    DiskWearWarnPct     = 80     # SSD wear above this % -> Warning
    DiskWearCritPct     = 95
    DiskTempWarnC       = 60
    DiskTempCritC       = 70
    CpuLoadWarnPct      = 85     # sustained CPU load over the sample
    MemUsedWarnPct      = 85
    MemUsedCritPct      = 95
    ThermalWarnC        = 85
    ThermalCritC        = 95
    BatteryWearWarnPct  = 30     # capacity lost vs design
    BatteryWearCritPct  = 50
    UptimeWarnDays      = 14
    UpdateWarnDays      = 45     # no update installed in this many days
    UpdateCritDays      = 90
    DefSigWarnDays      = 3      # antivirus signatures older than this
    DefSigCritDays      = 7
    DriverOldYears      = 5      # GPU driver older than this -> Warning
    AppCrashWarn        = 5      # app crashes in the window
    TempFolderWarnGB    = 5
    StartupItemsWarn    = 15
    PingLossWarnPct     = 25
    PingLatencyWarnMs   = 150
}

$script:Results = New-Object System.Collections.Generic.List[object]
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Since = (Get-Date).AddDays(-$Days)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('OK', 'Info', 'Warning', 'Critical', 'Skipped', 'Error')][string]$Status,
        [string]$Detail = '',
        [string]$Fix = ''
    )
    $script:Results.Add([pscustomobject]@{
        Category = $Category
        Check    = $Check
        Status   = $Status
        Detail   = $Detail
        Fix      = $Fix
    })
}

# Runs one check block; any unexpected failure becomes an "Error" row instead
# of stopping the whole run.
function Invoke-Check {
    param([string]$Category, [string]$Name, [scriptblock]$Body)
    Write-Host ("  {0,-12} {1}" -f $Category, $Name) -ForegroundColor DarkGray
    try { & $Body }
    catch {
        Add-Result $Category $Name 'Error' ("Check could not run: " + $_.Exception.Message)
    }
}

function Get-Cim {
    param([string]$Class, [string]$Namespace = 'root/cimv2', [string]$Filter)
    $p = @{ ClassName = $Class; Namespace = $Namespace; ErrorAction = 'Stop' }
    if ($Filter) { $p.Filter = $Filter }
    Get-CimInstance @p
}

function Format-GB { param([double]$Bytes) '{0:N1} GB' -f ($Bytes / 1GB) }

function Get-Events {
    param([hashtable]$Filter, [int]$Max = 500)
    $Filter.StartTime = $Since
    try { $ev = @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
    catch {
        # No matching events, or the provider/log does not exist on this PC.
        # Match the error id, which is not translated, rather than the localized message.
        if ($_.FullyQualifiedErrorId -match '^NoMatching(Events|Providers|Logs)Found' -or
            $_.Exception.Message -match 'No events were found|not an event provider|no event log') { $ev = @() } else { throw }
    }
    # The leading comma stops PowerShell unrolling a 0- or 1-item array into $null or a
    # single object, so callers can always use .Count and [0].
    return , $ev
}

# Shows "500+" when a query hit its -MaxEvents limit, so capped counts are not presented as exact.
function Format-Count { param([int]$Count, [int]$Max) if ($Count -ge $Max) { "$Count+" } else { "$Count" } }

# Runs an external program. Windows PowerShell 5.1 turns native stderr into
# terminating errors when ErrorActionPreference is Stop, so relax it here.
function Invoke-Native {
    param([string]$Exe, [string[]]$ArgList)
    $ErrorActionPreference = 'Continue'
    & $Exe @ArgList 2>&1 | ForEach-Object { "$_" }
}

function Skip-NoAdmin { param([string]$Cat, [string]$Name)
    Add-Result $Cat $Name 'Skipped' 'Needs administrator rights.' 'Run RunDiagnostic.bat (it asks for admin rights) for this check.'
}

# ===========================================================================
# SYSTEM OVERVIEW
# ===========================================================================
function Test-SystemInfo {
    $os = Get-Cim Win32_OperatingSystem
    $cs = Get-Cim Win32_ComputerSystem
    $bios = Get-Cim Win32_BIOS
    $bb = $null; try { $bb = Get-Cim Win32_BaseBoard } catch {}

    $script:Overview = [ordered]@{
        'Computer name' = $env:COMPUTERNAME
        'Manufacturer / model' = "$($cs.Manufacturer) $($cs.Model)".Trim()
        'Motherboard' = if ($bb) { "$($bb.Manufacturer) $($bb.Product)".Trim() } else { 'Unknown' }
        'BIOS' = "$($bios.Manufacturer) $($bios.SMBIOSBIOSVersion) ($(if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { '?' }))"
        'Operating system' = "$($os.Caption) $($os.OSArchitecture), version $($os.Version) build $($os.BuildNumber)"
        'Installed' = $os.InstallDate.ToString('yyyy-MM-dd')
        'Last boot' = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
        'Report run as admin' = $script:IsAdmin
    }

    $uptime = (Get-Date) - $os.LastBootUpTime
    $d = [math]::Round($uptime.TotalDays, 1)
    if ($uptime.TotalDays -gt $T.UptimeWarnDays) {
        Add-Result 'System' 'Uptime' 'Warning' "Running for $d days without a restart." 'Restart the PC; long uptimes leave updates pending and memory fragmented.'
    } else { Add-Result 'System' 'Uptime' 'OK' "Up for $d days." }

    # Support status of the Windows build: end-of-servicing dates (Microsoft lifecycle)
    # per build and servicing channel. Home/Pro ("Consumer") and Enterprise/Education
    # get different lengths; LTSC, IoT LTSC and Server have their own long lifecycles.
    $eos = @{
        10240 = @{ LTSC = '2025-10-14' }
        14393 = @{ LTSC = '2026-10-13'; Server = '2027-01-12' }
        17763 = @{ LTSC = '2029-01-09'; Server = '2029-01-09' }
        19044 = @{ Consumer = '2023-06-13'; Enterprise = '2024-06-11'; LTSC = '2027-01-12'; IoT = '2032-01-13' }
        19045 = @{ Consumer = '2025-10-14'; Enterprise = '2025-10-14' }
        20348 = @{ Server = '2031-10-14' }
        22000 = @{ Consumer = '2023-10-10'; Enterprise = '2024-10-08' }
        22621 = @{ Consumer = '2024-10-08'; Enterprise = '2025-10-14' }
        22631 = @{ Consumer = '2025-11-11'; Enterprise = '2026-11-10' }
        26100 = @{ Consumer = '2026-10-13'; Enterprise = '2027-10-12'; LTSC = '2029-10-09'; IoT = '2034-10-10'; Server = '2034-10-10' }
        26200 = @{ Consumer = '2027-10-12'; Enterprise = '2028-10-10' }
    }
    $build = [int]$os.BuildNumber
    $edition = ''
    try { $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID } catch {}
    $channel = if ($os.ProductType -ne 1) { 'Server' }
               elseif ($edition -match '^IoTEnterpriseS') { 'IoT' }
               elseif ($edition -match '^EnterpriseS') { 'LTSC' }
               elseif ($edition -match '^(Enterprise|Education|IoTEnterprise|ServerRdsh)') { 'Enterprise' }
               else { 'Consumer' }
    $end = $null
    if ($eos.ContainsKey($build)) {
        $try = @($channel)
        if ($channel -eq 'IoT') { $try += 'LTSC' }
        if ($channel -in 'IoT', 'LTSC') { $try += 'Enterprise' }
        foreach ($ch in $try) { if ($eos[$build].ContainsKey($ch)) { $end = [datetime]$eos[$build][$ch]; break } }
    }
    $maxKnown = ($eos.Keys | Measure-Object -Maximum).Maximum
    $label = "$($os.Caption) build $build"
    $upgradeFix = 'Install the latest Windows feature update (Settings > Windows Update), or upgrade to a supported release.'
    if (-not $end -and $build -gt $maxKnown) {
        Add-Result 'System' 'Windows version' 'OK' "$label (newer than this tool's support table)."
    } elseif (-not $end) {
        Add-Result 'System' 'Windows version' 'Critical' "$label is an old Windows release that no longer receives security updates." $upgradeFix
    } elseif ($end -lt (Get-Date)) {
        if ($build -eq 19045) {
            Add-Result 'System' 'Windows version' 'Warning' "Windows 10 22H2. Support ended $($end.ToString('yyyy-MM-dd')); updates only continue with Extended Security Updates (ESU)." 'Plan an upgrade to Windows 11 or enrol in Extended Security Updates.'
        } else {
            Add-Result 'System' 'Windows version' 'Critical' "$label - support for this release ended $($end.ToString('yyyy-MM-dd')); it no longer receives security updates." $upgradeFix
        }
    } elseif (($end - (Get-Date)).TotalDays -le 90) {
        Add-Result 'System' 'Windows version' 'Warning' "$label - support ends $($end.ToString('yyyy-MM-dd'))." $upgradeFix
    } else {
        Add-Result 'System' 'Windows version' 'OK' "$label, supported until $($end.ToString('yyyy-MM-dd'))."
    }
}

# ===========================================================================
# HARDWARE
# ===========================================================================
function Test-Cpu {
    $cpus = @(Get-Cim Win32_Processor)
    foreach ($c in $cpus) {
        $info = "$($c.Name.Trim()) - $($c.NumberOfCores) cores / $($c.NumberOfLogicalProcessors) threads, max $($c.MaxClockSpeed) MHz"
        if ($c.Status -ne 'OK') {
            Add-Result 'CPU' 'Processor status' 'Critical' "$info. Windows reports status '$($c.Status)'."
        } else { Add-Result 'CPU' 'Processor' 'OK' $info }

        if ($c.CurrentClockSpeed -and $c.MaxClockSpeed -and $c.CurrentClockSpeed -lt ($c.MaxClockSpeed * 0.5)) {
            Add-Result 'CPU' 'Clock speed' 'Info' "Running at $($c.CurrentClockSpeed) of $($c.MaxClockSpeed) MHz. Normal when idle or on battery saver; if it stays low under load, check power plan and cooling."
        }
    }

    # Sample load over ~5 seconds
    $samples = @()
    for ($i = 0; $i -lt 5; $i++) {
        $samples += (Get-Cim Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        Start-Sleep -Seconds 1
    }
    $avg = [math]::Round(($samples | Measure-Object -Average).Average)
    if ($avg -ge $T.CpuLoadWarnPct) {
        $top = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 |
               ForEach-Object { $_.ProcessName }
        Add-Result 'CPU' 'CPU load' 'Warning' "Average load $avg% over 5 seconds. Heaviest processes overall: $($top -join ', ')." 'Close heavy programs, check Task Manager, scan for malware.'
    } else { Add-Result 'CPU' 'CPU load' 'OK' "Average load $avg% over 5 seconds." }
}

function Test-Thermal {
    if (-not $script:IsAdmin) { Skip-NoAdmin 'CPU' 'Temperature'; return }
    $zones = $null
    try { $zones = @(Get-Cim MSAcpi_ThermalZoneTemperature -Namespace 'root/wmi') } catch {}
    if (-not $zones -or $zones.Count -eq 0) {
        Add-Result 'CPU' 'Temperature' 'Skipped' 'This PC does not expose temperature sensors to Windows (common on desktops).' 'Use the manufacturer tool or HWiNFO for exact temperatures.'
        return
    }
    $temps = $zones | ForEach-Object { [math]::Round(($_.CurrentTemperature / 10) - 273.15, 1) } | Where-Object { $_ -gt 0 -and $_ -lt 150 }
    if (-not $temps) { Add-Result 'CPU' 'Temperature' 'Skipped' 'Sensors returned no usable readings.'; return }
    $max = ($temps | Measure-Object -Maximum).Maximum
    $txt = "Thermal zone readings: $(($temps | ForEach-Object { "$_ C" }) -join ', '). (ACPI zones are approximate.)"
    if ($max -ge $T.ThermalCritC) { Add-Result 'CPU' 'Temperature' 'Critical' $txt 'Clean dust from fans and vents, check the cooler, replace thermal paste.' }
    elseif ($max -ge $T.ThermalWarnC) { Add-Result 'CPU' 'Temperature' 'Warning' $txt 'Check airflow and fans.' }
    else { Add-Result 'CPU' 'Temperature' 'OK' $txt }
}

function Test-Memory {
    $os = Get-Cim Win32_OperatingSystem
    $total = $os.TotalVisibleMemorySize * 1KB
    $free = $os.FreePhysicalMemory * 1KB
    $usedPct = [math]::Round((1 - $free / $total) * 100)
    $txt = "$(Format-GB ($total - $free)) of $(Format-GB $total) in use ($usedPct%)."
    if ($usedPct -ge $T.MemUsedCritPct) { Add-Result 'Memory' 'RAM usage' 'Critical' $txt 'Close programs; if this is normal for you, add more RAM.' }
    elseif ($usedPct -ge $T.MemUsedWarnPct) { Add-Result 'Memory' 'RAM usage' 'Warning' $txt 'Close unused programs and browser tabs.' }
    else { Add-Result 'Memory' 'RAM usage' 'OK' $txt }

    $mods = @(Get-Cim Win32_PhysicalMemory)
    if ($mods.Count -gt 0) {
        $desc = ($mods | ForEach-Object {
            "$($_.DeviceLocator): $(Format-GB $_.Capacity) @ $($_.ConfiguredClockSpeed) MHz ($($_.Manufacturer) $($_.PartNumber))".Trim()
        }) -join '; '
        $speeds = @($mods | Select-Object -ExpandProperty ConfiguredClockSpeed -Unique)
        $sizes = @($mods | Select-Object -ExpandProperty Capacity -Unique)
        if ($speeds.Count -gt 1 -or $sizes.Count -gt 1) {
            Add-Result 'Memory' 'RAM modules' 'Info' "Mixed modules installed - $desc." 'Mismatched sticks can disable dual-channel or cause instability.'
        } else { Add-Result 'Memory' 'RAM modules' 'OK' "$($mods.Count) module(s) - $desc." }
        # Installed capacity, not usable memory (which is reduced by firmware/iGPU reservations)
        $installed = ($mods | Measure-Object -Property Capacity -Sum).Sum
        if ($installed -lt 8GB) {
            Add-Result 'Memory' 'RAM amount' 'Warning' "Only $(Format-GB $installed) RAM installed. Windows 10/11 runs poorly below 8 GB." 'Upgrade RAM if the PC feels slow.'
        }
    }

    # Results of Windows Memory Diagnostic, if it was ever run in the window
    $md = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results' } 5
    if ($md.Count -gt 0) {
        $last = $md[0]
        # 1101/1201 = no errors found, 1102/1202 = errors found
        $st = if ($last.Id -in 1102, 1202) { 'Critical' } elseif ($last.Id -in 1101, 1201) { 'OK' } else { 'Info' }
        Add-Result 'Memory' 'Memory test result' $st "Windows Memory Diagnostic ($($last.TimeCreated.ToString('yyyy-MM-dd'))): $($last.Message)" $(if ($st -eq 'Critical') { 'Replace the failing RAM module.' } else { '' })
    }
}

function Test-Storage {
    # Physical disk health
    $pdisks = $null
    try { $pdisks = @(Get-PhysicalDisk -ErrorAction Stop) } catch {}
    if ($pdisks) {
        foreach ($d in $pdisks) {
            $name = "$($d.FriendlyName) ($($d.MediaType), $(Format-GB $d.Size))"
            $ops = ($d.OperationalStatus | ForEach-Object { "$_" }) -join ', '
            if ($d.HealthStatus -eq 'Unhealthy') {
                Add-Result 'Storage' "Disk health: $($d.FriendlyName)" 'Critical' "$name reports Unhealthy ($ops)." 'Back up NOW and replace this drive.'
            } elseif ($d.HealthStatus -eq 'Warning') {
                Add-Result 'Storage' "Disk health: $($d.FriendlyName)" 'Warning' "$name reports Warning ($ops)." 'Back up your data and plan to replace this drive.'
            } elseif ($d.HealthStatus -eq 'Healthy') {
                Add-Result 'Storage' "Disk health: $($d.FriendlyName)" 'OK' "$name - Healthy."
            } else {
                Add-Result 'Storage' "Disk health: $($d.FriendlyName)" 'Info' "$name - health status '$($d.HealthStatus)': this drive or its controller does not report health." 'Check the drive with the manufacturer tool or CrystalDiskInfo.'
            }

            if ($script:IsAdmin) {
                $rc = $null
                try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
                if ($rc) {
                    $bits = @()
                    $sev = 'OK'; $fix = ''
                    if ($null -ne $rc.Wear) {
                        $bits += "wear $($rc.Wear)%"
                        if ($rc.Wear -ge $T.DiskWearCritPct) { $sev = 'Critical'; $fix = 'SSD is near end of life - back up and replace.' }
                        elseif ($rc.Wear -ge $T.DiskWearWarnPct -and $sev -ne 'Critical') { $sev = 'Warning'; $fix = 'SSD is wearing out - plan a replacement.' }
                    }
                    if ($rc.Temperature) {
                        $bits += "temp $($rc.Temperature) C"
                        if ($rc.Temperature -ge $T.DiskTempCritC) { $sev = 'Critical'; $fix = 'Drive is overheating - improve airflow.' }
                        elseif ($rc.Temperature -ge $T.DiskTempWarnC -and $sev -eq 'OK') { $sev = 'Warning'; $fix = 'Drive runs hot - improve airflow.' }
                    }
                    $errs = 0
                    foreach ($p in 'ReadErrorsUncorrected', 'WriteErrorsUncorrected') { if ($rc.$p) { $errs += $rc.$p } }
                    if ($errs -gt 0) { $bits += "$errs uncorrected read/write errors"; $sev = 'Critical'; $fix = 'Uncorrected errors mean data loss risk - back up and replace the drive.' }
                    if ($rc.PowerOnHours) { $bits += "$($rc.PowerOnHours) power-on hours" }
                    if ($bits.Count -gt 0) {
                        Add-Result 'Storage' "Disk counters: $($d.FriendlyName)" $sev ($bits -join ', ') $fix
                    }
                }
            }
        }
    } else {
        Add-Result 'Storage' 'Disk health' 'Skipped' 'Storage module unavailable on this system.'
    }

    # SMART failure prediction (older but widely supported)
    if ($script:IsAdmin) {
        try {
            $smart = @(Get-Cim MSStorageDriver_FailurePredictStatus -Namespace 'root/wmi')
            $bad = @($smart | Where-Object { $_.PredictFailure })
            if ($bad.Count -gt 0) {
                Add-Result 'Storage' 'SMART failure prediction' 'Critical' "$($bad.Count) drive(s) predict failure: $(($bad | ForEach-Object { $_.InstanceName }) -join '; ')." 'Back up immediately and replace the drive.'
            } elseif ($smart.Count -gt 0) {
                Add-Result 'Storage' 'SMART failure prediction' 'OK' "$($smart.Count) drive(s) report no predicted failure."
            }
        } catch { }   # not supported by many NVMe drivers - counters above cover it
    }

    # Free space per volume
    $vols = @(Get-Cim Win32_LogicalDisk -Filter 'DriveType=3')
    foreach ($v in $vols) {
        if (-not $v.Size) { continue }
        $pct = [math]::Round($v.FreeSpace / $v.Size * 100, 1)
        $txt = "$($v.DeviceID) $(Format-GB $v.FreeSpace) free of $(Format-GB $v.Size) ($pct%)."
        $fix = 'Run Disk Cleanup (cleanmgr), empty the Recycle Bin, uninstall unused programs, or move files to another drive.'
        if ($pct -lt $T.DiskFreeCritPct -or $v.FreeSpace -lt ($T.DiskFreeCritGB * 1GB)) { Add-Result 'Storage' "Free space $($v.DeviceID)" 'Critical' $txt $fix }
        elseif ($pct -lt $T.DiskFreeWarnPct) { Add-Result 'Storage' "Free space $($v.DeviceID)" 'Warning' $txt $fix }
        else { Add-Result 'Storage' "Free space $($v.DeviceID)" 'OK' $txt }
    }

    # File system dirty bit (read from WMI rather than parsing fsutil's translated output)
    if ($script:IsAdmin) {
        foreach ($wv in @(Get-Cim Win32_Volume -Filter 'DriveType=3')) {
            if ($wv.DirtyBitSet -and $wv.DriveLetter) {
                Add-Result 'Storage' "File system $($wv.DriveLetter)" 'Warning' "Volume $($wv.DriveLetter) is marked dirty (file system errors suspected)." "Run: chkdsk $($wv.DriveLetter) /f  (may need a restart)."
            }
        }
    }

    # Disk errors in the System log
    $diskEv = Get-Events @{ LogName = 'System'; Id = 7, 11, 51, 52, 55, 98, 129, 153, 157; Level = 1, 2, 3 } 300
    $diskEv = @($diskEv | Where-Object { $_.ProviderName -match '^(disk|Ntfs|Microsoft-Windows-Ntfs|stornvme|storahci|iaStor\w*|nvme\w*|volmgr)$' })
    if ($diskEv.Count -gt 0) {
        $groups = ($diskEv | Group-Object Id | ForEach-Object { "ID $($_.Name) x$($_.Count)" }) -join ', '
        $sev = if (@($diskEv | Where-Object { $_.Id -in 7, 11, 55 }).Count -gt 0) { 'Critical' } else { 'Warning' }
        Add-Result 'Storage' 'Disk errors in event log' $sev "$($diskEv.Count) disk/controller errors in the last $Days days ($groups). Latest: $($diskEv[0].TimeCreated.ToString('yyyy-MM-dd HH:mm'))." 'ID 7 = bad block, 11 = controller error, 55 = file system corruption, 129/153 = timeouts. Back up, check cables, run chkdsk, update storage drivers.'
    } else { Add-Result 'Storage' 'Disk errors in event log' 'OK' "No disk errors in the last $Days days." }
}

function Test-Gpu {
    $gpus = @(Get-Cim Win32_VideoController)
    foreach ($g in $gpus) {
        $drvDate = $g.DriverDate
        $age = if ($drvDate) { [math]::Round(((Get-Date) - $drvDate).TotalDays / 365, 1) } else { $null }
        $vram = if ($g.AdapterRAM -and $g.AdapterRAM -gt 0) { ", $(Format-GB ([uint32]$g.AdapterRAM))+ VRAM" } else { '' }
        $txt = "$($g.Name)$vram, driver $($g.DriverVersion)$(if ($drvDate) { ' (' + $drvDate.ToString('yyyy-MM-dd') + ')' })"
        if ($g.ConfigManagerErrorCode -ne 0 -or $g.Status -ne 'OK') {
            Add-Result 'Graphics' "GPU: $($g.Name)" 'Critical' "$txt - device error code $($g.ConfigManagerErrorCode), status $($g.Status)." 'Reinstall the graphics driver from the GPU maker (NVIDIA / AMD / Intel).'
        } elseif ($g.Name -match 'Basic Display|Basic Render') {
            Add-Result 'Graphics' "GPU: $($g.Name)" 'Warning' "$txt - Windows is using the generic display driver." 'Install the proper graphics driver from your GPU or PC maker.'
        } elseif ($null -ne $age -and $age -gt $T.DriverOldYears) {
            Add-Result 'Graphics' "GPU: $($g.Name)" 'Warning' "$txt - driver is $age years old." 'Update the graphics driver.'
        } else { Add-Result 'Graphics' "GPU: $($g.Name)" 'OK' $txt }
    }

    $tdr = Get-Events @{ LogName = 'System'; Id = 4101 } 50
    if ($tdr.Count -gt 0) {
        Add-Result 'Graphics' 'Display driver resets' 'Warning' "Display driver stopped responding and recovered $($tdr.Count) time(s) in the last $Days days." 'Update/clean-install the graphics driver; check GPU temperature and overclocks.'
    }
}

function Test-Battery {
    $bat = @(); try { $bat = @(Get-Cim Win32_Battery) } catch {}
    if ($bat.Count -eq 0) { Add-Result 'Power' 'Battery' 'Info' 'No battery (desktop PC).'; return }
    foreach ($b in $bat) {
        Add-Result 'Power' 'Battery charge' 'Info' "$($b.EstimatedChargeRemaining)% charged."
    }
    if (-not $script:IsAdmin) { Skip-NoAdmin 'Power' 'Battery wear'; return }
    try {
        $design = @(Get-Cim BatteryStaticData -Namespace 'root/wmi')
        $full = @(Get-Cim BatteryFullChargedCapacity -Namespace 'root/wmi')
        for ($i = 0; $i -lt [math]::Min($design.Count, $full.Count); $i++) {
            $dc = $design[$i].DesignedCapacity; $fc = $full[$i].FullChargedCapacity
            if ($dc -gt 0) {
                $wear = [math]::Round((1 - $fc / $dc) * 100)
                if ($wear -lt 0) { $wear = 0 }
                $txt = "Holds $fc of $dc mWh design capacity ($wear% worn)."
                if ($wear -ge $T.BatteryWearCritPct) { Add-Result 'Power' 'Battery wear' 'Critical' $txt 'Replace the battery.' }
                elseif ($wear -ge $T.BatteryWearWarnPct) { Add-Result 'Power' 'Battery wear' 'Warning' $txt 'Battery is aging; expect shorter runtime.' }
                else { Add-Result 'Power' 'Battery wear' 'OK' $txt }
            }
        }
    } catch { Add-Result 'Power' 'Battery wear' 'Skipped' 'Battery capacity data not available. Try: powercfg /batteryreport' }
}

function Test-Devices {
    $codes = @{
        1 = 'not configured correctly'; 3 = 'driver may be corrupted'; 10 = 'cannot start'
        12 = 'not enough free resources'; 14 = 'needs a restart'; 18 = 'drivers need reinstalling'
        19 = 'registry information corrupted'; 21 = 'being removed'; 22 = 'disabled'
        24 = 'not present / not working'; 28 = 'driver not installed'; 31 = 'not working properly'
        32 = 'driver service disabled'; 39 = 'driver corrupted or missing'; 43 = 'stopped after reporting problems'
        45 = 'not connected'; 48 = 'driver blocked'; 52 = 'driver signature not verified'
    }
    $bad = @(Get-Cim Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' |
             Where-Object { $_.ConfigManagerErrorCode -notin 22, 45 })   # disabled / unplugged are not faults
    if ($bad.Count -eq 0) { Add-Result 'Devices' 'Device Manager' 'OK' 'All devices report working.'; return }
    foreach ($d in $bad) {
        $c = [int]$d.ConfigManagerErrorCode
        $why = if ($codes.ContainsKey($c)) { $codes[$c] } else { 'error' }
        $name = if ($d.Name) { $d.Name } else { $d.DeviceID }
        $sev = if ($c -in 28, 1) { 'Warning' } else { 'Critical' }
        Add-Result 'Devices' "Device: $name" $sev "Code $c - $why." 'Open Device Manager, right-click the device > Update driver, or download the driver from the maker.'
    }
}

function Test-HardwareErrors {
    $whea = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger' } 200
    $fatal = @($whea | Where-Object { $_.Level -le 2 })
    if ($fatal.Count -gt 0) {
        Add-Result 'Stability' 'Hardware errors (WHEA)' 'Critical' "$($fatal.Count) fatal hardware error(s) and $($whea.Count - $fatal.Count) corrected in the last $Days days. Latest: $($fatal[0].TimeCreated.ToString('yyyy-MM-dd HH:mm'))." 'Usually CPU, RAM, PCIe or overclock instability. Remove overclocks/XMP, test RAM (mdsched), update BIOS.'
    } elseif ($whea.Count -gt 20) {
        Add-Result 'Stability' 'Hardware errors (WHEA)' 'Warning' "$($whea.Count) corrected hardware errors in the last $Days days." 'Often a PCIe link issue; update chipset drivers and BIOS.'
    } else { Add-Result 'Stability' 'Hardware errors (WHEA)' 'OK' "$($whea.Count) corrected / 0 fatal hardware errors." }

    $bsod = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001 } 50
    $power = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41 } 50
    if ($bsod.Count -gt 0) {
        $codes = ($bsod | ForEach-Object { if ($_.Message -match '0x[0-9a-fA-F]{8}') { $Matches[0] } } | Select-Object -Unique) -join ', '
        Add-Result 'Stability' 'Blue screens' 'Critical' "$($bsod.Count) blue screen crash(es) in the last $Days days. Bug check codes: $codes." 'Look up the code; common causes are drivers, RAM and overheating. Dumps are in C:\Windows\Minidump.'
    } else { Add-Result 'Stability' 'Blue screens' 'OK' "No blue screens in the last $Days days." }
    if ($power.Count -gt 0) {
        Add-Result 'Stability' 'Unexpected shutdowns' 'Warning' "$($power.Count) unexpected power loss / hard reset(s) in the last $Days days." 'Check the power supply, cables and temperatures; also logged after holding the power button.'
    }

    $dumps = @(Get-ChildItem "$env:SystemRoot\Minidump" -Filter *.dmp -ErrorAction SilentlyContinue)
    if ($dumps.Count -gt 0) {
        $latest = ($dumps | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
        Add-Result 'Stability' 'Crash dump files' 'Info' "$($dumps.Count) crash dump(s) in $env:SystemRoot\Minidump, latest $($latest.ToString('yyyy-MM-dd'))."
    }
}

# ===========================================================================
# SOFTWARE / OS HEALTH
# ===========================================================================
function Test-WindowsUpdate {
    $pending = @()
    $keys = @{
        'Windows Update'      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        'Component servicing' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    }
    foreach ($k in $keys.Keys) { if (Test-Path $keys[$k]) { $pending += $k } }
    try {
        $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations
        if ($pfro) { $pending += 'File rename operations' }
    } catch {}
    if ($pending.Count -gt 0) {
        Add-Result 'Updates' 'Pending restart' 'Warning' "A restart is pending ($($pending -join ', '))." 'Restart the PC to finish installing updates.'
    } else { Add-Result 'Updates' 'Pending restart' 'OK' 'No restart pending.' }

    $hf = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    if ($hf.Count -gt 0) {
        $last = $hf[0].InstalledOn
        $age = [math]::Round(((Get-Date) - $last).TotalDays)
        $txt = "Last update installed $($last.ToString('yyyy-MM-dd')) ($age days ago, $($hf[0].HotFixID))."
        if ($age -ge $T.UpdateCritDays) { Add-Result 'Updates' 'Windows Update' 'Critical' $txt 'Open Settings > Windows Update and install updates.' }
        elseif ($age -ge $T.UpdateWarnDays) { Add-Result 'Updates' 'Windows Update' 'Warning' $txt 'Open Settings > Windows Update and check for updates.' }
        else { Add-Result 'Updates' 'Windows Update' 'OK' $txt }
    }

    $wuFail = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 20 } 50
    if ($wuFail.Count -gt 0) {
        Add-Result 'Updates' 'Failed updates' 'Warning' "$($wuFail.Count) update installation failure(s) in the last $Days days." 'Run the Windows Update troubleshooter (Settings > System > Troubleshoot).'
    }

    $wu = Get-Service wuauserv -ErrorAction SilentlyContinue
    if ($wu -and $wu.StartType -eq 'Disabled') {
        Add-Result 'Updates' 'Update service' 'Critical' 'The Windows Update service is disabled.' 'Set "Windows Update" service to Manual in services.msc.'
    }
}

function Test-Security {
    # Antivirus
    $mp = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}   # fails when the Defender service is stopped/disabled
    if (-not $mp -or -not $mp.AntivirusEnabled -or -not $mp.RealTimeProtectionEnabled) {
        # Defender is off or cannot be queried: look for another antivirus that is actually turned on.
        # productState bit 0x1000 = real-time protection on, bit 0x10 = signatures out of date.
        $other = @()
        try { $other = @(Get-Cim AntiVirusProduct -Namespace 'root/SecurityCenter2' | Where-Object { $_.displayName -notmatch 'Defender' }) } catch {}
        $on = @($other | Where-Object { ([int64]$_.productState -band 0x1000) -ne 0 })
        $stale = @($on | Where-Object { ([int64]$_.productState -band 0x10) -ne 0 })
        if ($stale.Count -gt 0) {
            Add-Result 'Security' 'Antivirus' 'Warning' "Third-party antivirus is on but its signatures are out of date: $(($stale.displayName) -join ', ')." 'Open the antivirus program and update it, or renew its subscription.'
        } elseif ($on.Count -gt 0) {
            Add-Result 'Security' 'Antivirus' 'OK' "Third-party antivirus active: $(($on.displayName) -join ', ')."
        } elseif (-not $mp) {
            $offNote = if ($other.Count -gt 0) { " ($(($other.displayName) -join ', ') is installed but turned off)" } else { '' }
            Add-Result 'Security' 'Antivirus' 'Critical' "Microsoft Defender could not be queried (its service may be stopped) and no active antivirus was found$offNote." 'Open Windows Security > Virus & threat protection and turn protection on, or re-enable your antivirus.'
        } else {
            $offNote = if ($other.Count -gt 0) { " ($(($other.displayName) -join ', ') is installed but turned off)" } else { '' }
            Add-Result 'Security' 'Antivirus' 'Critical' "Microsoft Defender real-time protection is off and no other active antivirus was found$offNote." 'Turn on real-time protection in Windows Security.'
        }
    } else {
        $sigAge = [math]::Round(((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays, 1)
        $txt = "Microsoft Defender on. Signatures $sigAge day(s) old."
        if ($sigAge -ge $T.DefSigCritDays) { Add-Result 'Security' 'Antivirus' 'Critical' $txt 'Update signatures: Windows Security > Virus protection > Check for updates.' }
        elseif ($sigAge -ge $T.DefSigWarnDays) { Add-Result 'Security' 'Antivirus' 'Warning' $txt 'Update antivirus signatures.' }
        else { Add-Result 'Security' 'Antivirus' 'OK' $txt }
    }
    if ($mp) {
        $threats = @()
        try { $threats = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $Since }) } catch {}
        if ($threats.Count -gt 0) {
            $active = @($threats | Where-Object { $_.ThreatStatusID -notin 2, 3, 4, 5, 6 })   # not removed/quarantined/allowed
            $sev = if ($active.Count -gt 0) { 'Critical' } else { 'Warning' }
            Add-Result 'Security' 'Malware detections' $sev "$($threats.Count) threat detection(s) in the last $Days days, $($active.Count) not yet resolved." 'Open Windows Security > Protection history and run a full scan.'
        } else { Add-Result 'Security' 'Malware detections' 'OK' "No threats detected in the last $Days days." }
    }

    # Firewall
    try {
        $off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled })
        if ($off.Count -gt 0) {
            Add-Result 'Security' 'Firewall' 'Critical' "Firewall is OFF for profile(s): $(($off.Name) -join ', ')." 'Turn the firewall on in Windows Security > Firewall & network protection.'
        } else { Add-Result 'Security' 'Firewall' 'OK' 'Firewall enabled for all profiles.' }
    } catch { Add-Result 'Security' 'Firewall' 'Error' 'Could not read firewall state.' }

    # UAC
    try {
        $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop).EnableLUA
        if ($uac -eq 0) { Add-Result 'Security' 'User Account Control' 'Critical' 'UAC is disabled.' 'Re-enable UAC in Control Panel > User Accounts.' }
        else { Add-Result 'Security' 'User Account Control' 'OK' 'UAC enabled.' }
    } catch {}

    if ($script:IsAdmin) {
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            if ($sb) { Add-Result 'Security' 'Secure Boot' 'OK' 'Secure Boot is on.' }
            else { Add-Result 'Security' 'Secure Boot' 'Warning' 'Secure Boot is off.' 'Enable Secure Boot in the UEFI/BIOS settings.' }
        } catch { Add-Result 'Security' 'Secure Boot' 'Info' 'Secure Boot not supported (legacy BIOS mode).' }

        try {
            $tpm = Get-Tpm -ErrorAction Stop
            if (-not $tpm.TpmPresent) { Add-Result 'Security' 'TPM' 'Warning' 'No TPM chip found (required for Windows 11 and BitLocker).' 'Enable TPM / fTPM / PTT in UEFI settings.' }
            elseif (-not $tpm.TpmReady) { Add-Result 'Security' 'TPM' 'Warning' 'TPM present but not ready.' 'Open tpm.msc to initialise it.' }
            else { Add-Result 'Security' 'TPM' 'OK' 'TPM present and ready.' }
        } catch { Add-Result 'Security' 'TPM' 'Skipped' 'Could not query TPM.' }

        try {
            $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            if ($bl.ProtectionStatus -eq 'On') { Add-Result 'Security' 'Drive encryption' 'OK' "BitLocker protecting $env:SystemDrive." }
            else { Add-Result 'Security' 'Drive encryption' 'Info' "System drive is not encrypted (BitLocker $($bl.VolumeStatus))." 'Consider BitLocker / Device Encryption, especially on laptops.' }
        } catch { Add-Result 'Security' 'Drive encryption' 'Info' 'BitLocker not available on this Windows edition.' }
    } else {
        Skip-NoAdmin 'Security' 'Secure Boot / TPM / BitLocker'
    }

    # Activation
    try {
        $lic = @(Get-Cim SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'")
        if (@($lic | Where-Object { $_.LicenseStatus -eq 1 }).Count -gt 0) { Add-Result 'Security' 'Windows activation' 'OK' 'Windows is activated.' }
        else { Add-Result 'Security' 'Windows activation' 'Warning' 'Windows is not activated.' 'Settings > System > Activation.' }
    } catch {}
}

function Test-SystemFiles {
    if (-not $script:IsAdmin) { Skip-NoAdmin 'OS Health' 'Component store (DISM)'; return }
    if ($Quick) { Add-Result 'OS Health' 'Component store (DISM)' 'Skipped' 'Skipped in -Quick mode.'; return }
    $out = (Invoke-Native 'dism.exe' @('/Online', '/Cleanup-Image', '/CheckHealth', '/English')) -join "`n"
    if ($out -match 'No component store corruption detected') {
        Add-Result 'OS Health' 'Component store (DISM)' 'OK' 'No Windows component corruption detected.'
    } elseif ($out -match 'repairable') {
        Add-Result 'OS Health' 'Component store (DISM)' 'Critical' 'Windows system files are flagged as corrupted (repairable).' 'Run as admin: DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow'
    } else {
        $tail = ($out -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -Last 2) -join ' '
        Add-Result 'OS Health' 'Component store (DISM)' 'Warning' "DISM result unclear: $tail"
    }

    # Last SFC result, if CBS.log shows a recent run
    $cbs = "$env:SystemRoot\Logs\CBS\CBS.log"
    if (Test-Path $cbs) {
        $hit = Select-String -Path $cbs -Pattern 'found corrupt files and (was unable|successfully)' -ErrorAction SilentlyContinue | Select-Object -Last 1
        if ($hit -and $hit.Line -match 'unable') {
            Add-Result 'OS Health' 'Last SFC scan' 'Critical' 'The last sfc /scannow found corrupt files it could not fix.' 'Run DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow again.'
        }
    }
}

function Test-Services {
    # Auto-start services that are not running (ignoring ones that normally stop by design)
    $ignore = 'gupdate|edgeupdate|MapsBroker|RemoteRegistry|sppsvc|WbioSrvc|TrustedInstaller|GoogleUpdater|BITS|wuauserv|ShellHWDetection|tiledatamodelsvc|CDPSvc|clr_optimization|dbupdate|UsoSvc|WaaSMedicSvc|WMPNetworkSvc|DoSvc|Intel.*Update|VSStandardCollector'
    # Per-user service templates (registry Type has 0x40 set, e.g. CDPUserSvc) never run
    # themselves; their CDPUserSvc_xxxxx instances do.
    $isUserTemplate = {
        param($n)
        try { ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$n" -Name Type -ErrorAction Stop).Type -band 0x40) -ne 0 } catch { $false }
    }
    # ExitCode 0 = the service stopped cleanly on its own (trigger-start services do this).
    $svc = @(Get-Cim Win32_Service -Filter "StartMode='Auto' AND State<>'Running' AND ExitCode<>0" |
             Where-Object { $_.Name -notmatch $ignore -and $_.DelayedAutoStart -ne $true -and -not (& $isUserTemplate $_.Name) })
    $critical = 'EventLog|Winmgmt|RpcSs|Dhcp|Dnscache|LanmanWorkstation|mpssvc|WinDefend|CryptSvc|Audiosrv|AudioEndpointBuilder|Schedule|Themes|nsi|BFE|ProfSvc|Power|PlugPlay'
    foreach ($s in $svc) {
        $sev = if ($s.Name -match "^($critical)$") { 'Critical' } else { 'Warning' }
        Add-Result 'Services' "Service stopped: $($s.DisplayName)" $sev "Set to start automatically but is $($s.State) (exit code $($s.ExitCode))." "Try: Start-Service $($s.Name)  or restart the PC."
    }
    if ($svc.Count -eq 0) { Add-Result 'Services' 'Automatic services' 'OK' 'All automatic services are running.' }

    $svcCrash = Get-Events @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7031, 7034 } 200
    if ($svcCrash.Count -gt 3) {
        # Event property 0 is the service name (language-independent, unlike the message text)
        $names = ($svcCrash | ForEach-Object { if ($_.Properties.Count -gt 0) { [string]$_.Properties[0].Value } } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
        Add-Result 'Services' 'Service crashes' 'Warning' "$(Format-Count $svcCrash.Count 200) unexpected service terminations in the last $Days days: $names." 'Update or reinstall the software that owns these services.'
    }
}

function Test-AppCrashes {
    $crashes = Get-Events @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000 } 500
    $hangs = Get-Events @{ LogName = 'Application'; ProviderName = 'Application Hang'; Id = 1002 } 500
    $all = @($crashes) + @($hangs)
    if ($all.Count -eq 0) { Add-Result 'Applications' 'Program crashes' 'OK' "No program crashes in the last $Days days."; return }
    $byApp = $all | ForEach-Object { if ($_.Properties.Count -gt 0) { [string]$_.Properties[0].Value } } |
             Group-Object | Sort-Object Count -Descending | Select-Object -First 8
    $list = ($byApp | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
    $sev = if ($all.Count -ge $T.AppCrashWarn) { 'Warning' } else { 'Info' }
    Add-Result 'Applications' 'Program crashes' $sev "$(Format-Count $crashes.Count 500) crash(es) and $(Format-Count $hangs.Count 500) hang(s) in the last $Days days: $list." 'Update or reinstall the programs that crash most often.'
}

function Test-Startup {
    $items = @()
    try { $items = @(Get-Cim Win32_StartupCommand) } catch {}
    # Respect items the user disabled in Task Manager
    $disabled = @{}
    foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
                   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder') {
        if (Test-Path $k) {
            $p = Get-ItemProperty $k
            foreach ($n in ($p.PSObject.Properties | Where-Object { $_.Value -is [byte[]] })) {
                if ($n.Value[0] -band 1) { $disabled[$n.Name] = $true }
            }
        }
    }
    $enabled = @($items | Where-Object { -not $disabled.ContainsKey($_.Name) -and -not $disabled.ContainsKey("$($_.Name).lnk") })
    $names = ($enabled | Select-Object -ExpandProperty Name -Unique) -join ', '
    if ($enabled.Count -ge $T.StartupItemsWarn) {
        Add-Result 'Applications' 'Startup programs' 'Warning' "$($enabled.Count) programs start with Windows: $names." 'Disable ones you do not need in Task Manager > Startup apps.'
    } else { Add-Result 'Applications' 'Startup programs' 'OK' "$($enabled.Count) startup program(s): $names." }
}

function Test-InstalledSoftware {
    $paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
             'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $apps = @(Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -and -not ($_.PSObject.Properties['SystemComponent'] -and $_.SystemComponent -eq 1) })
    $script:InstalledApps = $apps | Sort-Object DisplayName -Unique | ForEach-Object {
        [pscustomobject]@{
            Name      = $_.DisplayName
            Version   = if ($_.PSObject.Properties['DisplayVersion']) { $_.DisplayVersion } else { '' }
            Publisher = if ($_.PSObject.Properties['Publisher']) { $_.Publisher } else { '' }
        }
    }
    Add-Result 'Applications' 'Installed programs' 'Info' "$(@($script:InstalledApps).Count) programs installed (full list at the end of the report)."

    # Known end-of-life / risky software
    $eol = @(
        @{ P = '^Adobe Flash'; W = 'Adobe Flash Player is discontinued and insecure.' },
        # Major version only, e.g. "Java 7 Update 80", "Java(TM) SE Development Kit 6 Update 45" (not "JDK 17.0.6")
        @{ P = '^Java(\(TM\))?( SE (Development Kit|Runtime Environment))? (6|7) Update\b'; W = 'Very old Java runtime with known security holes.' },
        @{ P = '^Microsoft Silverlight'; W = 'Silverlight is discontinued.' },
        @{ P = '^Python 2\.'; W = 'Python 2 is end-of-life.' },
        @{ P = '^Microsoft Office.*20(07|10|13)'; W = 'This Office version no longer receives security updates.' },
        @{ P = '^QuickTime'; W = 'QuickTime for Windows is discontinued and has unpatched flaws.' }
    )
    foreach ($e in $eol) {
        $hit = @($script:InstalledApps | Where-Object { $_.Name -match $e.P })
        foreach ($h in $hit) {
            Add-Result 'Applications' "Outdated: $($h.Name)" 'Warning' $e.W 'Uninstall it unless you specifically need it.'
        }
    }
}

function Test-Drivers {
    # Unsigned drivers loaded (signature check on running kernel drivers)
    try {
        $unsigned = @(Get-Cim Win32_PnPSignedDriver | Where-Object { $_.DeviceName -and $_.IsSigned -eq $false })
        if ($unsigned.Count -gt 0) {
            Add-Result 'Drivers' 'Unsigned drivers' 'Warning' "$($unsigned.Count) unsigned driver(s): $(($unsigned | Select-Object -ExpandProperty DeviceName -Unique) -join ', ')." 'Replace with signed drivers from the hardware maker.'
        } else { Add-Result 'Drivers' 'Driver signatures' 'OK' 'All device drivers are signed.' }
    } catch {}

    $drvFail = Get-Events @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7000, 7026 } 100
    if ($drvFail.Count -gt 0) {
        Add-Result 'Drivers' 'Drivers failing to load' 'Warning' "$($drvFail.Count) driver/service load failure(s) in the last $Days days. Latest: $(($drvFail[0].Message -split "`n")[0])" 'Reinstall or remove the software that installed the failing driver.'
    }
}

function Test-SystemEvents {
    # Fetch more errors than the warning threshold so the threshold can always be reached
    $errMax = [math]::Max(1000, 20 * $Days + 1)
    $crit = Get-Events @{ LogName = 'System'; Level = 1 } 200
    $err = Get-Events @{ LogName = 'System'; Level = 2 } $errMax
    $top = ($err | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
    $txt = "$(Format-Count $crit.Count 200) critical and $(Format-Count $err.Count $errMax) error events in the System log over $Days days. Top sources: $top."
    if ($crit.Count -gt 0) { Add-Result 'OS Health' 'System event log' 'Warning' $txt 'Open Event Viewer > Windows Logs > System for details. Specific causes are listed in other sections.' }
    elseif ($err.Count -gt (20 * $Days)) { Add-Result 'OS Health' 'System event log' 'Warning' $txt 'An unusually high error rate; check the top sources.' }
    else { Add-Result 'OS Health' 'System event log' 'OK' $txt }
}

function Test-Housekeeping {
    # Temp folders
    $size = 0
    foreach ($p in @($env:TEMP, "$env:SystemRoot\Temp") | Select-Object -Unique) {
        $size += (Get-ChildItem $p -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    }
    if ($size -ge ($T.TempFolderWarnGB * 1GB)) {
        Add-Result 'OS Health' 'Temporary files' 'Warning' "$(Format-GB $size) in temp folders." 'Settings > System > Storage > Temporary files, or run cleanmgr.'
    } else { Add-Result 'OS Health' 'Temporary files' 'OK' "$(Format-GB $size) in temp folders." }

    # Page file
    $pf = @(Get-Cim Win32_PageFileUsage)
    if ($pf.Count -eq 0) {
        Add-Result 'OS Health' 'Page file' 'Warning' 'No page file configured. Programs may crash when RAM runs out, and crash dumps cannot be written.' 'System Properties > Advanced > Performance > Virtual memory: let Windows manage it.'
    } else {
        foreach ($p in $pf) {
            $pct = if ($p.AllocatedBaseSize) { [math]::Round($p.PeakUsage / $p.AllocatedBaseSize * 100) } else { 0 }
            $st = if ($pct -ge 90) { 'Warning' } else { 'OK' }
            Add-Result 'OS Health' 'Page file' $st "$($p.Name): $($p.AllocatedBaseSize) MB, peak use $pct%." $(if ($st -ne 'OK') { 'Page file nearly full at peak; add RAM or enlarge the page file.' } else { '' })
        }
    }

    # Time sync (service state via Get-Service, which is not translated; w32tm text is English-only)
    try {
        $w32svc = Get-Service W32Time -ErrorAction SilentlyContinue
        $w32 = (Invoke-Native 'w32tm.exe' @('/query', '/status')) -join "`n"
        # On home PCs the service is trigger-started and is often stopped between syncs; only Disabled is a fault.
        if ($w32svc -and $w32svc.StartType -eq 'Disabled') {
            Add-Result 'OS Health' 'Clock sync' 'Warning' 'Windows Time service is disabled; the clock may drift and break HTTPS/logins.' 'Set the "Windows Time" service to Manual in services.msc, then sync in Settings > Time & language.'
        } elseif ($w32 -match 'Last Successful Sync Time:\s*(.+)') {
            $ls = $Matches[1].Trim()
            $dt = [datetime]::MinValue
            if ([datetime]::TryParse($ls, [ref]$dt) -and ((Get-Date) - $dt).TotalDays -gt 14) {
                Add-Result 'OS Health' 'Clock sync' 'Warning' "Clock last synced $ls." 'Settings > Time & language > Sync now.'
            } else { Add-Result 'OS Health' 'Clock sync' 'OK' "Last time sync: $ls." }
        }
    } catch {}

    # Power plan
    try {
        $plan = (Invoke-Native 'powercfg.exe' @('/getactivescheme')) -join ''
        if ($plan -match '\((.+)\)') {
            $name = $Matches[1]
            # Match the built-in Power saver plan by its GUID; plan names are translated
            if ($plan -match 'a1841308-3541-4fab-bc81-f71556f20b4a') { Add-Result 'Power' 'Power plan' 'Info' "Active plan: $name - performance is reduced." 'Switch to Balanced if the PC feels slow.' }
            else { Add-Result 'Power' 'Power plan' 'OK' "Active plan: $name." }
        }
    } catch {}
}

function Test-Network {
    $up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and -not $_.Virtual })
    if ($up.Count -eq 0) {
        Add-Result 'Network' 'Network adapter' 'Critical' 'No physical network adapter is connected.' 'Check the cable / Wi-Fi connection and network drivers.'
        return
    }
    foreach ($a in $up) { Add-Result 'Network' "Adapter: $($a.Name)" 'OK' "$($a.InterfaceDescription), $($a.LinkSpeed)." }

    # Only connected adapters: disconnected Bluetooth / Wi-Fi Direct adapters normally hold 169.254 addresses
    $upIdx = @($up | Select-Object -ExpandProperty InterfaceIndex)
    $apipa = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '169.254.*' -and $_.InterfaceIndex -in $upIdx })
    if ($apipa.Count -gt 0) {
        Add-Result 'Network' 'IP address' 'Warning' "Adapter(s) have no DHCP address (169.254.x.x): $(($apipa.InterfaceAlias) -join ', ')." 'Restart the router, or run: ipconfig /release && ipconfig /renew'
    }

    if ($Quick) { Add-Result 'Network' 'Internet connectivity' 'Skipped' 'Skipped in -Quick mode.'; return }

    $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
    $targets = [ordered]@{}
    if ($gw -and $gw -ne '0.0.0.0') { $targets['Router'] = $gw }
    $targets['Internet'] = '1.1.1.1'
    foreach ($k in $targets.Keys) {
        $ok = 0; $lat = @()
        for ($i = 0; $i -lt 4; $i++) {
            $p = New-Object System.Net.NetworkInformation.Ping
            try { $r = $p.Send($targets[$k], 1500); if ($r.Status -eq 'Success') { $ok++; $lat += $r.RoundtripTime } } catch {}
        }
        $loss = 100 - $ok * 25
        $avg = if ($lat.Count) { [math]::Round(($lat | Measure-Object -Average).Average) } else { $null }
        $txt = "$k ($($targets[$k])): $loss% loss$(if ($null -ne $avg) { ", avg $avg ms" })."
        if ($ok -eq 0) { Add-Result 'Network' "Ping $k" 'Critical' $txt $(if ($k -eq 'Router') { 'Cannot reach the router - check Wi-Fi/cable.' } else { 'No internet - restart the router or contact your ISP.' }) }
        elseif ($loss -ge $T.PingLossWarnPct -or $avg -ge $T.PingLatencyWarnMs) { Add-Result 'Network' "Ping $k" 'Warning' $txt 'Unstable connection; move closer to Wi-Fi or use a cable.' }
        else { Add-Result 'Network' "Ping $k" 'OK' $txt }
    }

    try {
        $null = Resolve-DnsName 'www.microsoft.com' -ErrorAction Stop -QuickTimeout
        Add-Result 'Network' 'DNS' 'OK' 'Name resolution works.'
    } catch {
        Add-Result 'Network' 'DNS' 'Critical' 'Cannot resolve internet names.' 'Run: ipconfig /flushdns, or set DNS to 1.1.1.1 / 8.8.8.8.'
    }

    # Proxy / hosts file tampering
    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hosts) {
        $lines = @(Get-Content $hosts | Where-Object { $_ -match '^\s*[^#\s]' })
        if ($lines.Count -gt 0) {
            Add-Result 'Network' 'Hosts file' 'Info' "Hosts file has $($lines.Count) custom entr$(if ($lines.Count -eq 1) { 'y' } else { 'ies' }). Malware sometimes adds entries here." "Review $hosts if websites behave oddly."
        }
    }
}

# ===========================================================================
# REPORT
# ===========================================================================
function ConvertTo-Html-Safe { param([string]$s) [System.Net.WebUtility]::HtmlEncode($s) }

function Write-Report {
    param([string]$Dir)
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir | Out-Null }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
    $base = Join-Path $Dir "Diagnostic_$($env:COMPUTERNAME)_$stamp"

    $order = @{ Critical = 0; Error = 1; Warning = 2; Info = 3; Skipped = 4; OK = 5 }
    $counts = @{}
    foreach ($s in $order.Keys) { $counts[$s] = @($script:Results | Where-Object Status -eq $s).Count }
    # A check that could not run is not a clean result, so it raises the overall status to Warning
    $overall = if ($counts.Critical -gt 0) { 'Critical' } elseif ($counts.Warning -gt 0 -or $counts.Error -gt 0) { 'Warning' } else { 'OK' }
    $headline = switch ($overall) {
        'Critical' { "$($counts.Critical) serious problem(s) need attention" }
        'Warning'  { if ($counts.Warning -gt 0) { "$($counts.Warning) issue(s) worth looking at" } else { "$($counts.Error) check(s) could not run" } }
        default    { 'No problems found' }
    }

    # JSON
    [pscustomobject]@{
        Generated = (Get-Date).ToString('o')
        Overall   = $overall
        Counts    = $counts
        Overview  = $script:Overview
        Results   = $script:Results
        Installed = $script:InstalledApps
    } | ConvertTo-Json -Depth 5 | Set-Content -Path "$base.json" -Encoding UTF8

    $e = { param($x) ConvertTo-Html-Safe ([string]$x) }

    $issues = $script:Results | Where-Object { $_.Status -in 'Critical', 'Warning', 'Error' } |
              Sort-Object @{ e = { $order[$_.Status] } }, Category
    $issueHtml = if (@($issues).Count -eq 0) { '<p class="none">Nothing needs fixing. Nice.</p>' } else {
        ($issues | ForEach-Object {
            "<div class='issue $($_.Status.ToLower())'><div class='ih'><span class='badge $($_.Status.ToLower())'>$($_.Status)</span><b>$(& $e $_.Check)</b><span class='cat'>$(& $e $_.Category)</span></div><div>$(& $e $_.Detail)</div>$(if ($_.Fix) { "<div class='fix'><b>What to do:</b> $(& $e $_.Fix)</div>" })</div>"
        }) -join "`n"
    }

    $catHtml = ($script:Results | Group-Object Category | ForEach-Object {
        $rows = ($_.Group | Sort-Object @{ e = { $order[$_.Status] } } | ForEach-Object {
            "<tr><td><span class='badge $($_.Status.ToLower())'>$($_.Status)</span></td><td>$(& $e $_.Check)</td><td>$(& $e $_.Detail)$(if ($_.Fix -and $_.Status -notin 'OK') { "<div class='fix'>$(& $e $_.Fix)</div>" })</td></tr>"
        }) -join ''
        $worst = ($_.Group | Sort-Object @{ e = { $order[$_.Status] } } | Select-Object -First 1).Status.ToLower()
        "<details class='sec' $(if ($worst -in 'critical','warning','error') { 'open' })><summary><span class='dot $worst'></span>$(& $e $_.Name)<span class='n'>$($_.Count) checks</span></summary><table>$rows</table></details>"
    }) -join "`n"

    $ovHtml = ($script:Overview.GetEnumerator() | ForEach-Object { "<tr><th>$(& $e $_.Key)</th><td>$(& $e $_.Value)</td></tr>" }) -join ''
    $appHtml = (@($script:InstalledApps) | ForEach-Object { "<tr><td>$(& $e $_.Name)</td><td>$(& $e $_.Version)</td><td>$(& $e $_.Publisher)</td></tr>" }) -join ''

    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PC Diagnostic - $(& $e $env:COMPUTERNAME)</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#667085;--line:#e4e7ec;--ok:#12805c;--info:#2e6fd8;--warn:#b26b00;--crit:#c4282d;--skip:#8a8f98}
@media (prefers-color-scheme:dark){:root{--bg:#14161b;--card:#1d2027;--fg:#e8eaee;--mut:#9aa1ad;--line:#2d313a;--ok:#3cc28f;--info:#6b9ff0;--warn:#e9a23b;--crit:#f0646a;--skip:#8a8f98}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 60px}h1{margin:0 0 4px;font-size:26px}h2{margin:32px 0 12px;font-size:18px}
.sub{color:var(--mut)}.hero{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--ov);border-radius:10px;padding:18px 20px;margin:20px 0}
.hero b{font-size:20px;color:var(--ov)}.counts{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}.counts span{padding:4px 10px;border-radius:999px;background:var(--bg);font-size:13px}
.badge{display:inline-block;min-width:68px;text-align:center;padding:1px 8px;border-radius:5px;font-size:12px;font-weight:600;color:#fff}
.badge.ok{background:var(--ok)}.badge.info{background:var(--info)}.badge.warning{background:var(--warn)}.badge.critical,.badge.error{background:var(--crit)}.badge.skipped{background:var(--skip)}
.issue{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--warn);border-radius:8px;padding:12px 14px;margin-bottom:10px}
.issue.critical,.issue.error{border-left-color:var(--crit)}.ih{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:4px}.cat{color:var(--mut);font-size:13px;margin-left:auto}
.fix{margin-top:6px;color:var(--mut);font-size:14px}.none{background:var(--card);padding:14px;border-radius:8px;border:1px solid var(--line)}
.sec{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:8px}.sec summary{cursor:pointer;padding:10px 14px;font-weight:600;display:flex;align-items:center;gap:10px}
.n{margin-left:auto;color:var(--mut);font-weight:400;font-size:13px}.dot{width:10px;height:10px;border-radius:50%;background:var(--ok)}
.dot.warning{background:var(--warn)}.dot.critical,.dot.error{background:var(--crit)}.dot.info{background:var(--info)}.dot.skipped{background:var(--skip)}
table{width:100%;border-collapse:collapse}td,th{padding:7px 14px;border-top:1px solid var(--line);text-align:left;vertical-align:top}
.sec td:first-child{width:90px}.sec td:nth-child(2){width:28%;font-weight:500}th{color:var(--mut);font-weight:500;width:200px}
.box{background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:auto}
@media (max-width:640px){.sec td:nth-child(2){width:auto}td,th{padding:6px 10px}th{width:auto}}
</style></head><body><main>
<h1>PC Diagnostic Report</h1>
<div class="sub">$(& $e $env:COMPUTERNAME) &middot; $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; event logs checked for the last $Days days$(if (-not $script:IsAdmin) { ' &middot; <b>not run as admin - some checks skipped</b>' })</div>
<div class="hero" style="--ov:var(--$(@{OK='ok';Warning='warn';Critical='crit'}[$overall]))"><b>$headline</b>
<div class="counts"><span>Critical: $($counts.Critical)</span><span>Warning: $($counts.Warning)</span><span>Info: $($counts.Info)</span><span>OK: $($counts.OK)</span><span>Skipped: $($counts.Skipped)</span><span>Check errors: $($counts.Error)</span></div></div>
<h2>Issues found</h2>
$issueHtml
<h2>All checks</h2>
$catHtml
<h2>System overview</h2>
<div class="box"><table>$ovHtml</table></div>
<h2>Installed programs ($(@($script:InstalledApps).Count))</h2>
<details class="sec"><summary>Show list</summary><table>$appHtml</table></details>
<p class="sub">Generated by Diagnostic-kun. Read-only: no changes were made to this PC.</p>
</main></body></html>
"@
    Set-Content -Path "$base.html" -Value $html -Encoding UTF8
    return [pscustomobject]@{ Html = "$base.html"; Json = "$base.json"; Overall = $overall; Counts = $counts }
}

# ===========================================================================
# MAIN
# ===========================================================================
if ($env:OS -ne 'Windows_NT') { Write-Error 'This tool only runs on Windows.'; exit 2 }

Write-Host ''
Write-Host '  Diagnostic-kun - Windows PC health check' -ForegroundColor Cyan
if (-not $script:IsAdmin) { Write-Host '  Not running as Administrator: some checks will be skipped.' -ForegroundColor Yellow }
Write-Host ''

$script:Overview = [ordered]@{}
$script:InstalledApps = @()

$checks = @(
    @('System',       'System information',   ${function:Test-SystemInfo}),
    @('CPU',          'Processor and load',   ${function:Test-Cpu}),
    @('CPU',          'Temperatures',         ${function:Test-Thermal}),
    @('Memory',       'RAM',                  ${function:Test-Memory}),
    @('Storage',      'Disks and volumes',    ${function:Test-Storage}),
    @('Graphics',     'Graphics adapters',    ${function:Test-Gpu}),
    @('Power',        'Battery',              ${function:Test-Battery}),
    @('Devices',      'Device Manager',       ${function:Test-Devices}),
    @('Stability',    'Crashes and hardware errors', ${function:Test-HardwareErrors}),
    @('Updates',      'Windows Update',       ${function:Test-WindowsUpdate}),
    @('Security',     'Security settings',    ${function:Test-Security}),
    @('OS Health',    'System file integrity',${function:Test-SystemFiles}),
    @('Services',     'Windows services',     ${function:Test-Services}),
    @('Drivers',      'Drivers',              ${function:Test-Drivers}),
    @('Applications', 'Program crashes',      ${function:Test-AppCrashes}),
    @('Applications', 'Startup programs',     ${function:Test-Startup}),
    @('Applications', 'Installed software',   ${function:Test-InstalledSoftware}),
    @('OS Health',    'System event log',     ${function:Test-SystemEvents}),
    @('OS Health',    'Housekeeping',         ${function:Test-Housekeeping}),
    @('Network',      'Network',              ${function:Test-Network})
)
$sw = [Diagnostics.Stopwatch]::StartNew()
foreach ($c in $checks) { Invoke-Check $c[0] $c[1] $c[2] }

$r = Write-Report -Dir $OutputDir
Write-Host ''
$color = @{ OK = 'Green'; Warning = 'Yellow'; Critical = 'Red' }[$r.Overall]
Write-Host ("  Result: {0}  (Critical {1}, Warning {2}, OK {3})  in {4:N0}s" -f $r.Overall, $r.Counts.Critical, $r.Counts.Warning, $r.Counts.OK, $sw.Elapsed.TotalSeconds) -ForegroundColor $color
Write-Host "  Report: $($r.Html)"
Write-Host "  Data:   $($r.Json)"
Write-Host ''
if (-not $NoOpen) { Start-Process $r.Html }

# Exit code for scripting: 0 = OK, 1 = warnings, 2 = critical
exit @{ OK = 0; Warning = 1; Critical = 2 }[$r.Overall]
