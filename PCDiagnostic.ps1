<#
.SYNOPSIS
    Diagnostic-kun: checks the hardware and software of a Windows 10/11 PC and
    writes a report of anything that looks wrong.

.DESCRIPTION
    Runs a set of read-only checks (it changes nothing on the PC) and rates each
    one OK, Info, Warning or Critical. Results are saved as an HTML report and a
    JSON file, and each report shows what changed since the previous scan.
    Run as Administrator for complete results; without admin rights some checks
    (disk health counters, temperatures, BitLocker, TPM, Secure Boot, DISM) are
    skipped and marked as such.

    Fixes are never applied automatically: the window (-Gui) and the console
    menu (-Fix) only run a fix after you choose it and confirm.

.PARAMETER OutputDir
    Folder for the reports. Defaults to a "Reports" folder next to this script.

.PARAMETER Days
    How many days of event logs to look through. Default 7.

.PARAMETER Quick
    Skips the slower checks (DISM component store check, network tests).

.PARAMETER NoOpen
    Do not open the HTML report when finished.

.PARAMETER Gui
    Shows a window with a progress bar, the results, and buttons for fixes,
    a shareable report and the weekly check. RunDiagnostic.bat uses this.

.PARAMETER Fix
    Console mode: after the scan, list the available fixes and ask which to run.

.PARAMETER Shareable
    Also write a copy of the report without the PC name, user name and
    installed programs, for sending to someone who is helping you.

.PARAMETER InstallSchedule
    Turns on a weekly background check that shows a notification only when
    something becomes critical. Needs administrator rights.

.PARAMETER RemoveSchedule
    Turns the weekly background check off.

.PARAMETER Scheduled
    Used by the weekly task: no window, notification only when needed.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\PCDiagnostic.ps1
    powershell -ExecutionPolicy Bypass -File .\PCDiagnostic.ps1 -Days 30 -Quick -Fix
    powershell -ExecutionPolicy Bypass -File .\PCDiagnostic.ps1 -InstallSchedule
#>
[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path $PSScriptRoot 'Reports'),
    [ValidateRange(1, 365)][int]$Days = 7,
    [switch]$Quick,
    [switch]$NoOpen,
    [switch]$Gui,
    [switch]$Fix,
    [switch]$Shareable,
    [switch]$InstallSchedule,
    [switch]$RemoveSchedule,
    [switch]$Scheduled,
    # Internal: used by the window and the tests
    [Parameter(DontShow)][string]$ProgressFile,
    [Parameter(DontShow)][string]$SensorProbe,
    [Parameter(DontShow)][switch]$GuiSelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:OS -ne 'Windows_NT') { [Console]::Error.WriteLine('This tool only runs on Windows.'); exit 2 }

$script:Version = 'dev'          # replaced with the release number by build/Build-Package.ps1
$script:TaskName = 'Diagnostic-kun weekly check'
$script:KeepRuns = 30            # older reports in the Reports folder are deleted after this many
$OutputDir = $OutputDir.TrimEnd('\')

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
    ThermalWarnC        = 85     # CPU temperature
    ThermalCritC        = 95
    GpuTempWarnC        = 85
    GpuTempCritC        = 95
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
$script:Metrics = New-Object System.Collections.Generic.List[object]
$script:Overview = [ordered]@{}
$script:InstalledApps = @()
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Since = (Get-Date).AddDays(-$Days)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# The FixId parameter names an entry in $script:FixActions (below) that the window
# and the -Fix menu can offer for this result; FixArg is passed to it (a drive, a service...).
function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('OK', 'Info', 'Warning', 'Critical', 'Skipped', 'Error')][string]$Status,
        [string]$Detail = '',
        [string]$Fix = '',
        [string]$FixId = '',
        [string]$FixArg = ''
    )
    $script:Results.Add([pscustomobject]@{
        Category = $Category
        Check    = $Check
        Status   = $Status
        Detail   = $Detail
        Fix      = $Fix
        FixId    = $FixId
        FixArg   = $FixArg
    })
}

# A number that is compared with the previous scan ("free space 120 GB -> 98 GB").
# -PerWindow marks counts over the last -Days days, only compared when -Days matches.
function Add-Metric {
    param(
        [string]$Name,
        [double]$Value,
        [string]$Unit = '',
        [switch]$HigherIsWorse,
        [double]$MinChange = 1,
        [switch]$PerWindow
    )
    $script:Metrics.Add([pscustomobject]@{
        Name          = $Name
        Value         = [math]::Round($Value, 1)
        Unit          = $Unit
        HigherIsWorse = [bool]$HigherIsWorse
        MinChange     = $MinChange
        PerWindow     = [bool]$PerWindow
    })
}

# Reads a property from a hashtable or object, or returns $Default when it is
# missing (reports saved by older versions lack newer fields).
function Get-Prop {
    param($Obj, [string]$Name, $Default = $null)
    if ($null -eq $Obj) { return $Default }
    if ($Obj -is [System.Collections.IDictionary]) {
        if ($Obj.Contains($Name)) { return $Obj[$Name] } else { return $Default }
    }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $Default }
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
# FIXES - only ever run after the user picks them and confirms
# ===========================================================================
# Title may contain {0}, replaced by the result's FixArg.
$script:FixActions = [ordered]@{
    'cleanmgr'        = @{ Title = 'Open Disk Cleanup for drive {0}'
                           Run   = { param($a) Start-Process cleanmgr.exe -ArgumentList "/d $($a.TrimEnd(':'))" } }
    'chkdsk'          = @{ Title = 'Check and repair drive {0} with chkdsk (the system drive is checked at the next restart)'
                           Run   = { param($a) Start-Process cmd.exe -ArgumentList "/k chkdsk $a /f" } }
    'repair-system'   = @{ Title = 'Repair Windows system files with DISM and SFC (15-30 minutes, opens a window)'
                           Run   = { Start-Process cmd.exe -ArgumentList '/k DISM /Online /Cleanup-Image /RestoreHealth && sfc /scannow' } }
    'start-service'   = @{ Title = 'Start the "{0}" service'
                           Run   = { param($a) Start-Service -Name $a } }
    'wu-service'      = @{ Title = 'Turn the Windows Update service back on'
                           Run   = { Set-Service wuauserv -StartupType Manual; Start-Service wuauserv } }
    'open-update'     = @{ Title = 'Open Windows Update'
                           Run   = { Start-Process 'ms-settings:windowsupdate' } }
    'defender-on'     = @{ Title = 'Turn on Microsoft Defender real-time protection'
                           Run   = {
                               Set-MpPreference -DisableRealtimeMonitoring $false
                               if (-not (Get-MpComputerStatus).RealTimeProtectionEnabled) {
                                   throw 'Windows did not allow it (Tamper Protection or a policy). Turn it on in Windows Security.'
                               } } }
    'defender-update' = @{ Title = 'Update Microsoft Defender virus definitions'
                           Run   = { Update-MpSignature } }
    'open-security'   = @{ Title = 'Open Windows Security'
                           Run   = { Start-Process 'windowsdefender:' } }
    'firewall-on'     = @{ Title = 'Turn the Windows Firewall back on for all networks'
                           Run   = { Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True } }
    'open-devmgr'     = @{ Title = 'Open Device Manager to update or reinstall drivers'
                           Run   = { Start-Process devmgmt.msc } }
    'memory-test'     = @{ Title = 'Open Windows Memory Diagnostic (tests RAM during a restart)'
                           Run   = { Start-Process mdsched.exe } }
    'open-startup'    = @{ Title = 'Open Startup apps settings'
                           Run   = { Start-Process 'ms-settings:startupapps' } }
    'open-apps'       = @{ Title = 'Open "Programs and Features" to uninstall programs'
                           Run   = { Start-Process appwiz.cpl } }
    'time-sync'       = @{ Title = 'Turn Windows Time back on and sync the clock'
                           Run   = { Set-Service W32Time -StartupType Manual; Start-Service W32Time; $null = Invoke-Native 'w32tm.exe' @('/resync') } }
    'power-balanced'  = @{ Title = 'Switch to the Balanced power plan'
                           Run   = { $null = Invoke-Native 'powercfg.exe' @('/setactive', 'SCHEME_BALANCED') } }
    'renew-ip'        = @{ Title = 'Renew the network address (DHCP)'
                           Run   = { $null = Invoke-Native 'ipconfig.exe' @('/renew') } }
    'flush-dns'       = @{ Title = 'Clear the DNS cache'
                           Run   = { Clear-DnsClientCache } }
    'restart'         = @{ Title = 'Restart the PC in 1 minute (save your work first; cancel with "shutdown /a")'
                           Run   = { $null = Invoke-Native 'shutdown.exe' @('/r', '/t', '60', '/c', 'Restarting to finish Windows updates (Diagnostic-kun)') } }
}

# The distinct fixes offered for a set of results, most severe first, restart last.
function Get-AvailableFixes {
    param($Results)
    $rank = @{ Critical = 0; Warning = 1; Info = 2 }
    $seen = @{}
    $list = foreach ($r in @($Results)) {
        $id = [string](Get-Prop $r 'FixId' '')
        $arg = [string](Get-Prop $r 'FixArg' '')
        if (-not $id -or -not $rank.ContainsKey([string]$r.Status) -or -not $script:FixActions.Contains($id)) { continue }
        if ($seen.ContainsKey("$id|$arg")) { continue }
        $seen["$id|$arg"] = $true
        [pscustomobject]@{
            Id     = $id
            Arg    = $arg
            Title  = $script:FixActions[$id].Title -f $arg
            Reason = "$($r.Check) ($($r.Status))"
            Order  = if ($id -eq 'restart') { 9 } else { $rank[[string]$r.Status] }
        }
    }
    , @($list | Sort-Object Order)
}

function Invoke-Fix {
    param($Item)
    try {
        & $script:FixActions[$Item.Id].Run $Item.Arg
        "Done: $($Item.Title)"
    } catch {
        "Failed: $($Item.Title) - $($_.Exception.Message)"
    }
}

# Console menu for -Fix
function Invoke-FixMenu {
    param($Data)
    $fixes = Get-AvailableFixes $Data.Results
    if ($fixes.Count -eq 0) { Write-Host '  No automatic fixes are available for the problems found.'; return }
    Write-Host '  Fixes available (nothing runs unless you choose it):' -ForegroundColor Cyan
    for ($i = 0; $i -lt $fixes.Count; $i++) { Write-Host ("   [{0}] {1}  - for: {2}" -f ($i + 1), $fixes[$i].Title, $fixes[$i].Reason) }
    $ans = Read-Host '  Type the numbers to run, separated by commas, or press Enter to skip'
    $nums = @($ans -split '[,\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } |
              Where-Object { $_ -ge 1 -and $_ -le $fixes.Count } | Select-Object -Unique)
    foreach ($n in $nums) {
        $f = $fixes[$n - 1]
        if ((Read-Host "  Run '$($f.Title)'? (y/n)") -match '^\s*y') { Write-Host ('  ' + (Invoke-Fix $f)) }
    }
    if ($nums.Count -gt 0) { Write-Host '  Run the scan again to check the result.' }
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
        Add-Result 'System' 'Uptime' 'Warning' "Running for $d days without a restart." 'Restart the PC; long uptimes leave updates pending and memory fragmented.' -FixId restart
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
        Add-Result 'System' 'Windows version' 'Critical' "$label is an old Windows release that no longer receives security updates." $upgradeFix -FixId open-update
    } elseif ($end -lt (Get-Date)) {
        if ($build -eq 19045) {
            Add-Result 'System' 'Windows version' 'Warning' "Windows 10 22H2. Support ended $($end.ToString('yyyy-MM-dd')); updates only continue with Extended Security Updates (ESU)." 'Plan an upgrade to Windows 11 or enrol in Extended Security Updates.' -FixId open-update
        } else {
            Add-Result 'System' 'Windows version' 'Critical' "$label - support for this release ended $($end.ToString('yyyy-MM-dd')); it no longer receives security updates." $upgradeFix -FixId open-update
        }
    } elseif (($end - (Get-Date)).TotalDays -le 90) {
        Add-Result 'System' 'Windows version' 'Warning' "$label - support ends $($end.ToString('yyyy-MM-dd'))." $upgradeFix -FixId open-update
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

# --- Temperatures and fans -------------------------------------------------
# The release zip ships LibreHardwareMonitorLib (MPL-2.0) in .\lib. It is loaded
# in a separate PowerShell process (-SensorProbe) so that a crash or hang in the
# sensor library cannot take the whole scan down. Without it, the check falls
# back to nvidia-smi for NVIDIA GPUs and ACPI thermal zones for the CPU.
$script:PawnIoUrl = 'https://github.com/namazso/PawnIO.Setup/releases'

$script:ResolverSource = @'
using System; using System.IO; using System.Reflection;
public static class DkAssemblyResolver {
    static string dir;
    public static void Register(string d) { dir = d; AppDomain.CurrentDomain.AssemblyResolve += OnResolve; }
    static Assembly OnResolve(object sender, ResolveEventArgs e) {
        string p = Path.Combine(dir, new AssemblyName(e.Name).Name + ".dll");
        return File.Exists(p) ? Assembly.LoadFrom(p) : null;
    }
}
'@

# Child-process mode: read temperature and fan sensors, write them to $OutFile as JSON.
function Invoke-SensorProbe {
    param([string]$OutFile)
    $dir = Join-Path $PSScriptRoot 'lib'
    # powershell.exe has no binding redirects for the library's dependencies, so
    # resolve any assembly from .\lib by name, whatever version is requested.
    Add-Type -TypeDefinition $script:ResolverSource
    [DkAssemblyResolver]::Register($dir)
    $null = [Reflection.Assembly]::LoadFrom((Join-Path $dir 'LibreHardwareMonitorLib.dll'))
    $computer = New-Object LibreHardwareMonitor.Hardware.Computer
    $computer.IsCpuEnabled = $true
    $computer.IsGpuEnabled = $true
    $computer.IsMotherboardEnabled = $true
    $computer.IsControllerEnabled = $true
    $computer.Open()
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $all = New-Object System.Collections.Generic.List[object]
        foreach ($h in $computer.Hardware) { $all.Add($h); foreach ($sub in $h.SubHardware) { $all.Add($sub) } }
        foreach ($pass in 1..2) { foreach ($h in $all) { $h.Update() }; Start-Sleep -Milliseconds 500 }
        foreach ($h in $all) {
            foreach ($s in $h.Sensors) {
                $kind = [string]$s.SensorType
                if ($kind -in 'Temperature', 'Fan' -and $null -ne $s.Value) {
                    $out.Add([pscustomobject]@{ Hardware = [string]$h.Name; Type = [string]$h.HardwareType; Sensor = [string]$s.Name; Kind = $kind; Value = [math]::Round([double]$s.Value, 1) })
                }
            }
        }
    } finally { $computer.Close() }
    [pscustomobject]@{ Readings = $out.ToArray() } | ConvertTo-Json -Depth 3 | Set-Content -Path $OutFile -Encoding UTF8
}

function Get-SensorReadings {
    $lib = Join-Path $PSScriptRoot 'lib\LibreHardwareMonitorLib.dll'
    if (-not (Test-Path $lib)) { return [pscustomobject]@{ Readings = @(); Note = 'NoLibrary' } }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("dk_sensors_{0}.json" -f [guid]::NewGuid())
    $exe = (Get-Process -Id $PID).Path
    $p = Start-Process -FilePath $exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -SensorProbe `"$tmp`"" -WindowStyle Hidden -PassThru
    $null = $p.Handle   # keeps the exit code readable after the process ends
    $note = ''
    $readings = @()
    if (-not $p.WaitForExit(60000)) {
        try { $p.Kill() } catch {}
        $note = 'The sensor library did not answer within 60 seconds.'
    } elseif (Test-Path $tmp) {
        $readings = @((Get-Content $tmp -Raw | ConvertFrom-Json).Readings)
    } else {
        $note = "The sensor library failed to load (exit code $($p.ExitCode))."
    }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    [pscustomobject]@{ Readings = $readings; Note = $note }
}

function Test-Sensors {
    if (-not $script:IsAdmin) { Skip-NoAdmin 'Temperatures' 'Temperatures and fans'; return }
    $probe = Get-SensorReadings
    $readings = @($probe.Readings | Where-Object { $_ })
    $hasLib = $probe.Note -ne 'NoLibrary'
    if ($probe.Note -and $hasLib) { Add-Result 'Temperatures' 'Sensor library' 'Info' $probe.Note }

    # NVIDIA fallback when the library gave no GPU temperatures
    if (-not @($readings | Where-Object { $_.Kind -eq 'Temperature' -and $_.Type -like 'Gpu*' })) {
        $smi = @("$env:SystemRoot\System32\nvidia-smi.exe", "$env:ProgramFiles\NVIDIA Corporation\NVSMI\nvidia-smi.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($smi) {
            foreach ($line in @(Invoke-Native $smi @('--query-gpu=name,temperature.gpu', '--format=csv,noheader,nounits'))) {
                $f = $line -split ',\s*'
                if ($f.Count -ge 2 -and $f[1] -match '^\d+$') {
                    $readings += [pscustomobject]@{ Hardware = $f[0]; Type = 'GpuNvidia'; Sensor = 'GPU Core'; Kind = 'Temperature'; Value = [double]$f[1] }
                }
            }
        }
    }

    # CPU
    $cpuT = @($readings | Where-Object { $_.Kind -eq 'Temperature' -and $_.Type -eq 'Cpu' })
    $main = @($cpuT | Where-Object { $_.Sensor -match 'Package|Tctl|Tdie|Core Max' })
    if ($main.Count -eq 0) { $main = $cpuT }
    if ($main.Count -gt 0) {
        $max = ($main | Measure-Object -Property Value -Maximum).Maximum
        $txt = "$($main[0].Hardware): $max C (measured while the scan was running)."
        if ($max -ge $T.ThermalCritC) { Add-Result 'Temperatures' 'CPU temperature' 'Critical' $txt 'Clean dust from fans and vents, check the cooler is seated and its fan spins, renew thermal paste.' }
        elseif ($max -ge $T.ThermalWarnC) { Add-Result 'Temperatures' 'CPU temperature' 'Warning' $txt 'Check airflow and that all fans spin; clean dust from vents.' }
        else { Add-Result 'Temperatures' 'CPU temperature' 'OK' $txt }
    } else {
        # ACPI thermal zones: approximate, and missing on many desktops
        $zones = @()
        try { $zones = @(Get-Cim MSAcpi_ThermalZoneTemperature -Namespace 'root/wmi') } catch {}
        $temps = @($zones | ForEach-Object { [math]::Round(($_.CurrentTemperature / 10) - 273.15, 1) } | Where-Object { $_ -gt 0 -and $_ -lt 150 })
        if ($temps.Count -gt 0) {
            $max = ($temps | Measure-Object -Maximum).Maximum
            $txt = "Thermal zone readings: $(($temps | ForEach-Object { "$_ C" }) -join ', '). (ACPI zones are approximate.)"
            if ($max -ge $T.ThermalCritC) { Add-Result 'Temperatures' 'CPU temperature' 'Critical' $txt 'Clean dust from fans and vents, check the cooler, replace thermal paste.' }
            elseif ($max -ge $T.ThermalWarnC) { Add-Result 'Temperatures' 'CPU temperature' 'Warning' $txt 'Check airflow and fans.' }
            else { Add-Result 'Temperatures' 'CPU temperature' 'OK' $txt }
        } elseif ($hasLib) {
            Add-Result 'Temperatures' 'CPU temperature' 'Info' 'Not available: reading the CPU sensor needs the free PawnIO driver.' "Install PawnIO from $($script:PawnIoUrl), then scan again to see CPU temperature and fan speeds."
        } else {
            Add-Result 'Temperatures' 'CPU temperature' 'Skipped' 'This PC does not expose CPU temperature to Windows.' 'Use the release zip from GitHub (it includes a sensor library), or HWiNFO, for exact temperatures.'
        }
    }

    # GPU (one row per graphics card)
    foreach ($g in @($readings | Where-Object { $_.Kind -eq 'Temperature' -and $_.Type -like 'Gpu*' } | Group-Object Hardware)) {
        $core = @($g.Group | Where-Object { $_.Sensor -match 'Core' -and $_.Sensor -notmatch 'Hot ?Spot|Memory' })
        if ($core.Count -eq 0) { $core = @($g.Group) }
        $t = ($core | Measure-Object -Property Value -Maximum).Maximum
        $txt = "$($g.Name): $t C."
        if ($t -ge $T.GpuTempCritC) { Add-Result 'Temperatures' "GPU temperature: $($g.Name)" 'Critical' $txt 'Clean the graphics card fans and heatsink; check case airflow.' }
        elseif ($t -ge $T.GpuTempWarnC) { Add-Result 'Temperatures' "GPU temperature: $($g.Name)" 'Warning' $txt 'Check the graphics card fans and case airflow.' }
        else { Add-Result 'Temperatures' "GPU temperature: $($g.Name)" 'OK' $txt }
    }

    # Fans. 0 RPM alone is normal (unused headers, fans that stop when cool), so it
    # is only a problem when every fan reads 0 while the CPU is hot.
    $fans = @($readings | Where-Object { $_.Kind -eq 'Fan' })
    if ($fans.Count -gt 0) {
        $list = ($fans | ForEach-Object { "$($_.Sensor) $([int]$_.Value) RPM" }) -join ', '
        $cpuHot = @($main | Where-Object { $_.Value -ge $T.ThermalWarnC }).Count -gt 0
        if ($cpuHot -and @($fans | Where-Object { $_.Value -gt 0 }).Count -eq 0) {
            Add-Result 'Temperatures' 'Fans' 'Critical' "All fans report 0 RPM while the CPU is hot: $list." 'Check that the CPU and case fans are connected and spinning.'
        } else { Add-Result 'Temperatures' 'Fans' 'OK' $list }
    }
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
                        Add-Metric "Wear: $($d.FriendlyName)" $rc.Wear '%' -HigherIsWorse
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
        Add-Metric "Free space $($v.DeviceID)" ($v.FreeSpace / 1GB) 'GB'
        if ($pct -lt $T.DiskFreeCritPct -or $v.FreeSpace -lt ($T.DiskFreeCritGB * 1GB)) { Add-Result 'Storage' "Free space $($v.DeviceID)" 'Critical' $txt $fix -FixId cleanmgr -FixArg $v.DeviceID }
        elseif ($pct -lt $T.DiskFreeWarnPct) { Add-Result 'Storage' "Free space $($v.DeviceID)" 'Warning' $txt $fix -FixId cleanmgr -FixArg $v.DeviceID }
        else { Add-Result 'Storage' "Free space $($v.DeviceID)" 'OK' $txt }
    }

    # File system dirty bit (read from WMI rather than parsing fsutil's translated output)
    if ($script:IsAdmin) {
        foreach ($wv in @(Get-Cim Win32_Volume -Filter 'DriveType=3')) {
            if ($wv.DirtyBitSet -and $wv.DriveLetter) {
                Add-Result 'Storage' "File system $($wv.DriveLetter)" 'Warning' "Volume $($wv.DriveLetter) is marked dirty (file system errors suspected)." "Run: chkdsk $($wv.DriveLetter) /f  (may need a restart)." -FixId chkdsk -FixArg $wv.DriveLetter
            }
        }
    }

    # Disk errors in the System log
    $diskEv = Get-Events @{ LogName = 'System'; Id = 7, 11, 51, 52, 55, 98, 129, 153, 157; Level = 1, 2, 3 } 300
    $diskEv = @($diskEv | Where-Object { $_.ProviderName -match '^(disk|Ntfs|Microsoft-Windows-Ntfs|stornvme|storahci|iaStor\w*|nvme\w*|volmgr)$' })
    Add-Metric "Disk errors (last $Days days)" $diskEv.Count -HigherIsWorse -PerWindow
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
            Add-Result 'Graphics' "GPU: $($g.Name)" 'Critical' "$txt - device error code $($g.ConfigManagerErrorCode), status $($g.Status)." 'Reinstall the graphics driver from the GPU maker (NVIDIA / AMD / Intel).' -FixId open-devmgr
        } elseif ($g.Name -match 'Basic Display|Basic Render') {
            Add-Result 'Graphics' "GPU: $($g.Name)" 'Warning' "$txt - Windows is using the generic display driver." 'Install the proper graphics driver from your GPU or PC maker.' -FixId open-update
        } elseif ($null -ne $age -and $age -gt $T.DriverOldYears) {
            Add-Result 'Graphics' "GPU: $($g.Name)" 'Warning' "$txt - driver is $age years old." 'Update the graphics driver.' -FixId open-update
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
                Add-Metric 'Battery wear' $wear '%' -HigherIsWorse -MinChange 2
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
        Add-Result 'Devices' "Device: $name" $sev "Code $c - $why." 'Open Device Manager, right-click the device > Update driver, or download the driver from the maker.' -FixId open-devmgr
    }
}

function Test-HardwareErrors {
    $whea = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger' } 200
    $fatal = @($whea | Where-Object { $_.Level -le 2 })
    Add-Metric "Hardware errors (last $Days days)" $whea.Count -HigherIsWorse -PerWindow
    if ($fatal.Count -gt 0) {
        Add-Result 'Stability' 'Hardware errors (WHEA)' 'Critical' "$($fatal.Count) fatal hardware error(s) and $($whea.Count - $fatal.Count) corrected in the last $Days days. Latest: $($fatal[0].TimeCreated.ToString('yyyy-MM-dd HH:mm'))." 'Usually CPU, RAM, PCIe or overclock instability. Remove overclocks/XMP, test RAM (mdsched), update BIOS.' -FixId memory-test
    } elseif ($whea.Count -gt 20) {
        Add-Result 'Stability' 'Hardware errors (WHEA)' 'Warning' "$($whea.Count) corrected hardware errors in the last $Days days." 'Often a PCIe link issue; update chipset drivers and BIOS.'
    } else { Add-Result 'Stability' 'Hardware errors (WHEA)' 'OK' "$($whea.Count) corrected / 0 fatal hardware errors." }

    $bsod = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001 } 50
    $power = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41 } 50
    Add-Metric "Blue screens (last $Days days)" $bsod.Count -HigherIsWorse -PerWindow
    if ($bsod.Count -gt 0) {
        $codes = ($bsod | ForEach-Object { if ($_.Message -match '0x[0-9a-fA-F]{8}') { $Matches[0] } } | Select-Object -Unique) -join ', '
        Add-Result 'Stability' 'Blue screens' 'Critical' "$($bsod.Count) blue screen crash(es) in the last $Days days. Bug check codes: $codes." 'Look up the code; common causes are drivers, RAM and overheating. Dumps are in C:\Windows\Minidump.' -FixId memory-test
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
        Add-Result 'Updates' 'Pending restart' 'Warning' "A restart is pending ($($pending -join ', '))." 'Restart the PC to finish installing updates.' -FixId restart
    } else { Add-Result 'Updates' 'Pending restart' 'OK' 'No restart pending.' }

    $hf = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    if ($hf.Count -gt 0) {
        $last = $hf[0].InstalledOn
        $age = [math]::Round(((Get-Date) - $last).TotalDays)
        $txt = "Last update installed $($last.ToString('yyyy-MM-dd')) ($age days ago, $($hf[0].HotFixID))."
        if ($age -ge $T.UpdateCritDays) { Add-Result 'Updates' 'Windows Update' 'Critical' $txt 'Open Settings > Windows Update and install updates.' -FixId open-update }
        elseif ($age -ge $T.UpdateWarnDays) { Add-Result 'Updates' 'Windows Update' 'Warning' $txt 'Open Settings > Windows Update and check for updates.' -FixId open-update }
        else { Add-Result 'Updates' 'Windows Update' 'OK' $txt }
    }

    $wuFail = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 20 } 50
    if ($wuFail.Count -gt 0) {
        Add-Result 'Updates' 'Failed updates' 'Warning' "$($wuFail.Count) update installation failure(s) in the last $Days days." 'Run the Windows Update troubleshooter (Settings > System > Troubleshoot).' -FixId open-update
    }

    $wu = Get-Service wuauserv -ErrorAction SilentlyContinue
    if ($wu -and $wu.StartType -eq 'Disabled') {
        Add-Result 'Updates' 'Update service' 'Critical' 'The Windows Update service is disabled.' 'Set "Windows Update" service to Manual in services.msc.' -FixId wu-service
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
            Add-Result 'Security' 'Antivirus' 'Warning' "Third-party antivirus is on but its signatures are out of date: $(($stale.displayName) -join ', ')." 'Open the antivirus program and update it, or renew its subscription.' -FixId open-security
        } elseif ($on.Count -gt 0) {
            Add-Result 'Security' 'Antivirus' 'OK' "Third-party antivirus active: $(($on.displayName) -join ', ')."
        } elseif (-not $mp) {
            $offNote = if ($other.Count -gt 0) { " ($(($other.displayName) -join ', ') is installed but turned off)" } else { '' }
            Add-Result 'Security' 'Antivirus' 'Critical' "Microsoft Defender could not be queried (its service may be stopped) and no active antivirus was found$offNote." 'Open Windows Security > Virus & threat protection and turn protection on, or re-enable your antivirus.' -FixId open-security
        } else {
            $offNote = if ($other.Count -gt 0) { " ($(($other.displayName) -join ', ') is installed but turned off)" } else { '' }
            Add-Result 'Security' 'Antivirus' 'Critical' "Microsoft Defender real-time protection is off and no other active antivirus was found$offNote." 'Turn on real-time protection in Windows Security.' -FixId defender-on
        }
    } else {
        $sigAge = [math]::Round(((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays, 1)
        $txt = "Microsoft Defender on. Signatures $sigAge day(s) old."
        if ($sigAge -ge $T.DefSigCritDays) { Add-Result 'Security' 'Antivirus' 'Critical' $txt 'Update signatures: Windows Security > Virus protection > Check for updates.' -FixId defender-update }
        elseif ($sigAge -ge $T.DefSigWarnDays) { Add-Result 'Security' 'Antivirus' 'Warning' $txt 'Update antivirus signatures.' -FixId defender-update }
        else { Add-Result 'Security' 'Antivirus' 'OK' $txt }
    }
    if ($mp) {
        $threats = @()
        try { $threats = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $Since }) } catch {}
        if ($threats.Count -gt 0) {
            $active = @($threats | Where-Object { $_.ThreatStatusID -notin 2, 3, 4, 5, 6 })   # not removed/quarantined/allowed
            $sev = if ($active.Count -gt 0) { 'Critical' } else { 'Warning' }
            Add-Result 'Security' 'Malware detections' $sev "$($threats.Count) threat detection(s) in the last $Days days, $($active.Count) not yet resolved." 'Open Windows Security > Protection history and run a full scan.' -FixId open-security
        } else { Add-Result 'Security' 'Malware detections' 'OK' "No threats detected in the last $Days days." }
    }

    # Firewall
    try {
        $off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled })
        if ($off.Count -gt 0) {
            Add-Result 'Security' 'Firewall' 'Critical' "Firewall is OFF for profile(s): $(($off.Name) -join ', ')." 'Turn the firewall on in Windows Security > Firewall & network protection.' -FixId firewall-on
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
        Add-Result 'OS Health' 'Component store (DISM)' 'Critical' 'Windows system files are flagged as corrupted (repairable).' 'Run as admin: DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow' -FixId repair-system
    } else {
        $tail = ($out -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -Last 2) -join ' '
        Add-Result 'OS Health' 'Component store (DISM)' 'Warning' "DISM result unclear: $tail"
    }

    # Last SFC result, if CBS.log shows a recent run
    $cbs = "$env:SystemRoot\Logs\CBS\CBS.log"
    if (Test-Path $cbs) {
        $hit = Select-String -Path $cbs -Pattern 'found corrupt files and (was unable|successfully)' -ErrorAction SilentlyContinue | Select-Object -Last 1
        if ($hit -and $hit.Line -match 'unable') {
            Add-Result 'OS Health' 'Last SFC scan' 'Critical' 'The last sfc /scannow found corrupt files it could not fix.' 'Run DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow again.' -FixId repair-system
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
        Add-Result 'Services' "Service stopped: $($s.DisplayName)" $sev "Set to start automatically but is $($s.State) (exit code $($s.ExitCode))." "Try: Start-Service $($s.Name)  or restart the PC." -FixId start-service -FixArg $s.Name
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
    Add-Metric "Program crashes and hangs (last $Days days)" $all.Count -HigherIsWorse -PerWindow
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
    Add-Metric 'Startup programs' $enabled.Count -HigherIsWorse
    if ($enabled.Count -ge $T.StartupItemsWarn) {
        Add-Result 'Applications' 'Startup programs' 'Warning' "$($enabled.Count) programs start with Windows: $names." 'Disable ones you do not need in Task Manager > Startup apps.' -FixId open-startup
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
            Add-Result 'Applications' "Outdated: $($h.Name)" 'Warning' $e.W 'Uninstall it unless you specifically need it.' -FixId open-apps
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
    Add-Metric "System log errors (last $Days days)" $err.Count -HigherIsWorse -MinChange 10 -PerWindow
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
    Add-Metric 'Temporary files' ($size / 1GB) 'GB' -HigherIsWorse
    if ($size -ge ($T.TempFolderWarnGB * 1GB)) {
        Add-Result 'OS Health' 'Temporary files' 'Warning' "$(Format-GB $size) in temp folders." 'Settings > System > Storage > Temporary files, or run cleanmgr.' -FixId cleanmgr -FixArg $env:SystemDrive
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
            Add-Result 'OS Health' 'Clock sync' 'Warning' 'Windows Time service is disabled; the clock may drift and break HTTPS/logins.' 'Set the "Windows Time" service to Manual in services.msc, then sync in Settings > Time & language.' -FixId time-sync
        } elseif ($w32 -match 'Last Successful Sync Time:\s*(.+)') {
            $ls = $Matches[1].Trim()
            $dt = [datetime]::MinValue
            if ([datetime]::TryParse($ls, [ref]$dt) -and ((Get-Date) - $dt).TotalDays -gt 14) {
                Add-Result 'OS Health' 'Clock sync' 'Warning' "Clock last synced $ls." 'Settings > Time & language > Sync now.' -FixId time-sync
            } else { Add-Result 'OS Health' 'Clock sync' 'OK' "Last time sync: $ls." }
        }
    } catch {}

    # Power plan
    try {
        $plan = (Invoke-Native 'powercfg.exe' @('/getactivescheme')) -join ''
        if ($plan -match '\((.+)\)') {
            $name = $Matches[1]
            # Match the built-in Power saver plan by its GUID; plan names are translated
            if ($plan -match 'a1841308-3541-4fab-bc81-f71556f20b4a') { Add-Result 'Power' 'Power plan' 'Info' "Active plan: $name - performance is reduced." 'Switch to Balanced if the PC feels slow.' -FixId power-balanced }
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
        Add-Result 'Network' 'IP address' 'Warning' "Adapter(s) have no DHCP address (169.254.x.x): $(($apipa.InterfaceAlias) -join ', ')." 'Restart the router, or run: ipconfig /release && ipconfig /renew' -FixId renew-ip
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
        Add-Result 'Network' 'DNS' 'Critical' 'Cannot resolve internet names.' 'Run: ipconfig /flushdns, or set DNS to 1.1.1.1 / 8.8.8.8.' -FixId flush-dns
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
# COMPARISON WITH THE PREVIOUS SCAN
# ===========================================================================
function Get-PreviousData {
    param([string]$Dir, [string]$ExcludePath)
    $files = @(Get-ChildItem -Path $Dir -Filter "Diagnostic_$($env:COMPUTERNAME)_*.json" -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -ne $ExcludePath } | Sort-Object LastWriteTime -Descending)
    foreach ($f in $files) {
        try { return (Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch {}
    }
    $null
}

function Compare-Runs {
    param($Prev, $Curr)
    $rank = @{ OK = 0; Info = 0; Skipped = 0; Error = 1; Warning = 1; Critical = 2 }
    $worse = New-Object System.Collections.Generic.List[string]
    $better = New-Object System.Collections.Generic.List[string]
    $newCritical = New-Object System.Collections.Generic.List[string]

    $prevMap = @{}
    foreach ($r in @($Prev.Results)) { if ($r) { $prevMap["$($r.Category)|$($r.Check)"] = $r } }
    $currKeys = @{}
    foreach ($r in @($Curr.Results)) {
        $k = "$($r.Category)|$($r.Check)"
        $currKeys[$k] = $true
        $now = $rank[[string]$r.Status]
        if ($prevMap.ContainsKey($k)) {
            $p = $prevMap[$k]
            $was = $rank[[string]$p.Status]
            if ($now -gt $was) { $worse.Add("$($r.Check): $($p.Status) -> $($r.Status)") }
            elseif ($now -lt $was) { $better.Add("$($r.Check): $($p.Status) -> $($r.Status)") }
            if ($r.Status -eq 'Critical' -and $p.Status -ne 'Critical') { $newCritical.Add($r.Check) }
        } elseif ($now -gt 0) {
            $worse.Add("$($r.Check): new $($r.Status)")
            if ($r.Status -eq 'Critical') { $newCritical.Add($r.Check) }
        }
    }
    # A problem row disappears when it is fixed (e.g. a stopped service runs again).
    # Only trust that when both scans ran the same way (quick mode / admin rights).
    $sameMode = ((Get-Prop $Prev 'Quick') -eq (Get-Prop $Curr 'Quick')) -and ((Get-Prop $Prev 'IsAdmin') -eq (Get-Prop $Curr 'IsAdmin'))
    if ($sameMode) {
        foreach ($k in @($prevMap.Keys)) {
            $p = $prevMap[$k]
            if (-not $currKeys.ContainsKey($k) -and $p.Status -in 'Warning', 'Critical') {
                $better.Add("$($p.Check): no longer reported (was $($p.Status))")
            }
        }
    }

    $pm = @{}
    foreach ($m in @(Get-Prop $Prev 'Metrics' @())) { if ($m) { $pm[[string]$m.Name] = $m } }
    foreach ($m in @($Curr.Metrics)) {
        if (-not $pm.ContainsKey([string]$m.Name)) { continue }
        if ($m.PerWindow -and (Get-Prop $Prev 'Days') -ne (Get-Prop $Curr 'Days')) { continue }
        $old = [double]$pm[[string]$m.Name].Value
        $new = [double]$m.Value
        $d = $new - $old
        if ([math]::Abs($d) -lt [double]$m.MinChange) { continue }
        $unit = if ($m.Unit -eq '%') { '%' } elseif ($m.Unit) { " $($m.Unit)" } else { '' }
        $sign = if ($d -gt 0) { '+' } else { '' }
        $txt = '{0}: {1}{3} -> {2}{3} ({4}{5}{3})' -f $m.Name, $old, $new, $unit, $sign, [math]::Round($d, 1)
        if (($d -gt 0) -eq [bool]$m.HigherIsWorse) { $worse.Add($txt) } else { $better.Add($txt) }
    }

    [pscustomobject]@{
        Since       = Get-Prop $Prev 'Generated' '?'
        Worse       = $worse.ToArray()
        Better      = $better.ToArray()
        NewCritical = $newCritical.ToArray()
    }
}

# ===========================================================================
# REPORT
# ===========================================================================
function Get-Overall {
    param($Counts)
    if ($Counts.Critical -gt 0) { 'Critical' } elseif ($Counts.Warning -gt 0 -or $Counts.Error -gt 0) { 'Warning' } else { 'OK' }
}

function Get-Headline {
    param([string]$Overall, $Counts)
    if ($Overall -eq 'Critical') { return "$($Counts.Critical) serious problem(s) need attention" }
    if ($Overall -eq 'Warning') {
        if ($Counts.Warning -gt 0) { return "$($Counts.Warning) issue(s) worth looking at" }
        return "$($Counts.Error) check(s) could not run"
    }
    'No problems found'
}

# Hides the PC name, user name and profile path, for the shareable report.
function Protect-Text {
    param([string]$Text)
    if (-not $Text) { return $Text }
    $pairs = @(, @($env:USERPROFILE, '%USERPROFILE%'))
    $pairs += , @($env:COMPUTERNAME, 'THIS-PC')
    if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) { $pairs += , @($env:USERDOMAIN, 'DOMAIN') }
    if ($env:USERNAME -and $env:USERNAME.Length -ge 3) { $pairs += , @($env:USERNAME, 'user') }
    foreach ($p in $pairs) {
        if ($p[0]) {
            $pattern = '(?<![A-Za-z0-9])' + [regex]::Escape($p[0]) + '(?![A-Za-z0-9])'
            $Text = [regex]::Replace($Text, $pattern, $p[1], 'IgnoreCase')
        }
    }
    $Text
}

function Write-Report {
    param($Data, [string]$Path, [switch]$Redact)
    $order = @{ Critical = 0; Error = 1; Warning = 2; Info = 3; Skipped = 4; OK = 5 }
    if ($Redact) { $e = { param($x) [System.Net.WebUtility]::HtmlEncode((Protect-Text ([string]$x))) } }
    else { $e = { param($x) [System.Net.WebUtility]::HtmlEncode([string]$x) } }

    $results = @($Data.Results | Where-Object { $_ })
    $counts = $Data.Counts
    $overall = [string]$Data.Overall
    $headline = Get-Headline $overall $counts

    # Issues
    $issues = @($results | Where-Object { $_.Status -in 'Critical', 'Warning', 'Error' } |
                Sort-Object @{ e = { $order[[string]$_.Status] } }, Category)
    if ($issues.Count -eq 0) { $issueHtml = '<p class="none">Nothing needs fixing. Nice.</p>' }
    else {
        $issueHtml = ($issues | ForEach-Object {
            $st = ([string]$_.Status).ToLower()
            $fid = [string](Get-Prop $_ 'FixId' '')
            $oneClick = ''
            if ($fid -and $script:FixActions.Contains($fid)) {
                $title = $script:FixActions[$fid].Title -f [string](Get-Prop $_ 'FixArg' '')
                $oneClick = "<div class='fix'><b>One-click fix:</b> $(& $e $title) <span class='mut'>(in the Diagnostic-kun window)</span></div>"
            }
            $what = if ($_.Fix) { "<div class='fix'><b>What to do:</b> $(& $e $_.Fix)</div>" } else { '' }
            "<div class='issue $st'><div class='ih'><span class='badge $st'>$($_.Status)</span><b>$(& $e $_.Check)</b><span class='cat'>$(& $e $_.Category)</span></div><div>$(& $e $_.Detail)</div>$what$oneClick</div>"
        }) -join "`n"
    }

    # Changes since the last scan
    $cmp = Get-Prop $Data 'Comparison'
    if ($cmp) {
        $worse = @(Get-Prop $cmp 'Worse' @() | Where-Object { $_ })
        $better = @(Get-Prop $cmp 'Better' @() | Where-Object { $_ })
        $since = & $e (Get-Prop $cmp 'Since' '?')
        if (($worse.Count + $better.Count) -eq 0) { $chgHtml = "<p class='none'>Nothing changed since the last scan ($since).</p>" }
        else {
            $chgHtml = "<p class='sub'>Compared with the scan on $since.</p><div class='chg'>"
            if ($worse.Count -gt 0) { $chgHtml += "<div><h3 class='w'>Got worse ($($worse.Count))</h3><ul>" + (($worse | ForEach-Object { "<li>$(& $e $_)</li>" }) -join '') + '</ul></div>' }
            if ($better.Count -gt 0) { $chgHtml += "<div><h3 class='b'>Improved ($($better.Count))</h3><ul>" + (($better | ForEach-Object { "<li>$(& $e $_)</li>" }) -join '') + '</ul></div>' }
            $chgHtml += '</div>'
        }
    } else {
        $chgHtml = "<p class='none'>This is the first saved scan of this PC. Next time, this section shows what changed.</p>"
    }

    # All checks, grouped by area
    $catHtml = ($results | Group-Object Category | ForEach-Object {
        $sorted = @($_.Group | Sort-Object @{ e = { $order[[string]$_.Status] } })
        $rows = ($sorted | ForEach-Object {
            $st = ([string]$_.Status).ToLower()
            $fixTxt = if ($_.Fix -and $_.Status -ne 'OK') { "<div class='fix'>$(& $e $_.Fix)</div>" } else { '' }
            "<tr><td><span class='badge $st'>$($_.Status)</span></td><td>$(& $e $_.Check)</td><td>$(& $e $_.Detail)$fixTxt</td></tr>"
        }) -join ''
        $worst = ([string]$sorted[0].Status).ToLower()
        $open = if ($worst -in 'critical', 'warning', 'error') { 'open' } else { '' }
        "<details class='sec' $open><summary><span class='dot $worst'></span>$(& $e $_.Name)<span class='n'>$($_.Count) checks</span></summary><table>$rows</table></details>"
    }) -join "`n"

    # Overview (an ordered dictionary when live, an object when read back from JSON)
    $ov = Get-Prop $Data 'Overview'
    $ovRows = @()
    if ($ov -is [System.Collections.IDictionary]) { foreach ($k in $ov.Keys) { $ovRows += "<tr><th>$(& $e $k)</th><td>$(& $e $ov[$k])</td></tr>" } }
    elseif ($ov) { foreach ($p in $ov.PSObject.Properties) { $ovRows += "<tr><th>$(& $e $p.Name)</th><td>$(& $e $p.Value)</td></tr>" } }
    $ovHtml = $ovRows -join ''

    $apps = @(Get-Prop $Data 'Installed' @() | Where-Object { $_ })
    if ($Redact) { $appSection = "<h2>Installed programs</h2><p class='sub'>Hidden in this shareable copy.</p>" }
    else {
        $appHtml = ($apps | ForEach-Object { "<tr><td>$(& $e $_.Name)</td><td>$(& $e $_.Version)</td><td>$(& $e $_.Publisher)</td></tr>" }) -join ''
        $appSection = "<h2>Installed programs ($($apps.Count))</h2><details class='sec'><summary>Show list</summary><table>$appHtml</table></details>"
    }

    $computer = & $e (Get-Prop $Data 'Computer' $env:COMPUTERNAME)
    $generated = & $e (Get-Prop $Data 'Generated' '')
    $days = Get-Prop $Data 'Days' 7
    $ver = & $e (Get-Prop $Data 'Version' '')
    $adminNote = if (-not (Get-Prop $Data 'IsAdmin' $true)) { ' &middot; <b>not run as admin - some checks skipped</b>' } else { '' }
    $shareNote = if ($Redact) { "<p class='share'>Shareable copy: the PC name, user name and installed programs are hidden.</p>" } else { '' }
    $ovColor = @{ OK = 'ok'; Warning = 'warn'; Critical = 'crit' }[$overall]

    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PC Diagnostic - $computer</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#667085;--line:#e4e7ec;--ok:#12805c;--info:#2e6fd8;--warn:#b26b00;--crit:#c4282d;--skip:#8a8f98}
@media (prefers-color-scheme:dark){:root{--bg:#14161b;--card:#1d2027;--fg:#e8eaee;--mut:#9aa1ad;--line:#2d313a;--ok:#3cc28f;--info:#6b9ff0;--warn:#e9a23b;--crit:#f0646a;--skip:#8a8f98}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 60px}h1{margin:0 0 4px;font-size:26px}h2{margin:32px 0 12px;font-size:18px}
.sub,.mut{color:var(--mut)}.hero{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--ov);border-radius:10px;padding:18px 20px;margin:20px 0}
.hero b{font-size:20px;color:var(--ov)}.counts{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}.counts span{padding:4px 10px;border-radius:999px;background:var(--bg);font-size:13px}
.badge{display:inline-block;min-width:68px;text-align:center;padding:1px 8px;border-radius:5px;font-size:12px;font-weight:600;color:#fff}
.badge.ok{background:var(--ok)}.badge.info{background:var(--info)}.badge.warning{background:var(--warn)}.badge.critical,.badge.error{background:var(--crit)}.badge.skipped{background:var(--skip)}
.issue{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--warn);border-radius:8px;padding:12px 14px;margin-bottom:10px}
.issue.critical,.issue.error{border-left-color:var(--crit)}.ih{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:4px}.cat{color:var(--mut);font-size:13px;margin-left:auto}
.fix{margin-top:6px;color:var(--mut);font-size:14px}.none,.share{background:var(--card);padding:12px 14px;border-radius:8px;border:1px solid var(--line)}.share{border-style:dashed}
.chg{display:grid;grid-template-columns:1fr 1fr;gap:12px}.chg>div{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px}
.chg h3{margin:0 0 6px;font-size:15px}.chg h3.w{color:var(--crit)}.chg h3.b{color:var(--ok)}.chg ul{margin:0;padding-left:18px}
.sec{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:8px}.sec summary{cursor:pointer;padding:10px 14px;font-weight:600;display:flex;align-items:center;gap:10px}
.n{margin-left:auto;color:var(--mut);font-weight:400;font-size:13px}.dot{width:10px;height:10px;border-radius:50%;background:var(--ok)}
.dot.warning{background:var(--warn)}.dot.critical,.dot.error{background:var(--crit)}.dot.info{background:var(--info)}.dot.skipped{background:var(--skip)}
table{width:100%;border-collapse:collapse}td,th{padding:7px 14px;border-top:1px solid var(--line);text-align:left;vertical-align:top}
.sec td:first-child{width:90px}.sec td:nth-child(2){width:28%;font-weight:500}th{color:var(--mut);font-weight:500;width:200px}
.box{background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:auto}
@media (max-width:640px){.sec td:nth-child(2){width:auto}td,th{padding:6px 10px}th{width:auto}.chg{grid-template-columns:1fr}}
</style></head><body><main>
<h1>PC Diagnostic Report</h1>
<div class="sub">$computer &middot; $generated &middot; event logs checked for the last $days days$adminNote</div>
$shareNote
<div class="hero" style="--ov:var(--$ovColor)"><b>$headline</b>
<div class="counts"><span>Critical: $($counts.Critical)</span><span>Warning: $($counts.Warning)</span><span>Info: $($counts.Info)</span><span>OK: $($counts.OK)</span><span>Skipped: $($counts.Skipped)</span><span>Check errors: $($counts.Error)</span></div></div>
<h2>Changes since the last scan</h2>
$chgHtml
<h2>Issues found</h2>
$issueHtml
<h2>All checks</h2>
$catHtml
<h2>System overview</h2>
<div class="box"><table>$ovHtml</table></div>
$appSection
<p class="sub">Generated by Diagnostic-kun $ver. Read-only: no changes were made to this PC.</p>
</main></body></html>
"@
    Set-Content -Path $Path -Value $html -Encoding UTF8
}

# ===========================================================================
# SCAN
# ===========================================================================
function Write-ScanProgress {
    param([string]$Text)
    if ($ProgressFile) { try { [IO.File]::WriteAllText($ProgressFile, $Text) } catch {} }
}

function Remove-OldReports {
    param([string]$Dir)
    $old = @(Get-ChildItem -Path $Dir -Filter "Diagnostic_$($env:COMPUTERNAME)_*.json" -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending | Select-Object -Skip $script:KeepRuns)
    foreach ($f in $old) {
        $base = Join-Path $f.DirectoryName ([IO.Path]::GetFileNameWithoutExtension($f.Name))
        foreach ($ext in '.json', '.html', '_shareable.html') { Remove-Item -LiteralPath ($base + $ext) -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-Scan {
    $script:Results.Clear()
    $script:Metrics.Clear()
    $script:Overview = [ordered]@{}
    $script:InstalledApps = @()

    $checks = @(
        @('System',       'System information',          ${function:Test-SystemInfo}),
        @('CPU',          'Processor and load',          ${function:Test-Cpu}),
        @('Temperatures', 'Temperatures and fans',       ${function:Test-Sensors}),
        @('Memory',       'RAM',                         ${function:Test-Memory}),
        @('Storage',      'Disks and volumes',           ${function:Test-Storage}),
        @('Graphics',     'Graphics adapters',           ${function:Test-Gpu}),
        @('Power',        'Battery',                     ${function:Test-Battery}),
        @('Devices',      'Device Manager',              ${function:Test-Devices}),
        @('Stability',    'Crashes and hardware errors', ${function:Test-HardwareErrors}),
        @('Updates',      'Windows Update',              ${function:Test-WindowsUpdate}),
        @('Security',     'Security settings',           ${function:Test-Security}),
        @('OS Health',    'System file integrity',       ${function:Test-SystemFiles}),
        @('Services',     'Windows services',            ${function:Test-Services}),
        @('Drivers',      'Drivers',                     ${function:Test-Drivers}),
        @('Applications', 'Program crashes',             ${function:Test-AppCrashes}),
        @('Applications', 'Startup programs',            ${function:Test-Startup}),
        @('Applications', 'Installed software',          ${function:Test-InstalledSoftware}),
        @('OS Health',    'System event log',            ${function:Test-SystemEvents}),
        @('OS Health',    'Housekeeping',                ${function:Test-Housekeeping}),
        @('Network',      'Network',                     ${function:Test-Network})
    )
    $i = 0
    foreach ($c in $checks) {
        $i++
        Write-ScanProgress "$i|$($checks.Count)|$($c[1])"
        Invoke-Check $c[0] $c[1] $c[2]
    }
    Write-ScanProgress "$($checks.Count)|$($checks.Count)|Writing the report"

    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
    $base = Join-Path $OutputDir ("Diagnostic_{0}_{1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    $counts = [ordered]@{}
    foreach ($s in 'Critical', 'Error', 'Warning', 'Info', 'Skipped', 'OK') { $counts[$s] = @($script:Results | Where-Object { $_.Status -eq $s }).Count }
    $data = [pscustomobject]@{
        Tool       = 'Diagnostic-kun'
        Version    = $script:Version
        Generated  = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Computer   = $env:COMPUTERNAME
        Days       = $Days
        Quick      = [bool]$Quick
        IsAdmin    = $script:IsAdmin
        Overall    = Get-Overall $counts
        Counts     = $counts
        Overview   = $script:Overview
        Results    = $script:Results.ToArray()
        Metrics    = $script:Metrics.ToArray()
        Installed  = @($script:InstalledApps)
        Comparison = $null
    }
    $prev = Get-PreviousData -Dir $OutputDir -ExcludePath "$base.json"
    if ($prev) { $data.Comparison = Compare-Runs $prev $data }

    $data | ConvertTo-Json -Depth 6 | Set-Content -Path "$base.json" -Encoding UTF8
    Write-Report -Data $data -Path "$base.html"
    $share = $null
    if ($Shareable) { $share = "$($base)_shareable.html"; Write-Report -Data $data -Path $share -Redact }
    Remove-OldReports $OutputDir
    Write-ScanProgress "done|$base.json|$base.html"
    [pscustomobject]@{ Data = $data; Html = "$base.html"; Json = "$base.json"; Shareable = $share }
}

function Write-ConsoleSummary {
    param($Run)
    $d = $Run.Data
    $color = @{ OK = 'Green'; Warning = 'Yellow'; Critical = 'Red' }[[string]$d.Overall]
    Write-Host ''
    Write-Host ("  Result: {0} - {1}  (Critical {2}, Warning {3}, OK {4}, could not run {5})" -f $d.Overall, (Get-Headline $d.Overall $d.Counts), $d.Counts.Critical, $d.Counts.Warning, $d.Counts.OK, $d.Counts.Error) -ForegroundColor $color
    $cmp = $d.Comparison
    if ($cmp) {
        Write-Host ("  Since the last scan ({0}): {1} got worse, {2} improved." -f $cmp.Since, @($cmp.Worse).Count, @($cmp.Better).Count)
        foreach ($w in (@($cmp.Worse) | Select-Object -First 5)) { Write-Host "    - $w" -ForegroundColor Yellow }
    }
    Write-Host "  Report: $($Run.Html)"
    if ($Run.Shareable) { Write-Host "  Shareable copy (no PC name, user name or program list): $($Run.Shareable)" }
    Write-Host "  Data:   $($Run.Json)"
    Write-Host ''
}

# ===========================================================================
# WEEKLY CHECK AND NOTIFICATIONS
# ===========================================================================
function Test-WeeklyCheck { [bool](Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue) }

# Returns a description of when it runs, e.g. "Monday at 12:00".
function Install-WeeklyCheck {
    if (-not $script:IsAdmin) { throw 'Turning on the weekly check needs administrator rights. Start Diagnostic-kun with RunDiagnostic.bat.' }
    $exe = Join-Path $PSHOME 'powershell.exe'
    $argLine = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Scheduled -OutputDir `"$OutputDir`" -Days 7"
    $day = (Get-Date).DayOfWeek
    $action = New-ScheduledTaskAction -Execute $exe -Argument $argLine
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $day -At '12:00'
    # Runs as the signed-in user (so the notification is visible), with admin rights for the full check
    $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    $null = Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Weekly PC health check by Diagnostic-kun. Shows a notification only when something becomes critical.' -Force
    "$day at 12:00"
}

function Remove-WeeklyCheck {
    if (Test-WeeklyCheck) { Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false }
}

function Show-Notification {
    param([string]$Title, [string]$Text, [string]$OpenPath)
    $esc = { param($s) [Security.SecurityElement]::Escape([string]$s) }
    try {
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $launch = ''
        if ($OpenPath) { $launch = " activationType=`"protocol`" launch=`"$(& $esc ([Uri]$OpenPath).AbsoluteUri)`"" }
        $xml = "<toast$launch><visual><binding template=`"ToastGeneric`"><text>$(& $esc $Title)</text><text>$(& $esc $Text)</text></binding></visual></toast>"
        $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $doc.LoadXml($xml)
        # The app id of Windows PowerShell, so Windows accepts the notification without registering an app
        $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show([Windows.UI.Notifications.ToastNotification]::new($doc))
    } catch {
        # Fallback: a tray balloon
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        $icon = New-Object System.Windows.Forms.NotifyIcon
        $icon.Icon = [System.Drawing.SystemIcons]::Warning
        $icon.Visible = $true
        $icon.ShowBalloonTip(15000, $Title, $Text, [System.Windows.Forms.ToolTipIcon]::Warning)
        Start-Sleep -Seconds 15
        $icon.Dispose()
    }
}

# ===========================================================================
# WINDOW (-Gui)
# ===========================================================================
# The scan runs in a separate hidden PowerShell process that reports progress
# through a small text file, so the window never freezes during slow checks.
function Set-ConsoleVisible {
    param([bool]$Visible)
    try {
        if (-not ('DiagKun.ConsoleWindow' -as [type])) {
            Add-Type -Namespace DiagKun -Name ConsoleWindow -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
        }
        $h = [DiagKun.ConsoleWindow]::GetConsoleWindow()
        if ($h -ne [IntPtr]::Zero) { $null = [DiagKun.ConsoleWindow]::ShowWindow($h, $(if ($Visible) { 5 } else { 0 })) }
    } catch {}
}

function New-Ctl {
    param([string]$Type, [int]$X, [int]$Y, [int]$W, [int]$H, [string]$Text = '', [string]$Anchor = 'Top,Left')
    $c = New-Object "System.Windows.Forms.$Type"
    $c.Location = New-Object System.Drawing.Point($X, $Y)
    $c.Size = New-Object System.Drawing.Size($W, $H)
    if ($Text) { $c.Text = $Text }
    $c.Anchor = [System.Windows.Forms.AnchorStyles]$Anchor
    $c
}

function Show-Message {
    param([string]$Text, [string]$Icon = 'Information')
    [void][System.Windows.Forms.MessageBox]::Show($Text, 'Diagnostic-kun', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]$Icon)
}

# Event handlers run through this so an error shows a message instead of crashing the window.
function Invoke-Safely {
    param([scriptblock]$Body)
    try { & $Body } catch { Show-Message "Something went wrong: $($_.Exception.Message)" 'Error' }
}

function Read-ScanProgress {
    if (-not $script:GuiProgress) { return $null }
    $t = $null
    try { $t = [IO.File]::ReadAllText($script:GuiProgress) } catch { return $null }
    if (-not $t) { return $null }
    , $t.Split('|')
}

function Start-GuiScan {
    $ui = $script:ui
    Stop-GuiScan
    $script:GuiProgress = Join-Path ([IO.Path]::GetTempPath()) ("dk_progress_{0}.txt" -f [guid]::NewGuid())
    $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -NoOpen -ProgressFile `"$($script:GuiProgress)`" -OutputDir `"$OutputDir`" -Days $Days"
    if ($Quick) { $argLine += ' -Quick' }
    $script:ScanProc = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $argLine -WindowStyle Hidden -PassThru
    $null = $script:ScanProc.Handle
    $ui.ResultsPanel.Visible = $false
    $ui.ScanPanel.Visible = $true
    $ui.Bar.Value = 0
    $ui.Step.Text = 'Starting the scan...'
    $ui.Timer.Start()
}

function Stop-GuiScan {
    if ($script:ui -and $script:ui.Timer) { $script:ui.Timer.Stop() }
    $p = $script:ScanProc
    if ($p -and -not $p.HasExited) { try { $p.Kill() } catch {} }
    if ($script:GuiProgress) { Remove-Item $script:GuiProgress -Force -ErrorAction SilentlyContinue }
}

function Complete-GuiScan {
    param($State)
    $script:ui.Timer.Stop()
    Remove-Item $script:GuiProgress -Force -ErrorAction SilentlyContinue
    $data = Get-Content $State[1] -Raw | ConvertFrom-Json
    Show-GuiResults -Data $data -HtmlPath $State[2]
}

function Update-ScanState {
    $ui = $script:ui
    $state = Read-ScanProgress
    if ($state -and $state[0] -eq 'done') { Complete-GuiScan $state; return }
    if ($state -and $state.Count -ge 3) {
        $i = 0; $n = 0
        if ([int]::TryParse($state[0], [ref]$i) -and [int]::TryParse($state[1], [ref]$n) -and $n -gt 0) {
            $ui.Bar.Value = [math]::Max(0, [math]::Min(100, [int](($i - 1) * 100 / $n)))
            $ui.Step.Text = "Checking: $($state[2])   ($i of $n)"
        }
    }
    if ($script:ScanProc -and $script:ScanProc.HasExited) {
        $state = Read-ScanProgress   # it may have finished between the two reads
        if ($state -and $state[0] -eq 'done') { Complete-GuiScan $state; return }
        $ui.Timer.Stop()
        $ui.Step.Text = "The scan stopped unexpectedly (exit code $($script:ScanProc.ExitCode)). Close this window and run RunDiagnostic.bat again."
    }
}

function Show-GuiResults {
    param($Data, [string]$HtmlPath)
    $ui = $script:ui
    $script:GuiData = $Data
    $script:GuiHtml = $HtmlPath
    $colors = @{
        Critical = [System.Drawing.Color]::FromArgb(196, 40, 45)
        Error    = [System.Drawing.Color]::FromArgb(196, 40, 45)
        Warning  = [System.Drawing.Color]::FromArgb(178, 107, 0)
        OK       = [System.Drawing.Color]::FromArgb(18, 128, 92)
    }
    $overall = [string]$Data.Overall
    $c = $Data.Counts
    $ui.Headline.Text = Get-Headline $overall $c
    $ui.Headline.ForeColor = $colors[$overall]
    $ui.Counts.Text = "Critical: $($c.Critical)    Warning: $($c.Warning)    Info: $($c.Info)    OK: $($c.OK)    Skipped: $($c.Skipped)    Could not run: $($c.Error)"

    $cmp = Get-Prop $Data 'Comparison'
    if ($cmp) {
        $w = @(Get-Prop $cmp 'Worse' @() | Where-Object { $_ })
        $b = @(Get-Prop $cmp 'Better' @() | Where-Object { $_ })
        $txt = "Since the last scan ($(Get-Prop $cmp 'Since' '?')): $($w.Count) got worse, $($b.Count) improved."
        if ($w.Count -gt 0) { $txt += '  ' + (($w | Select-Object -First 2) -join ';  ') }
        $ui.Changes.Text = $txt
    } else {
        $ui.Changes.Text = 'First scan of this PC. Next time you will see what changed since this one.'
    }

    $order = @{ Critical = 0; Error = 1; Warning = 2 }
    $issues = @(@($Data.Results) | Where-Object { $_ -and $order.ContainsKey([string]$_.Status) } | Sort-Object @{ e = { $order[[string]$_.Status] } })
    $ui.List.BeginUpdate()
    $ui.List.Items.Clear()
    foreach ($r in $issues) {
        $item = New-Object System.Windows.Forms.ListViewItem([string]$r.Status)
        [void]$item.SubItems.Add([string]$r.Category)
        [void]$item.SubItems.Add([string]$r.Check)
        [void]$item.SubItems.Add([string]$r.Detail)
        $item.ForeColor = $colors[[string]$r.Status]
        [void]$ui.List.Items.Add($item)
    }
    if ($issues.Count -eq 0) {
        $item = New-Object System.Windows.Forms.ListViewItem('OK')
        [void]$item.SubItems.Add('')
        [void]$item.SubItems.Add('No problems found')
        [void]$item.SubItems.Add('Everything that was checked looks fine.')
        $item.ForeColor = $colors['OK']
        [void]$ui.List.Items.Add($item)
    }
    $ui.List.EndUpdate()

    $script:GuiFixList = Get-AvailableFixes $Data.Results
    $ui.Fixes.Items.Clear()
    foreach ($fx in $script:GuiFixList) { [void]$ui.Fixes.Items.Add("$($fx.Title)    (for: $($fx.Reason))") }
    $hasFixes = $script:GuiFixList.Count -gt 0
    if (-not $hasFixes) { [void]$ui.Fixes.Items.Add('No automatic fixes for the problems found.') }
    $ui.Fixes.Enabled = $hasFixes
    $ui.RunFix.Enabled = $hasFixes
    $ui.Open.Enabled = [bool]$HtmlPath
    $ui.Share.Enabled = [bool]$HtmlPath
    Update-WeeklyButton
    $ui.ScanPanel.Visible = $false
    $ui.ResultsPanel.Visible = $true
}

function Invoke-GuiFixes {
    $ui = $script:ui
    $chosen = @(foreach ($i in $ui.Fixes.CheckedIndices) { $script:GuiFixList[$i] })
    if ($chosen.Count -eq 0) { Show-Message 'Tick the fixes you want to run first.'; return }
    $msg = "Run these fixes?`n`n" + (($chosen | ForEach-Object { "- $($_.Title)" }) -join "`n")
    $answer = [System.Windows.Forms.MessageBox]::Show($msg, 'Diagnostic-kun', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    $ui.Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try { $out = @(foreach ($c in @($chosen | Sort-Object Order)) { Invoke-Fix $c }) }
    finally { $ui.Form.Cursor = [System.Windows.Forms.Cursors]::Default }
    for ($i = 0; $i -lt $ui.Fixes.Items.Count; $i++) { $ui.Fixes.SetItemChecked($i, $false) }
    Show-Message (($out -join "`n") + "`n`nClick ""Scan again"" to check the result.")
}

function Save-ShareableCopy {
    $path = $script:GuiHtml -replace '\.html$', '_shareable.html'
    Write-Report -Data $script:GuiData -Path $path -Redact
    Start-Process explorer.exe -ArgumentList "/select,`"$path`""
}

function Update-WeeklyButton {
    $script:ui.Weekly.Text = if (Test-WeeklyCheck) { 'Weekly check: ON (turn off)' } else { 'Turn on weekly check' }
}

function Switch-WeeklyCheck {
    if (Test-WeeklyCheck) {
        Remove-WeeklyCheck
        Show-Message 'The weekly check is turned off.'
    } else {
        $when = Install-WeeklyCheck
        Show-Message "The weekly check is on: every $when (or the next time the PC is on).`n`nYou only get a notification when something becomes critical. Keep this folder where it is - the check runs from here."
    }
    Update-WeeklyButton
}

function Show-DiagnosticWindow {
    param([switch]$SelfTest)
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $script:ScanProc = $null
    $script:GuiProgress = $null
    $script:GuiHtml = $null
    $script:GuiData = $null
    $script:GuiFixList = @()
    $ui = @{}
    $script:ui = $ui

    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Diagnostic-kun $script:Version"
    $f.ClientSize = New-Object System.Drawing.Size(900, 620)
    $f.MinimumSize = New-Object System.Drawing.Size(780, 580)
    $f.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $f.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $f.BackColor = [System.Drawing.Color]::White
    $ui.Form = $f

    $title = New-Ctl Label 20 12 860 36 'PC health check' 'Top,Left,Right'
    $title.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
    $sub = New-Ctl Label 22 50 860 24 'Checks your hardware and software. Nothing on the PC changes unless you choose a fix.' 'Top,Left,Right'
    $sub.ForeColor = [System.Drawing.Color]::DimGray

    # While scanning
    $scan = New-Ctl Panel 20 90 860 110 '' 'Top,Left,Right'
    $ui.Step = New-Ctl Label 0 0 860 24 'Starting the scan...' 'Top,Left,Right'
    $ui.Bar = New-Ctl ProgressBar 0 30 860 22 '' 'Top,Left,Right'
    $ui.Bar.Maximum = 100
    $ui.Cancel = New-Ctl Button 0 66 110 32 'Cancel'
    $scan.Controls.AddRange(@($ui.Step, $ui.Bar, $ui.Cancel))
    $ui.ScanPanel = $scan

    # After the scan
    $res = New-Ctl Panel 20 82 860 528 '' 'Top,Bottom,Left,Right'
    $res.Visible = $false
    $ui.Headline = New-Ctl Label 0 0 860 32 '' 'Top,Left,Right'
    $ui.Headline.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
    $ui.Counts = New-Ctl Label 0 34 860 22 '' 'Top,Left,Right'
    $ui.Changes = New-Ctl Label 0 58 860 42 '' 'Top,Left,Right'
    $ui.Changes.ForeColor = [System.Drawing.Color]::DimGray
    $ui.List = New-Ctl ListView 0 102 860 196 '' 'Top,Bottom,Left,Right'
    $ui.List.View = [System.Windows.Forms.View]::Details
    $ui.List.FullRowSelect = $true
    $ui.List.ShowItemToolTips = $true
    foreach ($col in @(@('Status', 80), @('Area', 110), @('Check', 230), @('Details', 420))) { [void]$ui.List.Columns.Add($col[0], $col[1]) }
    $fixLbl = New-Ctl Label 0 306 860 22 'Fixes you can run: tick them and click "Run selected fixes". Nothing runs until you confirm.' 'Bottom,Left,Right'
    $ui.Fixes = New-Ctl CheckedListBox 0 330 860 128 '' 'Bottom,Left,Right'
    $ui.Fixes.CheckOnClick = $true
    $ui.Fixes.IntegralHeight = $false
    $ui.RunFix = New-Ctl Button 0 470 170 36 'Run selected fixes' 'Bottom,Left'
    $ui.Open = New-Ctl Button 180 470 150 36 'Open full report' 'Bottom,Left'
    $ui.Share = New-Ctl Button 340 470 170 36 'Save shareable copy' 'Bottom,Left'
    $ui.Weekly = New-Ctl Button 520 470 200 36 'Turn on weekly check' 'Bottom,Left'
    $ui.Again = New-Ctl Button 730 470 130 36 'Scan again' 'Bottom,Left'
    $res.Controls.AddRange(@($ui.Headline, $ui.Counts, $ui.Changes, $ui.List, $fixLbl, $ui.Fixes, $ui.RunFix, $ui.Open, $ui.Share, $ui.Weekly, $ui.Again))
    $ui.ResultsPanel = $res

    $f.Controls.AddRange(@($title, $sub, $scan, $res))

    $ui.Timer = New-Object System.Windows.Forms.Timer
    $ui.Timer.Interval = 300
    $ui.Timer.add_Tick({ Invoke-Safely { Update-ScanState } })
    $ui.Cancel.add_Click({ $script:ui.Form.Close() })
    $ui.RunFix.add_Click({ Invoke-Safely { Invoke-GuiFixes } })
    $ui.Open.add_Click({ Invoke-Safely { Start-Process $script:GuiHtml } })
    $ui.Share.add_Click({ Invoke-Safely { Save-ShareableCopy } })
    $ui.Weekly.add_Click({ Invoke-Safely { Switch-WeeklyCheck } })
    $ui.Again.add_Click({ Invoke-Safely { Start-GuiScan } })
    $f.add_FormClosing({ Stop-GuiScan })

    if ($SelfTest) {
        # Used by the automated tests: build the window and fill it from the latest saved report, without showing it
        $last = Get-PreviousData -Dir $OutputDir -ExcludePath ''
        if ($last) { Show-GuiResults -Data $last -HtmlPath 'selftest.html' }
        $ui.Timer.Dispose()
        $f.Dispose()
        return
    }

    Set-ConsoleVisible $false
    $f.add_Shown({ Invoke-Safely { Start-GuiScan } })
    [void]$f.ShowDialog()
    $ui.Timer.Dispose()
    $f.Dispose()
}

# ===========================================================================
# MAIN
# ===========================================================================
$script:PauseAtEnd = $false

if ($SensorProbe) { Invoke-SensorProbe -OutFile $SensorProbe; exit 0 }
if ($InstallSchedule) { $when = Install-WeeklyCheck; Write-Host "Weekly check turned on: every $when."; exit 0 }
if ($RemoveSchedule) { Remove-WeeklyCheck; Write-Host 'Weekly check turned off.'; exit 0 }
if ($GuiSelfTest) { Show-DiagnosticWindow -SelfTest; Write-Host 'Window self-test passed.'; exit 0 }

if ($Gui) {
    try {
        Show-DiagnosticWindow
        exit 0
    } catch {
        Set-ConsoleVisible $true
        Write-Host "The window could not be shown ($($_.Exception.Message)). Running in this console instead." -ForegroundColor Yellow
        $Fix = [switch]$true
        $script:PauseAtEnd = $true
    }
}

try {
    if (-not $Scheduled) {
        Write-Host ''
        Write-Host "  Diagnostic-kun $script:Version - Windows PC health check" -ForegroundColor Cyan
        if (-not $script:IsAdmin) { Write-Host '  Not running as Administrator: some checks will be skipped.' -ForegroundColor Yellow }
        Write-Host ''
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $run = Invoke-Scan
    Write-ConsoleSummary $run
    Write-Host ("  Finished in {0:N0}s" -f $sw.Elapsed.TotalSeconds)

    if ($Scheduled) {
        # Weekly task: notify only when something newly became critical
        # (or on the first run, when anything is critical)
        $cmp = $run.Data.Comparison
        $newCrit = @(Get-Prop $cmp 'NewCritical' @() | Where-Object { $_ })
        if ($newCrit.Count -gt 0 -or (-not $cmp -and $run.Data.Overall -eq 'Critical')) {
            $what = if ($newCrit.Count -gt 0) { 'New: ' + (($newCrit | Select-Object -First 3) -join ', ') } else { Get-Headline $run.Data.Overall $run.Data.Counts }
            Show-Notification 'Diagnostic-kun found a serious problem' "$what. Click to open the report." $run.Html
        }
    } else {
        if (-not $NoOpen) { Start-Process $run.Html }
        if ($Fix) { Invoke-FixMenu $run.Data }
    }
    if ($script:PauseAtEnd) { $null = Read-Host 'Press Enter to close' }
    exit @{ OK = 0; Warning = 1; Critical = 2 }[[string]$run.Data.Overall]
} catch {
    Write-Host "Diagnostic-kun stopped with an error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    exit 3
}
