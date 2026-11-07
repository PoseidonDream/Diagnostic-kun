<#
.SYNOPSIS
    Automated checks for Diagnostic-kun, run by GitHub Actions on a real Windows
    machine (Windows PowerShell 5.1, as administrator).

.DESCRIPTION
    Runs the packaged script the way users do and fails if any check could not
    run, if the report, comparison or shareable copy is wrong, or if the window
    or the weekly check cannot be set up. The reports it creates are copied to
    test-reports\ for inspection.
#>
param([string]$PackageDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist\Diagnostic-kun'))
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$script = Join-Path (Resolve-Path $PackageDir) 'PCDiagnostic.ps1'
$ps = Join-Path $PSHOME 'powershell.exe'
$reports = Join-Path ([IO.Path]::GetTempPath()) 'dk-test-reports'
if (Test-Path $reports) { Remove-Item $reports -Recurse -Force }
$failures = New-Object System.Collections.Generic.List[string]
$taskName = 'Diagnostic-kun weekly check'

function Assert-That {
    param([bool]$Condition, [string]$Name, [string]$Detail = '')
    if ($Condition) { Write-Host "PASS  $Name" -ForegroundColor Green }
    else { Write-Host "FAIL  $Name  $Detail" -ForegroundColor Red; $failures.Add("$Name $Detail") }
}

# Runs the tool in a new Windows PowerShell process and returns its exit code
function Invoke-Tool {
    param([string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    Write-Host "> PCDiagnostic.ps1 $($Arguments -join ' ')" -ForegroundColor Cyan
    & $ps -NoProfile -ExecutionPolicy Bypass -File $script @Arguments 2>&1 | ForEach-Object { Write-Host "    $_" }
    $LASTEXITCODE
}

function Get-LatestReport {
    $f = Get-ChildItem -Path $reports -Filter 'Diagnostic_*.json' | Sort-Object LastWriteTime | Select-Object -Last 1
    if (-not $f) { return $null }
    [pscustomobject]@{ File = $f; Data = (Get-Content $f.FullName -Raw | ConvertFrom-Json) }
}

Write-Host "Testing $script on $([Environment]::OSVersion.VersionString), PowerShell $($PSVersionTable.PSVersion)"

# 1. Syntax
$tokens = $null; $parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$tokens, [ref]$parseErrors)
Assert-That ($parseErrors.Count -eq 0) 'Script parses without syntax errors' (($parseErrors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ')

# 2. Static analysis (errors fail the build; warnings are listed for information)
try {
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
        Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser -SkipPublisherCheck
    }
    $analysis = @(Invoke-ScriptAnalyzer -Path $script -Severity Error, Warning)
    $analysis | Where-Object Severity -eq 'Warning' | ForEach-Object { Write-Host "    warning line $($_.Line): $($_.RuleName) $($_.Message)" }
    $errs = @($analysis | Where-Object Severity -eq 'Error')
    Assert-That ($errs.Count -eq 0) 'PSScriptAnalyzer finds no errors' (($errs | ForEach-Object { "line $($_.Line): $($_.RuleName)" }) -join '; ')
} catch { Write-Host "SKIP  PSScriptAnalyzer unavailable: $($_.Exception.Message)" -ForegroundColor Yellow }

# 3. Every fix a check refers to exists
$src = Get-Content $script -Raw
$used = @([regex]::Matches($src, "-FixId\s+'?([a-z-]+)") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
$defined = @([regex]::Matches($src, "(?m)^\s+'([a-z-]+)'\s+=\s+@\{\s*Title") | ForEach-Object { $_.Groups[1].Value })
$missing = @($used | Where-Object { $_ -notin $defined })
Assert-That ($used.Count -gt 10 -and $missing.Count -eq 0) "Every fix used by a check exists ($($used.Count) used)" ($missing -join ', ')

# 4. Full scan
$code = Invoke-Tool @('-NoOpen', '-OutputDir', $reports)
Assert-That ($code -in 0, 1, 2) "Full scan finishes (exit code $code)"
$first = Get-LatestReport
Assert-That ($null -ne $first) 'Full scan writes a JSON report'
if ($first) {
    $results = @($first.Data.Results)
    $results | Sort-Object Category | Format-Table Status, Category, Check, Detail -AutoSize -Wrap | Out-String -Width 250 | Write-Host
    Assert-That ($results.Count -ge 30) "Scan produced enough results ($($results.Count))"
    $errorRows = @($results | Where-Object { $_.Status -eq 'Error' })
    Assert-That ($errorRows.Count -eq 0) 'No check failed to run' (($errorRows | ForEach-Object { "$($_.Check): $($_.Detail)" }) -join ' | ')
    Assert-That (Test-Path ($first.File.FullName -replace '\.json$', '.html')) 'HTML report is written next to the JSON'
    Assert-That ($null -eq $first.Data.Comparison) 'First scan has nothing to compare with'
    Assert-That (@($first.Data.Metrics).Count -ge 5) "Scan records numbers for comparison ($(@($first.Data.Metrics).Count))"
    if (Test-Path (Join-Path $PackageDir 'lib\LibreHardwareMonitorLib.dll')) {
        $lib = @($results | Where-Object { $_.Check -eq 'Sensor library' })
        Assert-That ($lib.Count -eq 0) 'Sensor library loads and answers' (($lib | ForEach-Object { $_.Detail }) -join ' ')
    }
}

# 5. Second scan: comparison with the first, and the shareable copy
Start-Sleep -Seconds 2
$code = Invoke-Tool @('-NoOpen', '-Quick', '-Shareable', '-OutputDir', $reports)
Assert-That ($code -in 0, 1, 2) "Quick scan with -Shareable finishes (exit code $code)"
$second = Get-LatestReport
Assert-That ($second -and $second.File.FullName -ne $first.File.FullName -and $null -ne $second.Data.Comparison) 'Second scan is compared with the first'
$share = Get-ChildItem -Path $reports -Filter '*_shareable.html' | Select-Object -Last 1
Assert-That ($null -ne $share) 'Shareable report is written'
if ($share) {
    $html = Get-Content $share.FullName -Raw
    Assert-That ($html -notmatch [regex]::Escape($env:COMPUTERNAME)) 'Shareable report hides the PC name'
    Assert-That ($html -notmatch ('(?<![A-Za-z0-9])' + [regex]::Escape($env:USERNAME) + '(?![A-Za-z0-9])')) 'Shareable report hides the user name'
    Assert-That ($html -match 'Hidden in this shareable copy') 'Shareable report hides the program list'
}

# 6. The window builds and fills in from a report (without being shown)
$code = Invoke-Tool @('-GuiSelfTest', '-OutputDir', $reports)
Assert-That ($code -eq 0) "Window self-test passes (exit code $code)"

# 7. Weekly check on and off
$code = Invoke-Tool @('-InstallSchedule', '-OutputDir', $reports)
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Assert-That ($code -eq 0 -and $null -ne $task) 'Weekly check can be turned on'
if ($task) { Assert-That ($task.Actions[0].Arguments -match '-Scheduled') 'Weekly task runs the scan in scheduled mode' }
$code = Invoke-Tool @('-RemoveSchedule')
Assert-That ($code -eq 0 -and -not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) 'Weekly check can be turned off'

# 8. What the weekly task runs
$code = Invoke-Tool @('-Scheduled', '-Quick', '-OutputDir', $reports)
Assert-That ($code -in 0, 1, 2) "Scheduled-mode scan finishes (exit code $code)"

# Keep the reports for the workflow artifact
$keep = Join-Path $root 'test-reports'
if (Test-Path $keep) { Remove-Item $keep -Recurse -Force }
Copy-Item -Path $reports -Destination $keep -Recurse

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host "$($failures.Count) test(s) failed:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host 'All tests passed.' -ForegroundColor Green
exit 0
