@echo off
:: PC Diagnostic launcher - asks for admin rights, then runs the PowerShell script.
:: "fltmc" only succeeds when elevated. ("net session" also fails as admin when the
:: Server service is off, which made the launcher re-launch itself forever.)
fltmc >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    rem Path and arguments go through environment variables so quotes or apostrophes
    rem in them cannot break the PowerShell command.
    set "DIAG_BAT=%~f0"
    set "DIAG_ARGS=%*"
    powershell -NoProfile -Command "$a = @{ FilePath = $env:DIAG_BAT; Verb = 'RunAs' }; if ($env:DIAG_ARGS) { $a.ArgumentList = $env:DIAG_ARGS }; Start-Process @a"
    if errorlevel 1 (
        echo Could not get administrator rights. Re-run and click Yes on the prompt.
        pause
    )
    exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0PCDiagnostic.ps1" %*
pause
