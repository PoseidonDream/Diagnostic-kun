# Diagnostic-kun

A Windows 10/11 PC health check. It looks at the hardware and software of the PC,
rates every check **OK / Info / Warning / Critical**, and writes a report that
lists each problem with a suggested fix.

It is **read-only**: it never changes settings, deletes files or installs anything.

## How to run

1. Go to [**Releases**](https://github.com/PoseidonDream/diagnostic-kun/releases), download
   `Diagnostic-kun-<version>.zip`, and unzip it (right-click > Extract All).
2. Double-click **`RunDiagnostic.bat`** and accept the administrator prompt.
   If Windows shows "Windows protected your PC", click **More info** > **Run anyway**
   (this appears for any downloaded script that isn't code-signed).
3. When it finishes (usually 30-90 seconds), the HTML report opens in your browser.

Reports are saved in the `Reports` folder as `Diagnostic_<PC>_<date>.html` plus a
`.json` copy for scripts or comparing runs.

From a PowerShell prompt you can also run it directly:

```powershell
powershell -ExecutionPolicy Bypass -File .\PCDiagnostic.ps1            # normal run
powershell -ExecutionPolicy Bypass -File .\PCDiagnostic.ps1 -Days 30   # look at 30 days of logs
powershell -ExecutionPolicy Bypass -File .\PCDiagnostic.ps1 -Quick     # skip DISM and network tests
powershell -ExecutionPolicy Bypass -File .\PCDiagnostic.ps1 -NoOpen -OutputDir C:\Reports
```

Exit code: `0` = all OK, `1` = warnings, `2` = critical problems.

Without admin rights it still runs, but disk health counters, temperatures, battery
wear, Secure Boot, TPM, BitLocker and the DISM integrity check are skipped.

## What it checks

| Area | Checks |
|---|---|
| System | Windows version support status, uptime, BIOS, model |
| CPU | Status, load sampled over 5 s, clock throttling, temperatures (if sensors are exposed) |
| Memory | Usage, total amount, mismatched modules, Windows Memory Diagnostic results |
| Storage | Disk health status, SSD wear, drive temperature, uncorrected errors, SMART failure prediction, free space per drive, dirty file systems, disk/controller errors in the event log |
| Graphics | Adapter status, generic "Basic Display" driver, driver age, display driver crashes (TDR) |
| Power | Battery charge and wear vs. design capacity, active power plan |
| Devices | Every device in Device Manager with an error code |
| Stability | Blue screens with bug check codes, unexpected shutdowns, WHEA hardware errors, crash dumps |
| Updates | Last installed update, failed updates, pending restart, Windows Update service disabled |
| Security | Antivirus status and signature age, recent malware detections, firewall, UAC, Secure Boot, TPM, BitLocker, activation |
| OS health | DISM component store corruption, last SFC result, System event log error rate, temp files, page file, clock sync |
| Services | Automatic services that are not running, services that keep crashing |
| Drivers | Unsigned drivers, drivers that fail to load |
| Applications | Program crashes and hangs by app, startup program count, installed programs, known end-of-life software |
| Network | Connected adapters, missing DHCP address, ping to router and internet, DNS, hosts-file entries |

## Adjusting what counts as a problem

All limits are in the `$T` table at the top of `PCDiagnostic.ps1`, for example
`DiskFreeWarnPct = 15` or `UpdateWarnDays = 45`. Change them and re-run.

## Limits

- CPU/GPU temperatures: Windows only exposes ACPI thermal zones, which many desktops
  do not provide. Use HWiNFO or the maker's tool for exact readings.
- A full RAM test needs a reboot: run `mdsched.exe`; its result shows in the next report.
- `sfc /scannow` is not run (it takes 10+ minutes); the report reads the last result
  and runs the faster `DISM /CheckHealth` instead.
