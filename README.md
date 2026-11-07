# Diagnostic-kun

Diagnostic-kun is a Windows 10/11 PC health check. It looks at the hardware and software of the PC,
rates every check **OK / Info / Warning / Critical**, explains each problem with a
suggested fix, and shows what changed since the last scan.

Scanning is **read-only**. Nothing on the PC changes unless you pick a fix and confirm it.

## How to run

1. Go to [**Releases**](https://github.com/PoseidonDream/Diagnostic-kun/releases), download
   `Diagnostic-kun-<version>.zip`, and unzip it (right-click > Extract All).
2. Double-click **`Diagnostic-kun.bat`** and accept the administrator prompt.
   If Windows shows "Windows protected your PC", click **More info** > **Run anyway**
   (this appears for any downloaded script that isn't code-signed).
3. A window shows a progress bar, then the results. From there you can:
   - **Open full report**: the detailed HTML report in your browser.
   - **Run selected fixes**: tick the fixes you want (for example "Open Disk Cleanup",
     "Start the service", "Repair Windows system files"), then confirm.
   - **Save shareable copy**: a copy of the report without your PC name, user name
     or installed programs, to send to someone helping you.
   - **Turn on weekly check**: scans once a week in the background and shows a
     notification only when something becomes critical. Keep the folder where it is;
     the weekly check runs from there.
   - **Scan again**: for example after running fixes.

Reports are saved in the `Reports` folder (the newest 30 scans are kept) as
`Diagnostic-kun_<PC>_<date>.html` plus a `.json` copy.

### Temperatures and fan speeds

The release zip includes a sensor library (`lib` folder, LibreHardwareMonitor), which
reads GPU temperatures out of the box. To also see **CPU temperature and fan speeds**,
install the free PawnIO driver from https://github.com/namazso/PawnIO.Setup/releases
and scan again. Without the release zip, the tool falls back to `nvidia-smi` for NVIDIA
graphics cards and to the approximate temperatures some laptops report to Windows.

### Without the window

From a PowerShell prompt as administrator:

```powershell
powershell -ExecutionPolicy Bypass -File .\Diagnostic-kun.ps1                # scan and open the report
powershell -ExecutionPolicy Bypass -File .\Diagnostic-kun.ps1 -Fix           # then offer fixes in the console
powershell -ExecutionPolicy Bypass -File .\Diagnostic-kun.ps1 -Days 30       # look at 30 days of event logs
powershell -ExecutionPolicy Bypass -File .\Diagnostic-kun.ps1 -Quick         # skip DISM and network tests
powershell -ExecutionPolicy Bypass -File .\Diagnostic-kun.ps1 -Shareable     # also write the shareable copy
powershell -ExecutionPolicy Bypass -File .\Diagnostic-kun.ps1 -InstallSchedule   # weekly check on
powershell -ExecutionPolicy Bypass -File .\Diagnostic-kun.ps1 -RemoveSchedule    # weekly check off
```

Exit code: `0` = all OK, `1` = warnings (or a check could not run), `2` = critical problems, `3` = the tool itself failed.

Without admin rights it still runs, but disk health counters, temperatures, battery
wear, Secure Boot, TPM, BitLocker and the DISM integrity check are skipped.

## What it checks

| Area | Checks |
|---|---|
| System | Windows version support status (per edition), uptime, BIOS, model |
| CPU | Status, load sampled over 5 s, clock throttling |
| Temperatures | CPU and GPU temperature, fan speeds |
| Memory | Usage, installed amount, mismatched modules, Windows Memory Diagnostic results |
| Storage | Disk health, SSD wear, drive temperature, uncorrected errors, SMART failure prediction, free space per drive, dirty file systems, disk/controller errors in the event log |
| Graphics | Adapter status, generic "Basic Display" driver, driver age, display driver crashes |
| Power | Battery charge and wear vs. design capacity, active power plan |
| Devices | Every device in Device Manager with an error code |
| Stability | Blue screens with bug check codes, unexpected shutdowns, hardware (WHEA) errors, crash dumps |
| Updates | Last installed update, failed updates, pending restart, Windows Update service disabled |
| Security | Antivirus status and signature age, recent malware detections, firewall, UAC, Secure Boot, TPM, BitLocker, activation |
| OS health | DISM component store corruption, last SFC result, System event log error rate, temp files, page file, clock sync |
| Services | Automatic services that failed, services that keep crashing |
| Drivers | Unsigned drivers, drivers that fail to load |
| Applications | Program crashes and hangs by app, startup program count, installed programs, known end-of-life software |
| Network | Connected adapters, missing DHCP address, ping to router and internet, DNS, hosts-file entries |

The report also compares each scan with the previous one: problems that appeared or
went away, and numbers such as free space, SSD wear, battery wear and crash counts.

## Adjusting what counts as a problem

All limits are in the `$T` table at the top of `Diagnostic-kun.ps1`, for example
`DiskFreeWarnPct = 15` or `UpdateWarnDays = 45`. Change them and re-run.

## Help test it

Every change is tested automatically on a Windows machine on GitHub, but real PCs
differ. Running it on a few different ones helps a lot: Windows 10 and 11, a laptop
and a desktop, and a PC with Windows in another language. If anything looks wrong, or
a check shows "Check error", [open an issue](https://github.com/PoseidonDream/Diagnostic-kun/issues/new/choose)
and attach the shareable report.

## For developers

- `build/Build-Package.ps1 -Version 0.2.0` builds `dist/Diagnostic-kun-v0.2.0.zip`
  (needs the .NET SDK to fetch the sensor library; `-SkipSensorLibrary` skips it).
- `tests/Run-Tests.ps1` runs the automated checks against the built package.
- GitHub Actions (`.github/workflows/ci.yml`) builds and tests every push. To publish
  a release: **Actions** > **Build and test** > **Run workflow**, enter a version number
  such as `0.2.0`, and click **Run workflow**. The release is created only if the tests pass.

## Limits

- A full RAM test needs a restart: run Windows Memory Diagnostic (also offered as a fix);
  its result shows in the next report.
- `sfc /scannow` is not run during the scan (it takes 10+ minutes); the report reads the
  last result and runs the faster `DISM /CheckHealth` instead. The "Repair Windows system
  files" fix runs both.
- The table of Windows end-of-support dates needs updating when new Windows versions
  come out.

Third-party libraries in the release zip are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
