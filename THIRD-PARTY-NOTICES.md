# Third-party notices

The release zip includes the libraries below in its `lib` folder. Diagnostic-kun
uses them only to read temperature and fan sensors. They are included unmodified,
as published on NuGet, and each remains under its own license.

| Library | License | Source code |
|---|---|---|
| LibreHardwareMonitorLib 0.9.6 | MPL-2.0 | https://github.com/LibreHardwareMonitor/LibreHardwareMonitor |
| DiskInfoToolkit | MPL-2.0 | https://github.com/Blacktempel/DiskInfoToolkit |
| RAMSPDToolkit-NDD | MPL-2.0 | https://github.com/Blacktempel/RAMSPDToolkit |
| BlackSharp.Core | MPL-2.0 | https://github.com/Blacktempel/BlackSharp |
| HidSharp | Apache-2.0 | https://software.seekye.com/hidsharp |
| System.Memory, System.Buffers, System.Numerics.Vectors, System.Runtime.CompilerServices.Unsafe, System.Management, System.Threading.AccessControl, System.Security.AccessControl, System.Security.Principal.Windows | MIT | https://github.com/dotnet |

- MPL-2.0: https://www.mozilla.org/MPL/2.0/
- Apache-2.0: https://www.apache.org/licenses/LICENSE-2.0
- MIT: https://opensource.org/license/mit

Reading CPU and motherboard sensors also needs the PawnIO driver, which is
**not** included. Users who want those readings install it themselves from
https://github.com/namazso/PawnIO.Setup/releases.
