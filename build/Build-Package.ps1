<#
.SYNOPSIS
    Builds the release zip: dist\Diagnostic-kun-v<Version>.zip

.DESCRIPTION
    Copies the script, launcher, README and notices into dist\Diagnostic-kun,
    stamps the version into the script, adds the sensor library (LibreHardwareMonitorLib
    and its dependencies, restored from NuGet with the .NET SDK) into lib\, and zips it.
    Used by .github/workflows/ci.yml; can also be run locally on Windows.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File build\Build-Package.ps1 -Version 0.2.0
#>
param(
    [string]$Version = 'dev',
    [switch]$SkipSensorLibrary
)
$ErrorActionPreference = 'Stop'

$Version = $Version.Trim().TrimStart('v', 'V')
if ($Version -ne 'dev' -and $Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version must look like 0.2.0 (got '$Version')." }

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
$pkg = Join-Path $dist 'Diagnostic-kun'
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
New-Item -ItemType Directory -Path $pkg | Out-Null

foreach ($f in 'PCDiagnostic.ps1', 'RunDiagnostic.bat', 'README.md', 'THIRD-PARTY-NOTICES.md') {
    Copy-Item -LiteralPath (Join-Path $root $f) -Destination $pkg
}

# Stamp the version into the packaged script
$ps1 = Join-Path $pkg 'PCDiagnostic.ps1'
$text = [IO.File]::ReadAllText($ps1)
$marker = "`$script:Version = 'dev'"
if (-not $text.Contains($marker)) { throw "Version marker not found in PCDiagnostic.ps1" }
[IO.File]::WriteAllText($ps1, $text.Replace($marker, "`$script:Version = '$Version'"))

if (-not $SkipSensorLibrary) {
    # A throwaway .NET Framework 4.7.2 project that only exists to restore the
    # library and copy every dependency DLL (win-x64 build) into one folder.
    $proj = Join-Path ([IO.Path]::GetTempPath()) 'dk-sensor-deps'
    if (Test-Path $proj) { Remove-Item $proj -Recurse -Force }
    New-Item -ItemType Directory -Path $proj | Out-Null
    @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net472</TargetFramework>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
    <CopyLocalLockFileAssemblies>true</CopyLocalLockFileAssemblies>
    <AssemblyName>DkSensorDeps</AssemblyName>
    <GenerateDocumentationFile>false</GenerateDocumentationFile>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="LibreHardwareMonitorLib" Version="0.9.6" />
    <PackageReference Include="Microsoft.NETFramework.ReferenceAssemblies" Version="1.0.3" PrivateAssets="all" />
  </ItemGroup>
</Project>
'@ | Set-Content -Path (Join-Path $proj 'DkSensorDeps.csproj') -Encoding UTF8
    Set-Content -Path (Join-Path $proj 'Empty.cs') -Value '// intentionally empty' -Encoding UTF8

    $out = Join-Path $proj 'out'
    & dotnet build (Join-Path $proj 'DkSensorDeps.csproj') -c Release -o $out --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Building the sensor library folder failed.' }

    $lib = Join-Path $pkg 'lib'
    New-Item -ItemType Directory -Path $lib | Out-Null
    Get-ChildItem -Path $out -Filter *.dll | Where-Object { $_.Name -ne 'DkSensorDeps.dll' } | Copy-Item -Destination $lib
    if (-not (Test-Path (Join-Path $lib 'LibreHardwareMonitorLib.dll'))) { throw 'LibreHardwareMonitorLib.dll is missing from the build output.' }
    Write-Host "Sensor library files:" ((Get-ChildItem $lib).Name -join ', ')
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = Join-Path $dist "Diagnostic-kun-v$Version.zip"
[IO.Compression.ZipFile]::CreateFromDirectory($pkg, $zip, [IO.Compression.CompressionLevel]::Optimal, $true)
$hash = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLower()
Set-Content -Path (Join-Path $dist 'SHA256.txt') -Value "$hash  $(Split-Path $zip -Leaf)" -Encoding ASCII
Write-Host "Built $zip"
Write-Host "SHA-256 $hash"
