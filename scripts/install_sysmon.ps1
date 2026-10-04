# Installs Sysinternals Sysmon with the SwiftOnSecurity community configuration.
# Run from an elevated PowerShell:  powershell -ExecutionPolicy Bypass -File scripts\install_sysmon.ps1
#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$work = Join-Path $env:TEMP "tinybrother-sysmon"
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Host "[*] Downloading Sysmon..."
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$work\Sysmon.zip"
Expand-Archive "$work\Sysmon.zip" -DestinationPath $work -Force

Write-Host "[*] Downloading SwiftOnSecurity config..."
Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$work\sysmonconfig.xml"

$exe = if ([Environment]::Is64BitOperatingSystem) { "Sysmon64.exe" } else { "Sysmon.exe" }
if (Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue) {
    Write-Host "[*] Sysmon already installed, updating config..."
    & "$work\$exe" -c "$work\sysmonconfig.xml"
} else {
    Write-Host "[*] Installing Sysmon..."
    & "$work\$exe" -accepteula -i "$work\sysmonconfig.xml"
}
Write-Host "[+] Done. Events: Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon"
