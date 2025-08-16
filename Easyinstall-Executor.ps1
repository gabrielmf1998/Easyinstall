#Vai instalar chamar outro script em adm
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://github.com/gabrielmf1998/Easyinstall/releases/download/Easyinstall-Executor/Easyinstall.ps1" -OutFile "$env:TEMP\Easyinstall.ps1"
Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$env:TEMP\Easyinstall.ps1`"" -Verb RunAs
exit
