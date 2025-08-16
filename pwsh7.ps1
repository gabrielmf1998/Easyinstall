#Vai instalar pwsh 7.5
$installerPath = "$env:TEMP\PowerShell-7.5.2-win-x64.exe"
Invoke-WebRequest -Uri "https://github.com/PowerShell/PowerShell/releases/download/v7.5.2/PowerShell-7.5.2-win-x64.exe" -OutFile $installerPath
Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait