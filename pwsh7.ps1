#Vai instalar pwsh 7.5
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "Power Shell 7.5" -ForegroundColor Gray
Write-Host "1 | Instalar"
Write-Host "2 | Sair"
$escolha = Read-Host
    switch ($escolha) {
        "1" {
            $installerPath = "$env:TEMP\PowerShell-7.5.2-win-x64.exe"
            Invoke-WebRequest -Uri "https://github.com/PowerShell/PowerShell/releases/download/v7.5.2/PowerShell-7.5.2-win-x64.exe" -OutFile $installerPath
            Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait
        }
        "2" {
            exit
        }
    }
