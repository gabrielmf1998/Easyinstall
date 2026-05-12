# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Install-HoYoPlay {
  # URLs dentro da propria function
  $Urls = @(
    "https://download-porter.hoyoverse.com/download-porter/2026/01/30/VYTpXlbWo8_1.12.0.322_1_0_hyp_hoyoverse_prod_202601211817_dzwouwoM.exe?trace_key=HoYoPlay_install_ua_4daafab9943f"
    "https://www.dropbox.com/scl/fi/dmigy8i7qzwflanmcr7s5/GenshinImpact_install_ua_04042a38e433.exe?rlkey=wrdl1s9t83ebj895k71ugeu8g&st=r1oldx18&dl=1"
    "https://download-porter.hoyoverse.com/download-porter/2026/01/30/VYTpXlbWo8_1.12.0.322_1_0_hyp_hoyoverse_prod_202601211817_dzwouwoM.exe"
  )

  $OutFile = "HoYoPlaySetup.exe"
  $dst     = Join-Path $env:TEMP $OutFile

  $InstalledTest = {
    (Test-Path "$env:ProgramFiles\HoYoPlay\launcher.exe") -or
    (Test-Path "${env:ProgramFiles(x86)}\HoYoPlay\launcher.exe") -or
    (Test-Path "$env:LOCALAPPDATA\HoYoPlay\launcher.exe")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  # 1) ja instalado?
  if (& $InstalledTest) {
    Write-Host "HoYoPlay ja esta instalado." -ForegroundColor Green
    return
  }

  # 2) so baixa se nao existir
  if (-not (Test-Path $dst)) {
    Write-Host "[Baixando e instalando HoYoPlay...]" -ForegroundColor Blue

    $ok = $false
    foreach ($u in $Urls) {
      try {
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri $u -OutFile $dst -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ((Test-Path $dst) -and ((Get-Item $dst).Length -gt 0)) {
          $ok = $true
          break
        }
      } catch {}
    }

    if (-not $ok) {
      Write-Host "Todos os servidores estao fora ou sem internet." -ForegroundColor Red
      return
    }
  }

  # 3) instala
  Start-Process -FilePath $dst
  Write-Host "[OK]" -ForegroundColor Green
}

#VAI INSTALAR RIOT CLIENT
function Install-RiotClient {
  # 3 URLs oficiais que instalam o Riot Client
  $Urls = @(
    "https://valorant.secure.dyn.riotcdn.net/channels/public/x/installer/current/live.live.na.exe"
    "https://lol.secure.dyn.riotcdn.net/channels/public/x/installer/current/live.na.exe"
    "https://lol.secure.dyn.riotcdn.net/channels/public/x/installer/current/live.br.exe"
  )

  $OutFile = "RiotClientSetup.exe"
  $dst     = Join-Path $env:TEMP $OutFile

  $InstalledTest = {
    (Test-Path "C:\Riot Games\Riot Client\RiotClientServices.exe") -or
    (Test-Path "$env:LOCALAPPDATA\Riot Games\Riot Client\RiotClientServices.exe")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  # 1) ja instalado?
  if (& $InstalledTest) {
    Write-Host "Riot Client ja esta instalado." -ForegroundColor Green
    return
  }

  # 2) so baixa se nao existir
  if (-not (Test-Path $dst)) {
    Write-Host "[Baixando e instalando Riot Client...]" -ForegroundColor Blue

    $ok = $false
    foreach ($u in $Urls) {
      try {
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri $u -OutFile $dst -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ((Test-Path $dst) -and ((Get-Item $dst).Length -gt 0)) {
          $ok = $true
          break
        }
      } catch {}
    }

    if (-not $ok) {
      Write-Host "Todos os servidores estao fora ou sem internet." -ForegroundColor Red
      return
    }
  }

  # 3) executa instalador
  #Start-Process -FilePath $dst
  Start-Process -FilePath $dst -ArgumentList '--skip-to-install'
  Write-Host "[OK]" -ForegroundColor Green
}

#VAI INSTALAR EPICGAMES
function Install-EpicGamesLauncher {
  $Urls = @(
    "https://www.dropbox.com/scl/fi/x90y4vx1zm129rud6gzsv/EpicInstaller-18.8.1-f8bb9aa8c431487fa07a4d507d03672e.msi?rlkey=zdn0ubzgo5juhygmpqksk1i1m&st=4hste41m&dl=1"
    "https://launcher-public-service-prod06.ol.epicgames.com/launcher/api/installer/download/EpicGamesLauncherInstaller.msi"
    "https://epicgames-download1.akamaized.net/Builds/UnrealEngineLauncher/Installers/Windows/EpicInstaller-19.1.5.msi?launcherfilename=EpicInstaller-19.1.5.msi"
  )

  $OutFile = "EpicGamesLauncherInstaller.msi"
  $dst     = Join-Path $env:TEMP $OutFile

  $InstalledTest = {
    (Test-Path "${env:ProgramFiles(x86)}\Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe") -or
    (Test-Path "${env:ProgramFiles(x86)}\Epic Games\Launcher\Portal\Binaries\Win32\EpicGamesLauncher.exe") -or
    (Test-Path "$env:ProgramFiles\Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  if (& $InstalledTest) {
    Write-Host "Epic Games Launcher ja esta instalado." -ForegroundColor Green
    return
  }

  if (-not (Test-Path $dst)) {
    Write-Host "[Baixando e instalando Epic Games Launcher...]" -ForegroundColor Blue

    $ok = $false
    foreach ($u in $Urls) {
      try {
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri $u -OutFile $dst -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop

        if ((Test-Path $dst) -and ((Get-Item $dst).Length -gt 0)) {
          $ok = $true
          break
        }
      } catch {}
    }

    if (-not $ok) {
      Write-Host "Todos os servidores estao fora ou sem internet." -ForegroundColor Red
      return
    }
  }

  Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$dst`" /qn /norestart"
  Write-Host "[OK]" -ForegroundColor Green
}


function Install-Steam {
  # URLs dentro da propria function
  $Urls = @(
    "https://cdn.fastly.steamstatic.com/client/installer/SteamSetup.exe"
    "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe"
    "https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe"
  )

  $OutFile = "SteamSetup.exe"
  $dst     = Join-Path $env:TEMP $OutFile

  $InstalledTest = {
    (Test-Path "${env:ProgramFiles(x86)}\Steam\Steam.exe") -or
    (Test-Path "$env:ProgramFiles\Steam\Steam.exe")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  # 1) ja instalado?
  if (& $InstalledTest) {
    Write-Host "Steam ja esta instalado." -ForegroundColor Green
    return
  }

  # 2) so baixa se nao existir
  if (-not (Test-Path $dst)) {
    Write-Host "[Baixando e instalando Steam...]" -ForegroundColor Blue

    $ok = $false
    foreach ($u in $Urls) {
      try {
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri $u -OutFile $dst -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ((Test-Path $dst) -and ((Get-Item $dst).Length -gt 0)) { $ok = $true; break }
      } catch {}
    }

    if (-not $ok) {
      Write-Host "Todos os servidores estao fora ou sem internet." -ForegroundColor Red
      return
    }
  }

  # 3) instala
  Start-Process -FilePath $dst -ArgumentList '/S' -Verb RunAs
  Write-Host "[OK]" -ForegroundColor Green
}


function Install-AllLaunchers {
  Install-Steam
  Install-HoYoPlay
  Install-RiotClient
  Install-EpicGamesLauncher
  Write-Host "Todos os programas foram baixados e executados em segundo plano!"
  Start-Sleep 2
}


