# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Install-OperaGXSetup {
  # URLs ficam dentro da propria function
  $Urls = @(
    "https://www.dropbox.com/scl/fi/kkyxxjjb4rlxf7pkviarh/OperaGXSetup.exe?rlkey=83pnniwj1lu6nj9shvcjxhju6&st=kqhxn43j&dl=1"
    "https://download.opera.com/download/get/?arch=x64&opsys=Windows&partner=www&product=Opera+GX"
    "https://download.opera.com/download/get/?arch=i386&opsys=Windows&partner=www&product=Opera+GX"
  )

  $OutFile = "OperaGXSetup.exe"
  $dst     = Join-Path $env:TEMP $OutFile

  $InstalledTest = {
    (Test-Path "$env:LOCALAPPDATA\Programs\Opera GX\opera.exe") -or
    (Test-Path "$env:ProgramFiles\Opera GX\opera.exe") -or
    (Test-Path "${env:ProgramFiles(x86)}\Opera GX\opera.exe")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  # 1) ja instalado?
  if (& $InstalledTest) {
    Write-Host "Opera GX ja esta instalado." -ForegroundColor Green
    return
  }

  # 2) so baixa se nao existir
  Write-Host "[Baixando e instalando OperaGX...]" -ForegroundColor Blue

$ok = $false
$MinSize = 1MB

foreach ($u in $Urls) {
  try {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue

    Invoke-WebRequest -Uri $u -OutFile $dst -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop

    if (Test-Path $dst) {
      if ((Get-Item $dst).Length -gt $MinSize) {
        $ok = $true
        break
      }
      else {
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
      }
    }
  }
  catch {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue
  }
}

if (-not $ok) {
  Write-Host "Todos os servidores estao fora, sem internet, ou o arquivo baixado e invalido (OperaGX)." -ForegroundColor Red
  return
}

  # 3) executa instalador
  Start-Process -FilePath $dst -ArgumentList '/silent /allusers=1 /launchopera=0 /setdefaultbrowser=0' -Verb RunAs
  Write-Host "[OK]" -ForegroundColor Green
}


function Install-GoogleChromeSetup {
  # URLs dentro da propria function
  $Urls = @(
    "https://www.dropbox.com/scl/fi/pr7vfrb9bxchhypvhhbsy/ChromeSetup.exe?rlkey=46pc5ik4qsxoy5xwnj1ca8fvw&st=7s4hqmom&dl=1"
    "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
    "https://dl.google.com/chrome/install/ChromeStandaloneSetup64.exe"
  )

  $OutFile = "ChromeSetup.exe"
  $dst     = Join-Path $env:TEMP $OutFile

  $InstalledTest = {
    (Test-Path "$env:ProgramFiles\Google\Chrome\Application\chrome.exe") -or
    (Test-Path "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") -or
    (Test-Path "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  # ja instalado?
  if (& $InstalledTest) {
    Write-Host "Google Chrome ja esta instalado." -ForegroundColor Green
    return
  }

  # so baixa se nao existir
  Write-Host "[Baixando e instalando Google-Chrome...]" -ForegroundColor Blue

$ok = $false
$MinSize = 1MB

foreach ($u in $Urls) {
  try {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue

    Invoke-WebRequest -Uri $u -OutFile $dst -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop

    if (Test-Path $dst) {
      if ((Get-Item $dst).Length -gt $MinSize) {
        $ok = $true
        break
      }
      else {
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
      }
    }
  }
  catch {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue
  }
}

if (-not $ok) {
  Write-Host "Todos os servidores estao fora, sem internet, ou o arquivo baixado e invalido (Google Chrome)." -ForegroundColor Red
  return
}

  # executa instalador sem travar o menu
  Start-Process -FilePath $dst -ArgumentList '/silent /install' -Verb RunAs
  Write-Host "[OK]" -ForegroundColor Green
}


function Install-VLC {
  # URLs do VLC ficam aqui dentro (3 tentativas, na ordem)
  $Urls = @(
    "https://www.dropbox.com/scl/fi/rzg6a4hcjip6hwm0avou3/vlc-3.0.21-win64.exe?rlkey=b5k03253t7204iitoibpudjn4&st=xpngwmev&dl=1"
    "https://get.videolan.org/vlc/3.0.21/win64/vlc-3.0.21-win64.exe"
    "https://download.videolan.org/pub/vlc/3.0.21/win64/vlc-3.0.21-win64.exe"
  )

  $OutFile = "vlc1.exe"
  $dst     = Join-Path $env:TEMP $OutFile

  $InstalledTest = {
    (Test-Path "$env:ProgramFiles\VideoLAN\VLC\vlc.exe") -or
    (Test-Path "${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  # 1) ja instalado?
  if (& $InstalledTest) {
    Write-Host "VLC ja esta instalado." -ForegroundColor Green
    return
  }

  # 2) so baixa se nao existir
  Write-Host "[Baixando e instalando VLC...]" -ForegroundColor Blue

$ok = $false
$MinSize = 1MB

foreach ($u in $Urls) {
  try {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue

    Invoke-WebRequest -Uri $u -OutFile $dst -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop

    if (Test-Path $dst) {
      if ((Get-Item $dst).Length -gt $MinSize) {
        $ok = $true
        break
      }
      else {
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
      }
    }
  }
  catch {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue
  }
}

if (-not $ok) {
  Write-Host "Todos os servidores estao fora, sem internet, ou o arquivo baixado e invalido." -ForegroundColor Red
  return
}

  # 3) instala (use "/S" se quiser silencioso)
  Start-Process -FilePath $dst -ArgumentList '/S' -Verb RunAs
  Write-Host "[OK]" -ForegroundColor Green

}

#VAI INSTALAR 7ZIP
function Install-7Zip {
  # URLs ficam DENTRO da function (organizado por programa)
  $Urls = @(
    "https://www.7-zip.org/a/7z2405-x64.exe"
    "https://sourceforge.net/projects/sevenzip/files/7-Zip/24.05/7z2405-x64.exe/download"
    "https://www.dropbox.com/scl/fi/mxzy930l435b2nekh7jb3/7zip.exe?rlkey=vlfa2ewujvoejrjjsnim233xo&st=8kci0vmd&dl=1"
  )

  $OutFile = "7zip.exe"
  $dst     = Join-Path $env:TEMP $OutFile

  $InstalledTest = {
    (Test-Path "$env:ProgramFiles\7-Zip\7z.exe") -or
    (Test-Path "${env:ProgramFiles(x86)}\7-Zip\7z.exe")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  # 1) ja instalado?
  if (& $InstalledTest) {
    Write-Host "7-Zip ja esta instalado." -ForegroundColor Green
    return
  }

  # 2) so baixa se nao existir
  Write-Host "[Baixando e instalando 7-ZIP...]" -ForegroundColor Blue

$ok = $false
$MinSize = 1MB

foreach ($u in $Urls) {
  try {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue

    Invoke-WebRequest -Uri $u -OutFile $dst -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop

    if (Test-Path $dst) {
      if ((Get-Item $dst).Length -gt $MinSize) {
        $ok = $true
        break
      }
      else {
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
      }
    }
  }
  catch {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue
  }
}

if (-not $ok) {
  Write-Host "Todos os servidores estao fora, sem internet, ou o arquivo baixado e invalido." -ForegroundColor Red
  return
}

  # 3) instala
  Start-Process -FilePath $dst -ArgumentList '/S' -Verb RunAs
  Write-Host "[OK]" -ForegroundColor Green
}


function Install-MsiAfterburner {
  # --- URLs (3 tentativas) ---
  $Urls = @(
    "https://www.dropbox.com/scl/fi/8dn8xetdhrakgxvmgtrnq/Guru3D-MSIAfterburnerSetup466Beta5Build16555.zip?rlkey=p32u18t82o8je99wqvh36kjiv&st=j53u0iq7&dl=1"
    "https://ftp.nluug.nl/pub/games/PC/guru3d/afterburner/[Guru3D]-MSIAfterburnerSetup466Beta5Build16555.zip"
    "https://www.guru3d.com/files-details/msi-afterburner-beta-download.html"
  )

  $ZipName      = "Afterburner.zip"
  $ZipPath      = Join-Path $env:TEMP $ZipName
  $ExtractPath  = Join-Path $env:TEMP "Afterburner"
  $InstallerExe = "MSIAfterburnerSetup466Beta5.exe"
  $Installer    = Join-Path $ExtractPath $InstallerExe

  $InstalledTest = {
    (Test-Path "$env:ProgramFiles (x86)\MSI Afterburner\MSIAfterburner.exe") -or
    (Test-Path "$env:ProgramFiles\MSI Afterburner\MSIAfterburner.exe")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  # Ja instalado?
  if (& $InstalledTest) {
    Write-Host "MSI Afterburner ja esta instalado." -ForegroundColor Green
    return
  }
 
#verifica se baixou
Write-Host "[Baixando e instalando MSI Afterburner...]" -ForegroundColor Blue

$ok = $false
$MinSize = 1MB

foreach ($u in $Urls) {
  try {
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue

    Invoke-WebRequest -Uri $u -OutFile $ZipPath -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop

    if (Test-Path $ZipPath) {
      if ((Get-Item $ZipPath).Length -gt $MinSize) {
        $ok = $true
        break
      }
      else {
        Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
      }
    }
  }
  catch {
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
  }
}

if (-not $ok) {
  Write-Host "Todos os servidores estao fora, sem internet, ou o arquivo baixado e invalido (Afterburner)." -ForegroundColor Red
  return
}
  # Extrai e instala
  Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

  # tenta achar o instalador no zip (caso mude a pasta interna)
  if (-not (Test-Path $Installer)) {
    $found = Get-ChildItem -Path $ExtractPath -Recurse -Filter $InstallerExe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $Installer = $found.FullName }
  }

  if (-not (Test-Path $Installer)) {
    Write-Host "Instalador do Afterburner nao encontrado apos extracao." -ForegroundColor Red
    return
  }

  Start-Process -FilePath $Installer -ArgumentList '/S' -Verb RunAs
  Write-Host "[OK]" -ForegroundColor Green
}

#VAI INSTALAR RTSS
function Install-RivaTuner {
  # --- URLs (3 tentativas) ---
  $Urls = @(
    "https://ftp.nluug.nl/pub/games/PC/guru3d/afterburner/[Guru3D.com]-RTSS.zip"
    "https://www.guru3d.com/files-details/rtss-rivatuner-statistics-server-download.html"
    "https://www.dropbox.com/scl/fi/REPLACE-ME/RTSS.zip?dl=1"
  )

  $ZipName      = "RTSS.zip"
  $ZipPath      = Join-Path $env:TEMP $ZipName
  $ExtractPath  = Join-Path $env:TEMP "RTSS"
  $InstallerExe = "RTSSSetup736.exe"
  $Installer    = Join-Path $ExtractPath $InstallerExe

  $InstalledTest = {
    (Test-Path "$env:ProgramFiles (x86)\RivaTuner Statistics Server\RTSS.exe") -or
    (Test-Path "$env:ProgramFiles\RivaTuner Statistics Server\RTSS.exe")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  # Ja instalado?
  if (& $InstalledTest) {
    Write-Host "RTSS ja esta instalado." -ForegroundColor Green
    return
  }

  Write-Host "[Baixando e instalando RTSS...]" -ForegroundColor Blue

$ok = $false
$MinSize = 1MB

foreach ($u in $Urls) {
  try {
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue

    Invoke-WebRequest -Uri $u -OutFile $ZipPath -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop

    if (Test-Path $ZipPath) {
      if ((Get-Item $ZipPath).Length -gt $MinSize) {
        $ok = $true
        break
      }
      else {
        Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
      }
    }
  }
  catch {
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
  }
}

if (-not $ok) {
  Write-Host "Todos os servidores estao fora, sem internet, ou o arquivo baixado e invalido (RTSS)." -ForegroundColor Red
  return
}

  # Extrai e instala
  Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

  # tenta achar o instalador no zip (caso mude a pasta interna)
  if (-not (Test-Path $Installer)) {
    $found = Get-ChildItem -Path $ExtractPath -Recurse -Filter $InstallerExe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $Installer = $found.FullName }
  }

  if (-not (Test-Path $Installer)) {
    Write-Host "Instalador do RTSS nao encontrado apos extracao." -ForegroundColor Red
    return
  }

  Start-Process -FilePath $Installer -ArgumentList '/S' -Verb RunAs
  Write-Host "[OK]" -ForegroundColor Green
}

#VAI INSTALAR DISCORD
function Install-Discord {
  $Urls = @(
    "https://www.dropbox.com/scl/fi/iexl5meb6e4uhace8r60h/DiscordSetup.exe?rlkey=66szuqcji8crzhd49e6s85xe6&st=xevxz12e&dl=1"
    "https://discord.com/api/downloads/distributions/app/installers/latest?arch=x64&channel=stable&platform=win"
    "https://discord.com/api/downloads/distributions/app/installers/latest?arch=x86&channel=stable&platform=win"
  )

  $OutFile = "DiscordSetup1.exe"
  $dst     = Join-Path $env:TEMP $OutFile

  $InstalledTest = {
    (Test-Path "$env:LOCALAPPDATA\Discord\Update.exe") -or
    (Test-Path "$env:APPDATA\discord\settings.json")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  if (& $InstalledTest) {
    Write-Host "Discord ja esta instalado." -ForegroundColor Green
    return
  }

  Write-Host "[Baixando e instalando Discord...]" -ForegroundColor Blue

$ok = $false
$MinSize = 1MB

foreach ($u in $Urls) {
  try {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue

    Invoke-WebRequest -Uri $u -OutFile $dst -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop

    if (Test-Path $dst) {
      if ((Get-Item $dst).Length -gt $MinSize) {
        $ok = $true
        break
      }
      else {
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
      }
    }
  }
  catch {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue
  }
}

if (-not $ok) {
  Write-Host "Todos os servidores estao fora, sem internet, ou o arquivo baixado e invalido (Discord)." -ForegroundColor Red
  return
}

  Start-Process -FilePath $dst -ArgumentList '-s'
  Write-Host "[OK]" -ForegroundColor Green
}

#VAI INSTALAR TELEGRAM
function Install-Telegram {
  $Urls = @(
    "https://www.dropbox.com/scl/fi/7d45ildoh0q86wjgeumlv/tsetup-x64.5.14.3.exe?rlkey=zzqcmywrltgf55mc6i244o1n0&st=um62cd0v&dl=1"
    "https://telegram.org/dl/desktop/win64"
    "https://sourceforge.net/projects/telegram-desktop.mirror/files/v6.5.1/tsetup-x64.6.5.1.exe/download"
  )

  $OutFile = "TelegramSetup.exe"
  $dst     = Join-Path $env:TEMP $OutFile

  $InstalledTest = {
    (Test-Path "$env:APPDATA\Telegram Desktop\Telegram.exe") -or
    (Test-Path "$env:LOCALAPPDATA\Telegram Desktop\Telegram.exe") -or
    (Test-Path "$env:ProgramFiles\Telegram Desktop\Telegram.exe")
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  if (& $InstalledTest) {
    Write-Host "Telegram ja esta instalado." -ForegroundColor Green
    return
  }

  Write-Host "[Baixando e instalando Telegram...]" -ForegroundColor Blue

$ok = $false
$MinSize = 1MB

foreach ($u in $Urls) {
  try {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue

    Invoke-WebRequest -Uri $u -OutFile $dst -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop

    if (Test-Path $dst) {
      if ((Get-Item $dst).Length -gt $MinSize) {
        $ok = $true
        break
      }
      else {
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
      }
    }
  }
  catch {
    Remove-Item $dst -Force -ErrorAction SilentlyContinue
  }
}

if (-not $ok) {
  Write-Host "Todos os servidores estao fora, sem internet, ou o arquivo baixado e invalido (Telegram)." -ForegroundColor Red
  return
}

  Start-Process -FilePath $dst -ArgumentList '/VERYSILENT /NORESTART'
  Write-Host "[OK]" -ForegroundColor Green
}

function Install-PowerShell7LatestWinget {
  Write-Host "[Instalando/atualizando PowerShell 7 mais recente via winget...]" -ForegroundColor Blue

  $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
  if (-not $winget) {
    throw "winget.exe nao encontrado. Instale/atualize o App Installer pela Microsoft Store."
  }

  $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
  if ($pwsh) {
    Invoke-Winget -Args @(
      'upgrade',
      '--id', 'Microsoft.PowerShell',
      '-e',
      '--accept-source-agreements',
      '--accept-package-agreements',
      '--silent'
    ) -SuccessName 'PowerShell 7'
  } else {
    Invoke-Winget -Args @(
      'install',
      '--id', 'Microsoft.PowerShell',
      '-e',
      '--accept-source-agreements',
      '--accept-package-agreements',
      '--silent'
    ) -SuccessName 'PowerShell 7'
  }
}

#VAI INSTALAR TODOS
function Install-AllProgramas {
  Install-7Zip
  Install-VLC
  Install-MsiAfterburner
  Install-RivaTuner
  Install-OperaGXSetup
  Install-GoogleChromeSetup
  Install-Discord
  Install-Telegram
  Install-PowerShell7LatestWinget
  Write-Host "Todos os programas foram baixados e executados em segundo plano!"
  Start-Sleep 2
}


