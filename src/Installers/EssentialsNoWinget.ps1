# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Start-InstallAppsMenuNoWinget {
    [CmdletBinding()]
    param(
        [switch]$Reinstall,
        [switch]$SilentPreferred
    )

    Write-Host "== Instalador de Apps (sem winget) =="
    Write-Host "O que deseja fazer?"
    Write-Host " [1] Instalar TUDO: Discord, Steam, Google Chrome, Telegram, Opera GX"
    Write-Host " [2] Instalar tudo MENOS Opera GX"
    Write-Host " [3] Instalar tudo MENOS Google Chrome"
    Write-Host " [0] Cancelar"
    Write-Host ""

    $opt = Read-Host "Selecione (0-3)"
    switch ($opt) {
        '1' { Start-InstallAppsNoWingetInNewWindow -IncludeOperaGX -IncludeChrome -Reinstall:$Reinstall -SilentPreferred:$SilentPreferred }
        '2' { Start-InstallAppsNoWingetInNewWindow -IncludeChrome  -Reinstall:$Reinstall -SilentPreferred:$SilentPreferred }
        '3' { Start-InstallAppsNoWingetInNewWindow -IncludeOperaGX -Reinstall:$Reinstall -SilentPreferred:$SilentPreferred }
        '0' { Write-Host "Cancelado." ; return }
        default { Write-Host "Opcao invalida." ; return }
    }
}

function Start-InstallAppsNoWingetInNewWindow {
    <#
    .SYNOPSIS
        Instala apps sem winget em uma NOVA janela do PowerShell (passo a passo), sem travar o script principal.

    .NOTES
        - Chrome: instala NORMAL (sem silent).
        - Opera GX: baixa offline installer mais recente via get.opera.com/ftp/pub/opera_gx/.
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeOperaGX,
        [switch]$IncludeChrome,
        [switch]$Reinstall,
        [switch]$SilentPreferred,
        [string]$LogDir = ""
    )

    function Get-DownloadsFolder {
        $guid = "{374DE290-123F-4565-9164-39C4925E467B}" # Downloads
        $k = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        try {
            $p = (Get-ItemProperty -Path $k -Name $guid -ErrorAction Stop).$guid
            if ($p) { return (Resolve-Path -Path $p).Path }
        } catch {}
        return (Join-Path $env:USERPROFILE "Downloads")
    }

    $downloadDir = Get-DownloadsFolder
    if (-not (Test-Path -LiteralPath $downloadDir)) { New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null }

    if (-not $LogDir) { $LogDir = $env:TEMP }
    if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

    $jobId  = ([guid]::NewGuid().ToString("N"))
    $jobDir = Join-Path $env:TEMP ("apps_install_" + $jobId)
    New-Item -ItemType Directory -Path $jobDir -Force | Out-Null

    $logPath    = Join-Path $LogDir ("apps_install_" + $jobId + ".log")
    $appsJson   = Join-Path $jobDir "apps.json"
    $runnerPath = Join-Path $jobDir "runner.ps1"

    # Base: Discord, Steam, Telegram (sempre)
    $apps = @(
        @{
            Name="Discord"
            Detect=@("Discord")
            Urls=@("https://discord.com/api/download?platform=win")
            File="DiscordSetup.exe"
            MinMB=5
            SilentArgs=@("/S")
            NoSilent=$false
            Special=""
        },
        @{
            Name="Steam"
            Detect=@("Steam")
            Urls=@("https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe")
            File="SteamSetup.exe"
            MinMB=2
            SilentArgs=@("/S")
            NoSilent=$false
            Special=""
        },
        @{
            Name="Telegram Desktop"
            Detect=@("Telegram Desktop","Telegram")
            Urls=@("https://telegram.org/dl/desktop/win")
            File="TelegramSetup.exe"
            MinMB=5
            SilentArgs=@("/VERYSILENT","/NORESTART")
            NoSilent=$false
            Special=""
        }
    )

    if ($IncludeChrome) {
        # Chrome: Offline EXE + INSTALL NORMAL (sem silent)
        $apps += @{
            Name       = "Google Chrome"
            Detect     = @("Google Chrome","Chrome")
            Urls       = @("https://dl.google.com/chrome/install/ChromeStandaloneSetup64.exe")
            File       = "ChromeStandaloneSetup64.exe"
            MinMB      = 30
            SilentArgs = @()       # nao usar silent
            NoSilent   = $true     # forca normal
            Special    = ""        # nao precisa
        }
    }

    if ($IncludeOperaGX) {
        # Opera GX: URL dinamica via FTP oficial (mais recente)
        $apps += @{
            Name="Opera GX"
            Detect=@("Opera GX","OperaGX","Opera GX Browser")
            Urls=@() # nao usado (dinamico)
            File="OperaGXSetup.exe"
            MinMB=30
            SilentArgs=@("/silent","/norestart") # tentamos, mas pode variar
            NoSilent=$false
            Special="OPERA_GX_FTP"
            FtpBase="https://get.opera.com/ftp/pub/opera_gx/"
        }
    }

    ($apps | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $appsJson -Encoding UTF8

    # Aviso na tela principal (pedido do usuario)
    Write-Host "== Instalacoes em segundo plano (sem winget) =="
    Write-Host "Sera instalado nesta rodada:"
    foreach ($a in $apps) { Write-Host (" - {0}" -f $a.Name) }
    Write-Host ""
    Write-Host "Abrirei uma NOVA janela do PowerShell para acompanhar o passo a passo."
    Write-Host ("Downloads/copias: {0}" -f $downloadDir)
    Write-Host ("Log: {0}" -f $logPath)
    Write-Host "Seu script principal continuara executando."
    Write-Host ""

    $runner = @'
param(
  [Parameter(Mandatory=$true)][string]$AppsJson,
  [Parameter(Mandatory=$true)][string]$LogPath,
  [Parameter(Mandatory=$true)][string]$DownloadDir,
  [switch]$Reinstall,
  [switch]$SilentPreferred
)

try { Start-Transcript -Path $LogPath -Append | Out-Null } catch {}

function Enable-Tls12 {
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
}

function Step([string]$msg) {
  $ts = (Get-Date).ToString("HH:mm:ss")
  Write-Host "[$ts] $msg"
}

function Get-InstalledByRegistry {
  param([string[]]$Needles)

  $paths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  foreach ($p in $paths) {
    try {
      $apps = Get-ItemProperty $p -ErrorAction SilentlyContinue
      foreach ($a in $apps) {
        if (-not $a.DisplayName) { continue }
        foreach ($n in $Needles) {
          if ($a.DisplayName -match [regex]::Escape($n)) {
            return [pscustomobject]@{ Installed=$true; Name=$a.DisplayName; Version=$a.DisplayVersion }
          }
        }
      }
    } catch {}
  }

  return [pscustomobject]@{ Installed=$false }
}

function Test-ExeOrMsiSignature {
  param([string]$Path)

  try {
    $fs = [System.IO.File]::OpenRead($Path)
    try {
      $b = New-Object byte[] 8
      $read = $fs.Read($b, 0, $b.Length)
      if ($read -lt 2) { return $false }

      $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
      if ($ext -eq ".exe") {
        # "MZ"
        return ($b[0] -eq 0x4D -and $b[1] -eq 0x5A)
      }
      if ($ext -eq ".msi") {
        # OLE header: D0 CF 11 E0 A1 B1 1A E1
        return ($b[0] -eq 0xD0 -and $b[1] -eq 0xCF -and $b[2] -eq 0x11 -and $b[3] -eq 0xE0)
      }
      return $true
    } finally {
      $fs.Close()
    }
  } catch {
    return $false
  }
}

function Download-HttpWebRequest {
  param([string]$Url,[string]$OutFile)

  Enable-Tls12
  $dir = Split-Path -Path $OutFile -Parent
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

  $req = [System.Net.HttpWebRequest]::Create($Url)
  $req.Method = "GET"
  $req.AllowAutoRedirect = $true
  $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/5.1"
  $req.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
  $req.Timeout = 300000
  $req.ReadWriteTimeout = 300000

  $resp = $null; $stream = $null; $fs = $null
  try {
    $resp = $req.GetResponse()
    $total = $resp.ContentLength
    $stream = $resp.GetResponseStream()
    $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

    $buf = New-Object byte[] 8192
    $readTotal = 0L
    $last = [datetime]::Now

    while (($r = $stream.Read($buf,0,$buf.Length)) -gt 0) {
      $fs.Write($buf,0,$r)
      $readTotal += $r

      if (([datetime]::Now - $last).TotalMilliseconds -ge 500) {
        $last = [datetime]::Now
        if ($total -gt 0) {
          $pct = [math]::Floor(($readTotal / $total) * 100)
          $barLen = 30
          $fill = [math]::Floor(($pct/100)*$barLen)
          $bar = ("#"*$fill).PadRight($barLen,"-")
          $mb = [math]::Round($readTotal/1MB,2)
          $mbt = [math]::Round($total/1MB,2)
          Write-Host ("`r[{0}] {1}% ({2}MB / {3}MB)" -f $bar,$pct,$mb,$mbt) -ForegroundColor Blue -NoNewline
        } else {
          $mb = [math]::Round($readTotal/1MB,2)
          Write-Host ("`rBaixando... {0}MB" -f $mb) -ForegroundColor Blue -NoNewline
        }
      }
    }
    Write-Host ""
  } finally {
    if ($fs) { $fs.Close() }
    if ($stream) { $stream.Close() }
    if ($resp) { try { $resp.Close() } catch {} }
  }
}

function Download-WithCurlIfAvailable {
  param([string]$Url,[string]$OutFile)

  $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
  if (-not $curl) { return $false }

  Step "   * Tentando fallback com curl.exe (-L)..."
  $args = @("-L","--fail","--retry","3","--retry-delay","2","-o",$OutFile,$Url)

  $p = Start-Process -FilePath $curl.Source -ArgumentList $args -Wait -PassThru
  return ($p.ExitCode -eq 0 -and (Test-Path -LiteralPath $OutFile))
}

function Start-ProcSafe {
  param([string]$FilePath,[string[]]$Args=$null)
  if ($Args -and $Args.Count -gt 0) {
    return Start-Process -FilePath $FilePath -ArgumentList $Args -Wait -PassThru
  } else {
    return Start-Process -FilePath $FilePath -Wait -PassThru
  }
}

function Get-LatestOperaGXInstallerUrl {
  param([string]$FtpBase)

  Enable-Tls12
  Step " - Opera GX: buscando versao mais recente no FTP..."
  Step (" - Base: {0}" -f $FtpBase)

  # 1) listar diretorios de versao
  $html = ""
  try {
    $r = Invoke-WebRequest -Uri $FtpBase -UseBasicParsing -ErrorAction Stop
    $html = $r.Content
  } catch {
    Step (" - Falha ao ler indice FTP: {0}" -f $_.Exception.Message)
    return $null
  }

  $matches = [regex]::Matches($html, 'href="(\d+\.\d+\.\d+\.\d+)/"', 'IgnoreCase')
  if (-not $matches -or $matches.Count -eq 0) {
    Step " - Nao achei diretorios de versao no indice."
    return $null
  }

  function To-VerArr([string]$v) { $v.Split('.') | ForEach-Object { [int]$_ } }

  $best = $null
  foreach ($m in $matches) {
    $ver = $m.Groups[1].Value
    if (-not $best) { $best = $ver; continue }

    $a = To-VerArr $ver
    $b = To-VerArr $best
    for ($i=0; $i -lt 4; $i++) {
      if ($a[$i] -gt $b[$i]) { $best = $ver; break }
      if ($a[$i] -lt $b[$i]) { break }
    }
  }

  Step (" - Versao selecionada: {0}" -f $best)

  # 2) listar /win/
  $winUrl = ($FtpBase.TrimEnd('/') + "/" + $best + "/win/")
  Step (" - Lendo: {0}" -f $winUrl)

  $html2 = ""
  try {
    $r2 = Invoke-WebRequest -Uri $winUrl -UseBasicParsing -ErrorAction Stop
    $html2 = $r2.Content
  } catch {
    Step (" - Falha ao ler indice win/: {0}" -f $_.Exception.Message)
    return $null
  }

  $is64 = [Environment]::Is64BitOperatingSystem
  $pattern = if ($is64) { 'href="(Opera_GX_[^"]+_Setup_x64\.exe)"' } else { 'href="(Opera_GX_[^"]+_Setup\.exe)"' }

  $m2 = [regex]::Match($html2, $pattern, 'IgnoreCase')
  if (-not $m2.Success -and $is64) {
    # fallback para Setup.exe se nao achar x64
    $m2 = [regex]::Match($html2, 'href="(Opera_GX_[^"]+_Setup\.exe)"', 'IgnoreCase')
  }
  if (-not $m2.Success) {
    Step " - Nao achei o Setup no indice win/."
    return $null
  }

  $fileName = $m2.Groups[1].Value
  $finalUrl = $winUrl + $fileName
  Step (" - Instalador: {0}" -f $fileName)
  Step (" - URL final: {0}" -f $finalUrl)
  return $finalUrl
}

$apps = Get-Content -LiteralPath $AppsJson -Raw | ConvertFrom-Json

Step "== Instalador (sem winget) =="
Step ("Downloads: {0}" -f $DownloadDir)
Step ("Log: {0}" -f $LogPath)
Step ("SilentPreferred: {0}" -f ([bool]$SilentPreferred))
Step ("Reinstall: {0}" -f ([bool]$Reinstall))

$idx = 0
foreach ($app in $apps) {
  $idx++
  $name = [string]$app.Name
  $needles = @($app.Detect)
  $urls = @($app.Urls)
  $file = [string]$app.File
  $minMB = [int]$app.MinMB
  $silentArgs = @($app.SilentArgs)
  $noSilent = [bool]$app.NoSilent
  $special = [string]$app.Special

  Write-Host ""
  Step ("[{0}/{1}] {2}" -f $idx, $apps.Count, $name)

  # IF: detectar instalado
  $det = Get-InstalledByRegistry -Needles $needles
  if ($det.Installed -and -not $Reinstall) {
    Step (" - Ja instalado: {0} (versao: {1}). Pulando." -f $det.Name, $det.Version)
    continue
  }
  if ($det.Installed -and $Reinstall) {
    Step " - Detectado instalado, mas Reinstall foi solicitado. Vou reinstalar."
  } else {
    Step " - Nao detectei instalado. Vou instalar."
  }

  $outFile = Join-Path $env:TEMP $file
  if (Test-Path -LiteralPath $outFile) { Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue }

  # IF: resolver URL especial (Opera GX FTP)
  if ($special -eq "OPERA_GX_FTP") {
    $ftpBase = [string]$app.FtpBase
    $u = Get-LatestOperaGXInstallerUrl -FtpBase $ftpBase
    if ($u) { $urls = @($u) } else { $urls = @() }
  }

  # IF: download (tenta HttpWebRequest e fallback curl)
  $downloaded = $false
  foreach ($u in $urls) {
    try {
      Step (" - Baixando de: {0}" -f $u)
      Step (" - Salvando em: {0}" -f $outFile)

      Download-HttpWebRequest -Url $u -OutFile $outFile

      $fi = Get-Item -LiteralPath $outFile -ErrorAction Stop
      $sizeMB = [math]::Round($fi.Length/1MB,2)
      Step (" - Tamanho baixado: {0} MB" -f $sizeMB)

      if ($fi.Length -lt ($minMB*1MB)) {
        Step (" - AVISO: menor que {0} MB. Tentando proxima URL..." -f $minMB)
        Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        continue
      }

      if (-not (Test-ExeOrMsiSignature -Path $outFile)) {
        Step " - AVISO: assinatura de arquivo nao parece EXE/MSI valido. Tentando proxima URL..."
        Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        continue
      }

      $downloaded = $true
      break
    } catch {
      Step (" - Falha no download: {0}" -f $_.Exception.Message)
      Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
    }
  }

  if (-not $downloaded) {
    # fallback curl para o primeiro URL (se houver)
    if ($urls -and $urls.Count -gt 0) {
      $ok = Download-WithCurlIfAvailable -Url $urls[0] -OutFile $outFile
      if ($ok) {
        $fi = Get-Item -LiteralPath $outFile -ErrorAction SilentlyContinue
        if ($fi -and $fi.Length -ge ($minMB*1MB) -and (Test-ExeOrMsiSignature -Path $outFile)) {
          $downloaded = $true
          Step (" - OK via curl. Tamanho: {0} MB" -f ([math]::Round($fi.Length/1MB,2)))
        } else {
          Step " - curl baixou algo invalido/pequeno. Vou abortar este app."
          Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        }
      } else {
        Step " - curl nao disponivel ou falhou."
      }
    }
  }

  if (-not $downloaded) {
    Step " - Nao consegui baixar o instalador. Pulando este app."
    continue
  }

  # Copiar instalador para Downloads (para auditoria do usuario)
  try {
    $userCopy = Join-Path $DownloadDir $file
    Copy-Item -LiteralPath $outFile -Destination $userCopy -Force
    Step (" - Copia em Downloads: {0}" -f $userCopy)
  } catch {
    Step (" - Nao consegui copiar para Downloads: {0}" -f $_.Exception.Message)
  }

  # IF: executar instalacao (Chrome: normal)
  $ext = [IO.Path]::GetExtension($outFile).ToLowerInvariant()
  Step (" - Executando instalador ({0})..." -f $ext)

  try {
    if ($ext -eq ".msi") {
      if ($special -eq "MSI_NORMAL" -or $noSilent) {
        Step " - MSI: instalacao NORMAL (sem silent)."
        $args = @("/i", $outFile)
        $p = Start-ProcSafe -FilePath "msiexec.exe" -Args $args
        Step (" - msiexec exit code: {0}" -f $p.ExitCode)
      } else {
        # se algum dia tiver MSI silencioso, entra aqui
        $args = @("/i", $outFile)
        if ($SilentPreferred -and $silentArgs -and $silentArgs.Count -gt 0) {
          Step " - MSI: tentando silent..."
          $args += $silentArgs
        } else {
          Step " - MSI: modo normal."
        }
        $p = Start-ProcSafe -FilePath "msiexec.exe" -Args $args
        Step (" - msiexec exit code: {0}" -f $p.ExitCode)
      }
    } else {
      $useSilent = ($SilentPreferred -and -not $noSilent -and $silentArgs -and $silentArgs.Count -gt 0)

      if ($useSilent) {
        Step (" - Tentando modo silencioso: {0}" -f ($silentArgs -join " "))
        $p1 = Start-ProcSafe -FilePath $outFile -Args $silentArgs
        Step (" - Exit code (silent): {0}" -f $p1.ExitCode)

        if ($p1.ExitCode -ne 0) {
          Step " - Silent falhou/foi ignorado. Tentando modo normal..."
          $p2 = Start-ProcSafe -FilePath $outFile
          Step (" - Exit code (normal): {0}" -f $p2.ExitCode)
        }
      } else {
        Step " - Executando modo normal (sem args)..."
        $p = Start-ProcSafe -FilePath $outFile
        Step (" - Exit code: {0}" -f $p.ExitCode)
      }
    }
  } catch {
    Step (" - Falha ao executar instalador: {0}" -f $_.Exception.Message)
    continue
  }

  # checagem pos (best effort)
  $det2 = Get-InstalledByRegistry -Needles $needles
  if ($det2.Installed) {
    Step (" - Concluido: detectado instalado: {0} (versao: {1})" -f $det2.Name, $det2.Version)
  } else {
    Step " - Finalizado, mas nao confirmei no Registro (pode ter instalado por outro escopo, ou requer reboot)."
  }
}

Write-Host ""
Step "== Fim das instalacoes =="
try { Stop-Transcript | Out-Null } catch {}
Write-Host ""
Write-Host "Pressione qualquer tecla para fechar esta janela..." -ForegroundColor Blue
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
'@

    Set-Content -LiteralPath $runnerPath -Value $runner -Encoding UTF8

    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy","Bypass",
        "-File", $runnerPath,
        "-AppsJson", $appsJson,
        "-LogPath", $logPath,
        "-DownloadDir", $downloadDir
    )
    if ($Reinstall) { $argList += "-Reinstall" }
    if ($SilentPreferred) { $argList += "-SilentPreferred" }

    # Nova janela (nao bloqueia)
    return (Start-Process -FilePath "powershell.exe" -ArgumentList $argList -PassThru)
}


