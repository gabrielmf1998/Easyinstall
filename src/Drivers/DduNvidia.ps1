# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Invoke-DDUCleanupNvidia {
    [CmdletBinding()]
    param(
        [string]$WorkDir = "$env:TEMP\DDU_NVIDIA",
        [ValidateSet('Ask','Normal','SafeAuto')]
        [string]$Mode = 'Ask',
        [switch]$DryRun,
        [switch]$WaitWorker,
        [ValidateSet('Normal','Minimized','Maximized','Hidden')]
        [string]$WindowStyle = 'Normal'
    )

    function Write-Log([string]$Msg, [string]$Level="INFO") {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$ts][$Level] $Msg"
    }

    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    $workerPath = Join-Path $WorkDir "DDU_NVIDIA_Worker.ps1"

    $worker = @'
param(
  [string]$WorkDir,
  [ValidateSet("Ask","Normal","SafeAuto")]
  [string]$Mode,
  [switch]$DryRun,
  [switch]$Elevated,
  [switch]$DoSafeAutoNow
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Log([string]$Msg, [string]$Level="INFO") {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[$ts][$Level] $Msg"
}

function Ensure-Tls12 {
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
}

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Relaunch-Admin([string[]]$Args) {
  Write-Log "Reexecutando como Administrador (UAC)..." "WARN"
  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $Args | Out-Null
  exit 0
}

function Test-IsSafeMode {
  if ($env:SAFEBOOT_OPTION) { return $true }
  return (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option")
}

#  FIX: switch valido / robusto (sem casos colados)
function Ask-YesNo([string]$Question, [bool]$DefaultYes=$true) {
  if ($Host.Name -notmatch "ConsoleHost") { return $DefaultYes }
  $suffix = if ($DefaultYes) { " [S/n]" } else { " [s/N]" }

  while ($true) {
    $ans = Read-Host ($Question + $suffix)
    if ([string]::IsNullOrWhiteSpace($ans)) { return $DefaultYes }

    $a = $ans.Trim().ToLowerInvariant()
    switch -Regex ($a) {
      '^(s|sim|y|yes)$' { return $true }
      '^(n|nao|nao|no)$' { return $false }
      default { Write-Host "Responda com S ou N." }
    }
  }
}

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Get-UninstallEntries([string]$Regex) {
  $roots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
  )
  $hits = @()
  foreach ($r in $roots) {
    if (-not (Test-Path $r)) { continue }
    foreach ($k in Get-ChildItem $r -ErrorAction SilentlyContinue) {
      try {
        $p = Get-ItemProperty $k.PSPath -ErrorAction Stop
        if ($p.DisplayName -and ($p.DisplayName -match $Regex)) {
          $hits += [pscustomobject]@{
            DisplayName    = $p.DisplayName
            DisplayVersion = $p.DisplayVersion
            Publisher      = $p.Publisher
          }
        }
      } catch {}
    }
  }
  return $hits
}

function Get-NvidiaDriverInventory {
  $drivers = @()
  try {
    $drivers = @(Get-CimInstance Win32_PnPSignedDriver -Filter "ClassGuid='{4d36e968-e325-11ce-bfc1-08002be10318}'" -ErrorAction Stop)
  } catch { $drivers = @() }

  $nvidiaDisplay = @($drivers | Where-Object {
    (($_.DriverProviderName + "") -match "NVIDIA") -or (($_.DeviceName + "") -match "NVIDIA")
  })

  $uninst = Get-UninstallEntries "NVIDIA"
  return [pscustomobject]@{
    NvidiaDisplayDrivers = $nvidiaDisplay
    NvidiaUninstall      = $uninst
  }
}

function Print-NvidiaInventory($inv, [string]$Title) {
  Write-Host ""
  Write-Log "=== $Title ==="
  if (@($inv.NvidiaDisplayDrivers).Count -eq 0) {
    Write-Log "DISPLAY drivers NVIDIA: nao encontrados."
  } else {
    Write-Log "DISPLAY drivers NVIDIA encontrados:"
    foreach ($d in @($inv.NvidiaDisplayDrivers)) {
      $date = $null
      try { $date = ([datetime]$d.DriverDate).ToString("yyyy-MM-dd") } catch { $date = ($d.DriverDate + "") }
      Write-Log ("- {0} | Provider={1} | Version={2} | Date={3}" -f $d.DeviceName, $d.DriverProviderName, $d.DriverVersion, $date)
    }
  }

  if (@($inv.NvidiaUninstall).Count -eq 0) {
    Write-Log "Entradas de Programas (Uninstall) com NVIDIA: nao encontradas."
  } else {
    Write-Log "Entradas de Programas (Uninstall) com NVIDIA:"
    foreach ($u in @($inv.NvidiaUninstall)) {
      Write-Log ("- {0} | Version={1} | Publisher={2}" -f $u.DisplayName, $u.DisplayVersion, $u.Publisher)
    }
  }
}

function Download-File([string[]]$Urls, [string]$OutFile) {
  foreach ($u in $Urls) {
    try {
      Write-Log "Baixando: $u"
      $headers = @{ "User-Agent" = "Mozilla/5.0" }
      Invoke-WebRequest -Uri $u -OutFile $OutFile -UseBasicParsing -Headers $headers
      if ((Test-Path $OutFile) -and ((Get-Item $OutFile).Length -gt 1024)) {
        Write-Log "Download OK: $OutFile ($((Get-Item $OutFile).Length) bytes)"
        return $true
      }
      Write-Log "Arquivo baixado parece invalido; tentando proximo..." "WARN"
    } catch {
      Write-Log "Falha no download: $u | $($_.Exception.Message)" "WARN"
    }
  }
  return $false
}

function Get-FileSha256([string]$Path) {
  try { return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToUpperInvariant() } catch { return $null }
}

function Find-DDUExe([string]$ExtractDir) {
  $c = Get-ChildItem -Path $ExtractDir -Recurse -Filter "Display Driver Uninstaller.exe" -ErrorAction SilentlyContinue
  return ($c | Select-Object -First 1).FullName
}

function Ensure-DDUExtracted([string]$DduSfxPath, [string]$ExtractDir) {
  Ensure-Dir $ExtractDir

  $dduExe = Find-DDUExe $ExtractDir
  if ($dduExe) { Write-Log "DDU ja extraido: $dduExe"; return $dduExe }

  Write-Log "Tentando extracao automatica (best-effort)..."
  try { Start-Process -FilePath $DduSfxPath -ArgumentList "-y -o`"$ExtractDir`"" -Wait | Out-Null } catch {}

  $dduExe = Find-DDUExe $ExtractDir
  if ($dduExe) { Write-Log "Extracao automatica OK: $dduExe"; return $dduExe }

  Write-Log "Extracao automatica nao confirmada. Abrindo extracao interativa..." "WARN"
  Start-Process -FilePath $DduSfxPath | Out-Null
  Write-Host ""
  Write-Host "Extraia para:"
  Write-Host "  $ExtractDir"
  Read-Host "Pressione ENTER quando terminar a extracao"

  $dduExe = Find-DDUExe $ExtractDir
  if (-not $dduExe) { throw "Nao encontrei 'Display Driver Uninstaller.exe' em $ExtractDir apos extracao." }
  Write-Log "Extracao manual OK: $dduExe"
  return $dduExe
}

function Run-DDU-CleanNvidia([string]$DduExePath) {
  $args = @("-silent","-logging","-createsystemrestorepoint","-nosafemodemsg","-cleannvidia","-restart")
  Write-Log ("Executando DDU: `"{0}`" {1}" -f $DduExePath, ($args -join " "))

  if ($DryRun) { Write-Log "DRY RUN: nao vou executar o DDU." "WARN"; return }

  Start-Process -FilePath $DduExePath -ArgumentList $args -Wait | Out-Null
}

function Configure-SafeBootOnce([string]$RunScriptPath) {
  Write-Log "Configurando boot em Safe Mode (uma vez) + RunOnce..."

  if ($DryRun) { Write-Log "DRY RUN: nao vou alterar bcdedit/RunOnce." "WARN"; return }

  $runOncePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
  New-Item -Path $runOncePath -Force | Out-Null
  $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$RunScriptPath`""
  New-ItemProperty -Path $runOncePath -Name "Run_DDU_NVIDIA_SafeMode" -Value $cmd -PropertyType String -Force | Out-Null

  & bcdedit /set "{current}" safeboot minimal | Out-Null
  shutdown.exe /r /t 0 | Out-Null
  exit 0
}

# -------------------- MAIN --------------------
Ensure-Tls12
Ensure-Dir $WorkDir

Write-Log "DDU NVIDIA worker iniciado. WorkDir=$WorkDir | Mode=$Mode | DryRun=$DryRun"

if (-not (Test-IsAdmin) -and -not $Elevated) {
  $args = @(
    "-NoProfile",
    "-ExecutionPolicy","Bypass",
    "-File", "`"$PSCommandPath`"",
    "-WorkDir", "`"$WorkDir`"",
    "-Mode", "`"$Mode`""
  )
  if ($DryRun) { $args += "-DryRun" }
  $args += "-Elevated"
  if ($DoSafeAutoNow) { $args += "-DoSafeAutoNow" }
  Relaunch-Admin -Args $args
}

$before = Get-NvidiaDriverInventory
Print-NvidiaInventory -inv $before -Title "ANTES (NVIDIA)"

$inSafe = Test-IsSafeMode
Write-Host ""
Write-Log ("Safe Mode atual: {0}" -f $inSafe)

if ($Mode -eq "Ask" -and -not $inSafe) {
  Write-Log "Recomendacao: usar Safe Mode para maior estabilidade com DDU." "WARN"
  if (Ask-YesNo "Agendar reboot em Safe Mode e executar automaticamente?" $true) {
    $Mode = "SafeAuto"
    $DoSafeAutoNow = $true
  } else {
    $Mode = "Normal"
  }
}

# DDU 18.1.4.2 (post oficial) + SHA256 (portable)
$dduVer = "18.1.4.2"
$dduUrl = "https://www.wagnardsoft.com/DDU/download/DDU%20v$dduVer.exe"
$expectedSha = "EDD9A06A164D01BCDF578926047A785ED7AA7BEE0F847E7235BACFE5BB25679C"
$fallbackPage = "https://www.wagnardsoft.com/display-driver-uninstaller-ddu"

$dduPath = Join-Path $WorkDir "DDU_v$dduVer.exe"

Write-Host ""
Write-Log "Baixando DDU v$dduVer..."
$ok = Download-File -Urls @($dduUrl) -OutFile $dduPath
if (-not $ok) {
  Write-Log "Falha no download direto (pode ser hotlink protection). Abrindo pagina oficial." "WARN"
  Start-Process $fallbackPage | Out-Null
  Write-Host "Baixe o DDU manualmente e salve como:"
  Write-Host "  $dduPath"
  Read-Host "Pressione ENTER quando o arquivo estiver nesse caminho"
}

if (-not (Test-Path $dduPath)) { throw "DDU nao encontrado em: $dduPath" }

$sha = Get-FileSha256 $dduPath
if ($sha) {
  Write-Log "SHA256 baixado:  $sha"
  Write-Log "SHA256 esperado: $expectedSha"
  if ($sha -ne $expectedSha) {
    Write-Log "SHA256 nao confere com o valor do post oficial. Recomendo baixar novamente do site oficial." "WARN"
    if (-not (Ask-YesNo "Continuar mesmo assim?" $false)) { exit 1 }
  }
}

$extractDir = Join-Path $WorkDir "DDU_Extracted"
$dduExe = Ensure-DDUExtracted -DduSfxPath $dduPath -ExtractDir $extractDir

if ($Mode -eq "SafeAuto" -and $DoSafeAutoNow -and -not $inSafe) {
  $runScript = Join-Path $WorkDir "Run_DDU_NVIDIA_SafeMode.ps1"
  $runBody = @"
`$ErrorActionPreference = 'Stop'
`$ProgressPreference = 'SilentlyContinue'
function Write-Log([string]`$Msg,[string]`$Level='INFO'){ `$ts=Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "[`$ts][`$Level] `$Msg" }
try {
  Write-Log 'Executando DDU NVIDIA em Safe Mode...'
  Start-Process -FilePath `"$dduExe`" -ArgumentList '-silent -logging -createsystemrestorepoint -nosafemodemsg -cleannvidia -restart' -Wait | Out-Null
} catch {
  Write-Log ('Erro rodando DDU: ' + `$_.Exception.Message) 'ERROR'
} finally {
  try { & bcdedit /deletevalue "{current}" safeboot | Out-Null } catch {}
}
"@
  Set-Content -Path $runScript -Value $runBody -Encoding UTF8
  Configure-SafeBootOnce -RunScriptPath $runScript
}

Write-Host ""
Write-Log "Antes de iniciar: feche apps e, idealmente, desconecte a internet ate reinstalar driver."
if (-not (Ask-YesNo "Confirmar e iniciar limpeza NVIDIA agora?" $true)) {
  Write-Log "Cancelado pelo usuario."
  exit 0
}

Run-DDU-CleanNvidia -DduExePath $dduExe
Write-Log "DDU acionou reboot (ou finalizou)."
'@

    Set-Content -LiteralPath $workerPath -Value $worker -Encoding UTF8

    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy","Bypass",
        "-File", "`"$workerPath`"",
        "-WorkDir", "`"$WorkDir`"",
        "-Mode", "`"$Mode`""
    )
    if ($DryRun) { $argList += "-DryRun" }

    Write-Log "Iniciando worker em outro PowerShell (WindowStyle=$WindowStyle)..."
    $p = Start-Process -FilePath "powershell.exe" -ArgumentList $argList -WindowStyle $WindowStyle -PassThru

    if ($WaitWorker) {
        Write-Log "Aguardando worker finalizar..."
        $p.WaitForExit()
        Write-Log "Worker finalizou. ExitCode=$($p.ExitCode)"
    } else {
        Write-Log "Worker iniciado (PID=$($p.Id))."
    }

    return $p
}


