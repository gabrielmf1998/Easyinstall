# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Invoke-GpuDriverAutoInstall {
    [CmdletBinding()]
    param(
        [string]$WorkDir = "$env:TEMP\GpuDriverAutoInstall",
        [switch]$DryRun,
        [switch]$WaitWorker,
        [ValidateSet('Normal','Minimized','Maximized','Hidden')]
        [string]$WindowStyle = 'Normal'
    )

    function Write-Log([string]$Msg, [string]$Level = "INFO") {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$ts][$Level] $Msg"
    }

    try {
        if (-not (Test-Path -LiteralPath $WorkDir)) {
            New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
        }
    } catch {
        Write-Log "Falha criando WorkDir: $WorkDir | $($_.Exception.Message)" "ERROR"
        return
    }

    $workerPath = Join-Path $WorkDir "GpuDriverWorker.ps1"

    $worker = @'
param(
  [string]$WorkDir,
  [switch]$DryRun,
  [switch]$Elevated,

  # acoes pre-selecionadas (usadas quando o worker relanca em admin)
  [switch]$DoNvidia,
  [switch]$DoAmd,
  [switch]$DoIntel,
  [switch]$DoVmwareTools
)

$ErrorActionPreference = "Stop"

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

function Ask-YesNo([string]$Question, [bool]$DefaultYes = $true) {
  if ($Host.Name -notmatch "ConsoleHost") { return $DefaultYes } # fallback nao-interativo
  $suffix = if ($DefaultYes) { " [S/n]" } else { " [s/N]" }
  while ($true) {
    $ans = Read-Host ($Question + $suffix)
    if ([string]::IsNullOrWhiteSpace($ans)) { return $DefaultYes }
    switch ($ans.Trim().ToLowerInvariant()) {
      "s" { return $true }
      "sim" { return $true }
      "y" { return $true }
      "yes" { return $true }
      "n" { return $false }
      "nao" { return $false }
      "nao" { return $false }
    }
  }
}

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Download-File([string[]]$Urls, [string]$OutFile) {
  foreach ($u in $Urls) {
    try {
      Write-Log "Download: $u"
      Invoke-WebRequest -Uri $u -OutFile $OutFile -UseBasicParsing
      if ((Test-Path $OutFile) -and ((Get-Item $OutFile).Length -gt 1024)) {
        Write-Log "Download OK: $OutFile ($((Get-Item $OutFile).Length) bytes)"
        return $true
      }
      Write-Log "Arquivo baixado parece invalido. Tentando proximo..." "WARN"
    } catch {
      Write-Log "Falha no download: $u | $($_.Exception.Message)" "WARN"
    }
  }
  return $false
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
            InstallLocation= $p.InstallLocation
          }
        }
      } catch {}
    }
  }
  return $hits
}

function Detect-VMType {
  $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
  $vc = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)

  $manu  = ($cs.Manufacturer + "")
  $model = ($cs.Model + "")
  $hint  = ($manu + " " + $model)

  # tambem olha a GPU (ajuda bastante)
  $gpuNames = ($vc | ForEach-Object { $_.Name }) -join " | "

  if ($hint -match "VMware" -or $gpuNames -match "VMware") { return "VMware" }
  if ($hint -match "VirtualBox|innotek|Oracle" -or $gpuNames -match "VirtualBox") { return "VirtualBox" }
  if ($hint -match "Virtual Machine" -and $manu -match "Microsoft") { return "Hyper-V" }
  if ($hint -match "KVM|QEMU|Bochs|HVM domU|Xen|Red Hat" -or $gpuNames -match "QXL|VirtIO|Red Hat") { return "KVM/QEMU" }

  return "Physical"
}

function Get-DisplayDriverInventory {
  $vc = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
  $dd = @()

  # ClassGuid de Display: {4d36e968-e325-11ce-bfc1-08002be10318}
  try {
    $dd = @(Get-CimInstance Win32_PnPSignedDriver -Filter "ClassGuid='{4d36e968-e325-11ce-bfc1-08002be10318}'" -ErrorAction Stop)
  } catch {
    $dd = @()
  }

  return [pscustomobject]@{
    VideoControllers = $vc
    DisplayDrivers   = $dd
  }
}

function Normalize-VendorsPresent($inv) {
  $vendors = New-Object System.Collections.Generic.HashSet[string]

  foreach ($x in @($inv.VideoControllers)) {
    $pnp = ($x.PNPDeviceID + "")
    $name = ($x.Name + "")
    if ($pnp -match "VEN_10DE" -or $name -match "NVIDIA") { [void]$vendors.Add("NVIDIA") }
    if ($pnp -match "VEN_1002" -or $name -match "AMD|Radeon") { [void]$vendors.Add("AMD") }
    if ($pnp -match "VEN_8086" -or $name -match "Intel") { [void]$vendors.Add("INTEL") }
  }

  # fallback: pelo driver provider tambem
  foreach ($d in @($inv.DisplayDrivers)) {
    $prov = ($d.DriverProviderName + "")
    $dn   = ($d.DeviceName + "")
    if ($prov -match "NVIDIA" -or $dn -match "NVIDIA") { [void]$vendors.Add("NVIDIA") }
    if ($prov -match "Advanced Micro Devices|AMD" -or $dn -match "Radeon|AMD") { [void]$vendors.Add("AMD") }
    if ($prov -match "Intel" -or $dn -match "Intel") { [void]$vendors.Add("INTEL") }
  }

  return @($vendors)
}

function Test-UsingBasicDisplayAdapter($inv) {
  foreach ($x in @($inv.VideoControllers)) {
    $name = ($x.Name + "")
    if ($name -match "Microsoft Basic Display Adapter") { return $true }
  }
  # fallback pelo provider Microsoft
  foreach ($d in @($inv.DisplayDrivers)) {
    $prov = ($d.DriverProviderName + "")
    $dn   = ($d.DeviceName + "")
    if ($prov -match "^Microsoft$" -and $dn -match "Basic Display") { return $true }
  }
  return $false
}

function Get-CpuVendor {
  $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $cpu) { return "UNKNOWN" }
  $m = ($cpu.Manufacturer + "")
  $n = ($cpu.Name + "")
  if ($m -match "Intel" -or $n -match "Intel") { return "INTEL" }
  if ($m -match "AMD" -or $n -match "AMD") { return "AMD" }
  return "UNKNOWN"
}

function Print-Inventory($inv, $vmType) {
  Write-Host ""
  Write-Log "=== AMBIENTE ==="
  $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
  if ($cs) {
    Write-Log ("Host: {0} | Modelo: {1}" -f $cs.Manufacturer, $cs.Model)
  }
  Write-Log ("VM detectada: {0}" -f $vmType)

  Write-Host ""
  Write-Log "=== GPUs (Win32_VideoController) ==="
  if (@($inv.VideoControllers).Count -eq 0) {
    Write-Log "Nenhuma GPU retornada por Win32_VideoController." "WARN"
  } else {
    foreach ($x in @($inv.VideoControllers)) {
      Write-Log ("- {0} | PNP={1} | DriverVersion={2}" -f $x.Name, $x.PNPDeviceID, $x.DriverVersion)
    }
  }

  Write-Host ""
  Write-Log "=== Drivers (Win32_PnPSignedDriver / DISPLAY) ==="
  if (@($inv.DisplayDrivers).Count -eq 0) {
    Write-Log "Nao consegui ler Win32_PnPSignedDriver (DISPLAY). Vou seguir apenas com Win32_VideoController." "WARN"
  } else {
    foreach ($d in @($inv.DisplayDrivers)) {
      $date = $null
      try { $date = ([datetime]$d.DriverDate).ToString("yyyy-MM-dd") } catch { $date = ($d.DriverDate + "") }
      Write-Log ("- {0} | Provider={1} | Version={2} | Date={3}" -f $d.DeviceName, $d.DriverProviderName, $d.DriverVersion, $date)
    }
  }

  Write-Host ""
  $basic = Test-UsingBasicDisplayAdapter $inv
  if ($basic) {
    Write-Log "Detectado: Microsoft Basic Display Adapter (driver generico). Normal quando driver do fabricante nao esta instalado." "WARN"
  } else {
    Write-Log "Nao parece estar usando Microsoft Basic Display Adapter."
  }
}

function Test-NvidiaAppInstalled {
  if ((Get-UninstallEntries "NVIDIA App").Count -gt 0) { return $true }
  if (Test-Path "C:\Program Files\NVIDIA Corporation\NVIDIA App") { return $true }
  return $false
}
function Get-NvidiaAppVersion {
  $x = Get-UninstallEntries "NVIDIA App" | Select-Object -First 1
  return ($x.DisplayVersion + "")
}

function Test-AmdSoftwareInstalled {
  if ((Get-UninstallEntries "AMD Software").Count -gt 0) { return $true }
  if (Test-Path "C:\Program Files\AMD\CNext\CNext\RadeonSoftware.exe") { return $true }
  return $false
}
function Get-AmdSoftwareVersion {
  $x = Get-UninstallEntries "AMD Software" | Select-Object -First 1
  return ($x.DisplayVersion + "")
}

function Test-IntelDsaInstalled {
  if ((Get-UninstallEntries "Intel\(R\) Driver.*Support Assistant|Intel.*Driver.*Support Assistant").Count -gt 0) { return $true }
  if (Get-Service -Name "DSAService" -ErrorAction SilentlyContinue) { return $true }
  if (Test-Path "C:\Program Files (x86)\Intel\Driver and Support Assistant") { return $true }
  return $false
}
function Get-IntelDsaVersion {
  $x = Get-UninstallEntries "Intel\(R\) Driver.*Support Assistant|Intel.*Driver.*Support Assistant" | Select-Object -First 1
  return ($x.DisplayVersion + "")
}

function Test-VmwareToolsInstalled {
  if ((Get-UninstallEntries "VMware Tools").Count -gt 0) { return $true }
  if (Test-Path "C:\Program Files\VMware\VMware Tools") { return $true }
  return $false
}
function Get-VmwareToolsVersion {
  $x = Get-UninstallEntries "VMware Tools" | Select-Object -First 1
  return ($x.DisplayVersion + "")
}

function Offer-NextStep([string]$WhatFailed, [scriptblock]$RetryBlock) {
  Write-Log $WhatFailed "ERROR"
  Write-Host ""
  Write-Host "Nao consegui confirmar a instalacao."
  Write-Host "Opcoes:"
  Write-Host "  [1] Tentar novamente agora"
  Write-Host "  [2] Reiniciar o computador (recomendado apos drivers)"
  Write-Host "  [3] Sair"
  Write-Host ""

  if ($Host.Name -notmatch "ConsoleHost") {
    Write-Log "Host nao interativo. Encerrando sem prompt." "WARN"
    return
  }

  $choice = Read-Host "Escolha (1/2/3)"
  switch ($choice) {
    "1" { & $RetryBlock }
    "2" {
      Write-Log "Reiniciando em 10 segundos (voce pode cancelar fechando esta janela)..." "WARN"
      Start-Sleep -Seconds 10
      shutdown.exe /r /t 0
    }
    default { Write-Log "Saindo." }
  }
}

# -------------------- installers --------------------
function Install-NvidiaApp {
  Write-Log "NVIDIA: instalar NVIDIA App (para atualizar drivers)."
  if (Test-NvidiaAppInstalled) {
    Write-Log ("NVIDIA App ja instalado. Versao: {0}" -f (Get-NvidiaAppVersion))
    return $true
  }
  if ($DryRun) { Write-Log "DRY RUN: pulando instalacao NVIDIA."; return $true }

  $out = Join-Path $WorkDir "NVIDIA_App.exe"
  $urls = @(
    "https://us.download.nvidia.com/nvapp/client/11.0.6.383/NVIDIA_app_v11.0.6.383.exe",
    "https://www.nvidia.com/pt-br/software/nvidia-app/"
  )

  $ok = Download-File -Urls $urls -OutFile $out
  if (-not $ok) {
    Start-Process "https://www.nvidia.com/pt-br/software/nvidia-app/"
    return $false
  }

  Write-Log "Executando instalador (tentativa silenciosa /S)..."
  try { Start-Process -FilePath $out -ArgumentList "/S" -Wait | Out-Null } catch {}
  Start-Sleep -Seconds 3

  if (Test-NvidiaAppInstalled) { Write-Log "NVIDIA App instalado/confirmado."; return $true }

  Write-Log "Nao confirmei instalacao silenciosa. Abrindo instalador interativo..." "WARN"
  Start-Process -FilePath $out | Out-Null
  Read-Host "Finalize o instalador e pressione ENTER aqui"
  return (Test-NvidiaAppInstalled)
}

function Install-AmdSoftware {
  Write-Log "AMD: instalar AMD Software: Adrenalin (Auto-Detect / Minimal Setup)."
  if (Test-AmdSoftwareInstalled) {
    Write-Log ("AMD Software ja instalado. Versao: {0}" -f (Get-AmdSoftwareVersion))
    return $true
  }
  if ($DryRun) { Write-Log "DRY RUN: pulando instalacao AMD."; return $true }

  $out = Join-Path $WorkDir "AMD_Adrenalin_MinimalSetup.exe"
  $urls = @(
    "https://drivers.amd.com/drivers/installer/25.30/whql/amd-software-adrenalin-edition-26.1.1-minimalsetup-260119_web.exe",
    "https://www.amd.com/en/support/download/drivers.html"
  )

  $ok = Download-File -Urls $urls -OutFile $out
  if (-not $ok) {
    Start-Process "https://www.amd.com/en/support/download/drivers.html"
    return $false
  }

  Write-Log "Executando installer (pode abrir UI)..."
  try { Start-Process -FilePath $out -Wait | Out-Null } catch {}

  Start-Sleep -Seconds 3
  return (Test-AmdSoftwareInstalled)
}

function Install-IntelDsa {
  Write-Log "INTEL: instalar Intel Driver & Support Assistant (DSA)."
  if (Test-IntelDsaInstalled) {
    Write-Log ("Intel DSA ja instalado. Versao: {0}" -f (Get-IntelDsaVersion))
    return $true
  }
  if ($DryRun) { Write-Log "DRY RUN: pulando instalacao Intel DSA."; return $true }

  $out = Join-Path $WorkDir "Intel_DSA.exe"
  $urls = @(
    "https://dsadata.intel.com/installer",
    "https://www.intel.com.br/content/www/br/pt/support/detect.html"
  )

  $ok = Download-File -Urls $urls -OutFile $out
  if (-not $ok) {
    Start-Process "https://www.intel.com.br/content/www/br/pt/support/detect.html"
    return $false
  }

  Write-Log "Executando instalador (tentativa silenciosa: -s -norestart)..."
  try { Start-Process -FilePath $out -ArgumentList "-s -norestart" -Wait | Out-Null } catch {}
  Start-Sleep -Seconds 3

  if (Test-IntelDsaInstalled) { Write-Log "Intel DSA instalado/confirmado."; return $true }

  Write-Log "Nao confirmei instalacao silenciosa. Abrindo instalador interativo..." "WARN"
  Start-Process -FilePath $out | Out-Null
  Read-Host "Finalize o instalador e pressione ENTER aqui"
  return (Test-IntelDsaInstalled)
}

function Install-VmwareTools {
  Write-Log "VMware: instalar VMware Tools."
  if (Test-VmwareToolsInstalled) {
    Write-Log ("VMware Tools ja instalado. Versao: {0}" -f (Get-VmwareToolsVersion))
    return $true
  }
  if ($DryRun) { Write-Log "DRY RUN: pulando instalacao VMware Tools."; return $true }

  # URL 'latest' oficial (diretorio publico)
  $base = "https://packages.vmware.com/tools/releases/latest/windows/x64/"
  $exeUrl = $base + "VMware-tools-13.0.10-25056151-x64.exe"
  $out = Join-Path $WorkDir "VMwareTools.exe"

  $ok = Download-File -Urls @($exeUrl, $base) -OutFile $out
  if (-not $ok) {
    Start-Process $base
    return $false
  }

  Write-Log "Executando instalador (UI pode aparecer)..."
  try { Start-Process -FilePath $out -Wait | Out-Null } catch {}
  Start-Sleep -Seconds 3
  return (Test-VmwareToolsInstalled)
}

# -------------------- main flow --------------------
try {
  Ensure-Tls12
  Ensure-Dir $WorkDir

  Write-Log "Worker iniciado. WorkDir=$WorkDir | DryRun=$DryRun | ElevatedFlag=$Elevated"
  $vmType = Detect-VMType
  $inv = Get-DisplayDriverInventory

  Print-Inventory -inv $inv -vmType $vmType

  # status de apps (mesmo se nao instalar)
  Write-Host ""
  Write-Log "=== STATUS DE SOFTWARE (se ja existir) ==="
  if (Test-NvidiaAppInstalled) { Write-Log ("NVIDIA App: INSTALADO | Versao: {0}" -f (Get-NvidiaAppVersion)) } else { Write-Log "NVIDIA App: nao instalado" }
  if (Test-AmdSoftwareInstalled) { Write-Log ("AMD Software: INSTALADO | Versao: {0}" -f (Get-AmdSoftwareVersion)) } else { Write-Log "AMD Software: nao instalado" }
  if (Test-IntelDsaInstalled) { Write-Log ("Intel DSA: INSTALADO | Versao: {0}" -f (Get-IntelDsaVersion)) } else { Write-Log "Intel DSA: nao instalado" }
  if ($vmType -eq "VMware") {
    if (Test-VmwareToolsInstalled) { Write-Log ("VMware Tools: INSTALADO | Versao: {0}" -f (Get-VmwareToolsVersion)) } else { Write-Log "VMware Tools: nao instalado" }
  }

  # Se ja vier com acoes definidas (segunda execucao, elevada), nao pergunta de novo
  if (-not ($DoNvidia -or $DoAmd -or $DoIntel -or $DoVmwareTools)) {

    # 1) VM path
    if ($vmType -ne "Physical") {
      Write-Host ""
      Write-Log "VM detectada: aplicando fluxo apropriado para o hypervisor..."
      switch ($vmType) {
        "VMware" {
          $DoVmwareTools = Ask-YesNo "VMware detectado. Deseja instalar/atualizar VMware Tools?" ($true)
        }
        "VirtualBox" {
          Write-Log "VirtualBox detectado. O recomendado e instalar 'Guest Additions' dentro da VM (menu Devices -> Insert Guest Additions CD image)." "WARN"
          if (Ask-YesNo "Deseja abrir a pagina oficial de downloads do VirtualBox agora?" ($true)) {
            Start-Process "https://www.virtualbox.org/wiki/Downloads" | Out-Null
          }
        }
        "Hyper-V" {
          Write-Log "Hyper-V detectado. Normalmente os drivers/integration vem via Windows Update no guest. Vou abrir a referencia oficial." "WARN"
          if (Ask-YesNo "Abrir referencia oficial (Integration Components)?" ($true)) {
            Start-Process "https://support.microsoft.com/pt-br/topic/atualiza%C3%A7%C3%A3o-de-componentes-de-integra%C3%A7%C3%A3o-hyper-v-para-m%C3%A1quinas-virtuais-windows-8a74ffad-576e-d5a0-5a2f-d6fb2594f990" | Out-Null
          }
        }
        "KVM/QEMU" {
          Write-Log "KVM/QEMU detectado. Em geral, o caminho e VirtIO (especialmente Proxmox/QEMU)." "WARN"
          if (Ask-YesNo "Abrir referencia VirtIO drivers?" ($true)) {
            Start-Process "https://pve.proxmox.com/wiki/Windows_VirtIO_Drivers" | Out-Null
          }
        }
      }
    }

    # 2) Se nao for VM (ou se for VM VMware com passthrough, ainda pode aparecer NVIDIA/AMD/Intel)  perguntar por vendor
    $vendors = Normalize-VendorsPresent $inv
    $basic = Test-UsingBasicDisplayAdapter $inv
    $cpuVendor = Get-CpuVendor

    Write-Host ""
    Write-Log ("Vendors detectados (GPU/driver): {0}" -f (if ($vendors.Count) { $vendors -join ", " } else { "(nenhum)" }))
    Write-Log ("CPU Vendor: {0}" -f $cpuVendor)

    if ($vendors.Count -eq 0) {
      # fallback: grafico integrado
      Write-Log "Nenhum vendor claro detectado. Vou seguir pelo CPU (grafico integrado)." "WARN"
      if ($cpuVendor -eq "AMD") {
        $DoAmd = Ask-YesNo "Deseja instalar/atualizar AMD Auto-Detect (Adrenalin) para grafico integrado?" ($basic)
      } elseif ($cpuVendor -eq "INTEL") {
        $DoIntel = Ask-YesNo "Deseja instalar/atualizar Intel DSA para grafico integrado Intel?" ($basic)
      } else {
        $DoIntel = Ask-YesNo "CPU desconhecida. Deseja tentar Intel DSA (fallback)?" ($basic)
      }
    } else {
      # Para cada vendor encontrado, perguntar (mesmo se ja tiver driver)
      if ($vendors -contains "NVIDIA") {
        $def = $basic -or (-not (Test-NvidiaAppInstalled))
        $DoNvidia = Ask-YesNo "NVIDIA detectada. Deseja instalar/atualizar NVIDIA App?" ($def)
      }
      if ($vendors -contains "AMD") {
        $def = $basic -or (-not (Test-AmdSoftwareInstalled))
        $DoAmd = Ask-YesNo "AMD detectada. Deseja instalar/atualizar AMD Software (Adrenalin Auto-Detect)?" ($def)
      }
      if ($vendors -contains "INTEL") {
        $def = $basic -or (-not (Test-IntelDsaInstalled))
        $DoIntel = Ask-YesNo "Intel detectada. Deseja instalar/atualizar Intel DSA?" ($def)
      }

      # Em notebooks hibridos (Intel + NVIDIA), muita gente quer manter Intel tambem  ja perguntamos acima.
    }
  }

  $needInstall = ($DoNvidia -or $DoAmd -or $DoIntel -or $DoVmwareTools)

  if (-not $needInstall) {
    Write-Log "Nenhuma acao selecionada. Encerrando."
    exit 0
  }

  # Elevacao sob demanda (somente quando vai instalar)
  if (-not (Test-IsAdmin) -and -not $Elevated) {
    Write-Log "Instalacao selecionada, mas o worker nao esta em Admin. Solicitando UAC..." "WARN"

    $args = @(
      "-NoProfile",
      "-ExecutionPolicy","Bypass",
      "-File", "`"$PSCommandPath`"",
      "-WorkDir", "`"$WorkDir`""
    )
    if ($DryRun) { $args += "-DryRun" }
    $args += "-Elevated"
    if ($DoNvidia) { $args += "-DoNvidia" }
    if ($DoAmd) { $args += "-DoAmd" }
    if ($DoIntel) { $args += "-DoIntel" }
    if ($DoVmwareTools) { $args += "-DoVmwareTools" }

    try {
      Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $args | Out-Null
      Write-Log "Worker elevado iniciado. Encerrando este."
      exit 0
    } catch {
      Write-Log "Usuario cancelou UAC ou falhou elevar: $($_.Exception.Message)" "ERROR"
      exit 1
    }
  }

  # -------------------- execucao das instalacoes --------------------
  Write-Host ""
  Write-Log "=== EXECUTANDO ACOES SELECIONADAS ==="

  $okAll = $true

  if ($DoVmwareTools) {
    $ok = Install-VmwareTools
    if (-not $ok) { $okAll = $false }
  }
  if ($DoNvidia) {
    $ok = Install-NvidiaApp
    if (-not $ok) { $okAll = $false }
  }
  if ($DoAmd) {
    $ok = Install-AmdSoftware
    if (-not $ok) { $okAll = $false }
  }
  if ($DoIntel) {
    $ok = Install-IntelDsa
    if (-not $ok) { $okAll = $false }
  }

  if ($okAll) {
    Write-Host ""
    Write-Log "SUCESSO: acoes concluidas e instalacao confirmada (por deteccao de software)."
    if (Ask-YesNo "Deseja reiniciar agora? (recomendado apos drivers)" ($false)) {
      shutdown.exe /r /t 0
    }
    exit 0
  }

  Offer-NextStep -WhatFailed "FALHA: nao consegui confirmar 1+ instalacoes." -RetryBlock {
    Write-Log "Retry manual iniciado..."
    $okAll2 = $true
    if ($DoVmwareTools) { if (-not (Install-VmwareTools)) { $okAll2 = $false } }
    if ($DoNvidia) { if (-not (Install-NvidiaApp)) { $okAll2 = $false } }
    if ($DoAmd) { if (-not (Install-AmdSoftware)) { $okAll2 = $false } }
    if ($DoIntel) { if (-not (Install-IntelDsa)) { $okAll2 = $false } }

    if ($okAll2) { Write-Log "SUCESSO apos retry." } else { Write-Log "Ainda falhou. Reinicie e tente novamente." "ERROR" }
  }

  exit 1

} catch {
  Write-Log "ERRO FATAL no worker: $($_.Exception.Message)" "ERROR"
  Write-Log ($_.ScriptStackTrace + "") "ERROR"
  exit 1
}
'@

    try {
        Set-Content -LiteralPath $workerPath -Value $worker -Encoding UTF8
    } catch {
        Write-Log "Falha escrevendo worker: $workerPath | $($_.Exception.Message)" "ERROR"
        return
    }

    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$workerPath`"",
        "-WorkDir", "`"$WorkDir`""
    )
    if ($DryRun) { $argList += "-DryRun" }

    Write-Log "Abrindo worker em outro PowerShell (WindowStyle=$WindowStyle)..."
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


