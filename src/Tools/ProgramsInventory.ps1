# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Invoke-ProgramsInventoryAndUpdater {
    [CmdletBinding()]
    param(
        [switch]$IncludeUwpApps,     # inclui apps da Microsoft Store (Get-AppxPackage)
        [switch]$ExportCsvOnStart    # exporta inventario automaticamente ao iniciar
    )

    $childTemplate = @'
$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = 'Inventario e Atualizador de Programas'

# Corrige caracteres estranhos (winget progress bar) no console PS 5.1
try { chcp 65001 > $null } catch {}
$utf8 = New-Object System.Text.UTF8Encoding $false
[Console]::InputEncoding  = $utf8
[Console]::OutputEncoding = $utf8
$OutputEncoding           = $utf8

function Say([string]$m) { Write-Host "[Programs] $(Get-Date -Format HH:mm:ss) - $m" -ForegroundColor Blue }
function Warn([string]$m){ Write-Host "[!] $m" -ForegroundColor Blue }
function Err([string]$m) { Write-Host "[X] $m" -ForegroundColor Red }

$includeUwp = __INCLUDE_UWP__
$exportOnStart = __EXPORT_ON_START__

function Get-Win32InstalledApps {
    # Registro: 64-bit + 32-bit + CurrentUser
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $apps = foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayName.Trim() } |
            ForEach-Object {
                [pscustomobject]@{
                    Type            = 'Win32'
                    Name            = [string]$_.DisplayName
                    Version         = [string]$_.DisplayVersion
                    Publisher       = [string]$_.Publisher
                    InstallLocation = [string]$_.InstallLocation
                    UninstallString = [string]$_.UninstallString
                    Source          = ($p -replace '\\\*','')
                }
            }
    }

    # Dedup basico por Nome+Versao+Publisher
    $apps |
        Sort-Object Name, Version, Publisher -Unique
}

function Get-UwpInstalledApps {
    # UWP / Store apps
    Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -and $_.Name.Trim() } |
        ForEach-Object {
            [pscustomobject]@{
                Type            = 'UWP'
                Name            = [string]$_.Name
                Version         = [string]$_.Version
                Publisher       = [string]$_.Publisher
                InstallLocation = [string]$_.InstallLocation
                UninstallString = ''
                Source          = 'AppxPackage'
            }
        } |
        Sort-Object Name -Unique
}

function Build-Inventory {
    Say "Coletando programas Win32 (Registro)..."
    $win32 = @(Get-Win32InstalledApps)

    $uwp = @()
    if ($includeUwp) {
        Say "Incluindo apps UWP/Microsoft Store (Get-AppxPackage -AllUsers)..."
        $uwp = @(Get-UwpInstalledApps)
    } else {
        Say "UWP/Microsoft Store: desativado (use -IncludeUwpApps para incluir)."
    }

    $all = @($win32 + $uwp)
    $all = $all | Sort-Object Type, Name, Version, Publisher

    Say ("Inventario pronto: {0} itens (Win32: {1} | UWP: {2})" -f $all.Count, $win32.Count, $uwp.Count)
    return $all
}

function Show-Inventory([object[]]$inv) {
    Write-Host ""
    Say "Mostrando inventario (pode ser longo)..."
    $inv | Select-Object Type, Name, Version, Publisher |
        Format-Table -AutoSize
    Write-Host ""
    Say "Dica: voce pode exportar para CSV no menu."
}

function Export-InventoryCsv([object[]]$inv) {
    $path = Join-Path $env:USERPROFILE ("InstalledPrograms_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Say "Exportando CSV para: $path"
    $inv | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Say "CSV exportado."
}

function Has-Command([string]$name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

function Winget-PreviewUpgrades {
    Say "Listando atualizacoes disponiveis via winget (winget upgrade)..."
    winget upgrade | Out-Host
}

function Winget-UpgradeAllInteractive {
    Say "Atualizando tudo que o winget reconhecer (sem silent; pode abrir instaladores)..."
    Say "Comando: winget upgrade --all --source winget --accept-source-agreements --accept-package-agreements --interactive"
    winget upgrade --all --source winget --accept-source-agreements --accept-package-agreements --interactive | Out-Host
    Say "winget upgrade --all finalizado."
}

function Winget-UpgradeByIdInteractive {
    $id = Read-Host "Digite o ID exato do pacote (ex: Valve.Steam). Enter cancela"
    if ([string]::IsNullOrWhiteSpace($id)) { return }
    Say ("Atualizando pacote: {0}" -f $id)
    Say ("Comando: winget upgrade --id {0} -e --source winget --accept-source-agreements --accept-package-agreements --interactive" -f $id)
    winget upgrade --id $id -e --source winget --accept-source-agreements --accept-package-agreements --interactive | Out-Host
    Say "Finalizado."
}

function Open-StoreUpdates {
    Say "Abrindo pagina de 'Downloads e atualizacoes' da Microsoft Store..."
    Start-Process "ms-windows-store://downloadsandupdates" | Out-Null
}

function Choco-UpgradeAll {
    if (-not (Has-Command choco)) { Err "Chocolatey (choco) nao encontrado."; return }
    Warn "Chocolatey pode pedir confirmacoes e/ou Admin."
    $ans = Read-Host "Rodar 'choco upgrade all' agora? (S/N)"
    if ($ans -notmatch '^[Ss]') { return }
    Say "Comando: choco upgrade all"
    choco upgrade all | Out-Host
    Say "Chocolatey finalizado."
}

function Scoop-UpgradeAll {
    if (-not (Has-Command scoop)) { Err "Scoop nao encontrado."; return }
    Warn "Scoop geralmente atualiza tudo via: scoop update *"
    $ans = Read-Host "Rodar 'scoop update *' agora? (S/N)"
    if ($ans -notmatch '^[Ss]') { return }
    Say "Comando: scoop update *"
    scoop update * | Out-Host
    Say "Scoop finalizado."
}

# ===== Execucao =====
$inventory = Build-Inventory

if ($exportOnStart) {
    Export-InventoryCsv $inventory
}

while ($true) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host "MENU - Inventario e Atualizacao"
    Write-Host "============================================================"
    Write-Host "1) Mostrar inventario completo (TODOS os programas)"
    Write-Host "2) Exportar inventario para CSV"
    Write-Host "3) Atualizar via winget (pre-visualizar atualizacoes)"
    Write-Host "4) Atualizar via winget (atualizar TUDO - interativo)"
    Write-Host "5) Atualizar via winget (atualizar por ID - interativo)"
    Write-Host "6) Atualizar apps da Microsoft Store (abre tela de updates)"
    Write-Host "7) Atualizar via Chocolatey (se existir)"
    Write-Host "8) Atualizar via Scoop (se existir)"
    Write-Host "9) Recoletar inventario (refazer lista)"
    Write-Host "0) Sair"
    Write-Host ""

    $opt = Read-Host "Escolha"
    switch ($opt) {
        '1' { Show-Inventory $inventory }
        '2' { Export-InventoryCsv $inventory }
        '3' {
            if (-not (Has-Command winget)) { Err "winget nao encontrado. Instale/atualize o App Installer na Store."; Open-StoreUpdates; break }
            Winget-PreviewUpgrades
        }
        '4' {
            if (-not (Has-Command winget)) { Err "winget nao encontrado. Instale/atualize o App Installer na Store."; break }
            Winget-UpgradeAllInteractive
        }
        '5' {
            if (-not (Has-Command winget)) { Err "winget nao encontrado. Instale/atualize o App Installer na Store."; break }
            Winget-PreviewUpgrades
            Winget-UpgradeByIdInteractive
        }
        '6' { Open-StoreUpdates }
        '7' { Choco-UpgradeAll }
        '8' { Scoop-UpgradeAll }
        '9' { $inventory = Build-Inventory }
        '0' { Say "Saindo."; return }
        default { Warn "Opcao invalida." }
    }
}

Read-Host "Pressione ENTER para fechar esta janela"
'@

    $includeUwpText = if ($IncludeUwpApps.IsPresent) { '$true' } else { '$false' }
    $exportText     = if ($ExportCsvOnStart.IsPresent) { '$true' } else { '$false' }

    $child = $childTemplate `
        -replace '__INCLUDE_UWP__', $includeUwpText `
        -replace '__EXPORT_ON_START__', $exportText

    Write-Host ">>> Abrindo outra janela do PowerShell para listar e oferecer atualizacoes..." -ForegroundColor Blue

    $bytes   = [Text.Encoding]::Unicode.GetBytes($child)
    $encoded = [Convert]::ToBase64String($bytes)

    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoExit",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", $encoded
    ) -WindowStyle Normal | Out-Null
}


