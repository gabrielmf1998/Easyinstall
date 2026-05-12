# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Invoke-WindowsMaintenanceWizard {
    [CmdletBinding()]
    param(
        [switch]$NoExitChildWindow
    )

    Set-StrictMode -Version Latest

    function Write-Header {
        param([string]$Title)
        Write-Host ""
        Write-Host ("=" * 72)
        Write-Host ("{0}" -f $Title)
        Write-Host ("=" * 72)
        Write-Host ""
    }

    function Pause-Local {
        Write-Host ""
        Read-Host "Pressione ENTER para continuar"
    }

    function Test-IsAdmin {
        try {
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            $p  = New-Object Security.Principal.WindowsPrincipal($id)
            return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { return $false }
    }

    function Start-ChildPowerShell {
        param(
            [Parameter(Mandatory)] [string]$Title,
            [Parameter(Mandatory)] [string]$ScriptBlockText,
            [switch]$AsAdmin
        )

        # Mostra ao usuario exatamente o que sera executado
        Write-Host ""
        Write-Host ">>> Abrindo outra janela do PowerShell para executar:" -ForegroundColor Blue
        Write-Host "    $Title" -ForegroundColor Blue
        Write-Host "    ---" -ForegroundColor DarkBlue
        $ScriptBlockText.Trim().Split("`n") | ForEach-Object { Write-Host ("    " + $_) -ForegroundColor DarkBlue }
        Write-Host "    ---" -ForegroundColor DarkBlue

        $childPayload = @"
`$ErrorActionPreference = 'Continue'
function _Say([string]`$m){ Write-Host `[WindowsMaintenance`] `$m -ForegroundColor Blue }
`$Host.UI.RawUI.WindowTitle = '$Title'
_Say 'Iniciando...'
try {
$ScriptBlockText
} catch {
    Write-Host ''
    Write-Host 'ERRO:' -ForegroundColor Red
    Write-Host `$_ -ForegroundColor Red
}
Write-Host ''
_Say 'Finalizado.'
Read-Host 'Pressione ENTER para fechar esta janela'
"@

        $args = @(
            '-NoProfile'
            '-ExecutionPolicy', 'Bypass'
            '-Command', $childPayload
        )

        $psi = @{
            FilePath     = 'powershell.exe'
            ArgumentList = $args
            WindowStyle  = 'Normal'
        }

        if ($AsAdmin) {
            $psi.Verb = 'RunAs'
        }

        try {
            Start-Process @psi | Out-Null
        } catch {
            Write-Host "Falha ao abrir janela elevada. Tente executar o PowerShell como Administrador. Detalhe: $($_.Exception.Message)" -ForegroundColor Blue
        }

        if (-not $NoExitChildWindow) {
            Pause-Local
        }
    }

    function Get-PhysicalDiskInfo {
    $result = @()

    # Preferir Get-PhysicalDisk (mais confiavel para SSD/HDD)
    try {
        $pds = Get-PhysicalDisk -ErrorAction Stop
        foreach ($d in $pds) {
            $result += [pscustomobject]@{
                FriendlyName = $d.FriendlyName
                MediaType    = [string]$d.MediaType      # SSD / HDD / Unspecified
                BusType      = [string]$d.BusType
                SizeGB       = [math]::Round(($d.Size / 1GB), 2)
                HealthStatus = [string]$d.HealthStatus
                Operational  = [string]$d.OperationalStatus
            }
        }
        if ($result.Count -gt 0) { return $result }
    } catch {
        # segue para fallback
    }

    # Fallback (WMI/CIM) - pode nao distinguir SSD/HDD com precisao em alguns PCs
    try {
        $w = Get-CimInstance Win32_DiskDrive
        foreach ($d in $w) {

            $mt = $null
            if ($d.PSObject.Properties.Match('MediaType').Count -gt 0) { $mt = [string]$d.MediaType }
            if ([string]::IsNullOrWhiteSpace($mt)) { $mt = 'Unspecified' }

            $bus = $null
            if ($d.PSObject.Properties.Match('InterfaceType').Count -gt 0) { $bus = [string]$d.InterfaceType }
            if ([string]::IsNullOrWhiteSpace($bus)) { $bus = 'Unspecified' }

            $sizeGB = $null
            try { $sizeGB = [math]::Round(([double]$d.Size / 1GB), 2) } catch { $sizeGB = $null }

            $result += [pscustomobject]@{
                FriendlyName = [string]$d.Model
                MediaType    = $mt
                BusType      = $bus
                SizeGB       = $sizeGB
                HealthStatus = 'Unspecified'
                Operational  = 'Unspecified'
            }
        }
    } catch {
        # se falhar, retorna o que tiver (possivelmente vazio)
    }

    return $result
}

    function Show-DiskSummary {
        Write-Header "Deteccao de discos (SSD/HDD) e status"
        $info = @(Get-PhysicalDiskInfo)

        if (-not $info -or $info.Count -eq 0) {
            Write-Host "Nao foi possivel detectar discos." -ForegroundColor Blue
            return
        }

        $info | Format-Table FriendlyName, MediaType, BusType, SizeGB, HealthStatus, Operational -AutoSize
        Write-Host ""
        Write-Host "Notas:" -ForegroundColor Gray
        Write-Host "- SSD: use 'Otimizar (TRIM/ReTrim)', NAO 'desfragmentar'." -ForegroundColor Gray
        Write-Host "- HDD: desfragmentar pode ser util, dependendo do uso." -ForegroundColor Gray
    }

    function Pick-DriveLetter {
        $vols = Get-Volume | Where-Object DriveLetter | Sort-Object DriveLetter
        Write-Host ""
        $vols | Select-Object DriveLetter, FileSystemLabel, FileSystem, SizeRemaining, Size |
            Format-Table -AutoSize
        Write-Host ""
        $dl = Read-Host "Digite a letra da unidade (ex: C)"
        $dl = ($dl.Trim().TrimEnd(':')).ToUpperInvariant()
        if ($dl -notmatch '^[A-Z]$') {
            Write-Host "Letra invalida." -ForegroundColor Blue
            return $null
        }
        return $dl
    }

    # ====== MENU PRINCIPAL ======
    while ($true) {
        Write-Header "Assistente de Manutencao do Windows (PowerShell 5.1)"
        Show-DiskSummary

        Write-Host ""
        Write-Host "Escolha uma acao:"
        Write-Host " 1) Verificar integridade do sistema (SFC /SCANNOW)  [Admin]"
        Write-Host " 2) Reparar imagem do Windows (DISM /Online /Cleanup-Image /RestoreHealth)  [Admin]"
        Write-Host " 3) Checar e corrigir disco (CHKDSK)  [Admin]"
        Write-Host " 4) Otimizar unidades (TRIM para SSD / Desfragmentar HDD)  [Admin recomendado]"
        Write-Host " 5) Limpeza nativa (Storage Sense / arquivos temporarios)  [padrao]"
        Write-Host " 6) Atualizar componentes do Windows Update (reset basico)  [Admin]"
        Write-Host " 7) Mostrar ferramentas nativas e atalhos uteis (GUI)  [padrao]"
        Write-Host " 0) Sair"
        Write-Host ""

        $choice = Read-Host "Opcao"
        switch ($choice) {
            '1' {
                Start-ChildPowerShell -AsAdmin -Title 'SFC /SCANNOW' -ScriptBlockText @"
_Say 'Executando SFC /SCANNOW (pode demorar)...'
sfc /scannow
_Say 'SFC concluido. Se houve corrupcao que nao foi corrigida, rode o DISM e repita o SFC.'
"@
            }
            '2' {
                Start-ChildPowerShell -AsAdmin -Title 'DISM RestoreHealth' -ScriptBlockText @"
_Say 'Executando DISM /Online /Cleanup-Image /RestoreHealth (pode demorar)...'
dism /online /cleanup-image /restorehealth
_Say 'DISM concluido. Recomenda-se rodar SFC /SCANNOW em seguida.'
"@
            }
            '3' {
                $dl = Pick-DriveLetter
                if (-not $dl) { Pause-Local; break }

                # Para o disco do sistema, chkdsk /f normalmente agenda no reboot.
                Start-ChildPowerShell -AsAdmin -Title "CHKDSK $dl" -ScriptBlockText @"
_Say 'Rodando CHKDSK...'
_Say 'Se for a unidade do sistema, pode ser necessario agendar para o proximo boot.'
chkdsk $dl`: /f /r
"@
            }
            '4' {
                # O Windows decide o melhor metodo via "defrag /O"
                Start-ChildPowerShell -AsAdmin -Title 'Otimizar unidades (defrag /O)' -ScriptBlockText @"
_Say 'Listando volumes e status (Get-Volume)...'
Get-Volume | Where-Object DriveLetter | Sort-Object DriveLetter | Format-Table DriveLetter, FileSystemLabel, FileSystem, HealthStatus, SizeRemaining, Size -AutoSize

_Say 'Executando otimizacao automatica (defrag /C /O /U /V)...'
_Say 'Isso faz TRIM/ReTrim em SSD e desfragmentacao em HDD quando aplicavel.'
defrag /C /O /U /V
"@
            }
            '5' {
                Start-ChildPowerShell -Title 'Limpeza nativa (Storage Sense / Temp)' -ScriptBlockText @"
_Say 'Abrindo configuracoes do Storage Sense (GUI)...'
Start-Process 'ms-settings:storagesense'

_Say 'Abrindo pasta de temporarios do usuario (%TEMP%)...'
Start-Process `$env:TEMP

_Say 'Abrindo Limpeza de Disco (cleanmgr)...'
Start-Process cleanmgr.exe
"@
            }
            '6' {
                Start-ChildPowerShell -AsAdmin -Title 'Reset basico do Windows Update' -ScriptBlockText @"
_Say 'Parando servicos do Windows Update...'
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Stop-Service bits -Force -ErrorAction SilentlyContinue
Stop-Service cryptsvc -Force -ErrorAction SilentlyContinue

_Say 'Renomeando pastas de cache (SoftwareDistribution/Catroot2)...'
Rename-Item -Path `$env:SystemRoot\SoftwareDistribution -NewName 'SoftwareDistribution.old' -ErrorAction SilentlyContinue
Rename-Item -Path `$env:SystemRoot\System32\catroot2 -NewName 'catroot2.old' -ErrorAction SilentlyContinue

_Say 'Iniciando servicos novamente...'
Start-Service cryptsvc -ErrorAction SilentlyContinue
Start-Service bits -ErrorAction SilentlyContinue
Start-Service wuauserv -ErrorAction SilentlyContinue

_Say 'Concluido. Voce pode tentar atualizar o Windows novamente.'
"@
            }
            '7' {
                Start-ChildPowerShell -Title 'Ferramentas nativas (atalhos)' -ScriptBlockText @"
_Say 'Abrindo ferramentas nativas uteis...'
_Say 'Gerenciador de Tarefas'
Start-Process taskmgr

_Say 'Monitor de Recursos'
Start-Process resmon

_Say 'Visualizador de Eventos'
Start-Process eventvwr.msc

_Say 'Gerenciamento de Disco'
Start-Process diskmgmt.msc

_Say 'Informacoes do Sistema'
Start-Process msinfo32

_Say 'Windows Security'
Start-Process 'windowsdefender:'
"@
            }
            '0' {
                Write-Host "Saindo." -ForegroundColor Gray
                return
            }
            default {
                Write-Host "Opcao invalida." -ForegroundColor Blue
                Pause-Local
            }
        }
    }
}


