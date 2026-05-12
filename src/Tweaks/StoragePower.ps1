# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Get-TrimStatus {
    [CmdletBinding()]
    param()

    $out = & fsutil behavior query DisableDeleteNotify 2>&1
    $txt = ($out | Out-String)

    # Interpretacao:
    # DisableDeleteNotify = 0  => TRIM habilitado
    # DisableDeleteNotify = 1  => TRIM desabilitado
    $ntfs = $null
    $refs = $null

    if ($txt -match '(?im)NTFS\s+DisableDeleteNotify\s*=\s*(\d)') { $ntfs = [int]$Matches[1] }
    if ($txt -match '(?im)ReFS\s+DisableDeleteNotify\s*=\s*(\d)') { $refs = [int]$Matches[1] }

    [pscustomobject]@{
        NTFS_DisableDeleteNotify = $ntfs
        ReFS_DisableDeleteNotify = $refs
        TrimEnabled_NTFS         = if ($ntfs -eq $null) { $null } else { ($ntfs -eq 0) }
        TrimEnabled_ReFS         = if ($refs -eq $null) { $null } else { ($refs -eq 0) }
        Raw                      = $txt.Trim()
    }
}

function Read-YesNoKey {
    [CmdletBinding()]
    param(
        [string]$Prompt = "Deseja habilitar TRIM? [S/N]: "
    )

    Write-Host -NoNewline $Prompt -ForegroundColor White

    try {
        $k = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        $ch = $k.Character.ToString().ToUpperInvariant()
        Write-Host $ch
    } catch {
        $ch = (Read-Host).Trim().Substring(0,1).ToUpperInvariant()
    }

    return ($ch -eq 'S' -or $ch -eq 'Y')
}

function Enable-Trim {
    [CmdletBinding()]
    param()

    # Requer Admin para "set"
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Para habilitar TRIM, execute o PowerShell em modo Administrador."
    }

    # Tenta sintaxe nova por filesystem; fallback para sintaxe antiga
    $ok = $false
    try {
        & fsutil behavior set DisableDeleteNotify NTFS 0 | Out-Null
        & fsutil behavior set DisableDeleteNotify ReFS 0 | Out-Null
        $ok = $true
    } catch {
        $ok = $false
    }

    if (-not $ok) {
        & fsutil behavior set DisableDeleteNotify 0 | Out-Null
    }
}

function Test-TrimAndOfferEnable {
    [CmdletBinding()]
    param(
        [switch]$Quiet
    )

    $s = Get-TrimStatus

    if (-not $Quiet) {
        Write-Host ""
        Write-Host "=== TRIM (SSD) ===" -ForegroundColor Blue
        Write-Host $s.Raw
        Write-Host ""
        Write-Host "Obs: DisableDeleteNotify=0 => TRIM habilitado | 1 => TRIM desabilitado" -ForegroundColor DarkGray
        Write-Host ""
    }

    # Se nao conseguiu parsear nada, so informa
    if ($s.NTFS_DisableDeleteNotify -eq $null -and $s.ReFS_DisableDeleteNotify -eq $null) {
        Write-Host "Nao consegui determinar o status do TRIM neste sistema." -ForegroundColor Blue
        pause
        return
    }

    $ntfsOk = ($s.TrimEnabled_NTFS -eq $true) -or ($s.TrimEnabled_NTFS -eq $null) # se nao existir NTFS no output, ignora
    $refsOk = ($s.TrimEnabled_ReFS -eq $true) -or ($s.TrimEnabled_ReFS -eq $null)

    if ($ntfsOk -and $refsOk) {
        Write-Host " TRIM ja esta habilitado." -ForegroundColor Green
        pause
        return
    }

    # TRIM desabilitado (ou parcial)
    Write-Host "  TRIM nao esta habilitado para todos os sistemas de arquivos (NTFS/ReFS)." -ForegroundColor Blue

    $want = Read-YesNoKey -Prompt "Deseja habilitar TRIM agora? [S/N]: "
    if (-not $want) {
        Write-Host "OK. Mantendo TRIM como esta." -ForegroundColor DarkGray
        pause
        return
    }

    Enable-Trim

    $s2 = Get-TrimStatus
    Write-Host ""
    Write-Host "Status apos tentativa:" -ForegroundColor Blue
    Write-Host $s2.Raw
    Write-Host ""

    $ntfsOk2 = ($s2.TrimEnabled_NTFS -eq $true) -or ($s2.TrimEnabled_NTFS -eq $null)
    $refsOk2 = ($s2.TrimEnabled_ReFS -eq $true) -or ($s2.TrimEnabled_ReFS -eq $null)

    if ($ntfsOk2 -and $refsOk2) {
        Write-Host " TRIM habilitado com sucesso." -ForegroundColor Green
    } else {
        Write-Host " Nao consegui habilitar TRIM completamente. Verifique permissoes/politicas do sistema." -ForegroundColor Red
    }
    pause
}

#VAI DESABILITAR ECONOMIA
function Set-WorkstationPowerProfile {
    <#
    .SYNOPSIS
        Ajusta configuracoes de energia no Windows (PowerShell 5.1):
        - Desabilita hibernacao
        - Ativa plano "Alto desempenho" (ou cria se nao existir)
        - Define para NAO desligar o monitor (AC) apos 15 minutos (0 = nunca)

    .NOTES
        Requer privilegios de administrador para desabilitar hibernacao e criar/alterar planos.
        Usa powercfg (nativo do Windows).
    #>

    [CmdletBinding()]
    param(
        [int]$MonitorTimeoutACMinutes = 15
    )

    Write-Host "== Aplicando perfil de energia =="

    # 1) Desabilitar hibernacao
    Write-Host "`n[1/3] Hibernacao"
    try {
        $hib = (powercfg /a) 2>&1
        if ($hib -match "Hibernacao" -and $hib -match "dispon") {
            Write-Host " - Hibernacao parece estar disponivel. Tentando desabilitar..."
        } else {
            Write-Host " - Nao foi possivel confirmar disponibilidade da hibernacao via 'powercfg /a'. Mesmo assim, vou aplicar o comando de desativacao."
        }

        powercfg /h off | Out-Null
        Write-Host " - Hibernacao desabilitada (powercfg /h off)."
    }
    catch {
        Write-Host " - Falha ao desabilitar hibernacao: $($_.Exception.Message)"
    }

    # 2) Garantir plano "Alto desempenho"
    Write-Host "`n[2/3] Plano de energia: Alto desempenho"

    # GUID conhecido do esquema High performance (Windows)
    $HighPerfWellKnownGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"

    $activeGuid = $null
    $highPerfGuid = $null

    try {
        $list = (powercfg /list) 2>&1

        # Tenta achar um plano com nome "Alto desempenho" (pt-BR) ou "High performance" (en-US)
        $lines = $list -split "`r?`n"
        foreach ($line in $lines) {
            # Exemplos:
            # "GUID do Esquema de Energia: xxxxxxxx-....  (Alto desempenho) *"
            # "Power Scheme GUID: xxxxxxxx-....  (High performance) *"
            if ($line -match "([0-9a-fA-F\-]{36}).*\((Alto desempenho|High performance)\)") {
                $highPerfGuid = $matches[1]
                break
            }
        }

        if ($highPerfGuid) {
            Write-Host " - Plano 'Alto desempenho' encontrado: $highPerfGuid"
        } else {
            Write-Host " - Plano 'Alto desempenho' nao encontrado. Vou tentar criar a partir do modelo conhecido..."
            # duplica a partir do GUID bem conhecido
            $dupOut = (powercfg -duplicatescheme $HighPerfWellKnownGuid) 2>&1

            # Saida costuma conter um GUID; vamos extrair
            if ($dupOut -match "([0-9a-fA-F\-]{36})") {
                $highPerfGuid = $matches[1]
                Write-Host " - Plano criado com sucesso: $highPerfGuid"
            } else {
                Write-Host " - Nao consegui extrair o GUID do plano criado. Saida: $dupOut"
            }
        }

        if ($highPerfGuid) {
            Write-Host " - Ativando plano 'Alto desempenho'..."
            powercfg /setactive $highPerfGuid | Out-Null
            Write-Host " - Plano ativo definido para: $highPerfGuid"
        } else {
            Write-Host " - Nao foi possivel localizar/criar o plano 'Alto desempenho'."
        }
    }
    catch {
        Write-Host " - Falha ao configurar plano de energia: $($_.Exception.Message)"
    }

    # 3) Desabilitar desligamento do monitor apos 15 min (na pratica: 0 = nunca) no modo AC
    Write-Host "`n[3/3] Monitor (modo ligado na tomada / AC)"

    try {
        if ($MonitorTimeoutACMinutes -lt 0) {
            Write-Host " - Valor invalido ($MonitorTimeoutACMinutes). Ajuste ignorado."
        } else {
            # Observacao: no powercfg, timeout de display em AC usa /x -monitor-timeout-ac <minutos>
            # Para "desabilitar desligar monitor apos 15 minutos", o correto e 0 (nunca).
            if ($MonitorTimeoutACMinutes -eq 0) {
                Write-Host " - Configurando monitor para NUNCA desligar (AC)..."
            } else {
                Write-Host " - Voce pediu para 'desabilitar desligar monitor apos 15 minutos'. Isso normalmente significa: NAO desligar nunca (0)."
                Write-Host " - Mesmo assim, vou aplicar o valor informado para timeout AC: $MonitorTimeoutACMinutes minuto(s)."
            }

            powercfg /x -monitor-timeout-ac $MonitorTimeoutACMinutes | Out-Null
            Write-Host " - Timeout do monitor em AC aplicado: $MonitorTimeoutACMinutes minuto(s). (0 = nunca)"
        }
    }
    catch {
        Write-Host " - Falha ao configurar timeout do monitor: $($_.Exception.Message)"
    }

    Write-Host "`n== Concluido =="
    pause
}


