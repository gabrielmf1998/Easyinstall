# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Read-RecallChoice {
    # Tenta ler 1 tecla (sem Enter). Se falhar, cai para Read-Host.
    try {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        $ch = $key.Character
        if ([string]::IsNullOrWhiteSpace($ch)) { return "" }
        return $ch.ToString().ToUpperInvariant()
    } catch {
        $ch = Read-Host "Escolha"
        if ([string]::IsNullOrWhiteSpace($ch)) { return "" }
        return $ch.Trim().Substring(0,1).ToUpperInvariant()
    }
}

function Set-RecallPolicies {
    [CmdletBinding()]
    param(
        [ValidateSet('Machine','User','Both')]
        [string]$Scope = 'Both',

        [Nullable[int]]$AllowRecallEnablement = $null,  # 0 bloqueia; 1 permite (se policy existir e for aplicada)
        [Nullable[int]]$DisableAIDataAnalysis = $null   # 1 bloqueia snapshots; 0 permite
    )

    $targets = @()
    if ($Scope -eq 'Machine' -or $Scope -eq 'Both') { $targets += 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' }
    if ($Scope -eq 'User'    -or $Scope -eq 'Both') { $targets += 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' }

    foreach ($path in $targets) {
        try {
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }

            if ($AllowRecallEnablement -ne $null) {
                New-ItemProperty -Path $path -Name 'AllowRecallEnablement' -PropertyType DWord -Value ([int]$AllowRecallEnablement) -Force | Out-Null
            }
            if ($DisableAIDataAnalysis -ne $null) {
                New-ItemProperty -Path $path -Name 'DisableAIDataAnalysis' -PropertyType DWord -Value ([int]$DisableAIDataAnalysis) -Force | Out-Null
            }
        } catch {
            Write-Host ("Falha ao escrever policy em {0}: {1}" -f $path, $_.Exception.Message) -ForegroundColor Blue
        }
    }
}

function Get-RecallStatus {
    $out = [ordered]@{
        FeaturePresent         = $false
        FeatureState           = $null
        PolicyAllowRecall      = $null
        PolicyDisableSnapshots = $null
        Verdict                = $null
        Details                = @()
    }

    # Policies
    $polMachine = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' -ErrorAction SilentlyContinue
    $polUser    = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' -ErrorAction SilentlyContinue

    function Get-PolicyValue($obj, $name) {
        if ($obj -and ($obj.PSObject.Properties.Name -contains $name)) { return $obj.$name }
        return $null
    }

    $allow = Get-PolicyValue $polMachine 'AllowRecallEnablement'
    if ($allow -eq $null) { $allow = Get-PolicyValue $polUser 'AllowRecallEnablement' }
    $snap  = Get-PolicyValue $polMachine 'DisableAIDataAnalysis'
    if ($snap -eq $null) { $snap = Get-PolicyValue $polUser 'DisableAIDataAnalysis' }

    $out.PolicyAllowRecall      = $allow
    $out.PolicyDisableSnapshots = $snap

    # Feature (pode nao existir)
    $feature = $null
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName Recall -ErrorAction Stop
    } catch {
        $feature = $null
    }

    if ($feature -eq $null) {
        $out.FeaturePresent = $false

        if ($allow -eq 0) { $out.Details += "Policy: AllowRecallEnablement=0 (bloqueia habilitar Recall)." }
        if ($snap -eq 1)  { $out.Details += "Policy: DisableAIDataAnalysis=1 (bloqueia snapshots)." }

        if ($out.Details.Count -gt 0) {
            $out.Verdict = "Recall: indisponivel/bloqueado por politica OU feature ausente neste Windows/PC."
        } else {
            $out.Verdict = "Recall: feature 'Recall' nao existe neste Windows/PC (muito comum fora de Copilot+)."
        }

        return [pscustomobject]$out
    }

    $out.FeaturePresent = $true
    $out.FeatureState   = [string]$feature.State

    if ($allow -eq 0) {
        $out.Verdict = "Recall: presente, mas bloqueado por politica (AllowRecallEnablement=0)."
        return [pscustomobject]$out
    }
    if ($snap -eq 1) {
        $out.Verdict = "Recall: presente, mas snapshots bloqueados por politica (DisableAIDataAnalysis=1)."
        return [pscustomobject]$out
    }

    if ($out.FeatureState -eq 'Enabled') {
        $out.Verdict = "Recall: presente e ATIVO (Enabled)."
    } else {
        $out.Verdict = "Recall: presente, mas NAO ativo (State=$($out.FeatureState))."
    }

    [pscustomobject]$out
}

function Recall-View {
    $r = Get-RecallStatus

    Write-Host ""
    Write-Host "=== RECALL STATUS ===" -ForegroundColor Blue
    Write-Host ("Feature presente: {0}" -f $r.FeaturePresent) -ForegroundColor Blue
    if ($r.FeaturePresent) {
        Write-Host ("Feature state:   {0}" -f $r.FeatureState) -ForegroundColor Blue
    }
    Write-Host ("Policy AllowRecallEnablement: {0}" -f $r.PolicyAllowRecall) -ForegroundColor DarkGray
    Write-Host ("Policy DisableAIDataAnalysis: {0}" -f $r.PolicyDisableSnapshots) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host $r.Verdict -ForegroundColor Green

    if ($r.Details -and $r.Details.Count -gt 0) {
        Write-Host ""
        Write-Host "Detalhes:" -ForegroundColor Blue
        foreach ($d in $r.Details) { Write-Host ("- {0}" -f $d) -ForegroundColor DarkGray }
    }
}

function Enable-RecallBestEffort {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== RECALL: HABILITAR (best-effort) ===" -ForegroundColor Blue

    # 1) Status atual
    $s = Get-RecallStatus
    Write-Host $s.Verdict -ForegroundColor DarkGray

    # Se feature nem existe, nao tem "milagre"
    if (-not $s.FeaturePresent) {
        Write-Host ""
        Write-Host "Nao da para habilitar: o feature 'Recall' nao esta presente neste PC/Windows." -ForegroundColor Blue
        Write-Host "Isso normalmente acontece em PCs que nao sao Copilot+." -ForegroundColor DarkGray
        return
    }

    # 2) Tentar destravar politicas (se existirem)
    # Obs: se for MDM/dominio, pode voltar sozinho; mas aqui e 'tentar de tudo' localmente.
    Write-Host ""
    Write-Host "Tentando liberar policies (se houver)..." -ForegroundColor Blue
    Set-RecallPolicies -Scope Both -AllowRecallEnablement 1 -DisableAIDataAnalysis 0

    # 3) Habilitar feature (PowerShell)
    try {
        Write-Host ""
        Write-Host "Habilitando feature via Enable-WindowsOptionalFeature..." -ForegroundColor Blue
        Enable-WindowsOptionalFeature -Online -FeatureName Recall -All -NoRestart -ErrorAction Stop | Out-Null
        Write-Host "Comando executado." -ForegroundColor Green
    } catch {
        Write-Host ("Falha no Enable-WindowsOptionalFeature: {0}" -f $_.Exception.Message) -ForegroundColor Blue

        # 4) Fallback DISM
        try {
            Write-Host ""
            Write-Host "Tentando fallback via DISM..." -ForegroundColor Blue
            & dism.exe /Online /Enable-Feature /FeatureName:Recall /All /NoRestart | Out-Host
        } catch {
            Write-Host ("Falha no DISM: {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    }

    # 5) Mostrar status final
    Write-Host ""
    $s2 = Get-RecallStatus
    Write-Host "RESULTADO:" -ForegroundColor Blue
    Write-Host $s2.Verdict -ForegroundColor Green
    if ($s2.Details -and $s2.Details.Count -gt 0) {
        foreach ($d in $s2.Details) { Write-Host ("- {0}" -f $d) -ForegroundColor DarkGray }
    }

    Write-Host ""
    Write-Host "Obs: pode ser necessario reiniciar para o estado refletir totalmente." -ForegroundColor DarkGray
}

function Disable-Recall {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== RECALL: DESABILITAR ===" -ForegroundColor Blue

    # 1) Bloquear snapshots por policy (mesmo se feature continuar instalado)
    Write-Host "Aplicando policy para bloquear snapshots (DisableAIDataAnalysis=1)..." -ForegroundColor Blue
    Set-RecallPolicies -Scope Both -DisableAIDataAnalysis 1

    # 2) Desabilitar feature (se existir)
    $s = Get-RecallStatus
    if ($s.FeaturePresent) {
        try {
            Write-Host "Desabilitando feature via Disable-WindowsOptionalFeature..." -ForegroundColor Blue
            Disable-WindowsOptionalFeature -Online -FeatureName Recall -NoRestart -ErrorAction Stop | Out-Null
            Write-Host "Feature desabilitado." -ForegroundColor Green
        } catch {
            Write-Host ("Falha ao desabilitar feature: {0}" -f $_.Exception.Message) -ForegroundColor Blue
        }
    } else {
        Write-Host "Feature 'Recall' nao esta presente; apenas policies foram aplicadas." -ForegroundColor DarkGray
    }

    Write-Host ""
    $s2 = Get-RecallStatus
    Write-Host "RESULTADO:" -ForegroundColor Blue
    Write-Host $s2.Verdict -ForegroundColor Green
}

function Disable-RecallPermanent {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== RECALL: DESABILITAR 'PERMANENTE' (remocao) ===" -ForegroundColor Blue
    Write-Host "Acao mais forte: remove o payload do feature + aplica policies bloqueando." -ForegroundColor DarkGray
    Write-Host "Nota honesta: grandes upgrades/reparos do Windows podem reintroduzir componentes, entao nao da para garantir 100% 'nem com Windows Update'." -ForegroundColor Blue

    # 1) Policies: bloquear e impedir habilitacao (localmente)
    Write-Host ""
    Write-Host "Aplicando policies (AllowRecallEnablement=0 e DisableAIDataAnalysis=1)..." -ForegroundColor Blue
    Set-RecallPolicies -Scope Both -AllowRecallEnablement 0 -DisableAIDataAnalysis 1

    # 2) Remover payload do feature (se existir)
    $s = Get-RecallStatus
    if ($s.FeaturePresent) {
        try {
            Write-Host "Removendo feature/payload via Disable-WindowsOptionalFeature -Remove..." -ForegroundColor Blue
            Disable-WindowsOptionalFeature -Online -FeatureName Recall -Remove -NoRestart -ErrorAction Stop | Out-Null
            Write-Host "Feature removido (payload removido)." -ForegroundColor Green
        } catch {
            Write-Host ("Falha ao remover payload: {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    } else {
        Write-Host "Feature 'Recall' nao esta presente; apenas policies foram aplicadas." -ForegroundColor DarkGray
    }

    Write-Host ""
    $s2 = Get-RecallStatus
    Write-Host "RESULTADO:" -ForegroundColor Blue
    Write-Host $s2.Verdict -ForegroundColor Green
    Write-Host ""
    Write-Host "Obs: pode ser necessario reiniciar." -ForegroundColor DarkGray
}

function Recall-Manage {
    while ($true) {
        Write-Host ""
        Write-Host "=== GERENCIAR RECALL ===" -ForegroundColor Blue
        Write-Host "[1] HABILITAR (best-effort)" -ForegroundColor Blue
        Write-Host "[2] DESABILITAR" -ForegroundColor Blue
        Write-Host "[3] DESABILITAR 'PERMANENTE' (remove payload + policies)" -ForegroundColor Blue
        Write-Host "[V] VER STATUS" -ForegroundColor DarkGray
        Write-Host "[Q] VOLTAR" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host -NoNewline "Escolha: " -ForegroundColor White

        $c = Read-RecallChoice
        Write-Host $c

        if ($c -eq 'Q') { return }
        elseif ($c -eq 'V') { Recall-View; continue }
        elseif ($c -eq '1') { Enable-RecallBestEffort; continue }
        elseif ($c -eq '2') { Disable-Recall; continue }
        elseif ($c -eq '3') { Disable-RecallPermanent; continue }
        else {
            Write-Host "Opcao invalida." -ForegroundColor Blue
        }
    }
}


