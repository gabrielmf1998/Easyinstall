#FORCA EXECUCAO DO SCRIPT APENAS NA 5.1 OU MAIS RECENTE DO PS

#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#LIBERA TLS1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#TIRA ANIMACAO DOWNLOAD
$ProgressPreference = 'SilentlyContinue'

#ARRUMA TAMANHO DA TELA
[Console]::SetWindowSize(80, 30)

#EXECUTE SOMENTE NO WINDOWS 11
function Assert-Windows11Only {
    if ($env:OS -ne 'Windows_NT') {
        throw "Este script só pode ser executado no Windows 11."
    }

    $caption = $null
    $build   = $null
    $ptype   = $null  # 1=Workstation (Client), 2=Domain Controller, 3=Server

    try {
        $os      = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $caption = [string]$os.Caption
        $build   = [int]$os.BuildNumber
        $ptype   = [int]$os.ProductType
    } catch {
        # Fallback via registro (caso CIM esteja indisponível)
        $cv      = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $caption = [string]$cv.ProductName
        $build   = [int]$cv.CurrentBuildNumber

        # Client/server pelo ProductOptions (WinNT = client)
        $po      = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -ErrorAction Stop
        $ptype   = if ($po.ProductType -eq 'WinNT') { 1 } else { 3 }
    }

    if ($ptype -ne 1) {
        throw ("Este script só pode ser executado no Windows 11 (Client). Detectado: {0} (Build {1})" -f $caption, $build)
    }

    # Windows 11: build >= 22000
    if ($build -lt 22000) {
        throw ("Este script só pode ser executado no Windows 11. Detectado: {0} (Build {1})" -f $caption, $build)
    }
}
Assert-Windows11Only

#TEMA PRETO
function Set-ConsoleBlackTheme {
    try {
        $raw = $Host.UI.RawUI

        # Console Host (conhost) / hosts que respeitam RawUI
        $raw.BackgroundColor = 'Black'
        $raw.ForegroundColor = 'White'

        # Reaplica cores na tela
        Clear-Host
    } catch {
        # Ignora se o host não suporta RawUI
    }

    # Fallback ANSI (Windows Terminal / hosts modernos)
    # 40 = fundo preto, 97 = texto branco brilhante, 0 = reset
    $esc = [char]27
    Write-Host "$esc[40m$esc[97m" -NoNewline
    Clear-Host
}
Set-ConsoleBlackTheme

# IMPEDE USUARIO DE CLICAR NO TERMINAL
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class ConsoleHelper {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll")]
    public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out int lpMode);
    [DllImport("kernel32.dll")]
    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, int dwMode);
}
"@
$handle = [ConsoleHelper]::GetStdHandle(-10)
$mode = 0
[ConsoleHelper]::GetConsoleMode($handle, [ref]$mode) | Out-Null
$newMode = $mode -band (-bnot 0x40)
[ConsoleHelper]::SetConsoleMode($handle, $newMode) | Out-Null

# FORCA EXECUCAO VIA ADM
function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsAdmin)) {
    Write-Host "Reabrindo em modo Administrador..." -ForegroundColor Yellow

    # Caminho do script atual (funciona quando o .ps1 está salvo e sendo executado como arquivo)
    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        throw "Não consegui detectar o caminho do script. Execute o .ps1 a partir de um arquivo salvo (não colado no terminal)."
    }

    # Preserva argumentos (se houver)
    $argList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$scriptPath`""
    ) + $args

    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    exit
}






#---->INICIO DOS FUNCTIONS

#VAI INSTALAR WINHANCE
function Install-Winhance {
    Write-Host ""
    Write-Host "Iniciando instalador do Winhance..." -ForegroundColor Cyan

    $cmd = 'try { irm "https://get.winhance.net" | iex } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }'
    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", $cmd
    )
}

#VAI INSTALAR CTT WINUTIL
function Install-CTT {
    Write-Host ""
    Write-Host "Iniciando instalador do CTT-WinUtil..." -ForegroundColor Cyan

    $cmd = 'try { irm "https://christitus.com/win" | iex } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }'
    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", $cmd
    )
}

#VAI TESTAR RECALL
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
            Write-Host ("Falha ao escrever policy em {0}: {1}" -f $path, $_.Exception.Message) -ForegroundColor Yellow
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

    # Feature (pode não existir)
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
            $out.Verdict = "Recall: indisponível/bloqueado por política OU feature ausente neste Windows/PC."
        } else {
            $out.Verdict = "Recall: feature 'Recall' não existe neste Windows/PC (muito comum fora de Copilot+)."
        }

        return [pscustomobject]$out
    }

    $out.FeaturePresent = $true
    $out.FeatureState   = [string]$feature.State

    if ($allow -eq 0) {
        $out.Verdict = "Recall: presente, mas bloqueado por política (AllowRecallEnablement=0)."
        return [pscustomobject]$out
    }
    if ($snap -eq 1) {
        $out.Verdict = "Recall: presente, mas snapshots bloqueados por política (DisableAIDataAnalysis=1)."
        return [pscustomobject]$out
    }

    if ($out.FeatureState -eq 'Enabled') {
        $out.Verdict = "Recall: presente e ATIVO (Enabled)."
    } else {
        $out.Verdict = "Recall: presente, mas NÃO ativo (State=$($out.FeatureState))."
    }

    [pscustomobject]$out
}

function Recall-View {
    $r = Get-RecallStatus

    Write-Host ""
    Write-Host "=== RECALL STATUS ===" -ForegroundColor Cyan
    Write-Host ("Feature presente: {0}" -f $r.FeaturePresent) -ForegroundColor Yellow
    if ($r.FeaturePresent) {
        Write-Host ("Feature state:   {0}" -f $r.FeatureState) -ForegroundColor Yellow
    }
    Write-Host ("Policy AllowRecallEnablement: {0}" -f $r.PolicyAllowRecall) -ForegroundColor DarkGray
    Write-Host ("Policy DisableAIDataAnalysis: {0}" -f $r.PolicyDisableSnapshots) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host $r.Verdict -ForegroundColor Green

    if ($r.Details -and $r.Details.Count -gt 0) {
        Write-Host ""
        Write-Host "Detalhes:" -ForegroundColor Cyan
        foreach ($d in $r.Details) { Write-Host ("- {0}" -f $d) -ForegroundColor DarkGray }
    }
}

function Enable-RecallBestEffort {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== RECALL: HABILITAR (best-effort) ===" -ForegroundColor Cyan

    # 1) Status atual
    $s = Get-RecallStatus
    Write-Host $s.Verdict -ForegroundColor DarkGray

    # Se feature nem existe, não tem "milagre"
    if (-not $s.FeaturePresent) {
        Write-Host ""
        Write-Host "Não dá para habilitar: o feature 'Recall' não está presente neste PC/Windows." -ForegroundColor Yellow
        Write-Host "Isso normalmente acontece em PCs que não são Copilot+." -ForegroundColor DarkGray
        return
    }

    # 2) Tentar destravar políticas (se existirem)
    # Obs: se for MDM/domínio, pode voltar sozinho; mas aqui é 'tentar de tudo' localmente.
    Write-Host ""
    Write-Host "Tentando liberar policies (se houver)..." -ForegroundColor Cyan
    Set-RecallPolicies -Scope Both -AllowRecallEnablement 1 -DisableAIDataAnalysis 0

    # 3) Habilitar feature (PowerShell)
    try {
        Write-Host ""
        Write-Host "Habilitando feature via Enable-WindowsOptionalFeature..." -ForegroundColor Cyan
        Enable-WindowsOptionalFeature -Online -FeatureName Recall -All -NoRestart -ErrorAction Stop | Out-Null
        Write-Host "Comando executado." -ForegroundColor Green
    } catch {
        Write-Host ("Falha no Enable-WindowsOptionalFeature: {0}" -f $_.Exception.Message) -ForegroundColor Yellow

        # 4) Fallback DISM
        try {
            Write-Host ""
            Write-Host "Tentando fallback via DISM..." -ForegroundColor Cyan
            & dism.exe /Online /Enable-Feature /FeatureName:Recall /All /NoRestart | Out-Host
        } catch {
            Write-Host ("Falha no DISM: {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    }

    # 5) Mostrar status final
    Write-Host ""
    $s2 = Get-RecallStatus
    Write-Host "RESULTADO:" -ForegroundColor Cyan
    Write-Host $s2.Verdict -ForegroundColor Green
    if ($s2.Details -and $s2.Details.Count -gt 0) {
        foreach ($d in $s2.Details) { Write-Host ("- {0}" -f $d) -ForegroundColor DarkGray }
    }

    Write-Host ""
    Write-Host "Obs: pode ser necessário reiniciar para o estado refletir totalmente." -ForegroundColor DarkGray
}

function Disable-Recall {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== RECALL: DESABILITAR ===" -ForegroundColor Cyan

    # 1) Bloquear snapshots por policy (mesmo se feature continuar instalado)
    Write-Host "Aplicando policy para bloquear snapshots (DisableAIDataAnalysis=1)..." -ForegroundColor Cyan
    Set-RecallPolicies -Scope Both -DisableAIDataAnalysis 1

    # 2) Desabilitar feature (se existir)
    $s = Get-RecallStatus
    if ($s.FeaturePresent) {
        try {
            Write-Host "Desabilitando feature via Disable-WindowsOptionalFeature..." -ForegroundColor Cyan
            Disable-WindowsOptionalFeature -Online -FeatureName Recall -NoRestart -ErrorAction Stop | Out-Null
            Write-Host "Feature desabilitado." -ForegroundColor Green
        } catch {
            Write-Host ("Falha ao desabilitar feature: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }
    } else {
        Write-Host "Feature 'Recall' não está presente; apenas policies foram aplicadas." -ForegroundColor DarkGray
    }

    Write-Host ""
    $s2 = Get-RecallStatus
    Write-Host "RESULTADO:" -ForegroundColor Cyan
    Write-Host $s2.Verdict -ForegroundColor Green
}

function Disable-RecallPermanent {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== RECALL: DESABILITAR 'PERMANENTE' (remoção) ===" -ForegroundColor Cyan
    Write-Host "Ação mais forte: remove o payload do feature + aplica policies bloqueando." -ForegroundColor DarkGray
    Write-Host "Nota honesta: grandes upgrades/reparos do Windows podem reintroduzir componentes, então não dá para garantir 100% 'nem com Windows Update'." -ForegroundColor Yellow

    # 1) Policies: bloquear e impedir habilitação (localmente)
    Write-Host ""
    Write-Host "Aplicando policies (AllowRecallEnablement=0 e DisableAIDataAnalysis=1)..." -ForegroundColor Cyan
    Set-RecallPolicies -Scope Both -AllowRecallEnablement 0 -DisableAIDataAnalysis 1

    # 2) Remover payload do feature (se existir)
    $s = Get-RecallStatus
    if ($s.FeaturePresent) {
        try {
            Write-Host "Removendo feature/payload via Disable-WindowsOptionalFeature -Remove..." -ForegroundColor Cyan
            Disable-WindowsOptionalFeature -Online -FeatureName Recall -Remove -NoRestart -ErrorAction Stop | Out-Null
            Write-Host "Feature removido (payload removido)." -ForegroundColor Green
        } catch {
            Write-Host ("Falha ao remover payload: {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    } else {
        Write-Host "Feature 'Recall' não está presente; apenas policies foram aplicadas." -ForegroundColor DarkGray
    }

    Write-Host ""
    $s2 = Get-RecallStatus
    Write-Host "RESULTADO:" -ForegroundColor Cyan
    Write-Host $s2.Verdict -ForegroundColor Green
    Write-Host ""
    Write-Host "Obs: pode ser necessário reiniciar." -ForegroundColor DarkGray
}

function Recall-Manage {
    while ($true) {
        Write-Host ""
        Write-Host "=== GERENCIAR RECALL ===" -ForegroundColor Cyan
        Write-Host "[1] HABILITAR (best-effort)" -ForegroundColor Yellow
        Write-Host "[2] DESABILITAR" -ForegroundColor Yellow
        Write-Host "[3] DESABILITAR 'PERMANENTE' (remove payload + policies)" -ForegroundColor Yellow
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
            Write-Host "Opção inválida." -ForegroundColor Yellow
        }
    }
}

#VAI TESTAR O IPV6
function Test-IPv6 {
    [CmdletBinding()]
    param(
        [int]$Count = 2,
        [string[]]$PingTargets = @(
            "2606:4700:4700::1111", # Cloudflare
            "2001:4860:4860::8888", # Google
            "2620:fe::fe"           # Quad9
        )
    )

    function Get-IPv6ScopeLabel {
        param([Parameter(Mandatory)][string]$Address)

        try { $ip = [System.Net.IPAddress]::Parse($Address) } catch { return "invalid" }
        $bytes = $ip.GetAddressBytes()

        # Link-local fe80::/10
        if ($bytes[0] -eq 0xFE -and (($bytes[1] -band 0xC0) -eq 0x80)) { return "link-local" }
        # ULA fc00::/7
        if (($bytes[0] -band 0xFE) -eq 0xFC) { return "unique-local" }
        # Global unicast 2000::/3
        if (($bytes[0] -band 0xE0) -eq 0x20) { return "global" }

        return "other"
    }

    function Test-IsVirtualInterface {
        param([string]$InterfaceAlias, [string]$InterfaceDescription)
        $text = ("{0} {1}" -f $InterfaceAlias, $InterfaceDescription).ToLowerInvariant()
        return ($text -match 'zerotier|wintun|wireguard|tap|tunnel|teredo|isatap|6to4|vpn|virtual|vmware|hyper-v|vbox|loopback')
    }

    Write-Host ""
    Write-Host "=== Diagnóstico IPv6 ===" -ForegroundColor Cyan

    # Binding IPv6 habilitado?
    $ipv6BindingEnabled = $false
    try {
        $ipv6BindingEnabled = [bool](Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop |
                                     Where-Object Enabled -eq $true |
                                     Select-Object -First 1)
    } catch {
        $ipv6BindingEnabled = $false
    }

    # Endereços IPv6
    $raw = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
           Where-Object { $_.IPAddress -and $_.IPAddress -ne "::1" } |
           Sort-Object InterfaceIndex, PrefixLength

    # Mapa de interfaces
    $ifMap = @{}
    try {
        Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { $ifMap[$_.IfIndex] = $_ }
    } catch {}

    $addrInfo = @()
    if ($raw) {
        $addrInfo = @(
            $raw | ForEach-Object {
                $if = $null
                if ($ifMap.ContainsKey($_.InterfaceIndex)) { $if = $ifMap[$_.InterfaceIndex] }

                $scope = Get-IPv6ScopeLabel $_.IPAddress
                $alias = $_.InterfaceAlias
                $desc  = if ($if) { $if.InterfaceDescription } else { "" }
                $isVirt = Test-IsVirtualInterface -InterfaceAlias $alias -InterfaceDescription $desc

                [pscustomobject]@{
                    IPAddress      = $_.IPAddress
                    Scope          = $scope
                    InterfaceAlias = $alias
                    IfIndex        = $_.InterfaceIndex
                    PrefixLength   = $_.PrefixLength
                    AddressState   = $_.AddressState
                    Description    = $desc
                    IsVirtual      = $isVirt
                }
            }
        )

        Write-Host ""
        Write-Host "Endereços IPv6 encontrados:" -ForegroundColor Cyan
        $addrInfo | ForEach-Object {
            $virt = if ($_.IsVirtual) { " (virtual)" } else { "" }
            Write-Host ("- {0,-39} scope={1,-12} if={2} ({3}) /{4}{5}" -f $_.IPAddress, $_.Scope, $_.IfIndex, $_.InterfaceAlias, $_.PrefixLength, $virt) -ForegroundColor DarkGray
        }
    } else {
        Write-Host "Nenhum endereço IPv6 encontrado." -ForegroundColor Yellow
    }

    $ipv6Enabled = $ipv6BindingEnabled -or [bool]$raw

    # IMPORTANTÍSSIMO com StrictMode: sempre força array
    $addrPhysical = @($addrInfo | Where-Object { $_.IsVirtual -eq $false })
    #$addrVirtual  = @($addrInfo | Where-Object { $_.IsVirtual -eq $true })

    # Scopes em array (não acessa .Scope direto)
    $scopesPhysical = @($addrPhysical | ForEach-Object { $_.Scope })

    #$hasLinkLocal = ($scopesPhysical -contains "link-local")
    
    #$hasULA       = ($scopesPhysical -contains "unique-local")
    $hasGlobal    = ($scopesPhysical -contains "global")

    $globalObj = $addrPhysical | Where-Object { $_.Scope -eq "global" } | Select-Object -First 1
    $globalIP  = if ($null -ne $globalObj) { $globalObj.IPAddress } else { $null }

    # Rota default IPv6 (::/0), preferindo interface física
    $defaultRoutes = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "::/0" -ErrorAction SilentlyContinue |
                     Sort-Object RouteMetric, InterfaceMetric

    $defaultRoutePhysical = $null
    foreach ($r in $defaultRoutes) {
        $if = $null
        if ($ifMap.ContainsKey($r.InterfaceIndex)) { $if = $ifMap[$r.InterfaceIndex] }
        $alias = if ($if) { $if.Name } else { "" }
        $desc  = if ($if) { $if.InterfaceDescription } else { "" }
        if (-not (Test-IsVirtualInterface -InterfaceAlias $alias -InterfaceDescription $desc)) {
            $defaultRoutePhysical = $r
            break
        }
    }

    $hasDefaultRoute = ($null -ne $defaultRoutePhysical)

    Write-Host ""
    if ($hasDefaultRoute) {
        Write-Host ("Rota default IPv6 OK: ::/0 via {0} (if={1})" -f $defaultRoutePhysical.NextHop, $defaultRoutePhysical.InterfaceIndex) -ForegroundColor Green
    } else {
        Write-Host "Sem rota default IPv6 (::/0) em interface física." -ForegroundColor Yellow
    }

    # Ping IPv6 (ICMP) – só tenta se tiver global + rota (física)
    $anyPingOk = $false
    $tc = Get-Command Test-Connection -ErrorAction SilentlyContinue
    $useTargetName = $false
    $useComputerName = $false
    if ($tc) {
        $useTargetName   = $tc.Parameters.ContainsKey("TargetName")
        $useComputerName = $tc.Parameters.ContainsKey("ComputerName")
    }

    Write-Host ""
    Write-Host "Testando conectividade IPv6 (ICMP)..." -ForegroundColor Cyan

    if ($hasGlobal -and $hasDefaultRoute) {
        foreach ($t in $PingTargets) {
            $ok = $false
            if ($tc) {
                if ($useTargetName) {
                    $ok = Test-Connection -TargetName $t -Count $Count -Quiet -ErrorAction SilentlyContinue
                } elseif ($useComputerName) {
                    $ok = Test-Connection -ComputerName $t -Count $Count -Quiet -ErrorAction SilentlyContinue
                }
            }

            if ($ok -eq $true) {
                $anyPingOk = $true
                Write-Host ("- {0}: OK" -f $t) -ForegroundColor Green
            } else {
                Write-Host ("- {0}: FALHA" -f $t) -ForegroundColor Red
            }
        }
    } else {
        Write-Host "Pulando ping IPv6: não há IPv6 global + rota default (em interface física)." -ForegroundColor Yellow
    }

    $internetIPv6Ok = ($ipv6Enabled -and $hasGlobal -and $hasDefaultRoute -and $anyPingOk)

    Write-Host ""
    Write-Host "=== RESULTADO ===" -ForegroundColor Cyan

    if (-not $ipv6Enabled) {
        Write-Host "Você não tem IPV6 Habilitado, verifique seu computador!" -ForegroundColor Red
        pause
        return
    }

    if ($internetIPv6Ok -and $globalIP) {
        Write-Host ("Você tem IPV6 ele é: {0}" -f $globalIP) -ForegroundColor Green
        pause
        return
    }

    # Habilitado, mas sem IPv6 de internet (global/rota/ping)
    # Se só tiver IPv6 virtual ou só fe80/ULA, cai aqui também.
    if (-not $hasGlobal) {
        Write-Host "Você tem IPV6 no Windows, mas não recebeu nada! Verifique seu roteador ou fale com seu provedor de internet!" -ForegroundColor Red
        pause
        return
    }

    Write-Host "Você tem IPV6 habilitado, mas não recebeu nada! Verifique seu roteador ou fale com seu provedor de internet!" -ForegroundColor Red
    pause
}

#VAI DESABILITAR MSSTORE
function Disable-WingetMsStoreSource {
    [CmdletBinding()]
    param(
        [switch]$Quiet
    )

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { throw "winget não encontrado (App Installer ausente ou alias desativado)." }

    # Em alguns builds o comando pode variar, então protegemos com try/catch
    $src = $null
    try {
        $src = & $winget.Source source list 2>$null
    } catch {
        $src = $null
    }

    if (-not $src) {
        if (-not $Quiet) {
            Write-Host "Não consegui ler 'winget source list'. Pulando ajuste do msstore." -ForegroundColor Yellow
        }
        return
    }

    $text = ($src -join "`n")

    # Se nem existe, nada a fazer
    if ($text -notmatch '(?im)^\s*msstore\b') {
        if (-not $Quiet) {
            Write-Host "Source msstore não existe nesta máquina. OK." -ForegroundColor DarkGray
        }
        return
    }

    # Heurística: se estiver disabled/desabilitado, não mexe
    if ($text -match '(?im)^\s*msstore\b.*\b(disabled|desabilitado)\b') {
        if (-not $Quiet) {
            Write-Host "Source msstore já está desabilitada. OK." -ForegroundColor DarkGray
        }
        return
    }

    # Tenta desabilitar
    if (-not $Quiet) {
        Write-Host "Desabilitando source msstore (evita erro de certificado)..." -ForegroundColor Cyan
    }

    try {
        & $winget.Source source disable msstore | Out-Null
        if (-not $Quiet) {
            Write-Host "msstore desabilitado." -ForegroundColor Green
        }
    } catch {
        if (-not $Quiet) {
            Write-Host ("Falha ao desabilitar msstore: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}
Disable-WingetMsStoreSource -Quiet

#VAI EXECUTAR WINGET QUANDO ACIONADO
function Invoke-Winget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Args,
        [string]$SuccessName,
        [switch]$VerboseOutput
    )

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { throw "winget não encontrado (App Installer ausente ou alias desativado)." }

    $pkgName = if ([string]::IsNullOrWhiteSpace($SuccessName)) { 'Pacote' } else { $SuccessName.Trim() }

    # Sempre evitar msstore: força --source winget se não existir
    if (-not ($Args -contains '--source')) {
        $Args = $Args + @('--source','winget')
    }

    # Executa e captura tudo, mas só mostra se der erro ou se -VerboseOutput
    $outputLines = & $winget.Source @Args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($outputLines -join "`n")

    if ($VerboseOutput) {
        Write-Host ""
        Write-Host ("winget {0}" -f ($Args -join ' ')) -ForegroundColor DarkGray
        Write-Host ""
        if ($outputLines) { $outputLines | ForEach-Object { Write-Host $_ } }
    }

    function Ok([string]$msg, [string]$color='Green') {
        Write-Host ""
        Write-Host ("✅ {0}" -f $msg) -ForegroundColor $color
    }
    function Warn([string]$msg) {
        Write-Host ""
        Write-Host ("⚠️  {0}" -f $msg) -ForegroundColor Yellow
    }

    # Exit 0 = ok
    if ($exitCode -eq 0) {
        if ($text -match 'Found an existing package already installed') {
            Warn ("{0}: já estava instalado." -f $pkgName)
        } elseif ($text -match 'Successfully installed|Installed successfully|Installation successful') {
            Ok ("{0}: instalado com sucesso." -f $pkgName)
        } else {
            Ok ("{0}: concluído." -f $pkgName)
        }
        return
    }

    # “Sem upgrade / não aplicável” (winget retorna !=0 mesmo sendo ok)
    $NO_APPLICABLE_UPDATE = @(-1978335189, -1978335188) # 0x8A15002B/0x8A15002C
    if ($NO_APPLICABLE_UPDATE -contains $exitCode) {
        if ($text -match 'Found an existing package already installed') {
            Warn ("{0}: já instalado e sem atualização disponível." -f $pkgName)
        } else {
            Warn ("{0}: nenhuma atualização disponível." -f $pkgName)
        }
        return
    }

    # 3010 = reboot necessário (considera sucesso)
    if ($exitCode -eq 3010) {
        Warn ("{0}: instalado, mas é necessário reiniciar." -f $pkgName)
        return
    }

    # Se chegou aqui: erro real -> mostra detalhes
    Write-Host ""
    Write-Host ("❌ {0}: falhou (exitcode={1})" -f $pkgName, $exitCode) -ForegroundColor Red
    if ($outputLines) {
        Write-Host ""
        $outputLines | ForEach-Object { Write-Host $_ }
    }
    throw ("winget falhou (exitcode={0})." -f $exitCode)
}

#VAI CHECAR O TRIM DO SSD NO WINDOWS
function Get-TrimStatus {
    [CmdletBinding()]
    param()

    $out = & fsutil behavior query DisableDeleteNotify 2>&1
    $txt = ($out | Out-String)

    # Interpretação:
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
        Write-Host "=== TRIM (SSD) ===" -ForegroundColor Cyan
        Write-Host $s.Raw
        Write-Host ""
        Write-Host "Obs: DisableDeleteNotify=0 => TRIM habilitado | 1 => TRIM desabilitado" -ForegroundColor DarkGray
        Write-Host ""
    }

    # Se não conseguiu parsear nada, só informa
    if ($s.NTFS_DisableDeleteNotify -eq $null -and $s.ReFS_DisableDeleteNotify -eq $null) {
        Write-Host "Não consegui determinar o status do TRIM neste sistema." -ForegroundColor Yellow
        pause
        return
    }

    $ntfsOk = ($s.TrimEnabled_NTFS -eq $true) -or ($s.TrimEnabled_NTFS -eq $null) # se não existir NTFS no output, ignora
    $refsOk = ($s.TrimEnabled_ReFS -eq $true) -or ($s.TrimEnabled_ReFS -eq $null)

    if ($ntfsOk -and $refsOk) {
        Write-Host "✅ TRIM já está habilitado." -ForegroundColor Green
        pause
        return
    }

    # TRIM desabilitado (ou parcial)
    Write-Host "⚠️  TRIM não está habilitado para todos os sistemas de arquivos (NTFS/ReFS)." -ForegroundColor Yellow

    $want = Read-YesNoKey -Prompt "Deseja habilitar TRIM agora? [S/N]: "
    if (-not $want) {
        Write-Host "OK. Mantendo TRIM como está." -ForegroundColor DarkGray
        pause
        return
    }

    Enable-Trim

    $s2 = Get-TrimStatus
    Write-Host ""
    Write-Host "Status após tentativa:" -ForegroundColor Cyan
    Write-Host $s2.Raw
    Write-Host ""

    $ntfsOk2 = ($s2.TrimEnabled_NTFS -eq $true) -or ($s2.TrimEnabled_NTFS -eq $null)
    $refsOk2 = ($s2.TrimEnabled_ReFS -eq $true) -or ($s2.TrimEnabled_ReFS -eq $null)

    if ($ntfsOk2 -and $refsOk2) {
        Write-Host "✅ TRIM habilitado com sucesso." -ForegroundColor Green
    } else {
        Write-Host "❌ Não consegui habilitar TRIM completamente. Verifique permissões/políticas do sistema." -ForegroundColor Red
    }
    pause
}

#VAI DESABILITAR ECONOMIA
function Set-WorkstationPowerProfile {
    <#
    .SYNOPSIS
        Ajusta configurações de energia no Windows (PowerShell 5.1):
        - Desabilita hibernação
        - Ativa plano "Alto desempenho" (ou cria se não existir)
        - Define para NÃO desligar o monitor (AC) após 15 minutos (0 = nunca)

    .NOTES
        Requer privilégios de administrador para desabilitar hibernação e criar/alterar planos.
        Usa powercfg (nativo do Windows).
    #>

    [CmdletBinding()]
    param(
        [int]$MonitorTimeoutACMinutes = 15
    )

    Write-Host "== Aplicando perfil de energia =="

    # 1) Desabilitar hibernação
    Write-Host "`n[1/3] Hibernação"
    try {
        $hib = (powercfg /a) 2>&1
        if ($hib -match "Hibernação" -and $hib -match "dispon") {
            Write-Host " - Hibernação parece estar disponível. Tentando desabilitar..."
        } else {
            Write-Host " - Não foi possível confirmar disponibilidade da hibernação via 'powercfg /a'. Mesmo assim, vou aplicar o comando de desativação."
        }

        powercfg /h off | Out-Null
        Write-Host " - Hibernação desabilitada (powercfg /h off)."
    }
    catch {
        Write-Host " - Falha ao desabilitar hibernação: $($_.Exception.Message)"
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
            Write-Host " - Plano 'Alto desempenho' não encontrado. Vou tentar criar a partir do modelo conhecido..."
            # duplica a partir do GUID bem conhecido
            $dupOut = (powercfg -duplicatescheme $HighPerfWellKnownGuid) 2>&1

            # Saída costuma conter um GUID; vamos extrair
            if ($dupOut -match "([0-9a-fA-F\-]{36})") {
                $highPerfGuid = $matches[1]
                Write-Host " - Plano criado com sucesso: $highPerfGuid"
            } else {
                Write-Host " - Não consegui extrair o GUID do plano criado. Saída: $dupOut"
            }
        }

        if ($highPerfGuid) {
            Write-Host " - Ativando plano 'Alto desempenho'..."
            powercfg /setactive $highPerfGuid | Out-Null
            Write-Host " - Plano ativo definido para: $highPerfGuid"
        } else {
            Write-Host " - Não foi possível localizar/criar o plano 'Alto desempenho'."
        }
    }
    catch {
        Write-Host " - Falha ao configurar plano de energia: $($_.Exception.Message)"
    }

    # 3) Desabilitar desligamento do monitor após 15 min (na prática: 0 = nunca) no modo AC
    Write-Host "`n[3/3] Monitor (modo ligado na tomada / AC)"

    try {
        if ($MonitorTimeoutACMinutes -lt 0) {
            Write-Host " - Valor inválido ($MonitorTimeoutACMinutes). Ajuste ignorado."
        } else {
            # Observação: no powercfg, timeout de display em AC usa /x -monitor-timeout-ac <minutos>
            # Para "desabilitar desligar monitor após 15 minutos", o correto é 0 (nunca).
            if ($MonitorTimeoutACMinutes -eq 0) {
                Write-Host " - Configurando monitor para NUNCA desligar (AC)..."
            } else {
                Write-Host " - Você pediu para 'desabilitar desligar monitor após 15 minutos'. Isso normalmente significa: NÃO desligar nunca (0)."
                Write-Host " - Mesmo assim, vou aplicar o valor informado para timeout AC: $MonitorTimeoutACMinutes minuto(s)."
            }

            powercfg /x -monitor-timeout-ac $MonitorTimeoutACMinutes | Out-Null
            Write-Host " - Timeout do monitor em AC aplicado: $MonitorTimeoutACMinutes minuto(s). (0 = nunca)"
        }
    }
    catch {
        Write-Host " - Falha ao configurar timeout do monitor: $($_.Exception.Message)"
    }

    Write-Host "`n== Concluído =="
    pause
}

#VAI INSTALAR VSC AIO
function Install-LatestVcRedistFromGitHub {
    [CmdletBinding()]
    param(
        [switch]$IncludePrerelease,
        [string]$DownloadDir = "",
        [string[]]$InstallerArgs = $null,     # ex: @("/quiet","/norestart") se você souber que funciona
        [string]$GitHubToken = ""             # opcional (evita rate limit)
    )

    Write-Host "== VC Redist (abbodi1406/vcredist) - baixar e instalar =="

    function Enable-Tls12 {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    }

    function Get-DownloadsFolder {
        $guid = "{374DE290-123F-4565-9164-39C4925E467B}" # Downloads
        $k = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        try {
            $p = (Get-ItemProperty -Path $k -Name $guid -ErrorAction Stop).$guid
            if ($p) { return (Resolve-Path -Path $p).Path }
        } catch {}
        return (Join-Path $env:USERPROFILE "Downloads")
    }

    function Download-FileWithProgress {
        param(
            [Parameter(Mandatory=$true)][string]$Url,
            [Parameter(Mandatory=$true)][string]$OutFile,
            [System.Net.CookieContainer]$Cookies = $null,
            [hashtable]$Headers = $null
        )

        Enable-Tls12

        $outDir = Split-Path -Path $OutFile -Parent
        if (-not (Test-Path -LiteralPath $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }

        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $req.AllowAutoRedirect = $true
        $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/5.1"
        $req.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
        $req.Timeout = 300000
        $req.ReadWriteTimeout = 300000

        if ($Cookies) { $req.CookieContainer = $Cookies }
        if ($Headers) {
            foreach ($k in $Headers.Keys) { $req.Headers[$k] = $Headers[$k] }
        }

        $resp = $null
        $stream = $null
        $fileStream = $null
        try {
            $resp = $req.GetResponse()
            $totalLength = $resp.ContentLength
            $stream = $resp.GetResponseStream()
            $fileStream = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

            $buffer = New-Object byte[] 8192
            $totalRead = 0L
            $lastUpdate = [datetime]::Now

            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $fileStream.Write($buffer, 0, $read)
                $totalRead += $read

                if (([datetime]::Now - $lastUpdate).TotalMilliseconds -ge 500) {
                    $lastUpdate = [datetime]::Now
                    if ($totalLength -gt 0) {
                        $percent = [math]::Floor(($totalRead / $totalLength) * 100)
                        $barLength = 30
                        $filledLength = [math]::Floor(($percent / 100) * $barLength)
                        $bar = ("#" * $filledLength).PadRight($barLength, "-")
                        $downloadedMB = [math]::Round($totalRead / 1MB, 2)
                        $totalMB = [math]::Round($totalLength / 1MB, 2)
                        Write-Host ("`r[{0}] {1}% ({2}MB / {3}MB)" -f $bar, $percent, $downloadedMB, $totalMB) -ForegroundColor Magenta -NoNewline
                    } else {
                        $downloadedMB = [math]::Round($totalRead / 1MB, 2)
                        Write-Host ("`rBaixando... {0}MB" -f $downloadedMB) -ForegroundColor Magenta -NoNewline
                    }
                }
            }
            Write-Host ""
        }
        finally {
            if ($fileStream) { $fileStream.Close() }
            if ($stream) { $stream.Close() }
            if ($resp) { try { $resp.Close() } catch {} }
        }
    }

    # Diretório de download
    if (-not $DownloadDir) { $DownloadDir = Get-DownloadsFolder }
    if (-not (Test-Path -LiteralPath $DownloadDir)) {
        New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
    }

    # GitHub API
    Enable-Tls12
    $owner = "abbodi1406"
    $repo  = "vcredist"

    $headers = @{
        "Accept"     = "application/vnd.github+json"
        "User-Agent" = "PowerShell-5.1"
    }
    if ($GitHubToken) {
        $headers["Authorization"] = "Bearer $GitHubToken"
        $headers["X-GitHub-Api-Version"] = "2022-11-28"
    }

    Write-Host "`n[1/3] Buscando release mais recente..."
    try {
        if ($IncludePrerelease) {
            $releasesUrl = "https://api.github.com/repos/$owner/$repo/releases?per_page=20"
            $rels = Invoke-RestMethod -Headers $headers -Uri $releasesUrl -Method GET -ErrorAction Stop
            # escolhe o mais recente por published_at (inclui prerelease)
            $rel = $rels | Sort-Object { [datetime]$_.published_at } -Descending | Select-Object -First 1
        } else {
            $latestUrl = "https://api.github.com/repos/$owner/$repo/releases/latest"
            $rel = Invoke-RestMethod -Headers $headers -Uri $latestUrl -Method GET -ErrorAction Stop
        }
    } catch {
        Write-Host " - Falha ao consultar GitHub API: $($_.Exception.Message)"
        Write-Host " - Dica: tente fornecer -GitHubToken se estiver em rate limit."
        return
    }

    if (-not $rel) {
        Write-Host " - Não encontrei release."
        return
    }

    $tag = $rel.tag_name
    $name = $rel.name
    $date = $rel.published_at
    Write-Host " - Release: $name"
    Write-Host " - Tag: $tag"
    Write-Host " - Publicado: $date"

    # Filtra assets relevantes
    $assets = @($rel.assets | Where-Object {
        $_.name -match "\.(exe|msi|zip)$"
    })

    if (-not $assets -or $assets.Count -eq 0) {
        Write-Host " - Este release não tem assets .exe/.msi/.zip."
        return
    }

    Write-Host "`n[2/3] Opções de download:"
    for ($i=0; $i -lt $assets.Count; $i++) {
        $a = $assets[$i]
        $sizeMB = [math]::Round(($a.size / 1MB), 2)
        Write-Host (" [{0}] {1}  ({2} MB)" -f ($i+1), $a.name, $sizeMB)
    }

    $choice = Read-Host "Selecione o número para baixar/instalar"
    if (-not ($choice -match "^\d+$")) {
        Write-Host " - Entrada inválida."
        return
    }
    $idx = [int]$choice - 1
    if ($idx -lt 0 -or $idx -ge $assets.Count) {
        Write-Host " - Opção fora do intervalo."
        return
    }

    $selected = $assets[$idx]
    $assetName = $selected.name
    $downloadUrl = $selected.browser_download_url

    $outFile = Join-Path $DownloadDir $assetName

    Write-Host "`n[3/3] Baixando e instalando..."
    Write-Host " - Arquivo: $assetName"
    Write-Host " - Destino: $outFile"

    if ((Test-Path -LiteralPath $outFile)) {
        Write-Host " - Arquivo já existe."
        $ans = Read-Host "Deseja baixar novamente? (S/N)"
        if ($ans -notin @("S","s","Y","y")) {
            Write-Host " - Reutilizando arquivo existente."
        } else {
            Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not (Test-Path -LiteralPath $outFile)) {
        try {
            Download-FileWithProgress -Url $downloadUrl -OutFile $outFile
            Write-Host " - Download concluído."
        } catch {
            Write-Host " - Falha no download: $($_.Exception.Message)"
            return
        }
    }

    # Hash + Assinatura
    try {
        $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $outFile).Hash
        Write-Host " - SHA256: $sha"
    } catch {
        Write-Host " - Não consegui calcular SHA256: $($_.Exception.Message)"
    }

    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $outFile
        Write-Host (" - Assinatura: {0}" -f $sig.Status)
        if ($sig.SignerCertificate) {
            Write-Host (" - Assinado por: {0}" -f $sig.SignerCertificate.Subject)
        }
    } catch {
        Write-Host " - Não consegui validar assinatura: $($_.Exception.Message)"
    }

    # Executar instalador (somente se for .exe/.msi)
    $ext = [IO.Path]::GetExtension($outFile).ToLowerInvariant()
    if ($ext -notin @(".exe",".msi")) {
        Write-Host " - Arquivo não é .exe/.msi (é $ext). Baixei, mas não vou executar automaticamente."
        return
    }

    Write-Host " - Executando instalador..."
    try {
        if ($InstallerArgs -and $InstallerArgs.Count -gt 0) {
            Start-Process -FilePath $outFile -ArgumentList $InstallerArgs -ErrorAction Stop | Out-Null
        } else {
            Start-Process -FilePath $outFile -ErrorAction Stop | Out-Null
        }
        Write-Host " - Finalizado."
    } catch {
        Write-Host " - Falha ao executar instalador: $($_.Exception.Message)"
        return
    }
}

#VAI INSTALAR OPERAGX
function Install-OperaGXSetup {
  # URLs ficam dentro da própria function
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

  # 1) já instalado?
  if (& $InstalledTest) {
    Write-Host "Opera GX já está instalado." -ForegroundColor Green
    return
  }

  # 2) só baixa se não existir
  Write-Host "[Baixando e instalando OperaGX...]" -ForegroundColor Yellow

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
  Write-Host "Todos os servidores estão fora, sem internet, ou o arquivo baixado é inválido (OperaGX)." -ForegroundColor Red
  return
}

  # 3) executa instalador
  Start-Process -FilePath $dst -ArgumentList '/silent /allusers=1 /launchopera=0 /setdefaultbrowser=0' -Verb RunAs
  Write-Host "[OK]" -ForegroundColor Green
}

#VAI INSTALAR HOYOPLAY
function Install-HoYoPlay {
  # URLs dentro da própria function
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

  # 1) já instalado?
  if (& $InstalledTest) {
    Write-Host "HoYoPlay já está instalado." -ForegroundColor Green
    return
  }

  # 2) só baixa se não existir
  if (-not (Test-Path $dst)) {
    Write-Host "[Baixando e instalando HoYoPlay...]" -ForegroundColor Yellow

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
      Write-Host "Todos os servidores estão fora ou sem internet." -ForegroundColor Red
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

  # 1) já instalado?
  if (& $InstalledTest) {
    Write-Host "Riot Client já está instalado." -ForegroundColor Green
    return
  }

  # 2) só baixa se não existir
  if (-not (Test-Path $dst)) {
    Write-Host "[Baixando e instalando Riot Client...]" -ForegroundColor Yellow

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
      Write-Host "Todos os servidores estão fora ou sem internet." -ForegroundColor Red
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
    Write-Host "Epic Games Launcher já está instalado." -ForegroundColor Green
    return
  }

  if (-not (Test-Path $dst)) {
    Write-Host "[Baixando e instalando Epic Games Launcher...]" -ForegroundColor Yellow

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
      Write-Host "Todos os servidores estão fora ou sem internet." -ForegroundColor Red
      return
    }
  }

  Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$dst`" /qn /norestart"
  Write-Host "[OK]" -ForegroundColor Green
}

#VAI INSTALAR OS ESSENTIALS
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
        default { Write-Host "Opção inválida." ; return }
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
            SilentArgs = @()       # não usar silent
            NoSilent   = $true     # força normal
            Special    = ""        # não precisa
        }
    }

    if ($IncludeOperaGX) {
        # Opera GX: URL dinâmica via FTP oficial (mais recente)
        $apps += @{
            Name="Opera GX"
            Detect=@("Opera GX","OperaGX","Opera GX Browser")
            Urls=@() # não usado (dinâmico)
            File="OperaGXSetup.exe"
            MinMB=30
            SilentArgs=@("/silent","/norestart") # tentamos, mas pode variar
            NoSilent=$false
            Special="OPERA_GX_FTP"
            FtpBase="https://get.opera.com/ftp/pub/opera_gx/"
        }
    }

    ($apps | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $appsJson -Encoding UTF8

    # Aviso na tela principal (pedido do usuário)
    Write-Host "== Instalações em segundo plano (sem winget) =="
    Write-Host "Será instalado nesta rodada:"
    foreach ($a in $apps) { Write-Host (" - {0}" -f $a.Name) }
    Write-Host ""
    Write-Host "Abrirei uma NOVA janela do PowerShell para acompanhar o passo a passo."
    Write-Host ("Downloads/cópias: {0}" -f $downloadDir)
    Write-Host ("Log: {0}" -f $logPath)
    Write-Host "Seu script principal continuará executando."
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
          Write-Host ("`r[{0}] {1}% ({2}MB / {3}MB)" -f $bar,$pct,$mb,$mbt) -ForegroundColor Magenta -NoNewline
        } else {
          $mb = [math]::Round($readTotal/1MB,2)
          Write-Host ("`rBaixando... {0}MB" -f $mb) -ForegroundColor Magenta -NoNewline
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
  Step " - Opera GX: buscando versão mais recente no FTP..."
  Step (" - Base: {0}" -f $FtpBase)

  # 1) listar diretórios de versão
  $html = ""
  try {
    $r = Invoke-WebRequest -Uri $FtpBase -UseBasicParsing -ErrorAction Stop
    $html = $r.Content
  } catch {
    Step (" - Falha ao ler índice FTP: {0}" -f $_.Exception.Message)
    return $null
  }

  $matches = [regex]::Matches($html, 'href="(\d+\.\d+\.\d+\.\d+)/"', 'IgnoreCase')
  if (-not $matches -or $matches.Count -eq 0) {
    Step " - Não achei diretórios de versão no índice."
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

  Step (" - Versão selecionada: {0}" -f $best)

  # 2) listar /win/
  $winUrl = ($FtpBase.TrimEnd('/') + "/" + $best + "/win/")
  Step (" - Lendo: {0}" -f $winUrl)

  $html2 = ""
  try {
    $r2 = Invoke-WebRequest -Uri $winUrl -UseBasicParsing -ErrorAction Stop
    $html2 = $r2.Content
  } catch {
    Step (" - Falha ao ler índice win/: {0}" -f $_.Exception.Message)
    return $null
  }

  $is64 = [Environment]::Is64BitOperatingSystem
  $pattern = if ($is64) { 'href="(Opera_GX_[^"]+_Setup_x64\.exe)"' } else { 'href="(Opera_GX_[^"]+_Setup\.exe)"' }

  $m2 = [regex]::Match($html2, $pattern, 'IgnoreCase')
  if (-not $m2.Success -and $is64) {
    # fallback para Setup.exe se não achar x64
    $m2 = [regex]::Match($html2, 'href="(Opera_GX_[^"]+_Setup\.exe)"', 'IgnoreCase')
  }
  if (-not $m2.Success) {
    Step " - Não achei o Setup no índice win/."
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
    Step (" - Já instalado: {0} (versão: {1}). Pulando." -f $det.Name, $det.Version)
    continue
  }
  if ($det.Installed -and $Reinstall) {
    Step " - Detectado instalado, mas Reinstall foi solicitado. Vou reinstalar."
  } else {
    Step " - Não detectei instalado. Vou instalar."
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
        Step (" - AVISO: menor que {0} MB. Tentando próxima URL..." -f $minMB)
        Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        continue
      }

      if (-not (Test-ExeOrMsiSignature -Path $outFile)) {
        Step " - AVISO: assinatura de arquivo não parece EXE/MSI válido. Tentando próxima URL..."
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
          Step " - curl baixou algo inválido/pequeno. Vou abortar este app."
          Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        }
      } else {
        Step " - curl não disponível ou falhou."
      }
    }
  }

  if (-not $downloaded) {
    Step " - Não consegui baixar o instalador. Pulando este app."
    continue
  }

  # Copiar instalador para Downloads (para auditoria do usuário)
  try {
    $userCopy = Join-Path $DownloadDir $file
    Copy-Item -LiteralPath $outFile -Destination $userCopy -Force
    Step (" - Cópia em Downloads: {0}" -f $userCopy)
  } catch {
    Step (" - Não consegui copiar para Downloads: {0}" -f $_.Exception.Message)
  }

  # IF: executar instalação (Chrome: normal)
  $ext = [IO.Path]::GetExtension($outFile).ToLowerInvariant()
  Step (" - Executando instalador ({0})..." -f $ext)

  try {
    if ($ext -eq ".msi") {
      if ($special -eq "MSI_NORMAL" -or $noSilent) {
        Step " - MSI: instalação NORMAL (sem silent)."
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

  # checagem pós (best effort)
  $det2 = Get-InstalledByRegistry -Needles $needles
  if ($det2.Installed) {
    Step (" - Concluído: detectado instalado: {0} (versão: {1})" -f $det2.Name, $det2.Version)
  } else {
    Step " - Finalizado, mas não confirmei no Registro (pode ter instalado por outro escopo, ou requer reboot)."
  }
}

Write-Host ""
Step "== Fim das instalações =="
try { Stop-Transcript | Out-Null } catch {}
Write-Host ""
Write-Host "Pressione qualquer tecla para fechar esta janela..." -ForegroundColor Yellow
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

    # Nova janela (não bloqueia)
    return (Start-Process -FilePath "powershell.exe" -ArgumentList $argList -PassThru)
}

#VAI CORRIGIR O HORARIO DO WINDOWS
function Fix-TimeAndNtp {
    [CmdletBinding()]
    param(
        [string]$NtpServer = '201.49.148.135',
        [string]$TimeZoneId = 'E. South America Standard Time',
        [int]$PollIntervalSeconds = 3600,
        [switch]$UpdateInternetTimeUi = $true
    )

    Write-Host ""
    Write-Host "=== CORRIGIR HORÁRIO (FUSO + NTP) ===" -ForegroundColor Cyan

    # Admin?
    $isAdmin = $false
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        $isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { $isAdmin = $false }
    if (-not $isAdmin) { throw "Execute em modo Administrador." }

    # 1) Fuso
    $beforeTz = Get-TimeZone
    Write-Host ("Fuso atual: {0} (UTC{1})" -f $beforeTz.Id, $beforeTz.BaseUtcOffset) -ForegroundColor DarkGray
    if ($beforeTz.Id -ne $TimeZoneId) {
        Write-Host ("Ajustando fuso para: {0}" -f $TimeZoneId) -ForegroundColor Cyan
        try { Set-TimeZone -Id $TimeZoneId -ErrorAction Stop } catch { & tzutil.exe /s $TimeZoneId | Out-Null }
    }

    function Repair-And-StartW32Time {
        Write-Host ""
        Write-Host "Reparando/ativando W32Time..." -ForegroundColor Cyan

        $svcKey   = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time'
        $paramKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
        $dllKey   = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
        $svchost  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'

        New-Item -Path $svcKey   -Force | Out-Null
        New-Item -Path $paramKey -Force | Out-Null

        # Defaults seguros do serviço (não “inventam” muito)
        try { Set-ItemProperty $svcKey -Name Start       -Type DWord -Value 2 -ErrorAction Stop } catch {}
        try { Set-ItemProperty $svcKey -Name Type        -Type DWord -Value 32 -ErrorAction Stop } catch {}   # SERVICE_WIN32_SHARE_PROCESS
        try { Set-ItemProperty $svcKey -Name ErrorControl -Type DWord -Value 1 -ErrorAction Stop } catch {}
        try { Set-ItemProperty $svcKey -Name ObjectName  -Value 'NT AUTHORITY\LocalService' -ErrorAction Stop } catch {}

        # ImagePath: mantém se existir; se não existir, coloca padrão comum
        $img = $null
        try { $img = (Get-ItemProperty $svcKey -Name ImagePath -ErrorAction Stop).ImagePath } catch {}
        if (-not $img) {
            $img = '%SystemRoot%\System32\svchost.exe -k LocalService -p'
            try { Set-ItemProperty $svcKey -Name ImagePath -Value $img -ErrorAction Stop } catch {}
        }

        # ServiceDll
        try {
            if (-not (Get-ItemProperty $dllKey -Name ServiceDll -ErrorAction SilentlyContinue)) {
                New-ItemProperty -Path $dllKey -Name ServiceDll -PropertyType ExpandString -Value '%SystemRoot%\System32\w32time.dll' -Force | Out-Null
            }
        } catch {}

        # Garantir que W32Time está no grupo svchost correto (-k <Grupo>)
        $group = 'LocalService'
        if ($img -match '-k\s+([^\s]+)') { $group = $Matches[1] }

        try {
            $grpVal = (Get-ItemProperty -Path $svchost -Name $group -ErrorAction SilentlyContinue).$group
            if (-not $grpVal) {
                # cria o grupo mínimo (se o grupo não existe)
                New-ItemProperty -Path $svchost -Name $group -PropertyType MultiString -Value @('W32Time') -Force | Out-Null
            } else {
                if ($grpVal -notcontains 'W32Time') {
                    $new = @($grpVal) + @('W32Time')
                    Set-ItemProperty -Path $svchost -Name $group -Value $new -ErrorAction SilentlyContinue
                }
            }
        } catch {}

        # Ajuste via sc (redundância)
        & sc.exe config w32time start= auto | Out-Null

        # re-register (muito comum resolver serviço quebrado)
        & w32tm /unregister | Out-Null
        Start-Sleep -Seconds 1
        & w32tm /register   | Out-Null
        Start-Sleep -Seconds 1

        # start
        & sc.exe start w32time | Out-Host
        Start-Sleep -Seconds 1

        $svc = Get-Service w32time -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -ne 'Running') {
            Write-Host ""
            Write-Host "W32Time NÃO iniciou. Diagnóstico:" -ForegroundColor Red
            & sc.exe query w32time | Out-Host
            & sc.exe qc w32time | Out-Host

            Write-Host ""
            Write-Host "Eventos recentes do Service Control Manager (pode indicar motivo):" -ForegroundColor Yellow
            try {
                Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} -MaxEvents 25 |
                    Where-Object { $_.Message -match 'W32Time|Windows Time' } |
                    Select-Object TimeCreated, Id, LevelDisplayName, Message |
                    Format-List | Out-Host
            } catch {}

            throw "Não dá para configurar NTP enquanto o serviço W32Time não iniciar."
        }
    }

    # 2) Garante W32Time rodando
    Repair-And-StartW32Time

    # 3) Configura NTP manual (W32Time)
    $peer = "$NtpServer,0x9"  # special poll + client

    Write-Host ""
    Write-Host ("Configurando NTP manual: {0}" -f $peer) -ForegroundColor Cyan

    $pParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    $pNtpCli = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'
    New-Item -Path $pParams -Force | Out-Null
    New-Item -Path $pNtpCli -Force | Out-Null

    Set-ItemProperty -Path $pParams -Name Type      -Value 'NTP' -ErrorAction Stop
    Set-ItemProperty -Path $pParams -Name NtpServer -Value $peer -ErrorAction Stop
    Set-ItemProperty -Path $pNtpCli -Name Enabled             -Type DWord -Value 1 -ErrorAction Stop
    Set-ItemProperty -Path $pNtpCli -Name SpecialPollInterval -Type DWord -Value $PollIntervalSeconds -ErrorAction Stop

    & w32tm /config /manualpeerlist:"$peer" /syncfromflags:manual /update | Out-Host

    # 4) Atualiza Internet Time UI (opcional)
    if ($UpdateInternetTimeUi) {
        Write-Host ""
        Write-Host "Atualizando lista do 'Internet Time' (UI)..." -ForegroundColor Cyan

        $subKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers'
        $rk = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($subKey)
        if ($rk) {
            $names = $rk.GetValueNames()
            $idx = $null

            foreach ($n in $names) {
                if ($n -match '^\d+$' -and ([string]$rk.GetValue($n,'')) -ieq $NtpServer) { $idx = [int]$n; break }
            }
            if ($null -eq $idx) {
                $max = 0
                foreach ($n in $names) { if ($n -match '^\d+$') { $i=[int]$n; if ($i -gt $max) { $max=$i } } }
                $idx = $max + 1
                $rk.SetValue("$idx", $NtpServer, [Microsoft.Win32.RegistryValueKind]::String)
            }

            $rk.SetValue('', "$idx", [Microsoft.Win32.RegistryValueKind]::String) # default
            $rk.Close()

            Write-Host ("Internet Time UI: índice {0} = {1}" -f $idx, $NtpServer) -ForegroundColor Green
            pause
        }
    }

    # 5) Reinicia e sincroniza
    Write-Host ""
    Write-Host "Reiniciando W32Time e forçando sync..." -ForegroundColor Cyan
    Restart-Service w32time -Force
    Start-Sleep -Seconds 1

    & w32tm /resync /force | Out-Host

    # 6) Verificações finais
    Write-Host ""
    Write-Host "Fonte atual (source):" -ForegroundColor Cyan
    & w32tm /query /source | Out-Host

    Write-Host ""
    Write-Host "Peers:" -ForegroundColor Cyan
    & w32tm /query /peers | Out-Host

    Write-Host ""
    Write-Host "Teste NTP (stripchart):" -ForegroundColor Cyan
    & w32tm /stripchart /computer:$NtpServer /samples:5 /dataonly | Out-Host

    Write-Host ""
    Write-Host "Obs: se o stripchart der 0x800705B4, é UDP 123 bloqueado ou servidor NTP não responde." -ForegroundColor Yellow
    pause
}

#VAI INSTALAR DRIVERS GPU/INTEGRADO
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

  # ações pré-selecionadas (usadas quando o worker relança em admin)
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
  if ($Host.Name -notmatch "ConsoleHost") { return $DefaultYes } # fallback não-interativo
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
      "não" { return $false }
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
      Write-Log "Arquivo baixado parece inválido. Tentando próximo..." "WARN"
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

  # também olha a GPU (ajuda bastante)
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

  # fallback: pelo driver provider também
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
    Write-Log "Não consegui ler Win32_PnPSignedDriver (DISPLAY). Vou seguir apenas com Win32_VideoController." "WARN"
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
    Write-Log "Detectado: Microsoft Basic Display Adapter (driver genérico). Normal quando driver do fabricante não está instalado." "WARN"
  } else {
    Write-Log "Não parece estar usando Microsoft Basic Display Adapter."
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
  Write-Host "Não consegui confirmar a instalação."
  Write-Host "Opções:"
  Write-Host "  [1] Tentar novamente agora"
  Write-Host "  [2] Reiniciar o computador (recomendado após drivers)"
  Write-Host "  [3] Sair"
  Write-Host ""

  if ($Host.Name -notmatch "ConsoleHost") {
    Write-Log "Host não interativo. Encerrando sem prompt." "WARN"
    return
  }

  $choice = Read-Host "Escolha (1/2/3)"
  switch ($choice) {
    "1" { & $RetryBlock }
    "2" {
      Write-Log "Reiniciando em 10 segundos (você pode cancelar fechando esta janela)..." "WARN"
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
    Write-Log ("NVIDIA App já instalado. Versão: {0}" -f (Get-NvidiaAppVersion))
    return $true
  }
  if ($DryRun) { Write-Log "DRY RUN: pulando instalação NVIDIA."; return $true }

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

  Write-Log "Não confirmei instalação silenciosa. Abrindo instalador interativo..." "WARN"
  Start-Process -FilePath $out | Out-Null
  Read-Host "Finalize o instalador e pressione ENTER aqui"
  return (Test-NvidiaAppInstalled)
}

function Install-AmdSoftware {
  Write-Log "AMD: instalar AMD Software: Adrenalin (Auto-Detect / Minimal Setup)."
  if (Test-AmdSoftwareInstalled) {
    Write-Log ("AMD Software já instalado. Versão: {0}" -f (Get-AmdSoftwareVersion))
    return $true
  }
  if ($DryRun) { Write-Log "DRY RUN: pulando instalação AMD."; return $true }

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
    Write-Log ("Intel DSA já instalado. Versão: {0}" -f (Get-IntelDsaVersion))
    return $true
  }
  if ($DryRun) { Write-Log "DRY RUN: pulando instalação Intel DSA."; return $true }

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

  Write-Log "Não confirmei instalação silenciosa. Abrindo instalador interativo..." "WARN"
  Start-Process -FilePath $out | Out-Null
  Read-Host "Finalize o instalador e pressione ENTER aqui"
  return (Test-IntelDsaInstalled)
}

function Install-VmwareTools {
  Write-Log "VMware: instalar VMware Tools."
  if (Test-VmwareToolsInstalled) {
    Write-Log ("VMware Tools já instalado. Versão: {0}" -f (Get-VmwareToolsVersion))
    return $true
  }
  if ($DryRun) { Write-Log "DRY RUN: pulando instalação VMware Tools."; return $true }

  # URL 'latest' oficial (diretório público)
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

  # status de apps (mesmo se não instalar)
  Write-Host ""
  Write-Log "=== STATUS DE SOFTWARE (se já existir) ==="
  if (Test-NvidiaAppInstalled) { Write-Log ("NVIDIA App: INSTALADO | Versão: {0}" -f (Get-NvidiaAppVersion)) } else { Write-Log "NVIDIA App: não instalado" }
  if (Test-AmdSoftwareInstalled) { Write-Log ("AMD Software: INSTALADO | Versão: {0}" -f (Get-AmdSoftwareVersion)) } else { Write-Log "AMD Software: não instalado" }
  if (Test-IntelDsaInstalled) { Write-Log ("Intel DSA: INSTALADO | Versão: {0}" -f (Get-IntelDsaVersion)) } else { Write-Log "Intel DSA: não instalado" }
  if ($vmType -eq "VMware") {
    if (Test-VmwareToolsInstalled) { Write-Log ("VMware Tools: INSTALADO | Versão: {0}" -f (Get-VmwareToolsVersion)) } else { Write-Log "VMware Tools: não instalado" }
  }

  # Se já vier com ações definidas (segunda execução, elevada), não pergunta de novo
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
          Write-Log "VirtualBox detectado. O recomendado é instalar 'Guest Additions' dentro da VM (menu Devices -> Insert Guest Additions CD image)." "WARN"
          if (Ask-YesNo "Deseja abrir a página oficial de downloads do VirtualBox agora?" ($true)) {
            Start-Process "https://www.virtualbox.org/wiki/Downloads" | Out-Null
          }
        }
        "Hyper-V" {
          Write-Log "Hyper-V detectado. Normalmente os drivers/integration vêm via Windows Update no guest. Vou abrir a referência oficial." "WARN"
          if (Ask-YesNo "Abrir referência oficial (Integration Components)?" ($true)) {
            Start-Process "https://support.microsoft.com/pt-br/topic/atualiza%C3%A7%C3%A3o-de-componentes-de-integra%C3%A7%C3%A3o-hyper-v-para-m%C3%A1quinas-virtuais-windows-8a74ffad-576e-d5a0-5a2f-d6fb2594f990" | Out-Null
          }
        }
        "KVM/QEMU" {
          Write-Log "KVM/QEMU detectado. Em geral, o caminho é VirtIO (especialmente Proxmox/QEMU)." "WARN"
          if (Ask-YesNo "Abrir referência VirtIO drivers?" ($true)) {
            Start-Process "https://pve.proxmox.com/wiki/Windows_VirtIO_Drivers" | Out-Null
          }
        }
      }
    }

    # 2) Se não for VM (ou se for VM VMware com passthrough, ainda pode aparecer NVIDIA/AMD/Intel) – perguntar por vendor
    $vendors = Normalize-VendorsPresent $inv
    $basic = Test-UsingBasicDisplayAdapter $inv
    $cpuVendor = Get-CpuVendor

    Write-Host ""
    Write-Log ("Vendors detectados (GPU/driver): {0}" -f (if ($vendors.Count) { $vendors -join ", " } else { "(nenhum)" }))
    Write-Log ("CPU Vendor: {0}" -f $cpuVendor)

    if ($vendors.Count -eq 0) {
      # fallback: gráfico integrado
      Write-Log "Nenhum vendor claro detectado. Vou seguir pelo CPU (gráfico integrado)." "WARN"
      if ($cpuVendor -eq "AMD") {
        $DoAmd = Ask-YesNo "Deseja instalar/atualizar AMD Auto-Detect (Adrenalin) para gráfico integrado?" ($basic)
      } elseif ($cpuVendor -eq "INTEL") {
        $DoIntel = Ask-YesNo "Deseja instalar/atualizar Intel DSA para gráfico integrado Intel?" ($basic)
      } else {
        $DoIntel = Ask-YesNo "CPU desconhecida. Deseja tentar Intel DSA (fallback)?" ($basic)
      }
    } else {
      # Para cada vendor encontrado, perguntar (mesmo se já tiver driver)
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

      # Em notebooks híbridos (Intel + NVIDIA), muita gente quer manter Intel também — já perguntamos acima.
    }
  }

  $needInstall = ($DoNvidia -or $DoAmd -or $DoIntel -or $DoVmwareTools)

  if (-not $needInstall) {
    Write-Log "Nenhuma ação selecionada. Encerrando."
    exit 0
  }

  # Elevação sob demanda (somente quando vai instalar)
  if (-not (Test-IsAdmin) -and -not $Elevated) {
    Write-Log "Instalação selecionada, mas o worker não está em Admin. Solicitando UAC..." "WARN"

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
      Write-Log "Usuário cancelou UAC ou falhou elevar: $($_.Exception.Message)" "ERROR"
      exit 1
    }
  }

  # -------------------- execução das instalações --------------------
  Write-Host ""
  Write-Log "=== EXECUTANDO AÇÕES SELECIONADAS ==="

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
    Write-Log "SUCESSO: ações concluídas e instalação confirmada (por detecção de software)."
    if (Ask-YesNo "Deseja reiniciar agora? (recomendado após drivers)" ($false)) {
      shutdown.exe /r /t 0
    }
    exit 0
  }

  Offer-NextStep -WhatFailed "FALHA: não consegui confirmar 1+ instalações." -RetryBlock {
    Write-Log "Retry manual iniciado..."
    $okAll2 = $true
    if ($DoVmwareTools) { if (-not (Install-VmwareTools)) { $okAll2 = $false } }
    if ($DoNvidia) { if (-not (Install-NvidiaApp)) { $okAll2 = $false } }
    if ($DoAmd) { if (-not (Install-AmdSoftware)) { $okAll2 = $false } }
    if ($DoIntel) { if (-not (Install-IntelDsa)) { $okAll2 = $false } }

    if ($okAll2) { Write-Log "SUCESSO após retry." } else { Write-Log "Ainda falhou. Reinicie e tente novamente." "ERROR" }
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

#WINDOWS NATIVE TOOLS
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

        # Mostra ao usuário exatamente o que será executado
        Write-Host ""
        Write-Host ">>> Abrindo outra janela do PowerShell para executar:" -ForegroundColor Cyan
        Write-Host "    $Title" -ForegroundColor Cyan
        Write-Host "    ---" -ForegroundColor DarkCyan
        $ScriptBlockText.Trim().Split("`n") | ForEach-Object { Write-Host ("    " + $_) -ForegroundColor DarkCyan }
        Write-Host "    ---" -ForegroundColor DarkCyan

        $childPayload = @"
`$ErrorActionPreference = 'Continue'
function _Say([string]`$m){ Write-Host `[WindowsMaintenance`] `$m -ForegroundColor Cyan }
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
            Write-Host "Falha ao abrir janela elevada. Tente executar o PowerShell como Administrador. Detalhe: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        if (-not $NoExitChildWindow) {
            Pause-Local
        }
    }

    function Get-PhysicalDiskInfo {
    $result = @()

    # Preferir Get-PhysicalDisk (mais confiável para SSD/HDD)
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

    # Fallback (WMI/CIM) - pode não distinguir SSD/HDD com precisão em alguns PCs
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
        Write-Header "Detecção de discos (SSD/HDD) e status"
        $info = @(Get-PhysicalDiskInfo)

        if (-not $info -or $info.Count -eq 0) {
            Write-Host "Não foi possível detectar discos." -ForegroundColor Yellow
            return
        }

        $info | Format-Table FriendlyName, MediaType, BusType, SizeGB, HealthStatus, Operational -AutoSize
        Write-Host ""
        Write-Host "Notas:" -ForegroundColor Gray
        Write-Host "- SSD: use 'Otimizar (TRIM/ReTrim)', NÃO 'desfragmentar'." -ForegroundColor Gray
        Write-Host "- HDD: desfragmentar pode ser útil, dependendo do uso." -ForegroundColor Gray
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
            Write-Host "Letra inválida." -ForegroundColor Yellow
            return $null
        }
        return $dl
    }

    # ====== MENU PRINCIPAL ======
    while ($true) {
        Write-Header "Assistente de Manutenção do Windows (PowerShell 5.1)"
        Show-DiskSummary

        Write-Host ""
        Write-Host "Escolha uma ação:"
        Write-Host " 1) Verificar integridade do sistema (SFC /SCANNOW)  [Admin]"
        Write-Host " 2) Reparar imagem do Windows (DISM /Online /Cleanup-Image /RestoreHealth)  [Admin]"
        Write-Host " 3) Checar e corrigir disco (CHKDSK)  [Admin]"
        Write-Host " 4) Otimizar unidades (TRIM para SSD / Desfragmentar HDD)  [Admin recomendado]"
        Write-Host " 5) Limpeza nativa (Storage Sense / arquivos temporários)  [padrão]"
        Write-Host " 6) Atualizar componentes do Windows Update (reset básico)  [Admin]"
        Write-Host " 7) Mostrar ferramentas nativas e atalhos úteis (GUI)  [padrão]"
        Write-Host " 0) Sair"
        Write-Host ""

        $choice = Read-Host "Opção"
        switch ($choice) {
            '1' {
                Start-ChildPowerShell -AsAdmin -Title 'SFC /SCANNOW' -ScriptBlockText @"
_Say 'Executando SFC /SCANNOW (pode demorar)...'
sfc /scannow
_Say 'SFC concluído. Se houve corrupção que não foi corrigida, rode o DISM e repita o SFC.'
"@
            }
            '2' {
                Start-ChildPowerShell -AsAdmin -Title 'DISM RestoreHealth' -ScriptBlockText @"
_Say 'Executando DISM /Online /Cleanup-Image /RestoreHealth (pode demorar)...'
dism /online /cleanup-image /restorehealth
_Say 'DISM concluído. Recomenda-se rodar SFC /SCANNOW em seguida.'
"@
            }
            '3' {
                $dl = Pick-DriveLetter
                if (-not $dl) { Pause-Local; break }

                # Para o disco do sistema, chkdsk /f normalmente agenda no reboot.
                Start-ChildPowerShell -AsAdmin -Title "CHKDSK $dl" -ScriptBlockText @"
_Say 'Rodando CHKDSK...'
_Say 'Se for a unidade do sistema, pode ser necessário agendar para o próximo boot.'
chkdsk $dl`: /f /r
"@
            }
            '4' {
                # O Windows decide o melhor método via "defrag /O"
                Start-ChildPowerShell -AsAdmin -Title 'Otimizar unidades (defrag /O)' -ScriptBlockText @"
_Say 'Listando volumes e status (Get-Volume)...'
Get-Volume | Where-Object DriveLetter | Sort-Object DriveLetter | Format-Table DriveLetter, FileSystemLabel, FileSystem, HealthStatus, SizeRemaining, Size -AutoSize

_Say 'Executando otimização automática (defrag /C /O /U /V)...'
_Say 'Isso faz TRIM/ReTrim em SSD e desfragmentação em HDD quando aplicável.'
defrag /C /O /U /V
"@
            }
            '5' {
                Start-ChildPowerShell -Title 'Limpeza nativa (Storage Sense / Temp)' -ScriptBlockText @"
_Say 'Abrindo configurações do Storage Sense (GUI)...'
Start-Process 'ms-settings:storagesense'

_Say 'Abrindo pasta de temporários do usuário (%TEMP%)...'
Start-Process `$env:TEMP

_Say 'Abrindo Limpeza de Disco (cleanmgr)...'
Start-Process cleanmgr.exe
"@
            }
            '6' {
                Start-ChildPowerShell -AsAdmin -Title 'Reset básico do Windows Update' -ScriptBlockText @"
_Say 'Parando serviços do Windows Update...'
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Stop-Service bits -Force -ErrorAction SilentlyContinue
Stop-Service cryptsvc -Force -ErrorAction SilentlyContinue

_Say 'Renomeando pastas de cache (SoftwareDistribution/Catroot2)...'
Rename-Item -Path `$env:SystemRoot\SoftwareDistribution -NewName 'SoftwareDistribution.old' -ErrorAction SilentlyContinue
Rename-Item -Path `$env:SystemRoot\System32\catroot2 -NewName 'catroot2.old' -ErrorAction SilentlyContinue

_Say 'Iniciando serviços novamente...'
Start-Service cryptsvc -ErrorAction SilentlyContinue
Start-Service bits -ErrorAction SilentlyContinue
Start-Service wuauserv -ErrorAction SilentlyContinue

_Say 'Concluído. Você pode tentar atualizar o Windows novamente.'
"@
            }
            '7' {
                Start-ChildPowerShell -Title 'Ferramentas nativas (atalhos)' -ScriptBlockText @"
_Say 'Abrindo ferramentas nativas úteis...'
_Say 'Gerenciador de Tarefas'
Start-Process taskmgr

_Say 'Monitor de Recursos'
Start-Process resmon

_Say 'Visualizador de Eventos'
Start-Process eventvwr.msc

_Say 'Gerenciamento de Disco'
Start-Process diskmgmt.msc

_Say 'Informações do Sistema'
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
                Write-Host "Opção inválida." -ForegroundColor Yellow
                Pause-Local
            }
        }
    }
}

#VAI INSTALAR GOOGLE-CHROME
function Install-GoogleChromeSetup {
  # URLs dentro da própria function
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

  # já instalado?
  if (& $InstalledTest) {
    Write-Host "Google Chrome já está instalado." -ForegroundColor Green
    return
  }

  # só baixa se não existir
  Write-Host "[Baixando e instalando Google-Chrome...]" -ForegroundColor Yellow

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
  Write-Host "Todos os servidores estão fora, sem internet, ou o arquivo baixado é inválido (Google Chrome)." -ForegroundColor Red
  return
}

  # executa instalador sem travar o menu
  Start-Process -FilePath $dst -ArgumentList '/silent /install' -Verb RunAs
  Write-Host "[OK]" -ForegroundColor Green
}



#VAI ARRUMAR O WINGET
try { chcp 65001 > $null } catch {}

$utf8 = New-Object System.Text.UTF8Encoding $false
[Console]::InputEncoding  = $utf8
[Console]::OutputEncoding = $utf8
$OutputEncoding           = $utf8




#VAI INSTALAR STEAM
function Install-Steam {
  # URLs dentro da própria function
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

  # 1) já instalado?
  if (& $InstalledTest) {
    Write-Host "Steam já está instalado." -ForegroundColor Green
    return
  }

  # 2) só baixa se não existir
  if (-not (Test-Path $dst)) {
    Write-Host "[Baixando e instalando Steam...]" -ForegroundColor Yellow

    $ok = $false
    foreach ($u in $Urls) {
      try {
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri $u -OutFile $dst -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ((Test-Path $dst) -and ((Get-Item $dst).Length -gt 0)) { $ok = $true; break }
      } catch {}
    }

    if (-not $ok) {
      Write-Host "Todos os servidores estão fora ou sem internet." -ForegroundColor Red
      return
    }
  }

  # 3) instala
  Start-Process -FilePath $dst -ArgumentList '/S' -Verb RunAs
  Write-Host "[OK]" -ForegroundColor Green
}


#VAI LISTAR APPS INSTALADO E ATUALIZAR
function Invoke-ProgramsInventoryAndUpdater {
    [CmdletBinding()]
    param(
        [switch]$IncludeUwpApps,     # inclui apps da Microsoft Store (Get-AppxPackage)
        [switch]$ExportCsvOnStart    # exporta inventário automaticamente ao iniciar
    )

    $childTemplate = @'
$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = 'Inventário e Atualizador de Programas'

# Corrige caracteres estranhos (winget progress bar) no console PS 5.1
try { chcp 65001 > $null } catch {}
$utf8 = New-Object System.Text.UTF8Encoding $false
[Console]::InputEncoding  = $utf8
[Console]::OutputEncoding = $utf8
$OutputEncoding           = $utf8

function Say([string]$m) { Write-Host "[Programs] $(Get-Date -Format HH:mm:ss) - $m" -ForegroundColor Cyan }
function Warn([string]$m){ Write-Host "[!] $m" -ForegroundColor Yellow }
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

    # Dedup básico por Nome+Versão+Publisher
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

    Say ("Inventário pronto: {0} itens (Win32: {1} | UWP: {2})" -f $all.Count, $win32.Count, $uwp.Count)
    return $all
}

function Show-Inventory([object[]]$inv) {
    Write-Host ""
    Say "Mostrando inventário (pode ser longo)..."
    $inv | Select-Object Type, Name, Version, Publisher |
        Format-Table -AutoSize
    Write-Host ""
    Say "Dica: você pode exportar para CSV no menu."
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
    Say "Listando atualizações disponíveis via winget (winget upgrade)..."
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
    Say "Abrindo página de 'Downloads e atualizações' da Microsoft Store..."
    Start-Process "ms-windows-store://downloadsandupdates" | Out-Null
}

function Choco-UpgradeAll {
    if (-not (Has-Command choco)) { Err "Chocolatey (choco) não encontrado."; return }
    Warn "Chocolatey pode pedir confirmações e/ou Admin."
    $ans = Read-Host "Rodar 'choco upgrade all' agora? (S/N)"
    if ($ans -notmatch '^[Ss]') { return }
    Say "Comando: choco upgrade all"
    choco upgrade all | Out-Host
    Say "Chocolatey finalizado."
}

function Scoop-UpgradeAll {
    if (-not (Has-Command scoop)) { Err "Scoop não encontrado."; return }
    Warn "Scoop geralmente atualiza tudo via: scoop update *"
    $ans = Read-Host "Rodar 'scoop update *' agora? (S/N)"
    if ($ans -notmatch '^[Ss]') { return }
    Say "Comando: scoop update *"
    scoop update * | Out-Host
    Say "Scoop finalizado."
}

# ===== Execução =====
$inventory = Build-Inventory

if ($exportOnStart) {
    Export-InventoryCsv $inventory
}

while ($true) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host "MENU - Inventário e Atualização"
    Write-Host "============================================================"
    Write-Host "1) Mostrar inventário completo (TODOS os programas)"
    Write-Host "2) Exportar inventário para CSV"
    Write-Host "3) Atualizar via winget (pré-visualizar atualizações)"
    Write-Host "4) Atualizar via winget (atualizar TUDO - interativo)"
    Write-Host "5) Atualizar via winget (atualizar por ID - interativo)"
    Write-Host "6) Atualizar apps da Microsoft Store (abre tela de updates)"
    Write-Host "7) Atualizar via Chocolatey (se existir)"
    Write-Host "8) Atualizar via Scoop (se existir)"
    Write-Host "9) Recoletar inventário (refazer lista)"
    Write-Host "0) Sair"
    Write-Host ""

    $opt = Read-Host "Escolha"
    switch ($opt) {
        '1' { Show-Inventory $inventory }
        '2' { Export-InventoryCsv $inventory }
        '3' {
            if (-not (Has-Command winget)) { Err "winget não encontrado. Instale/atualize o App Installer na Store."; Open-StoreUpdates; break }
            Winget-PreviewUpgrades
        }
        '4' {
            if (-not (Has-Command winget)) { Err "winget não encontrado. Instale/atualize o App Installer na Store."; break }
            Winget-UpgradeAllInteractive
        }
        '5' {
            if (-not (Has-Command winget)) { Err "winget não encontrado. Instale/atualize o App Installer na Store."; break }
            Winget-PreviewUpgrades
            Winget-UpgradeByIdInteractive
        }
        '6' { Open-StoreUpdates }
        '7' { Choco-UpgradeAll }
        '8' { Scoop-UpgradeAll }
        '9' { $inventory = Build-Inventory }
        '0' { Say "Saindo."; return }
        default { Warn "Opção inválida." }
    }
}

Read-Host "Pressione ENTER para fechar esta janela"
'@

    $includeUwpText = if ($IncludeUwpApps.IsPresent) { '$true' } else { '$false' }
    $exportText     = if ($ExportCsvOnStart.IsPresent) { '$true' } else { '$false' }

    $child = $childTemplate `
        -replace '__INCLUDE_UWP__', $includeUwpText `
        -replace '__EXPORT_ON_START__', $exportText

    Write-Host ">>> Abrindo outra janela do PowerShell para listar e oferecer atualizações..." -ForegroundColor Cyan

    $bytes   = [Text.Encoding]::Unicode.GetBytes($child)
    $encoded = [Convert]::ToBase64String($bytes)

    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoExit",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", $encoded
    ) -WindowStyle Normal | Out-Null
}

#INSTALA DDUCLEANNVIDIA
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

# ✅ FIX: switch válido / robusto (sem casos colados)
function Ask-YesNo([string]$Question, [bool]$DefaultYes=$true) {
  if ($Host.Name -notmatch "ConsoleHost") { return $DefaultYes }
  $suffix = if ($DefaultYes) { " [S/n]" } else { " [s/N]" }

  while ($true) {
    $ans = Read-Host ($Question + $suffix)
    if ([string]::IsNullOrWhiteSpace($ans)) { return $DefaultYes }

    $a = $ans.Trim().ToLowerInvariant()
    switch -Regex ($a) {
      '^(s|sim|y|yes)$' { return $true }
      '^(n|nao|não|no)$' { return $false }
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
    Write-Log "DISPLAY drivers NVIDIA: não encontrados."
  } else {
    Write-Log "DISPLAY drivers NVIDIA encontrados:"
    foreach ($d in @($inv.NvidiaDisplayDrivers)) {
      $date = $null
      try { $date = ([datetime]$d.DriverDate).ToString("yyyy-MM-dd") } catch { $date = ($d.DriverDate + "") }
      Write-Log ("- {0} | Provider={1} | Version={2} | Date={3}" -f $d.DeviceName, $d.DriverProviderName, $d.DriverVersion, $date)
    }
  }

  if (@($inv.NvidiaUninstall).Count -eq 0) {
    Write-Log "Entradas de Programas (Uninstall) com NVIDIA: não encontradas."
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
      Write-Log "Arquivo baixado parece inválido; tentando próximo..." "WARN"
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
  if ($dduExe) { Write-Log "DDU já extraído: $dduExe"; return $dduExe }

  Write-Log "Tentando extração automática (best-effort)..."
  try { Start-Process -FilePath $DduSfxPath -ArgumentList "-y -o`"$ExtractDir`"" -Wait | Out-Null } catch {}

  $dduExe = Find-DDUExe $ExtractDir
  if ($dduExe) { Write-Log "Extração automática OK: $dduExe"; return $dduExe }

  Write-Log "Extração automática não confirmada. Abrindo extração interativa..." "WARN"
  Start-Process -FilePath $DduSfxPath | Out-Null
  Write-Host ""
  Write-Host "Extraia para:"
  Write-Host "  $ExtractDir"
  Read-Host "Pressione ENTER quando terminar a extração"

  $dduExe = Find-DDUExe $ExtractDir
  if (-not $dduExe) { throw "Não encontrei 'Display Driver Uninstaller.exe' em $ExtractDir após extração." }
  Write-Log "Extração manual OK: $dduExe"
  return $dduExe
}

function Run-DDU-CleanNvidia([string]$DduExePath) {
  $args = @("-silent","-logging","-createsystemrestorepoint","-nosafemodemsg","-cleannvidia","-restart")
  Write-Log ("Executando DDU: `"{0}`" {1}" -f $DduExePath, ($args -join " "))

  if ($DryRun) { Write-Log "DRY RUN: não vou executar o DDU." "WARN"; return }

  Start-Process -FilePath $DduExePath -ArgumentList $args -Wait | Out-Null
}

function Configure-SafeBootOnce([string]$RunScriptPath) {
  Write-Log "Configurando boot em Safe Mode (uma vez) + RunOnce..."

  if ($DryRun) { Write-Log "DRY RUN: não vou alterar bcdedit/RunOnce." "WARN"; return }

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
  Write-Log "Recomendação: usar Safe Mode para maior estabilidade com DDU." "WARN"
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
  Write-Log "Falha no download direto (pode ser hotlink protection). Abrindo página oficial." "WARN"
  Start-Process $fallbackPage | Out-Null
  Write-Host "Baixe o DDU manualmente e salve como:"
  Write-Host "  $dduPath"
  Read-Host "Pressione ENTER quando o arquivo estiver nesse caminho"
}

if (-not (Test-Path $dduPath)) { throw "DDU não encontrado em: $dduPath" }

$sha = Get-FileSha256 $dduPath
if ($sha) {
  Write-Log "SHA256 baixado:  $sha"
  Write-Log "SHA256 esperado: $expectedSha"
  if ($sha -ne $expectedSha) {
    Write-Log "SHA256 não confere com o valor do post oficial. Recomendo baixar novamente do site oficial." "WARN"
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
Write-Log "Antes de iniciar: feche apps e, idealmente, desconecte a internet até reinstalar driver."
if (-not (Ask-YesNo "Confirmar e iniciar limpeza NVIDIA agora?" $true)) {
  Write-Log "Cancelado pelo usuário."
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

#VAI INSTALAR VLC
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

  # 1) já instalado?
  if (& $InstalledTest) {
    Write-Host "VLC já está instalado." -ForegroundColor Green
    return
  }

  # 2) só baixa se não existir
  Write-Host "[Baixando e instalando VLC...]" -ForegroundColor Yellow

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
  Write-Host "Todos os servidores estão fora, sem internet, ou o arquivo baixado é inválido." -ForegroundColor Red
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

  # 1) já instalado?
  if (& $InstalledTest) {
    Write-Host "7-Zip já está instalado." -ForegroundColor Green
    return
  }

  # 2) só baixa se não existir
  Write-Host "[Baixando e instalando 7-ZIP...]" -ForegroundColor Yellow

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
  Write-Host "Todos os servidores estão fora, sem internet, ou o arquivo baixado é inválido." -ForegroundColor Red
  return
}

  # 3) instala
  Start-Process -FilePath $dst -ArgumentList '/S' -Verb RunAs
  Write-Host "[OK]" -ForegroundColor Green
}

#VAI USAR WINGET COMO BUSCADOR/INSTALADOR
function Invoke-WinGetInteligente {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [string]$Term,

        [switch]$Repair,
        [switch]$Silent,
        [switch]$NoMSStore,
        [switch]$Utf8Console,

        [int]$MaxResults = 25
    )

    begin {
        function _Write([string]$msg, [ValidateSet('INFO','OK','WARN','ERR')] [string]$level='INFO') {
            switch ($level) {
                'OK'   { Write-Host "[OK]    $msg" -ForegroundColor Green }
                'WARN' { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
                'ERR'  { Write-Host "[ERRO]  $msg" -ForegroundColor Red }
                default { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
            }
        }

        function _InitUtf8Console {
            try { chcp 65001 > $null } catch {}
            try {
                $utf8 = New-Object System.Text.UTF8Encoding $false
                [Console]::InputEncoding  = $utf8
                [Console]::OutputEncoding = $utf8
                $script:OutputEncoding    = $utf8
            } catch {}
        }
        if ($Utf8Console) { _InitUtf8Console }

        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor `
                                                          [Net.ServicePointManager]::SecurityProtocol
        } catch {}

        function _GetWinGetExe {
            $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
            if ($cmd) { return $cmd.Source }

            $pkg = $null
            try { $pkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction Stop } catch {}
            if (-not $pkg) { try { $pkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -AllUsers -ErrorAction Stop } catch {} }

            if ($pkg -and $pkg.InstallLocation) {
                $candidate = Join-Path $pkg.InstallLocation 'winget.exe'
                if (Test-Path $candidate) { return $candidate }
            }

            $candidate2 = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
            if (Test-Path $candidate2) { return $candidate2 }

            return $null
        }

        function _InvokeWinget([string[]]$Args) {
            $exe = _GetWinGetExe
            if (-not $exe) { throw "winget.exe não encontrado. Instale/atualize o 'App Installer'." }

            $out  = & $exe @Args 2>&1
            $code = $LASTEXITCODE

            [pscustomobject]@{
                ExitCode = $code
                Output   = ($out -join "`n")
                Lines    = @($out)
                Args     = ($Args -join ' ')
            }
        }

        function _BaseArgsArray {
            $list = New-Object 'System.Collections.Generic.List[string]'
            [void]$list.Add('--accept-source-agreements')
            [void]$list.Add('--disable-interactivity')
            if ($NoMSStore) {
                [void]$list.Add('--source')
                [void]$list.Add('winget')
            }
            $list.ToArray()
        }

        function _MakeArgs([string[]]$head) {
            $list = New-Object 'System.Collections.Generic.List[string]'
            foreach ($h in @($head)) { if ($h -ne $null) { [void]$list.Add([string]$h) } }
            foreach ($b in @(_BaseArgsArray)) { [void]$list.Add([string]$b) }
            $list.ToArray()
        }

        function _AskYesNo([string]$Text, [bool]$DefaultYes=$true) {
            $def = if ($DefaultYes) { 'S/n' } else { 's/N' }
            $ans = Read-Host "$Text ($def)"
            if ([string]::IsNullOrWhiteSpace($ans)) { return $DefaultYes }
            ($ans.Trim().ToLower() -in @('s','sim','y','yes'))
        }

        function _LooksLikeMsStoreAgreementIssue([string]$text) {
            if (-not $text) { return $false }
            $t = $text.ToLowerInvariant()
            return (
                $t -like '*msstore*agreement*' -or
                $t -like '*terms of transaction*' -or
                $t -like '*do you agree*' -or
                $t -like '*requires that you view*agreements*' -or
                $t -like '*geographic region*'
            )
        }

        function _ParseWingetTable([string[]]$Lines) {
    $Lines = @($Lines | ForEach-Object { $_ -replace "`r","" })
    if ($Lines.Count -eq 0) { return @() }

    # 1) Parser por posição (colunas pelo header)
    function _FindHeaderIndex([string[]]$ls) {
        for ($i=0; $i -lt $ls.Count; $i++) {
            if ($ls[$i] -match '^\s*(Name|Nome)\s+(Id|ID)\s+(Version|Vers(ã|a)o)') { return $i }
        }
        -1
    }
    function _FindCol([string]$header, [string[]]$alts) {
        foreach ($a in $alts) {
            $m = [regex]::Match($header, '(?<!\S)' + [regex]::Escape($a) + '(?!\S)')
            if ($m.Success) { return $m.Index }
        }
        -1
    }

    $hi = _FindHeaderIndex $Lines
    if ($hi -ge 0) {
        $header = $Lines[$hi]

        $idxName      = _FindCol $header @('Name','Nome')
        $idxId        = _FindCol $header @('Id','ID')
        $idxVersion   = _FindCol $header @('Version','Versão','Versao')
        $idxAvailable = _FindCol $header @('Available','Disponível','Disponivel')
        $idxSource    = _FindCol $header @('Source','Fonte')
        $idxMatch     = _FindCol $header @('Match','Correspondência','Correspondencia')

        $cols = @()
        if ($idxName      -ge 0) { $cols += [pscustomobject]@{ Key='Name';      Idx=$idxName } }
        if ($idxId        -ge 0) { $cols += [pscustomobject]@{ Key='Id';        Idx=$idxId } }
        if ($idxVersion   -ge 0) { $cols += [pscustomobject]@{ Key='Version';   Idx=$idxVersion } }
        if ($idxAvailable -ge 0) { $cols += [pscustomobject]@{ Key='Available'; Idx=$idxAvailable } }
        if ($idxMatch     -ge 0) { $cols += [pscustomobject]@{ Key='Match';     Idx=$idxMatch } }
        if ($idxSource    -ge 0) { $cols += [pscustomobject]@{ Key='Source';    Idx=$idxSource } }

        $cols = $cols | Sort-Object Idx
        if ($cols.Count -ge 3) {
            $rows = @()

            for ($j=$hi+1; $j -lt $Lines.Count; $j++) {
                $line = $Lines[$j]
                if (-not $line) { continue }
                if ($line.Trim() -eq '' -or $line -match '^\s*-+\s*$') { continue }
                if ($line -match 'No package found|Nenhum pacote encontrado') { continue }

                $obj = [ordered]@{ Name=''; Id=''; Version=''; Available=''; Match=''; Source='' }

                for ($c=0; $c -lt $cols.Count; $c++) {
                    $start = [int]$cols[$c].Idx
                    $end   = if ($c -lt $cols.Count-1) { [int]$cols[$c+1].Idx } else { $line.Length }

                    $val = ''
                    if ($start -lt $line.Length) {
                        $realEnd = [Math]::Min($end, $line.Length)
                        $len = [Math]::Max(0, $realEnd - $start)
                        $val = $line.Substring($start, $len).Trim()
                    }

                    $obj[$cols[$c].Key] = $val
                }

                if ($obj.Id) { $rows += [pscustomobject]$obj }
            }

            if ($rows.Count -gt 0) { return @($rows) }
        }
    }

    # 2) Fallback regex (quando a tabela vem diferente)
    # Padrão: Name [2+ espaços] Id [2+ espaços] Version [2+ espaços] (Available)? [2+ espaços] (Source)?
    $rx = '^(?<Name>.+?)\s{2,}(?<Id>[A-Za-z0-9][A-Za-z0-9\.\-]+)\s{2,}(?<Version>\S+)(?:\s{2,}(?<Available>\S+))?(?:\s{2,}(?<Source>\S+))?\s*$'

    $rows2 = @()
    foreach ($line in $Lines) {
        if (-not $line) { continue }
        $t = $line.Trim()
        if ($t -eq '' -or $t -match '^\-+$') { continue }
        if ($t -match 'No package found|Nenhum pacote encontrado') { continue }

        $m = [regex]::Match($line, $rx)
        if ($m.Success) {
            $rows2 += [pscustomobject]@{
                Name      = $m.Groups['Name'].Value.Trim()
                Id        = $m.Groups['Id'].Value.Trim()
                Version   = $m.Groups['Version'].Value.Trim()
                Available = $m.Groups['Available'].Value.Trim()
                Match     = ''
                Source    = $m.Groups['Source'].Value.Trim()
            }
        }
    }

    @($rows2)
}

        function _RepairWinget {
            _Write "Reparando fontes do WinGet (source reset/update)..." 'INFO'
            try { _InvokeWinget (_MakeArgs @('source','reset','--force')) | Out-Null } catch {}
            try { _InvokeWinget (_MakeArgs @('source','update')) | Out-Null } catch {}
            _Write "Reparo concluído." 'OK'
        }

        function _Search([string]$q) {
    # monta args SEM concatenar com '+'
    function _Args([string[]]$head) {
        $l = New-Object 'System.Collections.Generic.List[string]'
        foreach ($x in @($head)) { if ($x -ne $null) { [void]$l.Add([string]$x) } }

        # igual ao manual + auto-aceite
        [void]$l.Add('--accept-source-agreements')

        # se o usuário pediu sem store
        if ($NoMSStore) { [void]$l.Add('--source'); [void]$l.Add('winget') }

        $l.ToArray()
    }

    $tries = @(
        @{ Name='all';     Head=@('search', $q) },
        @{ Name='winget';  Head=@('search', $q, '--source', 'winget') }
    )

    if (-not $NoMSStore) {
        $tries += @{ Name='msstore'; Head=@('search', $q, '--source', 'msstore') }
    }

    $lastOutput = $null

    foreach ($t in $tries) {
        $args = _Args $t.Head
        Write-Verbose ("winget " + ($args -join ' '))

        $r = _InvokeWinget $args
        $lastOutput = $r.Output

        # exitcode != 0 => erro real (não confundir com "não encontrado")
        if ($r.ExitCode -ne 0) { continue }

        $items = @(_ParseWingetTable $r.Lines)
        if ($items.Count -gt 0) { return $items }

        # Se o próprio winget disser explicitamente que não achou, podemos parar
        if ($r.Output -match 'No package found|Nenhum pacote encontrado') { return @() }
    }

    # aqui: não deu pra parsear nada. Não afirmar "não encontrado" sem prova.
    Write-Host "[WARN] Não consegui extrair resultados do winget, mas isso pode ser falha de parsing." -ForegroundColor Yellow
    if ($lastOutput) {
        Write-Host "----- Saída bruta do winget -----"
        Write-Host $lastOutput
        Write-Host "---------------------------------"
    }

    # fallback humano: permite colar um ID e continuar o fluxo
    $manualId = Read-Host "Cole um ID exato para continuar (ex: 7zip.7zip) ou Enter para cancelar"
    if (-not [string]::IsNullOrWhiteSpace($manualId)) {
        return @([pscustomobject]@{ Name=$manualId; Id=$manualId; Version=''; Available=''; Match=''; Source='' })
    }

    @()
}

        function _ListInstalledById([string]$id) {
            $r = _InvokeWinget (_MakeArgs @('list','--id',$id,'-e'))
            if ($r.ExitCode -ne 0) { return @() }
            @(_ParseWingetTable $r.Lines)
        }

        function _Show([string]$id) {
            $r = _InvokeWinget (_MakeArgs @('show','--id',$id,'-e'))
            $r.Output
        }

        function _Install([string]$id) {
            $head = New-Object 'System.Collections.Generic.List[string]'
            foreach ($x in @('install','--id',$id,'-e','--accept-package-agreements')) { [void]$head.Add($x) }
            if ($Silent) { [void]$head.Add('--silent') }

            $r = _InvokeWinget (_MakeArgs $head.ToArray())
            if ($r.ExitCode -eq 0) { _Write "Instalação concluída." 'OK'; return $true }
            _Write "Falha ao instalar (ExitCode=$($r.ExitCode))." 'ERR'
            $r.Output | Write-Host
            $false
        }

        function _Upgrade([string]$id) {
            $head = New-Object 'System.Collections.Generic.List[string]'
            foreach ($x in @('upgrade','--id',$id,'-e','--accept-package-agreements')) { [void]$head.Add($x) }
            if ($Silent) { [void]$head.Add('--silent') }

            $r = _InvokeWinget (_MakeArgs $head.ToArray())
            if ($r.ExitCode -eq 0) { _Write "Atualização concluída." 'OK'; return $true }
            _Write "Falha ao atualizar (ExitCode=$($r.ExitCode))." 'ERR'
            $r.Output | Write-Host
            $false
        }

        function _Uninstall([string]$id) {
            $r = _InvokeWinget (_MakeArgs @('uninstall','--id',$id,'-e'))
            if ($r.ExitCode -eq 0) { _Write "Desinstalação concluída." 'OK'; return $true }

            if (-not $NoMSStore -and (_LooksLikeMsStoreAgreementIssue $r.Output)) {
                _Write "Falhou por msstore/termos. Tentando '--source winget'..." 'WARN'
                $r2 = _InvokeWinget (_MakeArgs @('uninstall','--id',$id,'-e','--source','winget'))
                if ($r2.ExitCode -eq 0) { _Write "Desinstalação concluída (fallback)." 'OK'; return $true }
                _Write "Fallback também falhou (ExitCode=$($r2.ExitCode))." 'ERR'
                $r2.Output | Write-Host
                return $false
            }

            _Write "Falha ao desinstalar (ExitCode=$($r.ExitCode))." 'ERR'
            $r.Output | Write-Host
            $false
        }

        function _SelectFromResults($items) {
            $items = @($items)
            if ($items.Count -eq 0) { return $null }
            if ($items.Count -eq 1) { return $items[0] }

            _Write "Resultados:" 'INFO'
            for ($i=0; $i -lt $items.Count; $i++) {
                $it = $items[$i]
                "{0,2}. {1} | {2} | {3} | {4}" -f ($i+1), $it.Name, $it.Id, $it.Version, $it.Source | Write-Host
            }
            while ($true) {
                $sel = Read-Host "Escolha um número (0 cancela)"
                if ($sel -match '^\d+$') {
                    $k = [int]$sel
                    if ($k -eq 0) { return $null }
                    if ($k -ge 1 -and $k -le $items.Count) { return $items[$k-1] }
                }
                _Write "Seleção inválida." 'WARN'
            }
        }

        function _Menu([bool]$installed, [bool]$hasUpdate) {
            Write-Host ""
            Write-Host "Ações:"
            if (-not $installed) {
                Write-Host "  1) Instalar"
                Write-Host "  4) Detalhes"
                Write-Host "  0) Cancelar"
                $valid = @('0','1','4')
            } else {
                if ($hasUpdate) { Write-Host "  2) Atualizar (há update disponível)" }
                else { Write-Host "  2) Atualizar (pode não haver update)" }
                Write-Host "  3) Desinstalar"
                Write-Host "  4) Detalhes"
                Write-Host "  0) Cancelar"
                $valid = @('0','2','3','4')
            }

            while ($true) {
                $a = Read-Host "Escolha"
                if ($valid -contains $a) { return [int]$a }
                _Write "Opção inválida." 'WARN'
            }
        }
    }

    process {
        if ($Repair) { _RepairWinget }

        while ([string]::IsNullOrWhiteSpace($Term)) {
            $Term = Read-Host "Digite o nome do pacote para pesquisar"
            if ([string]::IsNullOrWhiteSpace($Term) -and (_AskYesNo "Nada digitado. Sair?" $true)) { return }
        }

        $items = @(_Search $Term)
        if ($items.Count -eq 0) { _Write "Nenhum pacote encontrado para '$Term'." 'WARN'; return }

        $chosen = _SelectFromResults $items
        if (-not $chosen) { return }

        $installedRows = @(_ListInstalledById $chosen.Id)
        $isInstalled = ($installedRows.Count -gt 0)

        $availableVersion = $null
        if ($isInstalled) {
            _Write ("Instalado: {0} | {1} | versão: {2}" -f $chosen.Name, $chosen.Id, $installedRows[0].Version) 'OK'
            $availableVersion = $installedRows[0].Available
            if ($availableVersion) { _Write ("Update disponível: {0}" -f $availableVersion) 'INFO' }
        } else {
            _Write ("Não instalado: {0} | {1}" -f $chosen.Name, $chosen.Id) 'INFO'
        }

        $action = _Menu -installed:$isInstalled -hasUpdate:([bool]$availableVersion)
        switch ($action) {
            0 { return }
            1 { if (_AskYesNo "Confirmar instalação de '$($chosen.Id)'?" $true) { _Install $chosen.Id | Out-Null } }
            2 { if (_AskYesNo "Confirmar atualização de '$($chosen.Id)'?" $true) { _Upgrade $chosen.Id | Out-Null } }
            3 { if (_AskYesNo "Confirmar desinstalação de '$($chosen.Id)'?" $false) { _Uninstall $chosen.Id | Out-Null } }
            4 { _Write "Detalhes:" 'INFO'; _Show $chosen.Id | Write-Host }
        }
    }
}

function Start-WinGetInteligenteWindow {
    [CmdletBinding()]
    param(
        [string]$Term,
        [switch]$Repair,
        [switch]$Silent,
        [switch]$NoMSStore,
        [int]$MaxResults = 25
    )

    $def = (Get-Command Invoke-WinGetInteligente -CommandType Function).Definition

    function _Sq([string]$s) { "'" + ($s -replace "'", "''") + "'" }

    $argsLine = New-Object System.Collections.Generic.List[string]
    if ($Term)      { [void]$argsLine.Add("-Term $(_Sq $Term)") }
    if ($Repair)    { [void]$argsLine.Add("-Repair") }
    if ($Silent)    { [void]$argsLine.Add("-Silent") }
    if ($NoMSStore) { [void]$argsLine.Add("-NoMSStore") }
    if ($MaxResults -gt 0) { [void]$argsLine.Add("-MaxResults $MaxResults") }

    $tmp = Join-Path $env:TEMP ("winget-inteligente-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))

    $content = @"
try { chcp 65001 > `$null } catch {}
try { mode con: cols=200 lines=3000 > `$null } catch {}
try {
  `$utf8 = New-Object System.Text.UTF8Encoding `$false
  [Console]::InputEncoding  = `$utf8
  [Console]::OutputEncoding = `$utf8
  `$OutputEncoding          = `$utf8
} catch {}

function Invoke-WinGetInteligente {
$def
}

Invoke-WinGetInteligente -Utf8Console $($argsLine -join ' ')
"@

    Set-Content -Path $tmp -Value $content -Encoding UTF8

    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-NoExit",
        "-File", $tmp
    ) | Out-Null

    Write-Host "[OK] Nova janela aberta. Script temporário: $tmp"
}

#VAI INSTALAR MSI AFTERBURNER
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

  # Já instalado?
  if (& $InstalledTest) {
    Write-Host "MSI Afterburner já está instalado." -ForegroundColor Green
    return
  }
 
#verifica se baixou
Write-Host "[Baixando e instalando MSI Afterburner...]" -ForegroundColor Yellow

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
  Write-Host "Todos os servidores estão fora, sem internet, ou o arquivo baixado é inválido (Afterburner)." -ForegroundColor Red
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
    Write-Host "Instalador do Afterburner não encontrado após extração." -ForegroundColor Red
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

  # Já instalado?
  if (& $InstalledTest) {
    Write-Host "RTSS já está instalado." -ForegroundColor Green
    return
  }

  Write-Host "[Baixando e instalando RTSS...]" -ForegroundColor Yellow

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
  Write-Host "Todos os servidores estão fora, sem internet, ou o arquivo baixado é inválido (RTSS)." -ForegroundColor Red
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
    Write-Host "Instalador do RTSS não encontrado após extração." -ForegroundColor Red
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
    Write-Host "Discord já está instalado." -ForegroundColor Green
    return
  }

  Write-Host "[Baixando e instalando Discord...]" -ForegroundColor Yellow

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
  Write-Host "Todos os servidores estão fora, sem internet, ou o arquivo baixado é inválido (Discord)." -ForegroundColor Red
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
    Write-Host "Telegram já está instalado." -ForegroundColor Green
    return
  }

  Write-Host "[Baixando e instalando Telegram...]" -ForegroundColor Yellow

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
  Write-Host "Todos os servidores estão fora, sem internet, ou o arquivo baixado é inválido (Telegram)." -ForegroundColor Red
  return
}

  Start-Process -FilePath $dst -ArgumentList '/VERYSILENT /NORESTART'
  Write-Host "[OK]" -ForegroundColor Green
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
  Write-Host "Todos os programas foram baixados e executados em segundo plano!"
  Start-Sleep 2
}

#VAI ARRUMAR O VRCHAT
function Set-Gaming-Features {
    [CmdletBinding()]
    param(
        [ValidateSet('OffCurrentUser','OffAllUsers','RemoveRegistry')]
        [string]$Mode
    )

    function Test-IsAdmin {
        $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Ensure-RegKey([string]$Path) {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    }

    function Get-RegValueSafe([string]$Path, [string]$Name) {
        try { Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop }
        catch { $null }
    }

    function Parse-DxSettings([string]$s) {
        $d = [ordered]@{}
        if ([string]::IsNullOrWhiteSpace($s)) { return $d }
        foreach ($part in ($s -split ';')) {
            if ([string]::IsNullOrWhiteSpace($part)) { continue }
            $kv = $part -split '=', 2
            if ($kv.Count -eq 2 -and -not $d.Contains($kv[0])) { $d[$kv[0]] = $kv[1] }
        }
        $d
    }

    function To-DxSettings([hashtable]$d) {
        if ($d.Count -eq 0) { return $null }
        (($d.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';') + ';'
    }

    function Get-GpuNote {
        $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
        if ($gpus.Count -eq 0) {
            return "Info: não foi possível detectar a GPU (WMI indisponível). As opções podem não existir/ser aplicáveis."
        }

        $names = ($gpus | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue) -join " | "
        if ($names -match 'Microsoft Basic Display Adapter') {
            return "Info: detectado driver genérico 'Microsoft Basic Display Adapter'. Sem driver de GPU, VRR/otimizações/HAGS podem não existir ou não surtir efeito até instalar o driver."
        }

        return "GPU(s): $names"
    }

    function Set-DxOffForHive([string]$hkuRoot) {
        $dxPath = "Registry::$hkuRoot\Software\Microsoft\DirectX\UserGpuPreferences"
        $dxName = "DirectXUserGlobalSettings"

        Ensure-RegKey $dxPath

        # Lê SEM acessar propriedade inexistente
        $cur  = Get-RegValueSafe $dxPath $dxName
        $dict = Parse-DxSettings $cur

        # OFF nas 2 opções do print
        $dict['SwapEffectUpgradeEnable'] = '0'  # Optimizations for windowed games
        $dict['VRROptimizeEnable']       = '0'  # Variable refresh rate

        $new = To-DxSettings $dict

        # Grava (cria se não existir)
        New-ItemProperty -Path $dxPath -Name $dxName -PropertyType String -Value $new -Force | Out-Null

        # Retorna status para mensagens
        [pscustomobject]@{
            HadValueBefore = -not [string]::IsNullOrWhiteSpace($cur)
            Before         = $cur
            After          = $new
        }
    }

    function Apply-AllUsers([scriptblock]$perHiveAction) {
        # NÃO lançar erro: só explicar e retornar $false
        if (-not (Test-IsAdmin)) { return $false }

        $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $sids = Get-ChildItem $profileList -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
                Select-Object -ExpandProperty PSChildName -Unique

        foreach ($sid in $sids) {
            $loaded = Test-Path "Registry::HKEY_USERS\$sid"
            if ($loaded) {
                & $perHiveAction "HKEY_USERS\$sid"
                continue
            }

            $p = Get-ItemProperty -Path (Join-Path $profileList $sid) -ErrorAction SilentlyContinue
            if (-not $p.ProfileImagePath) { continue }

            $userDir = [Environment]::ExpandEnvironmentVariables($p.ProfileImagePath)
            $ntuser  = Join-Path $userDir 'NTUSER.DAT'
            if (-not (Test-Path $ntuser)) { continue }

            $tmp = "GF_$($sid.Replace('-',''))"
            $loadTarget = "HKU\$tmp"

            try {
                & reg.exe load $loadTarget $ntuser | Out-Null
                & $perHiveAction "HKEY_USERS\$tmp"
            } finally {
                & reg.exe unload $loadTarget | Out-Null
            }
        }

        return $true
    }

    function Set-HagsOff {
        # HwSchMode: 1=Off, 2=On (em geral)
        $hagsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
        Ensure-RegKey $hagsPath
        New-ItemProperty -Path $hagsPath -Name 'HwSchMode' -PropertyType DWord -Value 1 -Force | Out-Null
    }

    function Remove-HagsValue {
        $hagsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
        if (Test-Path $hagsPath) {
            Remove-ItemProperty -Path $hagsPath -Name 'HwSchMode' -ErrorAction SilentlyContinue
        }
    }

    function Remove-DxGlobalForHive([string]$hkuRoot) {
        $dxPath = "Registry::$hkuRoot\Software\Microsoft\DirectX\UserGpuPreferences"
        if (Test-Path $dxPath) {
            Remove-ItemProperty -Path $dxPath -Name "DirectXUserGlobalSettings" -ErrorAction SilentlyContinue
        }
    }

    # ======================
    # Execução (sem "Erro:")
    # ======================
    Write-Host ""
    Write-Host (Get-GpuNote)

    switch ($Mode) {
        'OffCurrentUser' {
            $r = Set-DxOffForHive "HKEY_CURRENT_USER"

            if (-not $r.HadValueBefore) {
                Write-Host "OK: As configs globais do DirectX ainda não existiam neste usuário; criei agora e defini OFF (isso é normal em PCs sem driver/sem suporte)."
            } else {
                Write-Host "OK: Atualizei DirectXUserGlobalSettings e defini OFF."
            }

            if (Test-IsAdmin) {
                Set-HagsOff
                Write-Host "OK: HAGS = OFF. (Reinicie o PC para aplicar HAGS.)"
            } else {
                Write-Host "Info: HAGS não foi aplicado porque requer Administrador (HKLM)."
            }

            Write-Host "Ação: reinicie o VRChat/jogo/app para aplicar Optimizations/VRR."
            pause
        }

        'OffAllUsers' {
            if (-not (Test-IsAdmin)) {
                Write-Host "Info: Opção 2 requer Administrador. Vou aplicar somente no usuário atual (equivalente à opção 1)."
                Set-Gaming-Features -Mode OffCurrentUser
                return
            }

            $ok = Apply-AllUsers { param($root) Set-DxOffForHive $root | Out-Null }
            if (-not $ok) {
                Write-Host "Info: Não foi possível aplicar para todos os usuários (precisa Admin)."
                return
            }

            Set-HagsOff
            Write-Host "OK: OFF para todos os usuários + HAGS OFF."
            Write-Host "Ação: reinicie o PC (HAGS) e reinicie o jogo/app."
            pause
        }

        'RemoveRegistry' {
            if (-not (Test-IsAdmin)) {
                Write-Host "Info: Opção 3 requer Administrador. Nada foi removido."
                Write-Host "Motivo: remover envolve HKLM e perfis de outros usuários (HKU)."
                return
            }

            # backup simples
            $ts = Get-Date -Format "yyyyMMdd_HHmmss"
            $b1 = Join-Path $env:TEMP "GamingFeatures_BACKUP_UserGpuPreferences_$ts.reg"
            $b2 = Join-Path $env:TEMP "GamingFeatures_BACKUP_GraphicsDrivers_$ts.reg"
            & reg.exe export "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" $b1 /y | Out-Null
            & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" $b2 /y | Out-Null

            Apply-AllUsers { param($root) Remove-DxGlobalForHive $root } | Out-Null
            Remove-DxGlobalForHive "HKEY_CURRENT_USER"
            Remove-HagsValue

            Write-Host "OK: removi as entradas do Registro (DirectXUserGlobalSettings + HwSchMode)."
            Write-Host "Backups (.reg) em: $b1 | $b2"
            Write-Host "Ação: reinicie o PC."
            pause
        }
    }
}

#VAI INSTALAR TODOS OS LAUNCHERS
function Install-AllLaunchers {
  Install-Steam
  Install-HoYoPlay
  Install-RiotClient
  Install-EpicGamesLauncher
  Write-Host "Todos os programas foram baixados e executados em segundo plano!"
  Start-Sleep 2
}
function Test-Creditos {
    Clear-Host
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host "Easyinstall Enhanced v2" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "Criado e desenvolvido por gabrielmf1998 (Github)" -ForegroundColor Green
    pause
}


#VAI REMOVER TODO LIXO QUE VEM NO WINDOWS 11
function Invoke-W11AppRemovalWorker {
    [CmdletBinding()]
    param(
        [string]$LogPath = "$env:ProgramData\Win11Debloat\remocao.log",
        [ValidateSet('BlockWithFirewall','EEAUninstallPolicy','Skip')]
        [string]$EdgeMode = 'BlockWithFirewall'
    )

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    function Test-IsAdmin {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = [Security.Principal.WindowsPrincipal]::new($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Write-Status {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] $Message"

    # mostra na janela do PowerShell separada
    Write-Host $line -ForegroundColor $Color

    # continua gravando no log
    Add-Content -Path $LogPath -Value $line
}

    function Test-AnyLike {
        param(
            [AllowNull()][string]$Value,
            [string[]]$Patterns
        )
        if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
        foreach ($pattern in $Patterns) {
            if ($Value -like $pattern) { return $true }
        }
        return $false
    }

    function Remove-AppxTarget {
        param(
            [string]$Label,
            [string[]]$Patterns
        )

        Write-Status "==> Iniciando remoção: $Label"

        # Remover das contas existentes
        try {
            $installed = Get-AppxPackage -AllUsers | Where-Object {
                (Test-AnyLike -Value $_.Name -Patterns $Patterns) -or
                (Test-AnyLike -Value $_.PackageFamilyName -Patterns $Patterns)
            } | Sort-Object PackageFullName -Unique

            if (-not $installed) {
                Write-Status "Nenhum AppX instalado encontrado para: $Label"
            }

            foreach ($pkg in $installed) {
                try {
                    Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                    Write-Status "Removido (instalado): $($pkg.Name) | $($pkg.PackageFullName)"
                }
                catch {
                    Write-Status "Falhou ao remover (instalado): $($pkg.Name) | $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Status "Erro ao enumerar AppX instalado para $Label | $($_.Exception.Message)"
        }

        # Remover do provisionamento (novos perfis)
        try {
            $provisioned = Get-AppxProvisionedPackage -Online | Where-Object {
                (Test-AnyLike -Value $_.DisplayName -Patterns $Patterns) -or
                (Test-AnyLike -Value $_.PackageName -Patterns $Patterns)
            } | Sort-Object PackageName -Unique

            if (-not $provisioned) {
                Write-Status "Nenhum AppX provisionado encontrado para: $Label"
            }

            foreach ($pkg in $provisioned) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -AllUsers -ErrorAction Stop | Out-Null
                    Write-Status "Removido (provisionado): $($pkg.DisplayName) | $($pkg.PackageName)"
                }
                catch {
                    Write-Status "Falhou ao remover (provisionado): $($pkg.DisplayName) | $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Status "Erro ao enumerar AppX provisionado para $Label | $($_.Exception.Message)"
        }
    }

    function Remove-OneDrive {
        Write-Status "==> Iniciando remoção: OneDrive"

        try {
            Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Status "Não foi possível encerrar o processo do OneDrive: $($_.Exception.Message)"
        }

        $setupCandidates = @(
            "$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
            "$env:SystemRoot\System32\OneDriveSetup.exe"
        ) | Where-Object { Test-Path $_ }

        if (-not $setupCandidates) {
            Write-Status "OneDriveSetup.exe não encontrado."
            return
        }

        $setup = $setupCandidates[0]

        try {
            Start-Process -FilePath $setup -ArgumentList '/uninstall' -WindowStyle Hidden -Wait
            Write-Status "Comando de desinstalação do OneDrive executado: $setup /uninstall"
        }
        catch {
            Write-Status "Falha ao desinstalar OneDrive: $($_.Exception.Message)"
        }
    }

    function Configure-Edge {
        param(
            [ValidateSet('BlockWithFirewall','EEAUninstallPolicy','Skip')]
            [string]$Mode
        )

        Write-Status "==> Tratamento do Edge: $Mode"

        switch ($Mode) {
            'Skip' {
                Write-Status "Edge ignorado."
            }

            'EEAUninstallPolicy' {
                try {
                    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
                    if (-not (Test-Path $key)) {
                        New-Item -Path $key -Force | Out-Null
                    }

                    New-ItemProperty `
                        -Path $key `
                        -Name 'Uninstall{56eb18f8-b008-4cbd-b6d2-8c97fe7e9062}' `
                        -PropertyType DWord `
                        -Value 1 `
                        -Force | Out-Null

                    Write-Status "Policy do Edge configurada: Uninstall=1. (Só terá efeito em dispositivo ingressado em domínio e no EEA.)"
                }
                catch {
                    Write-Status "Falha ao configurar policy de desinstalação do Edge: $($_.Exception.Message)"
                }
            }

            'BlockWithFirewall' {
                try {
                    Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Status "Não foi possível encerrar o Edge: $($_.Exception.Message)"
                }

                $edgeExecutables = @(
                    "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
                    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
                ) | Where-Object { Test-Path $_ } | Select-Object -Unique

                if (-not $edgeExecutables) {
                    Write-Status "msedge.exe não encontrado; bloqueio por firewall ignorado."
                    return
                }

                $index = 0
                foreach ($exe in $edgeExecutables) {
                    $index++
                    $outName = "Block Microsoft Edge Outbound [$index]"
                    $inName  = "Block Microsoft Edge Inbound [$index]"

                    try {
                        if (-not (Get-NetFirewallRule -DisplayName $outName -ErrorAction SilentlyContinue)) {
                            New-NetFirewallRule -DisplayName $outName -Direction Outbound -Program $exe -Action Block | Out-Null
                            Write-Status "Regra criada: $outName -> $exe"
                        }
                        else {
                            Write-Status "Regra já existia: $outName"
                        }

                        if (-not (Get-NetFirewallRule -DisplayName $inName -ErrorAction SilentlyContinue)) {
                            New-NetFirewallRule -DisplayName $inName -Direction Inbound -Program $exe -Action Block | Out-Null
                            Write-Status "Regra criada: $inName -> $exe"
                        }
                        else {
                            Write-Status "Regra já existia: $inName"
                        }
                    }
                    catch {
                        Write-Status "Falha ao criar regra de firewall para Edge ($exe): $($_.Exception.Message)"
                    }
                }
            }
        }
    }
    function Remove-Teams {
    Write-Status "==> Iniciando remoção: Teams" Cyan

    # New Teams (AppX/MSIX)
    try {
        $pkgs = Get-AppxPackage *MSTeams* -AllUsers
        foreach ($pkg in $pkgs) {
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                Write-Status "Removido Teams AppX: $($pkg.PackageFullName)" Green
            }
            catch {
                Write-Status "Falha ao remover Teams AppX: $($_.Exception.Message)" Yellow
            }
        }
    }
    catch {
        Write-Status "Erro ao procurar Teams AppX: $($_.Exception.Message)" Yellow
    }

    # Teams machine-wide / bootstrapper
    try {
        $tb = Get-Command teamsbootstrapper.exe -ErrorAction SilentlyContinue
        if ($tb) {
            Start-Process -FilePath $tb.Source -ArgumentList '-x','-m' -Wait
            Write-Status "Executado: teamsbootstrapper.exe -x -m" Green
        }
        else {
            Write-Status "teamsbootstrapper.exe não encontrado no PATH." DarkYellow
        }
    }
    catch {
        Write-Status "Falha ao executar teamsbootstrapper.exe: $($_.Exception.Message)" Yellow
    }
}
function Remove-OneDrive {
    [CmdletBinding()]
    param(
        [switch]$BlockReuse
    )

    function _emit {
        param(
            [string]$Message,
            [string]$Color = 'Gray'
        )

        if (Get-Command Write-Status -ErrorAction SilentlyContinue) {
            Write-Status $Message $Color
        }
        else {
            Write-Host $Message -ForegroundColor $Color
        }
    }

    _emit "==> Iniciando remoção: OneDrive" Cyan

    # 1) fecha o processo
    try {
        Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        _emit "Processo OneDrive encerrado (se estava em execução)." DarkGray
    }
    catch {
        _emit "Falha ao encerrar OneDrive: $($_.Exception.Message)" Yellow
    }

    # 2) escolhe o setup correto
    $setup = if ([Environment]::Is64BitOperatingSystem) {
        "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    }
    else {
        "$env:SystemRoot\System32\OneDriveSetup.exe"
    }

    if (Test-Path $setup) {
        try {
            Start-Process -FilePath $setup -ArgumentList '/uninstall' -Wait
            _emit "Executado: $setup /uninstall" Green
        }
        catch {
            _emit "Falha ao executar uninstall do OneDrive: $($_.Exception.Message)" Yellow
        }
    }
    else {
        _emit "OneDriveSetup.exe não encontrado em: $setup" Yellow
    }

    # 3) remove atalhos visuais remanescentes
    $shortcuts = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Microsoft OneDrive.lnk",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk",
        "$env:USERPROFILE\Links\OneDrive.lnk"
    )

    foreach ($lnk in $shortcuts) {
        if (Test-Path $lnk) {
            try {
                Remove-Item -Path $lnk -Force
                _emit "Atalho removido: $lnk" Green
            }
            catch {
                _emit "Falha ao remover atalho: $lnk | $($_.Exception.Message)" Yellow
            }
        }
    }

    # 4) tentativa de limpeza visual no Explorer (best effort)
    try {
        $ns = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace'
        if (Test-Path $ns) {
            Get-ChildItem $ns -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $item = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    $name = $item.'(default)'
                    if ($name -eq 'OneDrive' -or $name -eq 'OneDrive - Personal') {
                        Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                        _emit "Entrada visual removida do Explorer: $($_.PSChildName)" Green
                    }
                }
                catch {}
            }
        }
    }
    catch {
        _emit "Falha na limpeza visual do Explorer: $($_.Exception.Message)" Yellow
    }

    # 5) opcional: bloqueia uso futuro via policy suportada
    if ($BlockReuse) {
        try {
            $policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
            if (-not (Test-Path $policyKey)) {
                New-Item -Path $policyKey -Force | Out-Null
            }

            New-ItemProperty `
                -Path $policyKey `
                -Name 'DisableFileSyncNGSC' `
                -PropertyType DWord `
                -Value 1 `
                -Force | Out-Null

            _emit "Policy aplicada: DisableFileSyncNGSC=1" Green
        }
        catch {
            _emit "Falha ao aplicar policy do OneDrive: $($_.Exception.Message)" Yellow
        }
    }

    _emit "==> Fim da remoção do OneDrive" Cyan
}

    # --- Início ---
    $logDir = Split-Path -Path $LogPath -Parent
    if ($logDir -and -not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType File -Force | Out-Null
    }

    if (-not (Test-IsAdmin)) {
        Write-Status "ERRO: execute em PowerShell elevado (Administrador)."
        throw "Execute em PowerShell elevado (Administrador)."
    }

    Write-Status "===== Início da rotina de remoção ====="

    $targets = @(
        @{ Label = 'Copilot';                  Patterns = @('*Microsoft.Copilot*','*Copilot*') },
        @{ Label = 'Family / Family Safety';   Patterns = @('*MicrosoftFamily*','*FamilySafety*') },
        @{ Label = 'Feedback Hub';             Patterns = @('*WindowsFeedbackHub*') },
        @{ Label = 'Ink Handwrite EN';         Patterns = @('*Ink.Handwrite.Main.Store.en*') },
        @{ Label = 'Microsoft Bing';           Patterns = @('*BingSearch*','*Microsoft.Bing*') },
        @{ Label = 'Microsoft Clipchamp';      Patterns = @('*Clipchamp*') },
        @{ Label = 'Microsoft News';           Patterns = @('*BingNews*','*MSNNews*') },
        @{ Label = 'Microsoft To Do';          Patterns = @('*Microsoft.Todos*','*Todo*') },
        @{ Label = 'Outlook (novo)';           Patterns = @('*OutlookForWindows*') },
        @{ Label = 'Power Automate';           Patterns = @('*PowerAutomateDesktop*','*PowerAutomate*') },
        @{ Label = 'Quick Assist';             Patterns = @('*QuickAssist*') },
        @{ Label = 'Solitaire & Casual Games'; Patterns = @('*MicrosoftSolitaireCollection*') },
        @{ Label = 'Sound Recorder';           Patterns = @('*WindowsSoundRecorder*') },
        @{ Label = 'Start Experiences App';    Patterns = @('*StartExperiencesApp*','*Microsoft.StartExperiencesApp*') },
        @{ Label = 'Sticky Notes';             Patterns = @('*MicrosoftStickyNotes*') },
        @{ Label = 'Weather';                  Patterns = @('*BingWeather*','*MSNWeather*') }
        @{ Label = 'Teams';                  Patterns = @(Remove-Teams) }
        @{ Label = 'Teams';                  Patterns = @(Remove-OneDrive) }
    )

    foreach ($target in $targets) {
        Remove-AppxTarget -Label $target.Label -Patterns $target.Patterns
    }

    Remove-OneDrive
    Configure-Edge -Mode $EdgeMode

    Write-Status "===== Fim da rotina de remoção ====="
}

function Start-W11AppRemoval {
    [CmdletBinding()]
    param(
        [string]$LogPath = "$env:ProgramData\Win11Debloat\remocao.log",
        [ValidateSet('BlockWithFirewall','EEAUninstallPolicy','Skip')]
        [string]$EdgeMode = 'BlockWithFirewall',
        [switch]$KeepOpen
    )

    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [Security.Principal.WindowsPrincipal]::new($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Abra o PowerShell como Administrador antes de executar esta função."
    }

    $safeLog = $LogPath -replace "'", "''"

    # pega o CORPO da função atual
    $workerBody = (Get-Item Function:\Invoke-W11AppRemovalWorker).Definition

    # recria a função corretamente em um script temporário
    $scriptContent = @"
function Invoke-W11AppRemovalWorker {
$workerBody
}

Invoke-W11AppRemovalWorker -LogPath '$safeLog' -EdgeMode '$EdgeMode'
"@

    $tempScript = Join-Path $env:TEMP ("W11AppRemoval_{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
    Set-Content -Path $tempScript -Value $scriptContent -Encoding UTF8

    $args = @(
        '-NoProfile',
        '-ExecutionPolicy','Bypass'
    )

    if ($KeepOpen) {
        $args += '-NoExit'
    }

    $args += @('-File', $tempScript)

    $proc = Start-Process `
        -FilePath 'powershell.exe' `
        -ArgumentList $args `
        -PassThru

    [pscustomobject]@{
        Started    = $true
        ProcessId  = $proc.Id
        LogPath    = $LogPath
        ScriptPath = $tempScript
        EdgeMode   = $EdgeMode
    }
}


#---->FIM DOS FUNCTIONS







#MENU MAIN
function Clear-AndHeader {
    Clear-Host
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host "  MENU - Instalador / Ferramentas (PS1) " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host ""
}

#MENU SECONDARY
function Read-Choice {
    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    $ch = $key.Character
    if ([string]::IsNullOrWhiteSpace($ch)) { return "" }
    return $ch.ToString().ToUpperInvariant()
}

function Write-Header([string]$Title) {
    Clear-Host
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host ""
}

function Wait-ConsoleKey {
    #Write-Host ""
    #Write-Host "Pressione qualquer tecla para continuar..." -ForegroundColor DarkGray
    #$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-ActionMenu([string]$Title, [System.Collections.IDictionary]$Actions, [switch]$AllowBack) {
    while ($true) {
        Write-Header $Title

        # mantém a ordem do [ordered] (OrderedDictionary)
        foreach ($entry in $Actions.GetEnumerator()) {
            $k = $entry.Key
            Write-Host "[$k] $($Actions[$k].Label)" -ForegroundColor Yellow
        }

        Write-Host ""
        if ($AllowBack) { Write-Host "[B] Voltar" -ForegroundColor DarkGray }
        Write-Host "[Q] Sair" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host -NoNewline "Escolha: " -ForegroundColor White

        $choice = Read-Choice
        Write-Host $choice

        if ($choice -eq 'Q') { return 'QUIT' }
        if ($AllowBack -and $choice -eq 'B') { return 'BACK' }

        # IMPORTANTe: OrderedDictionary usa .Contains(), não .ContainsKey()
        if ($Actions.Contains($choice)) {
            Write-Header $Title
            try {
                & $Actions[$choice].Run
            } catch {
                Write-Host ""
                Write-Host ("Erro: {0}" -f $_.Exception.Message) -ForegroundColor Red
            }
            Wait-ConsoleKey
        } else {
            Write-Host ""
            Write-Host "Opção inválida." -ForegroundColor Yellow
            Wait-ConsoleKey
        }
    }
}

#FUNÇÕES E ONDE INSTALAR PROGRAMAS
$MenuProgramas = [ordered]@{
    '1' = @{ Label='7-Zip'; Run={ Install-7Zip } }
    '2' = @{ Label='VLC'; Run={ Install-VLC } }
    '3' = @{ Label='MSI Afterburner'; Run={ Install-MsiAfterburner } }
    '4' = @{ Label='RTSS Rivatuner'; Run={ Install-RivaTuner} }
    '5' = @{ Label='Opera GX'; Run={ Install-OperaGXSetup} }
    '6' = @{ Label='Google Chrome'; Run={ Install-GoogleChromeSetup} }
    '7' = @{ Label='Discord'; Run={ Install-Discord} }
    '8' = @{ Label='Telegram'; Run={ Install-Telegram} }
    '9' = @{ Label='TODOS'; Run={ Install-AllProgramas} }
}

$MenuJogos = [ordered]@{
    '1' = @{ Label = 'Steam';      Run = { Install-Steam } }
    '2' = @{ Label = 'Hoyoplay';   Run = { Install-HoYoPlay } }
    '3' = @{ Label = 'RiotClient'; Run = { Install-RiotClient } }
    '4' = @{ Label = 'Epic Games'; Run = { Install-EpicGamesLauncher } }
    '5' = @{ Label='TODOS'; Run={ Install-AllLaunchers} }
}

$MenuTweaks = [ordered]@{
    '1' = @{ Label='Testar IPv6'; Run={ Test-IPv6 } }
    '2' = @{ Label='Recall (Desabilitar/Habilitar)'; Run={ Recall-Manage }}
    '3' = @{ Label='Ativar Windows/Office'; Run={ irm https://get.activated.win | iex }}
    '4' = @{ Label='Winhance'; Run={ Install-Winhance }}
    '5' = @{ Label='Sincronizar Horario NTP Brasil'; Run={ Fix-TimeAndNtp } }
    '6' = @{ Label='Verificar TRIM SSD/NVME'; Run={ Test-TrimAndOfferEnable } }
    '7' = @{ Label='Desabilitar Economia de Energia'; Run={ Set-WorkstationPowerProfile -MonitorTimeoutACMinutes 0 } }
    '8' = @{ Label='CTT WinUtil'; Run={ Install-CTT } }
    '9' = @{ Label='VS AIO (Todos os Visual Studio do Windows)'; Run={ Install-LatestVcRedistFromGitHub } }
    'A' = @{ Label='Ferramentas Nativas do Windows'; Run={ Invoke-WindowsMaintenanceWizard } }
    'C' = @{ Label='Executar DDUCleanUpNvidia'; Run={ Invoke-DDUCleanupNvidia } }
    'D' = @{
    Label = 'Desabilitar Gaming Features (Arrumar VrChat)'
    Run   = {
        Write-Host ""
        Write-Host "1 - Desativar (OFF no usuário atual)"
        Write-Host "2 - Desabilitar (OFF para todos os usuários) [ADMIN]"
        Write-Host "3 - Remover completamente via Registro (IRREVERSIVEL) [ADMIN]"
        $op = Read-Host "Escolha"

        switch ($op) {
            '1' { Set-Gaming-Features -Mode OffCurrentUser }
            '2' { Set-Gaming-Features -Mode OffAllUsers }
            '3' { Set-Gaming-Features -Mode RemoveRegistry }
            default {
                Write-Warning "Opção inválida. Usando 1 - Desativar."
                Set-Gaming-Features -Mode OffCurrentUser
            }
        }
    }
}
      'E' = @{ Label='Remover IA/Bloatware W11 '; Run={ Start-W11AppRemoval } }

}

$MenuDev = [ordered]@{
    '1' = @{ Label='Instalar Essentials Windows Gamming'; Run={ Start-InstallAppsMenuNoWinget -SilentPreferred } }
    '2' = @{ Label='Detectar Driver GPU/iGPU'; Run={ Invoke-GpuDriverAutoInstall -DryRun } }
    '3' = @{ Label='Instalar Driver GPU/iGPU'; Run={ Invoke-GpuDriverAutoInstall -WaitWorker } }
    '4' = @{ Label='Detectar Programas e Atualizar (Nativo Windows)'; Run={ Invoke-ProgramsInventoryAndUpdater -IncludeUwpApps } }
    '5' = @{
  Label='Buscar e Instalar (Winget)'
  Run={
    $term = Read-Host "Termo (ex: 7zip). Enter = interativo"
    if ([string]::IsNullOrWhiteSpace($term)) { $term = $null }

    Write-Host ""
    Write-Host "Modo:"
    Write-Host "  1) Normal"
    Write-Host "  2) Sem Microsoft Store (NoMSStore)"
    Write-Host "  3) Reparar (Repair)"
    $mode = Read-Host "Escolha (1/2/3)"

    $p = @{}
    if ($term) { $p.Term = $term }

    switch ($mode) {
      '2' { $p.NoMSStore = $true }
      '3' { $p.Repair    = $true }
      default { }
    }

    # não atrapalha seu loop:
    Start-WinGetInteligenteWindow @p
  }
}
}

$Categories = [ordered]@{
    '1' = @{ Label='Programas';       Items=$MenuProgramas }
    '2' = @{ Label='Game Launchers';           Items=$MenuJogos }
    '3' = @{ Label='Tweaks/Melhorias';          Items=$MenuTweaks }
    '4' = @{ Label='Em Desenvolvimento/Testes'; Items=$MenuDev }
    '5' = @{ Label='Créditos'; Run={ Test-Creditos } }
}

#MENU PRINCIPAL
while ($true) {
    Write-Header "EasyInstall Enhanced v2"
    Write-Host ""

    foreach ($k in $Categories.Keys) {
        Write-Host "[$k] $($Categories[$k].Label)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "[Q] Sair" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host -NoNewline "Escolha uma categoria: " -ForegroundColor White

    $cat = Read-Choice
    Write-Host $cat

    if ($cat -eq 'Q') { return }

    if ($Categories.Contains($cat)) {
        $selected = $Categories[$cat]

        if ($selected.Contains('Run') -and $null -ne $selected.Run) {
            & $selected.Run
            continue
        }

        if ($selected.Contains('Items') -and $null -ne $selected.Items) {
            $title = "Categoria: $($selected.Label)"
            $result = Show-ActionMenu -Title $title -Actions $selected.Items -AllowBack

            if ($result -eq 'QUIT') { return }
            continue
        }

        Write-Host ""
        Write-Host "Categoria sem ação configurada." -ForegroundColor Yellow
        Wait-ConsoleKey
        continue
    }

    Write-Host ""
    Write-Host "Categoria inválida." -ForegroundColor Yellow
    Wait-ConsoleKey
}