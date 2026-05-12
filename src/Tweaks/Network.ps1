# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

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
    Write-Host "=== Diagnostico IPv6 ===" -ForegroundColor Blue

    # Binding IPv6 habilitado?
    $ipv6BindingEnabled = $false
    try {
        $ipv6BindingEnabled = [bool](Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop |
                                     Where-Object Enabled -eq $true |
                                     Select-Object -First 1)
    } catch {
        $ipv6BindingEnabled = $false
    }

    # Enderecos IPv6
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
        Write-Host "Enderecos IPv6 encontrados:" -ForegroundColor Blue
        $addrInfo | ForEach-Object {
            $virt = if ($_.IsVirtual) { " (virtual)" } else { "" }
            Write-Host ("- {0,-39} scope={1,-12} if={2} ({3}) /{4}{5}" -f $_.IPAddress, $_.Scope, $_.IfIndex, $_.InterfaceAlias, $_.PrefixLength, $virt) -ForegroundColor DarkGray
        }
    } else {
        Write-Host "Nenhum endereco IPv6 encontrado." -ForegroundColor Blue
    }

    $ipv6Enabled = $ipv6BindingEnabled -or [bool]$raw

    # IMPORTANTISSIMO com StrictMode: sempre forca array
    $addrPhysical = @($addrInfo | Where-Object { $_.IsVirtual -eq $false })
    #$addrVirtual  = @($addrInfo | Where-Object { $_.IsVirtual -eq $true })

    # Scopes em array (nao acessa .Scope direto)
    $scopesPhysical = @($addrPhysical | ForEach-Object { $_.Scope })

    #$hasLinkLocal = ($scopesPhysical -contains "link-local")
    
    #$hasULA       = ($scopesPhysical -contains "unique-local")
    $hasGlobal    = ($scopesPhysical -contains "global")

    $globalObj = $addrPhysical | Where-Object { $_.Scope -eq "global" } | Select-Object -First 1
    $globalIP  = if ($null -ne $globalObj) { $globalObj.IPAddress } else { $null }

    # Rota default IPv6 (::/0), preferindo interface fisica
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
        Write-Host "Sem rota default IPv6 (::/0) em interface fisica." -ForegroundColor Blue
    }

    # Ping IPv6 (ICMP)  so tenta se tiver global + rota (fisica)
    $anyPingOk = $false
    $tc = Get-Command Test-Connection -ErrorAction SilentlyContinue
    $useTargetName = $false
    $useComputerName = $false
    if ($tc) {
        $useTargetName   = $tc.Parameters.ContainsKey("TargetName")
        $useComputerName = $tc.Parameters.ContainsKey("ComputerName")
    }

    Write-Host ""
    Write-Host "Testando conectividade IPv6 (ICMP)..." -ForegroundColor Blue

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
        Write-Host "Pulando ping IPv6: nao ha IPv6 global + rota default (em interface fisica)." -ForegroundColor Blue
    }

    $internetIPv6Ok = ($ipv6Enabled -and $hasGlobal -and $hasDefaultRoute -and $anyPingOk)

    Write-Host ""
    Write-Host "=== RESULTADO ===" -ForegroundColor Blue

    if (-not $ipv6Enabled) {
        Write-Host "Voce nao tem IPV6 Habilitado, verifique seu computador!" -ForegroundColor Red
        pause
        return
    }

    if ($internetIPv6Ok -and $globalIP) {
        Write-Host ("Voce tem IPV6 ele e: {0}" -f $globalIP) -ForegroundColor Green
        pause
        return
    }

    # Habilitado, mas sem IPv6 de internet (global/rota/ping)
    # Se so tiver IPv6 virtual ou so fe80/ULA, cai aqui tambem.
    if (-not $hasGlobal) {
        Write-Host "Voce tem IPV6 no Windows, mas nao recebeu nada! Verifique seu roteador ou fale com seu provedor de internet!" -ForegroundColor Red
        pause
        return
    }

    Write-Host "Voce tem IPV6 habilitado, mas nao recebeu nada! Verifique seu roteador ou fale com seu provedor de internet!" -ForegroundColor Red
    pause
}


