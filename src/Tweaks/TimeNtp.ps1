# Ajuste de horario e NTP para Windows 11.

function Fix-TimeAndNtp {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Alias('NtpServer')]
        [string[]]$NtpServers = @(
            'a.st1.ntp.br',
            'b.st1.ntp.br',
            'c.st1.ntp.br',
            'pool.ntp.br'
        ),

        [string]$TimeZoneId = 'E. South America Standard Time',
        [ValidateRange(900, 604800)]
        [int]$PollIntervalSeconds = 3600,
        [ValidateSet('Manual','Automatic')]
        [string]$StartupType = 'Manual',
        [bool]$UpdateInternetTimeUi = $true,
        [switch]$SkipTimeZone,
        [switch]$SkipStripChart
    )

    function Write-NtpInfo {
        param(
            [string]$Message,
            [ConsoleColor]$Color = [ConsoleColor]::Gray
        )
        Write-Host $Message -ForegroundColor $Color
    }

    function Test-NtpAdmin {
        try {
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            $p  = New-Object Security.Principal.WindowsPrincipal($id)
            return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch {
            return $false
        }
    }

    function Invoke-NtpCommand {
        param(
            [Parameter(Mandatory)][string]$FilePath,
            [Parameter(Mandatory)][string[]]$Arguments,
            [switch]$IgnoreExitCode
        )

        Write-NtpInfo ("`n> {0} {1}" -f $FilePath, ($Arguments -join ' ')) Blue
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE

        foreach ($line in @($output)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$line)) {
                Write-NtpInfo ("  {0}" -f $line) Gray
            }
        }

        if ($exitCode -ne 0 -and -not $IgnoreExitCode) {
            throw ("Comando falhou: {0} {1} | ExitCode={2}" -f $FilePath, ($Arguments -join ' '), $exitCode)
        }

        [pscustomobject]@{
            ExitCode = $exitCode
            Output   = ($output -join [Environment]::NewLine)
        }
    }

    function Get-NtpCleanServers {
        param([string[]]$Servers)

        $clean = New-Object System.Collections.Generic.List[string]
        foreach ($server in @($Servers)) {
            if ([string]::IsNullOrWhiteSpace($server)) { continue }

            $value = $server.Trim()
            if ($value -match ',') { $value = ($value -split ',', 2)[0].Trim() }
            if ([string]::IsNullOrWhiteSpace($value)) { continue }

            if ($value -notmatch '^[A-Za-z0-9\.\-:]+$') {
                throw "Servidor NTP invalido: $server"
            }

            if (-not $clean.Contains($value)) {
                [void]$clean.Add($value)
            }
        }

        if ($clean.Count -eq 0) {
            throw "Informe pelo menos um servidor NTP valido."
        }

        return $clean.ToArray()
    }

    function Set-NtpTimeZone {
        param([string]$Id)

        if ([string]::IsNullOrWhiteSpace($Id)) { return }

        $current = Get-TimeZone -ErrorAction Stop
        Write-NtpInfo ("Fuso atual: {0} (UTC{1})" -f $current.Id, $current.BaseUtcOffset) DarkGray

        if ($current.Id -eq $Id) {
            Write-NtpInfo "Fuso horario ja esta correto." Green
            return
        }

        $available = Get-TimeZone -ListAvailable | Where-Object { $_.Id -eq $Id } | Select-Object -First 1
        if (-not $available) {
            throw "Fuso horario nao encontrado neste Windows: $Id"
        }

        if ($PSCmdlet.ShouldProcess("Windows Time Zone", "Set-TimeZone -Id $Id")) {
            Set-TimeZone -Id $Id -ErrorAction Stop
        }

        Write-NtpInfo ("Fuso horario configurado: {0}" -f $Id) Green
    }

    function Wait-WindowsTimeServiceStatus {
        param(
            [ValidateSet('Running','Stopped')]
            [string]$ExpectedStatus,
            [int]$TimeoutSeconds = 25
        )

        if ($WhatIfPreference) { return $true }

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        do {
            $svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue
            if ($svc -and ([string]$svc.Status) -eq $ExpectedStatus) { return $true }
            Start-Sleep -Milliseconds 500
        } while ((Get-Date) -lt $deadline)

        return $false
    }

    function Write-WindowsTimeDiagnostics {
        Write-NtpInfo "`nDiagnostico do W32Time:" Blue

        Invoke-NtpCommand -FilePath 'sc.exe' -Arguments @('queryex', 'w32time') -IgnoreExitCode | Out-Null
        Invoke-NtpCommand -FilePath 'sc.exe' -Arguments @('qc', 'w32time') -IgnoreExitCode | Out-Null

        try {
            $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} -MaxEvents 20 -ErrorAction Stop |
                Where-Object { $_.Message -match 'W32Time|Windows Time' } |
                Select-Object -First 5)

            if ($events.Count -gt 0) {
                Write-NtpInfo "`nEventos recentes relacionados:" Blue
                foreach ($event in $events) {
                    Write-NtpInfo ("  {0} | Id {1} | {2}" -f $event.TimeCreated, $event.Id, (($event.Message -replace '\s+', ' ').Trim())) Gray
                }
            }
        } catch {}
    }

    function Repair-WindowsTimeRegistration {
        Write-NtpInfo "`nTentando reparo controlado do registro do servico W32Time..." Blue

        if (-not $PSCmdlet.ShouldProcess("W32Time", "w32tm /unregister + /register")) {
            return
        }

        Invoke-NtpCommand -FilePath 'sc.exe' -Arguments @('stop', 'w32time') -IgnoreExitCode | Out-Null
        Start-Sleep -Seconds 2

        Invoke-NtpCommand -FilePath 'w32tm.exe' -Arguments @('/unregister') -IgnoreExitCode | Out-Null
        Start-Sleep -Seconds 2
        Invoke-NtpCommand -FilePath 'w32tm.exe' -Arguments @('/register') | Out-Null
        Start-Sleep -Seconds 2

        try {
            Set-Service -Name W32Time -StartupType $StartupType -ErrorAction Stop
        } catch {
            $scStart = if ($StartupType -eq 'Automatic') { 'auto' } else { 'demand' }
            Invoke-NtpCommand -FilePath 'sc.exe' -Arguments @('config', 'w32time', 'start=', $scStart) -IgnoreExitCode | Out-Null
        }
    }

    function Start-WindowsTimeService {
        param([switch]$AllowRepair)

        $svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue
        if (-not $svc) {
            Repair-WindowsTimeRegistration
            $svc = Get-Service -Name W32Time -ErrorAction Stop
        }

        if ($svc.Status -eq 'Running') { return $true }

        if ($svc.Status -eq 'StartPending') {
            Write-NtpInfo "Servico W32Time esta em START_PENDING. Aguardando estabilizar..." Blue
            if (Wait-WindowsTimeServiceStatus -ExpectedStatus Running -TimeoutSeconds 20) { return $true }
        }

        if ($PSCmdlet.ShouldProcess("W32Time", "Start-Service")) {
            try {
                Start-Service -Name W32Time -ErrorAction Stop
            } catch {
                Write-NtpInfo ("Start-Service falhou: {0}" -f $_.Exception.Message) Blue
                Invoke-NtpCommand -FilePath 'sc.exe' -Arguments @('start', 'w32time') -IgnoreExitCode | Out-Null
            }
        }

        if (Wait-WindowsTimeServiceStatus -ExpectedStatus Running -TimeoutSeconds 25) { return $true }

        if ($AllowRepair) {
            Repair-WindowsTimeRegistration
            Invoke-NtpCommand -FilePath 'sc.exe' -Arguments @('start', 'w32time') -IgnoreExitCode | Out-Null
            if (Wait-WindowsTimeServiceStatus -ExpectedStatus Running -TimeoutSeconds 25) { return $true }
        }

        return $false
    }

    function Restart-WindowsTimeServiceSafe {
        $svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue

        if ($svc -and $svc.Status -eq 'Running') {
            if ($PSCmdlet.ShouldProcess("W32Time", "Stop-Service")) {
                try {
                    Stop-Service -Name W32Time -Force -ErrorAction Stop
                } catch {
                    Write-NtpInfo ("Stop-Service falhou: {0}" -f $_.Exception.Message) Blue
                    Invoke-NtpCommand -FilePath 'sc.exe' -Arguments @('stop', 'w32time') -IgnoreExitCode | Out-Null
                }
            }
            [void](Wait-WindowsTimeServiceStatus -ExpectedStatus Stopped -TimeoutSeconds 15)
        }

        return (Start-WindowsTimeService -AllowRepair)
    }

    function Ensure-WindowsTimeService {
        $svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue

        if (-not $svc) {
            Repair-WindowsTimeRegistration
        }

        if ($PSCmdlet.ShouldProcess("W32Time", "Set-Service -StartupType $StartupType")) {
            try {
                Set-Service -Name W32Time -StartupType $StartupType -ErrorAction Stop
            } catch {
                $scStart = if ($StartupType -eq 'Automatic') { 'auto' } else { 'demand' }
                Invoke-NtpCommand -FilePath 'sc.exe' -Arguments @('config', 'w32time', 'start=', $scStart) -IgnoreExitCode | Out-Null
            }
        }

        if (-not (Start-WindowsTimeService -AllowRepair)) {
            Write-WindowsTimeDiagnostics
            throw "Servico W32Time nao iniciou. Veja o diagnostico acima."
        }
    }

    function Set-NtpRegistry {
        param(
            [string]$PeerList,
            [int]$PollSeconds
        )

        $paramPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
        $clientPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'

        if ($PSCmdlet.ShouldProcess("W32Time registry", "Configurar parametros NTP")) {
            New-Item -Path $paramPath -Force | Out-Null
            New-Item -Path $clientPath -Force | Out-Null

            New-ItemProperty -Path $paramPath -Name Type -PropertyType String -Value 'NTP' -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $paramPath -Name NtpServer -PropertyType String -Value $PeerList -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $clientPath -Name Enabled -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $clientPath -Name SpecialPollInterval -PropertyType DWord -Value $PollSeconds -Force -ErrorAction Stop | Out-Null
        }
    }

    function Set-NtpInternetTimeUi {
        param([string[]]$Servers)

        if (-not $UpdateInternetTimeUi) { return }

        if (-not $PSCmdlet.ShouldProcess("Internet Time UI", "Atualizar lista de servidores")) {
            return
        }

        $subKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers'
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($subKey)
        if (-not $regKey) { return }

        try {
            $names = @($regKey.GetValueNames())
            $nextIndex = 1
            foreach ($name in $names) {
                if ($name -match '^\d+$') {
                    $nextIndex = [Math]::Max($nextIndex, ([int]$name + 1))
                }
            }

            $firstIndex = $null
            foreach ($server in $Servers) {
                $existing = $null
                foreach ($name in $names) {
                    if ($name -match '^\d+$' -and ([string]$regKey.GetValue($name, '') -ieq $server)) {
                        $existing = $name
                        break
                    }
                }

                if ($existing) {
                    if ($null -eq $firstIndex) { $firstIndex = $existing }
                    continue
                }

                $indexText = [string]$nextIndex
                $regKey.SetValue($indexText, $server, [Microsoft.Win32.RegistryValueKind]::String)
                if ($null -eq $firstIndex) { $firstIndex = $indexText }
                $nextIndex++
            }

            if ($firstIndex) {
                $regKey.SetValue('', $firstIndex, [Microsoft.Win32.RegistryValueKind]::String)
            }
        } finally {
            $regKey.Close()
        }
    }

    function Write-NtpPolicyWarning {
        $policyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time'
        if (Test-Path $policyRoot) {
            Write-NtpInfo "Aviso: existem policies em HKLM:\SOFTWARE\Policies\Microsoft\W32Time. GPO/MDM pode sobrescrever a configuracao." Blue
        }

        try {
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            if ($cs.PartOfDomain) {
                Write-NtpInfo "Aviso: este PC esta em dominio. O dominio pode controlar a sincronizacao de horario." Blue
            }
        } catch {}
    }

    function Write-NtpFinalStatus {
        param([string]$PrimaryServer)

        Write-NtpInfo "`nStatus do Windows Time:" Blue
        Invoke-NtpCommand -FilePath 'w32tm.exe' -Arguments @('/query', '/status') -IgnoreExitCode | Out-Null

        Write-NtpInfo "`nFonte atual:" Blue
        Invoke-NtpCommand -FilePath 'w32tm.exe' -Arguments @('/query', '/source') -IgnoreExitCode | Out-Null

        Write-NtpInfo "`nPeers configurados:" Blue
        Invoke-NtpCommand -FilePath 'w32tm.exe' -Arguments @('/query', '/peers') -IgnoreExitCode | Out-Null

        if (-not $SkipStripChart) {
            Write-NtpInfo "`nTeste NTP rapido:" Blue
            Invoke-NtpCommand -FilePath 'w32tm.exe' -Arguments @('/stripchart', "/computer:$PrimaryServer", '/samples:3', '/dataonly') -IgnoreExitCode | Out-Null
        }
    }

    Write-Host ""
    Write-NtpInfo "=== SINCRONIZAR HORARIO (WINDOWS 11 / NTP) ===" Blue

    if (-not (Test-NtpAdmin) -and -not $WhatIfPreference) {
        throw "Execute em modo Administrador."
    } elseif (-not (Test-NtpAdmin)) {
        Write-NtpInfo "Modo WhatIf sem Administrador: nenhuma alteracao sera aplicada." Blue
    }

    $servers = Get-NtpCleanServers -Servers $NtpServers
    $peerList = (($servers | ForEach-Object { "$_,0x9" }) -join ' ')
    $primaryServer = $servers[0]

    Write-NtpInfo ("Servidores NTP: {0}" -f ($servers -join ', ')) DarkGray
    Write-NtpInfo ("Intervalo de consulta: {0} segundos" -f $PollIntervalSeconds) DarkGray
    Write-NtpInfo ("Startup do W32Time: {0}" -f $StartupType) DarkGray

    Write-NtpPolicyWarning

    if (-not $SkipTimeZone) {
        Set-NtpTimeZone -Id $TimeZoneId
    }

    Ensure-WindowsTimeService

    Write-NtpInfo "`nConfigurando Windows Time..." Blue
    if ($PSCmdlet.ShouldProcess("W32Time", "Configurar NTP manual")) {
        Invoke-NtpCommand -FilePath 'w32tm.exe' -Arguments @(
            '/config',
            "/manualpeerlist:$peerList",
            '/syncfromflags:manual',
            '/reliable:no',
            '/update'
        ) | Out-Null
    }

    Set-NtpRegistry -PeerList $peerList -PollSeconds $PollIntervalSeconds
    Set-NtpInternetTimeUi -Servers $servers

    Write-NtpInfo "`nReiniciando W32Time..." Blue
    if (-not (Restart-WindowsTimeServiceSafe)) {
        Write-WindowsTimeDiagnostics
        throw "Falha ao iniciar o servico Windows Time (W32Time)."
    }

    Write-NtpInfo "`nSolicitando ressincronizacao..." Blue
    if ($PSCmdlet.ShouldProcess("W32Time", "w32tm /resync /rediscover")) {
        $resync = Invoke-NtpCommand -FilePath 'w32tm.exe' -Arguments @('/resync', '/rediscover') -IgnoreExitCode
        if ($resync.ExitCode -ne 0) {
            Write-NtpInfo "Primeira tentativa falhou. Tentando w32tm /resync..." Blue
            Invoke-NtpCommand -FilePath 'w32tm.exe' -Arguments @('/resync') -IgnoreExitCode | Out-Null
        }
    }

    Write-NtpFinalStatus -PrimaryServer $primaryServer

    Write-Host ""
    Write-NtpInfo "Concluido. Se a fonte ainda aparecer como Local CMOS Clock, aguarde alguns segundos e execute a opcao novamente." Green
    Write-NtpInfo "Se o teste NTP der timeout, verifique DNS, internet e bloqueio de UDP 123 no roteador/firewall." DarkGray
}
