# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

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

        Write-Status "==> Iniciando remocao: $Label"

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
        Write-Status "==> Iniciando remocao: OneDrive"

        try {
            Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Status "Nao foi possivel encerrar o processo do OneDrive: $($_.Exception.Message)"
        }

        $setupCandidates = @(
            "$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
            "$env:SystemRoot\System32\OneDriveSetup.exe"
        ) | Where-Object { Test-Path $_ }

        if (-not $setupCandidates) {
            Write-Status "OneDriveSetup.exe nao encontrado."
            return
        }

        $setup = $setupCandidates[0]

        try {
            Start-Process -FilePath $setup -ArgumentList '/uninstall' -WindowStyle Hidden -Wait
            Write-Status "Comando de desinstalacao do OneDrive executado: $setup /uninstall"
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

                    Write-Status "Policy do Edge configurada: Uninstall=1. (So tera efeito em dispositivo ingressado em dominio e no EEA.)"
                }
                catch {
                    Write-Status "Falha ao configurar policy de desinstalacao do Edge: $($_.Exception.Message)"
                }
            }

            'BlockWithFirewall' {
                try {
                    Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Status "Nao foi possivel encerrar o Edge: $($_.Exception.Message)"
                }

                $edgeExecutables = @(
                    "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
                    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
                ) | Where-Object { Test-Path $_ } | Select-Object -Unique

                if (-not $edgeExecutables) {
                    Write-Status "msedge.exe nao encontrado; bloqueio por firewall ignorado."
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
                            Write-Status "Regra ja existia: $outName"
                        }

                        if (-not (Get-NetFirewallRule -DisplayName $inName -ErrorAction SilentlyContinue)) {
                            New-NetFirewallRule -DisplayName $inName -Direction Inbound -Program $exe -Action Block | Out-Null
                            Write-Status "Regra criada: $inName -> $exe"
                        }
                        else {
                            Write-Status "Regra ja existia: $inName"
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
    Write-Status "==> Iniciando remocao: Teams" Blue

    # New Teams (AppX/MSIX)
    try {
        $pkgs = Get-AppxPackage *MSTeams* -AllUsers
        foreach ($pkg in $pkgs) {
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                Write-Status "Removido Teams AppX: $($pkg.PackageFullName)" Green
            }
            catch {
                Write-Status "Falha ao remover Teams AppX: $($_.Exception.Message)" Blue
            }
        }
    }
    catch {
        Write-Status "Erro ao procurar Teams AppX: $($_.Exception.Message)" Blue
    }

    # Teams machine-wide / bootstrapper
    try {
        $tb = Get-Command teamsbootstrapper.exe -ErrorAction SilentlyContinue
        if ($tb) {
            Start-Process -FilePath $tb.Source -ArgumentList '-x','-m' -Wait
            Write-Status "Executado: teamsbootstrapper.exe -x -m" Green
        }
        else {
            Write-Status "teamsbootstrapper.exe nao encontrado no PATH." DarkBlue
        }
    }
    catch {
        Write-Status "Falha ao executar teamsbootstrapper.exe: $($_.Exception.Message)" Blue
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

    _emit "==> Iniciando remocao: OneDrive" Blue

    # 1) fecha o processo
    try {
        Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        _emit "Processo OneDrive encerrado (se estava em execucao)." DarkGray
    }
    catch {
        _emit "Falha ao encerrar OneDrive: $($_.Exception.Message)" Blue
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
            _emit "Falha ao executar uninstall do OneDrive: $($_.Exception.Message)" Blue
        }
    }
    else {
        _emit "OneDriveSetup.exe nao encontrado em: $setup" Blue
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
                _emit "Falha ao remover atalho: $lnk | $($_.Exception.Message)" Blue
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
        _emit "Falha na limpeza visual do Explorer: $($_.Exception.Message)" Blue
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
            _emit "Falha ao aplicar policy do OneDrive: $($_.Exception.Message)" Blue
        }
    }

    _emit "==> Fim da remocao do OneDrive" Blue
}

    # --- Inicio ---
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

    Write-Status "===== Inicio da rotina de remocao ====="

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

    Write-Status "===== Fim da rotina de remocao ====="
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
        throw "Abra o PowerShell como Administrador antes de executar esta funcao."
    }

    $safeLog = $LogPath -replace "'", "''"

    # pega o CORPO da funcao atual
    $workerBody = (Get-Item Function:\Invoke-W11AppRemovalWorker).Definition

    # recria a funcao corretamente em um script temporario
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


