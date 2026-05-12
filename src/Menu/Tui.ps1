# TUI padronizada do EasyInstall.

function New-EasyInstallMenuItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Label,
        [string]$Description = '',
        [scriptblock]$Action = $null,
        [object[]]$Children = @()
    )

    [pscustomobject]@{
        Label       = $Label
        Description = $Description
        Action      = $Action
        Children    = @($Children)
    }
}

function Get-EasyInstallConsoleWidth {
    try {
        return [Math]::Max(92, [Console]::WindowWidth)
    } catch {
        return 100
    }
}

function Get-EasyInstallShortcut {
    param([int]$Index)

    $chars = '123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'.ToCharArray()
    if ($Index -lt $chars.Count) { return $chars[$Index].ToString() }
    return ' '
}

function Format-EasyInstallText {
    param(
        [string]$Text,
        [int]$Width
    )

    if ($null -eq $Text) { $Text = '' }
    if ($Width -lt 4) { return $Text }
    if ($Text.Length -le $Width) { return $Text.PadRight($Width) }
    return ($Text.Substring(0, [Math]::Max(0, $Width - 3)) + '...')
}

function Write-EasyInstallFrameLine {
    param(
        [string]$Text = '',
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    $width = Get-EasyInstallConsoleWidth
    $innerWidth = $width - 4
    Write-Host ('| ' + (Format-EasyInstallText -Text $Text -Width $innerWidth) + ' |') -ForegroundColor $Color
}

function Get-EasyInstallSystemInfo {
    $cache = Get-Variable -Name EasyInstallSystemInfoCache -Scope Script -ErrorAction SilentlyContinue
    if ($cache -and $cache.Value) { return $cache.Value }

    $windows = 'Indisponivel'
    $activated = 'Nao'
    $ipv4 = 'Indisponivel'
    $cpu = 'Indisponivel'
    $gpu = 'Indisponivel'
    $ram = 'Indisponivel'

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $windows = ('{0} Build {1}' -f ([string]$os.Caption).Trim(), $os.BuildNumber)
        $ram = ('{0} GB' -f ([Math]::Round(([double]$os.TotalVisibleMemorySize * 1KB / 1GB), 1)))
    } catch {}

    try {
        $lic = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction Stop |
            Where-Object {
                $_.PartialProductKey -and
                $_.LicenseStatus -eq 1 -and
                (($_.Name + '') -match 'Windows')
            } |
            Select-Object -First 1

        if ($lic) { $activated = 'Sim' }
    } catch {}

    try {
        $addr = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -and
                $_.IPAddress -notlike '127.*' -and
                $_.IPAddress -notlike '169.254.*'
            } |
            Sort-Object InterfaceMetric, InterfaceIndex |
            Select-Object -First 1

        if ($addr) { $ipv4 = [string]$addr.IPAddress }
    } catch {
        try {
            $addr2 = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
                ForEach-Object { $_.IPAddress } |
                Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notlike '127.*' -and $_ -notlike '169.254.*' } |
                Select-Object -First 1

            if ($addr2) { $ipv4 = [string]$addr2 }
        } catch {}
    }

    try {
        $cpuObj = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        if ($cpuObj.Name) { $cpu = ([string]$cpuObj.Name).Trim() }
    } catch {}

    try {
        $gpuNames = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop |
            Where-Object { $_.Name } |
            Select-Object -ExpandProperty Name -Unique)

        if ($gpuNames.Count -gt 0) { $gpu = ($gpuNames -join ' | ') }
    } catch {}

    $script:EasyInstallSystemInfoCache = [pscustomobject]@{
        Windows   = $windows
        Activated = $activated
        IPv4      = $ipv4
        CPU       = $cpu
        GPU       = $gpu
        RAM       = $ram
    }

    return $script:EasyInstallSystemInfoCache
}

function Write-EasyInstallLogo {
    $logo = @(
        ' EEEEE   AAA   SSSS  Y   Y      III  N   N  SSSS  TTTTT   AAA   L      L     ',
        ' E      A   A  S      Y Y        I   NN  N  S       T    A   A  L      L     ',
        ' EEEE   AAAAA   SSS    Y         I   N N N   SSS    T    AAAAA  L      L     ',
        ' E      A   A      S   Y         I   N  NN      S   T    A   A  L      L     ',
        ' EEEEE  A   A  SSSS    Y        III  N   N  SSSS    T    A   A  LLLLL  LLLLL '
    )

    foreach ($line in $logo) {
        Write-EasyInstallFrameLine -Text $line -Color Blue
    }
}

function Write-EasyInstallHeader {
    param(
        [string]$Title,
        [string]$Subtitle = ''
    )

    $width = Get-EasyInstallConsoleWidth
    $line = '+' + ('-' * ($width - 2)) + '+'
    $info = Get-EasyInstallSystemInfo

    try { Clear-Host } catch {}
    Write-Host $line -ForegroundColor Blue
    Write-EasyInstallLogo
    Write-EasyInstallFrameLine -Text $Title -Color White
    if (-not [string]::IsNullOrWhiteSpace($Subtitle)) {
        Write-EasyInstallFrameLine -Text $Subtitle -Color DarkGray
    }
    Write-Host $line -ForegroundColor Blue
    Write-EasyInstallFrameLine -Text ("Versao do Windows: {0}" -f $info.Windows) -Color DarkGray
    Write-EasyInstallFrameLine -Text ("Ativado: {0}    IPV4: {1}" -f $info.Activated, $info.IPv4) -Color DarkGray
    Write-EasyInstallFrameLine -Text ("CPU: {0}" -f $info.CPU) -Color DarkGray
    Write-EasyInstallFrameLine -Text ("GPU: {0}" -f $info.GPU) -Color DarkGray
    Write-EasyInstallFrameLine -Text ("RAM: {0}" -f $info.RAM) -Color DarkGray
    Write-Host $line -ForegroundColor Blue
    Write-Host ''
}

function Invoke-EasyInstallMenuItem {
    param(
        [Parameter(Mandatory)]$Item,
        [string]$ParentTitle
    )

    if ($Item.Children -and @($Item.Children).Count -gt 0) {
        Show-EasyInstallTuiMenu -Title $Item.Label -Subtitle $Item.Description -Items $Item.Children -AllowBack
        return
    }

    if ($null -eq $Item.Action) { return }

    $oldCursor = $true
    try { $oldCursor = [Console]::CursorVisible } catch {}

    try {
        try { [Console]::CursorVisible = $true } catch {}
        Write-EasyInstallHeader -Title $Item.Label -Subtitle $Item.Description
        & $Item.Action
    } catch {
        Write-Host ''
        Write-Host ("Erro: {0}" -f $_.Exception.Message) -ForegroundColor Red
    } finally {
        Write-Host ''
        Read-Host 'Pressione ENTER para voltar ao menu' | Out-Null
        try { [Console]::CursorVisible = $oldCursor } catch {}
    }
}

function Show-EasyInstallTuiMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [string]$Subtitle = '',
        [Parameter(Mandatory)][object[]]$Items,
        [switch]$AllowBack
    )

    $itemsList = @($Items)
    if ($itemsList.Count -eq 0) {
        $itemsList = @((New-EasyInstallMenuItem -Label 'Sem opcoes' -Description 'Nenhuma acao configurada.'))
    }

    $selected = 0
    $oldCursor = $true
    try { $oldCursor = [Console]::CursorVisible } catch {}

    try {
        try { [Console]::CursorVisible = $false } catch {}

        while ($true) {
            Write-EasyInstallHeader -Title $Title -Subtitle $Subtitle

            $shortcutMap = @{}
            for ($i = 0; $i -lt $itemsList.Count; $i++) {
                $item = $itemsList[$i]
                $shortcut = Get-EasyInstallShortcut -Index $i
                if ($shortcut -ne ' ') { $shortcutMap[$shortcut] = $i }

                $prefix = if ($i -eq $selected) { '>' } else { ' ' }
                $description = if ([string]::IsNullOrWhiteSpace($item.Description)) { '' } else { " - $($item.Description)" }
                $line = Format-EasyInstallText -Text (" {0} [{1}] {2}{3}" -f $prefix, $shortcut, $item.Label, $description) -Width (Get-EasyInstallConsoleWidth)

                if ($i -eq $selected) {
                    Write-Host $line -ForegroundColor White -BackgroundColor DarkBlue
                } else {
                    Write-Host $line -ForegroundColor Gray
                }
            }

            Write-Host ''
            if ($AllowBack) {
                Write-Host ' UP/DOWN navega | ENTER seleciona | ESC/BACKSPACE volta | Q sai' -ForegroundColor DarkGray
            } else {
                Write-Host ' UP/DOWN navega | ENTER seleciona | Q sai' -ForegroundColor DarkGray
            }

            $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            $char = $key.Character.ToString().ToUpperInvariant()

            if ($char -eq 'Q') { return }

            if ($AllowBack -and ($key.VirtualKeyCode -eq 27 -or $key.VirtualKeyCode -eq 8)) {
                return
            }

            if ($shortcutMap.ContainsKey($char)) {
                $selected = [int]$shortcutMap[$char]
                Invoke-EasyInstallMenuItem -Item $itemsList[$selected] -ParentTitle $Title
                continue
            }

            switch ($key.VirtualKeyCode) {
                38 {
                    $selected--
                    if ($selected -lt 0) { $selected = $itemsList.Count - 1 }
                }
                40 {
                    $selected++
                    if ($selected -ge $itemsList.Count) { $selected = 0 }
                }
                13 {
                    Invoke-EasyInstallMenuItem -Item $itemsList[$selected] -ParentTitle $Title
                }
            }
        }
    } finally {
        try { [Console]::CursorVisible = $oldCursor } catch {}
    }
}

function Start-EasyInstallTui {
    [CmdletBinding()]
    param()

    $appItems = @(
        (New-EasyInstallMenuItem -Label '7-Zip' -Description 'Instalar compactador' -Action { Install-7Zip }),
        (New-EasyInstallMenuItem -Label 'VLC' -Description 'Instalar player de video' -Action { Install-VLC }),
        (New-EasyInstallMenuItem -Label 'MSI Afterburner' -Description 'Instalar monitor/overclock GPU' -Action { Install-MsiAfterburner }),
        (New-EasyInstallMenuItem -Label 'RTSS Rivatuner' -Description 'Instalar overlay de estatisticas' -Action { Install-RivaTuner }),
        (New-EasyInstallMenuItem -Label 'Opera GX' -Description 'Instalar navegador' -Action { Install-OperaGXSetup }),
        (New-EasyInstallMenuItem -Label 'Google Chrome' -Description 'Instalar navegador' -Action { Install-GoogleChromeSetup }),
        (New-EasyInstallMenuItem -Label 'Discord' -Description 'Instalar comunicador' -Action { Install-Discord }),
        (New-EasyInstallMenuItem -Label 'Telegram' -Description 'Instalar mensageiro' -Action { Install-Telegram }),
        (New-EasyInstallMenuItem -Label 'Todos' -Description 'Instalar todos os programas desta lista' -Action { Install-AllProgramas })
    )

    $launcherItems = @(
        (New-EasyInstallMenuItem -Label 'Steam' -Description 'Instalar launcher Steam' -Action { Install-Steam }),
        (New-EasyInstallMenuItem -Label 'HoYoPlay' -Description 'Instalar launcher HoYoverse' -Action { Install-HoYoPlay }),
        (New-EasyInstallMenuItem -Label 'Riot Client' -Description 'Instalar launcher Riot' -Action { Install-RiotClient }),
        (New-EasyInstallMenuItem -Label 'Epic Games' -Description 'Instalar Epic Games Launcher' -Action { Install-EpicGamesLauncher }),
        (New-EasyInstallMenuItem -Label 'Todos' -Description 'Instalar todos os launchers' -Action { Install-AllLaunchers })
    )

    $gamingItems = @(
        (New-EasyInstallMenuItem -Label 'OFF no usuario atual' -Description 'Desativa otimizacoes/VRR para o usuario atual' -Action { Set-Gaming-Features -Mode OffCurrentUser }),
        (New-EasyInstallMenuItem -Label 'OFF para todos os usuarios' -Description 'Requer Administrador' -Action { Set-Gaming-Features -Mode OffAllUsers }),
        (New-EasyInstallMenuItem -Label 'Remover entradas do Registro' -Description 'Modo mais forte, cria backup .reg' -Action { Set-Gaming-Features -Mode RemoveRegistry })
    )

    $systemItems = @(
        (New-EasyInstallMenuItem -Label 'Testar IPv6' -Description 'Diagnostico de endereco, rota e ping' -Action { Test-IPv6 }),
        (New-EasyInstallMenuItem -Label 'Recall' -Description 'Ver, habilitar, desabilitar ou remover Recall' -Action { Recall-Manage }),
        (New-EasyInstallMenuItem -Label 'Ativar Windows/Office' -Description 'Executa script remoto get.activated.win' -Action { irm https://get.activated.win | iex }),
        (New-EasyInstallMenuItem -Label 'Sincronizar horario NTP Brasil' -Description 'Configura fuso e W32Time' -Action { Fix-TimeAndNtp }),
        (New-EasyInstallMenuItem -Label 'Detectar driver GPU/iGPU' -Description 'Inventario sem instalar' -Action { Invoke-GpuDriverAutoInstall -DryRun }),
        (New-EasyInstallMenuItem -Label 'Instalar driver GPU/iGPU' -Description 'NVIDIA, AMD, Intel ou VMware Tools' -Action { Invoke-GpuDriverAutoInstall -WaitWorker }),
        (New-EasyInstallMenuItem -Label 'Remover IA/Bloatware W11' -Description 'Remove AppX, OneDrive e trata Edge' -Action { Start-W11AppRemoval })
    )

    $improvementItems = @(
        (New-EasyInstallMenuItem -Label 'Verificar TRIM SSD/NVME' -Description 'Consulta e oferece habilitar TRIM' -Action { Test-TrimAndOfferEnable }),
        (New-EasyInstallMenuItem -Label 'Desabilitar economia de energia' -Description 'Alto desempenho, sem hibernacao e monitor sempre ligado' -Action { Set-WorkstationPowerProfile -MonitorTimeoutACMinutes 0 }),
        (New-EasyInstallMenuItem -Label 'Gaming Features / VRChat' -Description 'Padroniza HAGS, VRR e otimizacoes de jogos' -Children $gamingItems),
        (New-EasyInstallMenuItem -Label 'Winhance' -Description 'Executa instalador remoto' -Action { Install-Winhance }),
        (New-EasyInstallMenuItem -Label 'CTT WinUtil' -Description 'Executa script remoto christitus.com/win' -Action { Install-CTT })
    )

    $programItems = @(
        (New-EasyInstallMenuItem -Label 'Aplicativos' -Description '7-Zip, VLC, navegadores e comunicadores' -Children $appItems),
        (New-EasyInstallMenuItem -Label 'Game Launchers' -Description 'Steam, HoYoPlay, Riot e Epic Games' -Children $launcherItems),
        (New-EasyInstallMenuItem -Label 'VC Redist AIO' -Description 'Baixa release do projeto abbodi1406/vcredist' -Action { Install-LatestVcRedistFromGitHub }),
        (New-EasyInstallMenuItem -Label 'Essentials Windows Gaming' -Description 'Discord, Steam, Chrome/Opera/Telegram sem winget' -Action { Start-InstallAppsMenuNoWinget -SilentPreferred }),
        (New-EasyInstallMenuItem -Label 'Buscar e instalar via winget' -Description 'Pesquisa, instala, atualiza ou remove por ID' -Action {
            $term = Read-Host 'Termo (ex: 7zip). Enter = interativo'
            if ([string]::IsNullOrWhiteSpace($term)) { $term = $null }

            Write-Host ''
            Write-Host 'Modo:'
            Write-Host '  1) Normal'
            Write-Host '  2) Sem Microsoft Store (NoMSStore)'
            Write-Host '  3) Reparar (Repair)'
            $mode = Read-Host 'Escolha (1/2/3)'

            $p = @{}
            if ($term) { $p.Term = $term }

            switch ($mode) {
                '2' { $p.NoMSStore = $true }
                '3' { $p.Repair = $true }
                default { }
            }

            Start-WinGetInteligenteWindow @p
        })
    )

    $maintenanceItems = @(
        (New-EasyInstallMenuItem -Label 'Ferramentas nativas do Windows' -Description 'SFC, DISM, CHKDSK, Storage Sense e atalhos' -Action { Invoke-WindowsMaintenanceWizard }),
        (New-EasyInstallMenuItem -Label 'Detectar programas e atualizar' -Description 'Inventario local e upgrades por winget' -Action { Invoke-ProgramsInventoryAndUpdater -IncludeUwpApps }),
        (New-EasyInstallMenuItem -Label 'DDU Cleanup NVIDIA' -Description 'Baixa DDU e limpa driver NVIDIA' -Action { Invoke-DDUCleanupNvidia })
    )

    $mainItems = @(
        (New-EasyInstallMenuItem -Label 'Sistema' -Description 'Windows, drivers, rede, ativacao, Recall e debloat' -Children $systemItems),
        (New-EasyInstallMenuItem -Label 'Melhorias' -Description 'Energia, TRIM, Winhance, CTT e ajustes para jogos' -Children $improvementItems),
        (New-EasyInstallMenuItem -Label 'Programas' -Description 'Aplicativos, launchers, VC Redist e winget' -Children $programItems),
        (New-EasyInstallMenuItem -Label 'Manutencao' -Description 'Ferramentas nativas, inventario, updates e DDU' -Children $maintenanceItems),
        (New-EasyInstallMenuItem -Label 'Creditos' -Description 'Informacoes do projeto' -Action { Test-Creditos })
    )

    Show-EasyInstallTuiMenu -Title 'Menu principal' -Subtitle 'Use setas, ENTER ou atalhos numericos/letras.' -Items $mainItems
}
