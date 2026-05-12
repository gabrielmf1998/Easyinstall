# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

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
                'WARN' { Write-Host "[WARN]  $msg" -ForegroundColor Blue }
                'ERR'  { Write-Host "[ERRO]  $msg" -ForegroundColor Red }
                default { Write-Host "[INFO]  $msg" -ForegroundColor Blue }
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
            if (-not $exe) { throw "winget.exe nao encontrado. Instale/atualize o 'App Installer'." }

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

    # 1) Parser por posicao (colunas pelo header)
    function _FindHeaderIndex([string[]]$ls) {
        for ($i=0; $i -lt $ls.Count; $i++) {
            if ($ls[$i] -match '^\s*(Name|Nome)\s+(Id|ID)\s+(Version|Vers(a|a)o)') { return $i }
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
        $idxVersion   = _FindCol $header @('Version','Versao','Versao')
        $idxAvailable = _FindCol $header @('Available','Disponivel','Disponivel')
        $idxSource    = _FindCol $header @('Source','Fonte')
        $idxMatch     = _FindCol $header @('Match','Correspondencia','Correspondencia')

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
    # Padrao: Name [2+ espacos] Id [2+ espacos] Version [2+ espacos] (Available)? [2+ espacos] (Source)?
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
            _Write "Reparo concluido." 'OK'
        }

        function _Search([string]$q) {
    # monta args SEM concatenar com '+'
    function _Args([string[]]$head) {
        $l = New-Object 'System.Collections.Generic.List[string]'
        foreach ($x in @($head)) { if ($x -ne $null) { [void]$l.Add([string]$x) } }

        # igual ao manual + auto-aceite
        [void]$l.Add('--accept-source-agreements')

        # se o usuario pediu sem store
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

        # exitcode != 0 => erro real (nao confundir com "nao encontrado")
        if ($r.ExitCode -ne 0) { continue }

        $items = @(_ParseWingetTable $r.Lines)
        if ($items.Count -gt 0) { return $items }

        # Se o proprio winget disser explicitamente que nao achou, podemos parar
        if ($r.Output -match 'No package found|Nenhum pacote encontrado') { return @() }
    }

    # aqui: nao deu pra parsear nada. Nao afirmar "nao encontrado" sem prova.
    Write-Host "[WARN] Nao consegui extrair resultados do winget, mas isso pode ser falha de parsing." -ForegroundColor Blue
    if ($lastOutput) {
        Write-Host "----- Saida bruta do winget -----"
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
            if ($r.ExitCode -eq 0) { _Write "Instalacao concluida." 'OK'; return $true }
            _Write "Falha ao instalar (ExitCode=$($r.ExitCode))." 'ERR'
            $r.Output | Write-Host
            $false
        }

        function _Upgrade([string]$id) {
            $head = New-Object 'System.Collections.Generic.List[string]'
            foreach ($x in @('upgrade','--id',$id,'-e','--accept-package-agreements')) { [void]$head.Add($x) }
            if ($Silent) { [void]$head.Add('--silent') }

            $r = _InvokeWinget (_MakeArgs $head.ToArray())
            if ($r.ExitCode -eq 0) { _Write "Atualizacao concluida." 'OK'; return $true }
            _Write "Falha ao atualizar (ExitCode=$($r.ExitCode))." 'ERR'
            $r.Output | Write-Host
            $false
        }

        function _Uninstall([string]$id) {
            $r = _InvokeWinget (_MakeArgs @('uninstall','--id',$id,'-e'))
            if ($r.ExitCode -eq 0) { _Write "Desinstalacao concluida." 'OK'; return $true }

            if (-not $NoMSStore -and (_LooksLikeMsStoreAgreementIssue $r.Output)) {
                _Write "Falhou por msstore/termos. Tentando '--source winget'..." 'WARN'
                $r2 = _InvokeWinget (_MakeArgs @('uninstall','--id',$id,'-e','--source','winget'))
                if ($r2.ExitCode -eq 0) { _Write "Desinstalacao concluida (fallback)." 'OK'; return $true }
                _Write "Fallback tambem falhou (ExitCode=$($r2.ExitCode))." 'ERR'
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
                $sel = Read-Host "Escolha um numero (0 cancela)"
                if ($sel -match '^\d+$') {
                    $k = [int]$sel
                    if ($k -eq 0) { return $null }
                    if ($k -ge 1 -and $k -le $items.Count) { return $items[$k-1] }
                }
                _Write "Selecao invalida." 'WARN'
            }
        }

        function _Menu([bool]$installed, [bool]$hasUpdate) {
            Write-Host ""
            Write-Host "Acoes:"
            if (-not $installed) {
                Write-Host "  1) Instalar"
                Write-Host "  4) Detalhes"
                Write-Host "  0) Cancelar"
                $valid = @('0','1','4')
            } else {
                if ($hasUpdate) { Write-Host "  2) Atualizar (ha update disponivel)" }
                else { Write-Host "  2) Atualizar (pode nao haver update)" }
                Write-Host "  3) Desinstalar"
                Write-Host "  4) Detalhes"
                Write-Host "  0) Cancelar"
                $valid = @('0','2','3','4')
            }

            while ($true) {
                $a = Read-Host "Escolha"
                if ($valid -contains $a) { return [int]$a }
                _Write "Opcao invalida." 'WARN'
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
            _Write ("Instalado: {0} | {1} | versao: {2}" -f $chosen.Name, $chosen.Id, $installedRows[0].Version) 'OK'
            $availableVersion = $installedRows[0].Available
            if ($availableVersion) { _Write ("Update disponivel: {0}" -f $availableVersion) 'INFO' }
        } else {
            _Write ("Nao instalado: {0} | {1}" -f $chosen.Name, $chosen.Id) 'INFO'
        }

        $action = _Menu -installed:$isInstalled -hasUpdate:([bool]$availableVersion)
        switch ($action) {
            0 { return }
            1 { if (_AskYesNo "Confirmar instalacao de '$($chosen.Id)'?" $true) { _Install $chosen.Id | Out-Null } }
            2 { if (_AskYesNo "Confirmar atualizacao de '$($chosen.Id)'?" $true) { _Upgrade $chosen.Id | Out-Null } }
            3 { if (_AskYesNo "Confirmar desinstalacao de '$($chosen.Id)'?" $false) { _Uninstall $chosen.Id | Out-Null } }
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

    Write-Host "[OK] Nova janela aberta. Script temporario: $tmp"
}


