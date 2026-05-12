# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Disable-WingetMsStoreSource {
    [CmdletBinding()]
    param(
        [switch]$Quiet
    )

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { throw "winget nao encontrado (App Installer ausente ou alias desativado)." }

    # Em alguns builds o comando pode variar, entao protegemos com try/catch
    $src = $null
    try {
        $src = & $winget.Source source list 2>$null
    } catch {
        $src = $null
    }

    if (-not $src) {
        if (-not $Quiet) {
            Write-Host "Nao consegui ler 'winget source list'. Pulando ajuste do msstore." -ForegroundColor Blue
        }
        return
    }

    $text = ($src -join "`n")

    # Se nem existe, nada a fazer
    if ($text -notmatch '(?im)^\s*msstore\b') {
        if (-not $Quiet) {
            Write-Host "Source msstore nao existe nesta maquina. OK." -ForegroundColor DarkGray
        }
        return
    }

    # Heuristica: se estiver disabled/desabilitado, nao mexe
    if ($text -match '(?im)^\s*msstore\b.*\b(disabled|desabilitado)\b') {
        if (-not $Quiet) {
            Write-Host "Source msstore ja esta desabilitada. OK." -ForegroundColor DarkGray
        }
        return
    }

    # Tenta desabilitar
    if (-not $Quiet) {
        Write-Host "Desabilitando source msstore (evita erro de certificado)..." -ForegroundColor Blue
    }

    try {
        & $winget.Source source disable msstore | Out-Null
        if (-not $Quiet) {
            Write-Host "msstore desabilitado." -ForegroundColor Green
        }
    } catch {
        if (-not $Quiet) {
            Write-Host ("Falha ao desabilitar msstore: {0}" -f $_.Exception.Message) -ForegroundColor Blue
        }
    }
}
try {
    Disable-WingetMsStoreSource -Quiet
} catch {
    # A TUI deve abrir mesmo quando winget ainda nao existe.
}

#VAI EXECUTAR WINGET QUANDO ACIONADO
function Invoke-Winget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Args,
        [string]$SuccessName,
        [switch]$VerboseOutput
    )

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { throw "winget nao encontrado (App Installer ausente ou alias desativado)." }

    $pkgName = if ([string]::IsNullOrWhiteSpace($SuccessName)) { 'Pacote' } else { $SuccessName.Trim() }

    # Sempre evitar msstore: forca --source winget se nao existir
    if (-not ($Args -contains '--source')) {
        $Args = $Args + @('--source','winget')
    }

    # Executa e captura tudo, mas so mostra se der erro ou se -VerboseOutput
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
        Write-Host (" {0}" -f $msg) -ForegroundColor $color
    }
    function Warn([string]$msg) {
        Write-Host ""
        Write-Host ("  {0}" -f $msg) -ForegroundColor Blue
    }

    # Exit 0 = ok
    if ($exitCode -eq 0) {
        if ($text -match 'Found an existing package already installed') {
            Warn ("{0}: ja estava instalado." -f $pkgName)
        } elseif ($text -match 'Successfully installed|Installed successfully|Installation successful') {
            Ok ("{0}: instalado com sucesso." -f $pkgName)
        } else {
            Ok ("{0}: concluido." -f $pkgName)
        }
        return
    }

    # Sem upgrade / nao aplicavel (winget retorna !=0 mesmo sendo ok)
    $NO_APPLICABLE_UPDATE = @(-1978335189, -1978335188) # 0x8A15002B/0x8A15002C
    if ($NO_APPLICABLE_UPDATE -contains $exitCode) {
        if ($text -match 'Found an existing package already installed') {
            Warn ("{0}: ja instalado e sem atualizacao disponivel." -f $pkgName)
        } else {
            Warn ("{0}: nenhuma atualizacao disponivel." -f $pkgName)
        }
        return
    }

    # 3010 = reboot necessario (considera sucesso)
    if ($exitCode -eq 3010) {
        Warn ("{0}: instalado, mas e necessario reiniciar." -f $pkgName)
        return
    }

    # Se chegou aqui: erro real -> mostra detalhes
    Write-Host ""
    Write-Host (" {0}: falhou (exitcode={1})" -f $pkgName, $exitCode) -ForegroundColor Red
    if ($outputLines) {
        Write-Host ""
        $outputLines | ForEach-Object { Write-Host $_ }
    }
    throw ("winget falhou (exitcode={0})." -f $exitCode)
}


