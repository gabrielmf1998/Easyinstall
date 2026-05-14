#requires -Version 5.1

param(
    [string]$Repository = 'gabrielmf1998/Easyinstall',
    [string]$Branch = 'main'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Enable-EasyInstallExecutionPolicyForCurrentProcess {
    try {
        $env:PSExecutionPolicyPreference = 'Bypass'

        if ((Get-ExecutionPolicy -Scope Process -ErrorAction SilentlyContinue) -ne 'Bypass') {
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        }
    } catch {
        Write-Host ("Aviso: nao consegui ajustar a politica de execucao deste processo: {0}" -f $_.Exception.Message) -ForegroundColor Blue
    }
}

function Test-EasyInstallRepositoryRoot {
    param([Parameter(Mandatory)][string]$Path)

    return (
        (Test-Path -LiteralPath (Join-Path $Path 'src\Core\Bootstrap.ps1')) -and
        (Test-Path -LiteralPath (Join-Path $Path 'src\EasyInstall.Loader.ps1'))
    )
}

function Invoke-EasyInstallDownloadWithAnimation {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile
    )

    $frames = @('|', '/', '-', '\')
    $job = Start-Job -ScriptBlock {
        param($DownloadUri, $DownloadPath)

        $ProgressPreference = 'SilentlyContinue'
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
        Invoke-WebRequest -Uri $DownloadUri -OutFile $DownloadPath -UseBasicParsing -ErrorAction Stop
    } -ArgumentList $Uri, $OutFile

    $oldCursor = $true
    try { $oldCursor = [Console]::CursorVisible; [Console]::CursorVisible = $false } catch {}

    try {
        $i = 0
        while ($job.State -eq 'Running') {
            $frame = $frames[$i % $frames.Count]
            Write-Host ("`r{0} Baixando EasyInstall para a pasta TEMP do Windows..." -f $frame) -ForegroundColor Blue -NoNewline
            Start-Sleep -Milliseconds 150
            $i++
        }

        Receive-Job -Job $job -ErrorAction Stop | Out-Null
        Write-Host "`rOK Download concluido na pasta TEMP do Windows.           " -ForegroundColor Blue
    } finally {
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        try { [Console]::CursorVisible = $oldCursor } catch {}
    }
}

function Get-EasyInstallRepositoryFromGitHub {
    param(
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$Branch
    )

    $safeRepositoryName = ($Repository -replace '[\\/:*?"<>|]', '_')
    $safeBranchName = ($Branch -replace '[\\/:*?"<>|]', '_')
    $windowsTemp = [IO.Path]::GetTempPath()
    $downloadRoot = Join-Path $windowsTemp ("EasyInstall_{0}_{1}" -f $safeRepositoryName, $safeBranchName)
    $zipPath = Join-Path $windowsTemp ("EasyInstall_{0}_{1}.zip" -f $safeRepositoryName, $safeBranchName)
    $zipUrl = "https://github.com/$Repository/archive/refs/heads/$Branch.zip"

    if (Test-Path -LiteralPath $downloadRoot) {
        Remove-Item -LiteralPath $downloadRoot -Recurse -Force
    }

    New-Item -Path $downloadRoot -ItemType Directory -Force | Out-Null

    Invoke-EasyInstallDownloadWithAnimation -Uri $zipUrl -OutFile $zipPath

    Expand-Archive -LiteralPath $zipPath -DestinationPath $downloadRoot -Force
    Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue

    $repositoryRoot = Get-ChildItem -LiteralPath $downloadRoot -Directory |
        Where-Object { Test-EasyInstallRepositoryRoot -Path $_.FullName } |
        Select-Object -First 1

    if (-not $repositoryRoot) {
        throw "Nao encontrei os arquivos do EasyInstall depois de baixar: $zipUrl"
    }

    return $repositoryRoot.FullName
}

$script:EasyInstallRoot = $null

Enable-EasyInstallExecutionPolicyForCurrentProcess

if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot) -and (Test-EasyInstallRepositoryRoot -Path $PSScriptRoot)) {
    $script:EasyInstallRoot = $PSScriptRoot
} else {
    $script:EasyInstallRoot = Get-EasyInstallRepositoryFromGitHub -Repository $Repository -Branch $Branch
}

$script:EasyInstallEntryPoint = Join-Path $script:EasyInstallRoot 'Easyinstall.ps1'

. (Join-Path $script:EasyInstallRoot 'src\Core\Bootstrap.ps1')
Initialize-EasyInstallBootstrap -EntryPoint $script:EasyInstallEntryPoint -Arguments $args

. (Join-Path $script:EasyInstallRoot 'src\EasyInstall.Loader.ps1')
Start-EasyInstallTui
