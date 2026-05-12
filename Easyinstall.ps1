#requires -Version 5.1

param(
    [string]$Repository = 'gabrielmf1998/Easyinstall',
    [string]$Branch = 'main'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Test-EasyInstallRepositoryRoot {
    param([Parameter(Mandatory)][string]$Path)

    return (
        (Test-Path -LiteralPath (Join-Path $Path 'src\Core\Bootstrap.ps1')) -and
        (Test-Path -LiteralPath (Join-Path $Path 'src\EasyInstall.Loader.ps1'))
    )
}

function Get-EasyInstallRepositoryFromGitHub {
    param(
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$Branch
    )

    $safeRepositoryName = ($Repository -replace '[\\/:*?"<>|]', '_')
    $safeBranchName = ($Branch -replace '[\\/:*?"<>|]', '_')
    $downloadRoot = Join-Path $env:TEMP ("EasyInstall_{0}_{1}" -f $safeRepositoryName, $safeBranchName)
    $zipPath = Join-Path $env:TEMP ("EasyInstall_{0}_{1}.zip" -f $safeRepositoryName, $safeBranchName)
    $zipUrl = "https://github.com/$Repository/archive/refs/heads/$Branch.zip"

    if (Test-Path -LiteralPath $downloadRoot) {
        Remove-Item -LiteralPath $downloadRoot -Recurse -Force
    }

    New-Item -Path $downloadRoot -ItemType Directory -Force | Out-Null

    Write-Host "Baixando EasyInstall do GitHub..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

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
