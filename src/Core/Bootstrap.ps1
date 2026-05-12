# Bootstrap compartilhado do EasyInstall.
# Mantem validacoes e preparo do console fora dos modulos de dominio.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Assert-Windows11Only {
    if ($env:OS -ne 'Windows_NT') {
        throw "Este script so pode ser executado no Windows 11."
    }

    $caption = $null
    $build   = $null
    $ptype   = $null

    try {
        $os      = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $caption = [string]$os.Caption
        $build   = [int]$os.BuildNumber
        $ptype   = [int]$os.ProductType
    } catch {
        $cv      = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $caption = [string]$cv.ProductName
        $build   = [int]$cv.CurrentBuildNumber

        $po      = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -ErrorAction Stop
        $ptype   = if ($po.ProductType -eq 'WinNT') { 1 } else { 3 }
    }

    if ($ptype -ne 1) {
        throw ("Este script so pode ser executado no Windows 11 Client. Detectado: {0} (Build {1})" -f $caption, $build)
    }

    if ($build -lt 22000) {
        throw ("Este script so pode ser executado no Windows 11. Detectado: {0} (Build {1})" -f $caption, $build)
    }
}

function Set-ConsoleBlackTheme {
    try {
        $raw = $Host.UI.RawUI
        $raw.BackgroundColor = 'Black'
        $raw.ForegroundColor = 'White'
        Clear-Host
    } catch {}

    try {
        $esc = [char]27
        Write-Host "$esc[40m$esc[97m" -NoNewline
        Clear-Host
    } catch {}
}

function Disable-ConsoleQuickEdit {
    try {
        if (-not ('ConsoleHelper' -as [type])) {
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
        }

        $handle = [ConsoleHelper]::GetStdHandle(-10)
        $mode = 0
        [ConsoleHelper]::GetConsoleMode($handle, [ref]$mode) | Out-Null
        $newMode = $mode -band (-bnot 0x40)
        [ConsoleHelper]::SetConsoleMode($handle, $newMode) | Out-Null
    } catch {}
}

function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-EasyInstallBootstrap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EntryPoint,
        [object[]]$Arguments = @()
    )

    try { [Console]::SetWindowSize(100, 32) } catch {}

    Assert-Windows11Only
    Set-ConsoleBlackTheme
    Disable-ConsoleQuickEdit

    if (-not (Test-IsAdmin)) {
        Write-Host "Reabrindo em modo Administrador..." -ForegroundColor Blue

        if ([string]::IsNullOrWhiteSpace($EntryPoint) -or -not (Test-Path -LiteralPath $EntryPoint)) {
            throw "Nao consegui detectar o caminho do script principal."
        }

        $argList = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', "`"$EntryPoint`""
        ) + @($Arguments)

        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
        exit
    }
}
