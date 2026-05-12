# Carrega os subscripts do EasyInstall em ordem previsivel.

Set-StrictMode -Version Latest

$script:EasyInstallSourceRoot = Split-Path -Parent $PSCommandPath

$scriptFiles = @(
    'Core\ConsoleEncoding.ps1',
    'Tools\RemoteTools.ps1',
    'Tweaks\Recall.ps1',
    'Tweaks\Network.ps1',
    'Tools\WinGetCore.ps1',
    'Tweaks\StoragePower.ps1',
    'Installers\VcRedist.ps1',
    'Installers\Programs.ps1',
    'Installers\GameLaunchers.ps1',
    'Installers\EssentialsNoWinget.ps1',
    'Tweaks\TimeNtp.ps1',
    'Drivers\GpuDrivers.ps1',
    'Tools\WindowsMaintenance.ps1',
    'Tools\ProgramsInventory.ps1',
    'Drivers\DduNvidia.ps1',
    'Tools\WinGetInteligente.ps1',
    'Tweaks\GamingFeatures.ps1',
    'Misc\Credits.ps1',
    'Debloat\Win11AppRemoval.ps1',
    'Menu\Tui.ps1'
)

foreach ($relativePath in $scriptFiles) {
    $fullPath = Join-Path $script:EasyInstallSourceRoot $relativePath
    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw "Subscript nao encontrado: $fullPath"
    }

    . $fullPath
}
