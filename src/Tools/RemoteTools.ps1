# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Install-Winhance {
    Write-Host ""
    Write-Host "Iniciando instalador do Winhance..." -ForegroundColor Blue

    $cmd = 'try { irm "https://get.winhance.net" | iex } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }'
    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", $cmd
    )
}

#VAI INSTALAR CTT WINUTIL
function Install-CTT {
    Write-Host ""
    Write-Host "Iniciando instalador do CTT-WinUtil..." -ForegroundColor Blue

    $cmd = 'try { irm "https://christitus.com/win" | iex } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }'
    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", $cmd
    )
}


