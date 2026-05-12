# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

#VAI ARRUMAR O WINGET
try { chcp 65001 > $null } catch {}

$utf8 = New-Object System.Text.UTF8Encoding $false
[Console]::InputEncoding  = $utf8
[Console]::OutputEncoding = $utf8
$OutputEncoding           = $utf8


