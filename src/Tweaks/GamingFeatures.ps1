# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Set-Gaming-Features {
    [CmdletBinding()]
    param(
        [ValidateSet('OffCurrentUser','OffAllUsers','RemoveRegistry')]
        [string]$Mode
    )

    function Test-IsAdmin {
        $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Ensure-RegKey([string]$Path) {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    }

    function Get-RegValueSafe([string]$Path, [string]$Name) {
        try { Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop }
        catch { $null }
    }

    function Parse-DxSettings([string]$s) {
        $d = [ordered]@{}
        if ([string]::IsNullOrWhiteSpace($s)) { return $d }
        foreach ($part in ($s -split ';')) {
            if ([string]::IsNullOrWhiteSpace($part)) { continue }
            $kv = $part -split '=', 2
            if ($kv.Count -eq 2 -and -not $d.Contains($kv[0])) { $d[$kv[0]] = $kv[1] }
        }
        $d
    }

    function To-DxSettings([hashtable]$d) {
        if ($d.Count -eq 0) { return $null }
        (($d.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';') + ';'
    }

    function Get-GpuNote {
        $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
        if ($gpus.Count -eq 0) {
            return "Info: nao foi possivel detectar a GPU (WMI indisponivel). As opcoes podem nao existir/ser aplicaveis."
        }

        $names = ($gpus | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue) -join " | "
        if ($names -match 'Microsoft Basic Display Adapter') {
            return "Info: detectado driver generico 'Microsoft Basic Display Adapter'. Sem driver de GPU, VRR/otimizacoes/HAGS podem nao existir ou nao surtir efeito ate instalar o driver."
        }

        return "GPU(s): $names"
    }

    function Set-DxOffForHive([string]$hkuRoot) {
        $dxPath = "Registry::$hkuRoot\Software\Microsoft\DirectX\UserGpuPreferences"
        $dxName = "DirectXUserGlobalSettings"

        Ensure-RegKey $dxPath

        # Le SEM acessar propriedade inexistente
        $cur  = Get-RegValueSafe $dxPath $dxName
        $dict = Parse-DxSettings $cur

        # OFF nas 2 opcoes do print
        $dict['SwapEffectUpgradeEnable'] = '0'  # Optimizations for windowed games
        $dict['VRROptimizeEnable']       = '0'  # Variable refresh rate

        $new = To-DxSettings $dict

        # Grava (cria se nao existir)
        New-ItemProperty -Path $dxPath -Name $dxName -PropertyType String -Value $new -Force | Out-Null

        # Retorna status para mensagens
        [pscustomobject]@{
            HadValueBefore = -not [string]::IsNullOrWhiteSpace($cur)
            Before         = $cur
            After          = $new
        }
    }

    function Apply-AllUsers([scriptblock]$perHiveAction) {
        # NAO lancar erro: so explicar e retornar $false
        if (-not (Test-IsAdmin)) { return $false }

        $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $sids = Get-ChildItem $profileList -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
                Select-Object -ExpandProperty PSChildName -Unique

        foreach ($sid in $sids) {
            $loaded = Test-Path "Registry::HKEY_USERS\$sid"
            if ($loaded) {
                & $perHiveAction "HKEY_USERS\$sid"
                continue
            }

            $p = Get-ItemProperty -Path (Join-Path $profileList $sid) -ErrorAction SilentlyContinue
            if (-not $p.ProfileImagePath) { continue }

            $userDir = [Environment]::ExpandEnvironmentVariables($p.ProfileImagePath)
            $ntuser  = Join-Path $userDir 'NTUSER.DAT'
            if (-not (Test-Path $ntuser)) { continue }

            $tmp = "GF_$($sid.Replace('-',''))"
            $loadTarget = "HKU\$tmp"

            try {
                & reg.exe load $loadTarget $ntuser | Out-Null
                & $perHiveAction "HKEY_USERS\$tmp"
            } finally {
                & reg.exe unload $loadTarget | Out-Null
            }
        }

        return $true
    }

    function Set-HagsOff {
        # HwSchMode: 1=Off, 2=On (em geral)
        $hagsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
        Ensure-RegKey $hagsPath
        New-ItemProperty -Path $hagsPath -Name 'HwSchMode' -PropertyType DWord -Value 1 -Force | Out-Null
    }

    function Remove-HagsValue {
        $hagsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
        if (Test-Path $hagsPath) {
            Remove-ItemProperty -Path $hagsPath -Name 'HwSchMode' -ErrorAction SilentlyContinue
        }
    }

    function Remove-DxGlobalForHive([string]$hkuRoot) {
        $dxPath = "Registry::$hkuRoot\Software\Microsoft\DirectX\UserGpuPreferences"
        if (Test-Path $dxPath) {
            Remove-ItemProperty -Path $dxPath -Name "DirectXUserGlobalSettings" -ErrorAction SilentlyContinue
        }
    }

    # ======================
    # Execucao (sem "Erro:")
    # ======================
    Write-Host ""
    Write-Host (Get-GpuNote)

    switch ($Mode) {
        'OffCurrentUser' {
            $r = Set-DxOffForHive "HKEY_CURRENT_USER"

            if (-not $r.HadValueBefore) {
                Write-Host "OK: As configs globais do DirectX ainda nao existiam neste usuario; criei agora e defini OFF (isso e normal em PCs sem driver/sem suporte)."
            } else {
                Write-Host "OK: Atualizei DirectXUserGlobalSettings e defini OFF."
            }

            if (Test-IsAdmin) {
                Set-HagsOff
                Write-Host "OK: HAGS = OFF. (Reinicie o PC para aplicar HAGS.)"
            } else {
                Write-Host "Info: HAGS nao foi aplicado porque requer Administrador (HKLM)."
            }

            Write-Host "Acao: reinicie o VRChat/jogo/app para aplicar Optimizations/VRR."
            pause
        }

        'OffAllUsers' {
            if (-not (Test-IsAdmin)) {
                Write-Host "Info: Opcao 2 requer Administrador. Vou aplicar somente no usuario atual (equivalente a opcao 1)."
                Set-Gaming-Features -Mode OffCurrentUser
                return
            }

            $ok = Apply-AllUsers { param($root) Set-DxOffForHive $root | Out-Null }
            if (-not $ok) {
                Write-Host "Info: Nao foi possivel aplicar para todos os usuarios (precisa Admin)."
                return
            }

            Set-HagsOff
            Write-Host "OK: OFF para todos os usuarios + HAGS OFF."
            Write-Host "Acao: reinicie o PC (HAGS) e reinicie o jogo/app."
            pause
        }

        'RemoveRegistry' {
            if (-not (Test-IsAdmin)) {
                Write-Host "Info: Opcao 3 requer Administrador. Nada foi removido."
                Write-Host "Motivo: remover envolve HKLM e perfis de outros usuarios (HKU)."
                return
            }

            # backup simples
            $ts = Get-Date -Format "yyyyMMdd_HHmmss"
            $b1 = Join-Path $env:TEMP "GamingFeatures_BACKUP_UserGpuPreferences_$ts.reg"
            $b2 = Join-Path $env:TEMP "GamingFeatures_BACKUP_GraphicsDrivers_$ts.reg"
            & reg.exe export "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" $b1 /y | Out-Null
            & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" $b2 /y | Out-Null

            Apply-AllUsers { param($root) Remove-DxGlobalForHive $root } | Out-Null
            Remove-DxGlobalForHive "HKEY_CURRENT_USER"
            Remove-HagsValue

            Write-Host "OK: removi as entradas do Registro (DirectXUserGlobalSettings + HwSchMode)."
            Write-Host "Backups (.reg) em: $b1 | $b2"
            Write-Host "Acao: reinicie o PC."
            pause
        }
    }
}


