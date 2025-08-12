Write-Host "Iniciando..." -ForegroundColor Magenta
#Vai checar se o usuário executou como Administrador
Add-Type -AssemblyName System.Windows.Forms
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Add-Type -AssemblyName System.Windows.Forms
    $mensagem = "Este script precisa ser executado com privilégios de Administrador.`n`nPor favor, clique com o botão direito no arquivo e selecione 'Executar como Administrador'."
    $titulo = "Erro de Permissão!"
    $botoes = [System.Windows.Forms.MessageBoxButtons]::OK
    $icone = [System.Windows.Forms.MessageBoxIcon]::Error
    [System.Windows.Forms.MessageBox]::Show($mensagem, $titulo, $botoes, $icone) | Out-Null
    exit
}

$player = New-Object System.Media.SoundPlayer
            $URLMUSICA = "https://www.dropbox.com/scl/fi/4sf1zp1xplydavbmzrr68/MENU-mp3cut.net.wav?rlkey=5z1y6usen85vgugxoyihkgkqm&st=uiefb83q&dl=1"
            Invoke-WebRequest -Uri "$URLMUSICA" -OutFile "$env:TEMP\MENU.wav"
            $player.SoundLocation = "$env:TEMP\MENU.wav"
            $player.Load()
            $player.PlayLooping()



while ($true) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Clear-Host
$asciiArt = @'
███████  █████  ███████ ██    ██ ██ ███    ██ ███████ ████████  █████  ██      ██      
██      ██   ██ ██       ██  ██  ██ ████   ██ ██         ██    ██   ██ ██      ██      
█████   ███████ ███████   ████   ██ ██ ██  ██ ███████    ██    ███████ ██      ██      
██      ██   ██      ██    ██    ██ ██  ██ ██      ██    ██    ██   ██ ██      ██
███████ ██   ██ ███████    ██    ██ ██   ████ ███████    ██    ██   ██ ███████ ███████
'@
Write-Host $asciiArt -ForegroundColor Magenta
Write-Host "By gabrielmf1998" -ForegroundColor Cyan
Write-Host ""

$7zipurl = "https://www.7-zip.org/a/7z2405-x64.exe"
$7zipurlbackup = "https://www.dropbox.com/scl/fi/mxzy930l435b2nekh7jb3/7zip.exe?rlkey=vlfa2ewujvoejrjjsnim233xo&st=8kci0vmd&dl=1"
$discordurlbackup = "https://www.dropbox.com/scl/fi/iexl5meb6e4uhace8r60h/DiscordSetup.exe?rlkey=66szuqcji8crzhd49e6s85xe6&st=xevxz12e&dl=1"
$vlcurlbackup = "https://www.dropbox.com/scl/fi/rzg6a4hcjip6hwm0avou3/vlc-3.0.21-win64.exe?rlkey=b5k03253t7204iitoibpudjn4&st=xpngwmev&dl=1"
$steamurl = "https://cdn.fastly.steamstatic.com/client/installer/SteamSetup.exe"
#$steamurlbackup = "https://www.dropbox.com/scl/fi/hfm2xnam8syjc6zck034y/SteamSetup.exe?rlkey=d3ess7m9sos7r4uvxsmgxtrs6&st=pa1z9k55&dl=1"
$telegramurlbackup = "https://www.dropbox.com/scl/fi/7d45ildoh0q86wjgeumlv/tsetup-x64.5.14.3.exe?rlkey=zzqcmywrltgf55mc6i244o1n0&st=um62cd0v&dl=1"
$chromeurl = "https://www.dropbox.com/scl/fi/pr7vfrb9bxchhypvhhbsy/ChromeSetup.exe?rlkey=46pc5ik4qsxoy5xwnj1ca8fvw&st=7s4hqmom&dl=1"
$msiafterburnerurl = "https://ftp.nluug.nl/pub/games/PC/guru3d/afterburner/[Guru3D]-MSIAfterburnerSetup466Beta5Build16555.zip"
$msiafterburnerurlbackup = "https://www.dropbox.com/scl/fi/8dn8xetdhrakgxvmgtrnq/Guru3D-MSIAfterburnerSetup466Beta5Build16555.zip?rlkey=p32u18t82o8je99wqvh36kjiv&st=j53u0iq7&dl=1"
$rivatunnerurl = "https://ftp.nluug.nl/pub/games/PC/guru3d/afterburner/[Guru3D.com]-RTSS.zip"
$parsecurl = "https://builds.parsec.app/package/parsec-windows.exe"
$parsecurlbackup = "https://www.dropbox.com/scl/fi/bjxw4k1hsiwnfgsjx03fv/parsec-windows.exe?rlkey=7xr6wwawwqw5zvnlviq25b1sr&st=l1jvlij1&dl=1"
$radmimurlbackup = "https://www.dropbox.com/scl/fi/gvmwoqa0wbp8ewr2fa730/Radmin_VPN_1.4.4642.1.exe?rlkey=xetsxz3q9crmol0a2w7rb1694&st=fqfq54g0&dl=1"
$strimeourl = "https://dl.strem.io/stremio-shell-ng/v5.0.5/StremioSetup-v5.0.5.exe"
$strimeourlbackup = "https://www.dropbox.com/scl/fi/uq62szhbnzp1kq8wo6yc0/StremioSetup-v5.0.5.exe?rlkey=uab1o1ijoi3ftebppxubpstnu&st=rjca5qm0&dl=1"
$spotifyurl = "https://download.scdn.co/SpotifySetup.exe"
$spotifyurlbackup = "https://www.dropbox.com/scl/fi/c15frzd6ham1o3ggeqdsd/SpotifySetup.exe?rlkey=itf8073plo1lavcj8mgui2i87&st=sevl766t&dl=1"
$drivernvidiaurl = "https://us.download.nvidia.com/Windows/576.52/576.52-notebook-win10-win11-64bit-international-dch-whql.exe"
$drivernvidiaurlbackup = "https://www.dropbox.com/scl/fi/qlgmp84tl2sf1sq71cjzk/576.52-notebook-win10-win11-64bit-international-dch-whql.exe?rlkey=c60wdrzjvoanj1ihi8qk4he8s&st=aj0e90vk&dl=1"
$driveramdurl = "https://drivers.amd.com/drivers/whql-amd-software-adrenalin-edition-25.5.1-win10-win11-may8-rdna.exe"
$driveramdurlbackup = "https://www.dropbox.com/scl/fi/rm3liw9ojtbaamngdm14o/whql-amd-software-adrenalin-edition-25.5.1-win10-win11-may8-rdna.exe?rlkey=k8tfczazh6t5bex2y34i3u5lo&st=dvo5pwma&dl=1"
$winhanceurl = "https://github.com/memstechtips/Winhance/releases/download/v25.05.28/Winhance.Installer.exe"
#$caffeineurl = "https://github.com/kyleleong/caffeine/releases/download/v1.0.1/caffeine.exe"
$flameshoturl = "https://github.com/flameshot-org/flameshot/releases/download/v12.0.0/Flameshot-12.0.0-win64.msi"
$vmwareurl = "https://www.dropbox.com/scl/fi/4yd0j71ak8v5rjysxkwqu/vmware-workstation-pro-17-6-0-build-24238078.exe?rlkey=gzt0nkop38rilbqrfrpl4126v&st=212qsyal&dl=1"
$visualurl = "https://github.com/abbodi1406/vcredist/releases/download/v0.92.0/VisualCppRedist_AIO_x86_x64.exe"
$operagxurl = "https://www.dropbox.com/scl/fi/kkyxxjjb4rlxf7pkviarh/OperaGXSetup.exe?rlkey=83pnniwj1lu6nj9shvcjxhju6&st=kqhxn43j&dl=1"
$jogochinesvirus = "https://www.dropbox.com/scl/fi/dmigy8i7qzwflanmcr7s5/GenshinImpact_install_ua_04042a38e433.exe?rlkey=wrdl1s9t83ebj895k71ugeu8g&st=r1oldx18&dl=1"
$startallbackurl = "https://www.dropbox.com/scl/fi/psjk13pklejcib0lfg3xz/StartAllBack_3.9.12_setup.exe?rlkey=npx0f72p0ojbj5a5uss071il2&st=5ojrfqye&dl=1"
$Prismaurl = "https://www.dropbox.com/scl/fi/d690yek0trux9acod88iw/PrismLauncher-Windows-MSVC-Setup-9.4.exe?rlkey=zywtm6epmhc1kjd91b96rd30n&st=mypci9d6&dl=1"

    Write-Host "Principais" -ForegroundColor Magenta
    Write-Host ("{0,-50} {1}" -f "1 - Steam", "2 - Discord")
    Write-Host ("{0,-50} {1}" -f "3 - Telegram", "4 - Chrome")
    Write-Host "Drivers" -ForegroundColor Magenta
    Write-Host ("{0,-50} {1}" -f "5 - Nvidia", "6 - AMD")
    Write-Host "Entreterimento" -ForegroundColor Magenta
    Write-Host ("{0,-50} {1}" -f "7 - Spotify", "8 - Strimeo")
    Write-Host ("{0,-50} {1}" -f "9 - VLC Player", "10 - Parsec")
    Write-Host "Ferramentas" -ForegroundColor Magenta
    Write-Host ("{0,-50} {1}" -f "11 - 7zip", "12 - VisualStudio AIO")
    Write-Host ("{0,-50} {1}" -f "13 - Ativar Windows 10/11/Office", "14 - Winhance")
    Write-Host ("{0,-50} {1}" -f "15 - StartAllBack", "16 - Instalar Msi Afterburner")
    Write-Host ("{0,-50} {1}" -f "17 - Desativar Hibernação/Economia de Energia", "18 - Ativar TRIM NVME/Desabilitar Sysmain")
    Write-Host ("{0,-50} {1}" -f "19 - Desativar Defender/Firewall/Update", "00 - NULL") 
    Write-Host "Virus" -ForegroundColor Magenta
    Write-Host ("{0,-50} {1}" -f "20 - OperaGX", "21 - Genshin Impact") 
    Write-Host "Outros" -ForegroundColor Magenta
    Write-Host ("{0,-50} {1}" -f "22 - Radmin", "23 - VMWare")
    Write-Host ("{0,-50} {1}" -f "24 - FlameShot", "25 - PrismaLauncher")
    Write-Host ("{0,-50} {1}" -f "26 - Pacote Office 2024", "00 - NULL")   
    Write-Host ""
    $escolha = Read-Host "Digite uma opção "
    switch ($escolha) {
        "1" {
            Invoke-WebRequest -Uri "$steamurl" -OutFile "$env:TEMP\SteamInstall.exe"
            Start-Process "$env:TEMP\SteamInstall.exe"
        }
        "2" {
            Invoke-WebRequest -Uri "$discordurlbackup" -OutFile "$env:TEMP\Discord.exe"
            Start-Process "$env:TEMP\Discord.exe"
        }
        "3" {
            Invoke-WebRequest -Uri "$telegramurlbackup" -OutFile "$env:TEMP\Telegram.exe"
            Start-Process "$env:TEMP\Telegram.exe"
        }
        "4" {
            Invoke-WebRequest -Uri "$chromeurl" -OutFile "$env:TEMP\Chrome.exe"
            Start-Process "$env:TEMP\Chrome.exe"
        }
        "5" {
            Invoke-WebRequest -Uri "$drivernvidiaurl" -OutFile "$env:TEMP\Nvidia.exe"
                if (-Not (Test-Path "$env:TEMP\Nvidia.exe")) {
                    Write-Host "Link principal caiu, usando backup DropBox..." -ForegroundColor Yellow
                    Invoke-WebRequest -Uri "$drivernvidiaurlbackup" -OutFile "$env:TEMP\Nvidia.exe"
                    }
            Start-Process "$env:TEMP\Nvidia.exe"
        }
        "6" {
            Invoke-WebRequest -Uri "$driveramdurl" -OutFile "$env:TEMP\AMD.exe"
                if (-Not (Test-Path "$env:TEMP\AMD.exe")) {
                    Write-Host "Link principal caiu, usando backup DropBox..." -ForegroundColor Yellow
                    Invoke-WebRequest -Uri "$driveramdurlbackup" -OutFile "$env:TEMP\AMD.exe"
                    }
            Start-Process "$env:TEMP\AMD.exe"
        }
        "7" {
            Invoke-WebRequest -Uri "$spotifyurl" -OutFile "$env:TEMP\Spotify.exe"
                if (-Not (Test-Path "$env:TEMP\Spotify.exe")) {
                    Write-Host "Link principal caiu, usando backup DropBox..." -ForegroundColor Yellow
                    Invoke-WebRequest -Uri "$spotifyurlbackup" -OutFile "$env:TEMP\Spotify.exe"
                    }
            Start-Process "explorer.exe" -ArgumentList "`"$env:TEMP\Spotify.exe`""
        }
        "8" {
            Invoke-WebRequest -Uri "$strimeourl" -OutFile "$env:TEMP\Stremio.exe"
                if (-Not (Test-Path "$env:TEMP\Stremio.exe")) {
                    Write-Host "Link principal caiu, usando backup DropBox..." -ForegroundColor Yellow
                    Invoke-WebRequest -Uri "$strimeourlbackup" -OutFile "$env:TEMP\Stremio.exe"
                    }
            Start-Process "$env:TEMP\Stremio.exe"
        }
        "9" {
            Invoke-WebRequest -Uri "$vlcurlbackup" -OutFile "$env:TEMP\VideoLC.exe"
            Start-Process "$env:TEMP\VideoLC.exe"
        }
        "10" {
            Invoke-WebRequest -Uri "$parsecurl" -OutFile "$env:TEMP\Parsec.exe"
                if (-Not (Test-Path "$env:TEMP\Parsec.exe")) {
                    Write-Host "Link principal caiu, usando backup DropBox..." -ForegroundColor Yellow
                    Invoke-WebRequest -Uri "$parsecurlbackup" -OutFile "$env:TEMP\Parsec.exe"
                    }
            Start-Process "$env:TEMP\Parsec.exe"
        }
        "11" {
            Invoke-WebRequest -Uri "$7zipurl" -OutFile "$env:TEMP\7zip.exe"
                if (-Not (Test-Path "$env:TEMP\7zip.exe")) {
                    Write-Host "Link principal caiu, usando backup DropBox..." -ForegroundColor Yellow
                    Invoke-WebRequest -Uri "$7zipurlbackup" -OutFile "$env:TEMP\7zip.exe"
                    }
            Start-Process "$env:TEMP\7zip.exe"
        }  
        "12" {
            Invoke-WebRequest -Uri $visualurl -OutFile "$env:TEMP\VRCAIO.exe"
            Start-Process "$env:TEMP\VRCAIO.exe"
        }
        "13" {
            irm https://get.activated.win | iex
        }
        "14" {
            Invoke-WebRequest -Uri "$winhanceurl" -OutFile "$env:TEMP\Winhance.exe"
            Start-Process "$env:TEMP\Winhance.exe"
        }
        "15" {
            Invoke-WebRequest -Uri "$startallbackurl" -OutFile "$env:TEMP\StartAllBack.exe"
            Start-Process "$env:TEMP\StartAllBack.exe"
        }
        "16" {
            Invoke-WebRequest -Uri "$msiafterburnerurl" -OutFile "$env:TEMP\Afterburner.zip"
            Invoke-WebRequest -Uri "$rivatunnerurl" -OutFile "$env:TEMP\RTSS.zip"
            #Vai baixar os dois MSI e RTSS
                if (-Not (Test-Path "$env:TEMP\Afterburner.zip")) {
                    Write-Host "Link principal caiu, usando backup DropBox..." -ForegroundColor Yellow
                    Invoke-WebRequest -Uri "$msiafterburnerurlbackup" -OutFile "$env:TEMP\Afterburner.zip"
                    }
            #Vai extrair e instalar afterburner
            $temp = $env:TEMP
            $zipPathAfterburner = Join-Path $temp "Afterburner.zip"
            $extractPathAfterburner = Join-Path $temp "Afterburner"
            Expand-Archive -Path $zipPathAfterburner -DestinationPath $extractPathAfterburner -Force
            $instaladorAfterburner = Join-Path $extractPathAfterburner "MSIAfterburnerSetup466Beta5.exe"
            Start-Process $instaladorAfterburner -Verb RunAs
            
            #Vai extrair e instalar RTSS
            $zipPathRTSS = Join-Path $temp "RTSS.zip"
            $extractPathRTSS = Join-Path $temp "RTSS"
            Expand-Archive -Path $zipPathRTSS -DestinationPath $extractPathRTSS -Force
            $instaladorRTSS = Join-Path $extractPathRTSS "RTSSSetup736.exe"
            Start-Process $instaladorRTSS -Verb RunAs

        }
        "17" {
            powercfg -setactive SCHEME_MIN
            Write-Host "Economia de energia" -ForegroundColor Cyan
            Write-Host "[DESABILITADO]" -ForegroundColor Green
            powercfg -change -monitor-timeout-ac 0
            powercfg -change -monitor-timeout-dc 0
            powercfg -change -standby-timeout-ac 0
            powercfg -change -standby-timeout-dc 0
            powercfg -change -disk-timeout-ac 0
            powercfg -change -disk-timeout-dc 0
            Write-Host "Desligar monitor depois de 15 minutos" -ForegroundColor Cyan
            Write-Host "[DESABILITADO]" -ForegroundColor Green 
            powercfg -h off
            Write-Host "Boot rápida/Hibernação" -ForegroundColor Cyan
            Write-Host "[DESABILITADO]" -ForegroundColor Green 
            Pause

        }
        "18" {
            fsutil behavior set DisableDeleteNotify 0
            fsutil behavior query DisableDeleteNotify
            Write-Host "TRIM NVME" -ForegroundColor Cyan
            Write-Host "[HABILITADO]" -ForegroundColor Green 
            Start-Sleep 1
            Stop-Service -Name "SysMain" -Force
            Set-Service -Name "SysMain" -StartupType Disabled
            Write-Host "SysMain" -ForegroundColor Magenta 
            Write-Host "[DESABILITADO]" -ForegroundColor Green 
            pause
        }
        "19" {
            $URLTUTORIAL = "https://www.dropbox.com/scl/fi/zwni9d085zrh0gm5303or/secret-tutorial.pdf?rlkey=2qvg7bjj1omfz1favklatai98&st=t883byid&dl=1"
            Invoke-WebRequest -Uri "$URLTUTORIAL" -OutFile "$env:TEMP\secret-tutorial.pdf"

            Clear-Host
            Write-Host "Desativar esses serviços melhora o desempenho, mas não tanto assim." -ForegroundColor Magenta
            Start-Sleep 3
            Write-Host "Você vai estar mais correndo risco do que de fato ganhando desempenho." -ForegroundColor Magenta
            Start-Sleep 3
            Write-Host "Desativar Update/Firewall/Defender é somente para quem sabe o que BAIXA E INSTALA!" -ForegroundColor Magenta
            Start-Sleep 3
            Write-Host "Um total de 16 serviços relacionados a segurança seram desativados." -ForegroundColor Magenta
            Start-Sleep 3
            Write-Host "21 novas chaves de registro seram criadas, para impedir de rodar esses serviços....." -ForegroundColor Magenta
            Start-Sleep 3
            Write-Host "VOCÊ VAI SER HACKEADO, E VAI PERDER SUAS CONTAS, NÃO FAÇA ISSO!" -ForegroundColor Red
            Write-Host "EU NÃO ME RESPONSABILIZO POR QUALQUER DANO, PERCA, OU ROUBO DE DADOS!!!!" -ForegroundColor Red
            Write-Host ""
            Start-Sleep 4
            Write-Host "Se realmente deseja continuar, pressione qualquer tecla ou feche esta janela." -ForegroundColor Magenta
            Pause
            Write-Host "[ABRINDO TUTORIAL...]" -ForegroundColor Magenta
            Start-Process "$env:TEMP\secret-tutorial.pdf"
            Write-Host "Vá em Proteção contra vírus e ameaças > Gerenciar configurações > Desative a opção Proteção contra Violações!" -ForegroundColor Magenta
            Write-Host "Só pressione qualquer tecla se realmente desativou essa opção!!!" -ForegroundColor Red
            start ms-settings:windowsdefender
            Pause
            #Desativar Windows Update
            Stop-Service -Name wuauserv -Force
            Set-Service -Name wuauserv -StartupType Disabled
            Write-Host "Windows Update" -ForegroundColor Magenta
            Write-Host "[DESABILITADO]" -ForegroundColor Green
            #Desativar Outros serviços de Windows Update
            Stop-Service -Name bits -Force
            Set-Service -Name bits -StartupType Disabled
            Write-Host "Windows Update Reserva/Emergencia" -ForegroundColor Magenta
            Write-Host "[DESABILITADO]" -ForegroundColor Green
            #Desativar TaskManager relacionado ao Windows Update
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Force
            Write-Host "Ativador do Windows Update Temporário" -ForegroundColor Magenta
            Write-Host "[DESABILITADO]" -ForegroundColor Green
            #Desativar Windows Defender/Cloud Defender
            Set-MpPreference -DisableRealtimeMonitoring $true
            Set-MpPreference -DisableBehaviorMonitoring $true
            Set-MpPreference -DisableBlockAtFirstSeen $true
            Set-MpPreference -DisableIOAVProtection $true
            Set-MpPreference -DisableScriptScanning $true
            Set-MpPreference -EnableControlledFolderAccess Disabled
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Value 0 -Type DWord
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" -Name "Notification_Suppress" -Value 1 -Type DWord
            Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" | Disable-ScheduledTask -ErrorAction SilentlyContinue
            Set-Service -Name WinDefend -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "Windows Defender/Cloud Defender/Spynet/Proteção Ransoware" -ForegroundColor Magenta
            Write-Host "[DESABILITADO]" -ForegroundColor Green
            #Desativar Windows Firewall
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
            Get-NetFirewallProfile | Format-Table Name, Enabled
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall" -Force | Out-Null
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -Type DWord -Value 0
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "EnableFirewall" -Type DWord -Value 0
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "EnableFirewall" -Type DWord -Value 0
            Write-Host "Windows Firewall" -ForegroundColor Magenta
            Write-Host "[DESABILITADO]" -ForegroundColor Green
            #Desativar as tarefas referente a ativar Windows Defender
            Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" | Disable-ScheduledTask
            pause
        }
        "20" {
            Invoke-WebRequest -Uri "$operagxurl" -OutFile "$env:TEMP\OperaGXSetup.exe"
            Start-Process "$env:TEMP\OperaGXSetup.exe"
        }
        "21" {
            Invoke-WebRequest -Uri "$jogochinesvirus" -OutFile "$env:TEMP\GenshinImpact.exe"
            Start-Process "$env:TEMP\GenshinImpact.exe"  
        }
        "22" {
            Invoke-WebRequest -Uri "$radmimurlbackup" -OutFile "$env:TEMP\Radminv.exe"
            Start-Process "$env:TEMP\Radminv.exe" 
        }
        "23" {
            net localgroup Users /add
            net localgroup Users Administradores /add
            Invoke-WebRequest -Uri "$vmwareurl" -OutFile "$env:TEMP\VMWware.exe"
            Start-Process "$env:TEMP\VMWware.exe"
        }
        "24" {
            Invoke-WebRequest -Uri "$flameshoturl" -OutFile "$env:TEMP\Flameshot.msi"
            Start-Process "$env:TEMP\Flameshot.msi"
        }
        "25" {
            Invoke-WebRequest -Uri "$prismaurl" -OutFile "$env:TEMP\Prisma.exe"
            Start-Process "$env:TEMP\Prisma.exe"
        }
        "26" {
            if (-not (Test-Path "ProPlus2024Retail.img")) {
                            $PatchPath = "ProPlus2024Retail.img"
                            $url = "https://www.dropbox.com/scl/fi/b0vd9arpqxpkenuzi2vzj/ProPlus2024Retail.img?rlkey=fml8hx8qxdpregln1jcrgf0ce&st=1rfa5w4o&dl=1"
                            $request = [System.Net.HttpWebRequest]::Create($url)
                            $response = $request.GetResponse()
                            $totalLength = $response.ContentLength
                            $stream = $response.GetResponseStream()
                            $fileStream = [System.IO.File]::Create($PatchPath)
                            $buffer = New-Object byte[] 8192
                            $totalRead = 0
                            $sw = [System.Diagnostics.Stopwatch]::StartNew()
                            $lastUpdate = [datetime]::Now
                            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                                $fileStream.Write($buffer, 0, $read)
                                $totalRead += $read
                                if (([datetime]::Now - $lastUpdate).TotalMilliseconds -ge 500) {
                                        $lastUpdate = [datetime]::Now
                                if ($totalLength -gt 0) {
                                        $percent = [math]::Floor(($totalRead / $totalLength) * 100)
                                        $barLength = 30
                                        $filledLength = [math]::Floor(($percent / 100) * $barLength)
                                        $bar = ("#" * $filledLength).PadRight($barLength, "-")

                                        $downloadedMB = [math]::Round($totalRead / 1MB, 2)
                                        $totalMB = [math]::Round($totalLength / 1MB, 2)

                                     Write-Host ("`r[{0}] {1}% ({2}MB / {3}MB)" -f $bar, $percent, $downloadedMB, $totalMB) -ForegroundColor Magenta -NoNewline
                                    }
                                    else {
                                        $downloadedMB = [math]::Round($totalRead / 1MB, 2)
                                        Write-Host ("`rBaixando... {0}MB" -f $downloadedMB) -NoNewline -ForegroundColor Magenta
                                    }
                                }
                            }
                            $fileStream.Close()
                            $stream.Close()
                            $response.Close()
                            $sw.Stop()
                }


            $installerPath = "$env:TEMP\winrar-x64-700br.exe"
            Invoke-WebRequest -Uri "https://www.dropbox.com/scl/fi/524bkq27kbajxs35zjlgc/winrar-x64-700br.exe?rlkey=7e26ed7ik1vkwcu5o4tyh5cbo&st=iv8lpmel&dl=1" -OutFile $installerPath
            Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait
            
            Start-Process "C:\Program Files\WinRAR\WinRAR.exe" -ArgumentList "x","-ibck","ProPlus2024Retail.img","$($env:TEMP)\ProPlus2024Retail\","-o+" -WindowStyle Hidden -Wait
            Start-Process "$env:TEMP\ProPlus2024Retail\Setup.exe"
            pause

        }
        "27" {

        }              
        "99" {
            Write-Host "Bye bye :3" -ForegroundColor Cyan
            Start-Sleep 1
            # O comando 'break' interrompe o loop 'while ($true)', finalizando o script.
            break
        }
        default {
            # Este bloco é executado se a escolha não corresponder a nenhuma das opções acima.
            Write-Host "Opção inválida! Por favor, escolha um número." -ForegroundColor Red
            Start-Sleep 1
        }
    }
}
[void][System.Console]::ReadKey($true)
$player.Stop()