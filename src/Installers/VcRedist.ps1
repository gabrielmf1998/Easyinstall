# Auto-extraido de legacy\Easyinstall.monolith.ps1
# Mantenha funcoes de dominio neste arquivo.

function Install-LatestVcRedistFromGitHub {
    [CmdletBinding()]
    param(
        [switch]$IncludePrerelease,
        [string]$DownloadDir = "",
        [string[]]$InstallerArgs = $null,     # ex: @("/quiet","/norestart") se voce souber que funciona
        [string]$GitHubToken = ""             # opcional (evita rate limit)
    )

    Write-Host "== VC Redist (abbodi1406/vcredist) - baixar e instalar =="

    function Enable-Tls12 {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    }

    function Get-DownloadsFolder {
        $guid = "{374DE290-123F-4565-9164-39C4925E467B}" # Downloads
        $k = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        try {
            $p = (Get-ItemProperty -Path $k -Name $guid -ErrorAction Stop).$guid
            if ($p) { return (Resolve-Path -Path $p).Path }
        } catch {}
        return (Join-Path $env:USERPROFILE "Downloads")
    }

    function Download-FileWithProgress {
        param(
            [Parameter(Mandatory=$true)][string]$Url,
            [Parameter(Mandatory=$true)][string]$OutFile,
            [System.Net.CookieContainer]$Cookies = $null,
            [hashtable]$Headers = $null
        )

        Enable-Tls12

        $outDir = Split-Path -Path $OutFile -Parent
        if (-not (Test-Path -LiteralPath $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }

        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $req.AllowAutoRedirect = $true
        $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/5.1"
        $req.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
        $req.Timeout = 300000
        $req.ReadWriteTimeout = 300000

        if ($Cookies) { $req.CookieContainer = $Cookies }
        if ($Headers) {
            foreach ($k in $Headers.Keys) { $req.Headers[$k] = $Headers[$k] }
        }

        $resp = $null
        $stream = $null
        $fileStream = $null
        try {
            $resp = $req.GetResponse()
            $totalLength = $resp.ContentLength
            $stream = $resp.GetResponseStream()
            $fileStream = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

            $buffer = New-Object byte[] 8192
            $totalRead = 0L
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
                        Write-Host ("`r[{0}] {1}% ({2}MB / {3}MB)" -f $bar, $percent, $downloadedMB, $totalMB) -ForegroundColor Blue -NoNewline
                    } else {
                        $downloadedMB = [math]::Round($totalRead / 1MB, 2)
                        Write-Host ("`rBaixando... {0}MB" -f $downloadedMB) -ForegroundColor Blue -NoNewline
                    }
                }
            }
            Write-Host ""
        }
        finally {
            if ($fileStream) { $fileStream.Close() }
            if ($stream) { $stream.Close() }
            if ($resp) { try { $resp.Close() } catch {} }
        }
    }

    # Diretorio de download
    if (-not $DownloadDir) { $DownloadDir = Get-DownloadsFolder }
    if (-not (Test-Path -LiteralPath $DownloadDir)) {
        New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
    }

    # GitHub API
    Enable-Tls12
    $owner = "abbodi1406"
    $repo  = "vcredist"

    $headers = @{
        "Accept"     = "application/vnd.github+json"
        "User-Agent" = "PowerShell-5.1"
    }
    if ($GitHubToken) {
        $headers["Authorization"] = "Bearer $GitHubToken"
        $headers["X-GitHub-Api-Version"] = "2022-11-28"
    }

    Write-Host "`n[1/3] Buscando release mais recente..."
    try {
        if ($IncludePrerelease) {
            $releasesUrl = "https://api.github.com/repos/$owner/$repo/releases?per_page=20"
            $rels = Invoke-RestMethod -Headers $headers -Uri $releasesUrl -Method GET -ErrorAction Stop
            # escolhe o mais recente por published_at (inclui prerelease)
            $rel = $rels | Sort-Object { [datetime]$_.published_at } -Descending | Select-Object -First 1
        } else {
            $latestUrl = "https://api.github.com/repos/$owner/$repo/releases/latest"
            $rel = Invoke-RestMethod -Headers $headers -Uri $latestUrl -Method GET -ErrorAction Stop
        }
    } catch {
        Write-Host " - Falha ao consultar GitHub API: $($_.Exception.Message)"
        Write-Host " - Dica: tente fornecer -GitHubToken se estiver em rate limit."
        return
    }

    if (-not $rel) {
        Write-Host " - Nao encontrei release."
        return
    }

    $tag = $rel.tag_name
    $name = $rel.name
    $date = $rel.published_at
    Write-Host " - Release: $name"
    Write-Host " - Tag: $tag"
    Write-Host " - Publicado: $date"

    # Filtra assets relevantes
    $assets = @($rel.assets | Where-Object {
        $_.name -match "\.(exe|msi|zip)$"
    })

    if (-not $assets -or $assets.Count -eq 0) {
        Write-Host " - Este release nao tem assets .exe/.msi/.zip."
        return
    }

    Write-Host "`n[2/3] Opcoes de download:"
    for ($i=0; $i -lt $assets.Count; $i++) {
        $a = $assets[$i]
        $sizeMB = [math]::Round(($a.size / 1MB), 2)
        Write-Host (" [{0}] {1}  ({2} MB)" -f ($i+1), $a.name, $sizeMB)
    }

    $choice = Read-Host "Selecione o numero para baixar/instalar"
    if (-not ($choice -match "^\d+$")) {
        Write-Host " - Entrada invalida."
        return
    }
    $idx = [int]$choice - 1
    if ($idx -lt 0 -or $idx -ge $assets.Count) {
        Write-Host " - Opcao fora do intervalo."
        return
    }

    $selected = $assets[$idx]
    $assetName = $selected.name
    $downloadUrl = $selected.browser_download_url

    $outFile = Join-Path $DownloadDir $assetName

    Write-Host "`n[3/3] Baixando e instalando..."
    Write-Host " - Arquivo: $assetName"
    Write-Host " - Destino: $outFile"

    if ((Test-Path -LiteralPath $outFile)) {
        Write-Host " - Arquivo ja existe."
        $ans = Read-Host "Deseja baixar novamente? (S/N)"
        if ($ans -notin @("S","s","Y","y")) {
            Write-Host " - Reutilizando arquivo existente."
        } else {
            Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not (Test-Path -LiteralPath $outFile)) {
        try {
            Download-FileWithProgress -Url $downloadUrl -OutFile $outFile
            Write-Host " - Download concluido."
        } catch {
            Write-Host " - Falha no download: $($_.Exception.Message)"
            return
        }
    }

    # Hash + Assinatura
    try {
        $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $outFile).Hash
        Write-Host " - SHA256: $sha"
    } catch {
        Write-Host " - Nao consegui calcular SHA256: $($_.Exception.Message)"
    }

    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $outFile
        Write-Host (" - Assinatura: {0}" -f $sig.Status)
        if ($sig.SignerCertificate) {
            Write-Host (" - Assinado por: {0}" -f $sig.SignerCertificate.Subject)
        }
    } catch {
        Write-Host " - Nao consegui validar assinatura: $($_.Exception.Message)"
    }

    # Executar instalador (somente se for .exe/.msi)
    $ext = [IO.Path]::GetExtension($outFile).ToLowerInvariant()
    if ($ext -notin @(".exe",".msi")) {
        Write-Host " - Arquivo nao e .exe/.msi (e $ext). Baixei, mas nao vou executar automaticamente."
        return
    }

    Write-Host " - Executando instalador..."
    try {
        if ($InstallerArgs -and $InstallerArgs.Count -gt 0) {
            Start-Process -FilePath $outFile -ArgumentList $InstallerArgs -ErrorAction Stop | Out-Null
        } else {
            Start-Process -FilePath $outFile -ErrorAction Stop | Out-Null
        }
        Write-Host " - Finalizado."
    } catch {
        Write-Host " - Falha ao executar instalador: $($_.Exception.Message)"
        return
    }
}


