#Requires -Version 5.1
<#
.SYNOPSIS
Installs a SHA256-verified XOps CLI release for Windows (x64 or ARM64).
.PARAMETER Version
Release version (latest, v0.12.0 or 0.12.0). Defaults to XOPS_VERSION or latest.
.PARAMETER Repo
GitHub owner/repository. Defaults to XOPS_REPO or wentf9/xops-cli.
.PARAMETER GitHubToken
Optional token for GitHub API and private assets. Defaults to GITHUB_TOKEN or GH_TOKEN.
.PARAMETER InstallDir
Destination directory. Defaults to LOCALAPPDATA\Programs\xops.
.PARAMETER NoPath
Skip updating the user and current process PATH.
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Version = $(if ($env:XOPS_VERSION) { $env:XOPS_VERSION } else { 'latest' }),
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repo = $(if ($env:XOPS_REPO) { $env:XOPS_REPO } else { 'wentf9/xops-cli' }),
    [string]$GitHubToken = $(if ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { $env:GH_TOKEN }),
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\xops'),
    [switch]$NoPath
)

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    throw 'This installer only supports Windows.'
}

# PROCESSOR_ARCHITEW6432 identifies the native OS when using a 32-bit shell.
$architecture = $env:PROCESSOR_ARCHITEW6432
if (-not $architecture) {
    $architecture = $env:PROCESSOR_ARCHITECTURE
}
$assetName = switch ($architecture) {
    'AMD64' { 'xops.exe' }
    'ARM64' { 'xops-arm64.exe' }
    default { throw "Unsupported Windows architecture: $architecture" }
}

$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
if ($InstallDir.Contains(';')) {
    throw 'InstallDir must not contain a semicolon (PATH separator).'
}
$temporaryFile = $null
$stage = 'Preparing installation'
$headers = @{ 'User-Agent' = 'xops-installer'; 'Accept' = 'application/vnd.github+json' }
if ($GitHubToken) { $headers['Authorization'] = "Bearer $GitHubToken" }
$releaseURL = "https://api.github.com/repos/$Repo/releases/latest"
if ($Version -ne 'latest') {
    $tag = if ($Version.StartsWith('v')) { $Version } else { "v$Version" }
    $releaseURL = "https://api.github.com/repos/$Repo/releases/tags/$([Uri]::EscapeDataString($tag))"
}

function Save-ReleaseAsset($Asset, [string]$OutputFile) {
    if ($GitHubToken) {
        # Construct an API URL instead of sending credentials to an asset-supplied URL.
        if ("$($Asset.id)" -notmatch '^\d+$') { throw 'Release asset has no valid GitHub asset ID.' }
        $assetHeaders = @{
            'User-Agent' = 'xops-installer'
            'Accept' = 'application/octet-stream'
            'Authorization' = "Bearer $GitHubToken"
        }
        Invoke-WebRequest -UseBasicParsing -Uri "https://api.github.com/repos/$Repo/releases/assets/$($Asset.id)" `
            -Headers $assetHeaders -OutFile $OutputFile -TimeoutSec 300
    } else {
        $downloadURL = [Uri]$Asset.browser_download_url
        if ($downloadURL.Scheme -ne 'https' -or $downloadURL.Host -ne 'github.com') {
            throw 'Release asset must have an HTTPS download URL on github.com.'
        }
        Invoke-WebRequest -UseBasicParsing -Uri $downloadURL -OutFile $OutputFile -TimeoutSec 300
    }
}

$previousSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
try {
    # Windows PowerShell 5.1 may otherwise default to an older TLS version.
    [Net.ServicePointManager]::SecurityProtocol = $previousSecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $stage = "Fetching release '$Version' from $Repo"
    Write-Host "$stage..."
    $release = Invoke-RestMethod -Uri $releaseURL -Headers $headers -TimeoutSec 30
    $assets = @($release.assets | Where-Object { $_.name -ceq $assetName })
    if ($assets.Count -ne 1 -or -not $assets[0].browser_download_url) {
        throw "Release $($release.tag_name) does not contain a unique $assetName asset for $architecture. Check https://github.com/$Repo/releases."
    }
    $digest = [string]$assets[0].digest
    if ($digest -cnotmatch '^sha256:([a-fA-F0-9]{64})$') {
        throw "Release asset $assetName has no valid GitHub SHA256 digest. Choose a release whose asset metadata includes a SHA256 digest."
    }
    $expectedHash = $Matches[1]

    $stage = "Creating installation directory '$InstallDir' (check write permissions)"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    # This invocation owns the temporary download; finally removes it on failure.
    # Keep it beside the destination so replacement stays on the same volume.
    $temporaryFile = Join-Path $InstallDir ('.xops-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $stage = "Downloading $assetName from $Repo ($($release.tag_name))"
    Write-Host "Downloading $assetName ($($release.tag_name))..."
    Save-ReleaseAsset $assets[0] $temporaryFile
    if ((Get-Item -LiteralPath $temporaryFile -Force).Length -eq 0) {
        throw 'The downloaded file is empty.'
    }

    $stage = "Verifying SHA256 for $assetName"
    $actualHash = (Get-FileHash -LiteralPath $temporaryFile -Algorithm SHA256).Hash
    if ($actualHash -ne $expectedHash) {
        throw "SHA256 mismatch for $assetName. Expected $expectedHash; received $actualHash. Existing installation was not replaced."
    }
    Write-Host "SHA256 verified: $actualHash"

    $destination = Join-Path $InstallDir 'xops.exe'
    $stage = "Installing '$destination' (close running XOps processes and check write permissions)"
    if (Test-Path -LiteralPath $destination) {
        # A failed replacement (e.g. xops.exe is running) preserves the old binary.
        [System.IO.File]::Replace($temporaryFile, $destination, [System.Management.Automation.Language.NullString]::Value)
    } else {
        [System.IO.File]::Move($temporaryFile, $destination)
    }

    if (-not $NoPath) {
        $stage = "Updating user PATH (binary installed at '$destination'; retry with -NoPath to skip this step)"
        # Read user PATH separately; never persist the merged process/machine PATH.
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $userEntries = @($userPath -split ';' | Where-Object { $_ })
        $normalizedEntries = @($userEntries | ForEach-Object {
            [Environment]::ExpandEnvironmentVariables($_).Trim().TrimEnd('\')
        })
        if ($normalizedEntries -notcontains $InstallDir.TrimEnd('\')) {
            $newUserPath = (@($userEntries) + $InstallDir) -join ';'
            [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
        }
        $processEntries = @($env:PATH -split ';' | ForEach-Object { $_.Trim().TrimEnd('\') })
        if ($processEntries -notcontains $InstallDir.TrimEnd('\')) {
            $env:PATH = $InstallDir + ';' + $env:PATH
        }
    }

    Write-Host "Installed XOps CLI $($release.tag_name) to $destination"
    if ($NoPath) {
        Write-Host "Run: & '$destination' --help"
    } else {
        Write-Host 'Run: xops --help. Restart other terminals to pick up the updated user PATH.'
    }
} catch {
    $message = $_.Exception.Message
    $statusCode = $null
    if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
    switch ($statusCode) {
        401 { $message = 'GitHub authentication failed (HTTP 401). Check GITHUB_TOKEN / GH_TOKEN or -GitHubToken.' }
        403 { $message = 'GitHub denied access or the API rate limit was reached (HTTP 403). Check token permissions, or wait and retry.' }
        404 { $message = "GitHub release or asset not found (HTTP 404). Check -Repo '$Repo', -Version '$Version' and private repository access." }
        429 { $message = 'GitHub rate limit reached (HTTP 429). Wait before retrying; use a GitHub token for authenticated requests.' }
    }
    $failure = "${stage} failed: $message"
    if ($GitHubToken) { $failure = $failure.Replace($GitHubToken, '[REDACTED]') }
    throw $failure
} finally {
    [Net.ServicePointManager]::SecurityProtocol = $previousSecurityProtocol
    if ($temporaryFile -and (Test-Path -LiteralPath $temporaryFile)) {
        Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
    }
}
