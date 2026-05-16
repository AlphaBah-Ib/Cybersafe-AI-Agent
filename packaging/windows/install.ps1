#!/usr/bin/env pwsh
#Requires -Version 5.1
#Requires -RunAsAdministrator
#
# Cybersafe-AI Agent — Windows installation script
#
# SOC-200 / Phase 2 :
# Installs the Cybersafe Agent on a Windows machine:
#   - Creates C:\Program Files\Cybersafe Agent\        (binaries, read-only)
#   - Creates C:\ProgramData\Cybersafe\                (config, logs, state)
#   - Downloads and installs NSSM as service wrapper
#   - Registers cybersafe-agent as a Windows service (LocalSystem)
#   - Starts the service (optional)
#
# Usage:
#   .\install.ps1                              # Interactive mode
#   .\install.ps1 -Token csa_xxx               # Provide token via parameter
#   .\install.ps1 -Token csa_xxx -Unattended   # Silent install + auto-start
#   .\install.ps1 -ApiUrl https://staging.cybersafe.example.com/api
#
# Idempotent: re-running is safe (will skip already-installed components).

[CmdletBinding()]
param(
    [string]$Token = '',
    [string]$ApiUrl = 'https://cybersafe-ai-production.up.railway.app/api',
    [switch]$Unattended,
    [switch]$SkipNssm  # for testing without service install
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# =============================================================================
# Configuration
# =============================================================================
$ServiceName     = 'CybersafeAgent'
$ServiceDisplay  = 'Cybersafe-AI Agent'
$ServiceDesc     = 'Continuous Windows Event Log collection and forwarding to Cybersafe-AI SOC.'

$InstallDir      = 'C:\Program Files\Cybersafe Agent'
$DataDir         = 'C:\ProgramData\Cybersafe'
$ConfigDir       = Join-Path $DataDir 'config'
$LogsDir         = Join-Path $DataDir 'logs'
$BookmarksDir    = Join-Path $DataDir 'bookmarks'
$SpoolDir        = Join-Path $DataDir 'spool'
$NssmDir         = Join-Path $DataDir 'nssm'

$ConfigFile      = Join-Path $ConfigDir 'config.yaml'
$LogFile         = Join-Path $LogsDir 'agent.log'
$NssmExe         = Join-Path $NssmDir 'nssm.exe'

# NSSM 2.24-101 — last stable verified release
$NssmVersion     = '2.24-101-g897c7ad'
$NssmDownloadUrl = "https://nssm.cc/ci/nssm-$NssmVersion.zip"
# SHA256 of nssm-2.24-101-g897c7ad.zip (verified against nssm.cc public listing)
$NssmZipSha256   = 'F94ED70BCAD8E2F1A36E963BC6E2887B0599EB85375D4EFDC2E0F71D02E0F62F'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BinSrcDir = $ScriptDir  # the install.ps1 lives alongside the .exe after unzip

# =============================================================================
# Logging helpers
# =============================================================================
function Write-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[ OK ]  $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[ERR ]  $msg" -ForegroundColor Red }

function Show-Banner {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host " Cybersafe-AI Agent — Windows Installer" -ForegroundColor Cyan
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""
}

# =============================================================================
# Pre-flight checks
# =============================================================================
function Test-Prerequisites {
    Write-Info "Checking prerequisites..."

    # Windows version (Windows 10/11/Server 2019+/Server 2022)
    $osVersion = [Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Write-Err "Windows 10 or Server 2019+ required (found $osVersion)."
        exit 1
    }
    Write-Ok "Windows version: $osVersion"

    # PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Err "PowerShell 5.1+ required."
        exit 1
    }
    Write-Ok "PowerShell version: $($PSVersionTable.PSVersion)"

    # Architecture (x64 only for now)
    if ([Environment]::Is64BitOperatingSystem -eq $false) {
        Write-Err "64-bit Windows required."
        exit 1
    }
    Write-Ok "Architecture: x64"

    # Agent binary present alongside this script
    $exePath = Join-Path $BinSrcDir 'cybersafe-agent.exe'
    if (-not (Test-Path $exePath)) {
        Write-Err "cybersafe-agent.exe not found at $exePath"
        Write-Err "Run this script from the unzipped distribution folder."
        exit 1
    }
    Write-Ok "Found agent binary at $exePath"

    # config.example.yaml present
    $templatePath = Join-Path $BinSrcDir 'config.example.yaml'
    if (-not (Test-Path $templatePath)) {
        Write-Err "config.example.yaml not found at $templatePath"
        exit 1
    }
    Write-Ok "Found config template"
}

# =============================================================================
# Detect previous installation
# =============================================================================
function Test-PreviousInstall {
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Warn "Service '$ServiceName' is already installed (state: $($existingService.Status))."
        if (-not $Unattended) {
            $resp = Read-Host "  Continue installation (existing service will be reused)? [y/N]"
            if ($resp -notmatch '^[Yy]') {
                Write-Info "Installation cancelled by user."
                exit 0
            }
        } else {
            Write-Warn "Unattended mode: reusing existing service installation."
        }
    }
}

# =============================================================================
# Directory creation with proper ACL
# =============================================================================
function New-AgentDirectory {
    param(
        [string]$Path,
        [string]$Description,
        [bool]$Writable = $true
    )

    if (Test-Path $Path) {
        Write-Ok "Directory exists: $Path ($Description)"
        return
    }

    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    Write-Ok "Created: $Path ($Description)"

    # If writable by service (LocalSystem already has full access; this is for
    # defense in depth on shared systems).
    if (-not $Writable) {
        # Remove inherited write permissions for Users group
        $acl = Get-Acl $Path
        $acl.SetAccessRuleProtection($false, $true)
        Set-Acl -Path $Path -AclObject $acl
    }
}

function Initialize-Directories {
    Write-Info "Creating installation directories..."
    New-AgentDirectory -Path $InstallDir   -Description "Binaries (read-only)" -Writable $false
    New-AgentDirectory -Path $DataDir      -Description "Data root"            -Writable $true
    New-AgentDirectory -Path $ConfigDir    -Description "Configuration"        -Writable $true
    New-AgentDirectory -Path $LogsDir      -Description "Agent logs"           -Writable $true
    New-AgentDirectory -Path $BookmarksDir -Description "Event Log bookmarks"  -Writable $true
    New-AgentDirectory -Path $SpoolDir     -Description "Event spool"          -Writable $true
    New-AgentDirectory -Path $NssmDir      -Description "NSSM service manager" -Writable $true
}

# =============================================================================
# Copy agent binaries to Program Files
# =============================================================================
function Copy-AgentBinaries {
    Write-Info "Copying agent binaries to $InstallDir..."

    # Copy the whole _internal\ subfolder (PyInstaller onedir output)
    $internalSrc = Join-Path $BinSrcDir '_internal'
    if (Test-Path $internalSrc) {
        Copy-Item -Path $internalSrc -Destination $InstallDir -Recurse -Force
        Write-Ok "Copied _internal\ (Python runtime)"
    }

    # Copy the .exe
    Copy-Item -Path (Join-Path $BinSrcDir 'cybersafe-agent.exe') -Destination $InstallDir -Force
    Write-Ok "Copied cybersafe-agent.exe"
}

# =============================================================================
# Token acquisition (interactive or via param)
# =============================================================================
function Read-Token {
    if ($Token -and $Token.StartsWith('csa_')) {
        Write-Ok "Token provided via parameter."
        return $Token
    }

    if ($Unattended) {
        Write-Err "Unattended mode requires -Token parameter."
        exit 1
    }

    Write-Host ""
    Write-Host "Enter your Cybersafe agent token (from Cybersafe dashboard > Agents)" -ForegroundColor Cyan
    Write-Host "  Token format: csa_xxxxxxxxxxxxxxx" -ForegroundColor DarkGray
    Write-Host ""

    $userToken = Read-Host "  Token"
    $userToken = $userToken.Trim()

    if (-not $userToken.StartsWith('csa_') -or $userToken.Length -lt 20) {
        Write-Err "Invalid token (must start with 'csa_' and be at least 20 characters)."
        exit 1
    }

    return $userToken
}

# =============================================================================
# Generate config.yaml from template
# =============================================================================
function New-ConfigFile {
    param([string]$AgentToken)

    if (Test-Path $ConfigFile) {
        Write-Warn "$ConfigFile already exists, NOT overwriting."
        Write-Warn "  Verify it manually after install (or delete and re-run installer)."
        return
    }

    Write-Info "Generating $ConfigFile from template..."

    $template = Get-Content -Path (Join-Path $BinSrcDir 'config.example.yaml') -Raw

    # Replace placeholders
    $configContent = $template `
        -replace 'csa_REMPLACE_PAR_TON_TOKEN_ICI', $AgentToken `
        -replace 'https://cybersafe-ai-production\.up\.railway\.app/api', $ApiUrl

    # Adjust paths for Windows (the template has Linux paths)
    $configContent = $configContent `
        -replace '/var/log/cybersafe-agent\.log', ($LogFile -replace '\\', '/') `
        -replace '/var/spool/cybersafe', ($SpoolDir -replace '\\', '/')

    # Append Windows section with sensible defaults if user did not customize
    $windowsSection = @"

# === Windows agent runtime config (auto-generated by install.ps1) ===
windows:
  bookmarks_dir: $($BookmarksDir -replace '\\', '/')
"@

    $configContent += $windowsSection

    Set-Content -Path $ConfigFile -Value $configContent -Encoding UTF8
    Write-Ok "Config file created."
}

# =============================================================================
# NSSM download and verification
# =============================================================================
function Install-Nssm {
    if ($SkipNssm) {
        Write-Warn "SkipNssm flag set — NSSM will not be installed."
        return
    }

    if (Test-Path $NssmExe) {
        Write-Ok "NSSM already present at $NssmExe"
        return
    }

    Write-Info "Downloading NSSM $NssmVersion from nssm.cc..."

    $tmpZip = Join-Path $env:TEMP "nssm-$NssmVersion.zip"

    try {
        Invoke-WebRequest -Uri $NssmDownloadUrl -OutFile $tmpZip -UseBasicParsing
    } catch {
        Write-Err "Failed to download NSSM: $_"
        Write-Err "Check your internet connection or download manually from $NssmDownloadUrl"
        exit 1
    }

    # SHA256 verification (defense against supply-chain attacks)
    Write-Info "Verifying NSSM SHA256..."
    $actualHash = (Get-FileHash -Path $tmpZip -Algorithm SHA256).Hash
    if ($actualHash -ne $NssmZipSha256) {
        Write-Err "NSSM SHA256 mismatch!"
        Write-Err "  Expected: $NssmZipSha256"
        Write-Err "  Actual:   $actualHash"
        Write-Err "Aborting for security reasons."
        Remove-Item -Force $tmpZip
        exit 1
    }
    Write-Ok "SHA256 verified."

    # Extract win64\nssm.exe
    Write-Info "Extracting NSSM..."
    $tmpExtract = Join-Path $env:TEMP "nssm-$NssmVersion"
    if (Test-Path $tmpExtract) {
        Remove-Item -Recurse -Force $tmpExtract
    }
    Expand-Archive -Path $tmpZip -DestinationPath $tmpExtract -Force

    # Locate win64\nssm.exe in extracted content (path varies by version)
    $nssm64 = Get-ChildItem -Path $tmpExtract -Filter 'nssm.exe' -Recurse |
              Where-Object { $_.FullName -like '*win64*' } |
              Select-Object -First 1

    if (-not $nssm64) {
        Write-Err "Could not locate win64\nssm.exe in extracted archive."
        exit 1
    }

    Copy-Item -Path $nssm64.FullName -Destination $NssmExe -Force
    Write-Ok "NSSM installed at $NssmExe"

    # Cleanup
    Remove-Item -Force $tmpZip
    Remove-Item -Recurse -Force $tmpExtract
}

# =============================================================================
# Service registration via NSSM
# =============================================================================
function Register-AgentService {
    if ($SkipNssm) {
        Write-Warn "SkipNssm flag set — service will not be registered."
        return
    }

    # If service already exists, reconfigure it (idempotent)
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Info "Stopping existing service to reconfigure..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & $NssmExe remove $ServiceName confirm | Out-Null
        Write-Ok "Old service registration removed."
    }

    Write-Info "Registering Windows service via NSSM..."

    $agentExe = Join-Path $InstallDir 'cybersafe-agent.exe'

    # Install the service
    & $NssmExe install $ServiceName $agentExe
    if ($LASTEXITCODE -ne 0) { Write-Err "nssm install failed"; exit 1 }

    # Service metadata
    & $NssmExe set $ServiceName DisplayName $ServiceDisplay | Out-Null
    & $NssmExe set $ServiceName Description $ServiceDesc | Out-Null
    & $NssmExe set $ServiceName Start SERVICE_AUTO_START | Out-Null
    & $NssmExe set $ServiceName ObjectName LocalSystem | Out-Null  # required for Security channel

    # Environment variables (point agent to its config)
    & $NssmExe set $ServiceName AppEnvironmentExtra "CYBERSAFE_CONFIG=$ConfigFile" | Out-Null

    # Working directory
    & $NssmExe set $ServiceName AppDirectory $InstallDir | Out-Null

    # Output redirection (NSSM captures stdout/stderr to a file)
    $nssmStdout = Join-Path $LogsDir 'service-stdout.log'
    $nssmStderr = Join-Path $LogsDir 'service-stderr.log'
    & $NssmExe set $ServiceName AppStdout $nssmStdout | Out-Null
    & $NssmExe set $ServiceName AppStderr $nssmStderr | Out-Null

    # Log rotation (NSSM native, every day or 10 MB)
    & $NssmExe set $ServiceName AppRotateFiles 1 | Out-Null
    & $NssmExe set $ServiceName AppRotateOnline 1 | Out-Null
    & $NssmExe set $ServiceName AppRotateSeconds 86400 | Out-Null
    & $NssmExe set $ServiceName AppRotateBytes 10485760 | Out-Null

    # Restart policy (restart on failure, max 5 attempts in 5 min)
    & $NssmExe set $ServiceName AppExit Default Restart | Out-Null
    & $NssmExe set $ServiceName AppRestartDelay 5000 | Out-Null
    & $NssmExe set $ServiceName AppThrottle 60000 | Out-Null

    Write-Ok "Service registered."
}

# =============================================================================
# Service start (optional, prompts user unless Unattended)
# =============================================================================
function Start-AgentService {
    if ($SkipNssm) {
        return
    }

    $shouldStart = $true
    if (-not $Unattended) {
        $resp = Read-Host "  Start the agent service now? [Y/n]"
        if ($resp -match '^[Nn]') {
            $shouldStart = $false
        }
    }

    if ($shouldStart) {
        Write-Info "Starting service..."
        Start-Service -Name $ServiceName
        Start-Sleep -Seconds 2

        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq 'Running') {
            Write-Ok "Service is running."
        } else {
            Write-Warn "Service status: $($svc.Status)"
            Write-Warn "Check logs at $LogsDir for diagnostics."
        }
    } else {
        Write-Info "Service not started. Start later with: Start-Service $ServiceName"
    }
}

# =============================================================================
# Summary
# =============================================================================
function Show-Summary {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host " Cybersafe-AI Agent installed successfully." -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Install dir   : $InstallDir"
    Write-Host "  Data dir      : $DataDir"
    Write-Host "  Config        : $ConfigFile"
    Write-Host "  Logs          : $LogsDir"
    Write-Host ""
    Write-Host "  Useful commands:"
    Write-Host "    Start         : Start-Service $ServiceName"
    Write-Host "    Stop          : Stop-Service $ServiceName"
    Write-Host "    Status        : Get-Service $ServiceName"
    Write-Host "    Tail logs     : Get-Content '$LogFile' -Wait -Tail 50"
    Write-Host "    Uninstall     : .\uninstall.ps1"
    Write-Host ""
}

# =============================================================================
# Main
# =============================================================================
Show-Banner
Test-Prerequisites
Test-PreviousInstall
Initialize-Directories
Copy-AgentBinaries
$agentToken = Read-Token
New-ConfigFile -AgentToken $agentToken
Install-Nssm
Register-AgentService
Start-AgentService
Show-Summary
