#!/usr/bin/env pwsh
#Requires -Version 5.1
#Requires -RunAsAdministrator
#
# Cybersafe-AI Agent — Windows uninstall script
#
# SOC-200 / Phase 2 :
# Removes the Cybersafe Agent from a Windows machine.
#
# What it always does (no prompt):
#   - Stops the Windows service
#   - Removes the service registration via NSSM
#   - Deletes C:\Program Files\Cybersafe Agent\ (binaries)
#
# What it asks about (or removes if -Purge):
#   - C:\ProgramData\Cybersafe\config   (config + token)
#   - C:\ProgramData\Cybersafe\logs     (agent logs)
#   - C:\ProgramData\Cybersafe\bookmarks (Event Log bookmarks)
#   - C:\ProgramData\Cybersafe\spool    (queued events)
#   - C:\ProgramData\Cybersafe\nssm     (NSSM binary)
#
# Usage:
#   .\uninstall.ps1            # Interactive : asks before deleting data
#   .\uninstall.ps1 -Purge     # Non-interactive : deletes everything

[CmdletBinding()]
param(
    [switch]$Purge
)

$ErrorActionPreference = 'Continue'  # Continue on partial errors (idempotent uninstall)

# =============================================================================
# Configuration (must match install.ps1)
# =============================================================================
$ServiceName  = 'CybersafeAgent'

$InstallDir   = 'C:\Program Files\Cybersafe Agent'
$DataDir      = 'C:\ProgramData\Cybersafe'
$ConfigDir    = Join-Path $DataDir 'config'
$LogsDir      = Join-Path $DataDir 'logs'
$BookmarksDir = Join-Path $DataDir 'bookmarks'
$SpoolDir     = Join-Path $DataDir 'spool'
$NssmDir      = Join-Path $DataDir 'nssm'
$NssmExe      = Join-Path $NssmDir 'nssm.exe'

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
    Write-Host " Cybersafe-AI Agent — Windows Uninstaller" -ForegroundColor Cyan
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""
}

# =============================================================================
# Confirm helper (respects -Purge)
# =============================================================================
function Confirm-Action {
    param([string]$Prompt)

    if ($Purge) {
        return $true
    }

    $resp = Read-Host "$Prompt [y/N]"
    return ($resp -match '^[Yy]')
}

# =============================================================================
# Stop and remove the Windows service
# =============================================================================
function Remove-AgentService {
    Write-Info "Checking service '$ServiceName'..."

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Ok "Service '$ServiceName' is not installed."
        return
    }

    if ($svc.Status -eq 'Running') {
        Write-Info "Stopping service..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Write-Ok "Service stopped."
    } else {
        Write-Ok "Service was not running."
    }

    # Remove via NSSM if available, else use sc.exe
    if (Test-Path $NssmExe) {
        Write-Info "Removing service via NSSM..."
        & $NssmExe remove $ServiceName confirm 2>&1 | Out-Null
        Write-Ok "Service removed via NSSM."
    } else {
        Write-Warn "NSSM not found, falling back to sc.exe..."
        & sc.exe delete $ServiceName 2>&1 | Out-Null
        Write-Ok "Service removed via sc.exe."
    }
}

# =============================================================================
# Remove install dir (always — these are just binaries)
# =============================================================================
function Remove-InstallDir {
    if (Test-Path $InstallDir) {
        Write-Info "Removing $InstallDir..."
        try {
            Remove-Item -Path $InstallDir -Recurse -Force
            Write-Ok "Removed $InstallDir"
        } catch {
            Write-Err "Could not remove $InstallDir : $_"
            Write-Err "  Try again after a reboot if files are locked."
        }
    } else {
        Write-Ok "$InstallDir already absent."
    }
}

# =============================================================================
# Optional removal of data directories
# =============================================================================
function Remove-OptionalDir {
    param(
        [string]$Path,
        [string]$Description,
        [string]$Prompt
    )

    if (-not (Test-Path $Path)) {
        Write-Ok "$Description already absent."
        return
    }

    if (Confirm-Action -Prompt $Prompt) {
        try {
            Remove-Item -Path $Path -Recurse -Force
            Write-Ok "Removed $Path ($Description)"
        } catch {
            Write-Err "Could not remove $Path : $_"
        }
    } else {
        Write-Warn "Kept $Path ($Description)"
    }
}

function Remove-OptionalData {
    Write-Info "Optional data cleanup..."

    Remove-OptionalDir `
        -Path $ConfigDir `
        -Description "Config (contains your agent token)" `
        -Prompt "  Remove $ConfigDir (contains your agent token) ?"

    Remove-OptionalDir `
        -Path $LogsDir `
        -Description "Agent logs" `
        -Prompt "  Remove $LogsDir (agent logs) ?"

    Remove-OptionalDir `
        -Path $BookmarksDir `
        -Description "Event Log bookmarks" `
        -Prompt "  Remove $BookmarksDir (Event Log bookmarks) ?"

    Remove-OptionalDir `
        -Path $SpoolDir `
        -Description "Event spool" `
        -Prompt "  Remove $SpoolDir (queued events) ?"

    Remove-OptionalDir `
        -Path $NssmDir `
        -Description "NSSM service manager" `
        -Prompt "  Remove $NssmDir (NSSM binary) ?"

    # If all subfolders are removed and DataDir is empty, clean it up too
    if (Test-Path $DataDir) {
        $remaining = Get-ChildItem -Path $DataDir -Force -ErrorAction SilentlyContinue
        if (-not $remaining) {
            Remove-Item -Path $DataDir -Force
            Write-Ok "Removed empty $DataDir"
        }
    }
}

# =============================================================================
# Summary
# =============================================================================
function Show-Summary {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host " Cybersafe-AI Agent uninstalled." -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host ""

    if (-not $Purge) {
        Write-Host "  Note: data directories you chose to KEEP can be removed later"
        Write-Host "        manually, or re-run this script with -Purge."
        Write-Host ""
    }
}

# =============================================================================
# Main
# =============================================================================
Show-Banner

if ($Purge) {
    Write-Warn "Running in PURGE mode: ALL data will be deleted without confirmation."
    Write-Warn ""
}

Remove-AgentService
Remove-InstallDir
Remove-OptionalData
Show-Summary
