#!/usr/bin/env pwsh
#Requires -Version 5.1
#
# Cybersafe-AI Agent — Windows build script (PowerShell)
#
# SOC-200 / Phase 2 :
# Builds the Windows .exe using PyInstaller, producing a distributable
# folder at dist\cybersafe-agent\ and a zip at dist\cybersafe-agent-windows.zip
#
# Usage:
#   .\build.ps1
#   .\build.ps1 -Clean       # Force clean build (remove venv, build/, dist/)
#   .\build.ps1 -Verbose     # Verbose PyInstaller output
#
# Requirements:
#   - Python 3.10+ (with pip and venv module)
#   - Internet connection (to install pyinstaller + deps)
#
# Output:
#   dist\cybersafe-agent\                  (the distributable folder)
#   dist\cybersafe-agent-windows.zip       (zipped for distribution)
#
# CI/CD :
#   This script is invoked by .github/workflows/build-windows.yml on each
#   git tag matching v*. See README-Windows.md for details.

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$Verbose
)

# === Fail-fast configuration =================================================
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # speeds up Invoke-WebRequest in CI

# === Paths ===================================================================
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir '..\..')).Path
$SpecFile = Join-Path $ScriptDir 'cybersafe-agent.spec'
$VenvDir = Join-Path $ProjectRoot 'build-venv'
$BuildDir = Join-Path $ProjectRoot 'build'
$DistDir = Join-Path $ProjectRoot 'dist'
$ZipOutput = Join-Path $DistDir 'cybersafe-agent-windows.zip'

# === Logging helpers =========================================================
function Write-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[ OK ]  $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[ERR ]  $msg" -ForegroundColor Red }

function Show-Banner {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host " Cybersafe-AI Agent — Windows Build" -ForegroundColor Cyan
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""
}

# === Pre-flight checks =======================================================
function Test-PythonAvailable {
    Write-Info "Checking Python availability..."

    $pythonCmd = $null
    foreach ($candidate in @('python', 'python3', 'py')) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd) {
            $pythonCmd = $cmd.Source
            break
        }
    }

    if (-not $pythonCmd) {
        Write-Err "Python 3.10+ is required but was not found in PATH."
        Write-Err "Install from https://www.python.org/downloads/ and re-run."
        exit 1
    }

    $versionOutput = & $pythonCmd --version 2>&1
    Write-Ok "Found: $versionOutput at $pythonCmd"

    # Verify version >= 3.10
    $versionString = ($versionOutput -replace 'Python\s+', '').Trim()
    $version = [version]$versionString
    if ($version -lt [version]'3.10') {
        Write-Err "Python 3.10+ required, found $versionString."
        exit 1
    }

    return $pythonCmd
}

# === Cleanup =================================================================
function Invoke-Cleanup {
    Write-Info "Cleaning previous build artifacts..."

    foreach ($dir in @($BuildDir, $DistDir)) {
        if (Test-Path $dir) {
            Remove-Item -Recurse -Force $dir
            Write-Ok "Removed $dir"
        }
    }

    if ($Clean -and (Test-Path $VenvDir)) {
        Remove-Item -Recurse -Force $VenvDir
        Write-Ok "Removed $VenvDir (Clean mode)"
    }
}

# === Virtual environment setup ===============================================
function Initialize-BuildVenv {
    param($PythonCmd)

    if (-not (Test-Path $VenvDir)) {
        Write-Info "Creating isolated build venv at $VenvDir..."
        & $PythonCmd -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Failed to create venv."
            exit 1
        }
        Write-Ok "Build venv created."
    } else {
        Write-Ok "Build venv exists, reusing."
    }

    $venvPip = Join-Path $VenvDir 'Scripts\pip.exe'
    $venvPython = Join-Path $VenvDir 'Scripts\python.exe'

    Write-Info "Upgrading pip + setuptools + wheel..."
    & $venvPython -m pip install --quiet --upgrade pip setuptools wheel
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to upgrade pip."
        exit 1
    }

    Write-Info "Installing agent dependencies..."
    & $venvPip install --quiet -r (Join-Path $ProjectRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to install agent dependencies."
        exit 1
    }

    Write-Info "Installing PyInstaller..."
    & $venvPip install --quiet 'pyinstaller>=6.0'
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to install PyInstaller."
        exit 1
    }

    Write-Ok "Build venv ready."
    return $venvPython
}

# === Build with PyInstaller ==================================================
function Invoke-PyInstaller {
    param($VenvPython)

    Write-Info "Running PyInstaller (this may take 2-5 minutes)..."

    $pyiArgs = @(
        '-m', 'PyInstaller',
        '--clean',
        '--noconfirm',
        '--distpath', $DistDir,
        '--workpath', $BuildDir,
        $SpecFile
    )

    if ($Verbose) {
        $pyiArgs += '--log-level=DEBUG'
    } else {
        $pyiArgs += '--log-level=WARN'
    }

    Push-Location $ProjectRoot
    try {
        & $VenvPython @pyiArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Err "PyInstaller failed with exit code $LASTEXITCODE"
            exit 1
        }
    } finally {
        Pop-Location
    }

    $exePath = Join-Path $DistDir 'cybersafe-agent\cybersafe-agent.exe'
    if (-not (Test-Path $exePath)) {
        Write-Err "Build succeeded but $exePath was not produced."
        exit 1
    }

    Write-Ok "PyInstaller build complete."
}

# === Bundle config.example.yaml into dist folder =============================
function Copy-DistributionFiles {
    Write-Info "Copying distribution helper files..."

    $distAgentDir = Join-Path $DistDir 'cybersafe-agent'

    # Copy config.example.yaml for end users
    Copy-Item `
        -Path (Join-Path $ProjectRoot 'config.example.yaml') `
        -Destination $distAgentDir
    Write-Ok "  config.example.yaml -> $distAgentDir"

    # Copy install/uninstall scripts
    foreach ($script in @('install.ps1', 'uninstall.ps1', 'README-Windows.md')) {
        $src = Join-Path $ScriptDir $script
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $distAgentDir
            Write-Ok "  $script -> $distAgentDir"
        }
    }
}

# === Zip the dist folder =====================================================
function Compress-Distribution {
    Write-Info "Creating distribution zip..."

    if (Test-Path $ZipOutput) {
        Remove-Item -Force $ZipOutput
    }

    $sourceFolder = Join-Path $DistDir 'cybersafe-agent'
    Compress-Archive -Path $sourceFolder -DestinationPath $ZipOutput -CompressionLevel Optimal

    $zipSize = [math]::Round((Get-Item $ZipOutput).Length / 1MB, 2)
    Write-Ok "Zip created: $ZipOutput ($zipSize MB)"
}

# === Summary =================================================================
function Show-Summary {
    $exePath = Join-Path $DistDir 'cybersafe-agent\cybersafe-agent.exe'
    $folderSize = [math]::Round(
        (Get-ChildItem (Join-Path $DistDir 'cybersafe-agent') -Recurse |
         Measure-Object -Property Length -Sum).Sum / 1MB, 2
    )

    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host " Build complete!" -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Executable     : $exePath"
    Write-Host "  Folder size    : $folderSize MB"
    Write-Host "  Distribution   : $ZipOutput"
    Write-Host ""
    Write-Host "  Next steps :"
    Write-Host "    1. Test locally  : cd $DistDir\cybersafe-agent && .\cybersafe-agent.exe"
    Write-Host "    2. Distribute    : Ship $ZipOutput to clients"
    Write-Host "    3. Install client side : .\install.ps1 (after unzip)"
    Write-Host ""
}

# === Main ====================================================================
Show-Banner

$pythonCmd = Test-PythonAvailable
Invoke-Cleanup
$venvPython = Initialize-BuildVenv -PythonCmd $pythonCmd
Invoke-PyInstaller -VenvPython $venvPython
Copy-DistributionFiles
Compress-Distribution
Show-Summary
