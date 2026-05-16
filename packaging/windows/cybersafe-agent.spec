# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec file for Cybersafe Agent (Windows build).
#
# SOC-200 / Phase 2 :
# Build configuration for the Windows version of the Cybersafe Agent.
# Generated as part of the ADR-001 decision (Python + PyInstaller stack).
#
# Build:
#   pyinstaller packaging\windows\cybersafe-agent.spec --clean --noconfirm
#
# Output:
#   dist\cybersafe-agent\          (folder, ~50 MB total)
#       cybersafe-agent.exe        (entry point)
#       _internal\                 (Python runtime + dependencies)
#
# Distribution:
#   ZIP the dist\cybersafe-agent\ folder and ship it to clients.
#   The install.ps1 script handles deployment to C:\Program Files\Cybersafe Agent\.
#
# References:
#   https://pyinstaller.org/en/stable/spec-files.html
#

import os
import sys

# === Project paths ============================================================
# Resolve project root from this spec file location.
# The spec is located at: <project_root>/packaging/windows/cybersafe-agent.spec
# So the project root is two parents up.

SPEC_DIR = os.path.dirname(os.path.abspath(SPEC))
PROJECT_ROOT = os.path.abspath(os.path.join(SPEC_DIR, '..', '..'))
ENTRY_POINT = os.path.join(PROJECT_ROOT, 'cybersafe_agent', '__main__.py')


# === Hidden imports ===========================================================
# Modules that PyInstaller cannot detect automatically through static analysis.
# Critical for Windows : pywin32 submodules are loaded dynamically and must
# be explicitly declared here, otherwise the bundled .exe will crash with
# "ModuleNotFoundError: No module named 'win32evtlog'".

hidden_imports = [
    # pywin32 modules used by cybersafe_agent.platforms.windows
    'win32evtlog',
    'win32event',
    'winerror',
    'pywintypes',
    'win32api',
    'win32con',
    'win32security',
    'pythoncom',

    # XML parsing (used by parsers.windows for Event Log XML)
    'xml.etree.ElementTree',
    'xml.etree.cElementTree',

    # JSON & YAML (config loading)
    'yaml',
    'yaml.loader',
    'yaml.dumper',

    # Logging handlers (RotatingFileHandler used by main.py)
    'logging.handlers',

    # Threading (used by tailer)
    'threading',
    'queue',

    # HTTP client for sender.py
    'requests',
    'urllib3',
    'certifi',
    'charset_normalizer',
    'idna',
]


# === Excluded modules =========================================================
# Reduce binary size and attack surface by excluding what we don't need.

excludes = [
    'tkinter',     # No GUI
    'unittest',    # Tests not needed in production
    'pdb',         # No debugger in shipped binary
    'doctest',
    'IPython',
    'jupyter',
    'matplotlib',
    'numpy',       # Not used by agent
    'pandas',      # Not used by agent
    'PIL',
    'PyQt5',
    'PyQt6',
    'pytest',
]


# === Analysis phase ===========================================================

a = Analysis(
    [ENTRY_POINT],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=[],  # config.example.yaml shipped separately by install.ps1
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)


# === Compile phase ============================================================

pyz = PYZ(a.pure, a.zipped_data, cipher=None)


# === EXE phase ================================================================
# Single .exe entry point. The actual Python runtime + libs go into _internal\
# alongside it (onedir mode, configured below in COLLECT).
#
# Important :
#   - console=True : console app (writes to stdout/stderr, allows NSSM to capture logs)
#   - upx=False    : UPX compression triggers massive AV False Positives — keep raw
#   - strip=False  : keep debug symbols for crash diagnostics in production

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,  # onedir mode (binaries go in COLLECT below)
    name='cybersafe-agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Windows version info (embedded in the .exe properties)
    version='file_version_info.txt' if os.path.exists(os.path.join(SPEC_DIR, 'file_version_info.txt')) else None,
    icon=None,  # TODO: add icon when branding is ready
)


# === COLLECT phase (onedir output) ============================================

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='cybersafe-agent',
)
