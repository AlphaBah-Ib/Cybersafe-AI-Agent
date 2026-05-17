"""
Cross-OS path resolution for the Cybersafe Agent.

Centralizes all platform-dependent filesystem paths in a single module
so that the rest of the codebase remains OS-agnostic.

Supported platforms:
    - Linux   -> /etc, /var/log, /var/spool (FHS-compliant)
    - Windows -> C:\\ProgramData\\Cybersafe (Windows convention)
    - macOS   -> /etc, /var/log (treated like Linux for now)

Usage:
    from cybersafe_agent.paths import get_default_paths

    paths = get_default_paths()
    config_path = paths["config"]
    log_path    = paths["log_file"]
    spool_path  = paths["spool_dir"]
    bookmarks   = paths["bookmarks_dir"]

Design rationale:
    - Single function returns a dict (easier to extend than 4 functions)
    - No global mutable state (testable, no monkey-patching needed)
    - platform.system() is the canonical Python OS detection API
    - All paths are absolute and use the OS-native separator
"""
import platform
from pathlib import Path
from typing import Dict


# Windows ProgramData base directory.
# This is the Microsoft-recommended location for service-owned application
# data on Windows (writable by LocalSystem, persists across user sessions,
# excluded from user-profile backups).
_WINDOWS_DATA_ROOT = Path("C:/ProgramData/Cybersafe")

# Linux/macOS paths follow the Filesystem Hierarchy Standard (FHS).
_LINUX_CONFIG_DIR = Path("/etc/cybersafe")
_LINUX_LOG_DIR    = Path("/var/log")
_LINUX_SPOOL_DIR  = Path("/var/spool/cybersafe")


def get_default_paths() -> Dict[str, str]:
    """
    Return the default filesystem paths for the current OS.

    Returns:
        Dict with string paths (str, not Path, for backward compat with
        YAML config which uses strings):
            - config:         path to config.yaml
            - log_file:       path to agent.log
            - spool_dir:      directory for spooled events (resilience)
            - bookmarks_dir:  directory for Windows Event Log bookmarks
                              (empty string "" on Linux/macOS — unused)

    The returned paths are NOT created on disk. The caller is responsible
    for ensuring directories exist before reading/writing.
    """
    system = platform.system()  # "Linux", "Windows", "Darwin"

    if system == "Windows":
        return {
            "config":        str(_WINDOWS_DATA_ROOT / "config" / "config.yaml"),
            "log_file":      str(_WINDOWS_DATA_ROOT / "logs" / "agent.log"),
            "spool_dir":     str(_WINDOWS_DATA_ROOT / "spool"),
            "bookmarks_dir": str(_WINDOWS_DATA_ROOT / "bookmarks"),
        }

    # Linux + macOS (Darwin) + any other Unix-like fall through here.
    return {
        "config":        str(_LINUX_CONFIG_DIR / "config.yaml"),
        "log_file":      str(_LINUX_LOG_DIR / "cybersafe-agent.log"),
        "spool_dir":     str(_LINUX_SPOOL_DIR),
        "bookmarks_dir": "",  # Windows Event Log feature, unused on Linux
    }


def is_windows() -> bool:
    """Return True if running on Windows. Single source of truth for OS check."""
    return platform.system() == "Windows"
