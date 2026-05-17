"""
Tests unitaires pour cybersafe_agent.paths

SOC-204 : valide la résolution cross-OS des paths par défaut.

Stratégie de test :
  - Mock platform.system() pour simuler Linux, Windows, macOS
  - Vérifie qu'aucun path Linux ne fuit dans le retour Windows et vice-versa
  - Couvre les edge cases (Darwin, OS exotique)
  - Garantit la backward compatibility Linux (paths historiques inchangés)

Pour lancer :
    cd ~/cybersafe-agent
    python -m pytest tests/test_paths.py -v
"""
from unittest.mock import patch

import pytest

from cybersafe_agent.paths import get_default_paths, is_windows


# =============================================================================
# Linux defaults (backward compat critique pour les deploiements Ubuntu existants)
# =============================================================================

class TestLinuxDefaults:
    """Sur Linux, les paths historiques DOIVENT rester inchanges."""

    def test_config_path_linux(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Linux"):
            paths = get_default_paths()
            assert paths["config"] == "/etc/cybersafe/config.yaml"

    def test_log_file_linux(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Linux"):
            paths = get_default_paths()
            assert paths["log_file"] == "/var/log/cybersafe-agent.log"

    def test_spool_dir_linux(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Linux"):
            paths = get_default_paths()
            assert paths["spool_dir"] == "/var/spool/cybersafe"

    def test_bookmarks_dir_empty_on_linux(self):
        """Sur Linux, bookmarks_dir doit etre vide (feature Windows-only)."""
        with patch("cybersafe_agent.paths.platform.system", return_value="Linux"):
            paths = get_default_paths()
            assert paths["bookmarks_dir"] == ""

    def test_all_keys_present_linux(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Linux"):
            paths = get_default_paths()
            assert set(paths.keys()) == {
                "config", "log_file", "spool_dir", "bookmarks_dir"
            }


# =============================================================================
# Windows defaults (nouveaux paths cross-OS pour SOC-204)
# =============================================================================

class TestWindowsDefaults:
    """Sur Windows, les paths doivent etre sous C:\\ProgramData\\Cybersafe\\."""

    def test_config_path_windows(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Windows"):
            paths = get_default_paths()
            assert paths["config"] == "C:/ProgramData/Cybersafe/config/config.yaml"

    def test_log_file_windows(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Windows"):
            paths = get_default_paths()
            assert paths["log_file"] == "C:/ProgramData/Cybersafe/logs/agent.log"

    def test_spool_dir_windows(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Windows"):
            paths = get_default_paths()
            assert paths["spool_dir"] == "C:/ProgramData/Cybersafe/spool"

    def test_bookmarks_dir_windows(self):
        """Sur Windows, bookmarks_dir doit etre defini (utilise par EventLog tail)."""
        with patch("cybersafe_agent.paths.platform.system", return_value="Windows"):
            paths = get_default_paths()
            assert paths["bookmarks_dir"] == "C:/ProgramData/Cybersafe/bookmarks"

    def test_all_keys_present_windows(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Windows"):
            paths = get_default_paths()
            assert set(paths.keys()) == {
                "config", "log_file", "spool_dir", "bookmarks_dir"
            }


# =============================================================================
# Isolation : aucune fuite cross-OS
# =============================================================================

class TestNoOSLeak:
    """Garantit qu'aucun path Windows ne fuit dans le retour Linux et vice-versa."""

    def test_no_windows_path_on_linux(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Linux"):
            paths = get_default_paths()
            for key, value in paths.items():
                assert "C:" not in value, (
                    f"Path Windows fuit dans le retour Linux: {key}={value}"
                )
                assert "ProgramData" not in value, (
                    f"Path Windows fuit dans le retour Linux: {key}={value}"
                )

    def test_no_linux_path_on_windows(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Windows"):
            paths = get_default_paths()
            for key, value in paths.items():
                # bookmarks_dir reste "" sur Linux mais a une valeur sur Windows
                # donc on check la presence de prefixes Unix dans des paths non-vides
                if value:
                    assert not value.startswith("/etc/"), (
                        f"Path Linux fuit dans le retour Windows: {key}={value}"
                    )
                    assert not value.startswith("/var/"), (
                        f"Path Linux fuit dans le retour Windows: {key}={value}"
                    )


# =============================================================================
# Edge cases : macOS et OS inconnus
# =============================================================================

class TestEdgeCases:
    """Comportement sur les OS non-mainstream."""

    def test_macos_treated_as_linux(self):
        """Darwin (macOS) doit tomber dans le branch Linux par defaut."""
        with patch("cybersafe_agent.paths.platform.system", return_value="Darwin"):
            paths = get_default_paths()
            # On herite des paths Linux (FHS-compatible)
            assert paths["config"] == "/etc/cybersafe/config.yaml"
            assert paths["bookmarks_dir"] == ""

    def test_unknown_os_fallback_to_linux(self):
        """OS exotique (FreeBSD, etc.) tombe sur les defaults Linux."""
        with patch("cybersafe_agent.paths.platform.system", return_value="FreeBSD"):
            paths = get_default_paths()
            assert paths["config"] == "/etc/cybersafe/config.yaml"


# =============================================================================
# is_windows() helper
# =============================================================================

class TestIsWindows:
    """Le helper is_windows() doit etre la single source of truth pour l'OS check."""

    def test_returns_true_on_windows(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Windows"):
            assert is_windows() is True

    def test_returns_false_on_linux(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Linux"):
            assert is_windows() is False

    def test_returns_false_on_macos(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Darwin"):
            assert is_windows() is False


# =============================================================================
# Types de retour : tous les paths sont des str (compat YAML config)
# =============================================================================

class TestReturnTypes:
    """Les paths sont retournes en str (pas Path) pour compat YAML."""

    def test_all_paths_are_strings_linux(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Linux"):
            paths = get_default_paths()
            for key, value in paths.items():
                assert isinstance(value, str), (
                    f"{key} doit etre str, recu {type(value).__name__}"
                )

    def test_all_paths_are_strings_windows(self):
        with patch("cybersafe_agent.paths.platform.system", return_value="Windows"):
            paths = get_default_paths()
            for key, value in paths.items():
                assert isinstance(value, str), (
                    f"{key} doit etre str, recu {type(value).__name__}"
                )
