"""
Façade publique du tailer multi-plateforme.

Cette façade détecte le système d'exploitation au runtime et délègue
à l'implémentation appropriée :
  - Linux/macOS : LinuxLogTailer (fichiers /var/log/*.log via tail -f)
  - Windows     : WindowsLogTailer (Event Log via pywin32) [Phase 2 SOC-200]

L'API publique `LogTailer` reste identique à l'historique pour garantir
zéro régression sur le code existant qui consomme cette classe (main.py).

Pattern : "Factory façade" — détecte l'OS et expose un alias `LogTailer`
qui pointe vers l'implémentation concrète. Le reste du code ne sait pas
sur quelle plateforme il tourne, et n'a pas besoin de le savoir.

Historique :
  - SOC-020 : Implémentation Linux initiale (avant SOC-200)
  - SOC-200 : Refactor en façade multi-plateforme (Phase 2 Windows)
"""
import platform as _platform_module

# Détection de l'OS au moment de l'import (évalué une seule fois).
# On utilise platform.system() qui retourne :
#   - "Linux"   sur Linux
#   - "Darwin"  sur macOS
#   - "Windows" sur Windows
_OS_NAME = _platform_module.system()


if _OS_NAME == "Windows":
    # Phase 2 SOC-200 — Implémentation Windows via Event Log + pywin32.
    # Cet import lèvera ImportError si pywin32 n'est pas installé,
    # ce qui est le comportement souhaité (fail-fast au démarrage).
    from .platforms.windows import WindowsLogTailer as LogTailer  # noqa: F401

elif _OS_NAME in ("Linux", "Darwin"):
    # Implémentation historique pour Linux et macOS (lecture fichiers
    # via tail -f avec détection de rotation logrotate).
    from .platforms.linux import LinuxLogTailer as LogTailer  # noqa: F401

else:
    # OS non supporté : on lève une erreur explicite au démarrage
    # plutôt que de laisser un comportement imprévisible.
    raise RuntimeError(
        f"Système d'exploitation non supporté par Cybersafe Agent : "
        f"'{_OS_NAME}'. Plateformes supportées : Linux, macOS, Windows."
    )


__all__ = ["LogTailer"]
