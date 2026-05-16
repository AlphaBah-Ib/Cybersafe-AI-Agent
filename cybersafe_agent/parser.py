"""
Façade publique du parser multi-plateforme.

Cette façade détecte le format de la ligne reçue et délègue à
l'implémentation appropriée :
  - Ligne commençant par `{"channel":` → JSON Windows Event Log
    → parsers.windows.line_to_event()
  - Sinon → texte brut syslog Linux/macOS
    → parsers.linux.line_to_event()

L'API publique `line_to_event(line, source_path) -> dict` reste identique
à l'historique pour garantir zéro régression sur le code existant qui
consomme cette fonction (main.py via `from .parser import line_to_event`).

Pattern : "Strategy via content detection" — on ne se base PAS sur l'OS
au runtime (l'agent peut très bien tourner sur Linux et recevoir du JSON
Windows via un agent forwarder distant à l'avenir), mais sur le contenu
de la ligne elle-même. Plus robuste long terme.

Historique :
  - SOC-011 : Parser Linux/syslog initial
  - SOC-200 : Refactor en façade multi-plateforme (Phase 2 Windows)
"""
from . import parsers as _parsers_pkg  # noqa: F401 — force load du package


# Préfixe utilisé par WindowsLogTailer pour sérialiser ses events en JSON
# avant de les passer au callback. C'est ce préfixe qui sert de signature
# pour distinguer Windows (JSON) de Linux (texte syslog).
_WINDOWS_JSON_PREFIX = '{"channel":'


def line_to_event(line: str, source_path: str) -> dict:
    """
    Transforme une ligne de log (Linux syslog OU Windows JSON) en payload
    event prêt pour /api/soc/ingest/.

    Détection automatique du format :
      - Ligne commence par `{"channel":` → Windows Event Log (JSON)
      - Sinon → Linux/macOS syslog (texte brut)

    Le contrat de retour est identique pour les 2 cas (dict avec keys
    source, raw, event_type, severity, ts, parsed).
    """
    # On strip ici pour gérer les lignes avec espaces/tabs au début.
    stripped = line.lstrip() if line else ""

    if stripped.startswith(_WINDOWS_JSON_PREFIX):
        # Délégation au parser Windows pour les events JSON.
        from .parsers.windows import line_to_event as _windows_line_to_event
        return _windows_line_to_event(line, source_path)

    # Par défaut, parser Linux/syslog (préserve le comportement historique).
    from .parsers.linux import line_to_event as _linux_line_to_event
    return _linux_line_to_event(line, source_path)


__all__ = ["line_to_event"]
