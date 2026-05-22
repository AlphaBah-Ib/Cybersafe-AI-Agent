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


def line_to_event(
    line: str,
    source_path: str,
    source_type: str = "auto",
    source_format: str = "combined",
) -> dict:
    """
    Transforme une ligne de log en payload event prêt pour /api/soc/ingest/.

    Routing du parser selon le type de source declare dans la config (SOC-300) :
      - source_type == "nginx_access" -> parsers.nginx.line_to_event_access
      - source_type == "nginx_error"  -> parsers.nginx.line_to_event_error
      - source_type == "apache_access" -> parsers.apache.line_to_event_access
      - source_type == "iis_access"   -> parsers.iis.line_to_event_access
      - source_type == "auto" (defaut) -> detection par CONTENU :
            * ligne commence par `{"channel":` -> Windows Event Log (JSON)
            * sinon                            -> Linux/macOS syslog (texte brut)

    Le mode "auto" preserve a l'identique le comportement historique
    (SOC-011 + SOC-200), garantissant ZERO regression sur les sources
    existantes (auth.log, syslog, Windows Event Log).

    Le contrat de retour est identique pour tous les cas (dict avec keys
    source, raw, event_type, severity, ts, parsed).

    Args:
        line: ligne brute de log
        source_path: chemin du fichier source (pour le champ "source")
        source_type: type de la source ("auto" | "nginx_access" | "nginx_error")
        source_format: format nginx ("combined" | "custom"), pertinent pour
                       nginx_access uniquement
    """
    # ── Routing explicite par type (SOC-300) ────────────────────────────────
    if source_type == "nginx_access":
        from .parsers.nginx import line_to_event_access
        return line_to_event_access(line, source_path, source_format)

    if source_type == "nginx_error":
        from .parsers.nginx import line_to_event_error
        return line_to_event_error(line, source_path)

    # ── Apache access.log (SOC-301) ─────────────────────────────────────────
    # Apache combined == nginx combined ; le parser apache reutilise la regex
    # combined de nginx et ajoute le format "common" (CLF). Auto-detection si
    # source_format vaut "auto" ou n'est pas precise.
    if source_type == "apache_access":
        from .parsers.apache import line_to_event_access as _apache_access
        return _apache_access(line, source_path, source_format)

    # ── IIS access logs W3C (SOC-302) ───────────────────────────────────────
    # Format W3C Extended (auto-descriptif via en-tete #Fields:). Le parser
    # est stateful : il retient l'ordre des colonnes par fichier. source_path
    # sert de cle pour cet etat, d'ou son importance ici.
    if source_type == "iis_access":
        from .parsers.iis import line_to_event_access as _iis_access
        return _iis_access(line, source_path, source_format)

    # ── Mode "auto" : detection par contenu (comportement historique) ───────
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
