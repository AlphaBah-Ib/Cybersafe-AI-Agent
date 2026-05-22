"""
Parser pour les logs IIS au format W3C Extended (SOC-302 / Phase 3).

IIS utilise le W3C Extended Log File Format, fondamentalement different de
nginx/apache : c'est un format AUTO-DESCRIPTIF. Un en-tete #Fields: declare
l'ordre des colonnes, configurable par l'admin IIS. Les lignes de donnees
sont des valeurs separees par des espaces, "-" pour un champ absent.

Exemple de fichier IIS :
    #Software: Microsoft Internet Information Services 10.0
    #Version: 1.0
    #Date: 2026-05-22 00:00:00
    #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken
    2026-05-22 00:15:23 10.0.0.5 GET /admin/login - 80 - 203.0.113.5 Mozilla/5.0 403 0 0 125

PARSER STATEFUL :
Le tailer envoie les lignes une par une, sans contexte. Or l'interpretation
d'une ligne de donnees depend du dernier #Fields: vu. On maintient donc un
etat par fichier source : _fields_by_source[source_path] = [liste des champs].

Quand l'agent demarre en plein milieu d'un fichier IIS (seek a la fin), il
n'a pas encore vu de #Fields:. On utilise alors l'ordre PAR DEFAUT IIS 7+
(_DEFAULT_FIELDS) jusqu'a voir un vrai #Fields: (a la prochaine rotation IIS,
le nouveau fichier commence par les en-tetes #).

Mapping des champs W3C vers nos champs d'event :
    c-ip            -> ip          (client IP, PAS s-ip qui est le serveur)
    cs-method       -> method
    cs-uri-stem     -> path
    cs-uri-query    -> query
    sc-status       -> status
    sc-substatus    -> substatus   (sous-code IIS, ex: 403.4 -> substatus 4)
    cs(User-Agent)  -> user_agent  (les + sont decodes en espaces)
    cs(Referer)     -> referer
    time-taken      -> time_taken_ms

Severity : reutilise _access_severity_and_type de parsers.nginx (HTTP
standard), re-prefixe iis_*. event_type : iis_access, iis_4xx, iis_5xx,
iis_access_denied, iis_404, iis_conn_closed.

Robustesse : ligne de commentaire (#) ignoree (sauf #Fields:). Ligne de
donnees non parsable -> parse_failed + severity info (pas de fausse alerte).

Historique :
  - SOC-302 : Parser IIS W3C initial (Phase 3 Web servers Windows)
"""
import os
from datetime import datetime, timezone

from .nginx import _access_severity_and_type


# Ordre des champs par defaut IIS 7+ (W3C Extended).
# Utilise tant qu'aucun #Fields: explicite n'a ete vu pour le fichier.
_DEFAULT_FIELDS = [
    "date", "time", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query",
    "s-port", "cs-username", "c-ip", "cs(User-Agent)", "cs(Referer)",
    "sc-status", "sc-substatus", "sc-win32-status", "time-taken",
]

# Etat par fichier : {source_path: [liste des champs declares par #Fields:]}
# Module-level pour garder line_to_event_access(line, source_path) stateless
# en signature (compatible facade) tout en isolant l'etat par fichier.
_fields_by_source = {}


def reset_state(source_path: str = None):
    """
    Reinitialise l'etat des champs. Utile pour les tests et lors d'une
    rotation de fichier. Si source_path est None, reinitialise tout.
    """
    if source_path is None:
        _fields_by_source.clear()
    else:
        _fields_by_source.pop(source_path, None)


def _decode_w3c_value(value: str) -> str:
    """Decode une valeur W3C : '-' -> '', '+' -> espace (encodage IIS)."""
    if value == "-":
        return ""
    return value.replace("+", " ")


def _parse_fields_header(line: str) -> list:
    """Parse une ligne '#Fields: date time c-ip ...' -> liste des champs."""
    # Retire le prefixe "#Fields:" et split sur les espaces
    after = line.split(":", 1)[1] if ":" in line else ""
    return [f.strip() for f in after.split() if f.strip()]


def _parse_w3c_datetime(date_str: str, time_str: str):
    """Combine les champs date + time IIS (UTC) en ISO 8601. None si echec."""
    if not date_str or not time_str:
        return None
    try:
        dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except (ValueError, TypeError):
        return None


def _looks_like_ip(value: str) -> bool:
    """
    Validation basique : value ressemble-t-elle a une IPv4 ou IPv6 ?

    Evite d'accepter des valeurs aberrantes comme "ip" sur des lignes
    pourries (le mapping positionnel W3C peut sinon prendre n'importe
    quel mot comme IP).
    """
    if not value:
        return False
    # IPv4 : 4 octets 0-255 separes par des points
    if value.count(".") == 3:
        parts = value.split(".")
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    # IPv6 : contient au moins 2 ':' et seulement des caracteres hex/:/. 
    if ":" in value:
        allowed = set("0123456789abcdefABCDEF:.")
        return all(c in allowed for c in value) and value.count(":") >= 2
    return False


def parse_access(line: str, source_path: str = "") -> dict:
    """
    Parse une ligne IIS W3C.

    Gere les lignes de commentaire (#) : #Fields: met a jour l'etat des
    colonnes pour ce fichier ; les autres # sont ignorees (retour
    {"comment": True}). Les lignes de donnees sont mappees selon l'ordre
    des colonnes en vigueur (declare ou defaut).

    Retourne un dict de champs (ip, method, path, status, ...) ou
    {"parse_failed": True} / {"comment": True}.
    """
    stripped = line.strip()
    if not stripped:
        return {"parse_failed": True}

    # Ligne de commentaire
    if stripped.startswith("#"):
        lower = stripped.lower()
        if lower.startswith("#fields:"):
            fields = _parse_fields_header(stripped)
            if fields:
                _fields_by_source[source_path] = fields
        return {"comment": True}

    # Ligne de donnees : on utilise les champs declares, sinon le defaut.
    # used_fallback = True si on n'a JAMAIS vu de #Fields: pour ce fichier
    # (agent demarre en plein milieu) -> interpretation "best effort".
    used_fallback = source_path not in _fields_by_source
    fields = _fields_by_source.get(source_path, _DEFAULT_FIELDS)
    values = stripped.split(" ")

    # Tolere les #Fields: custom courts (ex: "c-ip cs-method sc-status").
    # On ne rejette que si vraiment trop court (< 2 valeurs). Le garde-fou
    # final (ni status ni ip -> parse_failed) attrape les lignes pourries.
    if len(values) < 2:
        return {"parse_failed": True}

    raw_map = {}
    for i, field in enumerate(fields):
        if i < len(values):
            raw_map[field] = values[i]

    parsed = {}

    # IP client (c-ip). Fallback sur s-ip uniquement si c-ip absent.
    # On valide le format IP pour ne pas accepter de valeurs aberrantes
    # (ex: une ligne pourrie dont un mot tomberait sur la colonne c-ip).
    ip = raw_map.get("c-ip") or raw_map.get("s-ip")
    if ip and ip != "-" and _looks_like_ip(ip):
        parsed["ip"] = ip

    if (m := raw_map.get("cs-method")) and m != "-":
        parsed["method"] = m

    if (p := raw_map.get("cs-uri-stem")) and p != "-":
        parsed["path"] = p[:2000]

    q = raw_map.get("cs-uri-query")
    if q and q != "-":
        parsed["query"] = _decode_w3c_value(q)[:2000]

    # Status HTTP
    status_str = raw_map.get("sc-status", "")
    if status_str and status_str.isdigit():
        parsed["status"] = int(status_str)

    sub = raw_map.get("sc-substatus")
    if sub and sub.isdigit():
        parsed["substatus"] = int(sub)

    ua = raw_map.get("cs(User-Agent)")
    if ua and ua != "-":
        parsed["user_agent"] = _decode_w3c_value(ua)[:500]

    ref = raw_map.get("cs(Referer)")
    if ref and ref != "-":
        parsed["referer"] = _decode_w3c_value(ref)[:500]

    user = raw_map.get("cs-username")
    if user and user != "-":
        parsed["user"] = user

    tt = raw_map.get("time-taken")
    if tt and tt.isdigit():
        parsed["time_taken_ms"] = int(tt)

    # Timestamp IIS (date + time, UTC)
    iis_ts = _parse_w3c_datetime(raw_map.get("date", ""), raw_map.get("time", ""))
    if iis_ts:
        parsed["iis_time"] = iis_ts

    # Si on n'a meme pas reussi a extraire un status, c'est suspect
    if "status" not in parsed and "ip" not in parsed:
        return {"parse_failed": True}

    # Signale une interpretation best-effort (champs par defaut, pas de
    # #Fields: vu pour ce fichier). L'analyste sait que le mapping POURRAIT
    # etre decale si l'admin IIS utilise un format custom.
    if used_fallback:
        parsed["parse_partial"] = True

    return parsed


def line_to_event_access(line: str, source_path: str, fmt: str = "auto") -> dict:
    """
    Transforme une ligne IIS W3C en payload event /api/soc/ingest/.

    Les lignes de commentaire (#) produisent un event "info" de type
    iis_log_meta (utile pour tracer, mais sans alerte). #Fields: met a jour
    l'etat des colonnes au passage.

    event_type prefixe iis_* (iis_access, iis_4xx, iis_5xx,
    iis_access_denied, iis_404, iis_conn_closed).
    """
    parsed = parse_access(line, source_path)

    # Ligne de commentaire / header : event meta, pas d'alerte
    if parsed.get("comment"):
        return {
            "source": os.path.basename(source_path),
            "raw": line.strip()[:5000],
            "event_type": "iis_log_meta",
            "severity": "info",
            "ts": datetime.now(timezone.utc).isoformat(),
            "parsed": {"comment": True},
        }

    status = parsed.get("status", 0)
    severity, event_type_nginx = _access_severity_and_type(status)
    event_type = event_type_nginx.replace("nginx_", "iis_", 1)

    if parsed.get("parse_failed"):
        severity, event_type = ("info", "iis_access_unparsed")

    return {
        "source": os.path.basename(source_path),
        "raw": line.strip()[:5000],
        "event_type": event_type,
        "severity": severity,
        "ts": datetime.now(timezone.utc).isoformat(),
        "parsed": parsed,
    }


__all__ = [
    "parse_access",
    "line_to_event_access",
    "reset_state",
    "_DEFAULT_FIELDS",
]
