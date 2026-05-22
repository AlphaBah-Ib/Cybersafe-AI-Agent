"""
Parser pour les logs nginx (access.log + error.log).

SOC-300 / Phase 3 — Web servers.

access.log :
  - Format "combined" (defaut nginx) :
      $remote_addr - $remote_user [$time_local] "$request" $status
      $body_bytes_sent "$http_referer" "$http_user_agent"
  - Format "custom" : gere via log_format string (V2, fallback combined)

error.log :
  2026/05/21 10:15:23 [error] 12345#0: *678 message, client: 1.2.3.4,
  server: example.com, request: "GET / HTTP/1.1", host: "example.com"

Severity mapping (access) base sur le status HTTP :
  - 2xx, 3xx        -> info
  - 401, 403        -> high   (acces refuse / tentative d'intrusion)
  - 404             -> low    (bruit frequent, mais utile pour scan detection)
  - autres 4xx      -> medium
  - 444             -> high   (nginx ferme la connexion - souvent bot/attaque)
  - 5xx             -> high   (erreur serveur, possible exploitation)

Severity mapping (error) base sur le niveau nginx :
  - [debug] [info] [notice] -> info
  - [warn]                  -> low
  - [error]                 -> medium
  - [crit] [alert] [emerg]  -> high

Robustesse : aucune ligne ne doit jamais crasher le parser. Une ligne
non reconnue retourne {"parse_failed": True} et un event de severite "info"
(pas de fausse alerte).

Historique :
  - SOC-300 : Parser nginx initial (Phase 3 Web servers)
"""
import os
import re
from datetime import datetime, timezone
from typing import Optional


# ── access.log combined ──────────────────────────────────────────────────
# 192.168.1.1 - alice [21/May/2026:10:15:23 +0000] "GET /path HTTP/1.1" 200 1234 "https://ref" "Mozilla/5.0"
RE_NGINX_COMBINED = re.compile(
    r"(?P<ip>\S+)\s+"                        # remote_addr
    r"\S+\s+"                                # ident (ignore, souvent -)
    r"(?P<user>\S+)\s+"                      # remote_user (- si absent)
    r"\[(?P<time>[^\]]+)\]\s+"               # [time_local]
    r'"(?P<method>[A-Z]+)\s+'                # "METHOD
    r"(?P<path>[^\"\s]*)"                    #  path
    r'(?:\s+(?P<protocol>HTTP/[\d.]+))?"\s+' #  HTTP/1.1"
    r"(?P<status>\d{3})\s+"                  # status
    r"(?P<size>\d+|-)\s+"                    # body_bytes_sent
    r'"(?P<referer>[^"]*)"\s+'               # "referer"
    r'"(?P<user_agent>[^"]*)"'               # "user_agent"
)

# Lignes malformees (request vide, methode inconnue) : fallback partiel
RE_NGINX_COMBINED_LOOSE = re.compile(
    r"(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
)

# ── error.log ──────────────────────────────────────────────────────────────
# 2026/05/21 10:15:23 [error] 12345#0: *678 open() failed, client: 1.2.3.4, server: ...
RE_NGINX_ERROR = re.compile(
    r"(?P<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"  # 2026/05/21 10:15:23
    r"\[(?P<level>\w+)\]\s+"                                # [error]
    r"(?P<pid>\d+)#(?P<tid>\d+):\s*"                        # 12345#0:
    r"(?:\*(?P<conn>\d+)\s+)?"                              # *678 (optionnel)
    r"(?P<message>.*)"                                      # le reste = message
)

# Client IP dans le message d'erreur : "..., client: 1.2.3.4, ..."
RE_ERROR_CLIENT = re.compile(r"client:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


# ── Parsing des timestamps nginx ───────────────────────────────────────────
def _parse_nginx_time(time_str: str) -> Optional[str]:
    """Convertit le time_local nginx (21/May/2026:10:15:23 +0000) en ISO 8601."""
    try:
        dt = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except (ValueError, TypeError):
        return None


def _parse_error_time(time_str: str) -> Optional[str]:
    """Convertit le timestamp error.log nginx (2026/05/21 10:15:23) en ISO 8601."""
    try:
        # error.log est en heure locale serveur (pas de TZ) -> on assume UTC
        dt = datetime.strptime(time_str, "%Y/%m/%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except (ValueError, TypeError):
        return None


# ── Severity mapping ────────────────────────────────────────────────────────
def _access_severity_and_type(status: int) -> tuple:
    """(severity, event_type) a partir du status HTTP."""
    if status in (401, 403):
        return ("high", "nginx_access_denied")
    if status == 404:
        return ("low", "nginx_404")
    if status == 444:
        return ("high", "nginx_conn_closed")
    if 500 <= status <= 599:
        return ("high", "nginx_5xx")
    if 400 <= status <= 499:
        return ("medium", "nginx_4xx")
    return ("info", "nginx_access")


_ERROR_LEVEL_SEVERITY = {
    "debug": "info", "info": "info", "notice": "info",
    "warn": "low",
    "error": "medium",
    "crit": "high", "alert": "high", "emerg": "high",
}


# ── Parsers de champs (publics, testables isolement) ────────────────────────
def parse_access_combined(line: str) -> dict:
    """
    Parse une ligne access.log combined.

    Retourne un dict de champs (ip, method, path, status, size, user_agent,
    et optionnellement protocol, referer, user, nginx_time).
    En cas d'echec total : {"parse_failed": True}.
    En cas d'echec partiel (request malformee) : {..., "parse_partial": True}.
    """
    m = RE_NGINX_COMBINED.search(line)
    if m:
        d = m.groupdict()
        parsed = {
            "ip": d["ip"],
            "method": d["method"],
            "path": d["path"][:2000],
            "status": int(d["status"]),
            "size": 0 if d["size"] == "-" else int(d["size"]),
            "user_agent": (d["user_agent"] or "")[:500],
        }
        if d.get("protocol"):
            parsed["protocol"] = d["protocol"]
        if d.get("referer") and d["referer"] != "-":
            parsed["referer"] = d["referer"][:500]
        if d.get("user") and d["user"] != "-":
            parsed["user"] = d["user"]
        nginx_ts = _parse_nginx_time(d["time"])
        if nginx_ts:
            parsed["nginx_time"] = nginx_ts
        return parsed

    # Fallback loose (request malformee : methode inconnue, request vide, etc.)
    m = RE_NGINX_COMBINED_LOOSE.search(line)
    if m:
        d = m.groupdict()
        return {
            "ip": d["ip"],
            "status": int(d["status"]),
            "size": 0 if d["size"] == "-" else int(d["size"]),
            "request_raw": d["request"][:2000],
            "parse_partial": True,
        }

    return {"parse_failed": True}


def parse_error(line: str) -> dict:
    """
    Parse une ligne error.log.

    Retourne un dict (level, error_message, et optionnellement pid,
    client_ip, nginx_time). En cas d'echec : {"parse_failed": True}.
    """
    m = RE_NGINX_ERROR.search(line)
    if not m:
        return {"parse_failed": True}
    d = m.groupdict()
    parsed = {
        "level": d["level"],
        "error_message": d["message"][:2000],
    }
    if d.get("pid"):
        parsed["pid"] = int(d["pid"])
    cm = RE_ERROR_CLIENT.search(d["message"])
    if cm:
        parsed["client_ip"] = cm.group(1)
    err_ts = _parse_error_time(d["time"])
    if err_ts:
        parsed["nginx_time"] = err_ts
    return parsed


# ── line_to_event publics (contrat /api/soc/ingest/) ────────────────────────
def line_to_event_access(line: str, source_path: str, fmt: str = "combined") -> dict:
    """
    Transforme une ligne access.log en payload event.

    Args:
        line: ligne brute du access.log
        source_path: chemin du fichier (pour le champ "source")
        fmt: "combined" (defaut) | "custom" (V2, fallback combined)
    """
    # fmt "custom" : V2 — pour l'instant fallback combined
    parsed = parse_access_combined(line)
    status = parsed.get("status", 0)
    severity, event_type = _access_severity_and_type(status)
    # Si parse echoue, on garde l'event mais en info (pas de fausse alerte)
    if parsed.get("parse_failed"):
        severity, event_type = ("info", "nginx_access_unparsed")
    return {
        "source": os.path.basename(source_path),
        "raw": line.strip()[:5000],
        "event_type": event_type,
        "severity": severity,
        "ts": datetime.now(timezone.utc).isoformat(),
        "parsed": parsed,
    }


def line_to_event_error(line: str, source_path: str) -> dict:
    """Transforme une ligne error.log en payload event."""
    parsed = parse_error(line)
    level = parsed.get("level", "error")
    severity = _ERROR_LEVEL_SEVERITY.get(level, "medium")
    event_type = f"nginx_error_{level}" if level else "nginx_error"
    if parsed.get("parse_failed"):
        severity, event_type = ("info", "nginx_error_unparsed")
    return {
        "source": os.path.basename(source_path),
        "raw": line.strip()[:5000],
        "event_type": event_type,
        "severity": severity,
        "ts": datetime.now(timezone.utc).isoformat(),
        "parsed": parsed,
    }


__all__ = [
    "parse_access_combined",
    "parse_error",
    "line_to_event_access",
    "line_to_event_error",
]
