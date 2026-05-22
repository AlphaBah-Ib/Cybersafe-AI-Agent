"""
Parser pour les logs Apache access.log (SOC-301 / Phase 3 Web servers).

Apache et nginx partagent le meme format "combined" (nginx l'a historiquement
copie d'Apache). Ce parser REUTILISE donc la regex combined de parsers.nginx
(DRY) et n'ajoute que ce qui est specifique a Apache : le format "common"
(Common Log Format, CLF), tres repandu sur les serveurs Apache, qui omet les
champs Referer et User-Agent.

Formats Apache access.log geres :
  - combined (LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"")
      127.0.0.1 - frank [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 200 1234 "https://ref" "Mozilla/5.0"
      => identique au combined nginx, parse par RE_NGINX_COMBINED
  - common / CLF (LogFormat "%h %l %u %t \"%r\" %>s %b")
      127.0.0.1 - frank [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 200 1234
      => sans Referer ni User-Agent, parse par RE_APACHE_COMMON

Auto-detection : si fmt == "auto" (ou inconnu), on tente combined d'abord,
puis common en fallback. Si le YAML precise format: combined ou format: common,
on respecte ce choix (mais on garde un fallback pour la robustesse).

Le mapping severity (status HTTP -> severity/event_type) est strictement le
meme que nginx (c'est du HTTP standard), donc on reutilise aussi
_access_severity_and_type de parsers.nginx.

Robustesse : aucune ligne ne crashe. Ligne non reconnue -> parse_failed +
severity info (pas de fausse alerte). event_type prefixe "apache_*".

Historique :
  - SOC-301 : Parser Apache access.log initial (Phase 3 Web servers)
"""
import os
import re
from datetime import datetime, timezone

# Reutilisation DRY des composants partages avec nginx (format combined
# identique + severity HTTP standard + parsing du time_local).
from .nginx import (
    RE_NGINX_COMBINED,
    RE_NGINX_COMBINED_LOOSE,
    _parse_nginx_time,
    _access_severity_and_type,
)


# ── access.log common / CLF (specifique Apache) ────────────────────────────
# %h %l %u %t "%r" %>s %b   (PAS de referer ni user-agent)
# 127.0.0.1 - frank [22/May/2026:00:15:23 +0000] "GET /page HTTP/1.1" 200 1234
RE_APACHE_COMMON = re.compile(
    r"(?P<ip>\S+)\s+"                        # %h remote host
    r"\S+\s+"                                # %l ident (souvent -)
    r"(?P<user>\S+)\s+"                      # %u remote user (- si absent)
    r"\[(?P<time>[^\]]+)\]\s+"               # %t [time_local]
    r'"(?P<method>[A-Z]+)\s+'                # "%r -> METHOD
    r"(?P<path>[^\"\s]*)"                    #        path
    r'(?:\s+(?P<protocol>HTTP/[\d.]+))?"\s+' #        HTTP/1.1"
    r"(?P<status>\d{3})\s+"                  # %>s status
    r"(?P<size>\d+|-)\s*$"                   # %b body bytes (- si 0), fin de ligne
)


def _build_parsed_from_combined_match(m) -> dict:
    """Construit le dict parsed depuis un match RE_NGINX_COMBINED."""
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
    ts = _parse_nginx_time(d["time"])
    if ts:
        parsed["apache_time"] = ts
    return parsed


def _build_parsed_from_common_match(m) -> dict:
    """Construit le dict parsed depuis un match RE_APACHE_COMMON (pas de UA/referer)."""
    d = m.groupdict()
    parsed = {
        "ip": d["ip"],
        "method": d["method"],
        "path": d["path"][:2000],
        "status": int(d["status"]),
        "size": 0 if d["size"] == "-" else int(d["size"]),
        "log_format": "common",
    }
    if d.get("protocol"):
        parsed["protocol"] = d["protocol"]
    if d.get("user") and d["user"] != "-":
        parsed["user"] = d["user"]
    ts = _parse_nginx_time(d["time"])
    if ts:
        parsed["apache_time"] = ts
    return parsed


def parse_access(line: str, fmt: str = "auto") -> dict:
    """
    Parse une ligne Apache access.log (combined OU common).

    Args:
        line: ligne brute du access.log
        fmt: "auto" (defaut, tente combined puis common) | "combined" | "common"

    Retourne un dict de champs (ip, method, path, status, size, et selon le
    format user_agent/referer pour combined). En cas d'echec : parse_failed.
    """
    fmt = (fmt or "auto").lower()

    # Si common explicitement demande : on tente common d'abord
    if fmt == "common":
        m = RE_APACHE_COMMON.search(line)
        if m:
            return _build_parsed_from_common_match(m)
        # fallback combined au cas ou
        m = RE_NGINX_COMBINED.search(line)
        if m:
            return _build_parsed_from_combined_match(m)
        return {"parse_failed": True}

    # fmt "combined" ou "auto" : on tente combined d'abord (plus riche)
    m = RE_NGINX_COMBINED.search(line)
    if m:
        return _build_parsed_from_combined_match(m)

    # Puis common (CLF sans referer/user-agent)
    m = RE_APACHE_COMMON.search(line)
    if m:
        return _build_parsed_from_common_match(m)

    # Fallback loose (request malformee : on recupere au moins ip + status)
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


def line_to_event_access(line: str, source_path: str, fmt: str = "auto") -> dict:
    """
    Transforme une ligne Apache access.log en payload event /api/soc/ingest/.

    event_type prefixe "apache_*" (apache_access, apache_4xx, apache_5xx,
    apache_access_denied, apache_404, apache_conn_closed).
    """
    parsed = parse_access(line, fmt)
    status = parsed.get("status", 0)
    severity, event_type_nginx = _access_severity_and_type(status)
    # On reutilise le mapping nginx mais on re-prefixe en apache_*
    event_type = event_type_nginx.replace("nginx_", "apache_", 1)
    if parsed.get("parse_failed"):
        severity, event_type = ("info", "apache_access_unparsed")
    return {
        "source": os.path.basename(source_path),
        "raw": line.strip()[:5000],
        "event_type": event_type,
        "severity": severity,
        "ts": datetime.now(timezone.utc).isoformat(),
        "parsed": parsed,
    }


__all__ = [
    "RE_APACHE_COMMON",
    "parse_access",
    "line_to_event_access",
]
