"""
Parser pour les logs Linux/syslog (auth.log, syslog, nginx, etc.).

SOC-200 / Phase 2 :
Anciennement situé dans cybersafe_agent/parser.py, ce code a été déplacé
ici dans le cadre du refactor multi-plateforme. La façade publique reste
cybersafe_agent.parser.line_to_event(), qui détecte le format de la ligne
et délègue au bon parser (Linux ou Windows).

Spécificités Linux :
- Patterns regex pour SSH (auth.log), sudo, sessions
- Extraction IP, user, port, PID, commande
- Détection de sévérité par mots-clés syslog
"""
import os
import re
from datetime import datetime, timezone
from typing import Tuple


# ── Patterns regex précompilés ───────────────────────────────────────────
RE_IP = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
RE_USER_FROM = re.compile(r"for (\w+) from")
RE_USER_INVALID = re.compile(r"[Ii]nvalid user (\w+)")
RE_PORT = re.compile(r"port (\d+)")
RE_PID = re.compile(r"\[(\d+)\]")
RE_SUDO_USER = re.compile(r"sudo:\s+(\w+)\s*:")
RE_SUDO_CMD = re.compile(r"COMMAND=(\S+(?:\s\S+)*)")


def detect_severity_and_type(line: str) -> Tuple[str, str]:
    """
    Détermine (severity, event_type) à partir de patterns courants Linux.

    Retourne un tuple (severity, event_type).
    Severity: info, low, medium, high, critical
    """
    lower = line.lower()

    # Tentatives d'authentification (sévérité haute)
    if "failed password" in lower:
        return ("high", "ssh_failed_login")
    if "authentication failure" in lower:
        return ("high", "auth_failure")
    if "invalid user" in lower:
        return ("high", "invalid_user")

    # Connexions réussies (sévérité moyenne — à monitorer)
    if "accepted password" in lower or "accepted publickey" in lower:
        return ("medium", "ssh_login_success")

    # Sudo (sévérité moyenne — à monitorer)
    if "sudo:" in lower and "command=" in lower:
        return ("medium", "sudo_command")

    # Sessions (info)
    if "session opened" in lower:
        return ("info", "session_opened")
    if "session closed" in lower:
        return ("info", "session_closed")

    # Erreurs systèmes (medium)
    if "error" in lower or "critical" in lower:
        return ("medium", "system_error")

    return ("info", "")


def extract_parsed_fields(line: str) -> dict:
    """Extrait des champs structurés (IP, user, port, etc.) de la ligne syslog."""
    parsed = {}

    if m := RE_IP.search(line):
        parsed["ip"] = m.group(1)

    # Extraction de l'utilisateur (3 patterns possibles)
    if m := RE_USER_FROM.search(line):
        parsed["user"] = m.group(1)
    elif m := RE_USER_INVALID.search(line):
        parsed["user"] = m.group(1)
    elif m := RE_SUDO_USER.search(line):
        parsed["user"] = m.group(1)

    if m := RE_PORT.search(line):
        try:
            parsed["port"] = int(m.group(1))
        except ValueError:
            pass

    if m := RE_PID.search(line):
        try:
            parsed["pid"] = int(m.group(1))
        except ValueError:
            pass

    if m := RE_SUDO_CMD.search(line):
        # Tronqué pour éviter abus (ex: COMMAND=cat /etc/shadow ...)
        parsed["cmd"] = m.group(1)[:200]

    return parsed


def line_to_event(line: str, source_path: str) -> dict:
    """
    Transforme une ligne de log Linux/syslog en payload event pour /api/soc/ingest/.

    Format conforme à docs/agent-event-format.md (SOC-011).
    """
    severity, event_type = detect_severity_and_type(line)
    return {
        "source": os.path.basename(source_path),
        "raw": line.strip()[:5000],  # tronqué pour éviter envoi monstrueux
        "event_type": event_type,
        "severity": severity,
        "ts": datetime.now(timezone.utc).isoformat(),
        "parsed": extract_parsed_fields(line),
    }
