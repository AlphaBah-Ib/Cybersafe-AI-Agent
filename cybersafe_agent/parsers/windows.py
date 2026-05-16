"""
Parser pour les events Windows Event Log (sérialisés en JSON par WindowsLogTailer).

SOC-200 / Phase 2 :
Reçoit des lignes JSON émises par cybersafe_agent.platforms.windows.WindowsLogTailer
et les normalise au même format que parsers/linux.py (dict avec keys source, raw,
event_type, severity, ts, parsed) pour que sender.py les envoie au backend de
manière identique aux events Linux.

Format JSON attendu en entrée :
    {
        "channel": "Security",
        "event_id": 4625,
        "level": "Information",
        "time_created": "2026-05-16T17:45:23+00:00",
        "computer": "DESKTOP-ABC",
        "provider": "Microsoft-Windows-Security-Auditing",
        "keywords": ["Audit Failure"],
        "event_data": {
            "TargetUserName": "admin",
            "IpAddress": "192.168.1.100",
            "LogonType": "3"
        },
        "message": "An account failed to log on..."
    }

Mapping EventID → (severity, event_type) aligné MITRE ATT&CK.
Le mapping est basé sur :
  - Recommandations Microsoft Security Baselines
  - CIS Microsoft Windows Benchmarks
  - MITRE ATT&CK Tactics (TA0001-TA0009)
"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Tuple


logger = logging.getLogger("cybersafe.parser.windows")


# =============================================================================
# Mapping EventID -> (severity, event_type)
# =============================================================================
# Aligné MITRE ATT&CK. Voir ADR-001 pour la justification de chaque EventID.
# Sévérité : info < low < medium < high < critical

WINDOWS_EVENT_MAPPING = {
    # ── Authentication (Security channel) ──────────────────────────────
    4624: ("medium",   "windows_logon_success"),       # TA0001 Initial Access
    4625: ("high",     "windows_logon_failed"),        # TA0006 Credential Access (brute force)
    4634: ("info",     "windows_logoff"),              # banal, faible intérêt SOC
    4647: ("info",     "windows_user_logoff"),         # logoff initié user
    4648: ("high",     "windows_explicit_creds"),      # TA0008 Lateral Movement
    4672: ("high",     "windows_admin_logon"),         # TA0004 Privilege Escalation
    4673: ("medium",   "windows_sensitive_priv"),      # TA0004 sensitive privilege use

    # ── Process & Service (Security channel) ───────────────────────────
    4688: ("medium",   "windows_process_create"),      # TA0002 Execution (CRITICAL VISIBILITY)
    4697: ("high",     "windows_service_install"),     # TA0003 Persistence (service)

    # ── Object access (Security channel) ───────────────────────────────
    4663: ("medium",   "windows_object_access"),       # TA0009 Collection (file/reg access)

    # ── Audit policy (Security channel) — TRES CRITIQUE ────────────────
    4719: ("critical", "windows_audit_policy_changed"),  # TA0005 Defense Evasion
    1102: ("critical", "windows_audit_log_cleared"),     # TA0005 (attaquant efface ses traces)

    # ── Account management (Security channel) ──────────────────────────
    4720: ("high",     "windows_user_created"),        # TA0003 Persistence
    4722: ("medium",   "windows_user_enabled"),        # account enabled
    4724: ("high",     "windows_password_reset"),      # TA0006 password reset attempt
    4725: ("medium",   "windows_user_disabled"),       # account disabled
    4728: ("high",     "windows_user_added_to_group"), # TA0004 added to security group
    4732: ("high",     "windows_user_added_to_local"), # TA0004 added to local group
    4738: ("medium",   "windows_user_changed"),        # user account modified

    # ── Kerberos (Security channel, AD environments) ───────────────────
    4768: ("medium",   "windows_kerberos_tgt"),        # TA0006 TGT requested
    4769: ("medium",   "windows_kerberos_service"),    # TA0006 service ticket requested

    # ── PowerShell (Microsoft-Windows-PowerShell/Operational) ──────────
    4103: ("medium",   "windows_powershell_module"),   # module logging
    4104: ("high",     "windows_powershell_script"),   # TA0002 script block (modern attacks)

    # ── Windows Defender (Microsoft-Windows-Windows Defender/Operational) ─
    1006: ("critical", "windows_malware_detected"),    # malware detected
    1007: ("critical", "windows_malware_action"),      # malware action taken
    1015: ("high",     "windows_defender_event"),      # suspicious activity

    # ── Task Scheduler (Microsoft-Windows-TaskScheduler/Operational) ───
    106:  ("medium",   "windows_task_registered"),     # TA0003 new task (persistence)
    140:  ("medium",   "windows_task_updated"),        # task updated
    141:  ("info",     "windows_task_deleted"),        # task deleted

    # ── RDP / Terminal Services ────────────────────────────────────────
    21:   ("medium",   "windows_rdp_session_start"),   # session reconnected
    23:   ("info",     "windows_rdp_session_end"),     # logoff
    24:   ("info",     "windows_rdp_session_disco"),   # disconnected
    25:   ("medium",   "windows_rdp_reconnect"),       # reconnect (suspicious if unusual hours)
}


# =============================================================================
# Mapping camelCase Windows -> snake_case Python
# =============================================================================
# Windows EventData fields use PascalCase (TargetUserName, IpAddress, ...).
# On les normalise en snake_case pour cohérence avec parsers/linux.py.
# Les clés non listées ici sont passées telles quelles (en snake_case auto).

WINDOWS_FIELD_MAPPING = {
    # User identification
    "TargetUserName":     "user",
    "SubjectUserName":    "subject_user",
    "TargetUserSid":      "user_sid",
    "SubjectUserSid":     "subject_sid",
    "TargetDomainName":   "domain",

    # Network
    "IpAddress":          "ip",
    "IpPort":             "port",
    "WorkstationName":    "workstation",

    # Logon details
    "LogonType":          "logon_type",
    "LogonProcessName":   "logon_process",
    "AuthenticationPackageName": "auth_package",

    # Process
    "ProcessName":        "process_name",
    "ProcessId":          "process_id",
    "CommandLine":        "cmd",
    "ParentProcessName":  "parent_process",

    # File / Object
    "ObjectName":         "object_name",
    "ObjectType":         "object_type",
    "AccessMask":         "access_mask",

    # Service
    "ServiceName":        "service_name",
    "ServiceType":        "service_type",
    "ServiceStartType":   "service_start_type",
}


def _camel_to_snake(name: str) -> str:
    """Convertit PascalCase ou camelCase en snake_case (fallback simple)."""
    result = []
    for i, c in enumerate(name):
        if c.isupper() and i > 0 and not name[i - 1].isupper():
            result.append("_")
        result.append(c.lower())
    return "".join(result)


def _normalize_event_data(event_data: dict) -> dict:
    """
    Normalise les clés EventData Windows (PascalCase) en snake_case Python.

    Utilise WINDOWS_FIELD_MAPPING pour les champs connus (mapping explicite),
    fallback sur _camel_to_snake() pour les champs inconnus.

    Convertit aussi certaines valeurs en types Python natifs
    (LogonType en int, etc.) quand c'est pertinent.
    """
    if not isinstance(event_data, dict):
        return {}

    parsed = {}
    for key, value in event_data.items():
        if not key:
            continue

        # 1. Normaliser la clé
        normalized_key = WINDOWS_FIELD_MAPPING.get(key) or _camel_to_snake(key)

        # 2. Nettoyer la valeur (skip vide et "-" Windows)
        if value in (None, "", "-"):
            continue

        # 3. Conversion type pour les champs numériques connus
        if normalized_key in ("port", "logon_type", "process_id"):
            try:
                value = int(value)
            except (ValueError, TypeError):
                pass  # garde la string si conversion échoue

        # 4. Tronquer les commandes pour éviter abus (similaire parsers/linux.py)
        if normalized_key == "cmd" and isinstance(value, str):
            value = value[:200]

        parsed[normalized_key] = value

    return parsed


def detect_severity_and_type(event_id: int, channel: str) -> Tuple[str, str]:
    """
    Détermine (severity, event_type) à partir de l'EventID Windows.

    Si l'EventID n'est pas dans le mapping connu, retourne ("info", "windows_unknown")
    avec une trace dans les logs pour qu'on puisse l'ajouter au mapping plus tard
    si nécessaire.
    """
    mapping = WINDOWS_EVENT_MAPPING.get(event_id)
    if mapping:
        return mapping

    # EventID inconnu : log warning pour amélioration future du mapping
    logger.debug(
        f"Unknown Windows EventID {event_id} from channel '{channel}' "
        f"(consider adding to WINDOWS_EVENT_MAPPING if relevant for SOC)"
    )
    return ("info", "windows_unknown")


def line_to_event(line: str, source_path: str) -> dict:
    """
    Transforme une ligne JSON Windows Event Log en payload event pour
    /api/soc/ingest/.

    Format de sortie identique à parsers.linux.line_to_event() pour
    cohérence backend.

    Robustesse :
      - JSON malformé -> dégradation gracieuse vers ("info", "windows_malformed")
      - Champ manquant -> valeur par défaut sans crash
      - EventID inconnu -> ("info", "windows_unknown") avec log debug
    """
    # ── 1. Parsing JSON robuste ─────────────────────────────────────────
    try:
        data = json.loads(line)
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning(
            f"Failed to parse Windows event JSON: {e} "
            f"(first 100 chars: {line[:100]!r})"
        )
        return {
            "source": os.path.basename(source_path) or "windows_unknown",
            "raw": line.strip()[:5000],
            "event_type": "windows_malformed",
            "severity": "info",
            "ts": datetime.now(timezone.utc).isoformat(),
            "parsed": {},
        }

    # ── 2. Extraction des métadonnées core ──────────────────────────────
    channel = data.get("channel") or "Unknown"
    event_id = data.get("event_id") or 0
    try:
        event_id = int(event_id)
    except (ValueError, TypeError):
        event_id = 0

    # ── 3. Severity & event_type via mapping MITRE ATT&CK ───────────────
    severity, event_type = detect_severity_and_type(event_id, channel)

    # ── 4. Timestamp : préserver celui de Windows si possible ───────────
    ts = data.get("time_created")
    if not ts or not isinstance(ts, str):
        ts = datetime.now(timezone.utc).isoformat()

    # ── 5. Extraction des champs structurés depuis event_data ───────────
    parsed = _normalize_event_data(data.get("event_data", {}))

    # ── 6. Enrichissement parsed avec métadonnées Windows utiles ────────
    parsed["event_id"] = event_id
    if computer := data.get("computer"):
        parsed["computer"] = computer
    if provider := data.get("provider"):
        parsed["provider"] = provider

    # ── 7. Construction de l'event final ────────────────────────────────
    return {
        "source": channel,  # ex: "Security", "System", ...
        "raw": line.strip()[:5000],
        "event_type": event_type,
        "severity": severity,
        "ts": ts,
        "parsed": parsed,
    }
