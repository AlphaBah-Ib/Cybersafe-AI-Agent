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
            "LogonType": "3",
            "Status": "0xC000006D",
            "SubStatus": "0xC0000064"
        },
        "message": "An account failed to log on..."
    }

Mapping EventID -> (severity, event_type) aligne MITRE ATT&CK.

Historique :
  - SOC-200 (16/05): mapping initial 33 EventIDs MITRE
  - SOC-202 fix (17/05): ajout fallback Level natif Windows
  - SOC-203 fix (17/05): ajout EventID 7045 + extraction failure_reason
                         + extraction image_path + decoder NTSTATUS case-insensitive
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

WINDOWS_EVENT_MAPPING = {
    # -- Authentication (Security channel) -----------------------------
    4624: ("medium",   "windows_logon_success"),       # TA0001 Initial Access
    4625: ("high",     "windows_logon_failed"),        # TA0006 Credential Access (brute force)
    4634: ("info",     "windows_logoff"),              # banal, faible interet SOC
    4647: ("info",     "windows_user_logoff"),         # logoff initie user
    4648: ("high",     "windows_explicit_creds"),      # TA0008 Lateral Movement
    4672: ("high",     "windows_admin_logon"),         # TA0004 Privilege Escalation
    4673: ("medium",   "windows_sensitive_priv"),      # TA0004 sensitive privilege use

    # -- Process & Service (Security channel) --------------------------
    4688: ("medium",   "windows_process_create"),      # TA0002 Execution
    4697: ("high",     "windows_service_install"),     # TA0003 Persistence (service via Sec audit)

    # -- Service Control Manager (System channel) ----------------------
    # SOC-203 fix : ajout pour couvrir l'US originale
    7045: ("high",     "windows_service_installed_scm"),  # TA0003 Persistence (service via SCM)

    # -- Object access (Security channel) ------------------------------
    4663: ("medium",   "windows_object_access"),       # TA0009 Collection (file/reg access)

    # -- Audit policy (Security channel) - TRES CRITIQUE ---------------
    4719: ("critical", "windows_audit_policy_changed"),  # TA0005 Defense Evasion
    1102: ("critical", "windows_audit_log_cleared"),     # TA0005

    # -- Account management (Security channel) -------------------------
    4720: ("high",     "windows_user_created"),        # TA0003 Persistence
    4722: ("medium",   "windows_user_enabled"),
    4724: ("high",     "windows_password_reset"),      # TA0006
    4725: ("medium",   "windows_user_disabled"),
    4728: ("high",     "windows_user_added_to_group"), # TA0004
    4732: ("high",     "windows_user_added_to_local"), # TA0004
    4738: ("medium",   "windows_user_changed"),

    # -- Kerberos (Security channel, AD) -------------------------------
    4768: ("medium",   "windows_kerberos_tgt"),
    4769: ("medium",   "windows_kerberos_service"),

    # -- PowerShell (Microsoft-Windows-PowerShell/Operational) ---------
    4103: ("medium",   "windows_powershell_module"),
    4104: ("high",     "windows_powershell_script"),   # TA0002

    # -- Windows Defender ---------------------------------------------
    1006: ("critical", "windows_malware_detected"),
    1007: ("critical", "windows_malware_action"),
    1015: ("high",     "windows_defender_event"),

    # -- Task Scheduler -----------------------------------------------
    106:  ("medium",   "windows_task_registered"),     # TA0003
    140:  ("medium",   "windows_task_updated"),
    141:  ("info",     "windows_task_deleted"),

    # -- RDP / Terminal Services --------------------------------------
    21:   ("medium",   "windows_rdp_session_start"),
    23:   ("info",     "windows_rdp_session_end"),
    24:   ("info",     "windows_rdp_session_disco"),
    25:   ("medium",   "windows_rdp_reconnect"),
}


# =============================================================================
# Mapping Windows Level natif -> severity Cybersafe (SOC-202 fix)
# =============================================================================

WINDOWS_LEVEL_TO_SEVERITY = {
    "Critical":    "critical",
    "Error":       "high",
    "Warning":     "medium",
    "Information": "info",
    "Verbose":     "info",
}


# =============================================================================
# Codes d'echec d'authentification NTSTATUS (SOC-203 fix)
# =============================================================================
# Source : Microsoft NTSTATUS documentation + EventID 4625 SubStatus mapping
# Utilise pour decoder le champ `failure_reason` lors d'echecs de logon.
#
# IMPORTANT : les cles sont normalisees en format "0xXXXXXXXX" (0x lowercase,
# hex digits uppercase) pour matching case-insensitive via _normalize_ntstatus().

NTSTATUS_LOGON_FAILURES = {
    "0xC0000064": "user_does_not_exist",        # bad username
    "0xC000006A": "wrong_password",
    "0xC000006D": "bad_credentials",            # generic credential failure
    "0xC000006E": "account_restriction",
    "0xC000006F": "logon_time_restriction",
    "0xC0000070": "workstation_restriction",
    "0xC0000071": "password_expired",
    "0xC0000072": "account_disabled",
    "0xC000009A": "insufficient_resources",
    "0xC0000133": "clock_skew",
    "0xC0000193": "account_expired",
    "0xC0000224": "password_must_change",
    "0xC0000234": "account_locked_out",
    "0xC0000371": "no_logon_servers",
}


# =============================================================================
# Mapping camelCase Windows -> snake_case Python
# =============================================================================

WINDOWS_FIELD_MAPPING = {
    # User identification
    "TargetUserName":     "user",
    "SubjectUserName":    "subject_user",
    "TargetUserSid":      "user_sid",
    "SubjectUserSid":     "subject_sid",
    "TargetDomainName":   "domain",
    "SubjectDomainName":  "subject_domain",

    # Network
    "IpAddress":          "ip",
    "IpPort":             "port",
    "WorkstationName":    "workstation",

    # Logon details
    "LogonType":          "logon_type",
    "LogonProcessName":   "logon_process",
    "AuthenticationPackageName": "auth_package",
    "Status":             "status_code",
    "SubStatus":          "sub_status_code",
    "FailureReason":      "failure_reason_raw",

    # Process
    "ProcessName":        "process_name",
    "ProcessId":          "process_id",
    "NewProcessName":     "process_name",   # alias for 4688
    "ParentProcessName":  "parent_process",
    "CommandLine":        "cmd",

    # File / Object
    "ObjectName":         "object_name",
    "ObjectType":         "object_type",
    "AccessMask":         "access_mask",

    # Service (SOC-203 fix : 7045 fields)
    "ServiceName":        "service_name",
    "ServiceType":        "service_type",
    "ServiceStartType":   "service_start_type",
    "ImagePath":          "image_path",
    "ServiceFileName":    "image_path",     # alias 7045

    # Group membership (4728/4732 fix)
    "MemberName":         "member",
    "GroupName":          "group",
}


def _camel_to_snake(name: str) -> str:
    """Convertit PascalCase ou camelCase en snake_case (fallback simple)."""
    result = []
    for i, c in enumerate(name):
        if c.isupper() and i > 0 and not name[i - 1].isupper():
            result.append("_")
        result.append(c.lower())
    return "".join(result)


def _normalize_ntstatus(code: str) -> str:
    """
    Normalise un NTSTATUS code en format canonique '0xXXXXXXXX'.

    Garantit que le prefix '0x' est en lowercase et les hex digits en uppercase,
    pour permettre un matching case-insensitive avec NTSTATUS_LOGON_FAILURES.

    Examples:
        "0xC0000064"  -> "0xC0000064"
        "0XC0000064"  -> "0xC0000064"
        "0xc0000064"  -> "0xC0000064"
        "C0000064"    -> "C0000064"    (no prefix, just upper)
        ""            -> ""
        None          -> ""
    """
    if not code or not isinstance(code, str):
        return ""
    code = code.strip()
    if code.lower().startswith("0x"):
        return "0x" + code[2:].upper()
    return code.upper()


def _decode_logon_failure_reason(status: str, sub_status: str) -> str:
    """
    Decode NTSTATUS codes en raison d'echec human-readable.

    Priorite : SubStatus (plus specifique) > Status > "unknown".

    Robust to case variations : "0xC0000064", "0XC0000064", "0xc0000064"
    sont tous traites de maniere identique grace a _normalize_ntstatus().

    Args:
        status: NTSTATUS code (ex: "0xC000006D")
        sub_status: sub-NTSTATUS code (ex: "0xC0000064")

    Returns:
        String courte (ex: "user_does_not_exist") ou "unknown" si non reconnu.
    """
    # SubStatus is more specific (e.g. wrong username vs wrong password)
    sub_normalized = _normalize_ntstatus(sub_status)
    if sub_normalized in NTSTATUS_LOGON_FAILURES:
        return NTSTATUS_LOGON_FAILURES[sub_normalized]

    # Fallback on Status
    status_normalized = _normalize_ntstatus(status)
    if status_normalized in NTSTATUS_LOGON_FAILURES:
        return NTSTATUS_LOGON_FAILURES[status_normalized]

    return "unknown"


def _normalize_event_data(event_data: dict) -> dict:
    """
    Normalise les cles EventData Windows (PascalCase) en snake_case Python.
    """
    if not isinstance(event_data, dict):
        return {}

    parsed = {}
    for key, value in event_data.items():
        if not key:
            continue

        normalized_key = WINDOWS_FIELD_MAPPING.get(key) or _camel_to_snake(key)

        if value in (None, "", "-"):
            continue

        # Conversion type pour les champs numeriques connus
        if normalized_key in ("port", "logon_type", "process_id"):
            try:
                value = int(value)
            except (ValueError, TypeError):
                pass

        # Tronquer les commandes pour eviter abus
        if normalized_key == "cmd" and isinstance(value, str):
            value = value[:200]

        # Tronquer les image paths pour eviter abus (service binaires)
        if normalized_key == "image_path" and isinstance(value, str):
            value = value[:500]

        parsed[normalized_key] = value

    return parsed


def detect_severity_and_type(event_id: int, channel: str, native_level: str = "") -> Tuple[str, str]:
    """
    Determine (severity, event_type) a partir de l'EventID Windows.

    Strategie 2 niveaux :
      1. Mapping MITRE ATT&CK explicite (priorite)
      2. Fallback sur Level natif Windows
    """
    mapping = WINDOWS_EVENT_MAPPING.get(event_id)
    if mapping:
        return mapping

    fallback_severity = WINDOWS_LEVEL_TO_SEVERITY.get(native_level, "info")

    if fallback_severity != "info":
        logger.debug(
            f"Unknown Windows EventID {event_id} from channel '{channel}' "
            f"(native level: {native_level}, fallback severity: {fallback_severity})."
        )

    return (fallback_severity, "windows_unknown")


def _enrich_parsed_per_eventid(event_id: int, parsed: dict) -> dict:
    """
    Enrichit le dict parsed avec des champs derives specifiques par EventID.

    SOC-203 fix : extraction de champs metiers critiques pour les regles
    de detection.
    """
    # EventID 4625 : decoder failure_reason depuis Status/SubStatus
    if event_id == 4625:
        status = parsed.get("status_code", "")
        sub_status = parsed.get("sub_status_code", "")
        parsed["failure_reason"] = _decode_logon_failure_reason(status, sub_status)

    # EventID 4732 / 4728 : extraire le group depuis TargetUserName
    # (dans ces events, TargetUserName est en fait le nom du groupe)
    if event_id in (4728, 4732):
        # Sur 4732/4728, "user" extrait par mapping = en fait le groupe
        # On renomme pour clarte semantique
        if "user" in parsed:
            parsed["group"] = parsed.pop("user")
        # Le membre ajoute est dans MemberName -> member
        # subject_user reste = administrateur qui a fait l'ajout

    return parsed


def line_to_event(line: str, source_path: str) -> dict:
    """
    Transforme une ligne JSON Windows Event Log en payload event pour
    /api/soc/ingest/.
    """
    # -- 1. Parsing JSON robuste ---------------------------------------
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

    # -- 2. Extraction metadonnees core --------------------------------
    channel = data.get("channel") or "Unknown"
    event_id = data.get("event_id") or 0
    try:
        event_id = int(event_id)
    except (ValueError, TypeError):
        event_id = 0

    # -- 3. Severity & event_type --------------------------------------
    native_level = data.get("level", "")
    severity, event_type = detect_severity_and_type(event_id, channel, native_level)

    # -- 4. Timestamp --------------------------------------------------
    ts = data.get("time_created")
    if not ts or not isinstance(ts, str):
        ts = datetime.now(timezone.utc).isoformat()

    # -- 5. Extraction et normalisation event_data ---------------------
    parsed = _normalize_event_data(data.get("event_data", {}))

    # -- 6. Enrichissement specifique par EventID (SOC-203 fix) --------
    parsed = _enrich_parsed_per_eventid(event_id, parsed)

    # -- 7. Metadonnees Windows ----------------------------------------
    parsed["event_id"] = event_id
    if computer := data.get("computer"):
        parsed["computer"] = computer
    if provider := data.get("provider"):
        parsed["provider"] = provider

    # -- 8. Event final ------------------------------------------------
    return {
        "source": channel,
        "raw": line.strip()[:5000],
        "event_type": event_type,
        "severity": severity,
        "ts": ts,
        "parsed": parsed,
    }
