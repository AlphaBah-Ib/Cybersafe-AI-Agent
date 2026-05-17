"""
Tests unitaires pour cybersafe_agent.parsers.windows

SOC-203 : couvre les 7 EventIDs critiques de l'US + fields métiers +
NTSTATUS decoder + fallback Level natif (SOC-202).

Stratégie de test :
  - 1 classe par responsabilité du parser
  - Samples JSON realistes basés sur Microsoft documentation
  - Couverture : EventIDs MITRE, fields extraction, edge cases, robustesse
  
Pour lancer :
    cd ~/cybersafe-agent
    python -m pytest tests/test_parsers_windows.py -v
"""

import json
import pytest

from cybersafe_agent.parsers.windows import (
    WINDOWS_EVENT_MAPPING,
    WINDOWS_LEVEL_TO_SEVERITY,
    NTSTATUS_LOGON_FAILURES,
    WINDOWS_FIELD_MAPPING,
    detect_severity_and_type,
    line_to_event,
    _decode_logon_failure_reason,
    _normalize_ntstatus,
    _normalize_event_data,
    _camel_to_snake,
)


# =============================================================================
# Helpers de test
# =============================================================================

def make_event(event_id, channel="Security", level="Information",
               event_data=None, computer="TEST-PC"):
    """Construit un JSON event sample pour les tests."""
    return json.dumps({
        "channel": channel,
        "event_id": event_id,
        "level": level,
        "time_created": "2026-05-17T10:00:00+00:00",
        "computer": computer,
        "provider": "Microsoft-Windows-Test",
        "event_data": event_data or {},
    })


# =============================================================================
# TestMappings : verifie l'integrite des dictionnaires de mapping
# =============================================================================

class TestMappings:
    """Verifie la coherence des mappings statiques."""

    def test_windows_event_mapping_has_critical_eventids(self):
        """Tous les EventIDs critiques de l'US doivent etre mappes."""
        critical_ids = [4624, 4625, 4634, 4720, 4732, 4688, 7045]
        for eid in critical_ids:
            assert eid in WINDOWS_EVENT_MAPPING, f"EventID {eid} manquant"

    def test_windows_event_mapping_values_are_valid_tuples(self):
        """Chaque valeur doit etre un tuple (severity, event_type)."""
        valid_severities = {"info", "low", "medium", "high", "critical"}
        for eid, mapping in WINDOWS_EVENT_MAPPING.items():
            assert isinstance(mapping, tuple), f"EventID {eid} : pas un tuple"
            assert len(mapping) == 2, f"EventID {eid} : tuple invalide"
            severity, event_type = mapping
            assert severity in valid_severities, f"EventID {eid} : severity '{severity}' invalide"
            assert event_type.startswith("windows_"), f"EventID {eid} : event_type doit commencer par windows_"

    def test_windows_level_to_severity_complete(self):
        """Les 5 levels natifs Windows doivent etre mappes."""
        expected_levels = {"Critical", "Error", "Warning", "Information", "Verbose"}
        assert set(WINDOWS_LEVEL_TO_SEVERITY.keys()) == expected_levels

    def test_ntstatus_codes_format(self):
        """Toutes les cles NTSTATUS doivent etre en format '0xXXXXXXXX'."""
        for code in NTSTATUS_LOGON_FAILURES.keys():
            assert code.startswith("0x"), f"Code {code} : prefix manquant"
            assert code[2:].isupper(), f"Code {code} : hex digits doivent etre en MAJ"


# =============================================================================
# TestNormalisationNTSTATUS : decoder NTSTATUS robuste a la casse
# =============================================================================

class TestNormalisationNTSTATUS:
    """Verifie la normalisation case-insensitive des codes NTSTATUS."""

    @pytest.mark.parametrize("input_code,expected", [
        ("0xC0000064", "0xC0000064"),    # canonical
        ("0XC0000064", "0xC0000064"),    # uppercase prefix
        ("0xc0000064", "0xC0000064"),    # lowercase hex
        ("0Xc0000064", "0xC0000064"),    # mixed case
        ("0xC0000064 ", "0xC0000064"),   # trailing whitespace
        (" 0xC0000064", "0xC0000064"),   # leading whitespace
        ("", ""),                          # empty
        (None, ""),                        # None
        ("C0000064", "C0000064"),         # no prefix
    ])
    def test_normalize_ntstatus(self, input_code, expected):
        assert _normalize_ntstatus(input_code) == expected


class TestDecodeLogonFailureReason:
    """Verifie le decoder de raison d'echec d'authentification."""

    def test_substatus_priority_over_status(self):
        """SubStatus doit avoir la priorite sur Status."""
        # Status = generic, SubStatus = specifique
        result = _decode_logon_failure_reason("0xC000006D", "0xC0000064")
        assert result == "user_does_not_exist"  # depuis SubStatus

    def test_fallback_on_status_if_substatus_empty(self):
        """Si SubStatus vide, fallback sur Status."""
        result = _decode_logon_failure_reason("0xC000006D", "")
        assert result == "bad_credentials"

    def test_unknown_code_returns_unknown(self):
        """Code NTSTATUS inconnu doit retourner 'unknown'."""
        result = _decode_logon_failure_reason("", "0xDEADBEEF")
        assert result == "unknown"

    def test_empty_inputs_return_unknown(self):
        assert _decode_logon_failure_reason("", "") == "unknown"
        assert _decode_logon_failure_reason(None, None) == "unknown"

    @pytest.mark.parametrize("substatus,expected", [
        ("0xC0000064", "user_does_not_exist"),
        ("0xC000006A", "wrong_password"),
        ("0xC0000234", "account_locked_out"),
        ("0xC0000072", "account_disabled"),
        ("0xC0000071", "password_expired"),
        ("0xC0000193", "account_expired"),
    ])
    def test_common_failure_reasons(self, substatus, expected):
        assert _decode_logon_failure_reason("", substatus) == expected

    def test_case_insensitive(self):
        """Doit fonctionner peu importe la casse du code."""
        assert _decode_logon_failure_reason("", "0xc0000064") == "user_does_not_exist"
        assert _decode_logon_failure_reason("", "0XC0000064") == "user_does_not_exist"
        assert _decode_logon_failure_reason("0xc000006d", "") == "bad_credentials"


# =============================================================================
# TestDetectSeverity : mapping MITRE + fallback Level natif
# =============================================================================

class TestDetectSeverityAndType:
    """Verifie la strategie 2 niveaux : MITRE > Level natif."""

    def test_known_eventid_uses_mitre_mapping(self):
        """EventID connu doit utiliser le mapping MITRE."""
        severity, event_type = detect_severity_and_type(4625, "Security", "Information")
        assert severity == "high"
        assert event_type == "windows_logon_failed"

    def test_unknown_eventid_with_error_level_falls_back_to_high(self):
        """EventID inconnu + Level Error -> severity high (fallback natif)."""
        severity, event_type = detect_severity_and_type(99999, "System", "Error")
        assert severity == "high"
        assert event_type == "windows_unknown"

    def test_unknown_eventid_with_critical_level_falls_back_to_critical(self):
        severity, _ = detect_severity_and_type(99998, "System", "Critical")
        assert severity == "critical"

    def test_unknown_eventid_with_warning_level_falls_back_to_medium(self):
        severity, _ = detect_severity_and_type(99997, "System", "Warning")
        assert severity == "medium"

    def test_unknown_eventid_without_level_falls_back_to_info(self):
        severity, event_type = detect_severity_and_type(99996, "System", "")
        assert severity == "info"
        assert event_type == "windows_unknown"

    def test_mitre_mapping_priority_over_native_level(self):
        """Meme avec Level Error, le mapping MITRE doit primer."""
        # EventID 4624 = mapping MITRE = "medium"
        # Si on passe Level "Error" (qui ferait high en fallback), MITRE prime
        severity, event_type = detect_severity_and_type(4624, "Security", "Error")
        assert severity == "medium"  # MITRE wins
        assert event_type == "windows_logon_success"


# =============================================================================
# Tests des 7 EventIDs critiques de l'US SOC-203
# =============================================================================

class TestEventID4624LogonSuccess:
    """EventID 4624 : Logon successful."""

    def test_extracts_user_ip_logon_type_computer(self):
        """L'US demande : user, ip, logon_type, computer."""
        event = line_to_event(make_event(4624, event_data={
            "TargetUserName": "alice",
            "IpAddress": "10.0.0.5",
            "LogonType": "3",
            "LogonProcessName": "Kerberos",
        }), "Security")

        assert event['event_type'] == 'windows_logon_success'
        assert event['severity'] == 'medium'
        assert event['parsed']['user'] == 'alice'
        assert event['parsed']['ip'] == '10.0.0.5'
        assert event['parsed']['logon_type'] == 3  # converti en int
        assert event['parsed']['computer'] == 'TEST-PC'

    def test_logon_type_is_int_not_string(self):
        """LogonType doit etre converti en int pour usage dans les regles."""
        event = line_to_event(make_event(4624, event_data={
            "LogonType": "10",  # RDP
        }), "Security")
        assert event['parsed']['logon_type'] == 10
        assert isinstance(event['parsed']['logon_type'], int)


class TestEventID4625LogonFailed:
    """EventID 4625 : Logon failed (avec failure_reason critique)."""

    def test_extracts_user_ip_failure_reason(self):
        """L'US demande : user, ip, failure_reason."""
        event = line_to_event(make_event(4625, event_data={
            "TargetUserName": "admin",
            "IpAddress": "192.168.1.100",
            "Status": "0xC000006D",
            "SubStatus": "0xC0000064",
        }), "Security")

        assert event['event_type'] == 'windows_logon_failed'
        assert event['severity'] == 'high'
        assert event['parsed']['user'] == 'admin'
        assert event['parsed']['ip'] == '192.168.1.100'
        assert event['parsed']['failure_reason'] == 'user_does_not_exist'

    def test_failure_reason_account_locked_out(self):
        """Detection de account lockout (signe de brute force en cours)."""
        event = line_to_event(make_event(4625, event_data={
            "TargetUserName": "victim",
            "SubStatus": "0xC0000234",
        }), "Security")
        assert event['parsed']['failure_reason'] == 'account_locked_out'

    def test_failure_reason_wrong_password(self):
        event = line_to_event(make_event(4625, event_data={
            "TargetUserName": "alice",
            "SubStatus": "0xC000006A",
        }), "Security")
        assert event['parsed']['failure_reason'] == 'wrong_password'

    def test_no_status_codes_failure_reason_unknown(self):
        event = line_to_event(make_event(4625, event_data={
            "TargetUserName": "x",
        }), "Security")
        assert event['parsed']['failure_reason'] == 'unknown'


class TestEventID4634Logoff:
    """EventID 4634 : Logoff."""

    def test_extracts_user_logon_type(self):
        """L'US demande : user, logon_type."""
        event = line_to_event(make_event(4634, event_data={
            "TargetUserName": "bob",
            "LogonType": "2",
        }), "Security")

        assert event['event_type'] == 'windows_logoff'
        assert event['severity'] == 'info'
        assert event['parsed']['user'] == 'bob'
        assert event['parsed']['logon_type'] == 2


class TestEventID4720UserCreated:
    """EventID 4720 : User account created (persistence)."""

    def test_extracts_new_user_and_by_user(self):
        """L'US demande : new_user, by_user."""
        event = line_to_event(make_event(4720, event_data={
            "TargetUserName": "new_user_42",
            "SubjectUserName": "admin",
        }), "Security")

        assert event['event_type'] == 'windows_user_created'
        assert event['severity'] == 'high'
        # Mapping : TargetUserName -> user (= new_user)
        # Mapping : SubjectUserName -> subject_user (= by_user)
        assert event['parsed']['user'] == 'new_user_42'
        assert event['parsed']['subject_user'] == 'admin'


class TestEventID4732UserAddedToGroup:
    """EventID 4732 : User added to local admin group."""

    def test_extracts_group_member_by_user(self):
        """L'US demande : target_user, group, by_user.
        
        Note specifique 4732/4728 : Windows met le nom du groupe dans
        TargetUserName (pas dans GroupName). Notre _enrich_parsed_per_eventid
        renomme automatiquement user -> group pour clarte.
        """
        event = line_to_event(make_event(4732, event_data={
            "TargetUserName": "Administrators",   # = group
            "MemberName": "CN=alice,CN=Users,DC=corp",
            "SubjectUserName": "admin",            # = by_user
        }), "Security")

        assert event['event_type'] == 'windows_user_added_to_local'
        assert event['severity'] == 'high'
        assert event['parsed']['group'] == 'Administrators'
        assert event['parsed']['member'] == 'CN=alice,CN=Users,DC=corp'
        assert event['parsed']['subject_user'] == 'admin'
        # Le field 'user' doit AVOIR ete renomme en 'group'
        assert 'user' not in event['parsed']


class TestEventID4688ProcessCreate:
    """EventID 4688 : Process created (execution)."""

    def test_extracts_process_parent_command_user(self):
        """L'US demande : process, parent, command_line, user."""
        event = line_to_event(make_event(4688, event_data={
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "CommandLine": "cmd.exe /c whoami",
            "SubjectUserName": "alice",
        }), "Security")

        assert event['event_type'] == 'windows_process_create'
        assert event['severity'] == 'medium'
        assert event['parsed']['process_name'].endswith('cmd.exe')
        assert event['parsed']['parent_process'].endswith('explorer.exe')
        assert 'whoami' in event['parsed']['cmd']
        assert event['parsed']['subject_user'] == 'alice'

    def test_command_line_truncated_at_200(self):
        """Les CommandLine longues doivent etre tronquees a 200 chars (anti-abus)."""
        long_cmd = "cmd.exe /c " + ("A" * 500)
        event = line_to_event(make_event(4688, event_data={
            "NewProcessName": "cmd.exe",
            "CommandLine": long_cmd,
        }), "Security")
        assert len(event['parsed']['cmd']) <= 200


class TestEventID7045ServiceInstalled:
    """EventID 7045 : Service installed via SCM (persistence majeure)."""

    def test_extracts_service_name_and_image_path(self):
        """L'US demande : service_name, image_path."""
        event = line_to_event(make_event(7045, channel="System", event_data={
            "ServiceName": "EvilService",
            "ImagePath": "C:\\Temp\\backdoor.exe -daemon",
            "ServiceType": "user mode service",
            "ServiceStartType": "auto start",
        }), "System")

        assert event['event_type'] == 'windows_service_installed_scm'
        assert event['severity'] == 'high'
        assert event['parsed']['service_name'] == 'EvilService'
        assert event['parsed']['image_path'] == 'C:\\Temp\\backdoor.exe -daemon'
        assert event['parsed']['service_type'] == 'user mode service'

    def test_image_path_truncated_at_500(self):
        """ImagePath enorme doit etre tronquee a 500 chars (anti-abus)."""
        long_path = "C:\\Temp\\backdoor.exe " + ("X" * 1000)
        event = line_to_event(make_event(7045, channel="System", event_data={
            "ServiceName": "Test",
            "ImagePath": long_path,
        }), "System")
        assert len(event['parsed']['image_path']) <= 500


# =============================================================================
# TestRobustness : edge cases & dégradation gracieuse
# =============================================================================

class TestRobustness:
    """Verifie la robustesse du parser face aux inputs malformes."""

    def test_malformed_json_returns_safe_event(self):
        """JSON invalide doit retourner un event 'windows_malformed' sans crash."""
        event = line_to_event("this is not json {{{", "Security")
        assert event['event_type'] == 'windows_malformed'
        assert event['severity'] == 'info'
        assert event['parsed'] == {}

    def test_empty_string_returns_safe_event(self):
        event = line_to_event("", "Security")
        assert event['event_type'] == 'windows_malformed'

    def test_missing_event_id_uses_zero(self):
        """event_id manquant doit etre 0 (fallback safe)."""
        event = line_to_event(json.dumps({"channel": "X"}), "X")
        assert event['parsed']['event_id'] == 0
        assert event['event_type'] == 'windows_unknown'

    def test_invalid_event_id_string_uses_zero(self):
        event = line_to_event(json.dumps({
            "channel": "X",
            "event_id": "not_a_number",
        }), "X")
        assert event['parsed']['event_id'] == 0

    def test_event_data_with_dash_value_skipped(self):
        """Windows utilise '-' pour 'non disponible'. On doit le skip."""
        event = line_to_event(make_event(4624, event_data={
            "TargetUserName": "alice",
            "IpAddress": "-",     # placeholder Windows
            "WorkstationName": "",
        }), "Security")
        assert event['parsed']['user'] == 'alice'
        assert 'ip' not in event['parsed']
        assert 'workstation' not in event['parsed']

    def test_missing_timestamp_uses_now(self):
        """time_created manquant doit utiliser datetime.now()."""
        event = line_to_event(json.dumps({
            "channel": "Security",
            "event_id": 4624,
        }), "Security")
        # ts doit etre une string ISO valide (pas None ni vide)
        assert event['ts']
        assert "T" in event['ts']

    def test_event_data_not_dict_returns_empty_parsed(self):
        """Si event_data n'est pas un dict, on degrade proprement."""
        event = line_to_event(json.dumps({
            "channel": "Security",
            "event_id": 4624,
            "event_data": "this should be a dict",
        }), "Security")
        # event_id est ajoute dans parsed meme si event_data malformee
        assert event['parsed']['event_id'] == 4624


# =============================================================================
# TestCamelToSnake : helper conversion naming
# =============================================================================

class TestCamelToSnake:

    @pytest.mark.parametrize("input_name,expected", [
        ("TargetUserName", "target_user_name"),
        ("IpAddress", "ip_address"),
        ("EventID", "event_id"),  # split sur dernier upper isole
        ("simple", "simple"),
        ("ID", "id"),
        ("", ""),
    ])
    def test_camel_to_snake(self, input_name, expected):
        assert _camel_to_snake(input_name) == expected
