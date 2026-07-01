"""
SOC-AUTH — Tests du parsing des patterns SSH auth.log preauth.

Ces lignes tombaient auparavant dans le catch-all (event_type="") et etaient
donc invisibles pour le moteur de regles. On verifie qu'elles sont desormais
categorisees, et que l'IP source est bien extraite (necessaire a l'agregation
backend par IP).

Samples issus de logs de production reels (Nabhorelan + VM prod).
"""
import pytest
from cybersafe_agent.parsers.linux import (
    detect_severity_and_type,
    extract_parsed_fields,
)
from cybersafe_agent.parser import line_to_event


# (ligne, event_type attendu, severity attendue)
PREAUTH_SAMPLES = [
    (
        "2026-07-01T13:50:11.910410+02:00 vmi2450869 sshd[1633983]: "
        "Disconnected from authenticating user root 121.184.144.232 port 55075 [preauth]",
        "ssh_preauth_disconnect", "medium",
    ),
    (
        "2026-07-01T13:50:11.909143+02:00 vmi2450869 sshd[1633983]: "
        "Received disconnect from 121.184.144.232 port 55075:11: Bye Bye [preauth]",
        "ssh_preauth_disconnect", "medium",
    ),
    (
        "2026-07-01T13:50:07.599837+02:00 vmi2450869 sshd[1633981]: "
        "Connection closed by authenticating user root 92.98.81.192 port 32020 [preauth]",
        "ssh_preauth_disconnect", "medium",
    ),
    (
        "2026-07-01T13:49:43.793498+02:00 vmi2450869 sshd[1633977]: "
        "pam_unix(sshd:auth): check pass; user unknown",
        "invalid_user", "high",
    ),
]


@pytest.mark.parametrize("line,expected_type,expected_sev", PREAUTH_SAMPLES)
def test_preauth_lines_are_categorized(line, expected_type, expected_sev):
    sev, etype = detect_severity_and_type(line)
    assert etype == expected_type, f"type attendu {expected_type}, obtenu {etype}"
    assert sev == expected_sev, f"severity attendue {expected_sev}, obtenu {sev}"


def test_preauth_no_longer_empty_type():
    """Regression : aucune de ces lignes ne doit retomber en event_type vide."""
    for line, _, _ in PREAUTH_SAMPLES:
        _, etype = detect_severity_and_type(line)
        assert etype != "", f"ligne non categorisee: {line[:80]}"


def test_preauth_source_ip_extracted():
    """L'IP source doit etre extraite (cle de l'agregation backend par IP)."""
    line = (
        "2026-07-01T13:50:07.599837+02:00 vmi2450869 sshd[1633981]: "
        "Connection closed by authenticating user root 92.98.81.192 port 32020 [preauth]"
    )
    parsed = extract_parsed_fields(line)
    assert parsed.get("ip") == "92.98.81.192"


def test_preauth_full_event_shape():
    """line_to_event doit produire un event complet avec le bon type."""
    line = (
        "2026-07-01T13:48:22 cybersafe-web-prod sshd[290811]: "
        "Disconnected from authenticating user root 143.95.209.223 port 54500 [preauth]"
    )
    ev = line_to_event(line, "/var/log/auth.log")
    assert ev["event_type"] == "ssh_preauth_disconnect"
    assert ev["severity"] == "medium"
    assert ev["source"] == "auth.log"
    assert ev["parsed"].get("ip") == "143.95.209.223"


def test_existing_patterns_still_work():
    """Non-regression : les patterns deja supportes restent inchanges."""
    cases = [
        ("Failed password for root from 1.2.3.4 port 22 ssh2", "ssh_failed_login"),
        ("Invalid user admin from 5.6.7.8", "invalid_user"),
        ("pam_unix(sshd:auth): authentication failure; ...", "auth_failure"),
        ("Accepted password for alice from 9.9.9.9 port 22 ssh2", "ssh_login_success"),
    ]
    for line, expected in cases:
        _, etype = detect_severity_and_type(line)
        assert etype == expected, f"{line[:40]} -> attendu {expected}, obtenu {etype}"
