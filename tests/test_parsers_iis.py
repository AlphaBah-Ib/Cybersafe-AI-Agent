"""
Tests unitaires du parser IIS W3C Extended (SOC-302).

Le parser IIS est STATEFUL : il retient l'ordre des colonnes (#Fields:) par
fichier source. Les tests utilisent reset_state() pour isoler chaque cas.
Inclut des cas d'attaque (sqlmap), le fallback champs defaut, et la
robustesse.
"""
import pytest

from cybersafe_agent.parsers.iis import (
    parse_access,
    line_to_event_access,
    reset_state,
    _DEFAULT_FIELDS,
)
from cybersafe_agent.parser import line_to_event


# En-tete #Fields: standard IIS (15 champs avec cs(Referer))
FIELDS_FULL = (
    "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port "
    "cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus "
    "sc-win32-status time-taken"
)

SRC = "/inetpub/logs/W3SVC1/u_ex260522.log"


@pytest.fixture(autouse=True)
def _reset():
    """Reinitialise l'etat des champs avant chaque test."""
    reset_state()
    yield
    reset_state()


# ════════════════════════════════════════════════════════════════════════════
# En-tete #Fields: et lignes de donnees
# ════════════════════════════════════════════════════════════════════════════

def test_fields_header_is_comment():
    r = parse_access(FIELDS_FULL, SRC)
    assert r.get("comment") is True


def test_data_after_fields():
    parse_access(FIELDS_FULL, SRC)
    data = ("2026-05-22 00:15:23 10.0.0.5 GET /admin/login - 80 - "
            "203.0.113.5 Mozilla/5.0 - 403 0 0 125")
    p = parse_access(data, SRC)
    assert p["ip"] == "203.0.113.5"   # c-ip, PAS s-ip (10.0.0.5)
    assert p["method"] == "GET"
    assert p["path"] == "/admin/login"
    assert p["status"] == 403
    assert p["user_agent"] == "Mozilla/5.0"
    assert p["time_taken_ms"] == 125


def test_c_ip_not_s_ip():
    """Verifie qu'on extrait bien le client (c-ip), pas le serveur (s-ip)."""
    parse_access(FIELDS_FULL, SRC)
    data = ("2026-05-22 00:15:23 192.168.1.1 GET / - 80 - "
            "8.8.8.8 UA - 200 0 0 5")
    p = parse_access(data, SRC)
    assert p["ip"] == "8.8.8.8"  # c-ip
    assert p["ip"] != "192.168.1.1"  # PAS s-ip


def test_decode_plus_in_user_agent():
    parse_access(FIELDS_FULL, SRC)
    data = ("2026-05-22 00:16:00 10.0.0.5 GET / - 80 - 1.2.3.4 "
            "Mozilla/5.0+(Windows+NT+10.0) - 200 0 0 50")
    p = parse_access(data, SRC)
    assert p["user_agent"] == "Mozilla/5.0 (Windows NT 10.0)"


def test_decode_plus_in_query():
    parse_access(FIELDS_FULL, SRC)
    data = ("2026-05-22 00:17:00 10.0.0.5 GET /search q=test+value 80 - "
            "1.2.3.4 UA - 200 0 0 10")
    p = parse_access(data, SRC)
    assert p["query"] == "q=test value"


def test_substatus():
    parse_access(FIELDS_FULL, SRC)
    data = ("2026-05-22 00:18:00 10.0.0.5 GET /secure - 80 - 1.2.3.4 "
            "UA - 403 4 0 10")
    p = parse_access(data, SRC)
    assert p["status"] == 403
    assert p["substatus"] == 4


def test_iis_time_iso():
    parse_access(FIELDS_FULL, SRC)
    data = "2026-05-22 00:15:23 10.0.0.5 GET / - 80 - 1.2.3.4 UA - 200 0 0 5"
    p = parse_access(data, SRC)
    assert "iis_time" in p
    assert p["iis_time"].startswith("2026-05-22T00:15:23")


# ════════════════════════════════════════════════════════════════════════════
# Fallback champs defaut + #Fields: custom
# ════════════════════════════════════════════════════════════════════════════

def test_fallback_default_fields():
    """Sans #Fields: vu, on utilise _DEFAULT_FIELDS + flag parse_partial."""
    # 15 valeurs alignees sur _DEFAULT_FIELDS
    data = ("2026-05-22 00:20:00 10.0.0.5 POST /wp-login.php - 80 - "
            "198.51.100.7 sqlmap - 403 0 0 5")
    p = parse_access(data, "/other/u_ex.log")
    assert p["ip"] == "198.51.100.7"
    assert p["method"] == "POST"
    assert p["status"] == 403
    assert p.get("parse_partial") is True


def test_no_parse_partial_after_fields():
    parse_access(FIELDS_FULL, SRC)
    data = ("2026-05-22 00:20:00 10.0.0.5 POST /x - 80 - "
            "1.2.3.4 UA - 200 0 0 5")
    p = parse_access(data, SRC)
    assert "parse_partial" not in p


def test_custom_short_fields():
    """#Fields: custom court (3 colonnes) doit fonctionner."""
    parse_access("#Fields: c-ip cs-method sc-status", SRC)
    p = parse_access("203.0.113.99 DELETE 500", SRC)
    assert p["ip"] == "203.0.113.99"
    assert p["method"] == "DELETE"
    assert p["status"] == 500


def test_state_isolated_per_file():
    """Chaque fichier a son propre #Fields:."""
    src_a = "/logs/a.log"
    src_b = "/logs/b.log"
    parse_access("#Fields: c-ip cs-method sc-status", src_a)
    parse_access(FIELDS_FULL, src_b)
    # src_a : ordre custom
    pa = parse_access("1.1.1.1 GET 200", src_a)
    assert pa["ip"] == "1.1.1.1" and pa["method"] == "GET"
    # src_b : ordre complet
    pb = parse_access(
        "2026-05-22 00:15:23 10.0.0.5 POST /x - 80 - 2.2.2.2 UA - 404 0 0 5",
        src_b,
    )
    assert pb["ip"] == "2.2.2.2" and pb["status"] == 404


# ════════════════════════════════════════════════════════════════════════════
# Severity mapping (prefixe iis_*)
# ════════════════════════════════════════════════════════════════════════════

# (status, severity, event_type)
SEVERITY_SAMPLES = [
    (200, "info", "iis_access"),
    (301, "info", "iis_access"),
    (401, "high", "iis_access_denied"),
    (403, "high", "iis_access_denied"),
    (404, "low", "iis_404"),
    (429, "medium", "iis_4xx"),
    (500, "high", "iis_5xx"),
    (503, "high", "iis_5xx"),
]


@pytest.mark.parametrize("status,severity,event_type", SEVERITY_SAMPLES)
def test_severity_mapping(status, severity, event_type):
    parse_access(FIELDS_FULL, SRC)
    data = (f"2026-05-22 00:00:00 10.0.0.5 GET /x - 80 - 1.2.3.4 UA - "
            f"{status} 0 0 5")
    ev = line_to_event_access(data, SRC)
    assert ev["severity"] == severity, f"status {status}"
    assert ev["event_type"] == event_type, f"status {status}"
    assert ev["source"] == "u_ex260522.log"


def test_attack_user_agent_captured():
    parse_access(FIELDS_FULL, SRC)
    data = ("2026-05-22 00:16:00 10.0.0.5 POST /wp-login.php - 80 - "
            "198.51.100.7 sqlmap/1.5 - 403 0 0 5")
    p = parse_access(data, SRC)
    assert "sqlmap" in p["user_agent"]


# ════════════════════════════════════════════════════════════════════════════
# Commentaires + robustesse
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("comment", [
    "#Software: Microsoft Internet Information Services 10.0",
    "#Version: 1.0",
    "#Date: 2026-05-22 00:00:00",
])
def test_meta_comments(comment):
    ev = line_to_event_access(comment, SRC)
    assert ev["event_type"] == "iis_log_meta"
    assert ev["severity"] == "info"


def test_malformed_no_crash():
    p = parse_access("garbage not iis", SRC)
    assert p.get("parse_failed")


def test_malformed_event_is_info():
    ev = line_to_event_access("garbage", SRC)
    assert ev["severity"] == "info"
    assert ev["event_type"] == "iis_access_unparsed"


def test_empty_line():
    assert parse_access("", SRC).get("parse_failed")


# ════════════════════════════════════════════════════════════════════════════
# Integration facade + non-regression
# ════════════════════════════════════════════════════════════════════════════

def test_facade_routes_iis():
    parse_access(FIELDS_FULL, SRC)  # set fields
    data = ("2026-05-22 00:15:23 10.0.0.5 GET /admin - 80 - "
            "203.0.113.5 sqlmap - 403 0 0 5")
    ev = line_to_event(data, SRC, source_type="iis_access")
    assert ev["event_type"] == "iis_access_denied"
    assert ev["parsed"]["ip"] == "203.0.113.5"


def test_facade_iis_meta():
    ev = line_to_event(FIELDS_FULL, SRC, source_type="iis_access")
    assert ev["event_type"] == "iis_log_meta"


def test_nginx_still_works():
    line = ('203.0.113.5 - - [22/May/2026:00:16:00 +0000] '
            '"POST /wp-login.php HTTP/1.1" 403 0 "-" "sqlmap/1.5"')
    ev = line_to_event(line, "/var/log/nginx/access.log", source_type="nginx_access")
    assert ev["event_type"] == "nginx_access_denied"


def test_apache_still_works():
    line = ('203.0.113.5 - - [22/May/2026:00:16:00 +0000] '
            '"POST /wp-login.php HTTP/1.1" 403 0 "-" "sqlmap/1.5"')
    ev = line_to_event(line, "/var/log/apache2/access.log", source_type="apache_access")
    assert ev["event_type"] == "apache_access_denied"


def test_auto_still_works():
    syslog = ("May 22 00:15:23 host sshd[1234]: Failed password for root "
              "from 1.2.3.4 port 22 ssh2")
    ev = line_to_event(syslog, "/var/log/auth.log")
    assert ev["event_type"] == "ssh_failed_login"
