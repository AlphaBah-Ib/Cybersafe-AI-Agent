"""
Tests unitaires du parser nginx (SOC-300).

Samples access.log au format combined (defaut nginx) et error.log,
incluant des cas d'attaque reels (sqlmap, path traversal) et des
lignes malformees pour valider la robustesse.
"""
import pytest

from cybersafe_agent.parsers.nginx import (
    parse_access_combined,
    parse_error,
    line_to_event_access,
    line_to_event_error,
)
from cybersafe_agent.parser import line_to_event


# ════════════════════════════════════════════════════════════════════════════
# access.log combined — extraction de champs
# ════════════════════════════════════════════════════════════════════════════

# (ligne, ip, method, path, status)
ACCESS_FIELD_SAMPLES = [
    (
        '203.0.113.5 - - [22/May/2026:00:15:23 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        "203.0.113.5", "GET", "/index.html", 200,
    ),
    (
        '198.51.100.7 - - [22/May/2026:00:16:00 +0000] "POST /wp-login.php HTTP/1.1" 403 0 "-" "sqlmap/1.5"',
        "198.51.100.7", "POST", "/wp-login.php", 403,
    ),
    (
        '192.0.2.10 - - [22/May/2026:00:17:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 153 "-" "curl/7.68"',
        "192.0.2.10", "GET", "/../../etc/passwd", 404,
    ),
    (
        '192.0.2.99 - alice [22/May/2026:00:18:00 +0000] "PUT /api/v1/users HTTP/2.0" 500 512 "https://app" "PostmanRuntime/7.29"',
        "192.0.2.99", "PUT", "/api/v1/users", 500,
    ),
]


@pytest.mark.parametrize("line,ip,method,path,status", ACCESS_FIELD_SAMPLES)
def test_access_combined_fields(line, ip, method, path, status):
    p = parse_access_combined(line)
    assert p["ip"] == ip
    assert p["method"] == method
    assert p["path"] == path
    assert p["status"] == status
    assert "user_agent" in p
    assert "size" in p


def test_access_size_dash_becomes_zero():
    line = '203.0.113.5 - - [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 304 - "-" "x"'
    p = parse_access_combined(line)
    assert p["size"] == 0


def test_access_referer_and_user_extracted():
    line = '192.0.2.99 - bob [22/May/2026:00:18:00 +0000] "GET / HTTP/1.1" 200 10 "https://ref.example" "UA"'
    p = parse_access_combined(line)
    assert p.get("referer") == "https://ref.example"
    assert p.get("user") == "bob"


def test_access_nginx_time_iso():
    line = '203.0.113.5 - - [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'
    p = parse_access_combined(line)
    # Doit etre converti en ISO 8601
    assert "nginx_time" in p
    assert p["nginx_time"].startswith("2026-05-22T00:15:23")


# ════════════════════════════════════════════════════════════════════════════
# access.log — severity mapping
# ════════════════════════════════════════════════════════════════════════════

# (status, severity attendue, event_type attendu)
ACCESS_SEVERITY_SAMPLES = [
    (200, "info", "nginx_access"),
    (301, "info", "nginx_access"),
    (401, "high", "nginx_access_denied"),
    (403, "high", "nginx_access_denied"),
    (404, "low", "nginx_404"),
    (429, "medium", "nginx_4xx"),
    (444, "high", "nginx_conn_closed"),
    (500, "high", "nginx_5xx"),
    (502, "high", "nginx_5xx"),
]


@pytest.mark.parametrize("status,severity,event_type", ACCESS_SEVERITY_SAMPLES)
def test_access_severity_mapping(status, severity, event_type):
    line = f'1.2.3.4 - - [22/May/2026:00:00:00 +0000] "GET /x HTTP/1.1" {status} 0 "-" "ua"'
    ev = line_to_event_access(line, "/var/log/nginx/access.log")
    assert ev["severity"] == severity, f"status {status}"
    assert ev["event_type"] == event_type, f"status {status}"
    assert ev["source"] == "access.log"


def test_access_attack_user_agent_captured():
    """Le user-agent d'un outil d'attaque doit etre present dans parsed."""
    line = '198.51.100.7 - - [22/May/2026:00:16:00 +0000] "POST /wp-login.php HTTP/1.1" 403 0 "-" "sqlmap/1.5"'
    p = parse_access_combined(line)
    assert "sqlmap" in p["user_agent"]


# ════════════════════════════════════════════════════════════════════════════
# error.log — extraction + severity
# ════════════════════════════════════════════════════════════════════════════

# (ligne, level, client_ip attendu ou None, severity)
ERROR_SAMPLES = [
    (
        '2026/05/22 00:15:23 [error] 12345#0: *678 open() "/var/www/x" failed (2: No such file), client: 203.0.113.5, server: example.com',
        "error", "203.0.113.5", "medium",
    ),
    (
        '2026/05/22 00:20:00 [crit] 12345#0: *679 SSL_do_handshake() failed, client: 198.51.100.7, server: example.com',
        "crit", "198.51.100.7", "high",
    ),
    (
        '2026/05/22 00:25:00 [warn] 12345#0: *680 upstream server temporarily disabled, client: 192.0.2.10',
        "warn", "192.0.2.10", "low",
    ),
    (
        '2026/05/22 00:28:00 [notice] 12345#0: signal process started',
        "notice", None, "info",
    ),
]


@pytest.mark.parametrize("line,level,client_ip,severity", ERROR_SAMPLES)
def test_error_parsing(line, level, client_ip, severity):
    p = parse_error(line)
    assert p["level"] == level
    assert "error_message" in p
    if client_ip is None:
        assert "client_ip" not in p
    else:
        assert p["client_ip"] == client_ip


@pytest.mark.parametrize("line,level,client_ip,severity", ERROR_SAMPLES)
def test_error_severity_mapping(line, level, client_ip, severity):
    ev = line_to_event_error(line, "/var/log/nginx/error.log")
    assert ev["severity"] == severity
    assert ev["event_type"] == f"nginx_error_{level}"
    assert ev["source"] == "error.log"


def test_error_pid_extracted():
    line = '2026/05/22 00:15:23 [error] 99999#0: *1 some error'
    p = parse_error(line)
    assert p["pid"] == 99999


# ════════════════════════════════════════════════════════════════════════════
# Robustesse — aucune ligne ne doit crasher le parser
# ════════════════════════════════════════════════════════════════════════════

def test_malformed_access_no_crash():
    p = parse_access_combined("complete garbage not nginx at all")
    assert p.get("parse_failed") or p.get("parse_partial")


def test_malformed_access_event_is_info():
    """Une ligne non parsee ne doit PAS generer de fausse alerte."""
    ev = line_to_event_access("garbage", "/var/log/nginx/access.log")
    assert ev["severity"] == "info"
    assert ev["event_type"] == "nginx_access_unparsed"


def test_malformed_error_no_crash():
    p = parse_error("not an nginx error line")
    assert p.get("parse_failed")


def test_empty_line_no_crash():
    assert parse_access_combined("").get("parse_failed")
    assert parse_error("").get("parse_failed")


def test_error_emerg_without_client():
    line = '2026/05/22 00:30:00 [emerg] 12345#0: bind() to 0.0.0.0:80 failed (98: Address already in use)'
    p = parse_error(line)
    assert p["level"] == "emerg"
    assert "client_ip" not in p
    ev = line_to_event_error(line, "/var/log/nginx/error.log")
    assert ev["severity"] == "high"


# ════════════════════════════════════════════════════════════════════════════
# Integration via la facade — routing par type (SOC-300)
# ════════════════════════════════════════════════════════════════════════════

def test_facade_routes_nginx_access():
    line = '203.0.113.5 - - [22/May/2026:00:16:00 +0000] "POST /wp-login.php HTTP/1.1" 403 0 "-" "sqlmap/1.5"'
    ev = line_to_event(line, "/var/log/nginx/access.log", source_type="nginx_access")
    assert ev["event_type"] == "nginx_access_denied"
    assert ev["parsed"]["ip"] == "203.0.113.5"


def test_facade_routes_nginx_error():
    line = '2026/05/22 00:20:00 [crit] 12345#0: *679 SSL failed, client: 198.51.100.7'
    ev = line_to_event(line, "/var/log/nginx/error.log", source_type="nginx_error")
    assert ev["event_type"] == "nginx_error_crit"
    assert ev["parsed"]["client_ip"] == "198.51.100.7"


def test_facade_auto_mode_unchanged():
    """Mode auto (defaut) : une ligne syslog reste parsee par le parser Linux."""
    syslog = "May 22 00:15:23 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
    ev = line_to_event(syslog, "/var/log/auth.log")
    assert ev["event_type"] == "ssh_failed_login"
    assert ev["parsed"]["ip"] == "1.2.3.4"
