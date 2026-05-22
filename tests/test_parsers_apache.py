"""
Tests unitaires du parser Apache access.log (SOC-301).

Apache combined est identique a nginx combined (reutilisation DRY).
Le format common (CLF) est specifique a Apache : sans Referer ni User-Agent.
Inclut des cas d'attaque reels et des lignes malformees (robustesse).
"""
import pytest

from cybersafe_agent.parsers.apache import (
    parse_access,
    line_to_event_access,
    RE_APACHE_COMMON,
)
from cybersafe_agent.parser import line_to_event


# ════════════════════════════════════════════════════════════════════════════
# access.log combined (== nginx, avec referer + user-agent)
# ════════════════════════════════════════════════════════════════════════════

COMBINED_SAMPLES = [
    (
        '203.0.113.5 - frank [22/May/2026:00:15:23 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://ref.example" "Mozilla/5.0"',
        "203.0.113.5", "GET", "/index.html", 200,
    ),
    (
        '198.51.100.7 - - [22/May/2026:00:16:00 +0000] "POST /wp-login.php HTTP/1.1" 403 0 "-" "sqlmap/1.5"',
        "198.51.100.7", "POST", "/wp-login.php", 403,
    ),
    (
        '192.0.2.99 - alice [22/May/2026:00:18:00 +0000] "PUT /api/users HTTP/2.0" 500 512 "https://app" "PostmanRuntime/7.29"',
        "192.0.2.99", "PUT", "/api/users", 500,
    ),
]


@pytest.mark.parametrize("line,ip,method,path,status", COMBINED_SAMPLES)
def test_combined_fields(line, ip, method, path, status):
    p = parse_access(line)
    assert p["ip"] == ip
    assert p["method"] == method
    assert p["path"] == path
    assert p["status"] == status
    assert "user_agent" in p  # combined a un user-agent


def test_combined_referer_and_user():
    line = '203.0.113.5 - frank [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 200 10 "https://ref.example" "UA"'
    p = parse_access(line)
    assert p.get("referer") == "https://ref.example"
    assert p.get("user") == "frank"


def test_combined_attack_user_agent():
    line = '198.51.100.7 - - [22/May/2026:00:16:00 +0000] "POST /wp-login.php HTTP/1.1" 403 0 "-" "sqlmap/1.5"'
    p = parse_access(line)
    assert "sqlmap" in p["user_agent"]


def test_combined_apache_time_iso():
    line = '203.0.113.5 - - [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'
    p = parse_access(line)
    assert "apache_time" in p
    assert p["apache_time"].startswith("2026-05-22T00:15:23")


# ════════════════════════════════════════════════════════════════════════════
# access.log common / CLF (sans referer ni user-agent)
# ════════════════════════════════════════════════════════════════════════════

COMMON_SAMPLES = [
    (
        '203.0.113.5 - frank [22/May/2026:00:15:23 +0000] "GET /index.html HTTP/1.1" 200 1234',
        "203.0.113.5", "GET", "/index.html", 200,
    ),
    (
        '198.51.100.7 - - [22/May/2026:00:16:00 +0000] "POST /wp-login.php HTTP/1.1" 403 0',
        "198.51.100.7", "POST", "/wp-login.php", 403,
    ),
    (
        '192.0.2.10 - - [22/May/2026:00:17:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 153',
        "192.0.2.10", "GET", "/../../etc/passwd", 404,
    ),
]


@pytest.mark.parametrize("line,ip,method,path,status", COMMON_SAMPLES)
def test_common_fields(line, ip, method, path, status):
    p = parse_access(line)
    assert p["ip"] == ip
    assert p["method"] == method
    assert p["path"] == path
    assert p["status"] == status
    assert p.get("log_format") == "common"
    assert "user_agent" not in p  # common n'a pas de user-agent


def test_common_regex_direct():
    """RE_APACHE_COMMON matche bien le CLF."""
    line = '127.0.0.1 - - [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 200 1234'
    m = RE_APACHE_COMMON.search(line)
    assert m is not None
    assert m.group("ip") == "127.0.0.1"
    assert m.group("status") == "200"


def test_combined_not_matched_as_common():
    """
    Garde-fou auto-detection : une ligne combined ne doit PAS etre parsee
    comme common (sinon on perdrait user_agent/referer).
    """
    combined = '203.0.113.5 - - [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 200 10 "-" "UA"'
    p = parse_access(combined, fmt="auto")
    # Doit etre detecte comme combined -> user_agent present
    assert "user_agent" in p
    assert p.get("log_format") != "common"


# ════════════════════════════════════════════════════════════════════════════
# Auto-detection + format explicite
# ════════════════════════════════════════════════════════════════════════════

def test_auto_detects_combined():
    line = '203.0.113.5 - - [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 200 10 "-" "UA"'
    p = parse_access(line, fmt="auto")
    assert "user_agent" in p


def test_auto_detects_common():
    line = '203.0.113.5 - - [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 200 10'
    p = parse_access(line, fmt="auto")
    assert p.get("log_format") == "common"


def test_format_common_explicit():
    line = '203.0.113.5 - - [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 200 10'
    p = parse_access(line, fmt="common")
    assert p.get("log_format") == "common"


def test_format_combined_explicit():
    line = '203.0.113.5 - - [22/May/2026:00:15:23 +0000] "GET / HTTP/1.1" 200 10 "-" "UA"'
    p = parse_access(line, fmt="combined")
    assert "user_agent" in p


# ════════════════════════════════════════════════════════════════════════════
# Severity mapping (prefixe apache_*)
# ════════════════════════════════════════════════════════════════════════════

# (status, severity, event_type) — meme logique que nginx mais prefixe apache_
SEVERITY_SAMPLES = [
    (200, "info", "apache_access"),
    (301, "info", "apache_access"),
    (401, "high", "apache_access_denied"),
    (403, "high", "apache_access_denied"),
    (404, "low", "apache_404"),
    (429, "medium", "apache_4xx"),
    (444, "high", "apache_conn_closed"),
    (500, "high", "apache_5xx"),
    (503, "high", "apache_5xx"),
]


@pytest.mark.parametrize("status,severity,event_type", SEVERITY_SAMPLES)
def test_severity_mapping(status, severity, event_type):
    line = f'1.2.3.4 - - [22/May/2026:00:00:00 +0000] "GET /x HTTP/1.1" {status} 0'
    ev = line_to_event_access(line, "/var/log/apache2/access.log")
    assert ev["severity"] == severity, f"status {status}"
    assert ev["event_type"] == event_type, f"status {status}"
    assert ev["source"] == "access.log"


# ════════════════════════════════════════════════════════════════════════════
# Robustesse
# ════════════════════════════════════════════════════════════════════════════

def test_malformed_no_crash():
    p = parse_access("complete garbage not apache")
    assert p.get("parse_failed") or p.get("parse_partial")


def test_malformed_event_is_info():
    ev = line_to_event_access("garbage", "/var/log/apache2/access.log")
    assert ev["severity"] == "info"
    assert ev["event_type"] == "apache_access_unparsed"


def test_empty_line_no_crash():
    assert parse_access("").get("parse_failed")


# ════════════════════════════════════════════════════════════════════════════
# Integration via la facade (routing par type SOC-301)
# ════════════════════════════════════════════════════════════════════════════

def test_facade_routes_apache_access_combined():
    line = '203.0.113.5 - - [22/May/2026:00:16:00 +0000] "POST /wp-login.php HTTP/1.1" 403 0 "-" "sqlmap/1.5"'
    ev = line_to_event(line, "/var/log/apache2/access.log", source_type="apache_access")
    assert ev["event_type"] == "apache_access_denied"
    assert ev["parsed"]["ip"] == "203.0.113.5"
    assert "sqlmap" in ev["parsed"]["user_agent"]


def test_facade_routes_apache_access_common():
    line = '198.51.100.7 - - [22/May/2026:00:16:00 +0000] "POST /wp-login.php HTTP/1.1" 403 0'
    ev = line_to_event(line, "/var/log/apache2/access.log", source_type="apache_access")
    assert ev["event_type"] == "apache_access_denied"
    assert ev["parsed"]["log_format"] == "common"


def test_facade_apache_format_common():
    line = '198.51.100.7 - - [22/May/2026:00:16:00 +0000] "GET /x HTTP/1.1" 200 10'
    ev = line_to_event(line, "/var/log/apache2/access.log",
                       source_type="apache_access", source_format="common")
    assert ev["parsed"]["log_format"] == "common"


# ════════════════════════════════════════════════════════════════════════════
# Non-regression : nginx et auto restent intacts
# ════════════════════════════════════════════════════════════════════════════

def test_nginx_routing_still_works():
    line = '203.0.113.5 - - [22/May/2026:00:16:00 +0000] "POST /wp-login.php HTTP/1.1" 403 0 "-" "sqlmap/1.5"'
    ev = line_to_event(line, "/var/log/nginx/access.log", source_type="nginx_access")
    assert ev["event_type"] == "nginx_access_denied"  # nginx_ pas apache_


def test_auto_mode_still_works():
    syslog = "May 22 00:15:23 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
    ev = line_to_event(syslog, "/var/log/auth.log")
    assert ev["event_type"] == "ssh_failed_login"
