"""
Tests unitaires pour le portage Windows de cybersafe_agent.port_inventory.

SOC-PORTS (Windows) : couvre le parsing de `netstat -ano`, le mapping PID->nom
via tasklist, la decision exposed/sensitive partagee avec Linux, et la
robustesse (localisation FR/EN, IPv6, tasklist absent).

Strategie :
  - samples netstat -ano realistes (EN et FR), IPv4 + IPv6
  - verifie le contrat de sortie identique a Linux (port/address/process/
    exposed/sensitive) et l'event final

Pour lancer :
    python -m pytest tests/test_port_inventory_windows.py -v
"""
import pytest

from cybersafe_agent.port_inventory import (
    _is_exposed,
    _parse_netstat_windows,
    _windows_pid_to_name,
    build_port_inventory_event,
    SENSITIVE_PORTS,
)


# =============================================================================
# Samples realistes de sortie `netstat -ano`
# =============================================================================

# Windows EN — en-tete anglais, IPv4 + IPv6, LISTENING + ESTABLISHED.
NETSTAT_EN = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       1234
  TCP    0.0.0.0:6379           0.0.0.0:0              LISTENING       4444
  TCP    127.0.0.1:5432         0.0.0.0:0              LISTENING       2222
  TCP    192.168.1.10:445       203.0.113.5:51000     ESTABLISHED     4
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::1]:9000             [::]:0                 LISTENING       7777
"""

# Windows FR — en-tete francais, mais 'LISTENING' reste en anglais.
NETSTAT_FR = """
Connexions actives

  Proto  Adresse locale         Adresse distante       Ã‰tat           PID
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       900
  TCP    127.0.0.1:25           0.0.0.0:0              LISTENING       300
"""


def _by_port(ports):
    return {p["port"]: p for p in ports}


# =============================================================================
# _is_exposed — logique commune Linux/Windows
# =============================================================================
class TestIsExposed:
    def test_wildcard_ipv4_is_exposed(self):
        assert _is_exposed("0.0.0.0") is True
        assert _is_exposed("*") is True

    def test_wildcard_ipv6_is_exposed(self):
        assert _is_exposed("::") is True
        assert _is_exposed("[::]") is True

    def test_loopback_ipv4_not_exposed(self):
        assert _is_exposed("127.0.0.1") is False

    def test_loopback_ipv6_not_exposed(self):
        assert _is_exposed("[::1]") is False
        assert _is_exposed("::1") is False

    def test_lan_address_is_exposed(self):
        # Une IP de LAN n'est pas loopback -> consideree exposee.
        assert _is_exposed("192.168.1.10") is True


# =============================================================================
# _parse_netstat_windows — parsing de la sortie netstat
# =============================================================================
class TestParseNetstatWindows:
    def test_only_listening_lines_kept(self):
        ports = _parse_netstat_windows(NETSTAT_EN, {})
        # La ligne ESTABLISHED (445 vers 203.0.113.5) ne doit PAS etre prise.
        # Mais le LISTENING [::]:445 oui -> 445 present une seule fois.
        got = _by_port(ports)
        assert 22 in got
        assert 6379 in got
        assert 5432 in got
        assert 445 in got      # via [::]:445 LISTENING
        assert 9000 in got
        # Le 445 retenu doit etre la ligne LISTENING [::], pas l'ESTABLISHED.
        assert got[445]["address"] == "[::]"

    def test_port_and_address_extracted(self):
        ports = _by_port(_parse_netstat_windows(NETSTAT_EN, {}))
        assert ports[22]["address"] == "0.0.0.0"
        assert ports[6379]["address"] == "0.0.0.0"
        assert ports[5432]["address"] == "127.0.0.1"

    def test_exposed_flag(self):
        ports = _by_port(_parse_netstat_windows(NETSTAT_EN, {}))
        assert ports[22]["exposed"] is True       # 0.0.0.0
        assert ports[6379]["exposed"] is True      # 0.0.0.0
        assert ports[5432]["exposed"] is False     # 127.0.0.1 (loopback)
        assert ports[445]["exposed"] is True       # [::]
        assert ports[9000]["exposed"] is False     # [::1] (loopback IPv6)

    def test_sensitive_detection(self):
        ports = _by_port(_parse_netstat_windows(NETSTAT_EN, {}))
        assert ports[6379]["sensitive"] == SENSITIVE_PORTS[6379]  # Redis
        assert ports[5432]["sensitive"] == SENSITIVE_PORTS[5432]  # PostgreSQL
        assert ports[22]["sensitive"] == ""                       # 22 non sensible

    def test_process_name_mapping(self):
        pid_to_name = {1234: "sshd.exe", 4444: "redis-server.exe"}
        ports = _by_port(_parse_netstat_windows(NETSTAT_EN, pid_to_name))
        assert ports[22]["process"] == "sshd.exe"
        assert ports[6379]["process"] == "redis-server.exe"
        # PID non mappe -> process vide (degradation gracieuse).
        assert ports[5432]["process"] == ""

    def test_process_empty_when_no_mapping(self):
        ports = _by_port(_parse_netstat_windows(NETSTAT_EN, {}))
        assert all(p["process"] == "" for p in ports.values())

    def test_french_locale_listening_parsed(self):
        # En-tete FR mais 'LISTENING' anglais -> doit parser quand meme.
        ports = _by_port(_parse_netstat_windows(NETSTAT_FR, {}))
        assert 3389 in ports
        assert 25 in ports
        assert ports[3389]["exposed"] is True      # 0.0.0.0
        assert ports[25]["exposed"] is False       # 127.0.0.1

    def test_empty_output_returns_empty(self):
        assert _parse_netstat_windows("", {}) == []

    def test_garbage_lines_ignored(self):
        junk = "blabla\nProto truc\n   \nTCP incomplete LISTENING"
        # 'TCP incomplete LISTENING' a < 5 colonnes -> ignore, pas de crash.
        assert _parse_netstat_windows(junk, {}) == []


# =============================================================================
# _windows_pid_to_name — robustesse du mapping best-effort
# =============================================================================
class TestWindowsPidToName:
    def test_returns_dict_without_crashing(self, monkeypatch):
        # tasklist absent / echec -> _run renvoie "" -> mapping vide, pas d'erreur.
        import cybersafe_agent.port_inventory as pi
        monkeypatch.setattr(pi, "_run", lambda cmd: "")
        assert pi._windows_pid_to_name() == {}

    def test_parses_csv_output(self, monkeypatch):
        import cybersafe_agent.port_inventory as pi
        fake_csv = (
            '"sshd.exe","1234","Services","0","12 000 K"\n'
            '"redis-server.exe","4444","Services","0","30 000 K"\n'
        )
        monkeypatch.setattr(pi, "_run", lambda cmd: fake_csv)
        mapping = pi._windows_pid_to_name()
        assert mapping[1234] == "sshd.exe"
        assert mapping[4444] == "redis-server.exe"

    def test_malformed_csv_line_skipped(self, monkeypatch):
        import cybersafe_agent.port_inventory as pi
        fake_csv = '"only-one-field"\n"good.exe","555","Services","0","1 K"\n'
        monkeypatch.setattr(pi, "_run", lambda cmd: fake_csv)
        mapping = pi._windows_pid_to_name()
        assert mapping == {555: "good.exe"}


# =============================================================================
# build_port_inventory_event — contrat de sortie identique a Linux
# =============================================================================
class TestBuildEventWindows:
    def test_event_schema_on_windows(self, monkeypatch):
        import cybersafe_agent.port_inventory as pi
        # Force la collecte a renvoyer un inventaire Windows simule.
        fake_ports = pi._parse_netstat_windows(
            NETSTAT_EN, {4444: "redis-server.exe"}
        )
        monkeypatch.setattr(pi, "collect_listening_ports", lambda: sorted(
            {(p["port"], p["address"]): p for p in fake_ports}.values(),
            key=lambda x: x["port"],
        ))
        ev = pi.build_port_inventory_event()
        assert ev["event_type"] == "port_inventory"
        assert ev["source"] == "port-inventory"
        # Redis expose -> severity warning + present dans sensitive_exposed.
        assert ev["severity"] == "warning"
        parsed = ev["parsed"]
        assert parsed["total"] >= 1
        sens_ports = {s["port"] for s in parsed["sensitive_exposed"]}
        assert 6379 in sens_ports
        assert {"port": 6379, "service": "Redis"} in parsed["sensitive_exposed"]
