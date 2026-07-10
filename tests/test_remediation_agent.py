# -*- coding: utf-8 -*-
"""
SOC-RESPONSE (agent) — tests du module remediation.

Mocks sur subprocess/requests : AUCUNE commande systeme ni requete reseau reelle.
Focus : anti-lockout (garde-fou critique), routage ban/unban, report.

A placer dans tests/ (pytest, comme le reste de l'agent).
"""
from unittest import mock

from cybersafe_agent import remediation as R


def test_active_ssh_source_ips_parse():
    who_out = "root  pts/0  2026-07-09 20:00 (203.0.113.5)\n" \
              "user  pts/1  2026-07-09 20:01 (198.51.100.7)\n"
    with mock.patch("cybersafe_agent.remediation.subprocess.run") as m:
        m.return_value = mock.Mock(stdout=who_out)
        ips = R._active_ssh_source_ips()
    assert "203.0.113.5" in ips
    assert "198.51.100.7" in ips


def test_anti_lockout_refuses_active_ssh_ip():
    """GARDE-FOU : ne jamais bannir l'IP d'une session SSH active."""
    order = {"id": 1, "action": "ban_ip", "target_ip": "203.0.113.5"}
    with mock.patch("cybersafe_agent.remediation._active_ssh_source_ips",
                    return_value={"203.0.113.5"}), \
         mock.patch("cybersafe_agent.remediation._apply_ban") as apply_ban, \
         mock.patch("cybersafe_agent.remediation._report") as report:
        R._process_order(order, "https://app.test/api", "tok")
    apply_ban.assert_not_called()               # le ban n'est PAS execute
    args = report.call_args[0]
    assert args[3] is False                     # success = False
    assert "anti-lockout" in args[4].lower()


def test_ban_executed_when_ip_not_active():
    order = {"id": 2, "action": "ban_ip", "target_ip": "45.155.205.99"}
    with mock.patch("cybersafe_agent.remediation._active_ssh_source_ips",
                    return_value=set()), \
         mock.patch("cybersafe_agent.remediation._detect_firewall",
                    return_value="ufw"), \
         mock.patch("cybersafe_agent.remediation._apply_ban",
                    return_value=(True, "ufw: rule added")) as apply_ban, \
         mock.patch("cybersafe_agent.remediation._report") as report:
        R._process_order(order, "https://app.test/api", "tok")
    apply_ban.assert_called_once()
    args = report.call_args[0]
    assert args[3] is True


def test_unban_routes_to_apply_unban():
    order = {"id": 3, "action": "unban_ip", "target_ip": "45.155.205.99"}
    with mock.patch("cybersafe_agent.remediation._detect_firewall",
                    return_value="ufw"), \
         mock.patch("cybersafe_agent.remediation._apply_unban",
                    return_value=(True, "ok")) as apply_unban, \
         mock.patch("cybersafe_agent.remediation._report"):
        R._process_order(order, "https://app.test/api", "tok")
    apply_unban.assert_called_once()


def test_empty_ip_reported_as_failure():
    order = {"id": 4, "action": "ban_ip", "target_ip": ""}
    with mock.patch("cybersafe_agent.remediation._report") as report:
        R._process_order(order, "https://app.test/api", "tok")
    args = report.call_args[0]
    assert args[3] is False


def test_apply_ban_ufw_builds_correct_command():
    with mock.patch("cybersafe_agent.remediation.subprocess.run") as m:
        m.return_value = mock.Mock(returncode=0, stdout="Rule added", stderr="")
        ok, detail = R._apply_ban("1.2.3.4", "ufw")
    assert ok is True
    called = m.call_args[0][0]
    assert called == ["ufw", "deny", "from", "1.2.3.4"]


def test_apply_ban_no_firewall():
    ok, detail = R._apply_ban("1.2.3.4", None)
    assert ok is False
    assert "firewall" in detail.lower()


def test_poll_once_handles_non_200():
    with mock.patch("cybersafe_agent.remediation.requests.get") as g:
        g.return_value = mock.Mock(status_code=401)
        # ne doit pas lever
        R._poll_once("https://app.test/api", "tok")


def test_orders_url_and_result_url():
    assert R._orders_url("https://app.test/api/") == "https://app.test/api/soc/agents/orders/"
    assert R._result_url("https://app.test/api", 7) == "https://app.test/api/soc/agents/orders/7/result/"
