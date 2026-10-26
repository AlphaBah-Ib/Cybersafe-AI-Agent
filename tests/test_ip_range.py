# -*- coding: utf-8 -*-
"""
US-SOC-R12 porte 3 (agent 2.1.0) — blocage de plage d'adresses.

    python -m pytest tests/test_ip_range.py -v
"""
import base64
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybersafe_agent import order_guard as g
from cybersafe_agent import remediation as r

NET = "45.148.10.0/24"
WHY = "Campagne de force brute depuis ce bloc"
_FMT = "%Y-%m-%dT%H:%M:%SZ"


@pytest.fixture
def key(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(g, "_ORDER_PUBLIC_KEY_B64", base64.b64encode(raw).decode("ascii"))
    return priv


@pytest.fixture
def journal(tmp_path):
    return g.ReplayJournal(str(tmp_path))


def make(priv, **fields):
    now = datetime.now(timezone.utc)
    order = {"id": 7, "action": "block_ip_range", "target_ip": NET, "ttl_seconds": 3600, "agent_id": 7,
             "issued_at": now.strftime(_FMT), "expires_at": (now + timedelta(minutes=5)).strftime(_FMT),
             "nonce": uuid.uuid4().hex, "params": {"justification": WHY}}
    order.update(fields)
    order["sig_alg"] = "ed25519-v2"
    order["signature"] = base64.b64encode(priv.sign(g.canonical(order, g.SIGNED_FIELDS_V2))).decode("ascii")
    return order


class TestGarde:
    def test_plage_valide(self, key, journal):
        g.guard_order(make(key), journal)

    def test_plage_ipv6(self, key, journal):
        g.guard_order(make(key, target_ip="2001:db8:1::/48"), journal)

    @pytest.mark.parametrize("target,motif", [
        ("45.148.0.0/16", "trop large"),
        ("2001:db8::/32", "trop large"),
        ("45.148.10.7/24", "invalide"),
        ("45.148.10.7", "invalide"),
        ("192.168.1.0/24", "interne"),
        ("10.1.2.0/24", "interne"),
        ("127.0.0.0/24", "interne"),
        ("fe80::/64", "interne"),
    ])
    def test_plages_refusees(self, key, journal, target, motif):
        with pytest.raises(g.OrderRejected, match=motif):
            g.guard_order(make(key, target_ip=target), journal)

    def test_justification_obligatoire(self, key, journal):
        with pytest.raises(g.OrderRejected, match="texte attendu"):
            g.guard_order(make(key, params={}), journal)
        with pytest.raises(g.OrderRejected, match="longueur"):
            g.guard_order(make(key, params={"justification": "court"}), journal)
        with pytest.raises(g.OrderRejected, match="controle"):
            g.guard_order(make(key, params={"justification": WHY + "\nDROP"}), journal)

    def test_levee_toujours_permise(self, key, journal):
        g.guard_order(make(key, action="unblock_ip_range", params={}), journal)

    def test_ban_ip_inchange(self, key, journal):
        g.guard_order(make(key, action="ban_ip", target_ip="45.148.10.9", params={}), journal)


@pytest.fixture
def ipt(monkeypatch):
    calls, state = [], {"rules": ""}

    def fake_run(cmd, **kw):
        calls.append(cmd)
        out = state["rules"] if cmd[1:3] == ["-S", "INPUT"] else ""
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")

    monkeypatch.setattr(r.shutil, "which", lambda name: "/usr/sbin/" + name)
    monkeypatch.setattr(r.subprocess, "run", fake_run)
    return types.SimpleNamespace(calls=calls, state=state)


class TestIptables:
    def test_regle_de_plage(self, ipt):
        ok, detail = r._apply_range_block(NET)
        assert ok, detail
        cmd = ipt.calls[-1]
        assert cmd[:5] == ["iptables", "-I", "INPUT", "-s", NET]
        assert cmd[cmd.index("--comment") + 1] == "cybersafe-range:" + NET
        assert cmd[-2:] == ["-j", "DROP"]

    def test_plage_ipv6(self, ipt):
        r._apply_range_block("2001:db8:1::/48")
        assert ipt.calls[-1][0] == "ip6tables"

    def test_retrait_par_commentaire(self, ipt):
        ipt.state["rules"] = (
            "-A INPUT -s 45.148.10.0/24 -m comment --comment \"cybersafe-range:45.148.10.0/24\" -j DROP\n"
            "-A INPUT -s 45.148.10.9/32 -j DROP\n")
        ok, detail = r._remove_range_block(NET)
        assert ok and "1 regle" in detail
        assert len([c for c in ipt.calls if c[1] == "-D"]) == 1


class TestAntiLockout:
    def test_contient(self):
        assert r._range_contains_any(NET, {"45.148.10.77"})
        assert not r._range_contains_any(NET, {"45.148.11.1"})
        assert not r._range_contains_any("45.148.10.77", {"45.148.10.77"})

    def test_session_ssh_dans_la_plage_refusee(self, monkeypatch):
        reports, applied = [], []
        monkeypatch.setattr(r, "_guard_order", lambda order: None)
        monkeypatch.setattr(r, "_active_ssh_source_ips", lambda: {"45.148.10.77"})
        monkeypatch.setattr(r, "_apply_range_block", lambda net: (applied.append(net), (True, "ok"))[1])
        monkeypatch.setattr(r, "_report", lambda api, tok, oid, ok, detail, rule_present=None: reports.append((ok, detail)))
        r._process_order({"id": 1, "action": "block_ip_range", "target_ip": NET,
                          "params": {"justification": WHY}}, "https://x", "t")
        assert applied == []
        assert reports[-1][0] is False and "anti-lockout" in reports[-1][1]

    def test_plage_executee_sans_session(self, monkeypatch):
        applied = []
        monkeypatch.setattr(r, "_guard_order", lambda order: None)
        monkeypatch.setattr(r, "_active_ssh_source_ips", lambda: {"203.0.113.5"})
        monkeypatch.setattr(r, "_apply_range_block", lambda net: (applied.append(net), (True, "ok"))[1])
        monkeypatch.setattr(r, "_report", lambda *a, **k: None)
        r._process_order({"id": 2, "action": "block_ip_range", "target_ip": NET,
                          "params": {"justification": WHY}}, "https://x", "t")
        assert applied == [NET]
