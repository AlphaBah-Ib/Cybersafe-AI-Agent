# -*- coding: utf-8 -*-
"""
US-SOC-R12 porte 2 (agent 2.0.0) — limitation de debit et signature v2.

    python -m pytest tests/test_rate_limit.py -v
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

IP = "1.2.3.4"
_FMT = "%Y-%m-%dT%H:%M:%SZ"

# Vecteur de reference v2, identique cote serveur (apps/soc/tests_r12_rate_limit.py).
REF_V2_PAYLOAD = {
    "id": 42, "action": "rate_limit_ip", "target_ip": "1.2.3.4", "ttl_seconds": 3600,
    "agent_id": 7, "issued_at": "2026-10-04T18:30:00Z", "expires_at": "2026-10-04T18:35:00Z",
    "nonce": "0123456789abcdef0123456789abcdef", "params": {"rate_per_minute": 30, "burst": 10},
}
REF_V2_CANONICAL = (
    b'{"action":"rate_limit_ip","agent_id":7,"expires_at":"2026-10-04T18:35:00Z","id":42,'
    b'"issued_at":"2026-10-04T18:30:00Z","nonce":"0123456789abcdef0123456789abcdef",'
    b'"params":{"burst":10,"rate_per_minute":30},"target_ip":"1.2.3.4","ttl_seconds":3600}'
)


@pytest.fixture
def key(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(g, "_ORDER_PUBLIC_KEY_B64", base64.b64encode(raw).decode("ascii"))
    return priv


@pytest.fixture
def journal(tmp_path):
    return g.ReplayJournal(str(tmp_path))


def make(priv, alg="ed25519-v2", after_sign=None, **fields):
    now = datetime.now(timezone.utc)
    order = {"id": 99, "action": "rate_limit_ip", "target_ip": IP, "ttl_seconds": 600, "agent_id": 7,
             "issued_at": now.strftime(_FMT), "expires_at": (now + timedelta(minutes=5)).strftime(_FMT),
             "nonce": uuid.uuid4().hex, "params": {"rate_per_minute": 30, "burst": 10}}
    order.update(fields)
    fields_signed = g.SIGNED_FIELDS_V2 if alg == "ed25519-v2" else g.SIGNED_FIELDS
    order["sig_alg"] = alg
    order["signature"] = base64.b64encode(priv.sign(g.canonical(order, fields_signed))).decode("ascii")
    order.update(after_sign or {})
    return order


class TestSignatureV2:
    def test_canonical_identique_au_serveur(self):
        assert g.canonical(REF_V2_PAYLOAD, g.SIGNED_FIELDS_V2) == REF_V2_CANONICAL

    def test_limitation_v2_acceptee(self, key, journal):
        g.guard_order(make(key), journal)

    def test_parametres_falsifies_refuses(self, key, journal):
        order = make(key, after_sign={"params": {"rate_per_minute": 1, "burst": 10}})
        with pytest.raises(g.OrderRejected, match="signature invalide"):
            g.guard_order(order, journal)

    def test_limitation_en_v1_refusee(self, key, journal):
        order = make(key, alg="ed25519")
        with pytest.raises(g.OrderRejected, match="signature v2 exigee"):
            g.guard_order(order, journal)

    def test_ban_ip_v1_toujours_accepte(self, key, journal):
        order = make(key, alg="ed25519", action="ban_ip")
        order.pop("params")
        order["signature"] = base64.b64encode(key.sign(g.canonical(order))).decode("ascii")
        g.guard_order(order, journal)

    def test_ban_ip_v2_accepte(self, key, journal):
        g.guard_order(make(key, action="ban_ip", params={}), journal)

    def test_ban_ip_avec_parametres_refuse(self, key, journal):
        with pytest.raises(g.OrderRejected, match="non autorise"):
            g.guard_order(make(key, action="ban_ip", params={"rate_per_minute": 5}), journal)


class TestParametres:
    @pytest.mark.parametrize("params,motif", [
        ({"rate_per_minute": 0, "burst": 10}, "hors bornes"),
        ({"rate_per_minute": 601, "burst": 10}, "hors bornes"),
        ({"rate_per_minute": 30, "burst": 101}, "hors bornes"),
        ({"rate_per_minute": "30", "burst": 10}, "entier attendu"),
        ({"rate_per_minute": True, "burst": 10}, "entier attendu"),
        ({"rate_per_minute": 30}, "entier attendu"),
        ({"rate_per_minute": 30, "burst": 10, "cmd": "x"}, "non autorise"),
    ])
    def test_parametres_refuses(self, key, journal, params, motif):
        with pytest.raises(g.OrderRejected, match=motif):
            g.guard_order(make(key, params=params), journal)


@pytest.fixture
def ipt(monkeypatch):
    calls = []
    state = {"rules": ""}

    def fake_run(cmd, **kw):
        calls.append(cmd)
        out = state["rules"] if cmd[1:3] == ["-S", "INPUT"] else ""
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")

    monkeypatch.setattr(r.shutil, "which", lambda name: "/usr/sbin/" + name)
    monkeypatch.setattr(r.subprocess, "run", fake_run)
    return types.SimpleNamespace(calls=calls, state=state)


class TestIptables:
    def test_regle_de_limitation(self, ipt):
        ok, detail = r._apply_rate_limit(IP, 30, 10)
        assert ok, detail
        cmd = ipt.calls[-1]
        assert cmd[:5] == ["iptables", "-I", "INPUT", "-s", IP]
        assert "30/minute" in cmd and "--hashlimit-burst" in cmd and "10" in cmd
        assert cmd[cmd.index("--comment") + 1] == "cybersafe-rl:1.2.3.4"
        assert len(cmd[cmd.index("--hashlimit-name") + 1]) <= 15

    def test_ipv6_utilise_ip6tables(self, ipt):
        r._apply_rate_limit("2001:db8::7", 30, 10)
        assert ipt.calls[-1][0] == "ip6tables"

    def test_retrait_par_commentaire(self, ipt):
        ipt.state["rules"] = (
            "-P INPUT ACCEPT\n"
            "-A INPUT -s 1.2.3.4/32 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 30/min "
            "--hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name csrlabc -m comment "
            "--comment cybersafe-rl:1.2.3.4 -j DROP\n"
            "-A INPUT -s 5.6.7.8/32 -m comment --comment cybersafe-rl:5.6.7.8 -j DROP\n"
            "-A INPUT -s 1.2.3.4/32 -j DROP\n")
        ok, detail = r._remove_rate_limit(IP)
        assert ok and "1 regle" in detail
        deletes = [c for c in ipt.calls if c[1] == "-D"]
        assert len(deletes) == 1
        assert deletes[0][deletes[0].index("--comment") + 1] == "cybersafe-rl:1.2.3.4"

    def test_ban_ipv6_utilise_ip6tables(self, ipt):
        r._apply_ban("2001:db8::7", "iptables")
        assert ipt.calls[-1][0] == "ip6tables"


class TestProcessOrder:
    def _setup(self, monkeypatch, active=()):
        seen = types.SimpleNamespace(applied=[], reports=[])
        monkeypatch.setattr(r, "_guard_order", lambda order: None)
        monkeypatch.setattr(r, "_active_ssh_source_ips", lambda: set(active))
        monkeypatch.setattr(r, "_detect_firewall", lambda: "iptables")
        monkeypatch.setattr(r, "_apply_rate_limit", lambda ip, rate, burst: (seen.applied.append((ip, rate, burst)), (True, "ok"))[1])
        monkeypatch.setattr(r, "_remove_rate_limit", lambda ip: (seen.applied.append(("remove", ip)), (True, "ok"))[1])
        monkeypatch.setattr(r, "_report", lambda api, tok, oid, ok, detail, rule_present=None: seen.reports.append((oid, ok, detail)))
        return seen

    def test_limitation_executee(self, monkeypatch):
        seen = self._setup(monkeypatch)
        r._process_order({"id": 1, "action": "rate_limit_ip", "target_ip": IP,
                          "params": {"rate_per_minute": 30, "burst": 10}}, "https://x", "t")
        assert seen.applied == [(IP, 30, 10)]
        assert seen.reports[-1][1] is True

    def test_levee_executee(self, monkeypatch):
        seen = self._setup(monkeypatch)
        r._process_order({"id": 2, "action": "remove_rate_limit", "target_ip": IP}, "https://x", "t")
        assert seen.applied == [("remove", IP)]

    def test_anti_lockout_sur_limitation(self, monkeypatch):
        seen = self._setup(monkeypatch, active={IP})
        r._process_order({"id": 3, "action": "rate_limit_ip", "target_ip": IP,
                          "params": {"rate_per_minute": 30, "burst": 10}}, "https://x", "t")
        assert seen.applied == []
        assert seen.reports[-1][1] is False and "anti-lockout" in seen.reports[-1][2]
