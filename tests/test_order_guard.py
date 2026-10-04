# -*- coding: utf-8 -*-
"""
US-SOC-R11 (agent 1.9.0) — controle des ordres de remediation.

    python -m pytest tests/test_order_guard.py -v

Comme test_signing.py : une paire de cles de test est injectee dans le module
(monkeypatch), on ne depend jamais de la vraie cle de production. Seul le
vecteur de reference (TestServerCompat) utilise une graine fixe.
"""
import base64
import threading
import time
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

# Vecteur de reference produit avec canonical() de
# backend/apps/soc/response/signing.py (graine de test = octets 0..31).
REF_ORDER = {
    "id": 42, "action": "ban_ip", "target_ip": "1.2.3.4", "ttl_seconds": 3600,
    "agent_id": 7, "issued_at": "2026-10-04T18:30:00Z",
    "expires_at": "2026-10-04T18:35:00Z",
    "nonce": "0123456789abcdef0123456789abcdef",
    "sig_alg": "ed25519",
    "signature": "fNLryf95D9CDjONunVrNHq0oSSIrPJ4fhOx/IbmghgXe+mX4z/NhhVlr1KX/"
                 "mjLytUr4MEkTnyK9jq70IVf9Dw==",
}
REF_CANONICAL = (
    b'{"action":"ban_ip","agent_id":7,"expires_at":"2026-10-04T18:35:00Z","id":42,'
    b'"issued_at":"2026-10-04T18:30:00Z","nonce":"0123456789abcdef0123456789abcdef",'
    b'"target_ip":"1.2.3.4","ttl_seconds":3600}'
)
REF_PUBLIC_KEY_B64 = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
REF_NOW = datetime(2026, 10, 4, 18, 31, tzinfo=timezone.utc).timestamp()


@pytest.fixture
def key(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    monkeypatch.setattr(g, "_ORDER_PUBLIC_KEY_B64", base64.b64encode(raw).decode("ascii"))
    return priv


def make_order(priv, sign_overrides=None, after_sign=None, now=None, **fields):
    """Ordre construit comme signed_payload() cote serveur."""
    now = datetime.now(timezone.utc) if now is None else now
    order = {
        "id": 99, "action": "ban_ip", "target_ip": IP, "ttl_seconds": 3600,
        "agent_id": 7, "issued_at": now.strftime(_FMT),
        "expires_at": (now + timedelta(minutes=5)).strftime(_FMT),
        "nonce": uuid.uuid4().hex,
    }
    order.update(fields)
    order.update(sign_overrides or {})
    order["sig_alg"] = "ed25519"
    order["signature"] = base64.b64encode(priv.sign(g.canonical(order))).decode("ascii")
    order.update(after_sign or {})
    return order


@pytest.fixture
def journal(tmp_path):
    return g.ReplayJournal(str(tmp_path))


# --- Compatibilite stricte avec le serveur -------------------------------

class TestServerCompat:
    def test_canonical_identique_au_serveur(self):
        extra = dict(REF_ORDER, champ_non_signe="ignore")
        assert g.canonical(extra) == REF_CANONICAL

    def test_signature_serveur_acceptee(self, monkeypatch, journal):
        monkeypatch.setattr(g, "_ORDER_PUBLIC_KEY_B64", REF_PUBLIC_KEY_B64)
        g.guard_order(dict(REF_ORDER), journal, now=REF_NOW)

    def test_cle_de_production_chargeable(self):
        g._public_key()  # 32 octets Ed25519 valides


# --- Controles unitaires ---------------------------------------------------

class TestGuard:
    def test_ordre_valide(self, key, journal):
        g.guard_order(make_order(key), journal)

    def test_ordre_non_signe(self, key, journal):
        order = make_order(key, after_sign={"sig_alg": None, "signature": None})
        with pytest.raises(g.OrderRejected, match="non signe"):
            g.guard_order(order, journal)

    def test_ip_modifiee_apres_signature(self, key, journal):
        order = make_order(key, after_sign={"target_ip": "5.6.7.8"})
        with pytest.raises(g.OrderRejected, match="signature invalide"):
            g.guard_order(order, journal)

    def test_signature_autre_cle(self, key, journal):
        other = Ed25519PrivateKey.generate()
        order = make_order(other)
        with pytest.raises(g.OrderRejected, match="signature invalide"):
            g.guard_order(order, journal)

    def test_signature_illisible(self, key, journal):
        order = make_order(key, after_sign={"signature": "pas du base64 !"})
        with pytest.raises(g.OrderRejected, match="illisible"):
            g.guard_order(order, journal)

    def test_tolerance_horloge(self, key, journal):
        past = datetime.now(timezone.utc) - timedelta(minutes=5, seconds=30)
        g.guard_order(make_order(key, now=past), journal)  # expire de 30 s : toléré

    def test_ordre_expire(self, key, journal):
        past = datetime.now(timezone.utc) - timedelta(minutes=10)
        with pytest.raises(g.OrderRejected, match="expire"):
            g.guard_order(make_order(key, now=past), journal)

    def test_rejeu_refuse(self, key, journal):
        order = make_order(key)
        g.guard_order(order, journal)
        with pytest.raises(g.OrderRejected, match="deja recu"):
            g.guard_order(dict(order), journal)

    def test_action_hors_liste(self, key, journal):
        with pytest.raises(g.OrderRejected, match="action non autorisee"):
            g.guard_order(make_order(key, action="exec"), journal)

    @pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "224.0.0.1", "0.0.0.0",
                                    "169.254.1.1", "fe80::1", "240.0.0.1",
                                    "::ffff:127.0.0.1"])
    def test_ip_interdite(self, key, journal, ip):
        with pytest.raises(g.OrderRejected, match="refusee"):
            g.guard_order(make_order(key, target_ip=ip), journal)

    @pytest.mark.parametrize("ip", ["", "pas-une-ip", "1.2.3.4; rm -rf /"])
    def test_ip_invalide(self, key, journal, ip):
        with pytest.raises(g.OrderRejected, match="target_ip"):
            g.guard_order(make_order(key, target_ip=ip), journal)

    def test_ordre_refuse_ne_consomme_pas_le_nonce(self, key, journal):
        bad = make_order(key, action="exec", nonce="n1")
        with pytest.raises(g.OrderRejected):
            g.guard_order(bad, journal)
        g.guard_order(make_order(key, nonce="n1"), journal)


class TestJournal:
    def test_persiste_entre_redemarrages(self, key, tmp_path):
        order = make_order(key)
        g.guard_order(order, g.ReplayJournal(str(tmp_path)))
        relu = g.ReplayJournal(str(tmp_path))
        assert relu.persistent
        with pytest.raises(g.OrderRejected, match="deja recu"):
            g.guard_order(dict(order), relu)

    def test_purge_des_nonces_expires(self, tmp_path):
        j = g.ReplayJournal(str(tmp_path))
        now = time.time()
        j.consume("ancien", now - 3600, now - 3700)
        j.consume("nouveau", now + 300, now)
        assert set(j._seen) == {"nouveau"}

    def test_dossier_non_inscriptible_memoire(self, key, tmp_path):
        blocker = tmp_path / "fichier"
        blocker.write_text("x")
        j = g.ReplayJournal(str(blocker / "sous-dossier"))
        assert not j.persistent
        order = make_order(key)
        g.guard_order(order, j)
        with pytest.raises(g.OrderRejected, match="deja recu"):
            g.guard_order(dict(order), j)

    def test_fichier_corrompu(self, tmp_path):
        (tmp_path / g.ReplayJournal.FILENAME).write_text("{pas du json")
        assert g.ReplayJournal(str(tmp_path)).persistent


# --- Integration dans remediation.py -------------------------------------

@pytest.fixture
def agent(monkeypatch, tmp_path):
    calls = types.SimpleNamespace(bans=[], reports=[])
    monkeypatch.setattr(r, "_journal", g.ReplayJournal(str(tmp_path)))
    monkeypatch.setattr(r, "_active_ssh_source_ips", lambda: set())
    monkeypatch.setattr(r, "_detect_firewall", lambda: "iptables")
    monkeypatch.setattr(r, "_apply_ban", lambda ip, fw: (calls.bans.append(ip), (True, "ok"))[1])
    monkeypatch.setattr(r, "_apply_unban", lambda ip, fw: (True, "ok"))
    monkeypatch.setattr(r, "_rule_present", lambda ip, fw: True)
    monkeypatch.setattr(r, "_report",
                        lambda api, tok, oid, ok, detail, rule_present=None:
                        calls.reports.append((oid, ok, detail)))
    return calls


class TestProcessOrder:
    def test_ordre_signe_execute(self, key, agent):
        r._process_order(make_order(key), "https://x", "t")
        assert agent.bans == [IP]
        assert agent.reports[-1][1] is True

    def test_rejeu_non_execute(self, key, agent):
        order = make_order(key)
        r._process_order(order, "https://x", "t")
        r._process_order(dict(order), "https://x", "t")
        assert agent.bans == [IP]
        assert agent.reports[-1][1] is False and "deja recu" in agent.reports[-1][2]

    def test_ordre_non_signe_non_execute(self, agent):
        r._process_order({"id": 5, "action": "ban_ip", "target_ip": IP},
                         "https://x", "t")
        assert agent.bans == []
        assert agent.reports == [(5, False, agent.reports[0][2])]
        assert agent.reports[0][2].startswith("R11 refus agent")

    def test_ip_falsifiee_non_executee(self, key, agent):
        r._process_order(make_order(key, after_sign={"target_ip": "8.8.8.8"}),
                         "https://x", "t")
        assert agent.bans == []


class TestHttps:
    def _run(self, monkeypatch, url):
        polls = []
        stop = threading.Event()

        def fake_poll(api_url, token):
            polls.append(api_url)
            stop.set()

        monkeypatch.setattr(r, "_poll_once", fake_poll)
        cfg = types.SimpleNamespace(api_url=url, token="t", remediation_poll_interval=0.01)
        t = threading.Thread(target=r.remediation_loop, args=(cfg, stop), daemon=True)
        t.start()
        t.join(0.5)
        stop.set()
        t.join(1)
        return polls

    def test_http_distant_refuse(self, monkeypatch):
        assert self._run(monkeypatch, "http://app.cybersafe-ai.com/api") == []

    def test_https_accepte(self, monkeypatch):
        assert self._run(monkeypatch, "https://app.cybersafe-ai.com/api") != []

    def test_http_localhost_accepte(self, monkeypatch):
        assert self._run(monkeypatch, "http://localhost:8000/api") != []
