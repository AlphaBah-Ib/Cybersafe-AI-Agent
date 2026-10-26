# -*- coding: utf-8 -*-
"""
US-SOC-R12 porte 4a (agent 2.2.0) — blocage au reverse proxy nginx.

    python -m pytest tests/test_reverse_proxy.py -v
"""
import base64
import json
import os
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybersafe_agent import order_guard as g
from cybersafe_agent import proxy_apply as pa
from cybersafe_agent import remediation as r

_FMT = "%Y-%m-%dT%H:%M:%SZ"


# --- garde de l'agent ---------------------------------------------------------
@pytest.fixture
def key(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(g, "_ORDER_PUBLIC_KEY_B64", base64.b64encode(raw).decode("ascii"))
    return priv


def make(priv, **fields):
    now = datetime.now(timezone.utc)
    order = {"id": 9, "action": "block_at_reverse_proxy", "target_ip": "45.148.10.9", "ttl_seconds": 3600,
             "agent_id": 7, "issued_at": now.strftime(_FMT),
             "expires_at": (now + timedelta(minutes=5)).strftime(_FMT), "nonce": uuid.uuid4().hex}
    order.update(fields)
    order["sig_alg"] = "ed25519-v2"
    order["signature"] = base64.b64encode(priv.sign(g.canonical(order, g.SIGNED_FIELDS_V2))).decode("ascii")
    return order


class TestGarde:
    def test_actions_acceptees(self, key, tmp_path):
        journal = g.ReplayJournal(str(tmp_path))
        g.guard_order(make(key), journal)
        g.guard_order(make(key, action="unblock_at_reverse_proxy"), journal)

    def test_plage_refusee(self, key, tmp_path):
        with pytest.raises(g.OrderRejected):
            g.guard_order(make(key, target_ip="45.148.10.0/24"), g.ReplayJournal(str(tmp_path)))


# --- programme root : validation et rendu --------------------------------------
class TestValidation:
    def test_rendu(self):
        gen, ips = pa.validate({"generation": 3, "deny": ["45.148.10.9", "2001:db8::5", "1.2.3.4", "1.2.3.4"]})
        assert gen == 3
        text = pa.render(ips)
        assert text.startswith("# Genere par Cybersafe-AI")
        assert text.splitlines()[2:] == ["deny 1.2.3.4;", "deny 45.148.10.9;", "deny 2001:db8::5;"]

    @pytest.mark.parametrize("obj,motif", [
        ([], "objet"),
        ({"generation": -1, "deny": []}, "generation"),
        ({"generation": True, "deny": []}, "generation"),
        ({"generation": 1, "deny": "1.2.3.4"}, "deny"),
        ({"generation": 1, "deny": ["1.2.3.0/24"]}, "adresse IP seule"),
        ({"generation": 1, "deny": ["1.2.3.4; include /etc/shadow"]}, "invalide"),
        ({"generation": 1, "deny": ["127.0.0.1"]}, "interdite"),
        ({"generation": 1, "deny": ["::1"]}, "interdite"),
        ({"generation": 1, "deny": ["0.0.0.0"]}, "interdite"),
        ({"generation": 1, "deny": [7]}, "adresse IP seule"),
    ])
    def test_refus(self, obj, motif):
        with pytest.raises(pa.Invalid, match=motif):
            pa.validate(obj)

    def test_trop_d_adresses(self, monkeypatch):
        monkeypatch.setattr(pa, "MAX_ENTRIES", 2)
        with pytest.raises(pa.Invalid, match="trop"):
            pa.validate({"generation": 1, "deny": ["1.1.1.1", "1.1.1.2", "1.1.1.3"]})

    def test_lien_symbolique_refuse(self, tmp_path):
        secret = tmp_path / "secret"
        secret.write_text('{"generation": 1, "deny": []}')
        link = tmp_path / "desired.json"
        link.symlink_to(secret)
        with pytest.raises(pa.Invalid, match="illisible"):
            pa.read_desired(str(link))


# --- programme root : application avec un faux nginx -------------------------------
class FakeNginx:
    def __init__(self, conf_path):
        self.conf_path = conf_path
        self.calls = []
        self.test_rc = 0
        self.included = True
        self.reload_rc = 0

    def __call__(self, cmd, timeout=60):
        self.calls.append(cmd[1:])
        if cmd[1:] == ["-t"]:
            return self.test_rc, "", "nginx: [emerg] boom in %s:2" % self.conf_path
        if cmd[1:] == ["-T"]:
            out = "# configuration file %s:\n" % self.conf_path if self.included else "# rien\n"
            return 0, out, ""
        if cmd[1:] == ["-s", "reload"]:
            return self.reload_rc, "", "reload KO"
        return -1, "", "inattendu"


@pytest.fixture
def env(tmp_path, monkeypatch):
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()
    state = tmp_path / "proxy"
    state.mkdir()
    monkeypatch.setattr(pa, "CONF_DIR", str(conf_dir))
    monkeypatch.setattr(pa, "STATUS_DIR", str(tmp_path / "status"))
    monkeypatch.setattr(pa, "DESIRED", str(state / "desired.json"))
    monkeypatch.setattr(pa, "ENFORCE_DIR", str(tmp_path / "cybersafe"))  # [R12-P4B] absent
    monkeypatch.setattr(pa, "_nginx_bin", lambda: "/usr/sbin/nginx")
    fake = FakeNginx(str(conf_dir / pa.CONF_NAME))
    monkeypatch.setattr(pa, "_run", fake)

    def desire(gen, deny):
        (state / "desired.json").write_text(json.dumps({"generation": gen, "deny": deny}))

    return types.SimpleNamespace(conf=conf_dir / pa.CONF_NAME, fake=fake, desire=desire,
                                 status=lambda: json.loads((tmp_path / "status" / "status.json").read_text()))


class TestApplication:
    def test_succes(self, env):
        env.desire(1, ["45.148.10.9"])
        st = pa.apply_once()
        assert st["ok"] and st["generation"] == 1, st
        assert "deny 45.148.10.9;" in env.conf.read_text()
        assert ["-s", "reload"] in env.fake.calls
        assert env.status()["ok"] is True

    def test_inchange_pas_de_rechargement(self, env):
        env.desire(1, ["45.148.10.9"])
        pa.apply_once()
        env.fake.calls.clear()
        env.desire(2, ["45.148.10.9"])
        st = pa.apply_once()
        assert st["ok"] and "inchange" in st["detail"]
        assert ["-s", "reload"] not in env.fake.calls

    def test_nginx_t_en_echec_restaure_et_ne_recharge_pas(self, env):
        env.desire(1, ["45.148.10.9"])
        pa.apply_once()
        before = env.conf.read_text()
        env.fake.calls.clear()
        env.fake.test_rc = 1
        env.desire(2, ["45.148.10.9", "45.148.10.10"])
        st = pa.apply_once()
        assert not st["ok"] and "refusee" in st["detail"] and "restauree" in st["detail"]
        assert env.conf.read_text() == before
        assert ["-s", "reload"] not in env.fake.calls

    def test_premier_fichier_retire_si_refuse(self, env):
        env.fake.test_rc = 1
        env.desire(1, ["45.148.10.9"])
        assert not pa.apply_once()["ok"]
        assert not env.conf.exists()

    def test_fichier_non_inclus(self, env):
        env.fake.included = False
        env.desire(1, ["45.148.10.9"])
        st = pa.apply_once()
        assert not st["ok"] and "include" in st["detail"]
        assert not env.conf.exists()

    def test_rechargement_en_echec(self, env):
        env.fake.reload_rc = 1
        env.desire(1, ["45.148.10.9"])
        st = pa.apply_once()
        assert not st["ok"] and "rechargement" in st["detail"]
        assert not env.conf.exists()

    def test_nginx_absent(self, env, monkeypatch):
        monkeypatch.setattr(pa, "_nginx_bin", lambda: None)
        env.desire(1, ["45.148.10.9"])
        st = pa.apply_once()
        assert not st["ok"] and "nginx absent" in st["detail"]
        assert not env.conf.exists()

    def test_etat_voulu_refuse_ne_touche_pas_nginx(self, env):
        env.desire(4, ["127.0.0.1"])
        st = pa.apply_once()
        assert not st["ok"] and st["generation"] == 4
        assert env.fake.calls == []
        assert not env.conf.exists()

    def test_pas_de_fichier_temporaire_restant(self, env):
        env.desire(1, ["45.148.10.9"])
        pa.apply_once()
        assert sorted(os.listdir(env.conf.parent)) == [pa.CONF_NAME]


# --- service de remediation (non privilegie) ----------------------------------------
@pytest.fixture
def rem(tmp_path, monkeypatch):
    monkeypatch.setattr(r, "_PROXY_DIR", str(tmp_path / "proxy"))
    status = tmp_path / "status.json"
    monkeypatch.setattr(r, "_PROXY_STATUS", str(status))
    monkeypatch.setattr(r, "_PROXY_WAIT_SECONDS", 0.0)
    desired = tmp_path / "proxy" / "desired.json"

    def answer(ok, detail="1 adresse(s) bloquee(s) au reverse proxy"):
        def fake_wait(generation, timeout=None):
            st = {"generation": generation, "ok": ok, "detail": detail}
            status.write_text(json.dumps(st))
            return st
        monkeypatch.setattr(r, "_proxy_wait", fake_wait)

    return types.SimpleNamespace(desired=desired, answer=answer,
                                 read=lambda: json.loads(desired.read_text()))


class TestRemediation:
    def test_blocage_puis_levee(self, rem):
        rem.answer(True)
        ok, detail = r._proxy_change("45.148.10.9", True)
        assert ok and detail.startswith("nginx:")
        assert rem.read() == {"generation": 1, "deny": ["45.148.10.9"]}
        ok, _ = r._proxy_change("45.148.10.9", False)
        assert ok and rem.read() == {"generation": 2, "deny": []}

    def test_echec_remet_l_etat_precedent(self, rem):
        rem.answer(True)
        r._proxy_change("45.148.10.9", True)
        rem.answer(False, "configuration nginx refusee (boom)")
        ok, detail = r._proxy_change("45.148.10.10", True)
        assert not ok and "refusee" in detail
        assert rem.read() == {"generation": 3, "deny": ["45.148.10.9"]}

    def test_silence_remet_l_etat_precedent(self, rem):
        ok, detail = r._proxy_change("45.148.10.9", True)  # personne ne repond (delai 0)
        assert not ok and "aucune reponse" in detail
        assert rem.read() == {"generation": 2, "deny": []}

    def test_etat_illisible_rien_n_est_ecrase(self, rem):
        rem.desired.parent.mkdir(parents=True)
        rem.desired.write_text("{pas du json")
        ok, detail = r._proxy_change("45.148.10.9", True)
        assert not ok and "illisible" in detail
        assert rem.desired.read_text() == "{pas du json"

    def test_dispatch(self, rem, monkeypatch):
        rem.answer(True)
        reports = []
        monkeypatch.setattr(r, "_guard_order", lambda order: None)
        monkeypatch.setattr(r, "_report", lambda api, tok, oid, ok, detail, rule_present=None:
                            reports.append((ok, detail)))
        r._process_order({"id": 1, "action": "block_at_reverse_proxy", "target_ip": "45.148.10.9"},
                         "https://x", "t")
        assert reports[-1][0] is True
        r._process_order({"id": 2, "action": "unblock_at_reverse_proxy", "target_ip": "45.148.10.9"},
                         "https://x", "t")
        assert reports[-1][0] is True and rem.read()["deny"] == []
