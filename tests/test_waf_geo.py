# -*- coding: utf-8 -*-
"""
US-SOC-R12 porte 4a-2 (agent 2.3.0) — regles WAF temporaires et blocage par pays (nginx).

    python -m pytest tests/test_waf_geo.py -v
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
from cybersafe_agent import proxy_rules as rules
from cybersafe_agent import remediation as r

_FMT = "%Y-%m-%dT%H:%M:%SZ"
REF_KEY = "waf:cb8c1f432d9712ac"  # meme vecteur que le serveur (tests_r12_waf_geo)
GOOD = [("block_path", "/wp-login.php"), ("block_path", "/xmlrpc.php"), ("block_user_agent", "sqlmap/1.7"),
        ("block_user_agent", "Nikto"), ("block_method", "TRACE"), ("block_method", "PROPFIND")]
BAD = [("block_path", "/"), ("block_path", "//"), ("block_path", "wp-login"), ("block_path", '/a";'),
       ("block_path", "/a$b"), ("block_path", "/a{1}"), ("block_path", "/%2e"),
       ("block_user_agent", "Mozilla"), ("block_user_agent", "chrome"), ("block_user_agent", "Safari"),
       ("block_user_agent", "Googlebot"), ("block_user_agent", "abc"), ("block_user_agent", "x\\y"),
       ("block_method", "GET"), ("block_method", "POST"), ("block_method", "OPTIONS"),
       ("block_method", "PATCH"), ("block_method", "trace"), ("raw_nginx", "deny all")]


class TestRegles:
    def test_cle_de_reference(self):
        assert rules.waf_key("block_path", "/wp-login.php") == REF_KEY

    @pytest.mark.parametrize("rule,value", GOOD)
    def test_regles_sures(self, rule, value):
        assert rules.waf_error(rule, value) is None

    @pytest.mark.parametrize("rule,value", BAD)
    def test_regles_dangereuses(self, rule, value):
        assert rules.waf_error(rule, value) is not None

    def test_motifs_nginx_sans_antislash(self):
        assert rules.nginx_pattern("block_path", "/wp-login.php") == "~*^/wp-login[.]php"
        assert rules.nginx_pattern("block_user_agent", "sqlmap/1.7 (x+y)") == "~*sqlmap/1[.]7 [(]x[+]y[)]"
        assert rules.nginx_pattern("block_method", "TRACE") == "TRACE"
        for rule, value in GOOD:
            assert "\\" not in rules.nginx_pattern(rule, value) and '"' not in rules.nginx_pattern(rule, value)


# --- garde des ordres --------------------------------------------------------------
@pytest.fixture
def key(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(g, "_ORDER_PUBLIC_KEY_B64", base64.b64encode(raw).decode("ascii"))
    return priv


def make(priv, **fields):
    now = datetime.now(timezone.utc)
    order = {"id": 9, "action": "temporary_waf_rule", "target_ip": REF_KEY, "ttl_seconds": 3600,
             "agent_id": 7, "issued_at": now.strftime(_FMT),
             "expires_at": (now + timedelta(minutes=5)).strftime(_FMT), "nonce": uuid.uuid4().hex,
             "params": {"rule": "block_path", "value": "/wp-login.php"}}
    order.update(fields)
    order["sig_alg"] = "ed25519-v2"
    order["signature"] = base64.b64encode(priv.sign(g.canonical(order, g.SIGNED_FIELDS_V2))).decode("ascii")
    return order


class TestGarde:
    def test_ordres_valides(self, key, tmp_path):
        journal = g.ReplayJournal(str(tmp_path))
        g.guard_order(make(key), journal)
        g.guard_order(make(key, action="remove_waf_rule", params={}), journal)
        g.guard_order(make(key, action="geo_block_country", target_ip="CN",
                           params={"justification": "Campagne de scans depuis ce pays"}), journal)
        g.guard_order(make(key, action="geo_unblock_country", target_ip="CN", params={}), journal)

    @pytest.mark.parametrize("fields,motif", [
        ({"params": {"rule": "block_method", "value": "GET"}, "target_ip": rules.waf_key("block_method", "GET")},
         "refusee"),
        ({"target_ip": rules.waf_key("block_path", "/autre")}, "incoherente"),
        ({"target_ip": "1.2.3.4"}, "identifiant"),
        ({"action": "geo_block_country", "target_ip": "cn", "params": {"justification": "x" * 20}}, "pays"),
        ({"action": "geo_block_country", "target_ip": "CN", "params": {}}, "justification"),
    ])
    def test_ordres_refuses(self, key, tmp_path, fields, motif):
        with pytest.raises(g.OrderRejected, match=motif):
            g.guard_order(make(key, **fields), g.ReplayJournal(str(tmp_path)))


# --- programme root : rendu et application -----------------------------------------
class FakeNginx:
    def __init__(self, conf, enforce):
        self.conf, self.enforce = conf, enforce
        self.calls = []
        self.test_err = ""
        self.includes = 2
        self.servers = 2
        self.reload_rc = 0
        self.require_enforce = False  # un site inclut deja enforce.conf

    def __call__(self, cmd, timeout=60):
        self.calls.append(cmd[1:])
        if cmd[1:] == ["-t"]:
            if self.require_enforce and not os.path.exists(self.enforce):
                return 1, "", "nginx: [emerg] open() %s failed" % self.enforce
            return (1 if self.test_err else 0), "", self.test_err
        if cmd[1:] == ["-T"]:
            out = "# configuration file %s:\n" % self.conf
            if self.includes:
                out += "# configuration file %s:\n" % self.enforce
            out += "#     include %s;\n" % self.enforce  # commentaire d'enforce.conf : jamais compte
            out += "".join("server {\n    include %s;\n}\n" % self.enforce for _ in range(self.includes))
            out += "server {\n}\n" * (self.servers - self.includes)
            return 0, out, ""
        if cmd[1:] == ["-s", "reload"]:
            return self.reload_rc, "", "reload KO"
        return -1, "", "inattendu"


@pytest.fixture
def env(tmp_path, monkeypatch):
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()
    enforce_dir = tmp_path / "cybersafe"
    enforce_dir.mkdir()
    state = tmp_path / "proxy"
    state.mkdir()
    geo_db = tmp_path / "GeoLite2-Country.mmdb"
    geo_db.write_bytes(b"x")
    monkeypatch.setattr(pa, "CONF_DIR", str(conf_dir))
    monkeypatch.setattr(pa, "ENFORCE_DIR", str(enforce_dir))
    monkeypatch.setattr(pa, "GEOIP_DB", str(geo_db))
    monkeypatch.setattr(pa, "STATUS_DIR", str(tmp_path / "status"))
    monkeypatch.setattr(pa, "DESIRED", str(state / "desired.json"))
    monkeypatch.setattr(pa, "_nginx_bin", lambda: "/usr/sbin/nginx")
    fake = FakeNginx(str(conf_dir / pa.CONF_NAME), str(enforce_dir / pa.ENFORCE_NAME))
    monkeypatch.setattr(pa, "_run", fake)

    def desire(gen, deny=(), waf=None, geo=None):
        data = {"generation": gen, "deny": list(deny)}
        if waf is not None:
            data["waf"] = {rules.waf_key(rl, v): {"rule": rl, "value": v} for rl, v in waf}
        if geo is not None:
            data["geo"] = list(geo)
        (state / "desired.json").write_text(json.dumps(data))

    return types.SimpleNamespace(conf=conf_dir / pa.CONF_NAME, enforce=enforce_dir / pa.ENFORCE_NAME,
                                 geo_db=geo_db, fake=fake, desire=desire)


class TestApplication:
    def test_variables_toujours_definies(self, env):
        env.desire(1, ["45.148.10.9"])
        st = pa.apply_once()
        assert st["ok"], st
        text = env.conf.read_text()
        for var in ("$cybersafe_waf_path", "$cybersafe_waf_ua", "$cybersafe_waf_method", "$cybersafe_geo_block"):
            assert var in text
        assert "geoip2" not in text  # aucun pays : module GeoIP2 non requis
        assert env.enforce.read_text() == pa.ENFORCE_TEXT

    def test_regles_waf_et_pays(self, env):
        env.desire(1, waf=GOOD, geo=["CN"])
        st = pa.apply_once()
        assert st["ok"], st
        text = env.conf.read_text()
        assert '"~*^/wp-login[.]php" 1;' in text
        assert '"~*sqlmap/1[.]7" 1;' in text
        assert '"TRACE" 1;' in text
        assert "geoip2 %s" % env.geo_db in text and '"CN" 1;' in text
        assert "6 regle(s) WAF" in st["detail"] and "CN" in st["detail"]
        assert "2 bloc(s) server sur 2" in st["detail"]

    def test_enforce_non_inclus_refuse_et_restaure(self, env):
        env.desire(1, ["45.148.10.9"])
        pa.apply_once()
        before = env.conf.read_text()
        env.fake.includes = 0
        env.fake.calls.clear()
        env.desire(2, ["45.148.10.9"], waf=[("block_method", "TRACE")])
        st = pa.apply_once()
        assert not st["ok"] and "include" in st["detail"]
        assert env.conf.read_text() == before
        assert ["-s", "reload"] not in env.fake.calls

    def test_couverture_partielle_signalee(self, env):
        env.fake.includes, env.fake.servers = 1, 3
        env.desire(1, waf=[("block_method", "TRACE")])
        st = pa.apply_once()
        assert st["ok"] and "1 bloc(s) server sur 3" in st["detail"] and "ATTENTION" in st["detail"]

    def test_base_geoip_absente(self, env):
        env.geo_db.unlink()
        env.desire(1, geo=["CN"])
        st = pa.apply_once()
        assert not st["ok"] and "GeoIP" in st["detail"]
        assert env.fake.calls == []

    def test_module_geoip2_absent(self, env):
        env.fake.test_err = 'nginx: [emerg] unknown directive "geoip2" in /etc/nginx/conf.d/x.conf:9'
        env.desire(1, geo=["CN"])
        st = pa.apply_once()
        assert not st["ok"] and "libnginx-mod-http-geoip2" in st["detail"]
        assert not env.conf.exists()

    @pytest.mark.parametrize("waf", [
        {"waf:0000000000000000": {"rule": "block_path", "value": "/wp-login.php"}},
        {REF_KEY: {"rule": "block_method", "value": "GET"}},
        {REF_KEY: "deny all"},
    ])
    def test_regles_corrompues_refusees(self, env, waf):
        (env.conf.parent.parent / "proxy" / "desired.json").write_text(
            json.dumps({"generation": 1, "deny": [], "waf": waf}))
        st = pa.apply_once()
        assert not st["ok"] and "refuse" in st["detail"]
        assert env.fake.calls == []

    def test_pays_invalide_refuse(self, env):
        env.desire(1, geo=["cn"])
        assert not pa.apply_once()["ok"]
        assert env.fake.calls == []

    def test_rechargement_rate_garde_une_configuration_valide(self, env):
        env.fake.require_enforce = True
        env.fake.reload_rc = 1
        env.desire(1, waf=[("block_method", "TRACE")])
        st = pa.apply_once()
        assert not st["ok"] and "rechargement" in st["detail"]
        # restaurer « aucun fichier » casserait nginx (include deja present) : on garde la version testee
        assert env.enforce.exists() and env.conf.exists()

    def test_inchange_pas_de_rechargement(self, env):
        env.desire(1, waf=[("block_method", "TRACE")])
        pa.apply_once()
        env.fake.calls.clear()
        env.desire(2, waf=[("block_method", "TRACE")])
        st = pa.apply_once()
        assert st["ok"] and "inchange" in st["detail"]
        assert ["-s", "reload"] not in env.fake.calls


# --- service de remediation --------------------------------------------------------
@pytest.fixture
def rem(tmp_path, monkeypatch):
    monkeypatch.setattr(r, "_PROXY_DIR", str(tmp_path / "proxy"))
    monkeypatch.setattr(r, "_PROXY_STATUS", str(tmp_path / "status.json"))
    desired = tmp_path / "proxy" / "desired.json"
    state = {"ok": True}

    def fake_wait(generation, timeout=None):
        return {"generation": generation, "ok": state["ok"], "detail": "ok" if state["ok"] else "refus"}

    monkeypatch.setattr(r, "_proxy_wait", fake_wait)
    return types.SimpleNamespace(read=lambda: json.loads(desired.read_text()), state=state)


class TestRemediation:
    def test_waf_ajout_et_retrait(self, rem):
        ok, _ = r._waf_change(REF_KEY, "block_path", "/wp-login.php", True)
        assert ok
        assert rem.read()["waf"] == {REF_KEY: {"rule": "block_path", "value": "/wp-login.php"}}
        ok, _ = r._waf_change(REF_KEY, None, None, False)
        assert ok and "waf" not in rem.read()

    def test_waf_dangereuse_refusee_sans_ecriture(self, rem):
        ok, detail = r._waf_change(rules.waf_key("block_method", "GET"), "block_method", "GET", True)
        assert not ok and "refusee" in detail

    def test_pays_et_adresses_conserves(self, rem):
        r._proxy_change("45.148.10.9", True)
        r._geo_change("CN", True)
        r._waf_change(REF_KEY, "block_path", "/wp-login.php", True)
        data = rem.read()
        assert data["deny"] == ["45.148.10.9"] and data["geo"] == ["CN"] and REF_KEY in data["waf"]
        r._geo_change("CN", False)
        data = rem.read()
        assert "geo" not in data and data["deny"] == ["45.148.10.9"] and REF_KEY in data["waf"]

    def test_echec_remet_l_etat_precedent(self, rem):
        r._geo_change("CN", True)
        rem.state["ok"] = False
        ok, _ = r._waf_change(REF_KEY, "block_path", "/wp-login.php", True)
        assert not ok
        data = rem.read()
        assert "waf" not in data and data["geo"] == ["CN"]

    def test_dispatch(self, rem, monkeypatch):
        reports = []
        monkeypatch.setattr(r, "_guard_order", lambda order: None)
        monkeypatch.setattr(r, "_report", lambda api, tok, oid, ok, detail, rule_present=None:
                            reports.append((ok, detail)))
        r._process_order({"id": 1, "action": "temporary_waf_rule", "target_ip": REF_KEY,
                          "params": {"rule": "block_path", "value": "/wp-login.php"}}, "https://x", "t")
        r._process_order({"id": 2, "action": "geo_block_country", "target_ip": "CN"}, "https://x", "t")
        assert [ok for ok, _ in reports] == [True, True]
        r._process_order({"id": 3, "action": "remove_waf_rule", "target_ip": REF_KEY}, "https://x", "t")
        r._process_order({"id": 4, "action": "geo_unblock_country", "target_ip": "CN"}, "https://x", "t")
        assert [ok for ok, _ in reports] == [True] * 4
        assert rem.read() == {"generation": 4, "deny": []}
