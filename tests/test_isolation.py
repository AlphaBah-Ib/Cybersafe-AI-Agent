# -*- coding: utf-8 -*-
"""
US-SOC-R14 (agent 2.4.0) — isolation controlee d'un serveur.

    python -m pytest tests/test_isolation.py -v

Aucune commande reelle : iptables / ip6tables sont simules (FakeNet), les dossiers
d'etat sont rediriges vers tmp_path.
"""
import base64
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybersafe_agent import isolation as iso
from cybersafe_agent import isolation_guard
from cybersafe_agent import order_guard as g
from cybersafe_agent import remediation as r

_FMT = "%Y-%m-%dT%H:%M:%SZ"
PRESERVE = ["198.51.100.10/32", "212.47.228.188/32", "2001:db8::/64"]
NOW = 1_800_000_000.0


# --- Pare-feu simule ------------------------------------------------------------------

class FakeNet:
    """iptables / ip6tables / *-restore : sauts et chaines, par famille."""

    def __init__(self):
        self.jumps = {"iptables": set(), "ip6tables": set()}
        self.chains = {"iptables": {}, "ip6tables": {}}
        self.calls = []
        self.fail_restore = set()

    def __call__(self, cmd, stdin=None):
        self.calls.append((cmd, stdin))
        tool = cmd[0]
        if tool.endswith("-restore"):
            fam = tool[:-len("-restore")]
            if fam in self.fail_restore:
                return 1, "", "iptables-restore: line 3 failed"
            return self._restore(fam, stdin)
        op = cmd[1]
        if op == "-C":
            return (0 if (cmd[2], cmd[4]) in self.jumps[tool] else 1), "", ""
        if op == "-D":
            if (cmd[2], cmd[4]) not in self.jumps[tool]:
                return 1, "", "absent"
            self.jumps[tool].discard((cmd[2], cmd[4]))
            return 0, "", ""
        if op == "-S":
            return (0 if cmd[2] in self.chains[tool] else 1), "", ""
        if op == "-F":
            self.chains[tool][cmd[2]] = []
            return 0, "", ""
        if op == "-X":
            if any(c == cmd[2] for _, c in self.jumps[tool]):
                return 1, "", "chaine referencee"
            self.chains[tool].pop(cmd[2], None)
            return 0, "", ""
        return 2, "", "commande inattendue"

    def _restore(self, fam, text):
        jumps, chains = set(self.jumps[fam]), dict(self.chains[fam])
        for line in text.splitlines():
            if line.startswith(":"):
                chains[line[1:].split()[0]] = []
            elif line.startswith("-A "):
                chains[line.split()[1]].append(line)
            elif line.startswith("-D "):
                key = (line.split()[1], line.split()[3])
                if key not in jumps:
                    return 1, "", "-D sur un saut absent"
                jumps.discard(key)
            elif line.startswith("-I "):
                parts = line.split()
                jumps.add((parts[1], parts[4]))
        self.jumps[fam], self.chains[fam] = jumps, chains
        return 0, "", ""

    def isolated_fully(self):
        return all(len(self.jumps[f]) == 3 for f in self.jumps)


@pytest.fixture
def net(tmp_path, monkeypatch):
    fake = FakeNet()
    monkeypatch.setattr(iso, "_run", fake)
    monkeypatch.setattr(iso.shutil, "which", lambda name: "/usr/sbin/" + name)
    monkeypatch.setattr(iso, "STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(iso, "GUARD_DIR", str(tmp_path / "guard"))
    monkeypatch.setattr(iso, "is_linux", lambda: True)
    monkeypatch.setattr(iso, "resolve_api", lambda url: (["212.47.228.188", "2001:bc8::1"], 443))
    monkeypatch.setattr(iso, "resolvers", lambda: ["10.0.0.53"])
    iso._write_json_atomic(iso.guard_stamp_path(), {"at": NOW - 10})
    return fake


def order(ttl=4 * 3600, preserve=None, oid=7):
    return {"id": oid, "action": "isolate_host", "target_ip": "host:12", "agent_id": 12,
            "ttl_seconds": ttl,
            "params": {"justification": "Serveur compromis (test)",
                       "preserve": PRESERVE if preserve is None else preserve}}


# --- Garde des ordres -------------------------------------------------------------------

@pytest.fixture
def key(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(g, "_ORDER_PUBLIC_KEY_B64", base64.b64encode(raw).decode("ascii"))
    return priv


def signed(priv, v2=True, **fields):
    now = datetime.now(timezone.utc)
    o = {"id": 5, "action": "isolate_host", "target_ip": "host:12", "ttl_seconds": 14400,
         "agent_id": 12, "issued_at": now.strftime(_FMT),
         "expires_at": (now + timedelta(minutes=5)).strftime(_FMT), "nonce": uuid.uuid4().hex,
         "params": {"justification": "Serveur compromis (test)", "preserve": PRESERVE}}
    o.update(fields)
    o["sig_alg"] = g.SIG_V2 if v2 else g.SIG_V1
    o["signature"] = base64.b64encode(
        priv.sign(g.canonical(o, g.SIGNED_FIELDS_V2 if v2 else g.SIGNED_FIELDS))).decode("ascii")
    return o


class TestGarde:
    def test_isolation_acceptee(self, key, tmp_path):
        g.guard_order(signed(key), g.ReplayJournal(str(tmp_path)))

    @pytest.mark.parametrize("target", ["host:13", "host:", "12", "1.2.3.4", "host:12 "])
    def test_jamais_un_autre_serveur(self, key, tmp_path, target):
        with pytest.raises(g.OrderRejected):
            g.guard_order(signed(key, target_ip=target), g.ReplayJournal(str(tmp_path)))

    @pytest.mark.parametrize("preserve", [["0.0.0.0/0"], ["::/0"], ["pas-un-reseau"], [12],
                                          "198.51.100.10/32", ["10.0.0.%d/32" % i for i in range(65)]])
    def test_destinations_preservees_controlees(self, key, tmp_path, preserve):
        o = signed(key, params={"justification": "Serveur compromis (test)", "preserve": preserve})
        with pytest.raises(g.OrderRejected):
            g.guard_order(o, g.ReplayJournal(str(tmp_path)))

    def test_justification_obligatoire_et_parametres_signes(self, key, tmp_path):
        with pytest.raises(g.OrderRejected):
            g.guard_order(signed(key, params={"preserve": PRESERVE}), g.ReplayJournal(str(tmp_path)))
        with pytest.raises(g.OrderRejected):
            g.guard_order(signed(key, v2=False), g.ReplayJournal(str(tmp_path)))

    def test_restauration_jamais_bloquee_par_ses_parametres(self, key, tmp_path):
        o = signed(key, action="restore_network", params={"justification": "copie", "autre": 1})
        g.guard_order(o, g.ReplayJournal(str(tmp_path)))
        with pytest.raises(g.OrderRejected):  # mais toujours limitee a son propre serveur
            g.guard_order(signed(key, action="restore_network", target_ip="host:99", params={}),
                          g.ReplayJournal(str(tmp_path)))


# --- Jeu de regles ------------------------------------------------------------------------

class TestRegles:
    def test_ipv4(self):
        txt = iso.build_ruleset(4, PRESERVE, ["212.47.228.188", "2001:bc8::1"], 443, ["10.0.0.53"])
        lines = txt.splitlines()
        assert lines[0] == "*filter" and lines[-1] == "COMMIT"
        assert "-A CYBERSAFE_ISO_IN -i lo -j ACCEPT" in lines
        assert "-A CYBERSAFE_ISO_IN -s 198.51.100.10/32 -j ACCEPT" in lines
        assert "-A CYBERSAFE_ISO_OUT -d 212.47.228.188 -p tcp --dport 443 -j ACCEPT" in lines
        assert "-A CYBERSAFE_ISO_OUT -d 10.0.0.53 -p udp --dport 53 -j ACCEPT" in lines
        assert not any("2001:" in l for l in lines)            # chaque famille ses adresses
        # le rejet est la DERNIERE regle de chaque chaine, avant l'insertion des sauts
        assert lines.index("-A CYBERSAFE_ISO_IN -j DROP") > lines.index("-A CYBERSAFE_ISO_IN -i lo -j ACCEPT")
        assert lines[-4:-1] == ["-I INPUT 1 -j CYBERSAFE_ISO_IN", "-I OUTPUT 1 -j CYBERSAFE_ISO_OUT",
                                "-I FORWARD 1 -j CYBERSAFE_ISO_FWD"]
        assert "ESTABLISHED,RELATED" not in txt                 # pas de laissez-passer general
        assert "0.0.0.0/0" not in txt

    def test_ipv6_voisinage(self):
        txt = iso.build_ruleset(6, PRESERVE, ["2001:bc8::1"], 443, [])
        assert "-A CYBERSAFE_ISO_IN -p ipv6-icmp --icmpv6-type 135 -j ACCEPT" in txt
        assert "-A CYBERSAFE_ISO_IN -s 2001:db8::/64 -j ACCEPT" in txt
        assert "198.51.100.10" not in txt

    def test_reapplication_sans_doublon(self):
        txt = iso.build_ruleset(4, [], ["1.2.3.4"], 443, [], {("INPUT", "CYBERSAFE_ISO_IN")})
        assert "-D INPUT -j CYBERSAFE_ISO_IN\n-I INPUT 1 -j CYBERSAFE_ISO_IN" in txt

    def test_destinations_preservees(self):
        assert iso.parse_preserve(PRESERVE) == (["198.51.100.10/32", "212.47.228.188/32"], ["2001:db8::/64"])
        for bad in (["0.0.0.0/0"], "x", ["x"]):
            with pytest.raises(ValueError):
                iso.parse_preserve(bad)

    def test_resolveurs(self, tmp_path):
        a, b = tmp_path / "a", tmp_path / "b"
        a.write_text("nameserver 127.0.0.53\n")
        b.write_text("# x\nnameserver 10.0.0.53\nnameserver fe80::1%eth0\n")
        assert iso.resolvers((str(tmp_path / "absent"), str(a), str(b))) == ["10.0.0.53", "fe80::1"]


# --- Isolation et restauration ----------------------------------------------------------------

class TestIsolation:
    def test_succes(self, net):
        ok, detail, rule = iso.isolate(order(), "https://api.cybersafe-ai.com/api", 60, ["203.0.113.9"], now=NOW)
        assert (ok, rule) == (True, True), detail
        assert net.isolated_fully()
        assert "sessions SSH coupees" in detail and "203.0.113.9" in detail
        st = iso.read_state()
        assert st["deadline"] == NOW + 4 * 3600 + iso.LOCAL_GRACE_SECONDS
        assert st["contact_timeout"] == iso.MIN_CONTACT_TIMEOUT
        # l'etat (donc la restauration locale) existe AVANT la premiere commande de pare-feu
        assert [c for c, _ in net.calls if c[0].endswith("-restore")]

    def test_session_d_une_destination_preservee_non_coupee(self, net):
        ok, detail, _ = iso.isolate(order(), "https://x", 60, ["198.51.100.10"], now=NOW)
        assert ok and "coupees" not in detail

    def test_echec_ipv6_annule_tout(self, net):
        net.fail_restore.add("ip6tables")
        ok, detail, _ = iso.isolate(order(), "https://x", 60, now=NOW)
        assert not ok and "annulee" in detail
        assert net.jumps == {"iptables": set(), "ip6tables": set()}   # jamais d'isolation partielle
        assert iso.read_state() is None

    @pytest.mark.parametrize("ttl", [None, 0, 30, 86401, "3600", True])
    def test_duree_invalide(self, net, ttl):
        ok, _, _ = iso.isolate(order(ttl=ttl), "https://x", 60, now=NOW)
        assert not ok and not net.calls

    def test_minuteur_inactif_refus(self, net):
        iso._write_json_atomic(iso.guard_stamp_path(), {"at": NOW - 600})
        ok, detail, _ = iso.isolate(order(), "https://x", 60, now=NOW)
        assert not ok and "minuteur" in detail and not net.calls

    def test_hors_linux_refus(self, net, monkeypatch):
        monkeypatch.setattr(iso, "is_linux", lambda: False)
        ok, detail, _ = iso.isolate(order(), "https://x", 60, now=NOW)
        assert not ok and "Linux" in detail

    def test_canal_ou_dns_introuvable_refus(self, net, monkeypatch):
        monkeypatch.setattr(iso, "resolve_api", lambda url: ([], 443))
        assert iso.isolate(order(), "https://x", 60, now=NOW)[0] is False
        monkeypatch.setattr(iso, "resolve_api", lambda url: (["1.2.3.4"], 443))
        monkeypatch.setattr(iso, "resolvers", lambda: [])
        assert iso.isolate(order(), "https://x", 60, now=NOW)[0] is False
        assert not net.calls

    def test_outil_absent_refus(self, net, monkeypatch):
        monkeypatch.setattr(iso.shutil, "which", lambda n: None if n == "ip6tables-restore" else "/x/" + n)
        ok, detail, _ = iso.isolate(order(), "https://x", 60, now=NOW)
        assert not ok and "ip6tables-restore" in detail

    def test_restauration_complete_et_idempotente(self, net):
        iso.isolate(order(), "https://x", 60, now=NOW)
        ok, detail = iso.restore_all()
        assert ok and "6 saut(s)" in detail
        assert net.jumps == {"iptables": set(), "ip6tables": set()}
        assert net.chains == {"iptables": {}, "ip6tables": {}}
        assert iso.read_state() is None
        assert iso.restore_all() == (True, "reseau deja restaure (aucune isolation en place)")

    def test_reisolation_sans_doublon(self, net):
        iso.isolate(order(), "https://x", 60, now=NOW)
        ok, _, _ = iso.isolate(order(oid=8), "https://x", 60, now=NOW)
        assert ok and net.isolated_fully()


# --- Minuteur de securite --------------------------------------------------------------------

class TestMinuteur:
    def test_rien_a_faire(self, net):
        assert iso.guard_tick(now=NOW) == "idle"
        assert iso.guard_alive(NOW + 5)

    def test_isolation_en_cours_conservee(self, net):
        iso.isolate(order(), "https://x", 60, now=NOW)
        iso.write_heartbeat(NOW + 200)
        assert iso.guard_tick(now=NOW + 300) == "isolated"
        assert net.isolated_fully()

    def test_echeance(self, net):
        iso.isolate(order(ttl=3600), "https://x", 60, now=NOW)
        iso.write_heartbeat(NOW + 3600 + 590)
        assert iso.guard_tick(now=NOW + 3600 + 599) == "isolated"   # le serveur restaure d'abord
        assert iso.guard_tick(now=NOW + 3600 + 600) == "restored"
        assert not iso.is_isolated()

    def test_perte_de_contact(self, net):
        iso.isolate(order(), "https://x", 60, now=NOW)
        assert iso.guard_tick(now=NOW + 299) == "isolated"
        assert iso.guard_tick(now=NOW + 301) == "restored"

    def test_intervalle_long_allonge_le_delai(self, net):
        iso.isolate(order(), "https://x", 600, now=NOW)
        assert iso.read_state()["contact_timeout"] == 1800
        assert iso.guard_tick(now=NOW + 1000) == "isolated"

    def test_plafond_24h_meme_si_l_etat_est_modifie(self, net):
        iso.isolate(order(), "https://x", 60, now=NOW)
        st = iso.read_state()
        st["deadline"] = NOW + 10 * 86400
        iso._write_json_atomic(iso.state_path(), st)
        iso.write_heartbeat(NOW + 86400 + 600)
        assert iso.guard_tick(now=NOW + 86400 + 600) == "restored"

    def test_etat_absent_ou_illisible_restaure(self, net):
        iso.isolate(order(), "https://x", 60, now=NOW)
        with open(iso.state_path(), "w") as fh:
            fh.write("{corrompu")
        assert iso.guard_tick(now=NOW + 10) == "restored"

    def test_etat_orphelin_supprime(self, net):
        iso.isolate(order(), "https://x", 60, now=NOW)
        net.jumps = {"iptables": set(), "ip6tables": set()}       # ex. redemarrage
        assert iso.guard_tick(now=NOW + 10) == "idle"
        assert iso.read_state() is None

    def test_point_d_entree(self, net, monkeypatch):
        monkeypatch.setattr(iso, "guard_tick", lambda now=None: "restore_failed")
        monkeypatch.setattr(isolation_guard, "guard_tick", lambda: "restore_failed")
        assert isolation_guard.main() == 1


# --- Service de remediation ---------------------------------------------------------------

class TestService:
    def test_aiguillage_sans_anti_lockout(self, monkeypatch):
        reports, seen = [], []
        monkeypatch.setattr(r, "_guard_order", lambda o: None)
        monkeypatch.setattr(r, "_active_ssh_source_ips", lambda: {"203.0.113.9"})
        monkeypatch.setattr(r, "_report", lambda api, tok, oid, ok, detail, rule_present=None:
                            reports.append((oid, ok, rule_present)))
        monkeypatch.setattr(r.isolation, "isolate",
                            lambda o, api, interval, active: seen.append((interval, active)) or (True, "isole", True))
        monkeypatch.setattr(r.isolation, "restore_all", lambda: (True, "restaure"))
        r._process_order(order(oid=1), "https://x", "t")
        r._process_order({"id": 2, "action": "restore_network", "target_ip": "host:12"}, "https://x", "t")
        assert reports == [(1, True, True), (2, True, None)]
        assert seen == [(60.0, {"203.0.113.9"})]

    def test_contact_note_a_chaque_releve(self, monkeypatch):
        beats = []

        class Resp:
            status_code = 200

            @staticmethod
            def json():
                return {"orders": []}

        monkeypatch.setattr(r.requests, "get", lambda *a, **k: Resp())
        monkeypatch.setattr(r.isolation, "write_heartbeat", lambda: beats.append(1))
        r._poll_once("https://x", "t")
        assert beats == [1]
