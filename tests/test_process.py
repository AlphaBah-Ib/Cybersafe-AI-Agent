# -*- coding: utf-8 -*-
"""
US-SOC-R15 (agent 2.5.0) — reponse sur processus suspects.

    python -m pytest tests/test_process.py -v

Les tests d'action portent sur de VRAIS processus lances par le test lui-meme
(sleep, petit serveur TCP local) : jamais sur un processus existant du poste.
Linux uniquement (pidfd, /proc).
"""
import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybersafe_agent import order_guard as g
from cybersafe_agent import process_apply as pa
from cybersafe_agent import process_ops as ops
from cybersafe_agent import remediation as r

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open"),
                                reason="Linux avec pidfd requis")
_FMT = "%Y-%m-%dT%H:%M:%SZ"


# --- Outils ---------------------------------------------------------------------------

@pytest.fixture
def sleeper():
    procs = []

    def start(seconds=60):
        p = subprocess.Popen(["sleep", str(seconds)])
        procs.append(p)
        for _ in range(100):  # attendre que l'exec de sleep soit fait
            if (ops._readlink(p.pid, "exe").endswith("sleep")
                    and ops._cmdline(p.pid)[0] == "sleep %d" % seconds):
                break
            time.sleep(0.01)
        return p
    yield start
    for p in procs:
        try:
            p.kill()
        except OSError:
            pass
        p.wait()


@pytest.fixture
def listener():
    code = ("import socket,sys,time\n"
            "s=socket.socket();s.bind(('127.0.0.1',0));s.listen(1)\n"
            "print(s.getsockname()[1],flush=True);time.sleep(60)\n")
    p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    port = int(p.stdout.readline())
    yield p, port
    p.kill()
    p.wait()


def fp_of(ev):
    return {k: ev[k] for k in ops.FINGERPRINT_KEYS}


@pytest.fixture
def key(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(g, "_ORDER_PUBLIC_KEY_B64", base64.b64encode(raw).decode("ascii"))
    return priv


FP = {"pid": 4242, "start_ticks": "123456", "boot_id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
      "exe": "/tmp/.x/miner", "exe_sha256": "a" * 64, "cmdline_sha256": "b" * 64, "uid": 1000}


def signed(priv, **fields):
    now = datetime.now(timezone.utc)
    o = {"id": 31, "action": "kill_process", "target_ip": "proc:17", "ttl_seconds": 3600,
         "agent_id": 12, "issued_at": now.strftime(_FMT),
         "expires_at": (now + timedelta(minutes=5)).strftime(_FMT), "nonce": uuid.uuid4().hex,
         "params": {"justification": "Mineur de cryptomonnaie (test)", "fingerprint": dict(FP)}}
    o.update(fields)
    o["sig_alg"] = g.SIG_V2
    o["signature"] = base64.b64encode(priv.sign(g.canonical(o, g.SIGNED_FIELDS_V2))).decode("ascii")
    return o


# --- Garde des ordres -------------------------------------------------------------------

class TestGarde:
    @pytest.mark.parametrize("action,target,params", [
        ("inspect_process", "port:8080", {}),
        ("inspect_process", "pid:4242", {}),
        ("quarantine_process", "proc:17", {"justification": "Processus suspect (test)", "fingerprint": FP}),
        ("kill_process", "proc:17", {"justification": "Processus suspect (test)", "fingerprint": FP}),
        ("release_process", "proc:17", {"fingerprint": FP}),
    ])
    def test_ordres_acceptes(self, key, tmp_path, action, target, params):
        g.guard_order(signed(key, action=action, target_ip=target, params=params),
                      g.ReplayJournal(str(tmp_path)))

    @pytest.mark.parametrize("action,target", [
        ("inspect_process", "port:0"), ("inspect_process", "port:65536"), ("inspect_process", "pid:1"),
        ("inspect_process", "pid:01"), ("inspect_process", "22"), ("inspect_process", "port:22 "),
        ("inspect_process", "proc:17"), ("kill_process", "pid:4242"), ("kill_process", "proc:0"),
        ("kill_process", "proc:17;id"), ("kill_process", "4242"),
    ])
    def test_cibles_refusees(self, key, tmp_path, action, target):
        params = {} if action == "inspect_process" else {"justification": "Processus suspect (test)",
                                                          "fingerprint": FP}
        with pytest.raises(g.OrderRejected):
            g.guard_order(signed(key, action=action, target_ip=target, params=params),
                          g.ReplayJournal(str(tmp_path)))

    @pytest.mark.parametrize("change", [
        {"pid": 1}, {"pid": "4242"}, {"pid": True}, {"uid": -1}, {"start_ticks": "12a"},
        {"start_ticks": 123}, {"boot_id": "pas-un-uuid"}, {"exe": ""}, {"exe": "x" * 1025},
        {"exe_sha256": "A" * 64}, {"cmdline_sha256": ""}, {"extra": 1},
    ])
    def test_empreinte_controlee(self, key, tmp_path, change):
        fp = dict(FP, **change)
        with pytest.raises(g.OrderRejected):
            g.guard_order(signed(key, params={"justification": "Processus suspect (test)",
                                              "fingerprint": fp}), g.ReplayJournal(str(tmp_path)))

    def test_empreinte_absente_ou_justification_absente(self, key, tmp_path):
        for params in ({"justification": "Processus suspect (test)"}, {"fingerprint": FP}):
            with pytest.raises(g.OrderRejected):
                g.guard_order(signed(key, params=params), g.ReplayJournal(str(tmp_path)))

    def test_empreinte_signee(self, key, tmp_path):
        o = signed(key)
        o["params"]["fingerprint"]["pid"] = 999  # modifiee apres signature
        with pytest.raises(g.OrderRejected, match="signature"):
            g.guard_order(o, g.ReplayJournal(str(tmp_path)))

    def test_exe_sha256_vide_admis(self, key, tmp_path):
        g.guard_order(signed(key, params={"justification": "Processus suspect (test)",
                                          "fingerprint": dict(FP, exe_sha256="")}),
                      g.ReplayJournal(str(tmp_path)))


# --- Releve ----------------------------------------------------------------------------

class TestReleve:
    def test_preuve_complete(self, sleeper):
        p = sleeper()
        ev = ops.capture(p.pid)
        assert ev["pid"] == p.pid and ev["ppid"] == os.getpid() and ev["uid"] == os.getuid()
        assert ev["name"] == "sleep" and ev["exe"].endswith("sleep") and ev["cmdline"] == "sleep 60"
        assert len(ev["exe_sha256"]) == 64 and len(ev["cmdline_sha256"]) == 64
        assert ev["start_ticks"].isdigit() and len(ev["boot_id"]) == 36 and ev["state"] in "SRD"
        assert ev["captured_at"].endswith("Z") and ev["protection"] == ""
        assert "environ" not in json.dumps(ev)
        assert ops.check_fingerprint(fp_of(ev), ops.capture(p.pid)) == []

    def test_hash_du_binaire(self, sleeper):
        import hashlib
        p = sleeper()
        with open(ops._readlink(p.pid, "exe"), "rb") as fh:
            assert ops.capture(p.pid)["exe_sha256"] == hashlib.sha256(fh.read()).hexdigest()

    def test_processus_absent(self, sleeper):
        p = sleeper()
        p.kill()
        p.wait()
        with pytest.raises(ops.ProcessError, match="introuvable"):
            ops.capture(p.pid)

    def test_port_vers_processus(self, listener):
        p, port = listener
        assert ops.find_listener(port)[0] == p.pid
        ok, detail, ev = ops.inspect("port:%d" % port)
        assert ok and ev["pid"] == p.pid and ev["listen_port"] == port
        assert any(c["state"] == "LISTEN" and c["local"].endswith(":%d" % port) for c in ev["connections"])

    def test_port_sans_ecoute(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        ok, detail, ev = ops.inspect("port:%d" % port)
        assert not ok and ev is None and "aucun processus" in detail

    def test_inspection_par_pid_et_cible_invalide(self, sleeper):
        p = sleeper()
        assert ops.inspect("pid:%d" % p.pid)[2]["pid"] == p.pid
        assert ops.inspect("pid:%d;id" % p.pid)[0] is False

    @pytest.mark.parametrize("ev,level", [
        (dict(pid=1, ppid=0, name="systemd", exe="/usr/lib/systemd/systemd", cmdline=""), "core"),
        (dict(pid=50, ppid=2, name="kworker/0:1", exe="", cmdline=""), "core"),
        (dict(pid=900, ppid=1, name="sshd", exe="/usr/sbin/sshd", cmdline="sshd: /usr/sbin/sshd"), "core"),
        (dict(pid=901, ppid=1, name="python3", exe="/usr/bin/python3.12",
              cmdline="/opt/cybersafe-agent/venv/bin/python -m cybersafe_agent"), "core"),
        (dict(pid=902, ppid=1, name="postgres", exe="/usr/lib/postgresql/16/bin/postgres", cmdline=""), "critical"),
        (dict(pid=903, ppid=1, name="php-fpm8.3", exe="/usr/sbin/php-fpm8.3", cmdline=""), "critical"),
        (dict(pid=904, ppid=900, name="sshd", exe="/usr/sbin/sshd", cmdline="sshd: alice"), ""),
        (dict(pid=905, ppid=1, name="miner", exe="/tmp/.x/miner (deleted)", cmdline="./miner"), ""),
    ])
    def test_protections(self, ev, level):
        assert ops.classify(ev)[0] == level


# --- Actions ---------------------------------------------------------------------------

class TestActions:
    def test_gel_puis_liberation(self, sleeper):
        p = sleeper()
        fp = fp_of(ops.capture(p.pid))
        ok, detail, ev = ops.act("quarantine_process", fp)
        assert ok and "gele" in detail and ev["pid"] == p.pid
        assert ops.read_stat(p.pid)[1] == "T"
        ok, detail, _ = ops.act("quarantine_process", fp)
        assert ok and "deja gele" in detail
        ok, detail, _ = ops.act("release_process", fp)
        assert ok and "libere" in detail and ops.read_stat(p.pid)[1] != "T"

    def test_arret(self, sleeper):
        p = sleeper()
        ok, detail, ev = ops.act("kill_process", fp_of(ops.capture(p.pid)))
        assert ok and "SIGKILL" in detail and ev["name"] == "sleep"
        assert p.wait(timeout=5) == -9

    def test_arret_d_un_processus_gele(self, sleeper):
        p = sleeper()
        fp = fp_of(ops.capture(p.pid))
        assert ops.act("quarantine_process", fp)[0]
        assert ops.act("kill_process", fp)[0]
        assert p.wait(timeout=5) == -9

    @pytest.mark.parametrize("field,value", [
        ("start_ticks", "1"), ("exe_sha256", "c" * 64), ("cmdline_sha256", "d" * 64),
        ("uid", 4242), ("exe", "/usr/bin/autre"), ("boot_id", "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"),
    ])
    def test_empreinte_differente_rien_n_est_fait(self, sleeper, field, value):
        p = sleeper()
        fp = dict(fp_of(ops.capture(p.pid)), **{field: value})
        for action in ("quarantine_process", "kill_process"):
            ok, detail, _ = ops.act(action, fp)
            assert not ok and "Rien n'a ete fait" in detail and field in detail
        assert p.poll() is None and ops.read_stat(p.pid)[1] != "T"

    def test_pid_reutilise(self, sleeper):
        """Meme PID, meme binaire, meme commande, mais autre demarrage : c'est un autre processus."""
        second = sleeper()
        fp_reuse = dict(fp_of(ops.capture(second.pid)),
                        start_ticks=str(int(ops.capture(second.pid)["start_ticks"]) - 1))
        ok, detail, _ = ops.act("kill_process", fp_reuse)
        assert not ok and "start_ticks" in detail and second.poll() is None

    def test_processus_deja_termine(self, sleeper):
        p = sleeper()
        fp = fp_of(ops.capture(p.pid))
        p.kill()
        p.wait()
        ok, detail, ev = ops.act("kill_process", fp)
        assert not ok and "introuvable" in detail and ev is None

    def test_processus_core_refuse_meme_si_l_empreinte_correspond(self, sleeper, monkeypatch):
        p = sleeper()
        fp = fp_of(ops.capture(p.pid))
        monkeypatch.setattr(ops, "CORE_NAMES", ops.CORE_NAMES | {"sleep"})
        ok, detail, _ = ops.act("kill_process", fp)
        assert not ok and "protege" in detail and p.poll() is None

    def test_nom_d_executable_piege(self):
        ev = dict(FP, exe="/tmp/a\nb")
        assert ops.check_fingerprint(dict(FP, exe="/tmp/a?b"), ev) == []

    def test_sans_pidfd_refus(self, monkeypatch):
        monkeypatch.delattr(os, "pidfd_open")
        ok, detail, _ = ops.act("kill_process", dict(FP))
        assert not ok and "pidfd" in detail


# --- Unite root ---------------------------------------------------------------------------

@pytest.fixture
def unit(tmp_path, monkeypatch):
    monkeypatch.setattr(pa, "STATE_DIR", str(tmp_path / "root"))
    os.makedirs(str(tmp_path / "root"))
    req = tmp_path / "request.json"
    monkeypatch.setattr(pa, "REQUEST", str(req))
    return req


class TestUniteRoot:
    def test_arret_bout_en_bout(self, key, unit, sleeper):
        p = sleeper()
        o = signed(key, params={"justification": "Processus suspect (test)",
                                "fingerprint": fp_of(ops.capture(p.pid))})
        unit.write_text(json.dumps({"order": o}))
        res = pa.apply_once()
        assert res["ok"] and res["nonce"] == o["nonce"] and res["evidence"]["pid"] == p.pid
        assert json.load(open(pa.result_path(31)))["ok"] is True
        assert p.wait(timeout=5) == -9

    def test_inspection_bout_en_bout(self, key, unit, listener):
        p, port = listener
        unit.write_text(json.dumps({"order": signed(key, action="inspect_process",
                                                    target_ip="port:%d" % port, params={})}))
        res = pa.apply_once()
        assert res["ok"] and res["evidence"]["pid"] == p.pid

    def test_signature_reverifiee(self, key, unit, sleeper):
        p = sleeper()
        o = signed(key, params={"justification": "Processus suspect (test)",
                                "fingerprint": fp_of(ops.capture(p.pid))})
        o["params"]["justification"] = "Modifie par le compte de l'agent"
        unit.write_text(json.dumps({"order": o}))
        res = pa.apply_once()
        assert not res["ok"] and "signature" in res["detail"] and p.poll() is None

    def test_action_hors_perimetre(self, key, unit):
        unit.write_text(json.dumps({"order": signed(key, action="ban_ip", target_ip="203.0.113.9",
                                                    params={})}))
        res = pa.apply_once()
        assert not res["ok"] and "perimetre" in res["detail"]

    def test_ordre_expire(self, key, unit):
        old = datetime.now(timezone.utc) - timedelta(hours=1)
        unit.write_text(json.dumps({"order": signed(key, expires_at=old.strftime(_FMT))}))
        res = pa.apply_once()
        assert not res["ok"] and "expire" in res["detail"]

    def test_rejeu_sans_effet_et_resultat_conserve(self, key, unit, sleeper):
        p = sleeper()
        o = signed(key, action="quarantine_process",
                   params={"justification": "Processus suspect (test)",
                           "fingerprint": fp_of(ops.capture(p.pid))})
        unit.write_text(json.dumps({"order": o}))
        assert pa.apply_once()["ok"]
        assert pa.apply_once() is None  # redeclenchement : resultat existant conserve
        os.unlink(pa.result_path(31))
        res = pa.apply_once()  # resultat efface : le journal anti-rejeu refuse quand meme
        assert not res["ok"] and "nonce" in res["detail"]

    def test_lien_symbolique_refuse(self, key, unit, tmp_path):
        target = tmp_path / "ailleurs.json"
        target.write_text(json.dumps({"order": signed(key)}))
        os.symlink(str(target), str(unit))
        assert pa.apply_once() is None
        assert not os.listdir(pa.STATE_DIR) or all(not n.startswith("result-") for n in os.listdir(pa.STATE_DIR))

    @pytest.mark.parametrize("content", ["pas du json", "[]", '{"order": 3}', '{"autre": {}}'])
    def test_demande_illisible(self, unit, content):
        unit.write_text(content)
        assert pa.apply_once() is None


# --- Service de remediation (messager) -----------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(r, "_PROC_DIR", str(tmp_path / "svc"))
    monkeypatch.setattr(r, "_PROC_RESULT_DIR", str(tmp_path / "root"))
    unit_file = tmp_path / "unit.path"
    unit_file.write_text("")
    monkeypatch.setattr(r, "_PROC_UNIT", str(unit_file))
    os.makedirs(str(tmp_path / "root"))
    return tmp_path


class TestService:
    def test_attend_le_resultat_de_cet_ordre(self, client):
        order = {"id": 31, "nonce": "n1", "action": "kill_process"}
        res_path = client / "root" / "result-31.json"
        res_path.write_text(json.dumps({"nonce": "ancien", "ok": False, "detail": "x"}))

        def unit_root():
            time.sleep(0.6)
            assert json.load(open(str(client / "svc" / "request.json")))["order"] == order
            res_path.write_text(json.dumps({"nonce": "n1", "ok": True, "detail": "termine",
                                            "evidence": {"pid": 4242}}))
        t = threading.Thread(target=unit_root)
        t.start()
        ok, detail, ev = r._process_action(order, timeout=5)
        t.join()
        assert ok and detail == "termine" and ev == {"pid": 4242}
        assert not (client / "svc" / "request.json").exists()

    def test_unite_absente(self, client, monkeypatch):
        monkeypatch.setattr(r, "_PROC_UNIT", str(client / "absent"))
        ok, detail, ev = r._process_action({"id": 31, "nonce": "n"})
        assert not ok and "ensure-units" in detail and ev is None

    def test_silence_de_l_unite(self, client):
        ok, detail, _ = r._process_action({"id": 31, "nonce": "n"}, timeout=0.6)
        assert not ok and "aucune reponse" in detail

    def test_aiguillage_et_preuve_remontee(self, monkeypatch):
        sent = []
        monkeypatch.setattr(r, "_guard_order", lambda o: None)
        monkeypatch.setattr(r, "_active_ssh_source_ips", lambda: set())
        monkeypatch.setattr(r, "_process_action", lambda o: (True, "gele", {"pid": 4242}))
        monkeypatch.setattr(r, "_report", lambda api, tok, oid, ok, detail, rule_present=None,
                            evidence=None: sent.append((oid, ok, detail, evidence)))
        r._process_order({"id": 31, "action": "quarantine_process", "target_ip": "proc:17"},
                         "https://x", "t")
        assert sent == [(31, True, "gele", {"pid": 4242})]

    def test_rapport_avec_preuve(self, monkeypatch):
        posted = []
        monkeypatch.setattr(r.requests, "post", lambda url, json=None, headers=None, timeout=None:
                            posted.append(json))
        r._report("https://x", "t", 31, True, "ok", evidence={"pid": 1})
        r._report("https://x", "t", 32, True, "ok")
        assert posted[0]["evidence"] == {"pid": 1} and "evidence" not in posted[1]
