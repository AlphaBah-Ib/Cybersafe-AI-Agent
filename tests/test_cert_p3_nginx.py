# -*- coding: utf-8 -*-
"""
[CERT04-P3] Integration sur un VRAI Nginx : plan, validation HTTP-01, installation,
certificat reellement servi en HTTPS, retour arriere, refus.

Necessite nginx et root (ports 80/443 sur 127.0.0.1) ; sinon les tests sont ignores.
    sudo python3 -m pytest tests/test_cert_p3_nginx.py -v
"""
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cybersafe_agent import cert_apply, cert_store, cert_webconf as wc
from cybersafe_agent.nginx_conf import NginxConfError, NginxConfig, tokenize

NAMES = ["client-a.fr", "www.client-a.fr"]
SHA_ANY = "a" * 64


def _port_free(port):
    s = socket.socket()
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


REAL = (shutil.which("nginx") is not None and os.geteuid() == 0
        and _port_free(80) and _port_free(443))
needs_nginx = pytest.mark.skipif(not REAL, reason="nginx + root + ports 80/443 libres requis")


# --- AC de test ------------------------------------------------------------------------
def _ca():
    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(timezone.utc)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
         .serial_number(1).not_valid_before(now - timedelta(days=1))
         .not_valid_after(now + timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .sign(k, hashes.SHA256()))
    return k, c


def issuer(directory, csr_path, names):
    with open(csr_path, "rb") as fh:
        csr = x509.load_pem_x509_csr(fh.read())
    k, ca = _ca()
    now = datetime.now(timezone.utc)
    leaf = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca.subject)
            .public_key(csr.public_key()).serial_number(int(uuid.uuid4().int >> 72))
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=45))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),
                           critical=False)
            .sign(k, hashes.SHA256()))
    return leaf, [ca]


def self_signed(tmp, name):
    k = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    c = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(k.public_key())
         .serial_number(5).not_valid_before(now - timedelta(days=1))
         .not_valid_after(now + timedelta(days=10)).sign(k, hashes.SHA256()))
    cp, kp = os.path.join(tmp, "old.crt"), os.path.join(tmp, "old.key")
    open(cp, "wb").write(c.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(k.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return cp, kp


# --- banc Nginx -----------------------------------------------------------------------------
class Bench:
    def __init__(self, tmp):
        # Dossier traversable par l'utilisateur non privilegie des workers Nginx
        # (comme /etc/nginx et /var/lib/... en production) : le banc reproduit les
        # vrais droits au lieu de faire tourner Nginx en root.
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="cs-nginx-", dir="/tmp")
        os.chmod(self.tmp, 0o755)
        self.conf = os.path.join(self.tmp, "nginx.conf")
        self.sites = os.path.join(self.tmp, "sites")
        os.makedirs(self.sites)
        os.makedirs(os.path.join(self.tmp, "www"), mode=0o755)
        os.chmod(self.sites, 0o755)
        with open(os.path.join(self.tmp, "www", "index.html"), "w") as fh:
            fh.write("site client\n")
        os.chmod(os.path.join(self.tmp, "www", "index.html"), 0o644)
        etc = os.path.join(self.tmp, "etc")
        os.mkdir(etc, 0o700)
        open(self.conf, "w").write(
            "pid %s/nginx.pid;\nerror_log %s/error.log;\nevents { worker_connections 64; }\n"
            "http {\n    access_log off;\n    include %s/*.conf;\n}\n"
            % (self.tmp, self.tmp, self.sites))
        base = ("nginx", "-p", self.tmp, "-c", self.conf)
        self.env = wc.Env(nginx_main=self.conf, snippet_dir=os.path.join(self.tmp, "cybersafe"),
                          certs_root=os.path.join(etc, "certs"),
                          webroot=os.path.join(self.tmp, "webroot"),
                          backup_dir=os.path.join(self.tmp, "backups"),
                          letsencrypt_dir=os.path.join(self.tmp, "letsencrypt"),
                          panel_markers=(), nginx_test_cmd=base + ("-t", "-q"),
                          nginx_reload_cmd=base + ("-s", "reload"), verify_timeout=8.0)
        self.base = base
        self.running = False

    def site(self, name, text):
        p = os.path.join(self.sites, name)
        open(p, "w").write(text)
        return p

    def start(self):
        subprocess.run(self.base, check=True)
        self.running = True

    def stop(self):
        if self.running:
            subprocess.run(self.base + ("-s", "stop"), check=False)
            self.running = False

    def snapshot(self):
        return {f: open(os.path.join(self.sites, f)).read() for f in sorted(os.listdir(self.sites))}

    def served_after(self, name, not_equal=None, equal=None):
        """Certificat servi une fois la bascule des workers terminee (rechargement asynchrone)."""
        import time
        deadline, got = time.monotonic() + 8, None
        while time.monotonic() < deadline:
            got = self.served_fingerprint(name)
            if (not_equal is not None and got != not_equal) or (equal is not None and got == equal):
                break
            time.sleep(0.2)
        return got

    def served_fingerprint(self, name):
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=name) as t:
                return t.getpeercert(binary_form=True)

    def http_get(self, host, path, expect=None):
        # Le rechargement de Nginx est asynchrone (nouveaux workers) : on laisse
        # quelques instants a la nouvelle configuration, comme verify_https.
        import time
        deadline = time.monotonic() + 5
        while True:
            c = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
            c.request("GET", path, headers={"Host": host})
            r = c.getresponse()
            got = (r.status, r.read().decode())
            c.close()
            if expect is None or got[0] == expect or time.monotonic() > deadline:
                return got
            time.sleep(0.2)


@pytest.fixture
def bench(tmp_path, monkeypatch):
    b = Bench(tmp_path)
    monkeypatch.setattr(wc, "ENV", b.env)
    old = os.umask(0o077)  # comme cert_apply en production
    try:
        yield b
    finally:
        os.umask(old)
        b.stop()
        shutil.rmtree(b.tmp, ignore_errors=True)


def order(**over):
    o = {"id": 1, "kind": "issue_install", "certificate_id": 3, "hostnames": list(NAMES),
         "web_server": "nginx", "acme_directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
         "plan_sha256": SHA_ANY}
    o.update(over)
    return o


def run_issue(bench, plan_sha, **kw):
    return cert_apply.do_issue_install(order(plan_sha256=plan_sha), wc,
                                       certs_root=bench.env.certs_root, issuer=kw.get("issuer", issuer))


HTTP_SITE = ("server {\n    listen 127.0.0.1:80;\n    server_name client-a.fr www.client-a.fr;\n"
             "    root %s/www;\n}\n")


# --- 1. lecteur de configuration (sans Nginx) ---------------------------------------------------
class TestReader:

    def test_tokens_quotes_comments_variables(self):
        toks = [t for t, _l, _q in tokenize('a "b c" \'d;\' # com\n root /x/${host}/y; {}')]
        assert toks == ["a", "b c", "d;", "root", "/x/${host}/y", ";", "{", "}"]

    def test_lines_and_blocks(self, tmp_path):
        p = tmp_path / "n.conf"
        p.write_text("events {}\nhttp {\n  server\n  {\n    listen 80;\n  }\n}\n")
        c = NginxConfig(str(p))
        s = list(c.servers())[0]
        assert (s.line, s.open_line, s.close_line) == (3, 4, 6)

    @pytest.mark.parametrize("text", ["http {", "http { }}", "listen 80", 'a "b;', "a { b }"])
    def test_syntax_errors(self, tmp_path, text):
        p = tmp_path / "n.conf"
        p.write_text(text)
        with pytest.raises(NginxConfError):
            NginxConfig(str(p))

    def test_include_cycle_and_missing(self, tmp_path):
        a, b = tmp_path / "a.conf", tmp_path / "b.conf"
        a.write_text("include %s;" % b)
        b.write_text("include %s;" % a)
        with pytest.raises(NginxConfError, match="circulaire"):
            NginxConfig(str(a))
        a.write_text("include %s/absent.conf;" % tmp_path)
        with pytest.raises(NginxConfError, match="introuvable"):
            NginxConfig(str(a))


# --- 2. parcours complets sur un vrai Nginx ---------------------------------------------------
@needs_nginx
class TestNginxFlows:

    def test_http_only_site_full_flow(self, bench):
        bench.site("a.conf", HTTP_SITE % bench.tmp)
        bench.start()
        plan = wc.compute_plan("nginx", NAMES, 3)
        assert "listen 443 ssl;" in plan.diff and "acme-challenge.conf" in plan.diff
        assert wc.compute_plan("nginx", NAMES, 3).sha256 == plan.sha256  # deterministe
        # phase A seule : la validation HTTP-01 est servie, le site reste servi
        wc.ensure_challenge("nginx", NAMES, 3, plan)
        tok = os.path.join(bench.env.webroot, ".well-known", "acme-challenge", "jeton123")
        old = os.umask(0o022)  # comme lego (cert_acme._lego_umask)
        open(tok, "w").write("preuve")
        os.umask(old)
        assert bench.http_get("client-a.fr", "/.well-known/acme-challenge/jeton123", 200) == (200, "preuve")
        assert bench.http_get("client-a.fr", "/")[1] == "site client\n"
        wc.restore("nginx", 3)
        # parcours complet via cert_apply
        res = run_issue(bench, plan.sha256)
        assert res["success"] and res["https_verified"], res
        served = bench.served_fingerprint("www.client-a.fr")
        leaf = x509.load_pem_x509_certificate(res["certificate_pem"].encode())
        assert served == leaf.public_bytes(serialization.Encoding.DER)
        assert bench.http_get("client-a.fr", "/")[1] == "site client\n"  # HTTP toujours servi
        # deuxieme calcul : plus rien a modifier, renouvellement sans approbation
        again = wc.compute_plan("nginx", NAMES, 3)
        assert again.files == [] and "aucune modification" in again.diff
        res2 = run_issue(bench, again.sha256)
        assert res2["success"], res2
        assert bench.served_after("client-a.fr", not_equal=served) != served

    def test_failed_renewal_keeps_serving_previous_cert(self, bench, monkeypatch):
        bench.site("a.conf", HTTP_SITE % bench.tmp)
        bench.start()
        res = run_issue(bench, wc.compute_plan("nginx", NAMES, 3).sha256)
        assert res["success"], res
        first = bench.served_fingerprint("client-a.fr")
        again = wc.compute_plan("nginx", NAMES, 3)
        # le nouveau certificat n'est pas celui que Nginx sert -> retour arriere
        monkeypatch.setattr(wc, "verify_https", lambda *a, **k: (_ for _ in ()).throw(
            wc.WebconfError("Verification HTTPS simulee en echec")))
        res2 = run_issue(bench, again.sha256)
        assert not res2["success"] and "INSTALL_ROLLED_BACK" in res2["detail"]
        assert bench.served_after("client-a.fr", equal=first) == first

    def test_existing_https_site_with_redirect(self, bench):
        cp, kp = self_signed(bench.tmp, "client-a.fr")
        bench.site("a.conf",
                   "server {\n    listen 127.0.0.1:80;\n    server_name client-a.fr www.client-a.fr;\n"
                   "    return 301 https://$host$request_uri;\n}\n"
                   "server {\n    listen 127.0.0.1:443 ssl;\n    server_name client-a.fr www.client-a.fr;\n"
                   "    ssl_certificate %s;\n    ssl_certificate_key %s;\n    root %s/www;\n}\n"
                   % (cp, kp, bench.tmp))
        bench.start()
        plan = wc.compute_plan("nginx", NAMES, 3)
        a = open(os.path.join(bench.sites, "a.conf")).read()
        final = plan.final[os.path.join(bench.sites, "a.conf")]
        assert "# cybersafe-ai: ssl_certificate %s;" % cp in final
        assert final.count("acme-challenge.conf") == 1          # bloc 443 seulement
        assert final.split("server {")[1].count("include") == 0  # bloc 80 (redirection) intact
        assert "listen 443 ssl;  # cybersafe-ai" not in final
        res = run_issue(bench, plan.sha256)
        assert res["success"], res
        assert bench.http_get("client-a.fr", "/x", 301)[0] == 301    # redirection preservee
        assert a != open(os.path.join(bench.sites, "a.conf")).read()

    def test_phase_b_failure_restores_everything(self, bench, monkeypatch):
        bench.site("a.conf", HTTP_SITE % bench.tmp)
        bench.start()
        before = bench.snapshot()
        plan = wc.compute_plan("nginx", NAMES, 3)
        real_install = wc.install

        def broken_install(*a, **kw):
            # simule un rechargement qui echoue pendant la phase B
            monkeypatch.setattr(bench.env, "nginx_reload_cmd", ("false",))
            try:
                return real_install(*a, **kw)
            finally:
                monkeypatch.setattr(bench.env, "nginx_reload_cmd", bench.base + ("-s", "reload"))
        monkeypatch.setattr(wc, "install", broken_install)
        res = run_issue(bench, plan.sha256)
        assert not res["success"] and "INSTALL_ROLLED_BACK" in res["detail"]
        assert bench.snapshot() == before
        assert not os.path.exists(os.path.join(bench.env.snippet_dir, "certs", "3.conf"))
        assert cert_store.current_version(3, root=bench.env.certs_root) is None
        assert bench.http_get("client-a.fr", "/")[1] == "site client\n"

    def test_issuance_failure_restores_phase_a(self, bench):
        bench.site("a.conf", HTTP_SITE % bench.tmp)
        bench.start()
        before = bench.snapshot()
        plan = wc.compute_plan("nginx", NAMES, 3)

        def refused(*a):
            from cybersafe_agent.cert_acme import AcmeError
            raise AcmeError("emission refusee : unauthorized")
        with pytest.raises(Exception):
            run_issue(bench, plan.sha256, issuer=refused)
        assert bench.snapshot() == before
        assert wc.compute_plan("nginx", NAMES, 3).sha256 == plan.sha256  # reessai sans reapprobation

    def test_config_changed_after_approval(self, bench):
        p = bench.site("a.conf", HTTP_SITE % bench.tmp)
        bench.start()
        plan = wc.compute_plan("nginx", NAMES, 3)
        open(p, "a").write("# modification apres approbation\n")
        res = run_issue(bench, plan.sha256)
        assert not res["success"] and res["detail"].startswith("PLAN_CHANGED")

    def test_nginx_t_failure_rolls_back_phase_a(self, bench, monkeypatch):
        bench.site("a.conf", HTTP_SITE % bench.tmp)
        bench.start()
        before = bench.snapshot()
        plan = wc.compute_plan("nginx", NAMES, 3)
        monkeypatch.setattr(bench.env, "nginx_test_cmd", ("false",))
        with pytest.raises(wc.WebconfError, match="annulee"):
            wc.ensure_challenge("nginx", NAMES, 3, plan)
        assert bench.snapshot() == before


# --- 3. refus (analyse seule, Nginx non demarre) ---------------------------------------------------
class TestRefusals:

    @pytest.fixture
    def b(self, bench):
        return bench

    def test_names_in_different_blocks(self, b):
        b.site("a.conf", "server { listen 80;\n server_name client-a.fr; root /x; }\n"
                         "server { listen 80;\n server_name www.client-a.fr; root /x; }\n")
        with pytest.raises(wc.WebconfError, match="blocs server differents"):
            wc.compute_plan("nginx", NAMES, 3)

    def test_block_serves_other_names(self, b):
        b.site("a.conf", "server {\n listen 80;\n server_name client-a.fr www.client-a.fr shop.fr;\n"
                         " root /x;\n}\n")
        with pytest.raises(wc.WebconfError, match="shop.fr"):
            wc.compute_plan("nginx", NAMES, 3)

    def test_name_not_declared(self, b):
        b.site("a.conf", "server {\n listen 80;\n server_name *.client-a.fr;\n root /x;\n}\n")
        with pytest.raises(wc.WebconfError, match="explicitement"):
            wc.compute_plan("nginx", NAMES, 3)

    def test_redirect_without_https_block(self, b):
        b.site("a.conf", "server {\n listen 80;\n server_name client-a.fr www.client-a.fr;\n"
                         " return 301 https://$host;\n}\n")
        with pytest.raises(wc.WebconfError, match="redirige"):
            wc.compute_plan("nginx", NAMES, 3)

    def test_certbot_managed(self, b):
        b.site("a.conf", "server {\n listen 443 ssl;\n server_name client-a.fr www.client-a.fr;\n"
                         " ssl_certificate %s/letsencrypt/live/x/fullchain.pem;\n"
                         " ssl_certificate_key %s/letsencrypt/live/x/privkey.pem;\n}\n"
                         % (b.tmp, b.tmp))
        with pytest.raises(wc.WebconfError, match="certbot"):
            wc.compute_plan("nginx", NAMES, 3)
        os.makedirs(os.path.join(b.tmp, "letsencrypt", "renewal"))
        open(os.path.join(b.tmp, "letsencrypt", "renewal", "client-a.fr.conf"), "w").write("")
        with pytest.raises(wc.WebconfError, match="certbot"):
            wc.compute_plan("nginx", NAMES, 3)

    def test_existing_challenge_location(self, b):
        b.site("a.conf", "server {\n listen 80;\n server_name client-a.fr www.client-a.fr;\n"
                         " location /.well-known/acme-challenge/ { root /y; }\n}\n")
        with pytest.raises(wc.WebconfError, match="autre outil"):
            wc.compute_plan("nginx", NAMES, 3)

    def test_one_line_block_and_panel(self, b, monkeypatch):
        b.site("a.conf", "server { listen 80; server_name client-a.fr www.client-a.fr; }\n")
        with pytest.raises(wc.WebconfError, match="inhabituel"):
            wc.compute_plan("nginx", NAMES, 3)
        monkeypatch.setattr(b.env, "panel_markers", (b.tmp,))
        with pytest.raises(wc.WebconfError, match="Panneau"):
            wc.compute_plan("nginx", NAMES, 3)

    def test_apache_not_yet(self, b):
        with pytest.raises(wc.WebconfError, match="Apache"):
            wc.compute_plan("apache", NAMES, 3)

    def test_plan_sensitive_to_any_change(self, b):
        p = b.site("a.conf", HTTP_SITE % b.tmp)
        s1 = wc.compute_plan("nginx", NAMES, 3).sha256
        open(p, "a").write("# commentaire\n")
        assert wc.compute_plan("nginx", NAMES, 3).sha256 != s1
        assert json.loads(json.dumps(wc.compute_plan("nginx", NAMES, 3).files))
