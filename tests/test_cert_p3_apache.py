# -*- coding: utf-8 -*-
"""
[CERT04-P3B] Integration sur un VRAI Apache 2.4 : plan, validation HTTP-01 (y compris
derriere une RewriteRule attrape-tout), installation, certificat servi, retour arriere,
refus (decision B : pas de VirtualHost 443 -> refus).

Necessite apache2 et root (ports 80/443 sur 127.0.0.1) ; sinon les tests sont ignores.
    sudo python3 -m pytest tests/test_cert_p3_apache.py -v
"""
import http.client
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cybersafe_agent import cert_apply, cert_store, cert_webconf as wc
from cybersafe_agent.apache_conf import ApacheConfError, ApacheConfig, parse_text

from .test_cert_p3_nginx import NAMES, _port_free, issuer, self_signed, wait_ports_free

MODS = "/usr/lib/apache2/modules"
REAL = (shutil.which("apache2") is not None and os.path.isdir(MODS) and os.geteuid() == 0
        and _port_free(80) and _port_free(443))
needs_apache = pytest.mark.skipif(not REAL, reason="apache2 + root + ports 80/443 libres requis")


class Bench:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="cs-apache-", dir="/tmp")
        os.chmod(self.tmp, 0o755)
        self.conf = os.path.join(self.tmp, "httpd.conf")
        self.sites = os.path.join(self.tmp, "sites")
        os.makedirs(self.sites, mode=0o755)
        www = os.path.join(self.tmp, "www")
        os.makedirs(www, mode=0o755)
        with open(os.path.join(www, "index.html"), "w") as fh:
            fh.write("site client\n")
        os.chmod(os.path.join(www, "index.html"), 0o644)
        etc = os.path.join(self.tmp, "etc")
        os.mkdir(etc, 0o700)
        mods = "".join("LoadModule %s_module %s/mod_%s.so\n" % (m, MODS, m)
                       for m in ("mpm_event", "authz_core", "alias", "ssl", "socache_shmcb",
                                 "rewrite", "dir"))
        with open(self.conf, "w") as fh:
            fh.write("ServerRoot \"%s\"\n%sPidFile %s/httpd.pid\nDefaultRuntimeDir %s\n"
                     "ErrorLog %s/error.log\nLogLevel warn\nUser www-data\nGroup www-data\n"
                     "ServerName localhost\nListen 127.0.0.1:80\nListen 127.0.0.1:443 https\n"
                     "<Directory \"%s\">\n    Require all granted\n</Directory>\n"
                     "IncludeOptional sites/*.conf\n"
                     % (self.tmp, mods, self.tmp, self.tmp, self.tmp, www))
        base = ("apache2", "-d", self.tmp, "-f", self.conf)
        self.base = base
        self.env = wc.Env(apache_main=self.conf, apache_snippet_dir=os.path.join(self.tmp, "cybersafe"),
                          certs_root=os.path.join(etc, "certs"),
                          webroot=os.path.join(self.tmp, "webroot"),
                          backup_dir=os.path.join(self.tmp, "backups"),
                          letsencrypt_dir=os.path.join(self.tmp, "letsencrypt"), panel_markers=(),
                          apache_test_cmd=base + ("-t",), apache_reload_cmd=base + ("-k", "graceful"),
                          apache_modules_cmd=base + ("-M",), verify_timeout=10.0)
        self.running = False

    def site(self, name, text):
        p = os.path.join(self.sites, name)
        with open(p, "w") as fh:
            fh.write(text % {"tmp": self.tmp})
        return p

    def start(self):
        subprocess.run(self.base + ("-k", "start"), check=True)
        self.running = True
        time.sleep(0.5)

    def stop(self):
        if self.running:
            subprocess.run(self.base + ("-k", "stop"), check=False)
            self.running = False
            wait_ports_free()

    def snapshot(self):
        return {f: open(os.path.join(self.sites, f)).read() for f in sorted(os.listdir(self.sites))}

    def fingerprint(self, name):
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=name) as t:
                return t.getpeercert(binary_form=True)

    def served_after(self, name, not_equal=None, equal=None):
        deadline, got = time.monotonic() + 10, None
        while time.monotonic() < deadline:
            got = self.fingerprint(name)
            if (not_equal is not None and got != not_equal) or (equal is not None and got == equal):
                break
            time.sleep(0.2)
        return got

    def get(self, host, path, https=False, expect=None):
        deadline = time.monotonic() + 8
        while True:
            if https:
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                c = http.client.HTTPSConnection("127.0.0.1", 443, timeout=5, context=ctx)
                c._tunnel_host = None
                c.server_hostname = host
            else:
                c = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
            c.request("GET", path, headers={"Host": host})
            r = c.getresponse()
            got = (r.status, r.read().decode())
            c.close()
            if expect is None or got[0] == expect or time.monotonic() > deadline:
                return got
            time.sleep(0.2)


@pytest.fixture
def bench(monkeypatch):
    b = Bench()
    monkeypatch.setattr(wc, "ENV", b.env)
    old = os.umask(0o077)  # comme cert_apply
    try:
        yield b
    finally:
        os.umask(old)
        b.stop()
        shutil.rmtree(b.tmp, ignore_errors=True)


def run_issue(b, plan_sha, issue=issuer):
    o = {"id": 1, "kind": "issue_install", "certificate_id": 3, "hostnames": list(NAMES),
         "web_server": "apache", "plan_sha256": plan_sha,
         "acme_directory": "https://acme-staging-v02.api.letsencrypt.org/directory"}
    return cert_apply.do_issue_install(o, wc, certs_root=b.env.certs_root, issuer=issue)


def token(b, value="preuve"):
    d = os.path.join(b.env.webroot, ".well-known", "acme-challenge")
    old = os.umask(0o022)
    with open(os.path.join(d, "jeton123"), "w") as fh:
        fh.write(value)
    os.umask(old)


HTTP_VH = ("<VirtualHost 127.0.0.1:80>\n    ServerName client-a.fr\n    ServerAlias www.client-a.fr\n"
           "    DocumentRoot %(tmp)s/www\n</VirtualHost>\n")
SSL_VH = ("<IfModule mod_ssl.c>\n<VirtualHost 127.0.0.1:443>\n    ServerName client-a.fr\n"
          "    ServerAlias www.client-a.fr\n    DocumentRoot %(tmp)s/www\n    SSLEngine on\n"
          "    SSLCertificateFile %(tmp)s/old.crt\n    SSLCertificateKeyFile %(tmp)s/old.key\n"
          "%(extra)s</VirtualHost>\n</IfModule>\n")


def ssl_site(b, extra=""):
    self_signed(b.tmp, "client-a.fr")
    return b.site("a-ssl.conf", SSL_VH.replace("%(extra)s", extra))


# --- 1. lecteur (sans Apache) ----------------------------------------------------------------
class TestReader:

    def test_sections_lines_continuation(self, tmp_path):
        st = parse_text("# c\n<VirtualHost *:80>\n  ServerName a.fr\n  ServerAlias b.fr \\\n"
                        "     c.fr\n</VirtualHost>\n", "x")
        vh = st[0]
        assert (vh.name, vh.line, vh.close_line) == ("virtualhost", 2, 6)
        assert vh.block[1].args == ["b.fr", "c.fr"]

    @pytest.mark.parametrize("text", ["<VirtualHost *:80>\n", "</VirtualHost>\n",
                                      "<A>\n</B>\n", 'ServerName "a.fr\n'])
    def test_syntax_errors(self, text):
        with pytest.raises(ApacheConfError):
            parse_text(text, "x")

    def test_includes(self, tmp_path):
        (tmp_path / "s").mkdir()
        (tmp_path / "s" / "a.conf").write_text("<VirtualHost *:80>\nServerName a.fr\n</VirtualHost>\n")
        main = tmp_path / "m.conf"
        main.write_text("ServerRoot %s\nIncludeOptional s/*.conf\nIncludeOptional absent/*.conf\n"
                        "<IfModule x>\nInclude s/a.conf\n</IfModule>\n" % tmp_path)
        assert len(list(ApacheConfig(str(main)).vhosts())) == 2
        main.write_text("Include ${APACHE_X}/a.conf\n")
        with pytest.raises(ApacheConfError, match="variable"):
            ApacheConfig(str(main))


# --- 2. parcours sur un vrai Apache -----------------------------------------------------------
@needs_apache
class TestApacheFlows:

    def test_full_flow_and_renewal(self, bench):
        bench.site("a.conf", HTTP_VH)
        ssl_site(bench)
        bench.start()
        old = bench.fingerprint("client-a.fr")
        plan = wc.compute_plan("apache", NAMES, 3)
        final = plan.final[os.path.join(bench.sites, "a-ssl.conf")]
        assert "# cybersafe-ai: SSLCertificateFile" in final
        assert final.count("acme-challenge.conf") == 1 and "certs/3.conf" in final
        assert wc.compute_plan("apache", NAMES, 3).sha256 == plan.sha256
        wc.ensure_challenge("apache", NAMES, 3, plan)
        token(bench)
        assert bench.get("client-a.fr", "/.well-known/acme-challenge/jeton123", expect=200) == (200, "preuve")
        assert bench.get("client-a.fr", "/index.html")[1] == "site client\n"
        wc.restore("apache", 3)
        res = run_issue(bench, plan.sha256)
        assert res["success"] and res["https_verified"], res
        leaf = x509.load_pem_x509_certificate(res["certificate_pem"].encode())
        served = bench.served_after("www.client-a.fr", not_equal=old)
        assert served == leaf.public_bytes(serialization.Encoding.DER)
        again = wc.compute_plan("apache", NAMES, 3)
        assert again.files == []
        res2 = run_issue(bench, again.sha256)
        assert res2["success"], res2
        assert bench.served_after("client-a.fr", not_equal=served) != served

    def test_redirect_and_catch_all_rewrite(self, bench):
        bench.site("a.conf", "<VirtualHost 127.0.0.1:80>\n    ServerName client-a.fr\n"
                             "    ServerAlias www.client-a.fr\n"
                             "    Redirect permanent / https://client-a.fr/\n</VirtualHost>\n")
        ssl_site(bench, "    RewriteEngine On\n    RewriteRule ^ /index.html [L]\n")
        bench.start()
        plan = wc.compute_plan("apache", NAMES, 3)
        http_final = plan.final.get(os.path.join(bench.sites, "a.conf"))
        assert http_final is None                      # vhost 80 (redirection) intact
        wc.ensure_challenge("apache", NAMES, 3, plan)
        token(bench)
        # Let's Encrypt suit la redirection : le jeton doit etre servi en HTTPS malgre la RewriteRule
        assert bench.get("client-a.fr", "/.well-known/acme-challenge/jeton123", https=True,
                         expect=200) == (200, "preuve")
        assert bench.get("client-a.fr", "/autre", https=True)[1] == "site client\n"
        assert bench.get("client-a.fr", "/x")[0] == 301
        wc.restore("apache", 3)
        assert run_issue(bench, plan.sha256)["success"]

    def test_phase_b_failure_restores(self, bench, monkeypatch):
        bench.site("a.conf", HTTP_VH)
        ssl_site(bench)
        bench.start()
        before = bench.snapshot()
        old = bench.fingerprint("client-a.fr")
        plan = wc.compute_plan("apache", NAMES, 3)
        real = wc.install

        def broken(*a, **k):
            monkeypatch.setattr(bench.env, "apache_test_cmd", ("false",))
            try:
                return real(*a, **k)
            finally:
                monkeypatch.setattr(bench.env, "apache_test_cmd", bench.base + ("-t",))
        monkeypatch.setattr(wc, "install", broken)
        res = run_issue(bench, plan.sha256)
        assert not res["success"] and "INSTALL_ROLLED_BACK" in res["detail"]
        assert bench.snapshot() == before
        assert bench.served_after("client-a.fr", equal=old) == old
        assert cert_store.current_version(3, root=bench.env.certs_root) is None


# --- 3. refus -------------------------------------------------------------------------------
@needs_apache
class TestApacheRefusals:

    def test_no_https_vhost_decision_b(self, bench):
        bench.site("a.conf", HTTP_VH)
        with pytest.raises(wc.WebconfError, match="a2ensite default-ssl"):
            wc.compute_plan("apache", NAMES, 3)

    def test_mod_ssl_missing(self, bench, monkeypatch):
        bench.site("a.conf", HTTP_VH)
        monkeypatch.setattr(bench.env, "apache_modules_cmd", ("true",))
        with pytest.raises(wc.WebconfError, match="a2enmod ssl"):
            wc.compute_plan("apache", NAMES, 3)

    def test_443_without_sslengine(self, bench):
        bench.site("a.conf", "<VirtualHost 127.0.0.1:443>\n    ServerName client-a.fr\n"
                             "    ServerAlias www.client-a.fr\n</VirtualHost>\n")
        with pytest.raises(wc.WebconfError, match="SSLEngine"):
            wc.compute_plan("apache", NAMES, 3)

    def test_certbot_and_extra_names(self, bench):
        bench.site("a-ssl.conf", "<VirtualHost 127.0.0.1:443>\n    ServerName client-a.fr\n"
                                 "    ServerAlias www.client-a.fr\n    SSLEngine on\n"
                                 "    SSLCertificateFile /etc/letsencrypt/live/x/fullchain.pem\n"
                                 "</VirtualHost>\n")
        with pytest.raises(wc.WebconfError, match="certbot"):
            wc.compute_plan("apache", NAMES, 3)
        bench.site("a-ssl.conf", "<VirtualHost 127.0.0.1:443>\n    ServerName client-a.fr\n"
                                 "    ServerAlias www.client-a.fr boutique.fr\n    SSLEngine on\n"
                                 "</VirtualHost>\n")
        with pytest.raises(wc.WebconfError, match="boutique.fr"):
            wc.compute_plan("apache", NAMES, 3)

    def test_names_split_and_not_declared(self, bench):
        bench.site("a.conf", "<VirtualHost 127.0.0.1:443>\n ServerName client-a.fr\n SSLEngine on\n"
                             "</VirtualHost>\n<VirtualHost 127.0.0.1:443>\n ServerName www.client-a.fr\n"
                             " SSLEngine on\n</VirtualHost>\n")
        with pytest.raises(wc.WebconfError, match="differents"):
            wc.compute_plan("apache", NAMES, 3)
        with pytest.raises(wc.WebconfError, match="explicitement"):
            wc.compute_plan("apache", ["autre.fr"], 3)
