# -*- coding: utf-8 -*-
"""
[CERT04-P2] Canal des certificats cote agent : controle des ordres, magasin de
cles, emission lego (simulee), execution root, service non privilegie.

    python -m pytest tests/test_cert_p2.py -v

Une paire de cles de test est injectee (monkeypatch) : jamais la vraie cle.
"""
import base64
import hashlib
import json
import os
import stat
import threading
import time
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from cybersafe_agent import cert_acme, cert_apply, cert_guard as g, cert_service, cert_store
from cybersafe_agent.order_guard import canonical

_FMT = "%Y-%m-%dT%H:%M:%SZ"
NAMES = ["client-a.fr", "www.client-a.fr"]
STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
SHA = "a" * 64


# --- fixtures -------------------------------------------------------------------
@pytest.fixture
def key(monkeypatch):
    k = Ed25519PrivateKey.generate()
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(g, "_CERT_ORDER_PUBLIC_KEY_B64", base64.b64encode(raw).decode())
    return k


def make_order(k, **over):
    now = datetime.now(timezone.utc)
    o = {"id": 11, "channel": "cert", "kind": "plan", "agent_id": 7, "certificate_id": 3,
         "hostnames": list(NAMES), "web_server": "nginx", "acme_directory": STAGING,
         "plan_sha256": "", "issued_at": now.strftime(_FMT),
         "expires_at": (now + timedelta(minutes=10)).strftime(_FMT),
         "nonce": uuid.uuid4().hex}
    o.update(over)
    o["sig_alg"] = "ed25519-cert-v1"
    o["signature"] = base64.b64encode(k.sign(canonical(o, g.SIGNED_FIELDS))).decode()
    return o


@pytest.fixture
def journal(tmp_path):
    return g.CertReplayJournal(str(tmp_path / "state"))


@pytest.fixture
def certs_root(tmp_path):
    base = tmp_path / "etc"
    base.mkdir(mode=0o700)
    return str(base / "certs")


def _ca():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(ca_key.public_key()).serial_number(1)
          .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    return ca_key, ca


def sign_csr(csr_pem, names=None):
    """Simule l'AC : signe la cle publique du CSR (ou force d'autres noms)."""
    csr = x509.load_pem_x509_csr(csr_pem)
    ca_key, ca = _ca()
    now = datetime.now(timezone.utc)
    leaf = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca.subject)
            .public_key(csr.public_key()).serial_number(77)
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=45))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in (names or NAMES)]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    return leaf.public_bytes(pem) + ca.public_bytes(pem)


# --- 1. controle des ordres -----------------------------------------------------------
class TestGuard:

    def test_production_key_is_valid(self):
        assert len(base64.b64decode(g._CERT_ORDER_PUBLIC_KEY_B64)) == 32

    def test_valid_plan_and_issue_orders(self, key, journal):
        g.guard_cert_order(make_order(key), journal)
        g.guard_cert_order(make_order(key, kind="issue_install", plan_sha256=SHA), journal)

    def test_backend_canonical_compat(self, key, journal):
        """Memes octets que backend/apps/certificates/signing.py (champs tries, compacts)."""
        o = make_order(key)
        expected = json.dumps({f: o[f] for f in g.SIGNED_FIELDS}, sort_keys=True,
                              separators=(",", ":"), ensure_ascii=True).encode("ascii")
        assert canonical(o, g.SIGNED_FIELDS) == expected
        assert set(g.SIGNED_FIELDS) >= {"channel", "plan_sha256", "hostnames"}

    @pytest.mark.parametrize("over,msg", [
        ({"channel": "soc"}, "canal"),
        ({"kind": "revoke"}, "type"),
        ({"web_server": "iis"}, "service web"),
        ({"acme_directory": "https://evil.example/directory"}, "annuaire"),
        ({"hostnames": ["www.client-a.fr", "client-a.fr"]}, "noms"),
        ({"hostnames": ["*.client-a.fr"]}, "noms"),
        ({"hostnames": ["intranet.local"]}, "noms"),
        ({"hostnames": []}, "noms"),
        ({"plan_sha256": SHA}, "empreinte"),
        ({"kind": "issue_install", "plan_sha256": ""}, "empreinte"),
        ({"certificate_id": 0}, "certificate_id"),
    ])
    def test_rejects_bad_fields(self, key, journal, over, msg):
        with pytest.raises(g.OrderRejected, match=msg):
            g.guard_cert_order(make_order(key, **over), journal)

    def test_rejects_tampering(self, key, journal):
        o = make_order(key)
        o["hostnames"] = ["autre-client.fr"]
        with pytest.raises(g.OrderRejected, match="signature invalide"):
            g.guard_cert_order(o, journal)

    def test_rejects_soc_signature_and_other_key(self, key, journal):
        o = make_order(key)
        o["sig_alg"] = "ed25519-v2"
        with pytest.raises(g.OrderRejected, match="algorithme"):
            g.guard_cert_order(o, journal)
        other = make_order(Ed25519PrivateKey.generate())
        with pytest.raises(g.OrderRejected, match="signature invalide"):
            g.guard_cert_order(other, journal)

    def test_rejects_expired_and_replay(self, key, journal):
        old = datetime.now(timezone.utc) - timedelta(hours=1)
        o = make_order(key, issued_at=old.strftime(_FMT),
                       expires_at=(old + timedelta(minutes=10)).strftime(_FMT))
        with pytest.raises(g.OrderRejected, match="expire"):
            g.guard_cert_order(o, journal)
        ok = make_order(key)
        g.guard_cert_order(ok, journal)
        with pytest.raises(g.OrderRejected, match="rejoue"):
            g.guard_cert_order(ok, journal)

    def test_invalid_order_does_not_burn_nonce(self, key, journal):
        o = make_order(key)
        bad = dict(o, signature=base64.b64encode(b"x" * 64).decode())
        with pytest.raises(g.OrderRejected):
            g.guard_cert_order(bad, journal)
        g.guard_cert_order(o, journal)  # le vrai ordre passe toujours

    def test_agent_id_binding(self, key, journal):
        with pytest.raises(g.OrderRejected, match="autre agent"):
            g.guard_cert_order(make_order(key), journal, agent_id=8)


# --- 2. magasin de cles --------------------------------------------------------------
class TestStore:

    def test_key_generated_locally_private(self, certs_root):
        vdir, csr_pem = cert_store.new_version(3, NAMES, root=certs_root)
        mode = stat.S_IMODE(os.stat(os.path.join(vdir, "privkey.pem")).st_mode)
        assert mode == 0o600
        assert stat.S_IMODE(os.stat(vdir).st_mode) == 0o700
        csr = x509.load_pem_x509_csr(csr_pem)
        sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert sorted(sans.get_values_for_type(x509.DNSName)) == NAMES
        assert b"PRIVATE" not in csr_pem

    def test_store_activate_rollback(self, certs_root):
        v1, csr1 = cert_store.new_version(3, NAMES, root=certs_root)
        leaf, chain = cert_store.split_pem_chain(sign_csr(csr1))
        cert_pem, chain_pem = cert_store.store_certificate(v1, leaf, chain, NAMES)
        assert "PRIVATE" not in cert_pem + chain_pem
        assert cert_store.activate(v1) is None
        v2, csr2 = cert_store.new_version(3, NAMES, root=certs_root)
        leaf2, chain2 = cert_store.split_pem_chain(sign_csr(csr2))
        cert_store.store_certificate(v2, leaf2, chain2, NAMES)
        assert cert_store.activate(v2) == os.path.basename(v1)
        assert cert_store.current_version(3, root=certs_root) == os.path.basename(v2)
        assert cert_store.rollback(3, root=certs_root) == os.path.basename(v1)
        assert cert_store.current_version(3, root=certs_root) == os.path.basename(v1)

    def test_rejects_cert_for_other_key(self, certs_root):
        v1, _ = cert_store.new_version(3, NAMES, root=certs_root)
        _, other_csr = cert_store.new_version(4, NAMES, root=certs_root)
        leaf, chain = cert_store.split_pem_chain(sign_csr(other_csr))
        with pytest.raises(cert_store.StoreError, match="cle"):
            cert_store.store_certificate(v1, leaf, chain, NAMES)

    def test_rejects_san_mismatch_and_private_key_bundle(self, certs_root):
        v1, csr = cert_store.new_version(3, NAMES, root=certs_root)
        leaf, chain = cert_store.split_pem_chain(sign_csr(csr, names=NAMES + ["evil.fr"]))
        with pytest.raises(cert_store.StoreError, match="noms"):
            cert_store.store_certificate(v1, leaf, chain, NAMES)
        with open(os.path.join(v1, "privkey.pem"), "rb") as fh:
            with pytest.raises(cert_store.StoreError, match="cle privee"):
                cert_store.split_pem_chain(sign_csr(csr) + fh.read())

    def test_prune_keeps_current_and_previous(self, certs_root):
        made = []
        for _ in range(5):
            v, csr = cert_store.new_version(3, NAMES, root=certs_root)
            leaf, chain = cert_store.split_pem_chain(sign_csr(csr))
            cert_store.store_certificate(v, leaf, chain, NAMES)
            cert_store.activate(v)
            made.append(os.path.basename(v))
            time.sleep(0.01)
        cert_store.prune(3, root=certs_root, keep=2)
        left = sorted(e for e in os.listdir(cert_store.cert_dir(3, certs_root)) if e.startswith("v"))
        assert made[-1] in left and made[-2] in left and len(left) == 2

    def test_discard_refuses_active_version(self, certs_root):
        v, csr = cert_store.new_version(3, NAMES, root=certs_root)
        cert_store.activate(v)
        with pytest.raises(cert_store.StoreError):
            cert_store.discard(v)


# --- 3. lego ----------------------------------------------------------------------------
def _fake_lego(tmp_path, body):
    p = tmp_path / "lego"
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(0o755)
    return str(p), hashlib.sha256(p.read_bytes()).hexdigest()


class TestAcme:

    def test_fail_closed_without_pinned_digest(self, monkeypatch):
        monkeypatch.setattr(cert_acme, "LEGO_SHA256", {})
        with pytest.raises(cert_acme.AcmeError, match="empreinte absente"):
            cert_acme._expected_sha256()

    def test_rejects_wrong_digest_and_writable_binary(self, tmp_path):
        path, digest = _fake_lego(tmp_path, "exit 0\n")
        with pytest.raises(cert_acme.AcmeError, match="empreinte inattendue"):
            cert_acme.open_verified_lego(path, "0" * 64)
        os.chmod(path, 0o777)
        with pytest.raises(cert_acme.AcmeError, match="modifiable"):
            cert_acme.open_verified_lego(path, digest)

    def test_rejects_symlinked_binary(self, tmp_path):
        path, digest = _fake_lego(tmp_path, "exit 0\n")
        link = tmp_path / "lego-link"
        os.symlink(path, link)
        with pytest.raises(cert_acme.AcmeError):
            cert_acme.open_verified_lego(str(link), digest)

    def test_real_exec_through_fd(self, tmp_path, certs_root, monkeypatch):
        """Execution reelle du binaire verifie via /proc/self/fd (pas de fenetre TOCTOU)."""
        vdir, csr = cert_store.new_version(3, NAMES, root=certs_root)
        bundle = tmp_path / "bundle.pem"
        bundle.write_bytes(sign_csr(csr))
        args_log = tmp_path / "args.txt"
        script = ('echo "$@" > %s\n'
                  'while [ $# -gt 0 ]; do [ "$1" = "--path" ] && P="$2"; shift; done\n'
                  'mkdir -p "$P/certificates" && cp %s "$P/certificates/client-a.fr.crt"\n'
                  % (args_log, bundle))
        path, digest = _fake_lego(tmp_path, script)
        monkeypatch.setattr(cert_acme, "ACME_HOME", str(tmp_path / "acme"))
        leaf, chain = cert_acme.issue(STAGING, os.path.join(vdir, "request.csr"), NAMES,
                                      lego_path=path, data_dir=str(tmp_path / "acme" / "lego"),
                                      webroot=str(tmp_path / "webroot"), expected_sha256=digest)
        cert_store.store_certificate(vdir, leaf, chain, NAMES)
        args = args_log.read_text()
        for expected in ("--csr", "--accept-tos", "--http.webroot", STAGING, " run"):
            assert expected in args
        assert "privkey" not in args
        assert not os.path.exists(tmp_path / "acme" / "lego" / "certificates")

    def test_lego_failure_and_key_in_output(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cert_acme, "ACME_HOME", str(tmp_path / "acme"))
        path, digest = _fake_lego(tmp_path, "echo 'urn:acme:error:unauthorized'; exit 1\n")
        with pytest.raises(cert_acme.AcmeError, match="unauthorized"):
            cert_acme.issue(STAGING, "/nonexistent.csr", NAMES, lego_path=path,
                            data_dir=str(tmp_path / "acme" / "lego"),
                            webroot=str(tmp_path / "w"), expected_sha256=digest)
        assert cert_acme._clean_output(b"-----BEGIN PRIVATE KEY-----") == "[sortie masquee]"


# --- 4. execution root ---------------------------------------------------------------------
class FakeWebconf:
    def __init__(self, sha=SHA, install_error=None):
        self.sha, self.install_error, self.calls = sha, install_error, []

    def compute_plan(self, web_server, names, cid):
        self.calls.append("plan")
        return types.SimpleNamespace(sha256=self.sha, diff="+ include x;", files=["/etc/nginx/a"])

    def ensure_challenge(self, *a):
        self.calls.append("challenge")

    def install(self, *a):
        self.calls.append("install")
        if self.install_error:
            raise RuntimeError(self.install_error)

    def verify_https(self, names, leaf):
        self.calls.append("verify")

    def restore(self, *a):
        self.calls.append("restore")


def _issuer(directory, csr_path, names):
    with open(csr_path, "rb") as fh:
        return cert_store.split_pem_chain(sign_csr(fh.read()))


class TestApply:

    def test_plan(self, key, journal):
        res = cert_apply.execute(make_order(key), journal, webconf=FakeWebconf())
        assert res["success"] and res["plan_sha256"] == SHA and res["files"]

    def test_issue_install_success(self, key, journal, certs_root):
        wc = FakeWebconf()
        res = cert_apply.execute(make_order(key, kind="issue_install", plan_sha256=SHA), journal,
                                 webconf=wc, certs_root=certs_root, issuer=_issuer)
        assert res["success"] and res["https_verified"] is True
        assert "PRIVATE" not in json.dumps(res)
        assert wc.calls == ["plan", "challenge", "install", "verify"]
        assert cert_store.current_version(3, root=certs_root)

    def test_plan_changed_refused_before_any_issuance(self, key, journal, certs_root):
        wc = FakeWebconf(sha="b" * 64)
        res = cert_apply.execute(make_order(key, kind="issue_install", plan_sha256=SHA), journal,
                                 webconf=wc, certs_root=certs_root, issuer=_issuer)
        assert not res["success"] and res["detail"].startswith("PLAN_CHANGED")
        assert wc.calls == ["plan"]
        assert not os.path.exists(certs_root)

    def test_install_failure_rolls_back_first_install(self, key, journal, certs_root):
        wc = FakeWebconf(install_error="nginx -t a echoue")
        res = cert_apply.execute(make_order(key, kind="issue_install", plan_sha256=SHA), journal,
                                 webconf=wc, certs_root=certs_root, issuer=_issuer)
        assert not res["success"] and "INSTALL_ROLLED_BACK" in res["detail"]
        assert wc.calls[-1] == "restore"
        assert cert_store.current_version(3, root=certs_root) is None
        assert not [e for e in os.listdir(cert_store.cert_dir(3, certs_root)) if e.startswith("v")]

    def test_install_failure_on_renewal_restores_previous(self, key, journal, certs_root):
        cert_apply.execute(make_order(key, kind="issue_install", plan_sha256=SHA), journal,
                           webconf=FakeWebconf(), certs_root=certs_root, issuer=_issuer)
        first = cert_store.current_version(3, root=certs_root)
        res = cert_apply.execute(make_order(key, kind="issue_install", plan_sha256=SHA), journal,
                                 webconf=FakeWebconf(install_error="reload KO"),
                                 certs_root=certs_root, issuer=_issuer)
        assert not res["success"]
        assert cert_store.current_version(3, root=certs_root) == first

    def test_issuance_failure_discards_version(self, key, journal, certs_root):
        def boom(*a):
            raise cert_acme.AcmeError("emission refusee : rate limited")
        res = cert_apply.execute(make_order(key, kind="issue_install", plan_sha256=SHA), journal,
                                 webconf=FakeWebconf(), certs_root=certs_root, issuer=boom)
        assert not res["success"] and "rate limited" in res["detail"]
        assert not [e for e in os.listdir(cert_store.cert_dir(3, certs_root)) if e.startswith("v")]

    def test_without_webconf_and_rejected_order(self, key, journal):
        assert cert_apply.execute(make_order(key), journal)["detail"].startswith("UNSUPPORTED")
        bad = make_order(key)
        bad["hostnames"] = ["pirate.fr"]
        res = cert_apply.execute(bad, journal, webconf=FakeWebconf())
        assert res["detail"].startswith("ORDER_REJECTED")

    def test_read_request_refuses_symlink_and_garbage(self, tmp_path):
        target = tmp_path / "t.json"
        target.write_text(json.dumps({"order": {"id": 1}}))
        link = tmp_path / "request.json"
        os.symlink(target, link)
        with pytest.raises(cert_apply.Invalid):
            cert_apply.read_request(str(link))
        bad = tmp_path / "bad.json"
        bad.write_text("{oops")
        with pytest.raises(cert_apply.Invalid):
            cert_apply.read_request(str(bad))
        assert cert_apply.read_request(str(tmp_path / "absent.json")) is None

    def test_write_result_never_writes_private_key(self, tmp_path):
        with pytest.raises(RuntimeError):
            cert_apply.write_result(5, {"x": "-----BEGIN EC PRIVATE KEY-----"}, str(tmp_path))
        p = cert_apply.write_result(5, {"success": True}, str(tmp_path))
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o640


# --- 5. service non privilegie ----------------------------------------------------------------
class TestService:

    def test_sanitize_blocks_private_key_and_unknown_fields(self):
        out = cert_service.sanitize({"success": True, "detail": "ok", "secret": "x",
                                     "certificate_pem": "-----BEGIN PRIVATE KEY-----"})
        assert out == {"success": False,
                       "detail": "LOCAL_SAFETY_BLOCK: resultat bloque par l'agent."}
        assert "secret" not in cert_service.sanitize({"success": True, "secret": "x"})

    def test_process_order_round_trip(self, key, journal, tmp_path):
        req, res_dir = tmp_path / "req", tmp_path / "res"
        res_dir.mkdir()
        order = make_order(key)
        (res_dir / ("result-%d.json" % order["id"])).write_text(json.dumps(
            {"order_id": order["id"], "success": True, "plan_sha256": SHA, "diff": "d",
             "files": ["/etc/nginx/a"]}))
        posted = []
        cert_service.process_order(order, "https://api.test/api", "tok", journal,
                                   threading.Event(),
                                   post=lambda url, **kw: posted.append((url, kw["json"])),
                                   request_dir=str(req), result_dir=str(res_dir))
        assert json.loads((req / "request.json").read_text())["order"]["id"] == order["id"]
        assert posted[0][0].endswith("/certs/agents/orders/11/result/")
        assert posted[0][1]["success"] is True and posted[0][1]["plan_sha256"] == SHA

    def test_invalid_order_reported_without_waking_root(self, key, journal, tmp_path):
        bad = make_order(key)
        bad["web_server"] = "iis"
        posted = []
        cert_service.process_order(bad, "https://api.test/api", "tok", journal, threading.Event(),
                                   post=lambda url, **kw: posted.append(kw["json"]),
                                   request_dir=str(tmp_path / "req"),
                                   result_dir=str(tmp_path / "res"))
        assert not (tmp_path / "req").exists()
        assert posted[0]["detail"].startswith("ORDER_REJECTED")

    def test_refuses_plain_http(self):
        assert not cert_service._secure("http://api.cybersafe-ai.com/api")
        assert cert_service._secure("https://api.cybersafe-ai.com/api")
