# -*- coding: utf-8 -*-
"""
[CERT04-P2] Execution des ordres de certificats, en ROOT.

Lance par systemd (cybersafe-cert-apply.service), declenche par
cybersafe-cert-apply.path quand le service NON privilegie (cert_service.py)
depose un ordre dans /var/lib/cybersafe/cert/request.json.

Ce programme ne fait confiance a RIEN dans ce fichier (modifiable par
l'utilisateur de l'agent) :
  - lecture sans suivre de lien symbolique, fichier ordinaire, taille bornee ;
  - l'ordre est entierement REVERIFIE (signature dediee, champs, expiration) et
    son nonce consomme dans un journal appartenant a root ;
  - le resultat est ecrit dans un dossier appartenant a root, lisible par le
    groupe de l'agent ; il ne contient JAMAIS de cle privee (controle final).

Types d'ordre :
  - plan          : analyse de la configuration du serveur web, SANS modification ;
  - issue_install : recalcul du plan, refus si son empreinte differe de celle
                    approuvee (signee), emission ACME, installation, verification
                    HTTPS, retour arriere automatique en cas d'echec.
L'analyse et l'installation sur le serveur web sont fournies par cert_webconf
(porte 3) ; sans ce module, les ordres sont refuses proprement.

    python -m cybersafe_agent.cert_apply
"""
import fcntl
import grp
import json
import logging
import os
import stat
import sys
import time

from . import cert_acme, cert_store
from .cert_guard import CertReplayJournal, OrderRejected, guard_cert_order

REQUEST = "/var/lib/cybersafe/cert/request.json"
RESULT_DIR = "/var/lib/cybersafe-cert"
LOCK = "/run/cybersafe-cert-apply.lock"
MAX_BYTES = 256 * 1024
RESULT_TTL = 24 * 3600
AGENT_GROUP = "cybersafe"

logger = logging.getLogger("cybersafe.cert")


class Invalid(Exception):
    pass


def read_request(path=REQUEST):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Invalid("demande illisible (%s)" % (exc.strerror or exc)) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Invalid("demande : fichier ordinaire attendu")
        if st.st_size > MAX_BYTES:
            raise Invalid("demande trop volumineuse")
        data = os.read(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Invalid("demande : JSON invalide") from None
    if not isinstance(obj, dict) or not isinstance(obj.get("order"), dict):
        raise Invalid("demande : ordre absent")
    return obj["order"]


def _webconf():
    try:
        from . import cert_webconf  # porte 3
    except ImportError:
        return None
    return cert_webconf


def _assert_no_secret(result):
    if "PRIVATE KEY" in json.dumps(result).upper():
        raise RuntimeError("resultat contenant une cle privee : jamais ecrit")


def write_result(order_id, result, result_dir=RESULT_DIR):
    _assert_no_secret(result)
    os.makedirs(result_dir, exist_ok=True)
    path = os.path.join(result_dir, "result-%d.json" % order_id)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    # Lisible par le groupe de l'agent (le service non privilegie le remonte) ;
    # explicite car le umask de main() est 077.
    if os.geteuid() == 0:
        try:
            os.fchown(fd, 0, grp.getgrnam(AGENT_GROUP).gr_gid)
        except KeyError:
            pass
    os.fchmod(fd, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(result, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return path


def purge_results(result_dir=RESULT_DIR, now=None):
    now = now or time.time()
    try:
        entries = os.listdir(result_dir)
    except OSError:
        return
    for name in entries:
        if name.startswith("result-") and name.endswith(".json"):
            p = os.path.join(result_dir, name)
            try:
                if now - os.lstat(p).st_mtime > RESULT_TTL:
                    os.unlink(p)
            except OSError:
                pass


def _fail(order_id, detail):
    return {"order_id": order_id, "success": False, "detail": str(detail)[:2000]}


def do_plan(order, webconf):
    plan = webconf.compute_plan(order["web_server"], order["hostnames"],
                                order["certificate_id"])
    return {"order_id": order["id"], "success": True, "detail": "Plan calcule.",
            "plan_sha256": plan.sha256, "diff": plan.diff, "files": plan.files}


def do_issue_install(order, webconf, certs_root=cert_store.CERTS_ROOT, issuer=cert_acme.issue):
    cid, names = order["certificate_id"], order["hostnames"]
    # 1. la configuration n'a pas change depuis l'approbation
    plan = webconf.compute_plan(order["web_server"], names, cid)
    if plan.sha256 != order["plan_sha256"]:
        return _fail(order["id"], "PLAN_CHANGED: la configuration du serveur a change depuis "
                                  "l'approbation ; une nouvelle analyse est necessaire.")
    # 2. extrait de validation HTTP-01 en place (idempotent, teste, retour arriere)
    webconf.ensure_challenge(order["web_server"], names, cid, plan)
    # 3. cle + CSR sur ce serveur, puis emission
    vdir, _csr = cert_store.new_version(cid, names, root=certs_root)
    try:
        leaf, chain = issuer(order["acme_directory"], os.path.join(vdir, "request.csr"), names)
        cert_pem, chain_pem = cert_store.store_certificate(vdir, leaf, chain, names)
    except Exception:
        cert_store.discard(vdir)
        raise
    # 4. activation + installation + verification HTTPS ; sinon retour arriere complet
    previous = cert_store.activate(vdir)
    try:
        webconf.install(order["web_server"], names, cid, plan)
        webconf.verify_https(names, leaf)
    except Exception as exc:
        # Renouvellement : l'ancien certificat d'abord, puis l'ancienne configuration
        # (rechargee par restore). Premiere installation : la configuration d'abord,
        # pour qu'aucune ne reference plus le lien retire ensuite.
        if previous:
            cert_store.rollback(cid, root=certs_root)
            webconf.restore(order["web_server"], cid)
        else:
            webconf.restore(order["web_server"], cid)
            cert_store.deactivate(cid, root=certs_root)
        try:
            cert_store.discard(vdir)
        except cert_store.StoreError:
            pass
        logger.error("[AUDIT] [cert] installation annulee (ordre %s) : %s", order["id"], exc)
        return _fail(order["id"], "INSTALL_ROLLED_BACK: %s" % exc)
    cert_store.prune(cid, root=certs_root)
    return {"order_id": order["id"], "success": True, "plan_sha256": plan.sha256,
            "https_verified": True, "certificate_pem": cert_pem, "chain_pem": chain_pem,
            "detail": "Certificat emis, installe et verifie en HTTPS."}


def execute(order, journal, webconf=None, **kw):
    """Renvoie le resultat (dict) a remonter. Ne leve pas pour un refus attendu."""
    oid = order.get("id") if isinstance(order.get("id"), int) else 0
    try:
        guard_cert_order(order, journal)
    except OrderRejected as exc:
        logger.warning("[AUDIT] [cert] ordre %s refuse : %s", oid, exc)
        return _fail(oid, "ORDER_REJECTED: %s" % exc)
    if webconf is None:
        return _fail(oid, "UNSUPPORTED: installation sur le serveur web pas encore disponible "
                          "dans cette version de l'agent.")
    try:
        if order["kind"] == "plan":
            return do_plan(order, webconf)
        return do_issue_install(order, webconf, **kw)
    except (cert_acme.AcmeError, cert_store.StoreError) as exc:
        return _fail(oid, str(exc))
    except Exception as exc:  # noqa: BLE001 — jamais de trace brute vers le serveur
        logger.exception("[cert] erreur inattendue (ordre %s)", oid)
        return _fail(oid, "INTERNAL_ERROR: %s" % type(exc).__name__)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    if os.geteuid() != 0:
        print("cert_apply doit etre lance en root", file=sys.stderr)
        return 2
    os.umask(0o077)
    lock_fd = os.open(LOCK, os.O_WRONLY | os.O_CREAT, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        purge_results()
        try:
            order = read_request()
        except Invalid as exc:
            logger.warning("[AUDIT] [cert] %s", exc)
            return 1
        if order is None:
            return 0
        journal = CertReplayJournal(RESULT_DIR)
        result = execute(order, journal, webconf=_webconf())
        oid = result.get("order_id") or 0
        if oid:
            write_result(oid, result)
        return 0
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    sys.exit(main())
