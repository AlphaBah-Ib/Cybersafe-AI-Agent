# -*- coding: utf-8 -*-
"""
US-SOC-R15 (agent 2.5.0) — reponse sur processus : unite ROOT cybersafe-process-apply.

Lance par systemd (cybersafe-process-apply.service), declenche par
cybersafe-process-apply.path des que le service de remediation (NON privilegie)
depose une demande dans /var/lib/cybersafe/process/request.json.

Ce programme ne fait confiance a RIEN dans ce fichier (il est modifiable par
l'utilisateur de l'agent) ; le service n'est qu'un messager :
  - lecture sans suivre de lien symbolique, fichier ordinaire, taille bornee ;
  - l'ordre SIGNE est entierement re-verifie ICI (signature Ed25519, expiration,
    action de la liste processus uniquement, parametres, cible) ;
  - journal anti-rejeu PROPRE, dans un dossier appartenant a root : un ordre ne
    s'execute qu'une fois, meme si la demande est redeposee ;
  - le processus est re-identifie par son empreinte signee et signale par pidfd
    (process_ops.act) ; jamais l'environnement du processus n'est lu ;
  - le resultat est ecrit dans /var/lib/cybersafe-process (root:cybersafe 0750).

    python -m cybersafe_agent.process_apply
"""
import fcntl
import json
import os
import stat
import sys
import tempfile
import time

from . import order_guard as guard
from . import process_ops as ops

REQUEST = "/var/lib/cybersafe/process/request.json"
STATE_DIR = "/var/lib/cybersafe-process"
MAX_BYTES = 256 * 1024
KEEP_RESULTS = 20


class Invalid(Exception):
    pass


def result_path(order_id):
    return os.path.join(STATE_DIR, "result-%d.json" % order_id)


def read_request(path=None):
    path = path or REQUEST
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


def _write_atomic(path, payload):
    fd, tmp = tempfile.mkstemp(prefix=".result-", dir=STATE_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)  # le dossier (root:cybersafe 0750) restreint la lecture
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _prune():
    try:
        names = [n for n in os.listdir(STATE_DIR) if n.startswith("result-") and n.endswith(".json")]
    except OSError:
        return
    paths = sorted((os.path.join(STATE_DIR, n) for n in names), key=lambda p: os.path.getmtime(p))
    for p in paths[:-KEEP_RESULTS]:
        try:
            os.unlink(p)
        except OSError:
            pass


def execute(order):
    """Ordre deja verifie -> (ok, detail, preuve)."""
    action = order["action"]
    if action == "inspect_process":
        return ops.inspect(order["target_ip"])
    return ops.act(action, order["params"]["fingerprint"])


def apply_once(request_path=None, now=None):
    """Une passe : demande -> verification complete -> action -> resultat. Renvoie le resultat."""
    try:
        order = read_request(request_path)
    except Invalid as exc:
        print("[cybersafe-process-apply] demande refusee : %s" % exc)
        return None
    if order is None:
        return None
    oid = order.get("id")
    if isinstance(oid, bool) or not isinstance(oid, int) or oid <= 0:
        print("[cybersafe-process-apply] demande refusee : identifiant d'ordre invalide")
        return None
    out = result_path(oid)
    if os.path.exists(out):
        return None  # deja traite (redeclenchement) : le resultat existant n'est jamais ecrase
    try:
        if order.get("action") not in guard.PROCESS_ACTIONS:
            raise guard.OrderRejected("action hors du perimetre processus: %r" % (order.get("action"),))
        guard.guard_order(order, guard.ReplayJournal(STATE_DIR), now=now)
    except guard.OrderRejected as exc:
        ok, detail, evidence = False, "refus de l'unite root : %s" % exc, None
    else:
        try:
            ok, detail, evidence = execute(order)
        except Exception as exc:  # noqa: BLE001
            ok, detail, evidence = False, "erreur inattendue : %s" % exc, None
    result = {"order_id": oid, "nonce": order.get("nonce"), "ok": bool(ok),
              "detail": str(detail)[:1500], "evidence": evidence,
              "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    _write_atomic(out, result)
    _prune()
    print("[cybersafe-process-apply] [AUDIT] ordre=%s action=%s cible=%s ok=%s %s"
          % (oid, order.get("action"), order.get("target_ip"), result["ok"], result["detail"]))
    return result


def main():
    os.umask(0o022)
    lock = None
    try:
        os.makedirs(STATE_DIR, mode=0o750, exist_ok=True)
        lock = open(os.path.join(STATE_DIR, ".lock"), "w")
        fcntl.flock(lock, fcntl.LOCK_EX)
    except OSError:
        lock = None
    try:
        apply_once()
    except Exception as exc:  # noqa: BLE001
        print("[cybersafe-process-apply] erreur inattendue : %s" % exc)
        return 1
    finally:
        if lock is not None:
            lock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
