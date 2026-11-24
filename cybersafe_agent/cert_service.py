# -*- coding: utf-8 -*-
"""
[CERT04-P2] Service des certificats, NON privilegie (utilisateur cybersafe,
aucune capability).

Boucle : releve les ordres signes sur /api/certs/agents/orders/, les controle
une premiere fois (refus immediat des ordres invalides, sans reveiller root),
les depose un par un pour cybersafe-cert-apply (root), attend le resultat et le
remonte au serveur.

Ce service ne manipule jamais de cle privee : il n'y a pas acces (magasin en
0700 root) et refuse de remonter un resultat qui en contiendrait une.

    python -m cybersafe_agent.cert_service --config /etc/cybersafe/config.yaml
"""
import argparse
import json
import logging
import os
import signal
import sys
import tempfile
import threading
import time
from urllib.parse import urlparse

import requests

from .cert_guard import CertReplayJournal, OrderRejected, guard_cert_order
from .config import load_config
from .paths import get_state_dir

logger = logging.getLogger("cybersafe.cert")

REQUEST_DIR = "/var/lib/cybersafe/cert"
RESULT_DIR = "/var/lib/cybersafe-cert"
HTTP_TIMEOUT = 15.0
RESULT_WAIT = {"plan": 120, "issue_install": 900}
POLL_INTERVAL = 60.0
MAX_RESULT_BYTES = 256 * 1024


def _orders_url(api_url):
    return "%s/certs/agents/orders/" % api_url.rstrip("/")


def _result_url(api_url, order_id):
    return "%s/certs/agents/orders/%d/result/" % (api_url.rstrip("/"), order_id)


def _headers(token):
    return {"X-Agent-Token": token, "User-Agent": "Cybersafe-Agent/cert"}


def _secure(api_url):
    p = urlparse(api_url or "")
    return p.scheme == "https" or (p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1"))


def write_request(order, request_dir=REQUEST_DIR):
    os.makedirs(request_dir, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".request-", dir=request_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"order": order}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, os.path.join(request_dir, "request.json"))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_result(order_id, result_dir=RESULT_DIR):
    path = os.path.join(result_dir, "result-%d.json" % order_id)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        data = os.read(fd, MAX_RESULT_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_RESULT_BYTES:
        return {"success": False, "detail": "RESULT_TOO_LARGE"}
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"success": False, "detail": "RESULT_UNREADABLE"}
    return obj if isinstance(obj, dict) else {"success": False, "detail": "RESULT_UNREADABLE"}


def wait_result(order_id, timeout, stop_event, result_dir=RESULT_DIR, step=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not stop_event.is_set():
        res = read_result(order_id, result_dir)
        if res is not None:
            return res
        stop_event.wait(step)
    return None


def sanitize(result):
    """Ce qui part vers le serveur. Jamais de cle privee : rapport remplace."""
    allowed = ("success", "detail", "plan_sha256", "diff", "files", "https_verified",
               "certificate_pem", "chain_pem")
    out = {k: result[k] for k in allowed if k in result}
    if "PRIVATE KEY" in json.dumps(out).upper():
        logger.critical("[AUDIT] [cert] resultat contenant une cle privee : NON transmis")
        return {"success": False, "detail": "LOCAL_SAFETY_BLOCK: resultat bloque par l'agent."}
    out["success"] = out.get("success") is True
    return out


def report(api_url, token, order_id, payload, post=requests.post):
    try:
        post(_result_url(api_url, order_id), json=payload, headers=_headers(token),
             timeout=HTTP_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[cert] remontee KO (ordre %s) : %s", order_id, exc)


def process_order(order, api_url, token, journal, stop_event, *, post=requests.post,
                  request_dir=REQUEST_DIR, result_dir=RESULT_DIR):
    oid = order.get("id") if isinstance(order, dict) and isinstance(order.get("id"), int) else None
    if oid is None:
        logger.warning("[AUDIT] [cert] ordre sans identifiant ignore")
        return
    try:
        guard_cert_order(order, journal)
    except OrderRejected as exc:
        logger.warning("[AUDIT] [cert] ordre %s refuse : %s", oid, exc)
        report(api_url, token, oid, {"success": False, "detail": "ORDER_REJECTED: %s" % exc}, post)
        return
    write_request(order, request_dir)
    res = wait_result(oid, RESULT_WAIT.get(order.get("kind"), 120), stop_event, result_dir)
    if res is None:
        if stop_event.is_set():
            return  # arret : le serveur expirera l'ordre (30 min)
        res = {"success": False, "detail": "LOCAL_TIMEOUT: l'execution n'a pas abouti a temps."}
    report(api_url, token, oid, sanitize(res), post)


def poll_once(api_url, token, journal, stop_event, get=requests.get, post=requests.post):
    try:
        r = get(_orders_url(api_url), headers=_headers(token), timeout=HTTP_TIMEOUT)
        if r.status_code != 200:
            logger.debug("[cert] releve HTTP %s", r.status_code)
            return
        orders = (r.json() or {}).get("orders", [])
    except Exception as exc:  # noqa: BLE001
        logger.debug("[cert] releve KO : %s", exc)
        return
    for order in orders if isinstance(orders, list) else []:
        if stop_event.is_set():
            return
        process_order(order, api_url, token, journal, stop_event, post=post)


def loop(config, stop_event):
    api_url, token = config.api_url, config.token
    if not _secure(api_url):
        logger.error("[AUDIT] [cert] api_url non HTTPS (%r) : service des certificats NON demarre.",
                     api_url)
        stop_event.wait()
        return
    journal = CertReplayJournal(get_state_dir())
    interval = float(getattr(config, "cert_poll_interval", POLL_INTERVAL) or POLL_INTERVAL)
    logger.info("[cert] actif (intervalle %ss)", interval)
    while not stop_event.is_set():
        poll_once(api_url, token, journal, stop_event)
        if stop_event.wait(timeout=interval):
            break


def main(argv=None):
    p = argparse.ArgumentParser(prog="cybersafe-cert")
    p.add_argument("--config", dest="config_path", default=None)
    args = p.parse_args(argv)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s"))
    root = logging.getLogger("cybersafe")
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    config = load_config(path=args.config_path)
    stop_event = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())
    loop(config, stop_event)
    return 0


if __name__ == "__main__":
    sys.exit(main())
