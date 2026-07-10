# -*- coding: utf-8 -*-
"""
SOC-RESPONSE — service de remediation (execution des ordres ban/unban IP).

Architecture (Option A) : ce module tourne dans un SERVICE SYSTEMD SEPARE
(cybersafe-remediation), distinct de l'agent de collecte. Ce service dispose
de la capability CAP_NET_ADMIN (accordee par systemd), ce qui lui permet
d'appeler ufw/iptables DIRECTEMENT, sans sudo. L'agent principal reste
totalement passif et durci (aucun privilege).

Canal DESCENDANT : le service interroge periodiquement le backend pour ses
ordres 'pending', les execute localement, puis remonte le resultat.

GARDE-FOUS cote service (en plus de l'allowlist backend) :
  - anti-lockout : ne JAMAIS bannir une IP ayant une session SSH active locale ;
  - commande PRECISE (liste d'arguments, jamais de shell) ;
  - privilege minimal : CAP_NET_ADMIN uniquement (pas root complet, pas de sudo).
"""
import logging
import shutil
import subprocess
import threading

import requests

logger = logging.getLogger("cybersafe.remediation")

_HTTP_TIMEOUT = 10.0


def _orders_url(api_url):
    return f"{api_url.rstrip('/')}/soc/agents/orders/"


def _result_url(api_url, order_id):
    return f"{api_url.rstrip('/')}/soc/agents/orders/{order_id}/result/"


def _active_ssh_source_ips():
    """
    IP sources des sessions SSH actives locales (anti-lockout).
    Best-effort : si la detection echoue, retourne set() (on ne bloque pas,
    l'allowlist backend reste le garde-fou principal).
    """
    ips = set()
    try:
        out = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            # ex: "root  pts/0  2026-07-09 20:00 (203.0.113.5)"
            if "(" in line and ")" in line:
                ip = line[line.rfind("(") + 1:line.rfind(")")].strip()
                if ip and not ip.startswith(":"):  # ignore les X displays
                    ips.add(ip)
    except Exception as exc:  # noqa: BLE001
        logger.debug("[remediation] who KO: %s", exc)
    return ips


def _detect_firewall():
    """
    Retourne 'ufw' si dispo et actif, sinon 'iptables' si present, sinon None.
    Appel direct (le service a CAP_NET_ADMIN, pas besoin de sudo).
    """
    if shutil.which("ufw"):
        try:
            out = subprocess.run(["ufw", "status"],
                                 capture_output=True, text=True, timeout=5)
            if "active" in out.stdout.lower() or "actif" in out.stdout.lower():
                return "ufw"
        except Exception:  # noqa: BLE001
            pass
    if shutil.which("iptables"):
        return "iptables"
    return None


def _apply_ban(ip, fw):
    """
    Execute le ban (commande precise, pas de shell, pas de sudo).
    Retourne (success: bool, detail: str).
    """
    if fw == "ufw":
        cmd = ["ufw", "deny", "from", ip]
    elif fw == "iptables":
        cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    else:
        return False, "aucun firewall (ufw/iptables) detecte"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return True, "%s: %s" % (fw, (r.stdout or "").strip()[:500])
        return False, "%s rc=%s err=%s" % (fw, r.returncode, (r.stderr or "").strip()[:500])
    except Exception as exc:  # noqa: BLE001
        return False, "exception: %s" % exc


def _apply_unban(ip, fw):
    if fw == "ufw":
        cmd = ["ufw", "delete", "deny", "from", ip]
    elif fw == "iptables":
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    else:
        return False, "aucun firewall detecte"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return (r.returncode == 0), "%s rc=%s" % (fw, r.returncode)
    except Exception as exc:  # noqa: BLE001
        return False, "exception: %s" % exc


def _report(api_url, token, order_id, success, detail):
    try:
        requests.post(
            _result_url(api_url, order_id),
            json={"success": success, "detail": detail},
            headers={"X-Agent-Token": token,
                     "User-Agent": "Cybersafe-Agent/remediation"},
            timeout=_HTTP_TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("[remediation] report KO order=%s: %s", order_id, exc)


def _process_order(order, api_url, token):
    """Traite un ordre. Applique les garde-fous, execute, rapporte."""
    oid = order.get("id")
    action = order.get("action")
    ip = (order.get("target_ip") or "").strip()

    if not ip:
        _report(api_url, token, oid, False, "target_ip vide")
        return

    # GARDE-FOU anti-lockout : ne pas bannir une IP de session SSH active.
    if action == "ban_ip":
        active = _active_ssh_source_ips()
        if ip in active:
            logger.warning("[remediation] ANTI-LOCKOUT: refus de bannir %s "
                           "(session SSH active)", ip)
            _report(api_url, token, oid, False,
                    "anti-lockout: IP d'une session SSH active, ban refuse")
            return

    fw = _detect_firewall()
    if action == "ban_ip":
        ok, detail = _apply_ban(ip, fw)
    elif action == "unban_ip":
        ok, detail = _apply_unban(ip, fw)
    else:
        ok, detail = False, "action inconnue: %s" % action

    level = logging.INFO if ok else logging.WARNING
    logger.log(level, "[remediation] order=%s %s %s -> %s (%s)",
               oid, action, ip, "OK" if ok else "FAIL", detail)
    _report(api_url, token, oid, ok, detail)


def _poll_once(api_url, token):
    """Recupere les ordres pending et les traite. Best-effort."""
    try:
        r = requests.get(
            _orders_url(api_url),
            headers={"X-Agent-Token": token,
                     "User-Agent": "Cybersafe-Agent/remediation"},
            timeout=_HTTP_TIMEOUT,
        )
        if r.status_code != 200:
            logger.debug("[remediation] pull HTTP %s", r.status_code)
            return
        orders = (r.json() or {}).get("orders", [])
    except Exception as exc:  # noqa: BLE001
        logger.debug("[remediation] pull KO: %s", exc)
        return

    for order in orders:
        _process_order(order, api_url, token)


def remediation_loop(config, stop_event):
    """
    Boucle : interroge le backend toutes les `remediation_poll_interval` secondes.
    S'arrete proprement quand stop_event est arme.
    """
    interval = getattr(config, "remediation_poll_interval", 60.0)
    api_url = config.api_url
    token = config.token
    logger.info("[remediation] active (intervalle %ss)", interval)
    while not stop_event.is_set():
        _poll_once(api_url, token)
        if stop_event.wait(timeout=interval):
            break
