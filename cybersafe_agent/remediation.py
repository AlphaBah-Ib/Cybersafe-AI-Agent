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
import hashlib
import ipaddress
import json
import os
import shlex
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlparse

import requests

# [R11-IMPORTS]
from .order_guard import OrderRejected, ReplayJournal, guard_order
from . import proxy_rules  # [R12-P4B]
from .paths import get_state_dir

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
    Retourne 'iptables' si present, sinon None.

    Le service tourne en non-root avec CAP_NET_ADMIN. iptables respecte cette
    capability ; ufw NON (il exige UID 0 : "You need to be root to run this
    script"). On utilise donc iptables directement comme moteur. Les regles
    inserees en tete de chaine INPUT (-I) restent effectives meme si ufw gere
    par ailleurs le firewall (ufw s'appuie lui-meme sur iptables/netfilter).
    """
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
        cmd = [_ipt(ip), "-I", "INPUT", "-s", ip, "-j", "DROP"]
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
        cmd = [_ipt(ip), "-D", "INPUT", "-s", ip, "-j", "DROP"]
    else:
        return False, "aucun firewall detecte"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return (r.returncode == 0), "%s rc=%s" % (fw, r.returncode)
    except Exception as exc:  # noqa: BLE001
        return False, "exception: %s" % exc


def _rule_present(ip, fw):
    """
    v1.8.1 : constat apres un ban - la regle de blocage est-elle en place ?
    `iptables -C` est une verification en LECTURE SEULE (meme privilege que le
    ban). Retourne True (rc 0), False (rc 1 : regle absente), ou None si le
    constat est impossible (autre moteur, erreur, permission) : le serveur ne
    change alors rien.
    """
    if fw != "iptables":
        return None
    try:
        r = subprocess.run([_ipt(ip), "-C", "INPUT", "-s", ip, "-j", "DROP"],
                           capture_output=True, text=True, timeout=15)
    except Exception as exc:  # noqa: BLE001
        logger.debug("[remediation] constat KO pour %s: %s", ip, exc)
        return None
    if r.returncode == 0:
        return True
    if r.returncode == 1:
        return False
    return None


# [R12-P2] ---------------------------------------------------------------------
# Limitation de debit : au-dela de N nouvelles connexions par minute depuis l'IP,
# les suivantes sont rejetees (connexions etablies intactes). La regle porte un
# commentaire « cybersafe-rl:<ip> » pour etre retrouvee et retiree sans connaitre
# ses parametres. Commandes precises, jamais de shell.

def _ipt(ip):
    """iptables pour IPv4, ip6tables pour IPv6."""
    return "ip6tables" if ":" in str(ip) else "iptables"


def _rl_comment(ip):
    return "cybersafe-rl:%s" % ip


def _rl_name(ip):
    # nom de table hashlimit : 15 caracteres au plus
    return "csrl" + hashlib.sha1(str(ip).encode("ascii")).hexdigest()[:11]


def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.returncode, (r.stdout or ""), (r.stderr or "").strip()[:500]
    except Exception as exc:  # noqa: BLE001
        return -1, "", "exception: %s" % exc


def _rate_limit_rules(ip):
    """Regles de limitation existantes pour cette IP (lignes de iptables -S, decoupees)."""
    tool = _ipt(ip)
    rc, out, _ = _run([tool, "-S", "INPUT"])
    if rc != 0:
        return []
    found = []
    for line in out.splitlines():
        try:
            args = shlex.split(line)
        except ValueError:
            continue
        if args[:2] != ["-A", "INPUT"]:
            continue
        for i, arg in enumerate(args[:-1]):
            if arg == "--comment" and args[i + 1] == _rl_comment(ip):
                found.append(args)
                break
    return found


def _remove_rate_limit(ip):
    tool = _ipt(ip)
    if not shutil.which(tool):
        return False, "%s introuvable" % tool
    removed = 0
    for args in _rate_limit_rules(ip):
        rc, _, err = _run([tool, "-D"] + args[1:])
        if rc != 0:
            return False, "%s rc=%s err=%s" % (tool, rc, err)
        removed += 1
    return True, "%s: %d regle(s) de limitation retiree(s)" % (tool, removed)


def _apply_rate_limit(ip, rate_per_minute, burst):
    tool = _ipt(ip)
    if not shutil.which(tool):
        return False, "%s introuvable" % tool
    ok, detail = _remove_rate_limit(ip)  # idempotent : jamais deux regles pour une IP
    if not ok:
        return False, detail
    cmd = [tool, "-I", "INPUT", "-s", ip,
           "-m", "conntrack", "--ctstate", "NEW",
           "-m", "hashlimit", "--hashlimit-name", _rl_name(ip), "--hashlimit-mode", "srcip",
           "--hashlimit-above", "%d/minute" % int(rate_per_minute),
           "--hashlimit-burst", str(int(burst)),
           "-m", "comment", "--comment", _rl_comment(ip),
           "-j", "DROP"]
    rc, out, err = _run(cmd)
    if rc != 0:
        return False, "%s rc=%s err=%s" % (tool, rc, err)
    return True, "%s: limite a %d connexions/min (rafale %d)" % (tool, int(rate_per_minute), int(burst))


# [R12-P3] ---------------------------------------------------------------------
# Blocage de plage : regle DROP sur la plage, reperee par « cybersafe-range:<plage> ».

def _range_comment(net):
    return "cybersafe-range:%s" % net


def _range_contains_any(net, ips):
    """La plage contient-elle une des adresses donnees ? (faux si ce n'est pas une plage)"""
    if "/" not in str(net):
        return False
    try:
        network = ipaddress.ip_network(str(net), strict=False)
    except ValueError:
        return False
    for ip in ips:
        try:
            if ipaddress.ip_address(ip) in network:
                return True
        except ValueError:
            continue
    return False


def _rules_with_comment(tool, comment):
    rc, out, _ = _run([tool, "-S", "INPUT"])
    if rc != 0:
        return []
    found = []
    for line in out.splitlines():
        try:
            args = shlex.split(line)
        except ValueError:
            continue
        if args[:2] != ["-A", "INPUT"]:
            continue
        for i, arg in enumerate(args[:-1]):
            if arg == "--comment" and args[i + 1] == comment:
                found.append(args)
                break
    return found


def _remove_range_block(net):
    tool = _ipt(net)
    if not shutil.which(tool):
        return False, "%s introuvable" % tool
    removed = 0
    for args in _rules_with_comment(tool, _range_comment(net)):
        rc, _, err = _run([tool, "-D"] + args[1:])
        if rc != 0:
            return False, "%s rc=%s err=%s" % (tool, rc, err)
        removed += 1
    return True, "%s: %d regle(s) de plage retiree(s)" % (tool, removed)


def _apply_range_block(net):
    tool = _ipt(net)
    if not shutil.which(tool):
        return False, "%s introuvable" % tool
    ok, detail = _remove_range_block(net)  # idempotent
    if not ok:
        return False, detail
    rc, _, err = _run([tool, "-I", "INPUT", "-s", net,
                       "-m", "comment", "--comment", _range_comment(net), "-j", "DROP"])
    if rc != 0:
        return False, "%s rc=%s err=%s" % (tool, rc, err)
    return True, "%s: plage %s bloquee" % (tool, net)


# [R12-P4] ---------------------------------------------------------------------
# Blocage au reverse proxy (nginx). Ce service n'a PAS le droit d'ecrire dans
# /etc/nginx ni de recharger nginx : il ecrit seulement l'« etat voulu » ; l'unite
# root cybersafe-proxy-apply le revalide, teste nginx, recharge et ecrit un
# statut que l'on attend ici. En cas d'echec, l'etat voulu est remis comme avant :
# aucun blocage orphelin ne peut etre applique plus tard.
_PROXY_DIR = "/var/lib/cybersafe/proxy"
_PROXY_STATUS = "/var/lib/cybersafe-proxy/status.json"
_PROXY_WAIT_SECONDS = 60.0


def _proxy_desired_path():
    return os.path.join(_PROXY_DIR, "desired.json")


def _proxy_read_desired():
    """Etat voulu actuel, ou None s'il est illisible (on n'ecrase jamais a l'aveugle)."""
    try:
        with open(_proxy_desired_path(), "r", encoding="utf-8") as fh:
            obj = json.load(fh)
    except FileNotFoundError:
        return {"generation": 0, "deny": [], "waf": {}, "geo": []}
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict) or not isinstance(obj.get("deny"), list):
        return None
    gen = obj.get("generation")
    if not isinstance(gen, int) or isinstance(gen, bool) or gen < 0:
        return None
    # [R12-P4B] regles WAF et pays (absents des etats ecrits par l'agent 2.2.0).
    obj.setdefault("waf", {})
    obj.setdefault("geo", [])
    if not isinstance(obj["waf"], dict) or not isinstance(obj["geo"], list):
        return None
    return obj


def _proxy_write_desired(generation, deny, waf=None, geo=None):
    os.makedirs(_PROXY_DIR, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".desired-", dir=_PROXY_DIR)
    data = {"generation": generation, "deny": sorted(deny)}
    if waf:  # [R12-P4B] cles absentes quand vides : etat lisible par l'unite 2.2.0
        data["waf"] = {k: waf[k] for k in sorted(waf)}
    if geo:
        data["geo"] = sorted(geo)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, _proxy_desired_path())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _proxy_read_status():
    try:
        with open(_PROXY_STATUS, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError):
        return None


def _proxy_wait(generation, timeout=None):
    """Attend le statut de cette generation (ou d'une plus recente). None si delai depasse."""
    deadline = time.monotonic() + (_PROXY_WAIT_SECONDS if timeout is None else timeout)
    while True:
        st = _proxy_read_status()
        gen = (st or {}).get("generation")
        if isinstance(gen, int) and not isinstance(gen, bool) and gen >= generation:
            return st
        if time.monotonic() >= deadline:
            return None
        time.sleep(1.0)


def _proxy_change(ip, block):
    """Ajoute (block=True) ou retire une adresse du blocage au reverse proxy."""
    try:
        ip = str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return False, "adresse invalide"
    current = _proxy_read_desired()
    if current is None:
        return False, "etat du reverse proxy illisible (%s) : rien n'a ete modifie" % _proxy_desired_path()
    after = set(current["deny"])
    if block:
        after.add(ip)
    else:
        after.discard(ip)
    return _proxy_commit(current, after, current["waf"], current["geo"])


def _proxy_commit(current, deny, waf, geo):
    """[R12-P4B] Ecrit le nouvel etat, attend l'unite root ; en cas d'echec, remet l'etat d'avant."""
    generation = current["generation"] + 1
    try:
        _proxy_write_desired(generation, deny, waf, geo)
    except OSError as exc:
        return False, "ecriture de l'etat voulu impossible : %s" % exc
    st = _proxy_wait(generation)
    if st is not None and st.get("ok"):
        return True, "nginx: %s" % st.get("detail")
    # Echec ou silence : on remet l'etat voulu comme avant.
    try:
        _proxy_write_desired(generation + 1, current["deny"], current["waf"], current["geo"])
    except OSError:
        logger.exception("[remediation] retour arriere de l'etat voulu impossible")
    if st is None:
        return False, ("aucune reponse de cybersafe-proxy-apply (unite non installee, ou "
                       "nginx bloque) : etat precedent remis")
    return False, "nginx: %s" % st.get("detail")

def _waf_change(key, rule, value, add):
    """[R12-P4B] Ajoute ou retire une regle WAF temporaire (revalidee ici)."""
    if not proxy_rules.is_waf_key(key):
        return False, "identifiant de regle WAF invalide"
    if add:
        err = proxy_rules.waf_error(rule, value)
        if err:
            return False, "regle WAF refusee : %s" % err
        if proxy_rules.waf_key(rule, value) != key:
            return False, "regle WAF incoherente avec son identifiant"
    current = _proxy_read_desired()
    if current is None:
        return False, "etat du reverse proxy illisible (%s) : rien n'a ete modifie" % _proxy_desired_path()
    waf = dict(current["waf"])
    if add:
        waf[key] = {"rule": rule, "value": value}
    else:
        waf.pop(key, None)
    if len(waf) > proxy_rules.MAX_WAF_RULES:
        return False, "trop de regles WAF actives sur ce serveur"
    return _proxy_commit(current, current["deny"], waf, current["geo"])


def _geo_change(country, add):
    """[R12-P4B] Bloque ou debloque un pays au reverse proxy."""
    if not proxy_rules.is_country(country):
        return False, "code pays invalide"
    current = _proxy_read_desired()
    if current is None:
        return False, "etat du reverse proxy illisible (%s) : rien n'a ete modifie" % _proxy_desired_path()
    geo = set(current["geo"])
    if add:
        geo.add(country)
    else:
        geo.discard(country)
    if len(geo) > proxy_rules.MAX_COUNTRIES:
        return False, "trop de pays bloques sur ce serveur"
    return _proxy_commit(current, current["deny"], current["waf"], sorted(geo))


def _report(api_url, token, order_id, success, detail, rule_present=None):
    payload = {"success": success, "detail": detail}
    if rule_present is not None:
        payload["rule_present"] = rule_present  # lu par le serveur (v1.8.1+)
    try:
        requests.post(
            _result_url(api_url, order_id),
            json=payload,
            headers={"X-Agent-Token": token,
                     "User-Agent": "Cybersafe-Agent/remediation"},
            timeout=_HTTP_TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("[remediation] report KO order=%s: %s", order_id, exc)


# [R11-HELPERS] US-SOC-R11 — controle des ordres et du canal.
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_journal = None
_journal_lock = threading.Lock()


def _get_journal():
    global _journal
    with _journal_lock:
        if _journal is None:
            _journal = ReplayJournal(get_state_dir())
        return _journal


def _guard_order(order):
    """None si l'ordre peut etre execute, sinon le motif du refus."""
    try:
        guard_order(order, _get_journal())
    except OrderRejected as exc:
        return str(exc)
    return None


def _api_url_is_secure(api_url):
    """https:// exige, sauf http:// vers la machine locale (developpement)."""
    try:
        parsed = urlparse(api_url or "")
        host = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme == "https":
        return True
    return parsed.scheme == "http" and host in _LOCAL_HOSTS


def _process_order(order, api_url, token):
    """Traite un ordre. Applique les garde-fous, execute, rapporte."""
    oid = order.get("id")
    action = order.get("action")
    ip = (order.get("target_ip") or "").strip()

    # [R11-PROCESS-GUARD] signature, expiration, usage unique, action, IP : AVANT tout.
    refus = _guard_order(order)
    if refus:
        logger.warning("[AUDIT] [remediation] ordre REFUSE order=%r action=%r ip=%r : %s",
                       oid, action, ip, refus)
        if oid is not None:
            _report(api_url, token, oid, False, ("R11 refus agent: %s" % refus)[:250])
        return

    if not ip:
        _report(api_url, token, oid, False, "target_ip vide")
        return

    # GARDE-FOU anti-lockout : ne pas bannir une IP de session SSH active.
    # [R12-P2] ni la limiter : une limitation peut bloquer une reconnexion.
    if action in ("ban_ip", "rate_limit_ip", "block_ip_range"):  # [R12-P3] plage comprise
        active = _active_ssh_source_ips()
        if ip in active or _range_contains_any(ip, active):
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
    elif action == "rate_limit_ip":
        p = order.get("params") or {}
        ok, detail = _apply_rate_limit(ip, p["rate_per_minute"], p["burst"])
    elif action == "remove_rate_limit":
        ok, detail = _remove_rate_limit(ip)
    elif action == "block_ip_range":
        ok, detail = _apply_range_block(ip)
    elif action == "unblock_ip_range":
        ok, detail = _remove_range_block(ip)
    elif action == "block_at_reverse_proxy":  # [R12-P4]
        ok, detail = _proxy_change(ip, True)
    elif action == "unblock_at_reverse_proxy":
        ok, detail = _proxy_change(ip, False)
    elif action == "temporary_waf_rule":  # [R12-P4B]
        p = order.get("params") or {}
        ok, detail = _waf_change(ip, p.get("rule"), p.get("value"), True)
    elif action == "remove_waf_rule":
        ok, detail = _waf_change(ip, None, None, False)
    elif action == "geo_block_country":
        ok, detail = _geo_change(ip, True)
    elif action == "geo_unblock_country":
        ok, detail = _geo_change(ip, False)
    else:
        ok, detail = False, "action inconnue: %s" % action

    # v1.8.1 : apres un ban reussi, constat de la regle (lecture seule).
    rule = _rule_present(ip, fw) if (ok and action == "ban_ip") else None
    if rule is False:
        logger.warning("[remediation] order=%s regle absente apres le ban de %s", oid, ip)
    level = logging.INFO if ok else logging.WARNING
    logger.log(level, "[remediation] order=%s %s %s -> %s (%s)",
               oid, action, ip, "OK" if ok else "FAIL", detail)
    _report(api_url, token, oid, ok, detail, rule_present=rule)


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
    # [R11-HTTPS-LOOP] jamais d'ordres de pare-feu sur un canal non chiffre.
    if not _api_url_is_secure(api_url):
        logger.error("[AUDIT] [remediation] api_url non HTTPS (%r) : remediation NON "
                     "demarree. Corriger api_url dans la configuration puis redemarrer "
                     "cybersafe-remediation.", api_url)
        stop_event.wait()  # pas de boucle de redemarrage systemd
        return
    logger.info("[remediation] active (intervalle %ss)", interval)
    while not stop_event.is_set():
        _poll_once(api_url, token)
        if stop_event.wait(timeout=interval):
            break
