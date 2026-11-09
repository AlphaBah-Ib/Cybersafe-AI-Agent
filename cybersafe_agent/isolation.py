# -*- coding: utf-8 -*-
"""
US-SOC-R14 (agent 2.4.0) — isolation controlee d'un serveur Linux.

ISOLATE_HOST n'est PAS un « DROP ALL » : trois chaines dediees (iptables ET ip6tables)
sont inserees en tete de INPUT / OUTPUT / FORWARD et ne laissent passer que :
  - la boucle locale ;
  - les destinations preservees transmises dans l'ordre SIGNE (IP de confiance,
    reseaux de management, infrastructure Cybersafe-AI) : administration et reprise ;
  - le canal HTTPS vers Cybersafe-AI (IP resolues AVANT l'isolation) ;
  - le DNS vers les resolveurs configures, DHCP / DHCPv6, decouverte de voisins IPv6,
    metadonnees du fournisseur (169.254.0.0/16), erreurs ICMP liees.
Tout le reste est rejete, y compris les connexions deja etablies (une session
d'attaquant en cours est coupee) et le trafic route (conteneurs).

Application ATOMIQUE par famille (iptables-restore --noflush) ; si une famille
echoue, tout est retire : jamais d'isolation partielle.

RESTAURATION, toujours possible et prevue AVANT l'isolation :
  1. ordre restore_network (serveur, a l'echeance ou a la demande) ;
  2. minuteur de securite LOCAL (cybersafe-isolation-guard.timer, root, toutes les
     30 s, independant de ce service) : restaure a l'echeance + 10 min, ou si plus
     aucun contact avec Cybersafe-AI depuis 5 min (interrupteur de securite) ;
  3. redemarrage du serveur (regles non persistantes).
L'isolation est REFUSEE si le minuteur local n'a pas tourne recemment.
"""
import ipaddress
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse

logger = logging.getLogger("cybersafe.isolation")

# Chaine dediee par chaine native ; les noms restent sous la limite de 28 caracteres.
CHAINS = (("INPUT", "CYBERSAFE_ISO_IN"), ("OUTPUT", "CYBERSAFE_ISO_OUT"),
          ("FORWARD", "CYBERSAFE_ISO_FWD"))
FAMILIES = ((4, "iptables", "iptables-restore"), (6, "ip6tables", "ip6tables-restore"))

STATE_DIR = "/var/lib/cybersafe/isolation"          # ecrit par le service (cybersafe)
GUARD_DIR = "/var/lib/cybersafe-isolation"          # ecrit par le minuteur (root)
MAX_TTL_SECONDS = 86400
MIN_TTL_SECONDS = 60
LOCAL_GRACE_SECONDS = 600       # le serveur restaure a l'echeance ; le minuteur local ensuite
MIN_CONTACT_TIMEOUT = 300       # interrupteur de securite : 5 min sans contact
GUARD_FRESH_SECONDS = 120       # le minuteur doit avoir tourne dans les 2 dernieres minutes
MAX_PRESERVED = 64
_STATE_MAX_BYTES = 65536
_METADATA_V4 = "169.254.0.0/16"
_NDP_TYPES = ("133", "134", "135", "136", "137")
_RESOLV_FILES = ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf")


def state_path():
    return os.path.join(STATE_DIR, "state.json")


def heartbeat_path():
    return os.path.join(STATE_DIR, "heartbeat")


def guard_stamp_path():
    return os.path.join(GUARD_DIR, "guard.stamp")


def _run(cmd, stdin=None):
    """Commande precise (liste d'arguments, jamais de shell)."""
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=20)
        return r.returncode, (r.stdout or ""), (r.stderr or "").strip()[:300]
    except Exception as exc:  # noqa: BLE001
        return -1, "", "exception: %s" % exc


def is_linux():
    return sys.platform.startswith("linux")


# --- Etat du pare-feu -----------------------------------------------------------

def _jump_present(tool, builtin, chain):
    return _run([tool, "-C", builtin, "-j", chain])[0] == 0


def _chain_exists(tool, chain):
    return _run([tool, "-S", chain])[0] == 0


def isolation_jumps():
    """Sauts d'isolation en place : liste de (outil, chaine native, chaine dediee)."""
    found = []
    for _, tool, _ in FAMILIES:
        if not shutil.which(tool):
            continue
        for builtin, chain in CHAINS:
            if _jump_present(tool, builtin, chain):
                found.append((tool, builtin, chain))
    return found


def is_isolated():
    return bool(isolation_jumps())


def reported_state():
    """[R14-P4] Etat signale au serveur a chaque releve : "isolated", "none" ou None (indetermine).

    Le minuteur de securite peut retablir le reseau sans ordre : le serveur compare cet
    etat a ce qu'il croit, et ne montre jamais « isole » un serveur qui ne l'est plus.
    """
    if not is_linux():
        return None
    try:
        return "isolated" if is_isolated() else "none"
    except Exception:  # noqa: BLE001
        return None


# --- Entrees ----------------------------------------------------------------------

def parse_preserve(raw):
    """Destinations preservees -> (IPv4, IPv6). ValueError si une entree est inacceptable."""
    if raw is None:
        raw = []
    if not isinstance(raw, list) or len(raw) > MAX_PRESERVED:
        raise ValueError("liste des destinations preservees invalide")
    v4, v6 = [], []
    for item in raw:
        if not isinstance(item, str):
            raise ValueError("destination preservee invalide: %r" % (item,))
        net = ipaddress.ip_network(item.strip(), strict=False)
        if net.prefixlen == 0:
            raise ValueError("destination preservee trop large: %s" % net)
        (v4 if net.version == 4 else v6).append(str(net))
    return sorted(set(v4)), sorted(set(v6))


def resolve_api(api_url):
    """IP du canal Cybersafe-AI, resolues AVANT l'isolation, et port HTTPS."""
    parsed = urlparse(api_url or "")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return [], port
    try:
        return [str(ipaddress.ip_address(host))], port
    except ValueError:
        pass
    ips = set()
    try:
        for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
            ips.add(str(ipaddress.ip_address(info[4][0].split("%")[0])))
    except (OSError, ValueError) as exc:
        logger.warning("[isolation] resolution de %s impossible : %s", host, exc)
    return sorted(ips), port


def resolvers(files=_RESOLV_FILES):
    """Resolveurs DNS en amont (hors boucle locale : le resolveur local passe par lo)."""
    out = []
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                try:
                    ip = ipaddress.ip_address(parts[1].split("%")[0])
                except ValueError:
                    continue
                if not ip.is_loopback and str(ip) not in out:
                    out.append(str(ip))
        if out:
            break   # le fichier de systemd-resolved prime sur le stub 127.0.0.53
    return out


# --- Jeu de regles ------------------------------------------------------------------

def build_ruleset(version, preserve, api_ips, api_port, dns, present_jumps=()):
    """Texte pour iptables-restore --noflush (une famille). Aucun « tout ouvrir » possible."""
    IN, OUT, FWD = (c for _, c in CHAINS)
    fam = [n for n in preserve if ipaddress.ip_network(n).version == version]
    api = [ip for ip in api_ips if ipaddress.ip_address(ip).version == version]
    ns = [ip for ip in dns if ipaddress.ip_address(ip).version == version]
    icmp = "icmp" if version == 4 else "ipv6-icmp"
    L = ["*filter", ":%s - [0:0]" % IN, ":%s - [0:0]" % OUT, ":%s - [0:0]" % FWD,
         "-A %s -i lo -j ACCEPT" % IN, "-A %s -o lo -j ACCEPT" % OUT]
    for net in fam:
        L += ["-A %s -s %s -j ACCEPT" % (IN, net), "-A %s -d %s -j ACCEPT" % (OUT, net),
              "-A %s -s %s -j ACCEPT" % (FWD, net), "-A %s -d %s -j ACCEPT" % (FWD, net)]
    for ip in api:
        L += ["-A %s -d %s -p tcp --dport %d -j ACCEPT" % (OUT, ip, api_port),
              "-A %s -s %s -p tcp --sport %d -m conntrack --ctstate ESTABLISHED -j ACCEPT"
              % (IN, ip, api_port)]
    for ip in ns:
        for proto in ("udp", "tcp"):
            L += ["-A %s -d %s -p %s --dport 53 -j ACCEPT" % (OUT, ip, proto),
                  "-A %s -s %s -p %s --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT"
                  % (IN, ip, proto)]
    if version == 4:
        L += ["-A %s -p udp --sport 68 --dport 67 -j ACCEPT" % OUT,
              "-A %s -p udp --sport 67 --dport 68 -j ACCEPT" % IN,
              "-A %s -d %s -j ACCEPT" % (OUT, _METADATA_V4),
              "-A %s -s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT" % (IN, _METADATA_V4)]
    else:
        for t in _NDP_TYPES:
            L += ["-A %s -p ipv6-icmp --icmpv6-type %s -j ACCEPT" % (IN, t),
                  "-A %s -p ipv6-icmp --icmpv6-type %s -j ACCEPT" % (OUT, t)]
        L += ["-A %s -p udp --sport 546 --dport 547 -j ACCEPT" % OUT,
              "-A %s -p udp --sport 547 --dport 546 -j ACCEPT" % IN]
    L += ["-A %s -p %s -m conntrack --ctstate RELATED -j ACCEPT" % (IN, icmp),
          "-A %s -j DROP" % IN, "-A %s -j DROP" % OUT, "-A %s -j DROP" % FWD]
    for builtin, chain in CHAINS:
        if (builtin, chain) in present_jumps:
            L.append("-D %s -j %s" % (builtin, chain))
        L.append("-I %s 1 -j %s" % (builtin, chain))
    L.append("COMMIT")
    return "\n".join(L) + "\n"


# --- Etat local -----------------------------------------------------------------------

def _write_json_atomic(path, data, mode=0o640):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_state():
    """Etat d'isolation : dict, None (absent) ou "invalid" (illisible -> on restaure)."""
    try:
        fd = os.open(state_path(), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    except OSError:
        return "invalid"
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            obj = json.loads(fh.read(_STATE_MAX_BYTES + 1) or "null")
    except (OSError, ValueError):
        return "invalid"
    if not isinstance(obj, dict):
        return "invalid"
    for key in ("started_at", "deadline", "contact_timeout"):
        v = obj.get(key)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return "invalid"
    return obj


def remove_state():
    try:
        os.unlink(state_path())
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("[isolation] suppression de l'etat impossible : %s", exc)


def write_heartbeat(now=None):
    """Contact reussi avec Cybersafe-AI (lu par l'interrupteur de securite)."""
    try:
        _write_json_atomic(heartbeat_path(), {"at": time.time() if now is None else now})
    except OSError as exc:
        logger.debug("[isolation] heartbeat non ecrit : %s", exc)


def _read_number(path, key):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            v = json.loads(fh.read(4096)).get(key)
    except (OSError, ValueError, AttributeError):
        return None
    return None if isinstance(v, bool) or not isinstance(v, (int, float)) else float(v)


def guard_alive(now=None):
    """Le minuteur local (root) a-t-il tourne recemment ?"""
    now = time.time() if now is None else now
    at = _read_number(guard_stamp_path(), "at")
    return at is not None and 0 <= now - at <= GUARD_FRESH_SECONDS


# --- Restauration -----------------------------------------------------------------------

def restore_all():
    """Retire l'isolation (idempotent). Sauts d'abord : le reseau est rouvert immediatement."""
    errors, removed = [], 0
    for _, tool, _ in FAMILIES:
        if not shutil.which(tool):
            continue
        for builtin, chain in CHAINS:
            for _ in range(5):
                if not _jump_present(tool, builtin, chain):
                    break
                rc, _, err = _run([tool, "-D", builtin, "-j", chain])
                if rc != 0:
                    errors.append("%s -D %s: %s" % (tool, builtin, err))
                    break
                removed += 1
        for _, chain in CHAINS:
            if _chain_exists(tool, chain):
                for op in ("-F", "-X"):
                    rc, _, err = _run([tool, op, chain])
                    if rc != 0:
                        errors.append("%s %s %s: %s" % (tool, op, chain, err))
    left = isolation_jumps()
    if left:
        return False, "restauration incomplete, sauts restants: %s ; %s" % (
            ", ".join("%s/%s" % (t, b) for t, b, _ in left), "; ".join(errors)[:300])
    remove_state()
    if removed == 0:
        return True, "reseau deja restaure (aucune isolation en place)"
    return True, "reseau restaure (%d saut(s) d'isolation retire(s))" % removed


# --- Isolation ----------------------------------------------------------------------------

def isolate(order, api_url, poll_interval=60.0, active_ssh=(), now=None):
    """Applique l'isolation. Retourne (succes, detail, regle_constatee)."""
    now = time.time() if now is None else now
    if not is_linux():
        return False, "isolation disponible sur Linux uniquement", None
    missing = [t for _, a, b in FAMILIES for t in (a, b) if not shutil.which(t)]
    if missing:
        return False, "outils absents : %s (isolation refusee)" % ", ".join(missing), None
    if not guard_alive(now):
        return False, ("minuteur de restauration local inactif (cybersafe-isolation-guard.timer) : "
                       "isolation refusee tant que la restauration n'est pas garantie"), None
    ttl = order.get("ttl_seconds")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
        return False, "duree d'isolation invalide (%r)" % (ttl,), None
    try:
        v4, v6 = parse_preserve((order.get("params") or {}).get("preserve"))
    except ValueError as exc:
        return False, str(exc), None
    api_ips, api_port = resolve_api(api_url)
    if not api_ips:
        return False, "canal Cybersafe-AI non resolu : isolation refusee (il serait coupe)", None
    dns = resolvers()
    if not dns:
        return False, "aucun resolveur DNS en amont detecte : isolation refusee", None

    contact_timeout = max(MIN_CONTACT_TIMEOUT, int(3 * float(poll_interval or 60)))
    state = {"order_id": order.get("id"), "started_at": now,
             "deadline": now + ttl + LOCAL_GRACE_SECONDS, "contact_timeout": contact_timeout,
             "preserve": v4 + v6, "api_ips": api_ips, "dns": dns}
    try:
        _write_json_atomic(state_path(), state)       # la restauration est prevue AVANT l'isolation
        write_heartbeat(now)
    except OSError as exc:
        return False, "etat d'isolation non ecrit (%s) : isolation refusee" % exc, None

    present = {(b, c) for t, b, c in isolation_jumps()}
    for version, tool, restore_tool in FAMILIES:
        fam_present = {(b, c) for t, b, c in isolation_jumps() if t == tool} if present else set()
        rules = build_ruleset(version, v4 + v6, api_ips, api_port, dns, fam_present)
        rc, _, err = _run([restore_tool, "--noflush"], stdin=rules)
        if rc != 0:
            ok, undo = restore_all()
            return False, ("%s a echoue (%s) : isolation annulee, %s" % (restore_tool, err, undo))[:500], None

    jumps = isolation_jumps()
    if len(jumps) != len(CHAINS) * len(FAMILIES):
        ok, undo = restore_all()
        return False, "isolation non constatee apres application : annulee, %s" % undo, False

    cut = sorted(ip for ip in set(active_ssh) if not _in_networks(ip, v4 + v6))
    detail = ("serveur isole : %d destination(s) preservee(s), canal Cybersafe-AI %s (port %d), DNS %s ; "
              "restauration locale au plus tard %s UTC" % (
                  len(v4) + len(v6), ",".join(api_ips), api_port, ",".join(dns),
                  time.strftime("%Y-%m-%d %H:%M", time.gmtime(state["deadline"]))))
    if cut:
        detail += " ; sessions SSH coupees (hors destinations preservees) : %s" % ", ".join(cut)
    return True, detail[:500], True


def _in_networks(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in nets:
        n = ipaddress.ip_network(net)
        if n.version == addr.version and addr in n:
            return True
    return False


# --- Minuteur de securite (root, cybersafe-isolation-guard.timer) ----------------------------

def guard_tick(now=None):
    """Un passage du minuteur. Retourne un code d'etat (journalise)."""
    now = time.time() if now is None else now
    try:
        _write_json_atomic(guard_stamp_path(), {"at": now}, mode=0o644)
    except OSError as exc:
        logger.error("[AUDIT] [isolation-guard] horodatage non ecrit : %s", exc)
    if not is_linux():
        return "unsupported"
    state = read_state()
    if not is_isolated():
        if state is not None:
            remove_state()
            logger.info("[AUDIT] [isolation-guard] etat d'isolation orphelin supprime "
                        "(aucune regle en place, ex. apres redemarrage)")
        return "idle"
    if not isinstance(state, dict):
        return _guard_restore("etat d'isolation absent ou illisible")
    deadline = min(float(state["deadline"]),
                   float(state["started_at"]) + MAX_TTL_SECONDS + LOCAL_GRACE_SECONDS)
    if now >= deadline:
        return _guard_restore("echeance atteinte")
    last = max(float(state["started_at"]), _read_number(heartbeat_path(), "at") or 0.0)
    if now - last > max(float(state["contact_timeout"]), MIN_CONTACT_TIMEOUT):
        return _guard_restore("plus aucun contact avec Cybersafe-AI depuis %d s" % int(now - last))
    return "isolated"


def _guard_restore(reason):
    ok, detail = restore_all()
    logger.warning("[AUDIT] [isolation-guard] restauration automatique (%s) -> %s : %s",
                   reason, "OK" if ok else "ECHEC", detail)
    return "restored" if ok else "restore_failed"
