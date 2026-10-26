# -*- coding: utf-8 -*-
"""
US-SOC-R12 porte 4a — application des blocages au reverse proxy (nginx).

Lance en ROOT par systemd (cybersafe-proxy-apply.service), declenche par
cybersafe-proxy-apply.path des que le service de remediation (NON privilegie)
modifie l'etat voulu (/var/lib/cybersafe/proxy/desired.json).

Ce programme ne fait confiance a RIEN dans ce fichier (il est modifiable par
l'utilisateur de l'agent) :
  - lecture sans suivre de lien symbolique, fichier ordinaire, taille bornee ;
  - chaque entree est revalidee : une adresse IP seule, jamais la boucle locale,
    une adresse non specifiee, multicast ou lien local ; nombre d'entrees borne ;
  - il n'ecrit QUE /etc/nginx/conf.d/cybersafe-blocklist.conf, des lignes
    « deny <ip>; » generees ici ;
  - « nginx -t » AVANT tout rechargement ; en cas d'echec, l'ancien fichier est
    restaure et nginx n'est PAS recharge ;
  - verifie que le fichier est bien inclus par la configuration active (sinon
    le blocage serait sans effet : echec annonce, pas de faux succes) ;
  - le statut est ecrit dans un repertoire appartenant a root.

    python -m cybersafe_agent.proxy_apply
"""
import datetime
import fcntl
import ipaddress
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

DESIRED = "/var/lib/cybersafe/proxy/desired.json"
STATUS_DIR = "/var/lib/cybersafe-proxy"
CONF_DIR = "/etc/nginx/conf.d"
CONF_NAME = "cybersafe-blocklist.conf"
LOCK = "/run/cybersafe-proxy-apply.lock"
MAX_BYTES = 1024 * 1024
MAX_ENTRIES = 5000
HEADER = ("# Genere par Cybersafe-AI (blocage au reverse proxy).\n"
          "# Ne pas modifier a la main : ce fichier est reecrit a chaque changement.\n")


class Invalid(Exception):
    pass


def _conf_path():
    return os.path.join(CONF_DIR, CONF_NAME)


def _status_path():
    return os.path.join(STATUS_DIR, "status.json")


def read_desired(path=None):
    """Lit l'etat voulu sans suivre de lien symbolique. Absent : etat vide."""
    path = path or DESIRED
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {"generation": 0, "deny": []}
    except OSError as exc:
        raise Invalid("etat voulu illisible (%s)" % (exc.strerror or exc)) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Invalid("etat voulu : fichier ordinaire attendu")
        if st.st_size > MAX_BYTES:
            raise Invalid("etat voulu trop volumineux")
        data = os.read(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Invalid("etat voulu : JSON invalide") from None


def generation_of(obj):
    gen = obj.get("generation") if isinstance(obj, dict) else None
    if isinstance(gen, int) and not isinstance(gen, bool) and gen >= 0:
        return gen
    return None


def validate(obj):
    """Renvoie (generation, adresses triees). Leve Invalid au moindre doute."""
    if not isinstance(obj, dict):
        raise Invalid("etat voulu : objet attendu")
    gen = generation_of(obj)
    if gen is None:
        raise Invalid("generation invalide")
    deny = obj.get("deny")
    if not isinstance(deny, list):
        raise Invalid("liste « deny » attendue")
    if len(deny) > MAX_ENTRIES:
        raise Invalid("trop d'adresses (%d au plus)" % MAX_ENTRIES)
    out = set()
    for raw in deny:
        if not isinstance(raw, str) or "/" in raw:
            raise Invalid("entree invalide : une adresse IP seule est attendue")
        try:
            ip = ipaddress.ip_address(raw.strip())
        except ValueError:
            raise Invalid("adresse invalide : %r" % raw[:60]) from None
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            raise Invalid("adresse interdite au blocage : %s" % ip)
        out.add(ip)
    return gen, sorted(out, key=lambda i: (i.version, int(i)))


def render(ips):
    return HEADER + "".join("deny %s;\n" % ip for ip in ips)


def _nginx_bin():
    found = shutil.which("nginx")
    if found:
        return found
    for candidate in ("/usr/sbin/nginx", "/usr/local/sbin/nginx"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return -1, "", str(exc)


def _last_line(text):
    """Cause la plus utile : la premiere ligne [emerg] ou [crit], sinon la derniere."""
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    for line in lines:
        if "[emerg]" in line or "[crit]" in line:
            return line[:300]
    return (lines[-1] if lines else "sans message")[:300]


def _write_atomic(path, content, mode=0o644):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".cybersafe-", dir=directory)  # sans .conf : ignore par nginx
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
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


def _read_conf():
    try:
        with open(_conf_path(), "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def _restore(old):
    if old is None:
        try:
            os.unlink(_conf_path())
        except FileNotFoundError:
            pass
    else:
        _write_atomic(_conf_path(), old)


def write_status(generation, ok, detail, count=None):
    os.makedirs(STATUS_DIR, mode=0o755, exist_ok=True)
    payload = {"generation": generation, "ok": bool(ok), "detail": str(detail)[:400],
               "count": count,
               "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    _write_atomic(_status_path(), json.dumps(payload, ensure_ascii=False) + "\n")
    return payload


def apply_once():
    """Une passe : etat voulu -> fichier nginx verifie -> rechargement. Renvoie le statut."""
    try:
        obj = read_desired()
    except Invalid as exc:
        return write_status(None, False, str(exc))
    gen = generation_of(obj)
    try:
        gen, ips = validate(obj)
    except Invalid as exc:
        return write_status(gen, False, "etat voulu refuse : %s" % exc)
    nginx = _nginx_bin()
    if nginx is None or not os.path.isdir(CONF_DIR):
        return write_status(gen, False, "nginx absent sur ce serveur (ou %s manquant)" % CONF_DIR)

    new = render(ips)
    old = _read_conf()
    changed = new != old
    if changed:
        _write_atomic(_conf_path(), new)
    rc, _, err = _run([nginx, "-t"])
    if rc != 0:
        if changed:
            _restore(old)
        return write_status(gen, False, "configuration nginx refusee (%s) : version precedente "
                                        "restauree, nginx non recharge" % _last_line(err))
    rc, out, _ = _run([nginx, "-T"])
    if rc != 0 or ("# configuration file %s:" % _conf_path()) not in out:
        if changed:
            _restore(old)
        return write_status(gen, False, "%s n'est pas pris en compte par nginx (ajouter "
                                        "« include %s/*.conf; » dans le bloc http)" % (_conf_path(), CONF_DIR))
    if changed:
        rc, _, err = _run([nginx, "-s", "reload"])
        if rc != 0:
            _restore(old)
            return write_status(gen, False, "rechargement de nginx impossible (%s) : version "
                                            "precedente restauree" % _last_line(err))
    return write_status(gen, True, "%d adresse(s) bloquee(s) au reverse proxy%s"
                        % (len(ips), "" if changed else " (inchange)"), count=len(ips))


def main():
    os.umask(0o022)
    try:
        lock = open(LOCK, "w")
        fcntl.flock(lock, fcntl.LOCK_EX)
    except OSError:
        lock = None
    try:
        status = apply_once()
    except Exception as exc:  # noqa: BLE001
        try:
            status = write_status(None, False, "erreur inattendue : %s" % exc)
        except Exception:  # noqa: BLE001
            print("[cybersafe-proxy-apply] erreur inattendue : %s" % exc)
            return 1
    print("[cybersafe-proxy-apply] generation=%s ok=%s %s"
          % (status.get("generation"), status.get("ok"), status.get("detail")))
    if lock is not None:
        lock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
