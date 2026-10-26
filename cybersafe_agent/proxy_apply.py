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
import re
import shutil
import stat
import subprocess
import sys
import tempfile

from . import proxy_rules as rules  # [R12-P4B]

DESIRED = "/var/lib/cybersafe/proxy/desired.json"
STATUS_DIR = "/var/lib/cybersafe-proxy"
CONF_DIR = "/etc/nginx/conf.d"
CONF_NAME = "cybersafe-blocklist.conf"
LOCK = "/run/cybersafe-proxy-apply.lock"
MAX_BYTES = 1024 * 1024
MAX_ENTRIES = 5000
HEADER = ("# Genere par Cybersafe-AI (blocage au reverse proxy).\n"
          "# Ne pas modifier a la main : ce fichier est reecrit a chaque changement.\n")


# [R12-P4B] fichier a inclure une fois dans chaque bloc server ; base GeoIP2.
ENFORCE_DIR = "/etc/nginx/cybersafe"
ENFORCE_NAME = "enforce.conf"
GEOIP_DB = "/var/lib/GeoIP/GeoLite2-Country.mmdb"
ENFORCE_TEXT = (
    "# Genere par Cybersafe-AI. A inclure UNE FOIS dans chaque bloc server :\n"
    "#     include /etc/nginx/cybersafe/enforce.conf;\n"
    "# Les variables sont definies dans /etc/nginx/conf.d/cybersafe-blocklist.conf.\n"
    "if ($cybersafe_waf_path) { return 403; }\n"
    "if ($cybersafe_waf_ua) { return 403; }\n"
    "if ($cybersafe_waf_method) { return 403; }\n"
    "if ($cybersafe_geo_block) { return 403; }\n"
)


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


# [R12-P4B] ---------------------------------------------------------------------
# Regles WAF temporaires et blocage geographique. Les variables sont TOUJOURS
# definies (meme vides) dans le fichier conf.d ; enforce.conf, inclus une fois par
# l'administrateur dans chaque bloc server, ne contient que des « return 403 ».
# Le fichier conf.d n'est jamais supprime une fois installe : un include orphelin
# ne peut pas casser nginx.
_SERVER_RE = re.compile(r"^\s*server\s*\{", re.MULTILINE)


def _enforce_path():
    return os.path.join(ENFORCE_DIR, ENFORCE_NAME)


def validate_rules(obj):
    """Renvoie (regles WAF [(regle, valeur)], pays [code]) revalides. Leve Invalid."""
    waf = obj.get("waf", {}) if isinstance(obj, dict) else {}
    geo = obj.get("geo", []) if isinstance(obj, dict) else []
    if not isinstance(waf, dict) or len(waf) > rules.MAX_WAF_RULES:
        raise Invalid("regles WAF illisibles ou trop nombreuses")
    out = []
    for key, rule in waf.items():
        if not isinstance(rule, dict) or not rules.is_waf_key(key):
            raise Invalid("regle WAF illisible")
        err = rules.waf_error(rule.get("rule"), rule.get("value"))
        if err:
            raise Invalid("regle WAF refusee : %s" % err)
        if rules.waf_key(rule["rule"], rule["value"]) != key:
            raise Invalid("regle WAF incoherente avec sa cle")
        out.append((rule["rule"], rule["value"]))
    if not isinstance(geo, list) or len(geo) > rules.MAX_COUNTRIES:
        raise Invalid("liste de pays illisible ou trop longue")
    for code in geo:
        if not rules.is_country(code):
            raise Invalid("code pays invalide")
    return sorted(set(out)), sorted(set(geo))


def render_full(ips, waf, geo):
    text = render(ips)
    text += "\n# Regles WAF temporaires et blocage par pays (lus par %s)\n" % _enforce_path()
    for source, variable, kind in (("$uri", "$cybersafe_waf_path", "block_path"),
                                   ("$http_user_agent", "$cybersafe_waf_ua", "block_user_agent"),
                                   ("$request_method", "$cybersafe_waf_method", "block_method")):
        text += "map %s %s {\n    default 0;\n" % (source, variable)
        for rule, value in waf:
            if rule == kind:
                text += '    "%s" 1;\n' % rules.nginx_pattern(rule, value)
        text += "}\n"
    if geo:
        text += "geoip2 %s {\n    $cybersafe_country_code country iso_code;\n}\n" % GEOIP_DB
        text += "map $cybersafe_country_code $cybersafe_geo_block {\n    default 0;\n"
        text += "".join('    "%s" 1;\n' % code for code in geo)
        text += "}\n"
    else:
        text += "map $remote_addr $cybersafe_geo_block {\n    default 0;\n}\n"
    return text


def _read_enforce():
    try:
        with open(_enforce_path(), "r", encoding="utf-8") as fh:
            return fh.read()
    except (FileNotFoundError, NotADirectoryError):
        return None


def _restore_enforce(old):
    if old is None:
        try:
            os.unlink(_enforce_path())
        except FileNotFoundError:
            pass
    else:
        _write_atomic(_enforce_path(), old)


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
    """Une passe : etat voulu -> fichiers nginx verifies -> rechargement. Renvoie le statut."""
    try:
        obj = read_desired()
    except Invalid as exc:
        return write_status(None, False, str(exc))
    gen = generation_of(obj)
    try:
        gen, ips = validate(obj)
        waf, geo = validate_rules(obj)  # [R12-P4B]
    except Invalid as exc:
        return write_status(gen, False, "etat voulu refuse : %s" % exc)
    nginx = _nginx_bin()
    if nginx is None or not os.path.isdir(CONF_DIR):
        return write_status(gen, False, "nginx absent sur ce serveur (ou %s manquant)" % CONF_DIR)
    if geo and not os.path.isfile(GEOIP_DB):
        return write_status(gen, False, "base GeoIP absente (%s) : blocage par pays impossible. "
                                        "Installer la base GeoLite2-Country (geoipupdate)." % GEOIP_DB)

    new = render_full(ips, waf, geo)
    old = _read_conf()
    changed = new != old
    old_enforce = _read_enforce()
    enforce_changed = os.path.isdir(ENFORCE_DIR) and old_enforce != ENFORCE_TEXT

    def undo():
        """Remet les fichiers precedents, sauf si cela rendait la configuration invalide
        (ex. enforce.conf deja inclus par un site) : la version nouvelle, elle, a passe
        nginx -t. La configuration sur disque reste toujours valide."""
        if changed:
            _restore(old)
        if enforce_changed:
            _restore_enforce(old_enforce)
        if (changed or enforce_changed) and _run([nginx, "-t"])[0] != 0:
            if changed:
                _write_atomic(_conf_path(), new)
            if enforce_changed:
                _write_atomic(_enforce_path(), ENFORCE_TEXT)
            return "nouvelle version conservee sur disque (seule valide), nginx non recharge"
        return "version precedente restauree"

    if changed:
        _write_atomic(_conf_path(), new)
    if enforce_changed:
        _write_atomic(_enforce_path(), ENFORCE_TEXT)
    rc, _, err = _run([nginx, "-t"])
    if rc != 0:
        if changed:  # la nouvelle version est refusee : retour simple a l'ancienne
            _restore(old)
        if enforce_changed:
            _restore_enforce(old_enforce)
        cause = _last_line(err)
        if 'unknown directive "geoip2"' in (err or ""):
            cause = "module GeoIP2 absent (apt install libnginx-mod-http-geoip2)"
        return write_status(gen, False, "configuration nginx refusee (%s) : version precedente "
                                        "restauree, nginx non recharge" % cause)
    rc, out, _ = _run([nginx, "-T"])
    if rc != 0 or ("# configuration file %s:" % _conf_path()) not in out:
        done = undo()
        return write_status(gen, False, "%s n'est pas pris en compte par nginx (ajouter "
                                        "« include %s/*.conf; » dans le bloc http) : %s"
                            % (_conf_path(), CONF_DIR, done))
    coverage = ""
    if waf or geo:
        includes = len(re.findall(r"^[ 	]*include[ 	]+%s[ 	]*;" % re.escape(_enforce_path()), out, re.MULTILINE))
        if ("# configuration file %s:" % _enforce_path()) not in out or includes == 0:
            done = undo()
            return write_status(gen, False, "regles WAF ou pays non applicables : ajouter « include %s; » "
                                            "dans chaque bloc server de nginx : %s" % (_enforce_path(), done))
        servers = len(_SERVER_RE.findall(out))
        coverage = " ; enforce.conf inclus dans %d bloc(s) server sur %d" % (includes, servers)
        if includes < servers:
            coverage += " (ATTENTION : blocs non proteges)"
    if changed or enforce_changed:
        rc, _, err = _run([nginx, "-s", "reload"])
        if rc != 0:
            done = undo()
            return write_status(gen, False, "rechargement de nginx impossible (%s) : %s"
                                % (_last_line(err), done))
    parts = ["%d adresse(s) bloquee(s) au reverse proxy" % len(ips)]
    if waf:
        parts.append("%d regle(s) WAF" % len(waf))
    if geo:
        parts.append("pays bloque(s) : %s" % ", ".join(geo))
    return write_status(gen, True, ", ".join(parts) + coverage
                        + ("" if (changed or enforce_changed) else " (inchange)"), count=len(ips))


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
