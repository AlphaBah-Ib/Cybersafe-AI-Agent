# -*- coding: utf-8 -*-
"""
[CERT04-P3] Configuration du serveur web pour les certificats geres (ROOT).

API utilisee par cert_apply :
    compute_plan(web_server, hostnames, cid)      -> Plan    (LECTURE SEULE)
    ensure_challenge(web_server, hostnames, cid, plan)       phase A : validation HTTP-01
    install(web_server, hostnames, cid, plan)                phase B : directives TLS
    verify_https(hostnames, leaf, plan)                      certificat servi = certificat emis
    restore(web_server, cid)                                 retour a l'etat d'avant la phase A

Principes :
  - le plan est deterministe et son empreinte couvre le CONTENU D'ORIGINE des
    fichiers : toute modification de la configuration apres l'approbation change
    l'empreinte, et l'ordre signe est alors refuse ;
  - uniquement des ajouts de lignes (include, listen) et la mise en commentaire
    d'anciennes directives ssl_certificate, ligne par ligne ; jamais de reecriture ;
  - chaque phase : sauvegarde, ecriture atomique, `nginx -t`, rechargement
    (reload, jamais restart) ; au moindre echec, restauration puis nouveau test ;
  - au moindre doute, refus explicite (WebconfError) sans rien modifier.
Nginx et Apache 2.4 (Debian / Ubuntu : apache2, apachectl, sites-enabled).
"""
import difflib
import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass, field

from . import cert_store
from .apache_conf import ApacheConfError, ApacheConfig
from .nginx_conf import NginxConfError, NginxConfig

MARK = "# cybersafe-ai"
VERIFY_STREAK = 3
MAX_DIFF = 200_000


class WebconfError(Exception):
    """Refus ou echec ; message affichable (francais), sans secret."""


@dataclass
class Env:
    """Chemins et commandes (remplaces dans les tests)."""
    nginx_main: str = "/etc/nginx/nginx.conf"
    snippet_dir: str = "/etc/nginx/cybersafe"
    certs_root: str = cert_store.CERTS_ROOT
    webroot: str = "/var/lib/cybersafe-acme-webroot"
    backup_dir: str = "/var/lib/cybersafe-cert/backups"
    letsencrypt_dir: str = "/etc/letsencrypt"
    panel_markers: tuple = ("/usr/local/psa", "/usr/local/cpanel", "/usr/local/directadmin")
    nginx_test_cmd: tuple = ("nginx", "-t", "-q")
    nginx_reload_cmd: tuple = ("systemctl", "reload", "nginx")
    apache_main: str = "/etc/apache2/apache2.conf"
    apache_server_root: str = None
    apache_snippet_dir: str = "/etc/apache2/cybersafe"
    apache_test_cmd: tuple = ("apachectl", "configtest")
    apache_reload_cmd: tuple = ("systemctl", "reload", "apache2")
    apache_modules_cmd: tuple = ("apachectl", "-M")
    https_port: int = 443
    verify_timeout: float = 15.0


ENV = Env()


@dataclass
class Plan:
    web_server: str
    certificate_id: int
    hostnames: list
    sha256: str = ""
    diff: str = ""
    files: list = field(default_factory=list)
    originals: dict = field(default_factory=dict)   # chemin -> contenu d'origine (None = absent)
    phase_a: dict = field(default_factory=dict)     # chemin -> contenu apres la phase A
    final: dict = field(default_factory=dict)       # chemin -> contenu final
    https_addr: str = "127.0.0.1"


def _sha(text):
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest() if text is not None else ""


def _run(cmd, timeout=60):
    try:
        p = subprocess.run(list(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)
    return p.returncode, (p.stdout or b"").decode("utf-8", "replace")[-1500:]


# --- analyse Nginx ----------------------------------------------------------------
def _listen_info(arg_list):
    """(port, ipv6, address, ssl) d'une directive listen ; port None si socket unix."""
    addr = arg_list[0] if arg_list else "80"
    opts = set(arg_list[1:])
    if addr.startswith("unix:"):
        return None, False, None, False
    ipv6 = addr.startswith("[")
    host = None
    if addr.isdigit():
        port = int(addr)
    elif ipv6:
        host, _, rest = addr[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 80
    elif ":" in addr:
        host, _, p = addr.rpartition(":")
        port = int(p) if p.isdigit() else 80
    else:
        host, port = addr, 80
    if host in ("*", "", "::", "0.0.0.0"):
        host = None
    return port, ipv6, host, "ssl" in opts


class _Block:
    def __init__(self, st):
        self.st = st
        self.names = []
        self.listens = []
        self.ssl_on = False
        self.returns = False
        self.ssl_cert_stmts = []
        self.has_challenge_location = False
        self.includes = set()
        for ch in st.block:  # directives propres au bloc (fichier du bloc)
            if ch.directive == "server_name":
                self.names += [a.lower() for a in ch.args]
            elif ch.directive == "listen":
                self.listens.append(_listen_info(ch.args))
            elif ch.directive == "ssl" and ch.args == ["on"]:
                self.ssl_on = True
            elif ch.directive == "return":
                self.returns = True
            elif ch.directive == "include" and ch.args:
                self.includes.add(ch.args[0])
        for ch in NginxConfig.children(st.block):  # include compris
            if ch.directive in ("ssl_certificate", "ssl_certificate_key"):
                self.ssl_cert_stmts.append(ch)
            elif ch.directive == "location" and any("acme-challenge" in a for a in ch.args):
                self.has_challenge_location = True
        if not self.listens:
            self.listens.append((80, False, None, False))

    @property
    def https(self):
        return any(p == 443 and (s or self.ssl_on) for p, _6, _h, s in self.listens)

    @property
    def http(self):
        return any(p == 80 and not s for p, _6, _h, s in self.listens)

    @property
    def http_ipv6(self):
        return any(p == 80 and v6 for p, v6, _h, _s in self.listens)

    def https_host(self):
        for p, _6, h, s in self.listens:
            if p == 443 and h and not h.startswith(("[", ":")) and ":" not in h:
                return h
        return "127.0.0.1"


def _snippets(env, cid):
    challenge = os.path.join(env.snippet_dir, "acme-challenge.conf")
    certconf = os.path.join(env.snippet_dir, "certs", "%d.conf" % cid)
    live = os.path.join(cert_store.cert_dir(cid, env.certs_root), "current")
    return {
        challenge: (
            "# Gere par Cybersafe-AI : validation HTTP-01 des certificats geres. Ne pas modifier.\n"
            "location ^~ /.well-known/acme-challenge/ {\n"
            "    root %s;\n"
            "    default_type \"text/plain\";\n"
            "    try_files $uri =404;\n"
            "}\n" % env.webroot),
        certconf: (
            "# Gere par Cybersafe-AI : certificat gere n. %d. Ne pas modifier.\n"
            "ssl_certificate %s/fullchain.pem;\n"
            "ssl_certificate_key %s/privkey.pem;\n" % (cid, live, live)),
    }, challenge, certconf


def _refusal_checks(env, names):
    for marker in env.panel_markers:
        if os.path.exists(marker):
            raise WebconfError("Panneau d'hebergement detecte (%s) : le serveur web est gere par "
                               "le panneau, Cybersafe-AI n'y touche pas." % marker)
    for n in names:
        if os.path.exists(os.path.join(env.letsencrypt_dir, "renewal", "%s.conf" % n)):
            raise WebconfError("%s est deja gere par certbot. La reprise d'un certbot existant "
                               "n'est pas encore proposee." % n)


def _indent_of(line):
    return line[:len(line) - len(line.lstrip())]


def _single_statement_line(text_lines, st, directive):
    line = text_lines[st.line - 1]
    body = line.split("#", 1)[0].strip()
    return body.startswith(directive) and body.endswith(";") and body.count(";") == 1


def _nginx_plan(env, names, cid):
    names = sorted(names)
    _refusal_checks(env, names)
    try:
        conf = NginxConfig(env.nginx_main)
    except NginxConfError as exc:
        raise WebconfError("Configuration Nginx illisible : %s" % exc) from None

    blocks = [_Block(s) for s in conf.servers()]
    per_name = {}
    for n in names:
        per_name[n] = tuple(i for i, b in enumerate(blocks) if n in b.names)
        if not per_name[n]:
            raise WebconfError("Aucun bloc server de Nginx ne declare explicitement %s "
                               "(server_name)." % n)
    groups = set(per_name.values())
    if len(groups) != 1:
        raise WebconfError("Ces noms sont servis par des blocs server differents : commandez un "
                           "certificat par groupe de noms servis ensemble.")
    targets = [blocks[i] for i in groups.pop()]

    for b in targets:
        extra = sorted(set(x for x in b.names if x not in ("_", "")) - set(names))
        if extra:
            raise WebconfError("Le bloc server (%s:%d) sert aussi %s : ajoutez ces noms a la "
                               "commande, sinon leur HTTPS serait casse."
                               % (b.st.file, b.st.line, ", ".join(extra[:5])))
        if not b.st.block or b.st.block[0].line <= (b.st.open_line or b.st.line):
            raise WebconfError("Bloc server au format inhabituel (%s:%d) : intervention refusee."
                               % (b.st.file, b.st.line))
        for c in b.ssl_cert_stmts:
            p = c.args[0] if c.args else ""
            if p.startswith(env.letsencrypt_dir + "/") or "/.acme.sh/" in p:
                raise WebconfError("Le certificat actuel de %s est gere par certbot ou acme.sh : "
                                   "reprise non proposee pour l'instant." % b.names[0])

    https_blocks = [b for b in targets if b.https]
    http_blocks = [b for b in targets if b.http and not b.https]
    if len(https_blocks) > 1 or len(http_blocks) > 1 or (not https_blocks and not http_blocks):
        raise WebconfError("Organisation des blocs server non prise en charge pour ces noms "
                           "(un bloc HTTP et/ou un bloc HTTPS attendus).")
    if not https_blocks and http_blocks[0].returns:
        raise WebconfError("Le site redirige deja vers HTTPS alors qu'aucun bloc HTTPS n'existe : "
                           "corrigez la redirection avant de commander le certificat.")

    snippets, challenge_path, certconf_path = _snippets(env, cid)
    edits_a, edits_b = {}, {}   # fichier -> liste de (ligne, [lignes a inserer]) / commentaires

    def insert(edits, b, lines):
        first = b.st.block[0]
        edits.setdefault(first.file, []).append(("ins", first.line, lines))

    def comment(edits, st):
        edits.setdefault(st.file, []).append(("com", st.line, None))

    for b in targets:
        if b.has_challenge_location and challenge_path not in b.includes:
            raise WebconfError("Une regle /.well-known/acme-challenge/ existe deja (%s:%d) : un "
                               "autre outil semble gerer les certificats." % (b.st.file, b.st.line))
        serves_challenge = b.https or not b.returns
        if serves_challenge and challenge_path not in b.includes:
            insert(edits_a, b, ["include %s;  %s" % (challenge_path, MARK)])

    tls = https_blocks[0] if https_blocks else http_blocks[0]
    if certconf_path not in tls.includes:
        lines = []
        if not https_blocks:  # decision A : listen 443 dans le bloc HTTP existant
            lines.append("listen 443 ssl;  %s" % MARK)
            if tls.http_ipv6:
                lines.append("listen [::]:443 ssl;  %s" % MARK)
        lines.append("include %s;  %s" % (certconf_path, MARK))
        insert(edits_b, tls, lines)
        for c in tls.ssl_cert_stmts:
            if c.file != tls.st.file:
                raise WebconfError("Le certificat actuel est defini dans un fichier partage (%s) : "
                                   "intervention refusee." % c.file)
            if not _single_statement_line(conf.texts[c.file].split("\n"), c, c.directive):
                raise WebconfError("Directive %s sur une ligne complexe (%s:%d) : intervention "
                                   "refusee." % (c.directive, c.file, c.line))
            comment(edits_b, c)

    plan = Plan("nginx", cid, names, https_addr=tls.https_host())
    touched = sorted(set(edits_a) | set(edits_b))
    for path in touched:
        orig = conf.texts[path]
        plan.originals[path] = orig
        plan.phase_a[path] = _apply_edits(orig, edits_a.get(path, []))
        plan.final[path] = _apply_edits(orig, edits_a.get(path, []) + edits_b.get(path, []))
    for path, content in snippets.items():
        try:
            with open(path, "r", encoding="utf-8") as fh:
                cur = fh.read()
        except FileNotFoundError:
            cur = None
        is_a = path == challenge_path
        needed = bool(edits_a) if is_a else bool(edits_b)
        if needed and cur != content:
            plan.originals[path] = cur
            plan.phase_a[path] = content if is_a else cur
            plan.final[path] = content
    _finish(plan)
    return plan


def _apply_edits(text, edits):
    lines = text.split("\n")
    inserts, comments = {}, set()
    for kind, line, payload in edits:
        if kind == "ins":
            inserts.setdefault(line, []).extend(payload)
        else:
            comments.add(line)
    out = []
    for no, line in enumerate(lines, start=1):
        if no in inserts:
            ind = _indent_of(line)
            out.extend(ind + l for l in inserts[no])
        if no in comments:
            out.append("%s# cybersafe-ai: %s" % (_indent_of(line), line.strip()))
        else:
            out.append(line)
    return "\n".join(out)


def _finish(plan):
    files = []
    diff = []
    for path in sorted(plan.final):
        orig, final = plan.originals.get(path), plan.final[path]
        files.append([path, _sha(orig), _sha(plan.phase_a.get(path)), _sha(final)])
        diff.extend(difflib.unified_diff((orig or "").splitlines(True), final.splitlines(True),
                                         fromfile=path if orig is not None else "/dev/null",
                                         tofile=path))
    canon = json.dumps({"v": 1, "web_server": plan.web_server, "certificate_id": plan.certificate_id,
                        "hostnames": plan.hostnames, "files": files},
                       sort_keys=True, separators=(",", ":"))
    plan.sha256 = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    plan.files = sorted(plan.final)
    plan.diff = "".join(diff) or "(aucune modification : configuration deja en place)\n"
    if len(plan.diff) > MAX_DIFF:
        raise WebconfError("Plan de modification trop volumineux : intervention refusee.")


def compute_plan(web_server, hostnames, cid, env=None):
    env = env or ENV
    if web_server == "nginx":
        return _nginx_plan(env, hostnames, cid)
    if web_server == "apache":
        return _apache_plan(env, hostnames, cid)
    raise WebconfError("Service web non pris en charge.")



# --- analyse Apache ---------------------------------------------------------------
_REDIRECTS = ("redirect", "redirectmatch", "redirectpermanent", "redirecttemp")


def _vhost_addr(arg):
    """(port, host) d'une adresse de <VirtualHost>."""
    if arg.startswith("["):
        host, _, rest = arg[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif ":" in arg:
        host, _, port = arg.rpartition(":")
    else:
        host, port = arg, ""
    if host in ("*", "_default_", "", "::", "0.0.0.0"):
        host = None
    return (int(port) if port.isdigit() else 80), host


class _VHost:
    def __init__(self, st):
        self.st = st
        self.addrs = [_vhost_addr(a) for a in st.args]
        self.names, self.ssl_engine, self.redirects = [], False, False
        self.ssl_cert_stmts, self.includes, self.has_challenge = [], set(), False
        rewrite_on = False
        for ch in st.block:  # directives propres au vhost
            if ch.name == "servername" and ch.args:
                self.names.append(ch.args[0].lower().split(":")[0])
            elif ch.name == "serveralias":
                self.names += [a.lower() for a in ch.args]
            elif ch.name in ("include", "includeoptional") and ch.args:
                self.includes.add(ch.args[0])
        for ch in ApacheConfig.children(st.block):
            if ch.name == "sslengine" and ch.args and ch.args[0].lower() == "on":
                self.ssl_engine = True
            elif ch.name in _REDIRECTS:
                self.redirects = True
            elif ch.name == "rewriteengine" and ch.args and ch.args[0].lower() == "on":
                rewrite_on = True
            elif ch.name == "rewriterule" and rewrite_on:
                self.redirects = True
            elif ch.name in ("sslcertificatefile", "sslcertificatekeyfile",
                             "sslcertificatechainfile"):
                self.ssl_cert_stmts.append(ch)
            elif ch.name in ("alias", "aliasmatch") and any("acme-challenge" in a for a in ch.args):
                self.has_challenge = True
            elif ch.name == "include" and ch.args and "letsencrypt" in ch.args[0]:
                self.ssl_cert_stmts.append(ch)

    @property
    def https(self):
        return self.ssl_engine and any(p == 443 for p, _h in self.addrs)

    @property
    def port443_without_ssl(self):
        return not self.ssl_engine and any(p == 443 for p, _h in self.addrs)

    @property
    def http(self):
        return any(p == 80 for p, _h in self.addrs) and not self.ssl_engine

    def https_host(self):
        for p, h in self.addrs:
            if p == 443 and h and h.replace(".", "").isdigit():
                return h
        return "127.0.0.1"


def _apache_snippets(env, cid):
    challenge = os.path.join(env.apache_snippet_dir, "acme-challenge.conf")
    certconf = os.path.join(env.apache_snippet_dir, "certs", "%d.conf" % cid)
    live = os.path.join(cert_store.cert_dir(cid, env.certs_root), "current")
    wk = os.path.join(env.webroot, ".well-known", "acme-challenge") + "/"
    return {
        challenge: (
            "# Gere par Cybersafe-AI : validation HTTP-01 des certificats geres. Ne pas modifier.\n"
            "# Une RewriteRule du site serait evaluee avant l'Alias : on laisse passer ce chemin.\n"
            "<IfModule mod_rewrite.c>\n"
            "    RewriteEngine On\n"
            "    RewriteRule ^/\\.well-known/acme-challenge/ - [L]\n"
            "</IfModule>\n"
            "Alias /.well-known/acme-challenge/ \"%s\"\n"
            "<Directory \"%s\">\n"
            "    Options None\n"
            "    AllowOverride None\n"
            "    Require all granted\n"
            "</Directory>\n" % (wk, wk)),
        certconf: (
            "# Gere par Cybersafe-AI : certificat gere n. %d. Ne pas modifier.\n"
            "SSLCertificateFile %s/fullchain.pem\n"
            "SSLCertificateKeyFile %s/privkey.pem\n" % (cid, live, live)),
    }, challenge, certconf


def _apache_plan(env, names, cid):
    names = sorted(names)
    _refusal_checks(env, names)
    if not os.path.isfile(env.apache_main):
        raise WebconfError("Apache introuvable (%s). Seules les distributions Debian et Ubuntu "
                           "sont prises en charge pour l'instant." % env.apache_main)
    code, out = _run(env.apache_modules_cmd)
    if code != 0 or "ssl_module" not in out:
        raise WebconfError("Le module SSL d'Apache n'est pas active : lancez `a2enmod ssl` puis "
                           "`systemctl restart apache2`, et relancez l'analyse.")
    try:
        conf = ApacheConfig(env.apache_main, env.apache_server_root)
    except ApacheConfError as exc:
        raise WebconfError("Configuration Apache illisible : %s" % exc) from None

    vhosts = [_VHost(v) for v in conf.vhosts()]
    per_name = {}
    for n in names:
        per_name[n] = tuple(i for i, v in enumerate(vhosts) if n in v.names)
        if not per_name[n]:
            raise WebconfError("Aucun VirtualHost d'Apache ne declare explicitement %s "
                               "(ServerName / ServerAlias)." % n)
    groups = set(per_name.values())
    if len(groups) != 1:
        raise WebconfError("Ces noms sont servis par des VirtualHost differents : commandez un "
                           "certificat par groupe de noms servis ensemble.")
    targets = [vhosts[i] for i in groups.pop()]
    for v in targets:
        extra = sorted(set(v.names) - set(names))
        if extra:
            raise WebconfError("Le VirtualHost (%s:%d) sert aussi %s : ajoutez ces noms a la "
                               "commande, sinon leur HTTPS serait casse."
                               % (v.st.file, v.st.line, ", ".join(extra[:5])))
        if not v.st.block or v.st.block[0].line <= v.st.line:
            raise WebconfError("VirtualHost au format inhabituel (%s:%d) : intervention refusee."
                               % (v.st.file, v.st.line))
        if v.port443_without_ssl:
            raise WebconfError("Le VirtualHost *:443 (%s:%d) n'a pas `SSLEngine on` : "
                               "intervention refusee." % (v.st.file, v.st.line))
        for c in v.ssl_cert_stmts:
            p = c.args[0] if c.args else ""
            if p.startswith(env.letsencrypt_dir + "/") or "letsencrypt" in p or "/.acme.sh/" in p:
                raise WebconfError("Le certificat actuel de %s est gere par certbot ou acme.sh : "
                                   "reprise non proposee pour l'instant." % v.names[0])

    https_v = [v for v in targets if v.https]
    http_v = [v for v in targets if v.http]
    if not https_v:
        raise WebconfError("Aucun VirtualHost HTTPS (port 443) pour ces noms. Activez-en un "
                           "d'abord (par exemple `a2ensite default-ssl` adapte a vos noms), puis "
                           "relancez l'analyse.")
    if len(https_v) > 1 or len(http_v) > 1:
        raise WebconfError("Organisation des VirtualHost non prise en charge pour ces noms "
                           "(un VirtualHost HTTP et/ou un VirtualHost HTTPS attendus).")

    snippets, challenge_path, certconf_path = _apache_snippets(env, cid)
    edits_a, edits_b = {}, {}

    def insert(edits, v, lines):
        first = v.st.block[0]
        edits.setdefault(first.file, []).append(("ins", first.line, lines))

    for v in targets:
        if v.has_challenge and challenge_path not in v.includes:
            raise WebconfError("Un Alias /.well-known/acme-challenge/ existe deja (%s:%d) : un "
                               "autre outil semble gerer les certificats." % (v.st.file, v.st.line))
        if (v.https or not v.redirects) and challenge_path not in v.includes:
            # Apache n'accepte pas de commentaire en fin de ligne : marqueur au-dessus.
            insert(edits_a, v, ["%s : validation HTTP-01" % MARK, "Include %s" % challenge_path])
    tls = https_v[0]
    if certconf_path not in tls.includes:
        insert(edits_b, tls, ["%s : certificat gere" % MARK, "Include %s" % certconf_path])
        for c in tls.ssl_cert_stmts:
            if c.file != tls.st.file:
                raise WebconfError("Le certificat actuel est defini dans un fichier partage (%s) : "
                                   "intervention refusee." % c.file)
            edits_b.setdefault(c.file, []).append(("com", c.line, None))

    plan = Plan("apache", cid, names, https_addr=tls.https_host())
    for path in sorted(set(edits_a) | set(edits_b)):
        orig = conf.texts[path]
        plan.originals[path] = orig
        plan.phase_a[path] = _apply_edits(orig, edits_a.get(path, []))
        plan.final[path] = _apply_edits(orig, edits_a.get(path, []) + edits_b.get(path, []))
    for path, content in snippets.items():
        try:
            with open(path, "r", encoding="utf-8") as fh:
                cur = fh.read()
        except FileNotFoundError:
            cur = None
        is_a = path == challenge_path
        needed = bool(edits_a) if is_a else bool(edits_b)
        if needed and cur != content:
            plan.originals[path] = cur
            plan.phase_a[path] = content if is_a else cur
            plan.final[path] = content
    _finish(plan)
    return plan

# --- application ----------------------------------------------------------------------
def _manifest_path(env, cid):
    return os.path.join(env.backup_dir, str(cid), "manifest.json")


def _load_manifest(env, cid):
    try:
        with open(_manifest_path(env, cid), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return None


def _save_manifest(env, cid, manifest):
    path = _manifest_path(env, cid)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _atomic_write(path, content, like=None):
    d = os.path.dirname(path)
    if not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o755)
    tmp = "%s.cybersafe-tmp" % path
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    if like is not None:
        os.chmod(tmp, like.st_mode & 0o7777)
        try:
            os.chown(tmp, like.st_uid, like.st_gid)
        except PermissionError:
            pass
    else:
        os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def _restore_from(manifest):
    for path, entry in manifest["files"].items():
        if entry["existed"]:
            with open(entry["backup"], "r", encoding="utf-8") as fh:
                content = fh.read()
            try:
                like = os.stat(path)
            except FileNotFoundError:
                like = None
            _atomic_write(path, content, like)
        else:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def _test_and_reload(env, web_server):
    if web_server == "apache":
        test, reload, label = env.apache_test_cmd, env.apache_reload_cmd, "Apache"
    else:
        test, reload, label = env.nginx_test_cmd, env.nginx_reload_cmd, "Nginx"
    code, out = _run(test)
    if code != 0:
        return "test de configuration %s en echec : %s" % (label, out.strip()[-600:])
    code, out = _run(reload)
    if code != 0:
        return "rechargement de %s en echec : %s" % (label, out.strip()[-600:])
    return None


def _apply_phase(env, plan, target, expected, phase):
    manifest = _load_manifest(env, plan.certificate_id) if phase == "B" else None
    if manifest is None:
        stamp = time.strftime("%Y%m%dT%H%M%S")
        manifest = {"run": stamp, "files": {}}
    bdir = os.path.join(env.backup_dir, str(plan.certificate_id), manifest["run"])
    changes = {p: c for p, c in target.items() if c is not None and c != expected.get(p)}
    # 1. la configuration n'a pas bouge depuis le calcul du plan
    for path in changes:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                cur = fh.read()
        except FileNotFoundError:
            cur = None
        if cur != expected.get(path):
            raise WebconfError("PLAN_CHANGED: %s a ete modifie pendant l'operation." % path)
    if not changes:
        _save_manifest(env, plan.certificate_id, manifest)
        if phase == "B":
            # Renouvellement : la configuration ne change pas mais les fichiers du
            # certificat (lien current) si ; le serveur ne les relit qu'au rechargement.
            err = _test_and_reload(env, plan.web_server)
            if err:
                raise WebconfError("Phase B : %s" % err)
        return
    # 2. sauvegarde des originaux (une seule fois par execution)
    os.makedirs(bdir, mode=0o700, exist_ok=True)
    for path in changes:
        if path in manifest["files"]:
            continue
        if os.path.exists(path):
            bpath = os.path.join(bdir, path.strip("/").replace("/", "__"))
            shutil.copy2(path, bpath)
            manifest["files"][path] = {"existed": True, "backup": bpath}
        else:
            manifest["files"][path] = {"existed": False, "backup": None}
    _save_manifest(env, plan.certificate_id, manifest)
    # 3. ecriture, test, rechargement ; sinon restauration complete
    for path, content in changes.items():
        like = os.stat(path) if os.path.exists(path) else None
        _atomic_write(path, content, like)
    err = _test_and_reload(env, plan.web_server)
    if err:
        _restore_from(manifest)
        err2 = _test_and_reload(env, plan.web_server)
        raise WebconfError("Phase %s annulee, configuration restauree : %s%s"
                           % (phase, err, "" if not err2 else " (ATTENTION : %s)" % err2))


def ensure_challenge(web_server, hostnames, cid, plan, env=None):
    env = env or ENV
    from .cert_acme import ensure_webroot
    ensure_webroot(env.webroot)
    _apply_phase(env, plan, plan.phase_a, plan.originals, "A")


def install(web_server, hostnames, cid, plan, env=None):
    env = env or ENV
    expected = {p: plan.phase_a.get(p, plan.originals.get(p)) for p in plan.final}
    _apply_phase(env, plan, plan.final, expected, "B")


def restore(web_server, cid, env=None):
    env = env or ENV
    manifest = _load_manifest(env, cid)
    if manifest and manifest.get("files"):
        _restore_from(manifest)
    if manifest is not None:
        os.replace(_manifest_path(env, cid), _manifest_path(env, cid) + ".restored")
    # Toujours recharger : apres un retour arriere du lien current (renouvellement),
    # le serveur doit relire l'ancien certificat meme si aucun fichier de
    # configuration n'a change.
    err = _test_and_reload(env, web_server)
    if err:
        raise WebconfError("Configuration restauree mais %s" % err)


def verify_https(hostnames, leaf, plan, env=None):
    """Le certificat servi en local pour chaque nom doit etre exactement le nouveau."""
    env = env or ENV
    from cryptography.hazmat.primitives import serialization
    expected = hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    deadline = time.monotonic() + env.verify_timeout
    # Apres un rechargement, les anciens workers acceptent encore brievement des
    # connexions : on exige plusieurs poignees de main CONSECUTIVES avec le nouveau
    # certificat, pour ne pas valider sur un seul worker deja a jour.
    for name in hostnames:
        last, streak = "aucune reponse", 0
        while streak < VERIFY_STREAK:
            try:
                with socket.create_connection((plan.https_addr, env.https_port), timeout=5) as raw:
                    with ctx.wrap_socket(raw, server_hostname=name) as tls:
                        got = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                if got == expected:
                    streak += 1
                    continue
                streak, last = 0, "un autre certificat est servi"
            except OSError as exc:
                streak, last = 0, str(exc)
            if time.monotonic() > deadline:
                raise WebconfError("Verification HTTPS de %s en echec : %s" % (name, last))
            time.sleep(0.3)
