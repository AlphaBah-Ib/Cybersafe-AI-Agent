# -*- coding: utf-8 -*-
"""
[CERT04-P2] Emission ACME par lego (execute en ROOT par cert_apply).

  - lego est un binaire externe : son empreinte SHA-256 est FIGEE ici, dans le
    code signe de l'agent. Le binaire est ouvert une seule fois, son empreinte
    calculee sur le descripteur, puis execute VIA CE MEME DESCRIPTEUR
    (/proc/self/fd/N) : aucune fenetre entre la verification et l'execution.
  - lego fonctionne en mode --csr : la cle privee est generee par cert_store et
    lego ne la voit jamais.
  - un compte ACME par serveur, dans ACME_HOME (0700 root) : la cle du compte
    ne quitte pas non plus ce serveur.
  - validation HTTP-01 par webroot dedie (WEBROOT), servi par le serveur web
    via l'extrait installe a la porte 3.
  - environnement minimal, delai borne, sortie bornee et filtree avant journal.
"""
import hashlib
import os
import platform
import shutil
import stat
import subprocess

from .cert_store import StoreError, split_pem_chain

ACME_HOME = "/var/lib/cybersafe-acme"
LEGO_PATH = os.path.join(ACME_HOME, "bin", "lego")
LEGO_DATA = os.path.join(ACME_HOME, "lego")
WEBROOT = "/var/lib/cybersafe-acme-webroot"
ACCOUNT_EMAIL = "certificats@cybersafe-ai.com"
RUN_TIMEOUT = 600
MAX_OUTPUT = 8000

# Version de lego et empreintes SHA-256 du binaire, par architecture.
# A RENSEIGNER a la publication (runbook) : tant qu'une valeur est vide,
# l'emission est refusee (fail-closed).
# lego 5.x : interface repensee (toutes les options APRES `run`, --cert.name).
LEGO_VERSION = "5.4.1"
CERT_NAME = "cybersafe"
# Empreintes des BINAIRES extraits des archives officielles lego_v5.4.1_linux_*.tar.gz
# (archives verifiees contre lego_5.4.1_checksums.txt le 26/11/2026).
LEGO_SHA256 = {
    "x86_64": "08958a0807295d2bad8eb9aa42bcc2c24cb31a3f327c4e4185c03d4d8a92c8ab",
    "aarch64": "bfeb0d5052238102e530f1b3603eebaaa8c1c0b680186d64d36189e0711c503b",
}
# Copie publique dans le bucket de Cybersafe-AI (objets tools/ en lecture publique,
# le reste du bucket reste prive). La confiance vient de l'empreinte ci-dessus,
# inscrite dans le code SIGNE de l'agent, pas du bucket ni du reseau.
LEGO_URL = ("https://cybersafe-agent-releases.s3.fr-par.scw.cloud/tools/lego/%s/linux-%s/lego"
            % (LEGO_VERSION, "%s"))
LEGO_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}
LEGO_MAX_BYTES = 150 * 1024 * 1024


class AcmeError(Exception):
    """Echec d'emission ; message affichable, sans secret."""


def _expected_sha256():
    arch = platform.machine()
    digest = LEGO_SHA256.get(arch, "")
    if len(digest) != 64:
        raise AcmeError("outil ACME non configure pour l'architecture %s (empreinte absente)"
                        % arch)
    return digest


def open_verified_lego(path=LEGO_PATH, expected=None):
    """Ouvre lego, verifie proprietaire, droits et empreinte. Renvoie le descripteur
    (a fermer par l'appelant)."""
    expected = expected or _expected_sha256()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise AcmeError("outil ACME absent (%s)" % path) from None
    except OSError as exc:
        raise AcmeError("outil ACME illisible (%s)" % (exc.strerror or exc)) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AcmeError("outil ACME : fichier ordinaire attendu")
        if os.geteuid() == 0 and st.st_uid != 0:
            raise AcmeError("outil ACME : doit appartenir a root")
        if st.st_mode & 0o022:
            raise AcmeError("outil ACME : modifiable par d'autres comptes")
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            h.update(chunk)
        if h.hexdigest() != expected:
            raise AcmeError("outil ACME : empreinte inattendue (binaire refuse)")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def ensure_lego(path=LEGO_PATH, expected=None, opener=None):
    """Installe lego s'il est absent ou different de la version figee : telechargement
    borne, empreinte verifiee AVANT installation, remplacement atomique (0755 root)."""
    expected = expected or _expected_sha256()
    try:
        fd = open_verified_lego(path, expected)
        os.close(fd)
        return path  # deja la bonne version
    except AcmeError:
        pass
    arch = LEGO_ARCH.get(platform.machine())
    if arch is None:
        raise AcmeError("architecture %s non prise en charge pour l'outil ACME"
                        % platform.machine())
    url = LEGO_URL % arch
    if opener is None:
        import urllib.request
        opener = urllib.request.urlopen
    bindir = os.path.dirname(path)
    os.makedirs(bindir, mode=0o700, exist_ok=True)
    os.chmod(bindir, 0o700)
    tmp = os.path.join(bindir, ".lego.download")
    h, size = hashlib.sha256(), 0
    try:
        with opener(url, timeout=120) as resp, open(tmp, "wb") as out:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > LEGO_MAX_BYTES:
                    raise AcmeError("outil ACME : telechargement trop volumineux")
                h.update(chunk)
                out.write(chunk)
        if h.hexdigest() != expected:
            raise AcmeError("outil ACME telecharge : empreinte inattendue (refuse)")
        os.chmod(tmp, 0o755)
        os.replace(tmp, path)
    except AcmeError:
        raise
    except Exception as exc:  # noqa: BLE001 — reseau, disque
        raise AcmeError("outil ACME : telechargement impossible (%s)" % type(exc).__name__) from None
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
    return path


def _clean_output(raw):
    text = (raw or b"").decode("utf-8", "replace")
    if "PRIVATE KEY" in text.upper():
        return "[sortie masquee]"
    return text[-MAX_OUTPUT:]


def lego_command(exe, directory, csr_path, data_dir=LEGO_DATA, webroot=WEBROOT):
    """lego 5.x : `lego run` puis ses options. Cle de compte : type par defaut (EC256)."""
    return [exe, "run", "--accept-tos", "--email", ACCOUNT_EMAIL, "--server", directory,
            "--path", data_dir, "--csr", csr_path, "--cert.name", CERT_NAME,
            "--http", "--http.webroot", webroot]


def ensure_webroot(webroot=WEBROOT):
    """Dossiers HTTP-01 lisibles par le serveur web (qui ne tourne pas en root).
    Droits EXPLICITES : cert_apply tourne sous umask 077, qui donnerait 0700 et un
    refus 403 a chaque validation."""
    path = webroot
    for part in ("", ".well-known", "acme-challenge"):
        path = os.path.join(path, part) if part else path
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o755)
    return path


def _prepare_dirs(data_dir, webroot):
    for path, mode in ((ACME_HOME, 0o700), (data_dir, 0o700)):
        os.makedirs(path, mode=mode, exist_ok=True)
        os.chmod(path, mode)
    ensure_webroot(webroot)


def _lego_umask():
    # lego ecrit les jetons HTTP-01 avec les droits par defaut : umask 022 pour qu'ils
    # soient lisibles par le serveur web (les donnees du compte restent dans un dossier 0700).
    os.umask(0o022)


def _result_file(data_dir):
    # Nom fixe par --cert.name (independant des domaines).
    return os.path.join(data_dir, "certificates", CERT_NAME + ".crt")


def issue(directory, csr_path, hostnames, *, lego_path=LEGO_PATH, data_dir=LEGO_DATA,
          webroot=WEBROOT, expected_sha256=None, runner=subprocess.run, ensure=True):
    """Emet le certificat pour le CSR. Renvoie (feuille, chaine) en objets x509."""
    _prepare_dirs(data_dir, webroot)
    out_file = _result_file(data_dir)
    certs_dir = os.path.dirname(out_file)
    if os.path.isdir(certs_dir):
        shutil.rmtree(certs_dir)  # ne jamais relire le resultat d'une emission precedente
    if ensure:
        ensure_lego(lego_path, expected_sha256)
    fd = open_verified_lego(lego_path, expected_sha256)
    try:
        exe = "/proc/self/fd/%d" % fd
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": ACME_HOME, "LANG": "C"}
        for var in ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"):
            if os.environ.get(var):
                env[var] = os.environ[var]
        try:
            proc = runner(lego_command(exe, directory, csr_path, data_dir, webroot),
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                          timeout=RUN_TIMEOUT, pass_fds=(fd,), check=False,
                          preexec_fn=_lego_umask)
        except subprocess.TimeoutExpired:
            raise AcmeError("l'autorite de certification n'a pas repondu a temps") from None
    finally:
        os.close(fd)
    if proc.returncode != 0:
        raise AcmeError("emission refusee : %s" % _clean_output(proc.stdout).strip()[-1500:])
    try:
        with open(out_file, "rb") as fh:
            bundle = fh.read()
    except OSError:
        raise AcmeError("certificat emis introuvable") from None
    finally:
        if os.path.isdir(certs_dir):
            shutil.rmtree(certs_dir)
    try:
        return split_pem_chain(bundle)
    except StoreError as exc:
        raise AcmeError(str(exc)) from None
