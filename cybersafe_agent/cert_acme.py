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
LEGO_VERSION = "4.25.2"
LEGO_SHA256 = {
    "x86_64": "",
    "aarch64": "",
}


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


def _clean_output(raw):
    text = (raw or b"").decode("utf-8", "replace")
    if "PRIVATE KEY" in text.upper():
        return "[sortie masquee]"
    return text[-MAX_OUTPUT:]


def lego_command(exe, directory, csr_path, data_dir=LEGO_DATA, webroot=WEBROOT):
    return [exe, "--accept-tos", "--email", ACCOUNT_EMAIL, "--server", directory,
            "--path", data_dir, "--key-type", "ec256", "--csr", csr_path,
            "--http", "--http.webroot", webroot, "run"]


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


def _result_file(data_dir, primary):
    # lego nomme ses fichiers d'apres le premier nom ("*" -> "_", hors porte 1).
    return os.path.join(data_dir, "certificates", primary.replace("*", "_") + ".crt")


def issue(directory, csr_path, hostnames, *, lego_path=LEGO_PATH, data_dir=LEGO_DATA,
          webroot=WEBROOT, expected_sha256=None, runner=subprocess.run):
    """Emet le certificat pour le CSR. Renvoie (feuille, chaine) en objets x509."""
    _prepare_dirs(data_dir, webroot)
    out_file = _result_file(data_dir, hostnames[0])
    certs_dir = os.path.dirname(out_file)
    if os.path.isdir(certs_dir):
        shutil.rmtree(certs_dir)  # ne jamais relire le resultat d'une emission precedente
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
