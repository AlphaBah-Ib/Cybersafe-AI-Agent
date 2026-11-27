# -*- coding: utf-8 -*-
"""
[CERT04-P2] Magasin local des certificats geres (execute en ROOT par cert_apply).

Disposition :
    /etc/cybersafe/certs/<certificate_id>/            0700 root
        v<horodatage>-<hasard>/                       0700 root, une version par emission
            privkey.pem                               0600 root  (jamais lue hors de ce serveur)
            cert.pem  chain.pem  fullchain.pem        0644 root  (publics)
        current -> v...                               lien symbolique, bascule atomique
        previous -> v...                              version precedente (retour arriere)

La configuration du serveur web (porte 3) ne pointe que vers
<certificate_id>/current/{fullchain,privkey}.pem : un renouvellement remplace
les fichiers et bascule le lien, sans modifier la configuration.

Regles :
  - la cle privee est generee ici (ECDSA P-256), ecrite en O_CREAT|O_EXCL 0600,
    jamais journalisee, jamais renvoyee par une fonction publique ;
  - aucune ecriture ne suit un lien symbolique place par un tiers ;
  - le CSR et les certificats sont publics.
"""
import os
import secrets
import stat
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

CERTS_ROOT = "/etc/cybersafe/certs"
KEEP_VERSIONS = 3


class StoreError(Exception):
    """Erreur du magasin ; message sans aucun secret."""


def _check_owned_dir(path):
    """Le dossier doit exister, etre un vrai dossier, appartenir a root, sans ecriture
    pour le groupe ni les autres."""
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise StoreError("%s n'est pas un dossier" % path)
    if st.st_uid != 0 and os.geteuid() == 0:
        raise StoreError("%s n'appartient pas a root" % path)
    if st.st_mode & 0o022:
        raise StoreError("%s est accessible en ecriture a d'autres comptes" % path)


def _mkdir_private(path):
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    _check_owned_dir(path)


def _write_new(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def cert_dir(certificate_id, root=CERTS_ROOT):
    if not isinstance(certificate_id, int) or isinstance(certificate_id, bool) or certificate_id < 1:
        raise StoreError("identifiant de certificat invalide")
    return os.path.join(root, str(certificate_id))


def new_version(certificate_id, hostnames, root=CERTS_ROOT):
    """Cree une version vide, y genere la cle privee et renvoie (dossier, csr_pem).
    La cle ne sort jamais du dossier."""
    _mkdir_private(os.path.dirname(root.rstrip("/")) or "/")  # /etc/cybersafe
    _mkdir_private(root)
    base = cert_dir(certificate_id, root)
    _mkdir_private(base)
    # Nom triable chronologiquement (nanosecondes, largeur fixe) : prune() s'appuie
    # sur cet ordre. Un horodatage a la seconde + suffixe aleatoire trierait au hasard
    # deux emissions de la meme seconde.
    vdir = os.path.join(base, "v%020d-%s" % (time.time_ns(), secrets.token_hex(4)))
    os.mkdir(vdir, 0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    _write_new(os.path.join(vdir, "privkey.pem"),
               key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()),
               0o600)
    # Sujet vide, noms uniquement en SAN : le Common Name est obsolete (lego 5 ne le
    # prend plus en charge par defaut, les AC publiques l'abandonnent).
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames]),
                          critical=False)
           .sign(key, hashes.SHA256()))
    del key
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    _write_new(os.path.join(vdir, "request.csr"), csr_pem, 0o644)
    return vdir, csr_pem


def split_pem_chain(pem_bytes):
    """Separe un bundle PEM en (feuille, chaine). Refuse tout ce qui n'est pas un
    certificat (en particulier une cle privee)."""
    if b"PRIVATE KEY" in pem_bytes.upper():
        raise StoreError("le bundle ACME contient une cle privee : refuse")
    try:
        certs = x509.load_pem_x509_certificates(pem_bytes)
    except ValueError:
        raise StoreError("bundle de certificats illisible") from None
    if len(certs) < 2:
        raise StoreError("chaine de certification absente")
    return certs[0], certs[1:]


def store_certificate(vdir, leaf, chain, hostnames):
    """Verifie la feuille contre la cle de la version et les noms, puis ecrit les
    fichiers publics. Renvoie (cert_pem, chain_pem) en texte."""
    with open(os.path.join(vdir, "privkey.pem"), "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    same_key = (key.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
                == leaf.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    del key
    if not same_key:
        raise StoreError("le certificat emis ne correspond pas a la cle generee sur ce serveur")
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = sorted({n.lower() for n in san.get_values_for_type(x509.DNSName)})
    except x509.ExtensionNotFound:
        names = []
    if names != sorted(hostnames):
        raise StoreError("les noms du certificat emis ne correspondent pas a la commande")
    if leaf.issuer != chain[0].subject:
        raise StoreError("chaine incoherente avec l'emetteur du certificat")
    pem = serialization.Encoding.PEM
    cert_pem = leaf.public_bytes(pem)
    chain_pem = b"".join(c.public_bytes(pem) for c in chain)
    _write_new(os.path.join(vdir, "cert.pem"), cert_pem, 0o644)
    _write_new(os.path.join(vdir, "chain.pem"), chain_pem, 0o644)
    _write_new(os.path.join(vdir, "fullchain.pem"), cert_pem + chain_pem, 0o644)
    return cert_pem.decode("ascii"), chain_pem.decode("ascii")


def _swap_link(base, name, target):
    tmp = os.path.join(base, ".%s.%s" % (name, secrets.token_hex(4)))
    os.symlink(target, tmp)
    os.replace(tmp, os.path.join(base, name))


def current_version(certificate_id, root=CERTS_ROOT):
    link = os.path.join(cert_dir(certificate_id, root), "current")
    try:
        return os.readlink(link)
    except OSError:
        return None


def activate(vdir):
    """Bascule current -> vdir (et previous -> ancienne). Atomique pour les lecteurs."""
    base = os.path.dirname(vdir)
    name = os.path.basename(vdir)
    try:
        old = os.readlink(os.path.join(base, "current"))
    except OSError:
        old = None
    if old and old != name:
        _swap_link(base, "previous", old)
    _swap_link(base, "current", name)
    return old


def rollback(certificate_id, root=CERTS_ROOT):
    """current -> previous. Renvoie la version restauree, ou None s'il n'y en a pas."""
    base = cert_dir(certificate_id, root)
    try:
        prev = os.readlink(os.path.join(base, "previous"))
    except OSError:
        return None
    _swap_link(base, "current", prev)
    return prev


def deactivate(certificate_id, root=CERTS_ROOT):
    """Retire le lien current (premiere installation annulee, aucune version precedente)."""
    try:
        os.unlink(os.path.join(cert_dir(certificate_id, root), "current"))
    except FileNotFoundError:
        pass


def discard(vdir):
    """Supprime une version jamais activee (emission ou installation en echec)."""
    base = os.path.dirname(vdir)
    name = os.path.basename(vdir)
    for link in ("current", "previous"):
        try:
            if os.readlink(os.path.join(base, link)) == name:
                raise StoreError("refus de supprimer une version en service")
        except OSError:
            pass
    for entry in os.listdir(vdir):
        os.unlink(os.path.join(vdir, entry))
    os.rmdir(vdir)


def prune(certificate_id, root=CERTS_ROOT, keep=KEEP_VERSIONS):
    """Ne garde que les `keep` versions les plus recentes, jamais current ni previous."""
    base = cert_dir(certificate_id, root)
    protected = set()
    for link in ("current", "previous"):
        try:
            protected.add(os.readlink(os.path.join(base, link)))
        except OSError:
            pass
    versions = sorted(e for e in os.listdir(base) if e.startswith("v"))
    for name in versions[:-keep] if keep else versions:
        if name not in protected:
            discard(os.path.join(base, name))
