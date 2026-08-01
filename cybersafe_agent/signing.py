"""
AGENT auto-update (sous-US 2) — verification de signature des releases.

La cle PUBLIQUE Ed25519 est embarquee EN DUR dans ce module (choix de securite) :
elle fait partie du code signe lui-meme. Un attaquant qui voudrait substituer sa
propre cle devrait modifier ce fichier, ce qui casserait la verification de la
mise a jour suivante. Le point d'ancrage de confiance est l'installation initiale
(install.sh, faite manuellement par l'operateur).

Verification en deux temps (integrite + authenticite) :
  1. le SHA256 de l'archive telechargee doit egaler le sha256 annonce (integrite)
  2. la signature Ed25519 de ce SHA256 doit etre valide (authenticite)
Les deux doivent passer ; sinon la release est REJETEE (aucune execution).
"""
import base64
import hashlib

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

# Cle publique de signature des releases Cybersafe-AI (Ed25519, PEM).
# Correspond a la cle privee detenue par l'editeur (jamais distribuee).
_SIGNING_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjVgi8NuqOjNybpHV4LTSYmGt1jK86t4K5dWzcrWr1/E=
-----END PUBLIC KEY-----
"""


class SignatureError(Exception):
    """Levee quand une release echoue a la verification (integrite ou signature)."""


def sha256_hex(data: bytes) -> str:
    """SHA256 hexadecimal d'un blob (l'archive telechargee)."""
    return hashlib.sha256(data).hexdigest()


def verify_release(archive_bytes: bytes, expected_sha256: str, signature_b64: str) -> str:
    """Verifie integrite + authenticite d'une archive de release.

    - archive_bytes  : contenu telecharge
    - expected_sha256: sha256 hex annonce par le backend
    - signature_b64  : signature Ed25519 (base64) du sha256, produite par l'editeur

    Retourne le sha256 recalcule si tout est valide. Leve SignatureError sinon.
    N'execute RIEN : se contente de valider. L'appelant ne doit utiliser l'archive
    que si cette fonction retourne sans lever.
    """
    # 1. Integrite : le hash recalcule doit correspondre a l'annonce.
    actual = sha256_hex(archive_bytes)
    if actual != (expected_sha256 or "").strip().lower():
        raise SignatureError(
            f"Integrite : SHA256 different (attendu {expected_sha256}, obtenu {actual})")

    # 2. Authenticite : la signature du hash doit etre valide avec la cle publique.
    if not signature_b64:
        raise SignatureError("Authenticite : signature absente.")
    try:
        signature = base64.b64decode(signature_b64)
    except (ValueError, TypeError) as exc:
        raise SignatureError(f"Authenticite : signature non decodable ({exc}).")

    pub = load_pem_public_key(_SIGNING_PUBLIC_KEY_PEM)
    try:
        pub.verify(signature, actual.encode("ascii"))
    except InvalidSignature:
        raise SignatureError("Authenticite : signature invalide (release non fiable).")

    return actual
