"""
AGENT auto-update (sous-US 2) — verification de signature Ed25519.
Le test le plus important de l'auto-update : il prouve qu'une archive alteree
ou une signature forgee est REJETEE. On signe avec une cle de test generee a la
volee, apres avoir injecte sa cle publique dans le module (monkeypatch) pour ne
pas dependre de la vraie cle de prod.
"""
import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from cybersafe_agent import signing
from cybersafe_agent.signing import verify_release, SignatureError, sha256_hex


@pytest.fixture
def signing_keypair(monkeypatch):
    """Genere une paire Ed25519 de test et injecte la cle publique dans le module."""
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    monkeypatch.setattr(signing, "_SIGNING_PUBLIC_KEY_PEM", pub_pem)
    return priv


def _sign(priv, archive: bytes):
    """Reproduit ce que fait la commande backend : signe le sha256 hex de l'archive."""
    digest = hashlib.sha256(archive).hexdigest()
    sig = priv.sign(digest.encode("ascii"))
    return digest, base64.b64encode(sig).decode("ascii")


ARCHIVE = b"contenu binaire d'une archive d'agent" * 100


class TestVerifyRelease:
    def test_valid_release_accepted(self, signing_keypair):
        """Signature valide + bon hash -> acceptee (retourne le sha256)."""
        sha, sig = _sign(signing_keypair, ARCHIVE)
        result = verify_release(ARCHIVE, sha, sig)
        assert result == sha

    def test_altered_archive_rejected(self, signing_keypair):
        """Archive alteree (le hash ne correspond plus) -> SignatureError (integrite)."""
        sha, sig = _sign(signing_keypair, ARCHIVE)
        tampered = ARCHIVE + b"MALWARE"
        with pytest.raises(SignatureError, match="Integrite"):
            verify_release(tampered, sha, sig)

    def test_forged_signature_rejected(self, signing_keypair):
        """Signature forgee (autre cle) sur le bon hash -> SignatureError (authenticite)."""
        # signer avec une AUTRE cle que celle injectee
        rogue = Ed25519PrivateKey.generate()
        sha, sig = _sign(rogue, ARCHIVE)
        with pytest.raises(SignatureError, match="Authenticite"):
            verify_release(ARCHIVE, sha, sig)

    def test_corrupted_signature_rejected(self, signing_keypair):
        """Signature valide mais 1 octet flippe -> rejetee."""
        sha, sig = _sign(signing_keypair, ARCHIVE)
        raw = bytearray(base64.b64decode(sig)); raw[0] ^= 0x01
        corrupt = base64.b64encode(bytes(raw)).decode("ascii")
        with pytest.raises(SignatureError, match="Authenticite"):
            verify_release(ARCHIVE, sha, corrupt)

    def test_missing_signature_rejected(self, signing_keypair):
        sha = sha256_hex(ARCHIVE)
        with pytest.raises(SignatureError, match="absente"):
            verify_release(ARCHIVE, sha, "")

    def test_wrong_sha256_rejected(self, signing_keypair):
        """sha256 annonce faux (meme si signature coherente avec lui) -> integrite KO."""
        _, sig = _sign(signing_keypair, ARCHIVE)
        with pytest.raises(SignatureError, match="Integrite"):
            verify_release(ARCHIVE, "deadbeef" * 8, sig)

    def test_undecodable_signature_rejected(self, signing_keypair):
        sha = sha256_hex(ARCHIVE)
        with pytest.raises(SignatureError):
            verify_release(ARCHIVE, sha, "!!!pas du base64!!!")
