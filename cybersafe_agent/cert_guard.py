# -*- coding: utf-8 -*-
"""
[CERT04-P2] Controle des ordres de CERTIFICATS avant execution.

Canal distinct des ordres de remediation (order_guard.py) :
  - cle publique dediee (CERT_ORDER_SIGNING_KEY cote serveur) : la compromission
    de la cle des ordres SOC ne permet pas de forger un ordre de certificat, et
    inversement ;
  - separation de domaine : sig_alg = "ed25519-cert-v1" et champ SIGNE
    channel = "cert" ;
  - liste fermee des types d'ordre, des services web et des annuaires ACME ;
  - noms d'hote revalides avec les memes regles que le serveur ;
  - expiration (tolerance d'horloge) et nonce a usage unique.

canonical() est celui des ordres SOC (memes octets que
backend/apps/soc/response/signing.py:canonical), avec SIGNED_FIELDS ci-dessous
(identiques a backend/apps/certificates/signing.py).
"""
import base64
import binascii
import ipaddress
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .order_guard import OrderRejected, ReplayJournal, canonical, \
    check_expiry

# Cle publique des ordres de certificats (Ed25519, 32 octets, base64).
# Generee le 24/11/2026 ; graine privee dans KeePassXC
# « Cybersafe - CERT_ORDER_SIGNING_KEY (Ed25519) ».
_CERT_ORDER_PUBLIC_KEY_B64 = "/noWfcrd/OzyK/UygCpRJjcySpfwhMIcOBFL1CdBQoY="

SIG_ALG = "ed25519-cert-v1"
CHANNEL = "cert"
SIGNED_FIELDS = ("id", "channel", "kind", "agent_id", "certificate_id", "hostnames",
                 "web_server", "acme_directory", "plan_sha256", "issued_at", "expires_at",
                 "nonce")
KINDS = frozenset({"plan", "issue_install"})
WEB_SERVERS = frozenset({"nginx", "apache"})
ACME_DIRECTORIES = frozenset({
    "https://acme-v02.api.letsencrypt.org/directory",
    "https://acme-staging-v02.api.letsencrypt.org/directory",
})
MAX_HOSTNAMES = 10

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_FORBIDDEN_TLDS = frozenset({
    "localhost", "local", "localdomain", "internal", "intranet", "lan", "home",
    "corp", "private", "test", "example", "invalid", "onion", "arpa", "alt",
})

__all__ = ["OrderRejected", "CertReplayJournal", "guard_cert_order", "valid_hostname"]


class CertReplayJournal(ReplayJournal):
    """Journal anti-rejeu propre au canal des certificats (fichier distinct)."""

    FILENAME = "cert_nonces.json"


def _public_key():
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(_CERT_ORDER_PUBLIC_KEY_B64))


def check_signature(order):
    if order.get("sig_alg") != SIG_ALG:
        raise OrderRejected("ordre de certificat non signe ou algorithme refuse (sig_alg=%r)"
                            % (order.get("sig_alg"),))
    sig_b64 = order.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        raise OrderRejected("signature absente")
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (binascii.Error, ValueError):
        raise OrderRejected("signature illisible") from None
    try:
        _public_key().verify(sig, canonical(order, SIGNED_FIELDS))
    except (InvalidSignature, ValueError):
        raise OrderRejected("signature invalide") from None


def valid_hostname(name):
    """Memes regles que backend/apps/certificates/hostnames.py (forme deja normalisee)."""
    if not isinstance(name, str) or not name or len(name) > 253 or name != name.lower():
        return False
    if "*" in name or name.endswith("."):
        return False
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        pass
    labels = name.split(".")
    if len(labels) < 2 or not all(_LABEL.match(lb) for lb in labels):
        return False
    return not labels[-1].isdigit() and labels[-1] not in _FORBIDDEN_TLDS


def _is_int(value, lo=1):
    return isinstance(value, int) and not isinstance(value, bool) and value >= lo


def check_fields(order, agent_id=None):
    if order.get("channel") != CHANNEL:
        raise OrderRejected("canal d'ordre inattendu: %r" % (order.get("channel"),))
    kind = order.get("kind")
    if kind not in KINDS:
        raise OrderRejected("type d'ordre de certificat non autorise: %r" % (kind,))
    for field in ("id", "agent_id", "certificate_id"):
        if not _is_int(order.get(field)):
            raise OrderRejected("%s invalide" % field)
    if agent_id is not None and order.get("agent_id") != agent_id:
        raise OrderRejected("ordre destine a un autre agent")
    if order.get("web_server") not in WEB_SERVERS:
        raise OrderRejected("service web non pris en charge: %r" % (order.get("web_server"),))
    if order.get("acme_directory") not in ACME_DIRECTORIES:
        raise OrderRejected("annuaire ACME non autorise: %r" % (order.get("acme_directory"),))
    names = order.get("hostnames")
    if (not isinstance(names, list) or not names or len(names) > MAX_HOSTNAMES
            or names != sorted(set(names)) or not all(valid_hostname(n) for n in names)):
        raise OrderRejected("noms d'hote invalides")
    plan = order.get("plan_sha256")
    if kind == "plan":
        if plan != "":
            raise OrderRejected("un ordre d'analyse ne porte pas d'empreinte de plan")
    elif not isinstance(plan, str) or not _HEX64.match(plan):
        raise OrderRejected("empreinte de plan invalide")
    if not isinstance(order.get("nonce"), str) or not _NONCE.match(order["nonce"]):
        raise OrderRejected("nonce invalide")


def guard_cert_order(order, journal, now=None, agent_id=None):
    """Leve OrderRejected si l'ordre ne doit pas etre execute. Ordre des controles :
    forme -> signature -> expiration -> nonce (consomme en dernier, seulement si
    tout le reste est valide)."""
    if not isinstance(order, dict):
        raise OrderRejected("ordre illisible")
    now = time.time() if now is None else now
    check_fields(order, agent_id=agent_id)
    check_signature(order)
    expires = check_expiry(order, now)
    journal.consume(order["nonce"], expires, now)
    return order
