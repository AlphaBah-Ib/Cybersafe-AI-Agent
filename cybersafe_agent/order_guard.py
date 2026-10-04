# -*- coding: utf-8 -*-
"""
US-SOC-R11 (agent 1.9.0) — controle des ordres de remediation AVANT execution.

Le serveur signe chaque ordre (Ed25519, backend/apps/soc/response/signing.py).
Ce module refuse tout ordre :
  - sans signature, ou dont la signature ne correspond pas a la cle embarquee ;
  - expire (tolerance d'horloge : CLOCK_TOLERANCE_SECONDS) ;
  - deja recu (nonce a usage unique, journal local) ;
  - dont l'action n'est pas dans la liste fermee ;
  - dont l'IP cible est invalide ou non bannissable.

La cle publique des ORDRES est distincte de celle des RELEASES (signing.py) :
la compromission de l'une ne donne aucun pouvoir sur l'autre.

canonical() DOIT rester identique a canonical() cote serveur : champs
SIGNED_FIELDS uniquement, cles triees, separateurs (",", ":"), ASCII.
sig_alg et signature ne sont PAS signes (sig_alg est controle a part).
"""
import base64
import binascii
import ipaddress
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger("cybersafe.remediation")

# Cle publique de signature des ordres (Ed25519, 32 octets bruts, base64).
# Derivee de SOC_ORDER_SIGNING_KEY sur le serveur web (verifiee le 4 oct. 2026).
_ORDER_PUBLIC_KEY_B64 = "lKBAW4dPQGloYAXNUlzs+E8bzsMIDlHfMRbXrx8pwsk="

SIGNED_FIELDS = ("id", "action", "target_ip", "ttl_seconds", "agent_id",
                 "issued_at", "expires_at", "nonce")
ALLOWED_ACTIONS = frozenset({"ban_ip", "unban_ip"})
CLOCK_TOLERANCE_SECONDS = 60
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_FORBIDDEN_IP_KINDS = (
    ("is_loopback", "loopback"),
    ("is_multicast", "multicast"),
    ("is_unspecified", "non specifiee"),
    ("is_link_local", "link-local"),
    ("is_reserved", "reservee"),
)


class OrderRejected(Exception):
    """Ordre refuse ; le message est remonte au serveur et journalise [AUDIT]."""


def canonical(order):
    body = {k: order.get(k) for k in SIGNED_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _public_key():
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(_ORDER_PUBLIC_KEY_B64))


def check_signature(order):
    if order.get("sig_alg") != "ed25519":
        raise OrderRejected("ordre non signe ou algorithme non supporte (sig_alg=%r)"
                            % (order.get("sig_alg"),))
    sig_b64 = order.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        raise OrderRejected("signature absente")
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (binascii.Error, ValueError):
        raise OrderRejected("signature illisible") from None
    try:
        _public_key().verify(sig, canonical(order))
    except (InvalidSignature, ValueError):
        raise OrderRejected("signature invalide") from None


def _parse_utc(value, field):
    if not isinstance(value, str):
        raise OrderRejected("%s absent" % field)
    try:
        return datetime.strptime(value, _DATE_FORMAT).replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        raise OrderRejected("%s illisible (%r)" % (field, value)) from None


def check_expiry(order, now):
    """Retourne expires_at (epoch). Refuse un ordre expire, tolerance comprise."""
    expires = _parse_utc(order.get("expires_at"), "expires_at")
    if now > expires + CLOCK_TOLERANCE_SECONDS:
        raise OrderRejected("ordre expire (expires_at=%s, horloge agent=%s)"
                            % (order.get("expires_at"),
                               time.strftime(_DATE_FORMAT, time.gmtime(now))))
    return expires


def check_action(order):
    action = order.get("action")
    if action not in ALLOWED_ACTIONS:
        raise OrderRejected("action non autorisee: %r" % (action,))


def check_ip(order):
    raw = order.get("target_ip")
    if not isinstance(raw, str) or not raw.strip():
        raise OrderRejected("target_ip vide")
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        raise OrderRejected("target_ip invalide: %r" % (raw,)) from None
    candidates = [ip]
    if ip.version == 6 and ip.ipv4_mapped is not None:  # ::ffff:127.0.0.1
        candidates.append(ip.ipv4_mapped)
    for candidate in candidates:
        for attr, label in _FORBIDDEN_IP_KINDS:
            if getattr(candidate, attr):
                raise OrderRejected("target_ip %s refusee (%s)" % (ip, label))


class ReplayJournal:
    """
    Nonces deja consommes -> expiration (epoch). Persiste en JSON (ecriture
    atomique, droits 600) ; en memoire seulement si le dossier n'est pas
    accessible en ecriture. Les nonces expires sont purges : le fichier reste
    minuscule, et un ordre expire est de toute facon refuse par check_expiry.
    """

    FILENAME = "remediation_nonces.json"

    def __init__(self, state_dir):
        self._lock = threading.Lock()
        self._seen = {}
        self._path = None
        if not state_dir:
            logger.warning("[AUDIT] [remediation] journal anti-rejeu en memoire seulement "
                           "(aucun dossier d'etat)")
            return
        path = os.path.join(state_dir, self.FILENAME)
        try:
            os.makedirs(state_dir, exist_ok=True)
            self._seen = self._load(path)
            self._write(path)  # preuve que l'ecriture fonctionne
            self._path = path
        except OSError as exc:
            logger.warning("[AUDIT] [remediation] journal anti-rejeu en memoire seulement "
                           "(%s : %s)", path, exc)

    @property
    def persistent(self):
        return self._path is not None

    @staticmethod
    def _load(path):
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return {str(k): float(v) for k, v in data.items()}
        except (ValueError, TypeError, AttributeError):
            logger.warning("[AUDIT] [remediation] journal anti-rejeu illisible, reinitialise : %s",
                           path)
            return {}

    def _write(self, path):
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self._seen, fh)
        os.replace(tmp, path)

    def consume(self, nonce, expires, now):
        """Enregistre le nonce ; OrderRejected s'il a deja ete vu."""
        with self._lock:
            limit = now - CLOCK_TOLERANCE_SECONDS
            self._seen = {k: v for k, v in self._seen.items() if v >= limit}
            if nonce in self._seen:
                raise OrderRejected("ordre deja recu (nonce rejoue)")
            self._seen[nonce] = expires
            if self._path:
                try:
                    self._write(self._path)
                except OSError as exc:
                    logger.warning("[AUDIT] [remediation] journal anti-rejeu non ecrit "
                                   "(memoire conservee) : %s", exc)


def guard_order(order, journal, now=None):
    """
    Leve OrderRejected si l'ordre ne doit pas etre execute. La signature est
    controlee en premier : tout ce qui suit porte sur des champs authentifies.
    Le nonce n'est consomme qu'en dernier, pour un ordre valide en tout point,
    et AVANT l'execution (un plantage pendant l'execution ne permet pas de rejeu).
    """
    now = time.time() if now is None else now
    check_signature(order)
    expires = check_expiry(order, now)
    check_action(order)
    check_ip(order)
    nonce = order.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise OrderRejected("nonce absent")
    journal.consume(nonce, expires, now)
