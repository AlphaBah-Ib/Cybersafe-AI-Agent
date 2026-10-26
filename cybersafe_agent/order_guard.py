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
# [R12-P2] v2 : les parametres sont signes ; exigee des qu'un ordre en porte.
SIGNED_FIELDS_V2 = SIGNED_FIELDS + ("params",)
SIG_V1, SIG_V2 = "ed25519", "ed25519-v2"
ALLOWED_ACTIONS = frozenset({"ban_ip", "unban_ip", "rate_limit_ip", "remove_rate_limit",
                             "block_ip_range", "unblock_ip_range"})  # [R12-P3]
# [R12-P3] plages : taille maximale, reseaux jamais bloquables par plage.
RANGE_ACTIONS = frozenset({"block_ip_range", "unblock_ip_range"})
RANGE_MIN_PREFIX = {4: 24, 6: 48}
_FORBIDDEN_RANGES = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8",
))
# Parametres autorises par action : nom -> (min, max). Memes bornes que le serveur.
PARAM_SPECS = {
    "rate_limit_ip": {"rate_per_minute": (1, 600), "burst": (1, 100)},
    "block_ip_range": {"justification": ("str", 10, 500)},
}
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


def canonical(order, fields=SIGNED_FIELDS):
    body = {k: order.get(k) for k in fields}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _public_key():
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(_ORDER_PUBLIC_KEY_B64))


def check_signature(order):
    if order.get("sig_alg") not in (SIG_V1, SIG_V2):
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
        fields = SIGNED_FIELDS_V2 if order.get("sig_alg") == SIG_V2 else SIGNED_FIELDS
        _public_key().verify(sig, canonical(order, fields))
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


def check_range(order):
    """[R12-P3] Plage CIDR exacte, taille bornee, jamais un reseau reserve ou interne."""
    raw = order.get("target_ip")
    if not isinstance(raw, str) or "/" not in raw:
        raise OrderRejected("plage invalide (notation CIDR attendue): %r" % (raw,))
    try:
        net = ipaddress.ip_network(raw.strip(), strict=True)
    except ValueError:
        raise OrderRejected("plage invalide: %r" % (raw,)) from None
    if net.prefixlen < RANGE_MIN_PREFIX[net.version]:
        raise OrderRejected("plage trop large: %s (/%d minimum)" % (net, RANGE_MIN_PREFIX[net.version]))
    if order.get("action") == "unblock_ip_range":
        return  # une levee est toujours permise
    for forbidden in _FORBIDDEN_RANGES:
        if forbidden.version == net.version and net.overlaps(forbidden):
            raise OrderRejected("plage %s refusee (reseau reserve ou interne)" % net)


def check_ip(order):
    if order.get("action") in RANGE_ACTIONS:  # [R12-P3]
        return check_range(order)
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


def check_params(order):
    """[R12-P2] Parametres : signes (v2), liste fermee, entiers dans les bornes."""
    params = order.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise OrderRejected("parametres illisibles")
    spec = PARAM_SPECS.get(order.get("action"), {})
    if (params or spec) and order.get("sig_alg") != SIG_V2:
        raise OrderRejected("parametres non signes (signature v2 exigee)")
    unknown = sorted(set(params) - set(spec))
    if unknown:
        raise OrderRejected("parametre(s) non autorise(s) : %s" % ", ".join(map(repr, unknown)))
    for name, bounds in spec.items():
        value = params.get(name)
        if len(bounds) == 3:  # texte : ("str", longueur min, longueur max)
            _, lo, hi = bounds
            if not isinstance(value, str):
                raise OrderRejected("parametre %s : texte attendu" % name)
            if any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise OrderRejected("parametre %s : caracteres de controle interdits" % name)
            if not lo <= len(value.strip()) <= hi:
                raise OrderRejected("parametre %s : longueur hors bornes (%s a %s)" % (name, lo, hi))
            continue
        lo, hi = bounds
        if isinstance(value, bool) or not isinstance(value, int):
            raise OrderRejected("parametre %s : entier attendu" % name)
        if not lo <= value <= hi:
            raise OrderRejected("parametre %s hors bornes (%s a %s)" % (name, lo, hi))


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
    check_params(order)  # [R12-P2]
    check_ip(order)
    nonce = order.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise OrderRejected("nonce absent")
    journal.consume(nonce, expires, now)
