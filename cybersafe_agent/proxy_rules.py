# -*- coding: utf-8 -*-
"""
US-SOC-R12 porte 4a-2 — regles WAF temporaires et blocage geographique : validation
COMMUNE a la garde des ordres, au service de remediation et au programme root
(cybersafe-proxy-apply). Memes regles que le serveur (apps/soc/response/actions.py),
memes cles : une regle n'atteint jamais nginx si un seul de ces controles echoue.

Trois modeles fermes, jamais de texte libre :
  - block_path       : prefixe de chemin ; « / » seul interdit ;
  - block_user_agent : refuse s'il figure dans un navigateur ou un robot de moteur
                       de recherche courant ;
  - block_method     : methodes rarement legitimes uniquement (jamais GET, POST,
                       HEAD, PUT, PATCH, DELETE ni OPTIONS).
Les valeurs ne contiennent jamais de guillemet, d'antislash, de dollar ni d'accolade :
elles ne peuvent pas sortir de la chaine nginx qui les contient.
"""
import hashlib
import re

WAF_RULES = ("block_path", "block_user_agent", "block_method")
WAF_METHODS = frozenset({"TRACE", "TRACK", "DEBUG", "CONNECT", "PROPFIND", "PROPPATCH",
                         "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"})
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{1,199}$")
_UA_RE = re.compile(r"^[A-Za-z0-9 ._/()+;:,-]{4,100}$")
_KEY_RE = re.compile(r"^waf:[0-9a-f]{16}$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
REFERENCE_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Opera/9.80 (Windows NT 6.1) Presto/2.12.388 Version/12.18 OPR/110.0.0.0",
)
MAX_WAF_RULES = 50
MAX_COUNTRIES = 5


def waf_key(rule, value):
    digest = hashlib.sha256(("%s\n%s" % (rule, value)).encode("utf-8")).hexdigest()
    return "waf:" + digest[:16]


def waf_error(rule, value):
    """None si la regle est sure, sinon le motif du refus."""
    if rule not in WAF_RULES:
        return "modele de regle WAF inconnu"
    if not isinstance(value, str):
        return "valeur de regle WAF invalide"
    if rule == "block_path":
        if not _PATH_RE.match(value) or not re.search(r"[A-Za-z0-9]", value):
            return "chemin invalide (« / » seul interdit, caracteres limites)"
        return None
    if rule == "block_user_agent":
        if not _UA_RE.match(value) or len(re.findall(r"[A-Za-z0-9]", value)) < 4:
            return "User-Agent invalide (4 a 100 caracteres limites)"
        low = value.lower()
        if any(low in ref.lower() for ref in REFERENCE_USER_AGENTS):
            return "User-Agent trop generique (navigateurs ou moteurs de recherche legitimes)"
        return None
    if value not in WAF_METHODS:
        return "methode non autorisee au blocage"
    return None


def is_waf_key(value):
    return isinstance(value, str) and bool(_KEY_RE.match(value))


def is_country(value):
    return isinstance(value, str) and bool(_COUNTRY_RE.match(value))


def _literal(value):
    """Caracteres speciaux d'une expression reguliere -> classe a un caractere (sans antislash)."""
    return "".join("[%s]" % c if c in ".()+" else c for c in value)


def nginx_pattern(rule, value):
    """Cle de « map » nginx (entre guillemets) pour une regle deja validee."""
    if rule == "block_path":
        return "~*^" + _literal(value)
    if rule == "block_user_agent":
        return "~*" + _literal(value)
    return value
