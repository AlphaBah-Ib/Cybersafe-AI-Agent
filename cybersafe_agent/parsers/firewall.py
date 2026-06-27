"""
Parser des logs de pare-feu (ufw / iptables / nftables).

Lit les lignes de blocage type :
  [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=54321 DPT=22 ...
  kernel: iptables denied: IN=eth0 ... SRC=1.2.3.4 ... DPT=3389 ...

Produit un event conforme au contrat /api/soc/ingest/ avec, dans parsed :
  - event_kind   : "port_scan_attempt" (consomme par les regles de detection)
  - src_ip       : IP source (SRC=)
  - dst_port     : port destination (DPT=)
  - src_port     : port source (SPT=)
  - proto        : protocole (PROTO=)
  - action       : BLOCK / DROP / DENY / REJECT (selon le log)

Les regles backend (scan de ports, flood, DROP repetes) agregent ces events
par src_ip pour decider d'une menace. Le parser ne decide pas seul : il fournit
des donnees normalisees.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone

# Champs cles=valeur des logs netfilter (SRC=1.2.3.4, DPT=22, PROTO=TCP...)
_KV = re.compile(r"\b([A-Z]+)=(\S+)")

# Marqueurs d'une ligne firewall pertinente + action associee
_ACTION_PATTERNS = [
    (re.compile(r"\[UFW BLOCK\]", re.I), "BLOCK"),
    (re.compile(r"\[UFW (?:AUDIT|ALLOW)\]", re.I), "AUDIT"),
    (re.compile(r"\bDROP\b"), "DROP"),
    (re.compile(r"\bDENY\b", re.I), "DENY"),
    (re.compile(r"\bREJECT\b", re.I), "REJECT"),
    (re.compile(r"iptables denied", re.I), "DROP"),
    (re.compile(r"nft (?:drop|reject)", re.I), "DROP"),
]


def _detect_action(line: str):
    """Renvoie l'action (BLOCK/DROP/...) si la ligne est un log firewall, sinon None."""
    for pat, action in _ACTION_PATTERNS:
        if pat.search(line):
            return action
    # ligne avec SRC=/DPT= mais sans action connue : on la traite quand meme
    # comme un log firewall generique si elle contient les deux champs.
    if "SRC=" in line and "DPT=" in line:
        return "BLOCK"
    return None


def parse_firewall(line: str) -> dict:
    """Parse une ligne firewall -> dict de champs normalises."""
    action = _detect_action(line)
    if action is None:
        return {"parse_failed": True}

    kv = dict(_KV.findall(line))
    src_ip = kv.get("SRC", "")
    dst_port = kv.get("DPT", "")
    src_port = kv.get("SPT", "")
    proto = kv.get("PROTO", "")

    parsed = {
        "event_kind": "port_scan_attempt",
        "action": action,
        "src_ip": src_ip,
        "dst_ip": kv.get("DST", ""),
        "proto": proto,
    }
    if dst_port.isdigit():
        parsed["dst_port"] = int(dst_port)
    if src_port.isdigit():
        parsed["src_port"] = int(src_port)
    return parsed


def line_to_event(line: str, source_path: str) -> dict:
    """Transforme une ligne de log firewall en payload event."""
    parsed = parse_firewall(line)
    if parsed.get("parse_failed"):
        # Ligne non reconnue comme firewall : event info neutre (pas de fausse
        # alerte, pas de event_kind => les regles firewall ne se declenchent pas).
        return {
            "source": os.path.basename(source_path),
            "raw": line.strip()[:5000],
            "event_type": "firewall_unparsed",
            "severity": "info",
            "ts": datetime.now(timezone.utc).isoformat(),
            "parsed": {},
        }
    return {
        "source": os.path.basename(source_path),
        "raw": line.strip()[:5000],
        "event_type": "firewall_block",
        "severity": "low",
        "ts": datetime.now(timezone.utc).isoformat(),
        "parsed": parsed,
    }


__all__ = ["parse_firewall", "line_to_event"]
