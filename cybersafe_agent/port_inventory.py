"""
Inventaire des ports en ecoute (SOC — surface d'attaque).

Collecte LOCALE (pas de scan reseau actif) des ports TCP en ecoute :
  - Linux/macOS : `ss -tlnp` (fallback `netstat -tlnp`)
  - Windows     : `netstat -ano -p TCP` + mapping PID->nom via `tasklist`

Le resultat est emballe dans un event 'port_inventory' envoye via le pipeline
standard. Le contrat de sortie (liste de dicts port/address/process/exposed/
sensitive, puis build_port_inventory_event) est IDENTIQUE quel que soit l'OS :
le backend ne distingue pas la plateforme source.
"""
from __future__ import annotations

import logging
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Dict, List

logger = logging.getLogger("cybersafe.port_inventory")

SENSITIVE_PORTS = {
    3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached",
    5984: "CouchDB", 9300: "Elasticsearch-transport", 2375: "Docker-API",
    2376: "Docker-API-TLS", 6443: "Kubernetes-API", 5601: "Kibana",
}

# Adresses considerees comme purement locales (NON exposees).
_LOCAL_PREFIXES = ("127.", "[::1]", "::1")


def _run(cmd: list) -> str:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, check=False,
        )
        return out.stdout or ""
    except Exception as exc:  # noqa: BLE001
        logger.warning("[port-inventory] %s a echoue: %s", cmd[0], exc)
        return ""


def _is_exposed(addr: str) -> bool:
    """Decide si une adresse d'ecoute est exposee (commune Linux + Windows).

    Exposee si elle ecoute sur toutes les interfaces (0.0.0.0, *, ::, [::])
    ou sur une adresse qui n'est pas purement loopback (127.x / ::1).
    """
    if addr in ("0.0.0.0", "*", "::", "[::]"):
        return True
    return not addr.startswith(_LOCAL_PREFIXES)


def _make_port_entry(addr: str, port: int, proc: str) -> Dict:
    """Construit une entree de port normalisee (forme commune a tous les OS)."""
    return {
        "port": port,
        "address": addr,
        "process": proc,
        "exposed": _is_exposed(addr),
        "sensitive": SENSITIVE_PORTS.get(port, ""),
    }


# ---------------------------------------------------------------------------
# Linux / macOS : parsing de `ss -tlnp` (ou `netstat -tlnp`)
# ---------------------------------------------------------------------------
def _parse_ss(output: str) -> List[Dict]:
    ports = []
    for line in output.splitlines():
        if "LISTEN" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[3]
        m = re.search(r":(\d+)$", local)
        if not m:
            continue
        port = int(m.group(1))
        addr = local[: m.start()]
        proc = ""
        pm = re.search(r'\("([^"]+)"', line)
        if pm:
            proc = pm.group(1)
        ports.append(_make_port_entry(addr, port, proc))
    return ports


# ---------------------------------------------------------------------------
# Windows : parsing de `netstat -ano -p TCP` + mapping PID -> nom de process
# ---------------------------------------------------------------------------
def _windows_pid_to_name() -> Dict[int, str]:
    """Mapping PID -> nom de l'executable, best-effort via `tasklist`.

    Robuste : toute erreur (tasklist absent, sortie inattendue, timeout)
    retourne {} -> les entrees auront process="" mais la collecte reussit.
    """
    mapping: Dict[int, str] = {}
    out = _run(["tasklist", "/FO", "CSV", "/NH"])
    if not out:
        return mapping
    # Format CSV sans en-tete : "Image Name","PID","Session Name","Session#","Mem Usage"
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # Decoupage CSV simple : champs entre guillemets separes par des virgules.
        fields = re.findall(r'"([^"]*)"', line)
        if len(fields) < 2:
            continue
        name = fields[0]
        try:
            pid = int(fields[1])
        except (ValueError, IndexError):
            continue
        mapping[pid] = name
    return mapping


def _parse_netstat_windows(output: str, pid_to_name: Dict[int, str]) -> List[Dict]:
    """Parse la sortie de `netstat -ano` Windows (lignes TCP LISTENING).

    Robuste a la localisation : on ne s'appuie ni sur l'en-tete ni sur un mot
    traduit, mais sur la structure des colonnes et sur le mot-cle 'LISTENING'
    (qui reste en anglais meme sur un Windows FR).

    Colonnes attendues : Proto  AdresseLocale  AdresseDistante  Etat  PID
      TCP    0.0.0.0:22       0.0.0.0:0        LISTENING   1234
      TCP    [::]:445         [::]:0           LISTENING   4
    """
    ports = []
    for line in output.splitlines():
        # Mot-cle stable (non localise) marquant un socket en ecoute.
        if "LISTENING" not in line:
            continue
        parts = line.split()
        # Proto, Local, Remote, State, PID -> au moins 5 colonnes.
        if len(parts) < 5:
            continue
        proto = parts[0].upper()
        if not proto.startswith("TCP"):
            continue
        local = parts[1]
        pid_str = parts[-1]

        # Extrait le port en fin d'adresse locale (IPv4 ou IPv6).
        m = re.search(r":(\d+)$", local)
        if not m:
            continue
        port = int(m.group(1))
        addr = local[: m.start()]

        proc = ""
        try:
            pid = int(pid_str)
            proc = pid_to_name.get(pid, "")
        except ValueError:
            pass

        ports.append(_make_port_entry(addr, port, proc))
    return ports


# ---------------------------------------------------------------------------
# Point d'entree multiplateforme
# ---------------------------------------------------------------------------
def collect_listening_ports() -> List[Dict]:
    system = platform.system()

    if system == "Windows":
        if not shutil.which("netstat"):
            logger.warning("[port-inventory] 'netstat' indisponible sur Windows.")
            return []
        out = _run(["netstat", "-ano", "-p", "TCP"])
        pid_to_name = _windows_pid_to_name()
        ports = _parse_netstat_windows(out, pid_to_name)
    else:
        # Linux / macOS
        if shutil.which("ss"):
            out = _run(["ss", "-tlnp"])
        elif shutil.which("netstat"):
            out = _run(["netstat", "-tlnp"])
        else:
            logger.warning("[port-inventory] ni 'ss' ni 'netstat' disponibles.")
            return []
        ports = _parse_ss(out)

    # Dedup (port, address) + tri par port : commun a tous les OS.
    seen = {}
    for p in ports:
        seen[(p["port"], p["address"])] = p
    return sorted(seen.values(), key=lambda x: x["port"])


def build_port_inventory_event() -> dict:
    ports = collect_listening_ports()
    exposed = [p for p in ports if p["exposed"]]
    sensitive = [p for p in exposed if p["sensitive"]]
    raw = (
        f"{len(ports)} port(s) en ecoute, {len(exposed)} expose(s), "
        f"{len(sensitive)} sensible(s) expose(s)."
    )
    severity = "warning" if sensitive else "info"
    return {
        "source": "port-inventory",
        "raw": raw[:5000],
        "event_type": "port_inventory",
        "severity": severity,
        "ts": datetime.now(timezone.utc).isoformat(),
        "parsed": {
            "ports": ports,
            "total": len(ports),
            "exposed_count": len(exposed),
            "sensitive_exposed": [
                {"port": p["port"], "service": p["sensitive"]} for p in sensitive
            ],
        },
    }
