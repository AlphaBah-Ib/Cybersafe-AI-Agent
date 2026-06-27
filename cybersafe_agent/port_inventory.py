"""
Inventaire des ports en ecoute (SOC — surface d'attaque).

Collecte LOCALE via `ss -tlnp` (pas de scan reseau actif). Le resultat est
emballe dans un event 'port_inventory' envoye via le pipeline standard.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import List, Dict

logger = logging.getLogger("cybersafe.port_inventory")

SENSITIVE_PORTS = {
    3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached",
    5984: "CouchDB", 9300: "Elasticsearch-transport", 2375: "Docker-API",
    2376: "Docker-API-TLS", 6443: "Kubernetes-API", 5601: "Kibana",
}


def _run(cmd: list) -> str:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, check=False,
        )
        return out.stdout or ""
    except Exception as exc:  # noqa: BLE001
        logger.warning("[port-inventory] %s a echoue: %s", cmd[0], exc)
        return ""


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
        exposed = (
            addr in ("0.0.0.0", "*", "::", "[::]")
            or not addr.startswith(("127.", "[::1]"))
        )
        ports.append({
            "port": port, "address": addr, "process": proc,
            "exposed": bool(exposed), "sensitive": SENSITIVE_PORTS.get(port, ""),
        })
    return ports


def collect_listening_ports() -> List[Dict]:
    out = ""
    if shutil.which("ss"):
        out = _run(["ss", "-tlnp"])
    elif shutil.which("netstat"):
        out = _run(["netstat", "-tlnp"])
    else:
        logger.warning("[port-inventory] ni 'ss' ni 'netstat' disponibles.")
        return []
    ports = _parse_ss(out)
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
