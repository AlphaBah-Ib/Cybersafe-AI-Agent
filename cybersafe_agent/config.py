"""
Chargement et validation de la configuration YAML.

Le path par défaut du fichier config dépend de l'OS (cf. paths.py) :
    - Linux   : /etc/cybersafe/config.yaml
    - Windows : C:\\ProgramData\\Cybersafe\\config\\config.yaml

Format attendu (config.example.yaml) — défauts cross-OS :
    token: csa_xxxxxxxxxxxxxxx
    api_url: https://cybersafe-ai-production.up.railway.app/api
    sources:
      - /var/log/auth.log         # Linux  (champ obligatoire, peut être vide [] sur Windows)
      - /var/log/syslog
    buffer:
      max_size: 100
      flush_interval: 2.0
    spool:
      enabled: true
      # dir: par défaut auto-détecté selon l'OS (voir paths.py)
      max_size_mb: 100
    # log_file: par défaut auto-détecté selon l'OS (voir paths.py)
    log_level: INFO

Ordre de résolution du fichier config :
    1. Argument CLI explicite (`--config /path/to/config.yaml`)
    2. Variable d'environnement CYBERSAFE_CONFIG
    3. Default OS-aware (cf. paths.get_default_paths()["config"])
"""
import os
import sys
from dataclasses import dataclass, field
from typing import List

import yaml

from cybersafe_agent.paths import get_default_paths


def _default_log_file() -> str:
    """Retourne le path de log par défaut selon l'OS."""
    return get_default_paths()["log_file"]


def _default_spool_dir() -> str:
    """Retourne le path de spool par défaut selon l'OS."""
    return get_default_paths()["spool_dir"]


def _default_bookmarks_dir() -> str:
    """Retourne le path de bookmarks par défaut selon l'OS (vide sur Linux)."""
    return get_default_paths()["bookmarks_dir"]


@dataclass
class AgentConfig:
    """Configuration de l'agent (chargée depuis YAML)."""

    # ── Obligatoires ─────────────────────────────────────────────────────
    token: str
    api_url: str
    sources: List[str]

    # ── Buffer ───────────────────────────────────────────────────────────
    buffer_max_size: int = 100
    buffer_flush_interval: float = 2.0

    # ── Logging local (default cross-OS via factory) ────────────────────
    log_file: str = field(default_factory=_default_log_file)
    log_level: str = "INFO"

    # ── Polling tail ─────────────────────────────────────────────────────
    tail_poll_interval: float = 1.0

    # ── Retry réseau ─────────────────────────────────────────────────────
    retry_max_attempts: int = 6
    retry_base_delay: float = 1.0
    retry_max_delay: float = 60.0

    # ── Spool disque (résilience SOC-022, default cross-OS) ─────────────
    spool_enabled: bool = True
    spool_dir: str = field(default_factory=_default_spool_dir)
    spool_max_size_mb: int = 100

    # ── Windows Event Log (SOC-200 Phase 2) ─────────────────────────────
    # Channels Event Log surveillés. Si vide -> 8 channels MITRE ATT&CK
    # par défaut (voir platforms/windows.py).
    windows_channels: List[str] = field(default_factory=list)

    # EventIDs filtrés sur le channel Security (XPath natif).
    # Si vide -> 20 EventIDs MITRE ATT&CK par défaut.
    windows_security_event_ids: List[int] = field(default_factory=list)

    # Dossier de persistance des bookmarks Windows Event Log.
    # Default cross-OS via factory (vide sur Linux, C:\\ProgramData\\... sur Windows).
    windows_bookmarks_dir: str = field(default_factory=_default_bookmarks_dir)

    @property
    def ingest_url(self) -> str:
        """URL complète de l'endpoint d'ingestion."""
        return f"{self.api_url.rstrip('/')}/soc/ingest/"


def load_config(path: str = None) -> AgentConfig:
    """
    Charge la config depuis un fichier YAML.

    Cherche dans cet ordre :
    1. Argument `path` explicite (CLI --config)
    2. Variable d'env CYBERSAFE_CONFIG
    3. Default OS-aware (paths.get_default_paths()["config"])
    """
    default_config_path = get_default_paths()["config"]

    config_path = (
        path
        or os.environ.get("CYBERSAFE_CONFIG")
        or default_config_path
    )

    if not os.path.exists(config_path):
        print(f"[ERROR] Fichier de config introuvable : {config_path}", file=sys.stderr)
        print(
            f"        Créez-le à partir de config.example.yaml.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        print(f"[ERROR] YAML invalide dans {config_path} :", file=sys.stderr)
        print(f"        {e}", file=sys.stderr)
        sys.exit(1)

    # Validation des champs obligatoires
    required = ["token", "api_url", "sources"]
    missing = [k for k in required if k not in raw]
    if missing:
        print(f"[ERROR] Champs obligatoires manquants : {missing}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(raw["sources"], list):
        print("[ERROR] Le champ 'sources' doit être une liste.", file=sys.stderr)
        sys.exit(1)

    # Validation du format du token
    token = raw["token"].strip()
    if not token.startswith("csa_") or len(token) < 20:
        print("[ERROR] Token invalide (doit commencer par 'csa_').", file=sys.stderr)
        sys.exit(1)

    # Construction du dataclass avec defaults
    buffer_cfg = raw.get("buffer", {}) or {}
    windows_cfg = raw.get("windows", {}) or {}
    spool_cfg = raw.get("spool", {}) or {}

    # Defaults cross-OS pour les paths non spécifiés dans le YAML
    os_defaults = get_default_paths()

    return AgentConfig(
        token=token,
        api_url=raw["api_url"].strip(),
        sources=[s.strip() for s in raw["sources"] if s.strip()],
        buffer_max_size=int(buffer_cfg.get("max_size", 100)),
        buffer_flush_interval=float(buffer_cfg.get("flush_interval", 2.0)),
        log_file=raw.get("log_file", os_defaults["log_file"]),
        log_level=raw.get("log_level", "INFO").upper(),
        tail_poll_interval=float(raw.get("tail_poll_interval", 1.0)),
        retry_max_attempts=int(raw.get("retry_max_attempts", 6)),
        retry_base_delay=float(raw.get("retry_base_delay", 1.0)),
        retry_max_delay=float(raw.get("retry_max_delay", 60.0)),
        spool_enabled=bool(spool_cfg.get("enabled", True)),
        spool_dir=str(spool_cfg.get("dir", os_defaults["spool_dir"])).strip(),
        spool_max_size_mb=int(spool_cfg.get("max_size_mb", 100)),
        windows_channels=[str(c).strip() for c in (windows_cfg.get("channels") or []) if str(c).strip()],
        windows_security_event_ids=[int(eid) for eid in (windows_cfg.get("security_event_ids") or []) if str(eid).strip().isdigit()],
        windows_bookmarks_dir=str(windows_cfg.get("bookmarks_dir", os_defaults["bookmarks_dir"])).strip(),
    )
