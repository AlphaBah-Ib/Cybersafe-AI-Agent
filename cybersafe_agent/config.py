"""
Chargement et validation de la configuration YAML.

Format attendu (config.example.yaml) :
    token: csa_xxxxxxxxxxxxxxx
    api_url: https://cybersafe-ai-production.up.railway.app/api
    sources:
      - /var/log/auth.log
      - /var/log/syslog
    buffer:
      max_size: 100
      flush_interval: 2.0
    log_file: /var/log/cybersafe-agent.log
    log_level: INFO
"""
import os
import sys
from dataclasses import dataclass
from typing import List

import yaml


# Chemin par défaut pour la prod (installé via systemd)
DEFAULT_CONFIG_PATH = "/etc/cybersafe/config.yaml"


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

    # ── Logging local ────────────────────────────────────────────────────
    log_file: str = "/var/log/cybersafe-agent.log"
    log_level: str = "INFO"

    # ── Polling tail ─────────────────────────────────────────────────────
    tail_poll_interval: float = 1.0

    # ── Retry réseau ─────────────────────────────────────────────────────
    retry_max_attempts: int = 6
    retry_base_delay: float = 1.0
    retry_max_delay: float = 60.0

    @property
    def ingest_url(self) -> str:
        """URL complète de l'endpoint d'ingestion."""
        return f"{self.api_url.rstrip('/')}/soc/ingest/"


def load_config(path: str = None) -> AgentConfig:
    """
    Charge la config depuis un fichier YAML.

    Cherche dans cet ordre :
    1. Argument `path` explicite
    2. Variable d'env CYBERSAFE_CONFIG
    3. /etc/cybersafe/config.yaml (chemin par défaut prod)
    """
    config_path = (
        path
        or os.environ.get("CYBERSAFE_CONFIG")
        or DEFAULT_CONFIG_PATH
    )

    if not os.path.exists(config_path):
        print(f"❌ Fichier de config introuvable : {config_path}", file=sys.stderr)
        print(
            f"   Crée-le à partir de config.example.yaml.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        with open(config_path, "r") as f:
            raw = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        print(f"❌ YAML invalide dans {config_path} :", file=sys.stderr)
        print(f"   {e}", file=sys.stderr)
        sys.exit(1)

    # Validation des champs obligatoires
    required = ["token", "api_url", "sources"]
    missing = [k for k in required if k not in raw]
    if missing:
        print(f"❌ Champs obligatoires manquants : {missing}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(raw["sources"], list) or not raw["sources"]:
        print("❌ Le champ 'sources' doit être une liste non vide.", file=sys.stderr)
        sys.exit(1)

    # Validation du format du token
    token = raw["token"].strip()
    if not token.startswith("csa_") or len(token) < 20:
        print("❌ Token invalide (doit commencer par 'csa_').", file=sys.stderr)
        sys.exit(1)

    # Construction du dataclass avec defaults
    buffer_cfg = raw.get("buffer", {}) or {}
    return AgentConfig(
        token=token,
        api_url=raw["api_url"].strip(),
        sources=[s.strip() for s in raw["sources"] if s.strip()],
        buffer_max_size=int(buffer_cfg.get("max_size", 100)),
        buffer_flush_interval=float(buffer_cfg.get("flush_interval", 2.0)),
        log_file=raw.get("log_file", "/var/log/cybersafe-agent.log"),
        log_level=raw.get("log_level", "INFO").upper(),
        tail_poll_interval=float(raw.get("tail_poll_interval", 1.0)),
        retry_max_attempts=int(raw.get("retry_max_attempts", 6)),
        retry_base_delay=float(raw.get("retry_base_delay", 1.0)),
        retry_max_delay=float(raw.get("retry_max_delay", 60.0)),
    )
