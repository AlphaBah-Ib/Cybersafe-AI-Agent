# -*- coding: utf-8 -*-
"""
SOC-RESPONSE — point d'entree autonome du service de remediation.

Lance par systemd (cybersafe-remediation.service) avec la capability
CAP_NET_ADMIN. Poll independamment le backend et execute les ordres ban/unban.
Ne partage RIEN avec l'agent de collecte hormis le fichier de config (meme
api_url + token).

Usage :
    python -m cybersafe_agent.remediation_service --config /etc/cybersafe/config.yaml
"""
import argparse
import logging
import signal
import sys
import threading

from cybersafe_agent.config import load_config
from cybersafe_agent.remediation import remediation_loop

logger = logging.getLogger("cybersafe.remediation")


def _setup_logging():
    """Logging simple vers stdout/journald (systemd capture)."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root = logging.getLogger("cybersafe")
    root.setLevel(logging.INFO)
    root.addHandler(handler)


def _build_arg_parser():
    p = argparse.ArgumentParser(
        prog="cybersafe-remediation",
        description="Service de remediation Cybersafe-AI (ban/unban IP).",
    )
    p.add_argument("--config", dest="config_path", default=None,
                   help="Chemin vers config.yaml (sinon resolution standard).")
    return p


def main(argv=None):
    args = _build_arg_parser().parse_args(argv)
    _setup_logging()

    config = load_config(path=args.config_path)

    logger.info("=" * 60)
    logger.info("Cybersafe Remediation Service - demarrage")
    logger.info("   Backend: %s", config.api_url)
    logger.info("   Poll:    %ss", getattr(config, "remediation_poll_interval", 60.0))
    logger.info("=" * 60)

    if not getattr(config, "remediation_enabled", True):
        logger.warning("remediation_enabled=False dans la config : arret immediat.")
        return 0

    stop_event = threading.Event()

    def _handle(signum, frame):
        logger.info("Signal %s recu - arret en cours...", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    remediation_loop(config, stop_event)
    logger.info("Service de remediation arrete proprement.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
