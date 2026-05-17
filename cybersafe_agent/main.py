"""
Point d'entrée principal de l'agent Cybersafe.

Orchestration :
    [Tailer] -> [Parser] -> [Buffer] -> [Sender] -> Backend Cybersafe
                                              |
                                           [Spool]   (si envoi echoue)

Modes d'invocation :

    1. Console / dev (Linux & Windows) :
         python -m cybersafe_agent
         python -m cybersafe_agent --config /path/to/config.yaml
         cybersafe-agent.exe                      (Windows console)

    2. Service Windows (SCM-managed) :
         cybersafe-agent.exe --service            (lance par le SCM via MSI)

       Le flag --service active le wrapper pywin32 ServiceFramework
       (cf. service_windows.py) qui signale SERVICE_RUNNING au SCM,
       evitant le timeout 1053/7000/7009.
"""
import argparse
import logging
import logging.handlers
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from cybersafe_agent.buffer import EventBuffer
from cybersafe_agent.config import AgentConfig, load_config
from cybersafe_agent.parser import line_to_event
from cybersafe_agent.paths import is_windows
from cybersafe_agent.sender import EventSender
from cybersafe_agent.spool import EventSpool
from cybersafe_agent.tailer import LogTailer


logger = logging.getLogger("cybersafe")


# =============================================================================
# Logging setup
# =============================================================================

def setup_logging(config: AgentConfig):
    """
    Configure le logger root + fichier rotatif.

    Si l'ecriture du fichier echoue (perms, FS read-only, etc.), on continue
    avec un logger console-only au lieu de crasher. Un agent qui logge dans
    stderr est toujours mieux qu'un agent qui meurt silencieusement.
    """
    level = getattr(logging, config.log_level, logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger("cybersafe")
    root.setLevel(level)
    root.handlers.clear()

    # Console handler (stdout) — toujours actif, sert de fallback
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    # File handler rotatif (10 Mo, 3 backups)
    # Cree le dossier parent au besoin (utile sur Windows fresh install)
    try:
        log_dir = os.path.dirname(config.log_file)
        if log_dir:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            config.log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        fh.setFormatter(formatter)
        root.addHandler(fh)
    except (PermissionError, FileNotFoundError, OSError) as e:
        print(
            f"[WARN] Cannot write to log file {config.log_file}: {e} "
            f"(continuing with console-only logging)",
            file=sys.stderr,
        )


def build_spool(config: AgentConfig):
    """
    Construit l'EventSpool si active en config.

    Retourne None si le spool est desactive ou si l'init echoue
    (ex: dossier non creable). L'agent continue sans spool plutot
    que de crasher.
    """
    if not config.spool_enabled:
        logger.warning(
            "Spool disabled in config - events will be lost on prolonged outages"
        )
        return None

    try:
        # Cree le dossier parent au besoin
        Path(config.spool_dir).mkdir(parents=True, exist_ok=True)
        spool = EventSpool(
            directory=config.spool_dir,
            max_size_mb=config.spool_max_size_mb,
        )
        logger.info(
            f"   Spool:      {config.spool_dir} "
            f"(max {config.spool_max_size_mb} MB, {spool.count()} file(s) queued)"
        )
        return spool
    except Exception as e:
        logger.error(
            f"Cannot initialize spool at {config.spool_dir}: {e} "
            f"- continuing without spool"
        )
        return None


# =============================================================================
# Main agent loop
# =============================================================================

def run(stop_event: Optional[threading.Event] = None, config_path: Optional[str] = None):
    """
    Boucle principale de l'agent.

    Args:
        stop_event: Si fourni (ex: par le wrapper service Windows),
                    la boucle s'arrete proprement quand stop_event.is_set()
                    devient True. Sinon, un Event interne est cree et
                    pilote par les signaux SIGINT/SIGTERM (Unix) ou
                    Ctrl+C (Windows console).
        config_path: Path explicite vers config.yaml (sinon resolution
                     standard via env var ou default OS-aware).
    """
    # ── 1. Config ────────────────────────────────────────────────────────
    config = load_config(path=config_path)
    setup_logging(config)

    logger.info("=" * 60)
    logger.info("Cybersafe Agent - demarrage")
    logger.info(f"   Backend:    {config.api_url}")
    logger.info(f"   Token:      {config.token[:12]}...{config.token[-4:]}")
    logger.info(f"   Sources:    {len(config.sources)} fichier(s)")
    logger.info(
        f"   Buffer:     max {config.buffer_max_size} events / "
        f"{config.buffer_flush_interval}s"
    )
    logger.info(f"   Log file:   {config.log_file}")

    # ── 2. Spool (resilience disque) ─────────────────────────────────────
    spool = build_spool(config)

    logger.info("=" * 60)

    # ── 3. Sender (avec spool si dispo) ──────────────────────────────────
    sender = EventSender(
        ingest_url=config.ingest_url,
        token=config.token,
        max_attempts=config.retry_max_attempts,
        base_delay=config.retry_base_delay,
        max_delay=config.retry_max_delay,
        spool=spool,
    )

    # Rattrapage : tente de rejouer ce qui dort dans le spool depuis
    # la session precedente (kill, reboot, perte reseau prolongee).
    if spool is not None and spool.count() > 0:
        logger.info(
            f"Spool catchup at startup: {spool.count()} file(s) to replay"
        )
        sender.drain_spool_blocking()

    # ── 4. Buffer (flush taille OU temps, callback = sender.send) ────────
    buffer = EventBuffer(
        max_size=config.buffer_max_size,
        flush_interval=config.buffer_flush_interval,
        flush_callback=sender.send,
    )
    buffer.start()

    # ── 5. Tailer (un thread par fichier) ────────────────────────────────
    def on_new_line(line: str, source_path: str):
        """Callback appele pour chaque nouvelle ligne capturee."""
        event = line_to_event(line, source_path)
        buffer.add(event)

    tailer = LogTailer(
        paths=config.sources,
        callback=on_new_line,
        poll_interval=config.tail_poll_interval,
    )
    tailer.start()

    # ── 6. Setup du stop_event cross-OS ──────────────────────────────────
    # Si pas fourni par le wrapper service Windows, on cree un Event interne
    # et on l'arme via les signaux Unix (SIGINT, SIGTERM).
    if stop_event is None:
        stop_event = threading.Event()

        def handle_signal(signum, frame):
            logger.info(f"Signal {signum} recu - arret en cours...")
            stop_event.set()

        # SIGINT (Ctrl+C) : supporte sur tous les OS
        signal.signal(signal.SIGINT, handle_signal)

        # SIGTERM : Unix uniquement (Windows ne le supporte pas dans signal.signal)
        if not is_windows():
            signal.signal(signal.SIGTERM, handle_signal)

    logger.info("Surveillance active. Ctrl+C pour quitter (ou stop via SCM).")

    # ── 7. Boucle d'attente cross-OS ────────────────────────────────────
    # signal.pause() n'existe pas sur Windows. On utilise Event.wait()
    # qui se debloque immediatement quand stop_event.set() est appele
    # (par un signal Unix OU par le wrapper service Windows).
    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=1.0)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt recu - arret en cours...")
        stop_event.set()

    # ── 8. Arret propre ──────────────────────────────────────────────────
    logger.info("Arret du tailer...")
    tailer.stop()

    logger.info("Flush final du buffer...")
    buffer.stop()

    logger.info("Fermeture du sender...")
    sender.close()

    logger.info("Agent arrete proprement.")


# =============================================================================
# CLI entry point
# =============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    """Construit le parseur d'arguments CLI."""
    parser = argparse.ArgumentParser(
        prog="cybersafe-agent",
        description="Cybersafe-AI Agent - SOC log collector and forwarder.",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help=(
            "Path to config.yaml. Overrides $CYBERSAFE_CONFIG env var and "
            "OS default (Linux: /etc/cybersafe/config.yaml, "
            "Windows: C:\\ProgramData\\Cybersafe\\config\\config.yaml)."
        ),
    )
    parser.add_argument(
        "--service",
        action="store_true",
        help=(
            "Windows only: run as a Windows service via pywin32 "
            "ServiceFramework (used by the MSI-installed service). "
            "On Linux/macOS this flag has no effect and is ignored."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version="cybersafe-agent 1.1.0",
    )
    return parser


def main(argv=None):
    """
    Point d'entree CLI principal.

    Dispatch :
        --service          -> run_as_service() (Windows SCM wrapper)
        sinon              -> run() (mode console, Linux ou Windows)
    """
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Set CYBERSAFE_CONFIG env var if --config was passed.
    # This is useful because load_config() in service mode is called from
    # a different thread/context where argv may not be available.
    if args.config:
        os.environ["CYBERSAFE_CONFIG"] = args.config

    if args.service:
        if not is_windows():
            print(
                "[ERROR] --service is only supported on Windows. "
                "Run without --service on Linux/macOS.",
                file=sys.stderr,
            )
            sys.exit(2)
        # Lazy import: only loaded when running as Windows service
        from cybersafe_agent.service_windows import run_as_service
        run_as_service()
    else:
        run(config_path=args.config)


if __name__ == "__main__":
    main()
