"""
Point d'entrée principal de l'agent Cybersafe.

Orchestration :
    [Tailer] → [Parser] → [Buffer] → [Sender] → Backend Cybersafe
                                          ↓
                                       [Spool]   (si envoi échoue)
"""
import logging
import logging.handlers
import os
import signal
import sys
from pathlib import Path

from .buffer import EventBuffer
from .config import AgentConfig, load_config
from .parser import line_to_event
from .sender import EventSender
from .spool import EventSpool
from .tailer import LogTailer


logger = logging.getLogger("cybersafe")


def setup_logging(config: AgentConfig):
    """Configure le logger root + fichier rotatif."""
    level = getattr(logging, config.log_level, logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger("cybersafe")
    root.setLevel(level)
    root.handlers.clear()

    # Console (stdout)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    # Fichier rotatif (10 Mo, 3 backups)
    try:
        log_dir = os.path.dirname(config.log_file)
        if log_dir:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            config.log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=3,
        )
        fh.setFormatter(formatter)
        root.addHandler(fh)
    except (PermissionError, FileNotFoundError) as e:
        print(
            f"⚠ Cannot write to log file {config.log_file}: {e}",
            file=sys.stderr,
        )


def build_spool(config: AgentConfig):
    """
    Construit l'EventSpool si activé en config.

    Retourne None si le spool est désactivé ou si l'init échoue
    (ex: dossier non créable). Dans ce dernier cas l'agent
    continue sans spool plutôt que de crasher.
    """
    if not config.spool_enabled:
        logger.warning(
            "⚠ Spool disabled in config — events will be lost on prolonged outages"
        )
        return None

    try:
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
            f"❌ Cannot initialize spool at {config.spool_dir}: {e} "
            f"— continuing without spool"
        )
        return None


def run():
    """Boucle principale de l'agent."""
    # ── 1. Config ────────────────────────────────────────────────────────
    config = load_config()
    setup_logging(config)

    logger.info("=" * 60)
    logger.info("🛡  Cybersafe Agent v1.0 — démarrage")
    logger.info(f"   Backend:    {config.api_url}")
    logger.info(f"   Token:      {config.token[:12]}...{config.token[-4:]}")
    logger.info(f"   Sources:    {len(config.sources)} fichier(s)")
    logger.info(
        f"   Buffer:     max {config.buffer_max_size} events / "
        f"{config.buffer_flush_interval}s"
    )
    logger.info(f"   Log file:   {config.log_file}")

    # ── 2. Spool (résilience disque) ─────────────────────────────────────
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
    # la session précédente (kill, reboot, perte réseau prolongée).
    if spool is not None and spool.count() > 0:
        logger.info(
            f"♻ Spool catchup at startup: {spool.count()} file(s) to replay"
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
        """Callback appelé pour chaque nouvelle ligne capturée."""
        event = line_to_event(line, source_path)
        buffer.add(event)

    tailer = LogTailer(
        paths=config.sources,
        callback=on_new_line,
        poll_interval=config.tail_poll_interval,
    )
    tailer.start()

    # ── 6. Gestion des signaux pour shutdown propre ──────────────────────
    stop_requested = {"value": False}

    def handle_signal(signum, frame):
        logger.info(f"📡 Signal {signum} reçu — arrêt en cours...")
        stop_requested["value"] = True

    signal.signal(signal.SIGINT, handle_signal)   # Ctrl+C
    signal.signal(signal.SIGTERM, handle_signal)  # systemd stop

    logger.info("👀 Surveillance active. Ctrl+C pour quitter.")

    # ── 7. Boucle d'attente ──────────────────────────────────────────────
    try:
        while not stop_requested["value"]:
            signal.pause()  # bloquant jusqu'à signal
    except (KeyboardInterrupt, SystemExit):
        pass

    # ── 8. Arrêt propre ──────────────────────────────────────────────────
    logger.info("🛑 Arrêt du tailer...")
    tailer.stop()

    logger.info("🛑 Flush final du buffer...")
    buffer.stop()

    logger.info("🛑 Fermeture du sender...")
    sender.close()

    logger.info("👋 Agent arrêté proprement.")


if __name__ == "__main__":
    run()
