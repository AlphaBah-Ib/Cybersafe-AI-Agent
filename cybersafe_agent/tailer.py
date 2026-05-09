"""
Tail multi-fichiers thread-safe.

SOC-020 :
- Tail en continu (suivi de la fin du fichier, comme tail -f)
- 1 thread par fichier surveillé
- Détecte la rotation de logs (logrotate) et ré-ouvre le fichier
- Détecte la troncature et ré-ouvre le fichier
"""
import logging
import os
import threading
import time
from typing import Callable, List


logger = logging.getLogger("cybersafe.tailer")


class LogTailer:
    """
    Surveille plusieurs fichiers de log et appelle un callback
    pour chaque nouvelle ligne détectée.

    Args:
        paths: Liste de chemins absolus à surveiller
        callback: Fonction(line, source_path) appelée pour chaque ligne
        poll_interval: Intervalle entre 2 polls (secondes)
    """

    def __init__(
        self,
        paths: List[str],
        callback: Callable[[str, str], None],
        poll_interval: float = 1.0,
    ):
        self.paths = paths
        self.callback = callback
        self.poll_interval = poll_interval

        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []

    def start(self):
        """Démarre un thread par fichier (idempotent)."""
        if self._threads:
            logger.warning("LogTailer.start() called twice; ignoring second call")
            return
        if not self.paths:
            logger.warning("⚠ No source files configured — tailer is idle")
            return
        for path in self.paths:
            t = threading.Thread(
                target=self._tail_loop,
                args=(path,),
                daemon=True,
                name=f"tailer-{os.path.basename(path)}",
            )
            t.start()
            self._threads.append(t)

    def stop(self):
        """Arrête proprement tous les threads."""
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=3.0)

    def _tail_loop(self, path: str):
        """Boucle de tail pour un fichier (1 thread par fichier)."""
        logger.info(f"  ✓ Watching: {path}")

        while not self._stop_event.is_set():
            try:
                with open(path, "r", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    inode = os.fstat(f.fileno()).st_ino

                    while not self._stop_event.is_set():
                        line = f.readline()
                        if line:
                            line = line.rstrip("\n")
                            if line:
                                try:
                                    self.callback(line, path)
                                except Exception as e:
                                    logger.error(
                                        f"Error in callback for {path}: {e}"
                                    )
                            continue

                        # Pas de nouvelle ligne → check rotation + sleep
                        time.sleep(self.poll_interval)

                        # Détection rotation : inode changé OU fichier tronqué
                        try:
                            current_inode = os.stat(path).st_ino
                            if current_inode != inode:
                                logger.info(
                                    f"  ↻ Log rotated: {path} (re-opening)"
                                )
                                break  # ré-ouverture via boucle externe
                            # Tronqué ?
                            if f.tell() > os.fstat(f.fileno()).st_size:
                                logger.info(
                                    f"  ↻ Log truncated: {path} (re-opening)"
                                )
                                break
                        except FileNotFoundError:
                            logger.warning(f"  ⚠ File disappeared: {path}")
                            time.sleep(2.0)
                            break

            except PermissionError:
                logger.error(
                    f"  ❌ Permission denied: {path} "
                    f"(run with sudo or fix groups)"
                )
                return  # on abandonne ce fichier
            except FileNotFoundError:
                logger.warning(f"  ⚠ File not found: {path} (waiting...)")
                time.sleep(5.0)
            except Exception as e:
                logger.error(f"  ❌ Unexpected error on {path}: {e}")
                time.sleep(5.0)
