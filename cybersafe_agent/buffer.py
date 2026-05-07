"""
Buffer thread-safe avec flush automatique par taille OU temps.

SOC-020 :
- max_size events accumulés → flush
- OU flush_interval secondes écoulées depuis le dernier flush → flush

Le buffer est thread-safe car plusieurs threads tailers
peuvent écrire dedans simultanément.
"""
import threading
import time
from typing import Callable, List


class EventBuffer:
    """
    Buffer thread-safe d'events.

    Le flush est déclenché par :
    - Atteinte de `max_size` (déclenché à add())
    - Timeout `flush_interval` (déclenché par un thread interne)

    Args:
        max_size: nombre max d'events avant flush
        flush_interval: délai max (secondes) entre 2 flushes
        flush_callback: fonction(List[dict]) -> bool, appelée pour envoyer
    """

    def __init__(
        self,
        max_size: int = 100,
        flush_interval: float = 2.0,
        flush_callback: Callable[[List[dict]], bool] = None,
    ):
        self.max_size = max_size
        self.flush_interval = flush_interval
        self.flush_callback = flush_callback or (lambda events: True)

        self._buffer: List[dict] = []
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()
        self._stop_event = threading.Event()
        self._timer_thread = None

    def start(self):
        """Démarre le thread qui surveille le timeout de flush."""
        self._timer_thread = threading.Thread(
            target=self._timer_loop,
            daemon=True,
            name="buffer-timer",
        )
        self._timer_thread.start()

    def stop(self):
        """Arrête proprement le thread + flush final."""
        self._stop_event.set()
        if self._timer_thread:
            self._timer_thread.join(timeout=3.0)
        self.flush()

    def add(self, event: dict):
        """Ajoute un event. Flush si max_size atteint."""
        with self._lock:
            self._buffer.append(event)
            should_flush = len(self._buffer) >= self.max_size

        if should_flush:
            self.flush()

    def add_many(self, events: List[dict]):
        """Ajoute plusieurs events d'un coup."""
        if not events:
            return
        with self._lock:
            self._buffer.extend(events)
            should_flush = len(self._buffer) >= self.max_size

        if should_flush:
            self.flush()

    def flush(self) -> int:
        """
        Vide le buffer et appelle le callback.
        Retourne le nombre d'events envoyés (0 si buffer vide ou échec).
        """
        with self._lock:
            if not self._buffer:
                self._last_flush = time.monotonic()
                return 0
            batch = self._buffer
            self._buffer = []
            self._last_flush = time.monotonic()

        # Si le callback échoue, les events sont perdus
        # (TODO SOC-022 : spool disque pour résilience)
        ok = self.flush_callback(batch)
        return len(batch) if ok else 0

    def _timer_loop(self):
        """Thread qui flush périodiquement si timeout dépassé."""
        while not self._stop_event.is_set():
            time.sleep(0.5)  # check toutes les 500ms

            with self._lock:
                if not self._buffer:
                    continue
                elapsed = time.monotonic() - self._last_flush
                should_flush = elapsed >= self.flush_interval

            if should_flush:
                self.flush()
